# SPDX-License-Identifier: GPL-3.0-or-later
"""Background worker for Phase 2 signature validation (network access).

## Responsibility

``ValidationWorker`` takes the ``DocumentValidation`` produced by
``validation_extractor.extract`` (Phase 1) and fills in the status fields
that require network access:

- ``chain_status``      – trust chain validated against EU LOTL/TSL
- ``revocation_status`` – OCSP response fetched or confirmed from embedded data

It mutates the ``DocumentValidation`` object **in-place** so the UI tree,
which already holds references to the same objects, updates automatically
when the worker emits ``step_done`` or ``finished``.

## Signal flow

``step_done(str)`` is emitted after each revision is processed.
``finished()`` is emitted once all revisions are done and the overall
status has been rolled up.  ``error(str)`` is emitted only for
unrecoverable fatal errors (rare); per-revision failures are silently
absorbed.

For future ``ask``-mode user-consent dialogs, the worker exposes:

- ``needs_tsl_download(country, message)`` – blocked, waiting for
  :meth:`grant_permission`.
- ``needs_lotl_refresh(message)`` – LOTL URL list stale, user may approve
  refresh.
- ``tsl_loaded(country, message)`` – informational, TSL was fetched.
- :meth:`grant_permission(approved)` – called from the UI thread to unblock.

## Validation strategy

For each revision the worker:

1. Fetches missing certificates via AIA caIssuers links (HTTP, per RFC 5280).
2. Checks all collected certificates (AIA-downloaded + CMS-embedded) against
   ``XmlCacheTrustStore``.  Any cert whose SHA-256 fingerprint appears in a
   nationally-published TSL is added to ``confirmed_trusted``.
3. Calls ``validate_pdf_signature`` / ``validate_pdf_timestamp`` with a
   ``ValidationContext`` whose ``extra_trust_roots`` contains only
   LOTL-confirmed certificates.
4. Maps ``PdfSignatureStatus.trusted`` to ``chain_status`` /
   ``revocation_status``.

## Trust model

The sole trust anchor for QES validation is the **EU LOTL** (List of Trusted
Lists) and the national TSLs it references.  National TSLs publish the
certificates of accredited Qualified Trust Service Providers (QTSPs), typically
their issuing CA (intermediate) certificates.

A LOTL-confirmed intermediate is used directly as an ``extra_trust_root``.
Per RFC 5280, a trust anchor is accepted without verifying its own certificate
signature – pyhanko stops chain-building at the confirmed intermediate and does
not need the root CA above it.  The root CA is therefore not part of the
verified chain and is shown as informational only.

certifi (Mozilla CA Bundle) is **not** used as a validation trust anchor.
It is only used for TLS connections when downloading LOTL and TSL files over
HTTPS.

## TSL loading policy

When ``auto_fetch_revocation = always``:
  The worker automatically fetches the relevant national TSL when a cert
  cannot be confirmed.  Country is inferred from the cert's Issuer-DN.
  Already-cached (and still valid) TSLs are reused without network access.
  If no LOTL URL list exists it is fetched first.

When ``auto_fetch_revocation = never``:
  No network access beyond what pyhanko itself does for OCSP.  Only
  previously cached TSL data is used.

When ``auto_fetch_revocation = ask`` (future):
  ``needs_tsl_download`` / ``needs_lotl_refresh`` signals are emitted and
  the worker blocks via QWaitCondition until :meth:`grant_permission` is
  called from the UI thread.

## Security

Only LOTL-confirmed certificates are added to ``extra_trust_roots``.
AIA-downloaded or CMS-embedded certificates not confirmed by a TSL are kept
in ``other_certs`` (chain-building only, never trusted as anchors).
"""

from __future__ import annotations

import hashlib
import io
import logging
from datetime import timedelta
from typing import Optional

from PyQt6.QtCore import QMutex, QThread, QWaitCondition, pyqtSignal

from .validation_result import (
    CertInfo, CertSource, DocumentValidation,
    RevisionInfo, SignatureInfo, ValidationStatus,
)

_log = logging.getLogger(__name__)

# ── Status helpers ────────────────────────────────────────────────────────────

_STATUS_PRIORITY = {
    ValidationStatus.INVALID:     0,
    ValidationStatus.UNKNOWN:     1,
    ValidationStatus.NOT_CHECKED: 2,
    ValidationStatus.VALID:       3,
}


def _worst(*statuses: ValidationStatus) -> ValidationStatus:
    return min(statuses, key=lambda s: _STATUS_PRIORITY[s])


# ── Certificate helpers ───────────────────────────────────────────────────────

def _verify_issuer_sig(cert_der: bytes, issuer_der: bytes) -> bool:
    """Return True if issuer_der's public key verifies cert_der's signature.

    Uses the cryptography library (already a pyhanko dependency).
    Supports RSA (PKCS#1 v1.5), EC (ECDSA), Ed25519, Ed448.
    Returns False on InvalidSignature or any unexpected error.
    """
    try:
        from cryptography.x509 import load_der_x509_certificate
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import padding, ec
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
        cert   = load_der_x509_certificate(cert_der)
        issuer = load_der_x509_certificate(issuer_der)
        pub = issuer.public_key()
        sig = cert.signature
        tbs = cert.tbs_certificate_bytes
        alg = cert.signature_hash_algorithm
        if isinstance(pub, RSAPublicKey):
            pub.verify(sig, tbs, padding.PKCS1v15(), alg)
        elif isinstance(pub, EllipticCurvePublicKey):
            pub.verify(sig, tbs, ec.ECDSA(alg))
        elif isinstance(pub, (Ed25519PublicKey, Ed448PublicKey)):
            pub.verify(sig, tbs)
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except Exception as exc:
        _log.debug("certchain [issuer_sig]: verification error: %s", exc)
        return False


def _cert_source_for_root(cert_asn1,
                           certifi_fps: frozenset,
                           trust_store) -> CertSource:
    """Map an asn1crypto cert to its CertSource.

    Trust confirmation uses SHA-256 fingerprints of the full cert DER, not
    just the Subject DN.  This prevents a spoofed cert with the same DN as a
    trusted root from being classified as CERTIFI.
    """
    subj = cert_asn1.subject.human_friendly
    try:
        fp = hashlib.sha256(cert_asn1.dump()).digest()
        in_certifi = fp in certifi_fps
        _log.debug("certchain [root src]: %r  certifi=%s", subj, in_certifi)
        if in_certifi:
            return CertSource.CERTIFI
    except Exception as _e:
        _log.debug("certchain [root src]: certifi check error: %s", _e)
    try:
        in_lotl = trust_store.is_trusted(cert_asn1.dump())
        _log.debug("certchain [root src]: %r  lotl=%s", subj, in_lotl)
        if in_lotl:
            return CertSource.EU_TSL
    except Exception as _e:
        _log.debug("certchain [root src]: lotl check error: %s", _e)
    _log.debug("certchain [root src]: %r  → DOWNLOADED", subj)
    return CertSource.DOWNLOADED


def _append_downloaded_certs(cert_chain: list,
                              aia_other_der: list[bytes],
                              aia_roots: list,
                              certifi_hashes: frozenset,
                              trust_store) -> list:
    """Append AIA-downloaded certs to *cert_chain* if not already present.

    Mutates *cert_chain* in-place.  NOT_FOUND placeholders whose subject is
    covered by a downloaded cert are replaced; remaining placeholders stay.

    Returns the list of asn1crypto Certificate objects (all AIA certs,
    including roots) to pass to the ``ValidationContext`` as ``other_certs``.
    """
    from asn1crypto import x509 as asn1_x509
    from datetime import datetime as _dt

    # Remove NOT_FOUND placeholders; they will be re-added only if the real
    # cert is still absent after the download pass.
    placeholder_subjects = {c.subject for c in cert_chain
                            if c.source == CertSource.NOT_FOUND}
    cert_chain[:] = [c for c in cert_chain if c.source != CertSource.NOT_FOUND]

    # Build deduplication sets: prefer subject.hashable (encoding-independent)
    # over human_friendly strings to avoid duplicates when Phase-1 embedded
    # cert and AIA-downloaded cert encode the subject DN differently.
    existing_h: set[bytes] = set()
    existing_s: set[str]   = set()
    for _ci in cert_chain:
        if _ci.subject_hashable is not None:
            existing_h.add(_ci.subject_hashable)
        else:
            existing_s.add(_ci.subject)
    new_asn1: list = []

    for der in aia_other_der:
        try:
            cert = asn1_x509.Certificate.load(der)
            subj = cert.subject.human_friendly
            try:
                h = cert.subject.dump()
            except Exception:
                h = None
            already = (h in existing_h) if h is not None else (subj in existing_s)
            if not already:
                is_root = cert.subject == cert.issuer
                try:
                    is_ca = bool(cert.ca)
                except Exception:
                    is_ca = is_root
                source  = (_cert_source_for_root(cert, certifi_hashes, trust_store)
                           if is_root else CertSource.DOWNLOADED)
                # Use original DER bytes (not cert.dump()) so cert_fingerprint
                # is consistent with fp_to_der in Step 7, which also uses sha256(der).
                cert_fp = hashlib.sha256(der).digest()
                ci = CertInfo(
                    subject=subj,
                    issuer=cert.issuer.human_friendly,
                    valid_from=cert["tbs_certificate"]["validity"]["not_before"].native,
                    valid_until=cert["tbs_certificate"]["validity"]["not_after"].native,
                    source=source,
                    status=ValidationStatus.NOT_CHECKED,
                    is_root=is_root,
                    is_ca=is_ca,
                    subject_hashable=h,
                    cert_fingerprint=cert_fp,
                )
                _log.debug("certchain [append]: +%s  source=%s  root=%s  h=%s",
                           subj[:60], source, is_root,
                           h.hex()[:16] if h else "None")
                cert_chain.append(ci)
                if h is not None:
                    existing_h.add(h)
                else:
                    existing_s.add(subj)
            else:
                _log.debug("certchain [append]: skip (already present): %s",
                           subj[:60])
            new_asn1.append(cert)
        except Exception:
            pass

    # Re-add placeholders for subjects still not covered by any downloaded cert
    covered_subjects = {c.subject for c in cert_chain}
    for subj in placeholder_subjects:
        if subj not in covered_subjects:
            cert_chain.append(CertInfo(
                subject=subj, issuer="?",
                valid_from=_dt.min, valid_until=_dt.max,
                source=CertSource.NOT_FOUND,
                status=ValidationStatus.NOT_CHECKED,
                is_root=False, is_ca=True,
            ))

    # Reclassify already-embedded roots using certifi / LOTL.
    # Only UPGRADE (EMBEDDED → CERTIFI/EU_TSL); never downgrade to DOWNLOADED.
    for cert_info in cert_chain:
        if cert_info.is_root and cert_info.source == CertSource.EMBEDDED:
            try:
                for root_asn1 in aia_roots:
                    try:
                        # Match by fingerprint (full cert DER), not just DN
                        if cert_info.cert_fingerprint is not None:
                            match = (hashlib.sha256(root_asn1.dump()).digest()
                                     == cert_info.cert_fingerprint)
                        else:
                            match = root_asn1.subject.human_friendly == cert_info.subject
                    except Exception:
                        match = root_asn1.subject.human_friendly == cert_info.subject
                    if match:
                        new_src = _cert_source_for_root(
                            root_asn1, certifi_hashes, trust_store)
                        if new_src != CertSource.DOWNLOADED:
                            cert_info.source = new_src
                        break
            except Exception:
                pass

    return new_asn1


# ── Per-signature validation ──────────────────────────────────────────────────

def _suppress_logs() -> tuple:
    ph  = logging.getLogger("pyhanko")
    cv  = logging.getLogger("pyhanko_certvalidator")
    old = ph.level, cv.level
    ph.setLevel(logging.CRITICAL)
    cv.setLevel(logging.CRITICAL)
    return old


def _restore_logs(old: tuple) -> None:
    logging.getLogger("pyhanko").setLevel(old[0])
    logging.getLogger("pyhanko_certvalidator").setLevel(old[1])


def _validate_one(rev: RevisionInfo,
                  sig_obj,
                  certifi_hashes: frozenset,
                  trust_store,
                  auto_fetch: bool = False) -> None:
    """Run Phase 2 validation for one revision, mutating *rev* in-place.

    Args:
        certifi_hashes: SHA-256 fingerprints of certifi roots, used only to
                        annotate CertSource (display purposes).  certifi roots
                        are NOT used as validation trust anchors.
        trust_store:    QesTrustStore instance for LOTL confirmation.
        auto_fetch:     If True, fetch missing TSLs from the network.
    """
    from asn1crypto import x509 as asn1_x509
    from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
    from pyhanko_certvalidator import ValidationContext
    from .signer import _fetch_aia_chain

    sig_info = rev.signed_by
    if sig_info is None:
        return

    # ── Step 1: AIA chain download ────────────────────────────────────────
    signer_cert_der: Optional[bytes] = None
    try:
        signer_cert_der = sig_obj.signer_cert.dump()
    except Exception:
        pass

    aia_other_der: list[bytes] = []
    aia_roots:     list        = []
    if signer_cert_der:
        try:
            aia_other_der, aia_roots = _fetch_aia_chain(signer_cert_der)
        except Exception:
            pass

    # ── Step 1.5: Embedded CMS certs ─────────────────────────────────────
    # Extract before the LOTL check so they can trigger TSL loading too.
    # Certs without an AIA extension never appear in aia_other_der/aia_roots;
    # without this step their country hint would never be evaluated.
    # The asn1 objects are kept for Step 4 (other_certs / chain-building).
    from asn1crypto import x509 as asn1_x509

    cms_certs: list = []
    try:
        for c in sig_obj.signed_data["certificates"]:
            try:
                cms_certs.append(c.chosen)
            except Exception:
                pass
    except Exception:
        pass

    # ── Step 2: LOTL confirmation ─────────────────────────────────────────
    # Check AIA-downloaded AND embedded CMS certs (deduplicated by SHA-256).
    # Using embedded certs avoids redundant HTTP downloads for certs that are
    # already present in the signature.
    #
    # ## Trust model: LOTL-confirmed intermediate as direct trust anchor
    #
    # National TSLs publish the certificates of accredited QTSPs – typically
    # their issuing CA (intermediate) certificates, not root CAs.
    #
    # A cert confirmed via TSL fingerprint is added to extra_trust_roots and
    # used as a direct trust anchor per RFC 5280.  pyhanko stops chain-building
    # at this anchor; the root CA above it is not verified and plays no role
    # in the trust decision.  The root is shown as informational only.
    #
    # SECURITY: Embedding a cert in the CMS structure does NOT grant trust.
    # A cert only becomes an extra_trust_root when LOTL explicitly confirms
    # its SHA-256 fingerprint in a nationally-published TSL.  An attacker who
    # embeds a self-signed cert gains nothing unless its fingerprint is in a TSL.
    _seen_check: set[bytes] = set()
    all_check_ders: list[bytes] = []

    def _add_check(der: bytes) -> None:
        fp = hashlib.sha256(der).digest()
        if fp not in _seen_check:
            _seen_check.add(fp)
            all_check_ders.append(der)

    for der in aia_other_der:
        _add_check(der)
    for r in aia_roots:
        _add_check(r.dump())
    for c in cms_certs:
        try:
            _add_check(c.dump())
        except Exception:
            pass

    confirmed_trusted: list = []   # LOTL-confirmed asn1 cert objects
    seen_confirmed: set[bytes] = set()

    def _maybe_add_confirmed(der: bytes) -> bool:
        """Check trust store and add to confirmed_trusted if found."""
        fp = hashlib.sha256(der).digest()
        if fp in seen_confirmed:
            return True
        if trust_store.is_trusted(der):
            seen_confirmed.add(fp)
            confirmed_trusted.append(asn1_x509.Certificate.load(der))
            return True
        return False

    _log.debug("certchain [signer LOTL]: checking %d certs (AIA+CMS)",
               len(all_check_ders))
    for cert_der in all_check_ders:
        _subj = asn1_x509.Certificate.load(cert_der).subject.human_friendly
        if _maybe_add_confirmed(cert_der):
            _log.debug("certchain [signer LOTL]: confirmed: %s", _subj[:70])
            continue
        if not auto_fetch:
            _log.debug("certchain [signer LOTL]: not confirmed (no auto-fetch): %s", _subj[:70])
            continue
        # Try fetching the relevant national TSL and recheck
        country = trust_store.country_hint(cert_der)
        if not country:
            _log.debug("certchain [signer LOTL]: no country hint for: %s", _subj[:70])
            continue
        if trust_store.tsl_is_cached(country):
            # TSL present but cert not found – no point re-fetching
            _log.debug("certchain [signer LOTL]: TSL[%s] cached but no match for: %s",
                       country, _subj[:70])
            continue
        if not trust_store.lotl_urls_valid():
            trust_store.fetch_lotl_urls()
        if trust_store.fetch_tsl(country):
            if _maybe_add_confirmed(cert_der):
                _log.info("LOTL: confirmed via %s TSL: %s", country, _subj)
                _log.debug("certchain [signer LOTL]: confirmed via %s TSL: %s",
                           country, _subj[:70])
            else:
                _log.debug("certchain [signer LOTL]: fetched TSL[%s] but still no match: %s",
                           country, _subj[:70])
        else:
            _log.debug("certchain [signer LOTL]: TSL[%s] fetch failed for: %s",
                       country, _subj[:70])
    _log.debug("certchain [signer LOTL]: confirmed_trusted count=%d",
               len(confirmed_trusted))

    # ── Step 3: Annotate cert_chain ───────────────────────────────────────
    aia_as_asn1 = _append_downloaded_certs(
        sig_info.cert_chain, aia_other_der, aia_roots, certifi_hashes, trust_store)

    # Also extend the TSA timestamp cert chain via AIA if present
    tsa_all_ders: list[bytes] = []   # TSA cert DER bytes, made available for Step 7
    if sig_info.timestamp and sig_info.timestamp.cert_chain:
        tsa_cert_der: Optional[bytes] = None
        try:
            TST_OID = "1.2.840.113549.1.9.16.2.14"
            unsigned_attrs = sig_obj.signed_data["signer_infos"][0]["unsigned_attrs"]
            for attr in unsigned_attrs:
                if attr["type"].dotted == TST_OID:
                    ts_sd = attr["values"][0]["content"]
                    tsa_certs = list(ts_sd["certificates"])
                    if tsa_certs:
                        tsa_cert_der = tsa_certs[0].chosen.dump()
                    break
        except Exception:
            pass
        if tsa_cert_der:
            try:
                tsa_aia_other, tsa_aia_roots = _fetch_aia_chain(tsa_cert_der)
                # LOTL confirmation for TSA chain: AIA + TSA-embedded certs,
                # deduplicated (same principle as signer chain in Step 2).
                _tsa_seen: set[bytes] = set()
                tsa_all_ders: list[bytes] = []
                for _d in (tsa_aia_other + [r.dump() for r in tsa_aia_roots]):
                    _fp = hashlib.sha256(_d).digest()
                    if _fp not in _tsa_seen:
                        _tsa_seen.add(_fp)
                        tsa_all_ders.append(_d)
                try:
                    for _c in ts_sd["certificates"]:
                        try:
                            _d = _c.chosen.dump()
                            _fp = hashlib.sha256(_d).digest()
                            if _fp not in _tsa_seen:
                                _tsa_seen.add(_fp)
                                tsa_all_ders.append(_d)
                        except Exception:
                            pass
                except Exception:
                    pass
                for cert_der in tsa_all_ders:
                    if _maybe_add_confirmed(cert_der):
                        continue
                    if not auto_fetch:
                        continue
                    country = trust_store.country_hint(cert_der)
                    if not country:
                        continue
                    if trust_store.tsl_is_cached(country):
                        continue
                    if not trust_store.lotl_urls_valid():
                        trust_store.fetch_lotl_urls()
                    if trust_store.fetch_tsl(country):
                        if _maybe_add_confirmed(cert_der):
                            _log.info("LOTL: TSA confirmed via %s TSL: %s",
                                      country,
                                      asn1_x509.Certificate.load(cert_der)
                                      .subject.human_friendly)
                _append_downloaded_certs(
                    sig_info.timestamp.cert_chain,
                    tsa_aia_other, tsa_aia_roots, certifi_hashes, trust_store)
            except Exception:
                pass

    # ── Step 4: Build ValidationContext ──────────────────────────────────
    # cms_certs already extracted in Step 1.5.
    # SECURITY: only LOTL-confirmed certs are trusted as anchors.
    # certifi roots are NOT included – they are TLS-only, not QES trust anchors.
    # AIA-downloaded and embedded certs not confirmed by a TSL go into
    # other_certs (chain-building only, never trusted as anchors).
    all_other   = cms_certs + aia_as_asn1
    extra_roots = confirmed_trusted

    vc = ValidationContext(
        other_certs=all_other or None,
        extra_trust_roots=extra_roots or None,
        allow_fetching=True,
        time_tolerance=timedelta(minutes=5),
    )

    # ── Step 5: Validate signature ────────────────────────────────────────
    old = _suppress_logs()
    try:
        if sig_info.sig_type == "doc_timestamp":
            status = validate_pdf_timestamp(sig_obj, validation_context=vc)
        else:
            status = validate_pdf_signature(sig_obj,
                                            signer_validation_context=vc)
    except Exception as exc:
        _log.debug("validation failed for %s: %s", sig_info.field_name, exc)
        return
    finally:
        _restore_logs(old)

    # ── Step 6: Map results to status fields ──────────────────────────────
    # source = provenance, set once; NOT_FOUND placeholders are the exception:
    # they represent roots absent from the PDF and get updated here once the
    # actual origin is known.  EMBEDDED sources are never changed.
    # status = validation outcome, set here in Phase 2.
    if status.trusted:
        sig_info.chain_status      = ValidationStatus.VALID
        sig_info.revocation_status = ValidationStatus.VALID

        # Build lookup sets using subject.dump() (DER bytes of DN) for comparison.
        # Use SHA-256 fingerprints (full cert DER) for trust confirmation –
        # NOT subject DNs.  A spoofed cert with the same DN as a trusted root
        # must never be classified as trusted.
        confirmed_fps: set[bytes] = {
            hashlib.sha256(c.dump()).digest() for c in confirmed_trusted}
        _log.debug("certchain [step6]: confirmed_fps=%d  certifi_hashes=%d",
                   len(confirmed_fps), len(certifi_hashes))

        def _source_for(cert_info: CertInfo) -> Optional[CertSource]:
            """Return EU_TSL / CERTIFI if cert fingerprint is in a trusted set."""
            fp = cert_info.cert_fingerprint
            if fp is not None:
                if fp in confirmed_fps:
                    return CertSource.EU_TSL
                if fp in certifi_hashes:
                    return CertSource.CERTIFI
            _log.debug("certchain [source_for]: no match for %r  fp=%s",
                       cert_info.subject[:60],
                       fp.hex()[:16] if fp else "None")
            return None

        def _update_chain(chain: list) -> None:
            for cert_info in chain:
                old_src = cert_info.source

                # Mark LOTL-confirmed certs (source of truth for trust display).
                # lotl_confirmed is set independently of physical origin (source).
                if (cert_info.cert_fingerprint is not None
                        and cert_info.cert_fingerprint in confirmed_fps):
                    cert_info.lotl_confirmed = True

                # Certs below the LOTL anchor were verified by pyhanko as part
                # of validate_pdf_signature (EE→anchor chain is fully checked).
                # The anchor itself, roots above it, and NOT_FOUND placeholders
                # are NOT covered by pyhanko.
                if (not cert_info.is_root
                        and not cert_info.lotl_confirmed
                        and cert_info.source != CertSource.NOT_FOUND):
                    cert_info.issuer_verified = True

                # Update source (physical origin) – only upgrade, never downgrade.
                # Root certs are NOT promoted to EU_TSL just because the chain is
                # trusted via an intermediate.  Their origin stays DOWNLOADED (AIA)
                # or EMBEDDED; lotl_confirmed=True on the intermediate is the signal.
                if cert_info.source == CertSource.NOT_FOUND:
                    trusted_src = _source_for(cert_info)
                    cert_info.source = trusted_src if trusted_src else CertSource.DOWNLOADED
                elif cert_info.source == CertSource.DOWNLOADED:
                    # Upgrade to EU_TSL/CERTIFI only if directly confirmed.
                    trusted_src = _source_for(cert_info)
                    if trusted_src:
                        cert_info.source = trusted_src
                    # Root not directly confirmed → stays DOWNLOADED (shown as informational)
                elif cert_info.is_root and cert_info.source == CertSource.EMBEDDED:
                    # Embedded root: upgrade only if directly confirmed.
                    trusted_src = _source_for(cert_info)
                    if trusted_src:
                        cert_info.source = trusted_src
                    # Otherwise stays EMBEDDED (shown as informational)

                if cert_info.source != old_src:
                    _log.debug("certchain [update]: %r  %s → %s",
                               cert_info.subject[:60], old_src, cert_info.source)
                else:
                    _log.debug("certchain [update]: %r  unchanged=%s  lotl=%s",
                               cert_info.subject[:60], cert_info.source,
                               cert_info.lotl_confirmed)
                # Set cert status; don't override a known OCSP revocation
                if (cert_info.ocsp and
                        cert_info.ocsp.status == ValidationStatus.INVALID):
                    cert_info.status = ValidationStatus.INVALID
                else:
                    cert_info.status = ValidationStatus.VALID

        _log.debug("certchain [step6]: updating signer chain (%d certs)",
                   len(sig_info.cert_chain))
        _update_chain(sig_info.cert_chain)
        if sig_info.timestamp:
            _log.debug("certchain [step6]: updating TSA chain (%d certs)",
                       len(sig_info.timestamp.cert_chain))
            _update_chain(sig_info.timestamp.cert_chain)
            sig_info.timestamp.chain_status = ValidationStatus.VALID

        # ── Step 7: Explicit issuer signature verification ────────────────
        # Build fingerprint→DER lookup from all cert bytes collected so far.
        # Used to verify that the root actually signed the LOTL anchor cert
        # (this relationship is NOT verified by pyhanko when the anchor is
        # an intermediate).  EE→anchor is already handled in _update_chain.
        fp_to_der: dict[bytes, bytes] = {}
        # Prefer original DER bytes (sha256 of raw bytes matches cert_fingerprint
        # computed from aia_other_der entries in _append_downloaded_certs).
        if signer_cert_der:
            fp_to_der[hashlib.sha256(signer_cert_der).digest()] = signer_cert_der
        for _der in aia_other_der:
            fp_to_der[hashlib.sha256(_der).digest()] = _der
        # all_check_ders: original DER bytes used during LOTL step (covers intermediate)
        for _der in all_check_ders:
            fp_to_der[hashlib.sha256(_der).digest()] = _der
        # tsa_all_ders: TSA cert DER bytes (AIA-downloaded + embedded in timestamp token).
        # Required so Step 7 can verify the TSA intermediate→root signature in Rev 1
        # signatures (where the TSA root is not in the signer's AIA chain).
        for _der in tsa_all_ders:
            _fp = hashlib.sha256(_der).digest()
            if _fp not in fp_to_der:
                fp_to_der[_fp] = _der
        # Fallback: re-encoded from asn1crypto objects (lower priority, may differ)
        for _c in aia_roots + cms_certs + confirmed_trusted:
            try:
                _der = _c.dump()
                _fp  = hashlib.sha256(_der).digest()
                if _fp not in fp_to_der:
                    fp_to_der[_fp] = _der
            except Exception:
                pass

        _log.debug("certchain [step7]: fp_to_der has %d entries", len(fp_to_der))

        def _verify_issuer_sigs(chain: list) -> None:
            for idx, cert_info in enumerate(chain):
                if cert_info.is_root or cert_info.issuer_verified is True:
                    continue  # root has no issuer; already verified by pyhanko
                issuer_info = chain[idx + 1] if idx + 1 < len(chain) else None
                if issuer_info is None or issuer_info.cert_fingerprint is None:
                    _log.debug("certchain [step7]: skip %s – no issuer in chain",
                               cert_info.subject[:60])
                    continue
                cert_der_   = fp_to_der.get(cert_info.cert_fingerprint)
                issuer_der_ = fp_to_der.get(issuer_info.cert_fingerprint)
                _log.debug("certchain [step7]: %s  cert_der=%s  issuer_der=%s  "
                           "cert_fp=%s  issuer_fp=%s",
                           cert_info.subject[:60],
                           cert_der_ is not None, issuer_der_ is not None,
                           cert_info.cert_fingerprint.hex()[:16]
                               if cert_info.cert_fingerprint else "None",
                           issuer_info.cert_fingerprint.hex()[:16]
                               if issuer_info.cert_fingerprint else "None")
                if cert_der_ is None or issuer_der_ is None:
                    continue
                result = _verify_issuer_sig(cert_der_, issuer_der_)
                cert_info.issuer_verified = result
                _log.debug("certchain [step7]: %s issuer_sig=%s",
                           cert_info.subject[:60], result)

        _verify_issuer_sigs(sig_info.cert_chain)
        if sig_info.timestamp:
            _verify_issuer_sigs(sig_info.timestamp.cert_chain)
    else:
        # Never upgrade: if Phase 1 already found INVALID (e.g. expired cert),
        # keep it – UNKNOWN must not overwrite a worse status.
        sig_info.chain_status = _worst(sig_info.chain_status, ValidationStatus.UNKNOWN)
        if sig_info.revocation_status == ValidationStatus.NOT_CHECKED:
            sig_info.revocation_status = ValidationStatus.UNKNOWN
        # Capture the AdES subindication so the UI can show a precise reason.
        # OUT_OF_BOUNDS_NO_POE, REVOKED_NO_POE, TRY_LATER etc. imply that
        # pyhanko successfully built and verified the chain; only a subsequent
        # check failed.  _chain_label_tip uses this to suppress "root unknown".
        try:
            indic = status.trust_problem_indic
            if indic is not None:
                sig_info.trust_problem_indic = type(indic).__name__ + "." + indic.name
        except Exception:
            pass

    if sig_info.crypto_status == ValidationStatus.NOT_CHECKED:
        sig_info.crypto_status = (ValidationStatus.VALID if status.valid
                                  else ValidationStatus.INVALID)

    sig_info.status = _worst(sig_info.crypto_status,
                             sig_info.chain_status,
                             sig_info.revocation_status)
    rev.status = sig_info.status


# ── QThread worker ────────────────────────────────────────────────────────────

class ValidationWorker(QThread):
    """Phase 2 background worker: validates signatures with network access.

    Signals:
        step_done(str):              emitted after each revision.
        finished():                  emitted when all revisions are done.
        error(str):                  emitted on unrecoverable fatal error.
        needs_tsl_download(str,str): (country, message) – worker blocked,
                                     call grant_permission() to continue.
        needs_lotl_refresh(str):     (message) – LOTL URL list stale.
        tsl_loaded(str, str):        (country, message) – info, TSL fetched.
    """

    step_done          = pyqtSignal(str)
    finished           = pyqtSignal()
    error              = pyqtSignal(str)
    needs_tsl_download = pyqtSignal(str, str)   # (country, message)
    needs_lotl_refresh = pyqtSignal(str)         # (message)
    tsl_loaded         = pyqtSignal(str, str)    # (country, message)

    def __init__(self, doc: DocumentValidation, pdf_bytes: bytes,
                 auto_fetch: bool = True) -> None:
        super().__init__()
        self._doc        = doc
        self._pdf_bytes  = pdf_bytes
        self._auto_fetch = auto_fetch
        # Infrastructure for future ask-mode blocking
        self._mutex       = QMutex()
        self._wait_cond   = QWaitCondition()
        self._user_approved = False

    def grant_permission(self, approved: bool) -> None:
        """Called from the UI thread to unblock a pending needs_* signal."""
        self._mutex.lock()
        self._user_approved = approved
        self._wait_cond.wakeAll()
        self._mutex.unlock()

    def run(self) -> None:
        try:
            from pyhanko.pdf_utils.reader import PdfFileReader
        except ImportError:
            self.error.emit("pyhanko nicht verfügbar")
            return

        try:
            reader = PdfFileReader(io.BytesIO(self._pdf_bytes), strict=False)
        except Exception as exc:
            self.error.emit(f"PDF konnte nicht geöffnet werden: {exc}")
            return

        # Collect all pyhanko sig objects keyed by field_name for robust matching.
        # Positional matching would break when unsigned revisions are present.
        sig_by_field: dict[str, object] = {}
        try:
            for s in reader.embedded_regular_signatures:
                sig_by_field[s.field_name or ""] = s
        except Exception:
            pass
        try:
            for ts in reader.embedded_timestamp_signatures:
                sig_by_field[ts.field_name or ""] = ts
        except Exception:
            pass

        # One trust store instance shared across all revisions
        from .lotl_trust import XmlCacheTrustStore
        trust_store = XmlCacheTrustStore()

        # If auto-fetch is on and LOTL URL list is missing or expired, refresh it now
        if self._auto_fetch and not trust_store.lotl_urls_valid():
            trust_store.fetch_lotl_urls()

        # certifi hashes are used only for CertSource annotation (display),
        # NOT as validation trust anchors.
        from .signer import _load_certifi_roots
        certifi_hashes = frozenset(
            hashlib.sha256(c.dump()).digest() for c in _load_certifi_roots())

        # Process each signed revision, matched by field_name
        for rev in self._doc.revisions:
            if self.isInterruptionRequested():
                break
            if rev.signed_by is None:
                continue
            sig_obj = sig_by_field.get(rev.signed_by.field_name or "")
            if sig_obj is None:
                _log.warning("Kein pyhanko-Objekt für Feld '%s' gefunden",
                             rev.signed_by.field_name)
                continue
            try:
                _validate_one(rev, sig_obj, certifi_hashes,
                              trust_store, auto_fetch=self._auto_fetch)
                self.step_done.emit(
                    f"Rev {rev.revision_number}: {rev.status.value}")
            except Exception as exc:
                _log.warning("Phase 2 failed for rev %s: %s",
                             rev.revision_number, exc)
                self.step_done.emit(
                    f"Rev {rev.revision_number}: Fehler – {exc}")

        # Roll up overall status
        if self._doc.revisions:
            self._doc.overall_status = _worst(
                *[r.status for r in self._doc.revisions])

        self.finished.emit()
