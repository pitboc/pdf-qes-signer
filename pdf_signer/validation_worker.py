# SPDX-License-Identifier: GPL-3.0-or-later
"""Background worker for Phase 2 signature validation (network access).

## Responsibility

``ValidationWorker`` takes the ``DocumentValidation`` produced by
``validation_extractor.extract`` (Phase 1) and fills in the status fields
that require network access:

- ``chain_status``      – trust chain validated against certifi/Mozilla roots
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

1. Loads certifi Mozilla CA roots (cached globally via ``signer.py``).
2. Downloads missing intermediate certificates via AIA caIssuers links.
3. For each AIA-downloaded root: checks ``XmlCacheTrustStore.is_trusted()``.
   Only LOTL-confirmed roots are added to ``extra_trust_roots``; unconfirmed
   roots are kept in ``other_certs`` (chain-building only, not trusted).
4. Calls ``validate_pdf_signature`` / ``validate_pdf_timestamp`` with a
   ``ValidationContext`` that includes the confirmed roots and
   ``allow_fetching=True`` for live OCSP queries.
5. Maps ``PdfSignatureStatus.trusted`` to ``chain_status`` /
   ``revocation_status``.

## TSL loading policy

When ``auto_fetch_revocation = always``:
  The worker automatically fetches the relevant national TSL when an
  AIA root cannot be confirmed.  Country is inferred from the root cert's
  Issuer-DN.  Already-cached (and still valid) TSLs are reused without
  network access.  If no LOTL URL list exists it is fetched first.

When ``auto_fetch_revocation = never``:
  No network access beyond what pyhanko itself does for OCSP.  Only
  previously cached TSL data is used.

When ``auto_fetch_revocation = ask`` (future):
  ``needs_tsl_download`` / ``needs_lotl_refresh`` signals are emitted and
  the worker blocks via QWaitCondition until :meth:`grant_permission` is
  called from the UI thread.

## Security

AIA-downloaded roots are NEVER added to ``extra_trust_roots`` without LOTL
confirmation.  Only certifi roots and LOTL-confirmed roots are trusted.
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
                try:
                    cert_fp = hashlib.sha256(cert.dump()).digest()
                except Exception:
                    cert_fp = None
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
                  certifi_roots: list,
                  certifi_hashes: frozenset,
                  trust_store,
                  auto_fetch: bool = False) -> None:
    """Run Phase 2 validation for one revision, mutating *rev* in-place.

    Args:
        certifi_roots:  Mozilla CA roots (always trusted).
        certifi_hashes: frozenset of subject.hashable for certifi roots.
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

    # ── Step 2: LOTL confirmation for AIA certs ──────────────────────────
    # National TSLs typically list Qualified Intermediate CAs, not roots.
    # We therefore check ALL AIA-downloaded certs (intermediates + roots)
    # against the trust store.  Any LOTL-confirmed cert – regardless of
    # level – may serve as a trust anchor in the ValidationContext.
    #
    # SECURITY: only certs found in a nationally-published TSL (reachable
    # via the EU LOTL over HTTPS/certifi) are allowed as extra_trust_roots.
    from asn1crypto import x509 as asn1_x509

    all_aia_ders: list[bytes] = (aia_other_der
                                  + [r.dump() for r in aia_roots])
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

    _log.debug("certchain [signer LOTL]: checking %d AIA certs", len(all_aia_ders))
    for cert_der in all_aia_ders:
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
        if not trust_store.has_lotl_urls():
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
                # LOTL confirmation for TSA chain certs (same as signer chain in Step 2)
                tsa_all_ders = tsa_aia_other + [r.dump() for r in tsa_aia_roots]
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
                    if not trust_store.has_lotl_urls():
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
    cms_certs: list = []
    try:
        for c in sig_obj.signed_data["certificates"]:
            try:
                cms_certs.append(c.chosen)
            except Exception:
                pass
    except Exception:
        pass

    # SECURITY: only certifi roots and LOTL-confirmed certs are trusted.
    # AIA-downloaded certs not in LOTL go into other_certs (chain-building only).
    all_other   = cms_certs + aia_as_asn1
    extra_roots = certifi_roots + confirmed_trusted

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
        certifi_fps: set[bytes] = {
            hashlib.sha256(c.dump()).digest() for c in certifi_roots}
        _log.debug("certchain [step6]: confirmed_fps=%d  certifi_fps=%d",
                   len(confirmed_fps), len(certifi_fps))

        def _source_for(cert_info: CertInfo) -> Optional[CertSource]:
            """Return EU_TSL / CERTIFI if cert fingerprint is in a trusted set."""
            fp = cert_info.cert_fingerprint
            if fp is not None:
                if fp in confirmed_fps:
                    return CertSource.EU_TSL
                if fp in certifi_fps:
                    return CertSource.CERTIFI
            _log.debug("certchain [source_for]: no match for %r  fp=%s",
                       cert_info.subject[:60],
                       fp.hex()[:16] if fp else "None")
            return None

        def _update_chain(chain: list) -> None:
            for cert_info in chain:
                old_src = cert_info.source
                if cert_info.source == CertSource.NOT_FOUND:
                    trusted_src = _source_for(cert_info)
                    cert_info.source = trusted_src if trusted_src else CertSource.DOWNLOADED
                elif cert_info.source == CertSource.DOWNLOADED:
                    # AIA-downloaded cert: upgrade to CERTIFI/EU_TSL if directly confirmed.
                    trusted_src = _source_for(cert_info)
                    if trusted_src:
                        cert_info.source = trusted_src
                    elif cert_info.is_root:
                        # Root was downloaded via AIA but is not directly listed in certifi
                        # or a TSL (many national QES root CAs aren't).  Since we are inside
                        # the status.trusted branch, pyhanko verified the full chain via a
                        # LOTL-confirmed trust anchor (typically a confirmed intermediate CA).
                        # Mark as EU_TSL to indicate "chain confirmed via EU trust infrastructure".
                        cert_info.source = CertSource.EU_TSL
                elif cert_info.is_root and cert_info.source == CertSource.EMBEDDED:
                    # Embedded root: upgrade to CERTIFI/EU_TSL if directly confirmed.
                    # If not directly in certifi/TSL but chain is trusted (status.trusted),
                    # pyhanko verified the chain via a LOTL-confirmed intermediate –
                    # mark as EU_TSL to reflect that the chain was LOTL-confirmed.
                    trusted_src = _source_for(cert_info)
                    cert_info.source = trusted_src if trusted_src else CertSource.EU_TSL
                if cert_info.source != old_src:
                    _log.debug("certchain [update]: %r  %s → %s",
                               cert_info.subject[:60], old_src, cert_info.source)
                else:
                    _log.debug("certchain [update]: %r  unchanged=%s  h=%s",
                               cert_info.subject[:60], cert_info.source,
                               cert_info.subject_hashable.hex()[:16]
                               if cert_info.subject_hashable else "None")
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
    else:
        sig_info.chain_status = ValidationStatus.UNKNOWN
        if sig_info.revocation_status == ValidationStatus.NOT_CHECKED:
            sig_info.revocation_status = ValidationStatus.UNKNOWN

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

        # If auto-fetch is on and we have no LOTL URL list yet, load it now
        if self._auto_fetch and not trust_store.has_lotl_urls():
            trust_store.fetch_lotl_urls()

        from .signer import _load_certifi_roots
        certifi_roots  = _load_certifi_roots()
        certifi_hashes = frozenset(
            hashlib.sha256(c.dump()).digest() for c in certifi_roots)

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
                _validate_one(rev, sig_obj, certifi_roots, certifi_hashes,
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
