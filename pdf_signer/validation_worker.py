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
                           certifi_hashes: frozenset,
                           trust_store) -> CertSource:
    """Map an asn1crypto cert to its CertSource."""
    try:
        if cert_asn1.subject.hashable in certifi_hashes:
            return CertSource.SYSTEM
    except Exception:
        pass
    try:
        if trust_store.is_trusted(cert_asn1.dump()):
            return CertSource.EU_TSL
    except Exception:
        pass
    return CertSource.DOWNLOADED


def _existing_subjects(chain: list[CertInfo]) -> set[str]:
    return {c.subject for c in chain}


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

    existing = _existing_subjects(cert_chain)
    new_asn1: list = []

    for der in aia_other_der:
        try:
            cert = asn1_x509.Certificate.load(der)
            subj = cert.subject.human_friendly
            if subj not in existing:
                is_root = cert.subject == cert.issuer
                try:
                    is_ca = bool(cert.ca)
                except Exception:
                    is_ca = is_root
                try:
                    subject_hashable = bytes(cert.subject.hashable)
                except Exception:
                    subject_hashable = None
                source  = (_cert_source_for_root(cert, certifi_hashes, trust_store)
                           if is_root else CertSource.DOWNLOADED)
                ci = CertInfo(
                    subject=subj,
                    issuer=cert.issuer.human_friendly,
                    valid_from=cert["tbs_certificate"]["validity"]["not_before"].native,
                    valid_until=cert["tbs_certificate"]["validity"]["not_after"].native,
                    source=source,
                    status=ValidationStatus.NOT_CHECKED,
                    is_root=is_root,
                    is_ca=is_ca,
                    subject_hashable=subject_hashable,
                )
                cert_chain.append(ci)
                existing.add(subj)
            new_asn1.append(cert)
        except Exception:
            pass

    # Re-add placeholders for subjects still not covered by any downloaded cert
    for subj in placeholder_subjects:
        if subj not in existing:
            cert_chain.append(CertInfo(
                subject=subj, issuer="?",
                valid_from=_dt.min, valid_until=_dt.max,
                source=CertSource.NOT_FOUND,
                status=ValidationStatus.NOT_CHECKED,
                is_root=False, is_ca=True,
            ))

    # Reclassify already-embedded roots using certifi / LOTL
    for cert_info in cert_chain:
        if cert_info.is_root and cert_info.source == CertSource.EMBEDDED:
            try:
                for root_asn1 in aia_roots:
                    if root_asn1.subject.human_friendly == cert_info.subject:
                        cert_info.source = _cert_source_for_root(
                            root_asn1, certifi_hashes, trust_store)
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

    for cert_der in all_aia_ders:
        if _maybe_add_confirmed(cert_der):
            continue
        if not auto_fetch:
            continue
        # Try fetching the relevant national TSL and recheck
        country = trust_store.country_hint(cert_der)
        if not country:
            continue
        if trust_store.tsl_is_cached(country):
            # TSL present but cert not found – no point re-fetching
            continue
        if not trust_store.has_lotl_urls():
            trust_store.fetch_lotl_urls()
        if trust_store.fetch_tsl(country):
            if _maybe_add_confirmed(cert_der):
                _log.info("LOTL: confirmed via %s TSL: %s",
                          country,
                          asn1_x509.Certificate.load(cert_der)
                          .subject.human_friendly)

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

        # Build lookup sets using subject.hashable (DER bytes) – encoding-independent.
        # Falls back to human_friendly string when hashable is unavailable.
        confirmed_hashables: set[bytes] = set()
        for c in confirmed_trusted:
            try:
                confirmed_hashables.add(bytes(c.subject.hashable))
            except Exception:
                pass
        certifi_hashables: set[bytes] = set()
        for c in certifi_roots:
            try:
                certifi_hashables.add(bytes(c.subject.hashable))
            except Exception:
                pass

        def _source_for(cert_info: CertInfo) -> Optional[CertSource]:
            """Return EU_TSL / SYSTEM if cert is in a trusted list, else None."""
            h = cert_info.subject_hashable
            if h is not None:
                if h in confirmed_hashables:
                    return CertSource.EU_TSL
                if h in certifi_hashables:
                    return CertSource.SYSTEM
            return None

        def _update_chain(chain: list) -> None:
            for cert_info in chain:
                if cert_info.source == CertSource.NOT_FOUND:
                    trusted_src = _source_for(cert_info)
                    cert_info.source = trusted_src if trusted_src else CertSource.DOWNLOADED
                elif cert_info.is_root and cert_info.source == CertSource.EMBEDDED:
                    # Embedded root confirmed by certifi/LOTL → update source.
                    # Embedded roots NOT in either list stay EMBEDDED (untrusted).
                    trusted_src = _source_for(cert_info)
                    if trusted_src:
                        cert_info.source = trusted_src
                # Set cert status; don't override a known OCSP revocation
                if (cert_info.ocsp and
                        cert_info.ocsp.status == ValidationStatus.INVALID):
                    cert_info.status = ValidationStatus.INVALID
                else:
                    cert_info.status = ValidationStatus.VALID

        _update_chain(sig_info.cert_chain)
        if sig_info.timestamp:
            _update_chain(sig_info.timestamp.cert_chain)
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

        # Collect all pyhanko sig objects sorted by revision (oldest first)
        all_sig_objs: list[tuple[int, object]] = []
        try:
            for s in reader.embedded_regular_signatures:
                all_sig_objs.append((s.signed_revision, s))
        except Exception:
            pass
        try:
            for t in reader.embedded_timestamp_signatures:
                all_sig_objs.append((t.signed_revision, t))
        except Exception:
            pass
        all_sig_objs.sort(key=lambda x: x[0])

        if len(all_sig_objs) != len(self._doc.revisions):
            self.error.emit(
                f"Revisionszahl stimmt nicht überein "
                f"({len(all_sig_objs)} vs {len(self._doc.revisions)})")
            return

        # One trust store instance shared across all revisions
        from .lotl_trust import XmlCacheTrustStore
        trust_store = XmlCacheTrustStore()

        # If auto-fetch is on and we have no LOTL URL list yet, load it now
        if self._auto_fetch and not trust_store.has_lotl_urls():
            trust_store.fetch_lotl_urls()

        from .signer import _load_certifi_roots
        certifi_roots  = _load_certifi_roots()
        certifi_hashes = frozenset(c.subject.hashable for c in certifi_roots)

        # Process each revision
        for rev, (_, sig_obj) in zip(self._doc.revisions, all_sig_objs):
            if self.isInterruptionRequested():
                break
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
