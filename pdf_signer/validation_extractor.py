# SPDX-License-Identifier: GPL-3.0-or-later
"""Extracts PDF signature validation data into ``DocumentValidation`` objects.

## Two-phase design

**Phase 1 – offline, instant** (``extract``):
  Reads all data already present in the PDF bytes.  No network access.
  Status fields are set where the embedded data is sufficient:

  - Crypto integrity is checked via pyhanko's byte-range verification.
  - Embedded OCSP responses are read and their ``cert_status`` mapped to
    ``ValidationStatus``.
  - Certificate chains are reconstructed from the CMS container and the
    DSS dictionary by following issuer/subject links.
  - Missing chain steps and absent revocation data are left as
    ``NOT_CHECKED`` so the UI can show them with a neutral icon.

**Phase 2 – optional network** (``update_revocation``):
  Called by a background ``QRunnable`` only when
  ``config.validation.auto_fetch_revocation = always``.  Fetches missing
  OCSP responses and AIA certificate chain links, then updates the status
  fields in-place on the ``DocumentValidation`` returned by Phase 1.

## Certificate pool

During extraction all certificates found in the PDF (CMS ``certificates``
set and DSS ``/Certs`` array) are collected into a pool keyed by
``subject.hashable``.  Chain building iterates: start with the signing
certificate, look up each issuer in the pool until a self-signed root or a
missing step is reached.

## OCSP matching

Each OCSP response in ``/DSS/OCSPs`` identifies the subject certificate by
``issuerNameHash`` + ``issuerKeyHash`` + ``serialNumber`` (RFC 6960 §4.1.1).
For Phase 1 this module matches by serial number only; ambiguities at the
same serial within one document are extremely unlikely in practice.
"""

from __future__ import annotations

import io
import logging
import re
from datetime import datetime, timezone
from typing import Optional

_log = logging.getLogger(__name__)

from .validation_result import (
    CertInfo, CertSource, CRLInfo, DocumentValidation, OCSPInfo,
    PadesProfile, RevisionInfo, SignatureInfo, TimestampInfo, ValidationStatus,
)


# ── certifi trust-anchor cache ────────────────────────────────────────────────

_certifi_fingerprints: Optional[set[bytes]] = None


def _get_certifi_fingerprints() -> set[bytes]:
    """Return SHA-256 fingerprints of all certs in the certifi Mozilla CA bundle.

    Using full-cert fingerprints (not just the DN) ensures that an attacker
    cannot spoof a trusted root by embedding a forged cert with the same
    Subject DN as a real certifi root.

    Result is cached after the first call.  Returns an empty set if certifi is
    not installed or the bundle cannot be read.
    """
    import hashlib
    global _certifi_fingerprints
    if _certifi_fingerprints is not None:
        return _certifi_fingerprints
    try:
        import certifi
        from asn1crypto import pem as asn1_pem
        fps: set[bytes] = set()
        with open(certifi.where(), "rb") as fh:
            pem_data = fh.read()
        for _, _, der in asn1_pem.unarmor(pem_data, multiple=True):
            try:
                fps.add(hashlib.sha256(der).digest())
            except Exception:
                pass
        _certifi_fingerprints = fps
        _log.debug("certchain: certifi fingerprints loaded: %d entries", len(fps))
    except Exception as _e:
        _certifi_fingerprints = set()
        _log.debug("certchain: certifi fingerprints failed to load: %s", _e)
    return _certifi_fingerprints


def _compute_chain_status(chain: list[CertInfo],
                          signing_time: Optional[datetime]) -> ValidationStatus:
    """Compute chain trust status from embedded data and the certifi bundle.

    Phase 1 (offline): certifi is the only external trust anchor.

    Returns:
        VALID      – complete chain, root in certifi, end-entity OCSP good
        UNKNOWN    – chain structurally ok but revocation or root unconfirmed
        INVALID    – chain broken, a cert was expired at signing time, or revoked
        NOT_CHECKED – chain is empty
    """
    if not chain:
        return ValidationStatus.NOT_CHECKED

    # Incomplete chain (NOT_FOUND placeholder at end)
    if any(c.source == CertSource.NOT_FOUND for c in chain):
        return ValidationStatus.INVALID

    # Validity dates at signing time
    check_time = signing_time
    if check_time is None:
        check_time = datetime.now(tz=timezone.utc)
    elif check_time.tzinfo is None:
        check_time = check_time.replace(tzinfo=timezone.utc)

    for c in chain:
        vf, vu = c.valid_from, c.valid_until
        if vf == datetime.min or vu == datetime.max:
            continue
        vf = vf if vf.tzinfo else vf.replace(tzinfo=timezone.utc)
        vu = vu if vu.tzinfo else vu.replace(tzinfo=timezone.utc)
        if not (vf <= check_time <= vu):
            return ValidationStatus.INVALID

    # End-entity revocation from embedded OCSP
    ee = chain[0]
    if ee.ocsp is not None and ee.ocsp.cert_status == "revoked":
        return ValidationStatus.INVALID

    # Root trust via certifi – update source in-place when matched
    root = chain[-1]
    root_trusted = False
    _log.debug("certchain [extractor]: root subject=%r is_root=%s source=%s "
               "fp=%s",
               root.subject, root.is_root, root.source,
               root.cert_fingerprint.hex()[:16] if root.cert_fingerprint else "None")
    if root.is_root and root.cert_fingerprint:
        certifi_fps = _get_certifi_fingerprints()
        matched = root.cert_fingerprint in certifi_fps
        _log.debug("certchain [extractor]: certifi fps=%d, root match=%s",
                   len(certifi_fps), matched)
        if matched:
            root_trusted = True
            root.source = CertSource.CERTIFI  # mark so UI can show the source
    else:
        _log.debug("certchain [extractor]: root not checked "
                   "(is_root=%s, has_fingerprint=%s)",
                   root.is_root, bool(root.cert_fingerprint))

    if not root_trusted:
        return ValidationStatus.UNKNOWN  # chain complete, root not in certifi

    # Root trusted: VALID only if OCSP good, otherwise UNKNOWN (revocation pending)
    if ee.ocsp is not None and ee.ocsp.cert_status == "good":
        return ValidationStatus.VALID
    return ValidationStatus.UNKNOWN


# ── Status helpers ────────────────────────────────────────────────────────────

_STATUS_PRIORITY = {
    ValidationStatus.INVALID:     0,
    ValidationStatus.UNKNOWN:     1,
    ValidationStatus.NOT_CHECKED: 2,
    ValidationStatus.VALID:       3,
}


def _worst(*statuses: ValidationStatus) -> ValidationStatus:
    """Return the most severe status (INVALID > UNKNOWN > NOT_CHECKED > VALID)."""
    return min(statuses, key=lambda s: _STATUS_PRIORITY[s])


def _ocsp_cert_status_to_vs(name: str) -> ValidationStatus:
    if name == "good":
        return ValidationStatus.VALID
    if name == "revoked":
        return ValidationStatus.INVALID
    return ValidationStatus.UNKNOWN


# ── Certificate helpers ───────────────────────────────────────────────────────

def _subject_cn(cert) -> str:
    """Return the Common Name from an asn1crypto X.509 certificate subject."""
    try:
        for rdn in cert.subject.chosen:
            for attr in rdn:
                if attr["type"].native == "common_name":
                    return str(attr["value"].native)
        return cert.subject.human_friendly
    except Exception:
        return "?"


def _cert_to_info(cert,
                  source: CertSource = CertSource.EMBEDDED,
                  ocsp: Optional[OCSPInfo] = None,
                  crl: Optional[CRLInfo] = None) -> CertInfo:
    """Convert an asn1crypto Certificate into a ``CertInfo`` dataclass."""
    try:
        tbs = cert["tbs_certificate"]
        not_before: datetime = tbs["validity"]["not_before"].native
        not_after:  datetime = tbs["validity"]["not_after"].native
        is_root = cert.subject == cert.issuer
        try:
            is_ca = bool(cert.ca)
        except Exception:
            is_ca = is_root
        try:
            subject_hashable = cert.subject.dump()
        except Exception:
            subject_hashable = None
        try:
            import hashlib as _hashlib
            cert_fingerprint = _hashlib.sha256(cert.dump()).digest()
        except Exception:
            cert_fingerprint = None
        return CertInfo(
            subject=cert.subject.human_friendly,
            issuer=cert.issuer.human_friendly,
            valid_from=not_before,
            valid_until=not_after,
            source=source,
            status=ValidationStatus.NOT_CHECKED,
            is_root=is_root,
            is_ca=is_ca,
            subject_hashable=subject_hashable,
            cert_fingerprint=cert_fingerprint,
            ocsp=ocsp,
            crl=crl,
        )
    except Exception:
        return CertInfo(
            subject="?",
            issuer="?",
            valid_from=datetime.min,
            valid_until=datetime.max,
            source=source,
            status=ValidationStatus.NOT_CHECKED,
        )


def _build_chain(signer_cert,
                 pool: list,
                 ocsp_by_serial: dict[int, OCSPInfo],
                 crl_info: Optional[CRLInfo]) -> list[CertInfo]:
    """Return ordered chain [end-entity, …, root] using *pool* to fill gaps.

    Args:
        signer_cert:    asn1crypto Certificate of the end-entity signer.
        pool:           All certificates available (CMS + DSS), as
                        asn1crypto Certificate objects.
        ocsp_by_serial: Mapping serial-number → OCSPInfo for quick lookup.
        crl_info:       CRLInfo to attach to the signing cert (or None).
    """
    # Build issuer lookup: subject.hashable → cert
    by_subject: dict = {}
    for c in pool:
        try:
            by_subject[c.subject.hashable] = c
        except Exception:
            pass

    chain: list[CertInfo] = []
    current = signer_cert
    seen: set = set()

    for _ in range(10):  # guard against cycles
        try:
            subject_hash = current.subject.hashable
        except Exception:
            break
        if subject_hash in seen:
            break
        seen.add(subject_hash)

        # OCSP and CRL only attached to the end-entity (index 0)
        is_first = len(chain) == 0
        serial: int = -1
        try:
            serial = current["tbs_certificate"]["serial_number"].native
        except Exception:
            pass
        ocsp = ocsp_by_serial.get(serial) if is_first else None
        crl  = crl_info if is_first else None

        chain.append(_cert_to_info(current, source=CertSource.EMBEDDED,
                                   ocsp=ocsp, crl=crl))

        try:
            if current.subject == current.issuer:
                break  # self-signed root reached
        except Exception:
            break

        try:
            issuer = by_subject.get(current.issuer.hashable)
        except Exception:
            issuer = None

        if issuer is None:
            # Chain incomplete: add a placeholder so the UI shows the gap
            try:
                issuer_name = current.issuer.human_friendly
            except Exception:
                issuer_name = "?"
            try:
                issuer_hashable = current.issuer.dump()
            except Exception:
                issuer_hashable = None
            chain.append(CertInfo(
                subject=issuer_name,
                issuer="?",
                valid_from=datetime.min,
                valid_until=datetime.max,
                source=CertSource.NOT_FOUND,
                status=ValidationStatus.NOT_CHECKED,
                is_root=False,   # unknown – could be intermediate or root
                is_ca=True,
                subject_hashable=issuer_hashable,
            ))
            break
        current = issuer

    return chain


# ── OCSP / DSS helpers ────────────────────────────────────────────────────────

def _parse_ocsp_der(der: bytes) -> Optional[tuple[int, OCSPInfo]]:
    """Parse one OCSP response DER blob.

    Returns ``(serial, OCSPInfo)`` on success or ``None`` on any error.
    The serial number identifies the subject certificate this response covers.
    """
    try:
        from asn1crypto import ocsp as asn1_ocsp
        resp = asn1_ocsp.OCSPResponse.load(der)
        if resp["response_status"].native != "successful":
            return None
        basic = resp["response_bytes"]["response"].parsed
        produced: datetime = basic["tbs_response_data"]["produced_at"].native
        for r in basic["tbs_response_data"]["responses"]:
            cs_name = r["cert_status"].name
            serial: int = r["cert_id"]["serial_number"].native
            return serial, OCSPInfo(
                produced_at=produced,
                cert_status=cs_name,
                source=CertSource.EMBEDDED,
                status=_ocsp_cert_status_to_vs(cs_name),
            )
    except Exception:
        pass
    return None


def _extract_dss(reader) -> tuple[list, dict[int, OCSPInfo], Optional[CRLInfo]]:
    """Read the PDF DSS dictionary and return its contents.

    Returns:
        ``(cert_pool, ocsp_by_serial, crl_info)`` where:
        - *cert_pool*      – list of asn1crypto Certificates from ``/Certs``
        - *ocsp_by_serial* – ``{serial: OCSPInfo}`` from ``/OCSPs``
        - *crl_info*       – ``CRLInfo`` if ``/CRLs`` is present, else ``None``
    """
    from asn1crypto import x509 as asn1_x509

    cert_pool: list = []
    ocsp_by_serial: dict[int, OCSPInfo] = {}
    crl_info: Optional[CRLInfo] = None

    try:
        root = reader.root
        dss_ref = root.get("/DSS")
        if dss_ref is None:
            return cert_pool, ocsp_by_serial, crl_info
        dss = dss_ref.get_object()

        # DSS certificates
        certs_ref = dss.get("/Certs")
        if certs_ref is not None:
            for ref in certs_ref.get_object():
                try:
                    der = ref.get_object().data
                    cert_pool.append(asn1_x509.Certificate.load(der))
                except Exception:
                    pass

        # OCSP responses
        ocsps_ref = dss.get("/OCSPs")
        if ocsps_ref is not None:
            for ref in ocsps_ref.get_object():
                try:
                    der = ref.get_object().data
                    result = _parse_ocsp_der(der)
                    if result is not None:
                        serial, info = result
                        ocsp_by_serial[serial] = info
                except Exception:
                    pass

        # CRLs – only note presence; detailed parsing deferred
        crls_ref = dss.get("/CRLs")
        if crls_ref is not None and len(crls_ref.get_object()) > 0:
            crl_info = CRLInfo(
                source=CertSource.EMBEDDED,
                status=ValidationStatus.NOT_CHECKED,
            )

    except Exception:
        pass

    return cert_pool, ocsp_by_serial, crl_info


# ── Timestamp helpers ─────────────────────────────────────────────────────────

def _extract_tst_info(signed_data) -> tuple[Optional[datetime], str]:
    """Return ``(gen_time, policy_oid)`` from a CMS SignedData wrapping TSTInfo."""
    try:
        from asn1crypto import tsp as asn1_tsp
        raw = signed_data["encap_content_info"]["content"].contents
        tst = asn1_tsp.TSTInfo.load(raw)
        gen_time: datetime = tst["gen_time"].native
        try:
            policy = tst["policy"].dotted
        except Exception:
            policy = ""
        return gen_time, policy
    except Exception:
        return None, ""


def _embedded_tsa_token(sig, dss_pool: list) -> Optional[TimestampInfo]:
    """Extract the RFC-3161 timestamp token embedded inside a regular signature.

    This token lives in the ``id-aa-signatureTimeStampToken`` unsigned attribute
    of the CMS ``SignerInfo``.  Returns ``None`` if no such token is present.

    Args:
        sig:      pyhanko ``EmbeddedPdfSignature`` object.
        dss_pool: Certificate pool from the document DSS, used to complete the
                  TSA chain when the TSA token itself does not include all
                  intermediates or the root (e.g. root added later by LTA).
    """
    try:
        from asn1crypto import cms as asn1_cms, x509 as asn1_x509

        unsigned_attrs = sig.signed_data["signer_infos"][0]["unsigned_attrs"]
        if not unsigned_attrs:
            return None

        TST_OID = "1.2.840.113549.1.9.16.2.14"
        for attr in unsigned_attrs:
            try:
                if attr["type"].dotted != TST_OID:
                    continue
                # attr['values'] is a SET; the token is the first element (ContentInfo)
                token_ci = attr["values"][0]
                ts_sd = token_ci["content"]
                gen_time, policy = _extract_tst_info(ts_sd)
                if gen_time is None:
                    continue
                # TSA signing certificate
                tsa_subject = "?"
                tsa_chain: list[CertInfo] = []
                try:
                    tsa_certs = list(ts_sd["certificates"])
                    if tsa_certs:
                        tsa_cert = tsa_certs[0].chosen
                        tsa_subject = _subject_cn(tsa_cert)
                        # Merge token-internal certs with DSS pool so that
                        # intermediates and the root added by a later LTA
                        # revision are also available for chain building.
                        all_tsa_certs = [c.chosen for c in tsa_certs] + dss_pool
                        tsa_chain = _build_chain(tsa_cert, all_tsa_certs, {}, None)
                except Exception:
                    pass
                return TimestampInfo(
                    time=gen_time,
                    tsa_subject=tsa_subject,
                    policy_oid=policy,
                    source=CertSource.EMBEDDED,
                    status=ValidationStatus.NOT_CHECKED,
                    cert_chain=tsa_chain,
                    chain_status=_compute_chain_status(tsa_chain, gen_time),
                )
            except Exception:
                continue
    except Exception:
        pass
    return None


# ── Crypto integrity check ────────────────────────────────────────────────────

def _check_crypto_integrity(sig, is_timestamp: bool = False) -> ValidationStatus:
    """Verify the PDF byte-range digest and CMS signature math.

    Uses ``validate_pdf_timestamp`` for document timestamps and
    ``validate_pdf_signature`` for regular signatures.  No validation context
    is passed so only the CMS structure (byte-range hash + signature math) is
    checked; chain and revocation validation are skipped.

    Returns ``NOT_CHECKED`` if pyhanko is unavailable or the call fails
    unexpectedly.
    """
    import logging
    _pyhanko_log = logging.getLogger("pyhanko")
    _cv_log = logging.getLogger("pyhanko_certvalidator")
    prev_pyhanko = _pyhanko_log.level
    prev_cv = _cv_log.level
    try:
        _pyhanko_log.setLevel(logging.CRITICAL)
        _cv_log.setLevel(logging.CRITICAL)
        if is_timestamp:
            from pyhanko.sign.validation import validate_pdf_timestamp
            status = validate_pdf_timestamp(sig)
        else:
            from pyhanko.sign.validation import validate_pdf_signature
            status = validate_pdf_signature(sig)
        # ``intact`` = byte-range hash matches (no tampering).
        # ``valid``  = CMS signature math verifies.
        # Both must be True for a cryptographically sound signature.
        return ValidationStatus.VALID if (status.intact and status.valid) else ValidationStatus.INVALID
    except Exception:
        return ValidationStatus.NOT_CHECKED
    finally:
        _pyhanko_log.setLevel(prev_pyhanko)
        _cv_log.setLevel(prev_cv)


# ── SignatureInfo builders ────────────────────────────────────────────────────

def _build_sig_info(sig, dss_pool: list,
                    ocsp_by_serial: dict[int, OCSPInfo],
                    crl_info: Optional[CRLInfo]) -> SignatureInfo:
    """Build a ``SignatureInfo`` for one regular (QES) embedded signature."""
    field_name = sig.field_name or "?"
    signing_time: Optional[datetime] = None
    try:
        signing_time = sig.self_reported_timestamp
    except Exception:
        pass

    # Signer certificate
    signer_cert = None
    try:
        signer_cert = sig.signer_cert
    except Exception:
        pass
    try:
        signer_subject = signer_cert.subject.human_friendly if signer_cert else field_name
    except Exception:
        signer_subject = _subject_cn(signer_cert) if signer_cert else field_name

    # Collect all available certs: CMS container + DSS pool
    cms_certs: list = []
    try:
        for c in sig.signed_data["certificates"]:
            try:
                cms_certs.append(c.chosen)
            except Exception:
                pass
    except Exception:
        pass

    all_certs = cms_certs + dss_pool
    chain: list[CertInfo] = []
    if signer_cert is not None:
        chain = _build_chain(signer_cert, all_certs, ocsp_by_serial, crl_info)

    # Embedded TSA timestamp token (optional, inside the signature)
    tsa_ts = _embedded_tsa_token(sig, dss_pool)

    # Crypto integrity (byte range hash)
    crypto_status = _check_crypto_integrity(sig)

    # Revocation: determined from embedded OCSP, otherwise NOT_CHECKED
    rev_status = ValidationStatus.NOT_CHECKED
    if chain and chain[0].ocsp is not None:
        rev_status = chain[0].ocsp.status

    overall = _worst(crypto_status, ValidationStatus.NOT_CHECKED, rev_status)

    return SignatureInfo(
        field_name=field_name,
        sig_type="signature",
        signer_subject=signer_subject,
        signing_time=tsa_ts.time if tsa_ts else signing_time,
        timestamp=tsa_ts,
        cert_chain=chain,
        crypto_status=crypto_status,
        chain_status=_compute_chain_status(chain, tsa_ts.time if tsa_ts else signing_time),
        revocation_status=rev_status,
        status=overall,
    )


def _build_doc_ts_info(ts, dss_pool: list) -> SignatureInfo:
    """Build a ``SignatureInfo`` for one LTA document timestamp."""
    field_name = ts.field_name or "?"
    gen_time: Optional[datetime] = None
    policy = ""
    try:
        gen_time, policy = _extract_tst_info(ts.signed_data)
    except Exception:
        pass
    if gen_time is None:
        try:
            gen_time = ts.self_reported_timestamp
        except Exception:
            pass

    # TSA signer certificate
    tsa_cert = None
    try:
        tsa_cert = ts.signer_cert
    except Exception:
        pass
    try:
        tsa_subject = tsa_cert.subject.human_friendly if tsa_cert else field_name
    except Exception:
        tsa_subject = _subject_cn(tsa_cert) if tsa_cert else field_name

    # Certificate chain
    tsa_cms_certs: list = []
    try:
        for c in ts.signed_data["certificates"]:
            try:
                tsa_cms_certs.append(c.chosen)
            except Exception:
                pass
    except Exception:
        pass
    all_certs = tsa_cms_certs + dss_pool
    chain: list[CertInfo] = []
    if tsa_cert is not None:
        chain = _build_chain(tsa_cert, all_certs, {}, None)

    tsa_chain_status = _compute_chain_status(chain, gen_time)
    ts_info = TimestampInfo(
        time=gen_time or datetime.min,
        tsa_subject=tsa_subject,
        policy_oid=policy,
        source=CertSource.EMBEDDED,
        status=ValidationStatus.NOT_CHECKED,
        cert_chain=chain,
        chain_status=tsa_chain_status,
    )

    crypto_status = _check_crypto_integrity(ts, is_timestamp=True)

    return SignatureInfo(
        field_name=field_name,
        sig_type="doc_timestamp",
        signer_subject=tsa_subject,
        signing_time=gen_time,
        timestamp=ts_info,
        cert_chain=chain,
        crypto_status=crypto_status,
        chain_status=tsa_chain_status,
        revocation_status=ValidationStatus.NOT_CHECKED,
        status=crypto_status,
    )


# ── Unsigned revision classification ─────────────────────────────────────────

def _classify_unsigned_revision(reader, idx: int) -> list:
    """Return category tags describing what changed in an unsigned revision.

    Tags: "original", "form_fields", "annotations", "dss", "metadata",
    "unknown".  Multiple tags are possible (e.g. ["dss", "metadata"]).

    Uses pyhanko's private ``_xref_sections`` to get the set of objects
    changed in this revision, then checks known PDF structures.

    Args:
        reader: ``PdfFileReader`` for the full document.
        idx:    0-based revision index (= pyhanko signed_revision value).
    """
    if idx == 0:
        return ["original"]

    try:
        section = reader.xrefs._xref_sections[idx]
        changed_obj_nums = {ref[0] for ref in section.xref_data.explicit_refs_in_revision}
    except Exception:
        return ["unknown"]

    if not changed_obj_nums:
        return ["unknown"]

    found: list = []

    try:
        from pyhanko.pdf_utils.generic import Reference
        resolver = reader.get_historical_resolver(idx)

        for obj_num in changed_obj_nums:
            try:
                obj = resolver.get_object(Reference(obj_num, 0))
                if not hasattr(obj, "keys"):
                    continue
                keys = set(obj.keys())

                # XMP metadata stream: /Type /Metadata + /Subtype /XML
                if ("/Type" in keys and "/Subtype" in keys
                        and str(obj.raw_get("/Type")) == "/Metadata"
                        and str(obj.raw_get("/Subtype")) == "/XML"
                        and "metadata" not in found):
                    found.append("metadata")
                    continue

                # DSS dictionary: top-level keys /Certs and/or /OCSPs and/or /CRLs
                if (("/Certs" in keys or "/OCSPs" in keys or "/CRLs" in keys)
                        and "dss" not in found):
                    found.append("dss")
                    continue

                # Widget annotation (form field): has /FT (field type)
                if "/FT" in keys and "form_fields" not in found:
                    found.append("form_fields")
                    continue

                # Other annotation: /Rect + /Subtype but no /FT
                if ("/Rect" in keys and "/Subtype" in keys
                        and "/FT" not in keys
                        and "annotations" not in found):
                    found.append("annotations")

            except Exception:
                continue

    except Exception:
        pass

    return found if found else ["unknown"]


# ── PAdES profile ────────────────────────────────────────────────────────────

def _calc_pades_profile(sig: SignatureInfo,
                         has_dss_data: bool,
                         doc_ts_revisions: set,
                         this_rev: int) -> PadesProfile:
    """Determine the PAdES conformance level from embedded data (Phase 1).

    Args:
        sig:              The signature to classify.
        has_dss_data:     True if the document DSS contains any entries.
        doc_ts_revisions: Set of PDF revision numbers that carry a document
                          timestamp (LTA).
        this_rev:         PDF revision number of *sig*.

    Note: ``has_dss_data`` is document-global; without ``/VRI`` it cannot be
    verified that the DSS entries specifically belong to *this* signature.
    This is an acceptable heuristic for Phase 1.
    """
    if sig.sig_type == "doc_timestamp":
        return PadesProfile.LTA  # by convention – see module docstring

    has_tsa_token = sig.timestamp is not None
    if not has_tsa_token:
        return PadesProfile.B

    if not has_dss_data:
        return PadesProfile.T

    # LTA: at least one document timestamp in a later revision covers this one
    has_lta_after = any(r > this_rev for r in doc_ts_revisions)
    return PadesProfile.LTA if has_lta_after else PadesProfile.LT


# ── Public API ────────────────────────────────────────────────────────────────

def extract(pdf_bytes: bytes) -> DocumentValidation:
    """Phase 1: extract all validation data from *pdf_bytes* without network access.

    Opens the PDF in memory, reads all embedded signatures, document
    timestamps, and the DSS dictionary, and returns a populated
    ``DocumentValidation``.  Status fields that require network access
    (trust chain, online OCSP) are left as ``NOT_CHECKED``.

    Never raises; any unrecoverable error returns an empty
    ``DocumentValidation`` with ``overall_status = NOT_CHECKED``.
    """
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
    except ImportError:
        return DocumentValidation()

    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes), strict=False)
    except Exception:
        return DocumentValidation()

    # DSS dictionary (LTA validation data embedded during signing)
    dss_pool, ocsp_by_serial, crl_info = _extract_dss(reader)
    has_dss = bool(dss_pool or ocsp_by_serial or crl_info)

    # Collect all signatures sorted by PDF revision (oldest first)
    entries: list[tuple[int, SignatureInfo]] = []

    # docMDP level from the first (certifying) signature, if any.
    # EmbeddedPdfSignature.docmdp_level returns an MDPPerm enum or None.
    docmdp_level: Optional[int] = None
    try:
        for sig in reader.embedded_regular_signatures:
            try:
                si = _build_sig_info(sig, dss_pool, ocsp_by_serial,
                                     crl_info)
                entries.append((sig.signed_revision, si))
                if docmdp_level is None and sig.docmdp_level is not None:
                    docmdp_level = sig.docmdp_level.value
            except Exception:
                pass
    except Exception:
        pass

    is_lta = False
    try:
        for ts in reader.embedded_timestamp_signatures:
            try:
                si = _build_doc_ts_info(ts, dss_pool)
                entries.append((ts.signed_revision, si))
                is_lta = True
            except Exception:
                pass
    except Exception:
        pass

    # Byte-Grenzen der Revisionen: Position nach %%EOF des jeweiligen
    # xref-Abschnitts.  end_location zeigt auf den Beginn des trailer-Keywords;
    # %%EOF folgt danach.  Wir suchen das erste %%EOF nach end_location,
    # damit fitz beim Schneiden an dieser Stelle ein vollständiges PDF erhält
    # (inkl. Trailer und EOF-Marker) und die korrekte Revision rendert.
    revision_end_offsets: list[int] = []
    try:
        for sec in reader.xrefs._xref_sections:
            start = sec.meta_info.end_location
            m = re.search(b"%%EOF[\\r\\n]*", pdf_bytes[start:start + 4096])
            if m:
                revision_end_offsets.append(start + m.end())
            else:
                revision_end_offsets.append(start)
    except Exception:
        revision_end_offsets = []

    entries.sort(key=lambda x: x[0])

    # Total PDF revisions (including unsigned ones).
    # Linearisierte PDFs haben eine zweite xref-Sektion (Hint) am Dateianfang,
    # die pyhanko als eigene Revision zählt.  Diese Sektion ist kein echter
    # inkrementeller Update: ihr Byte-Offset ist kleiner als der der ersten
    # Sektion.  Wir erkennen und entfernen solche Artefakte anhand nicht-
    # monoton steigender revision_end_offsets.
    if revision_end_offsets:
        filtered_offsets: list[int] = []
        filtered_indices: list[int] = []  # 0-based xref-section indices to keep
        for i, off in enumerate(revision_end_offsets):
            if filtered_offsets and off <= filtered_offsets[-1]:
                # Offset nicht größer als der vorherige → Linearisierungs-Hint
                continue
            filtered_offsets.append(off)
            filtered_indices.append(i)
        revision_end_offsets = filtered_offsets
        total_pdf_revisions = len(filtered_indices)
        # Signatur-Revisionen auf neue Indizes umrechnen
        old_to_new = {old: new for new, old in enumerate(filtered_indices)}
        entries = [(old_to_new[r], si) for r, si in entries if r in old_to_new]
        sig_by_rev_new: dict[int, SignatureInfo] = {}
        for rev_num, si in entries:
            sig_by_rev_new[rev_num] = si
    else:
        total_pdf_revisions = max((r for r, _ in entries), default=1)
        try:
            total_pdf_revisions = reader.xrefs.total_revisions
        except Exception:
            pass
        sig_by_rev_new = {r: si for r, si in entries}

    sig_by_rev = sig_by_rev_new

    # Set of revision numbers that carry a document timestamp (for LTA detection)
    doc_ts_revs: set[int] = {
        rev_num for rev_num, si in sig_by_rev.items() if si.sig_type == "doc_timestamp"
    }

    # Assign PAdES profile to each regular signature
    for rev_num, si in sig_by_rev.items():
        si.pades_profile = _calc_pades_profile(si, has_dss, doc_ts_revs, rev_num)

    # Build RevisionInfo for every PDF revision (signed and unsigned).
    # signed_revision from pyhanko is 0-based (0 = first xref section).
    # We display revision numbers 1-based to the user (idx + 1).
    revisions: list[RevisionInfo] = []
    for idx in range(total_pdf_revisions):
        sig_info = sig_by_rev.get(idx)
        if sig_info is None:
            change_types = _classify_unsigned_revision(reader, idx)
        else:
            change_types = []
        revisions.append(RevisionInfo(
            revision_number=idx + 1,
            total_revisions=total_pdf_revisions,
            description=sig_info.signer_subject if sig_info else "",
            date=sig_info.signing_time if sig_info else None,
            signed_by=sig_info,
            status=sig_info.status if sig_info else ValidationStatus.NOT_CHECKED,
            change_types=change_types,
        ))

    signed_revisions = [r for r in revisions if r.signed_by is not None]
    overall = (_worst(*[r.status for r in signed_revisions])
               if signed_revisions else ValidationStatus.NOT_CHECKED)

    return DocumentValidation(
        revisions=revisions,
        overall_status=overall,
        has_dss=has_dss,
        is_lta=is_lta,
        revision_end_offsets=revision_end_offsets,
        docmdp_level=docmdp_level,
    )
