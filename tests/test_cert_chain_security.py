# SPDX-License-Identifier: GPL-3.0-or-later
"""Security tests for certificate chain validation.

Verifies that forged, expired, and untrusted certificate chains are never
classified as VALID.  These tests are the automated equivalent of the manual
test PDFs in tools/create_test_pdfs.py.

## What is tested

| Test                       | Security property                                      |
|----------------------------|--------------------------------------------------------|
| test_untrusted_root            | Unknown CA root → chain must NOT be VALID              |
| test_spoofed_root_dn           | Same DN as certifi root, different key → NOT CERTIFI   |
| test_expired_signing_cert      | Expired leaf cert → INVALID in Phase 1 AND Phase 2    |
| test_expired_ca_cert           | Expired CA cert → INVALID in Phase 1 AND Phase 2      |
| test_self_signed               | Self-signed cert, not in certifi → NOT VALID           |
| test_tampered_content          | Bytes modified after signing → crypto_status INVALID   |
| test_phase2_preserves_invalid  | Phase 2 must never downgrade INVALID to UNKNOWN        |
| test_multi_warning_red_yellow  | Tampered + post-sig → crypto INVALID + post-sig warning|
| test_two_yellow_warnings       | Between-sig + post-last-sig → two separate warnings    |

Phase 2 runs synchronously (worker.run() called directly) with
auto_fetch=False so the tests are deterministic and require no network access.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Qt infrastructure is required even for headless validation (ValidationWorker
# inherits from QThread).  Create the application object before any Qt imports.
from PyQt6.QtCore import QCoreApplication
_qt_app = QCoreApplication.instance() or QCoreApplication(sys.argv)

import pytest

# Make sure the project root and tools/ are importable.
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "tools"))

from pdf_signer.validation_extractor import extract
from pdf_signer.validation_worker import ValidationWorker
from pdf_signer.validation_result import CertSource, DocumentValidation, SignatureInfo, ValidationStatus

import create_test_pdfs as gen


# ── helpers ───────────────────────────────────────────────────────────────────

def _run_phase1(pdf_bytes: bytes) -> DocumentValidation:
    """Run Phase 1 only (offline, no network) and return the DocumentValidation."""
    return extract(pdf_bytes)


def _run_validation(pdf_bytes: bytes, auto_fetch: bool = False) -> DocumentValidation:
    """Run Phase 1 + Phase 2 synchronously and return the DocumentValidation."""
    doc = extract(pdf_bytes)
    worker = ValidationWorker(doc, pdf_bytes, auto_fetch=auto_fetch)
    worker.run()   # synchronous – no QThread.start() needed for tests
    return doc


def _first_sig(doc: DocumentValidation) -> SignatureInfo:
    """Return the first signature found in doc (fails the test if absent)."""
    for rev in doc.revisions:
        if rev.signed_by and rev.signed_by.sig_type == "signature":
            return rev.signed_by
    pytest.fail("No signature found in document")


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def pdf_dir(tmp_path_factory):
    """Generate all test PDFs once per test session."""
    out = tmp_path_factory.mktemp("cert_security_pdfs")
    gen.gen_01_untrusted_root(out)
    gen.gen_02_spoofed_root_dn(out)
    gen.gen_03_expired_signing_cert(out)
    gen.gen_04_expired_ca_cert(out)
    gen.gen_05_self_signed(out)
    gen.gen_06_tampered_content(out)
    gen.gen_07_tampered_plus_post_sig(out)
    gen.gen_08_two_yellow_warnings(out)
    return out


# ── tests ─────────────────────────────────────────────────────────────────────

def test_untrusted_root_not_valid(pdf_dir):
    """Signature with a completely unknown root CA must not validate as VALID."""
    doc = _run_validation((pdf_dir / "01_untrusted_root.pdf").read_bytes())
    sig = _first_sig(doc)
    assert sig.chain_status != ValidationStatus.VALID, (
        f"Untrusted root chain must not be VALID, got chain_status={sig.chain_status}"
    )


def test_spoofed_root_dn_not_trusted(pdf_dir):
    """SECURITY: A cert with the same DN as a certifi root but a different key
    must never be accepted as a trusted root.

    This test would fail if trust confirmation used only the Subject DN instead
    of the full certificate fingerprint (SHA-256 of DER bytes).
    """
    doc = _run_validation((pdf_dir / "02_spoofed_root_dn.pdf").read_bytes())
    sig = _first_sig(doc)
    assert sig.chain_status != ValidationStatus.VALID, (
        "Spoofed root (same DN as certifi root, different key) "
        f"must NOT be VALID, got chain_status={sig.chain_status}"
    )
    root_certs = [c for c in sig.cert_chain if c.is_root]
    for root in root_certs:
        assert root.source != CertSource.CERTIFI, (
            f"Spoofed root '{root.subject}' must NOT have source CERTIFI, "
            f"got source={root.source}"
        )


def test_expired_signing_cert_not_valid(pdf_dir):
    """An expired leaf (signing) certificate must produce INVALID in both phases.

    Regression for two bugs:
    - Bug 1: chain_status was missing from the overall status calculation in
      Phase 1, so sig.status was NOT_CHECKED even though chain_status=INVALID.
    - Bug 2: Phase 2 unconditionally set chain_status=UNKNOWN (untrusted root),
      overwriting the INVALID set by Phase 1 (expired cert).
    Both phases must independently produce INVALID, not just != VALID.
    """
    from datetime import datetime, timezone
    pdf = (pdf_dir / "03_expired_signing_cert.pdf").read_bytes()

    # Phase 1 alone must already report INVALID
    doc1 = _run_phase1(pdf)
    sig1 = _first_sig(doc1)
    assert sig1.chain_status == ValidationStatus.INVALID, (
        f"Phase 1: expired signing cert must have chain_status=INVALID, "
        f"got {sig1.chain_status}"
    )
    assert sig1.status == ValidationStatus.INVALID, (
        f"Phase 1: expired signing cert must have overall status=INVALID, "
        f"got {sig1.status}"
    )

    # Phase 2 must NOT downgrade INVALID to UNKNOWN
    doc2 = _run_validation(pdf)
    sig2 = _first_sig(doc2)
    assert sig2.chain_status == ValidationStatus.INVALID, (
        f"Phase 2: expired cert chain_status must stay INVALID (not be overwritten "
        f"by UNKNOWN from untrusted root), got {sig2.chain_status}"
    )
    assert sig2.status == ValidationStatus.INVALID, (
        f"Phase 2: expired signing cert overall status must be INVALID, "
        f"got {sig2.status}"
    )

    # Sanity: confirm the leaf cert is actually expired
    leaf = sig2.cert_chain[0] if sig2.cert_chain else None
    assert leaf is not None and leaf.valid_until < datetime.now(tz=timezone.utc), (
        f"Expected expired leaf cert, valid_until={getattr(leaf, 'valid_until', '?')}"
    )


def test_expired_ca_cert_not_valid(pdf_dir):
    """An expired intermediate CA must produce INVALID in both phases.

    Same regression coverage as test_expired_signing_cert_not_valid but for
    an expired CA cert instead of an expired leaf cert.
    """
    from datetime import datetime, timezone
    pdf = (pdf_dir / "04_expired_ca_cert.pdf").read_bytes()

    # Phase 1 alone must already report INVALID
    doc1 = _run_phase1(pdf)
    sig1 = _first_sig(doc1)
    assert sig1.chain_status == ValidationStatus.INVALID, (
        f"Phase 1: expired CA cert must have chain_status=INVALID, "
        f"got {sig1.chain_status}"
    )
    assert sig1.status == ValidationStatus.INVALID, (
        f"Phase 1: expired CA cert must have overall status=INVALID, "
        f"got {sig1.status}"
    )

    # Phase 2 must NOT downgrade INVALID to UNKNOWN
    doc2 = _run_validation(pdf)
    sig2 = _first_sig(doc2)
    assert sig2.chain_status == ValidationStatus.INVALID, (
        f"Phase 2: expired CA chain_status must stay INVALID, got {sig2.chain_status}"
    )
    assert sig2.status == ValidationStatus.INVALID, (
        f"Phase 2: expired CA cert overall status must be INVALID, "
        f"got {sig2.status}"
    )

    # Sanity: confirm the intermediate CA cert is actually expired
    ca_certs = [c for c in sig2.cert_chain if c.is_ca and not c.is_root]
    expired_cas = [c for c in ca_certs
                   if c.valid_until < datetime.now(tz=timezone.utc)]
    assert expired_cas, (
        f"Expected at least one expired CA cert in chain, got: "
        f"{[(c.subject, c.valid_until) for c in ca_certs]}"
    )


def test_self_signed_not_valid(pdf_dir):
    """A self-signed certificate not present in certifi must not be VALID."""
    doc = _run_validation((pdf_dir / "05_self_signed.pdf").read_bytes())
    sig = _first_sig(doc)
    assert sig.chain_status != ValidationStatus.VALID, (
        f"Self-signed (not in certifi) chain must not be VALID, "
        f"got chain_status={sig.chain_status}"
    )


def test_tampered_content_crypto_invalid(pdf_dir):
    """Content modified after signing must produce crypto_status=INVALID."""
    doc = _run_validation((pdf_dir / "06_tampered_content.pdf").read_bytes())
    sig = _first_sig(doc)
    assert sig.crypto_status == ValidationStatus.INVALID, (
        f"Tampered content must have crypto_status=INVALID, "
        f"got crypto_status={sig.crypto_status}"
    )


def test_phase2_preserves_invalid(pdf_dir):
    """Regression: Phase 2 must never overwrite an INVALID chain_status with UNKNOWN.

    Previously, the else-branch in _validate_one unconditionally set
    chain_status=UNKNOWN when pyhanko returned status.trusted=False, even if
    Phase 1 had already determined chain_status=INVALID (e.g. expired cert).
    This test verifies that the worst-of logic is applied instead.
    """
    for filename in ("03_expired_signing_cert.pdf", "04_expired_ca_cert.pdf"):
        pdf = (pdf_dir / filename).read_bytes()
        doc1 = _run_phase1(pdf)
        sig1 = _first_sig(doc1)
        phase1_chain = sig1.chain_status

        doc2 = _run_validation(pdf)
        sig2 = _first_sig(doc2)
        phase2_chain = sig2.chain_status

        # Phase 2 must never produce a status better than Phase 1
        from pdf_signer.validation_extractor import _STATUS_PRIORITY
        assert (_STATUS_PRIORITY[phase2_chain] <= _STATUS_PRIORITY[phase1_chain]), (
            f"{filename}: Phase 2 chain_status ({phase2_chain}) is better than "
            f"Phase 1 chain_status ({phase1_chain}) – Phase 2 must not upgrade status"
        )
        assert phase2_chain == ValidationStatus.INVALID, (
            f"{filename}: expected INVALID after Phase 2, got {phase2_chain}"
        )


def test_multi_warning_red_yellow(pdf_dir):
    """Tampered content + unsigned post-sig annotation → two independent warnings.

    Verifies that crypto_status=INVALID and a post-signature modification are
    both detected simultaneously (multi-warning scenario).
    """
    from pdf_signer.validation_dialog import check_post_sig_warnings

    doc = _run_validation((pdf_dir / "07_tampered_plus_post_sig.pdf").read_bytes())
    sig = _first_sig(doc)

    assert sig.crypto_status == ValidationStatus.INVALID, (
        f"Tampered content must have crypto_status=INVALID, got {sig.crypto_status}"
    )

    post_last, between = check_post_sig_warnings(doc.revisions)
    assert post_last, (
        f"Expected post-signature modification warning, got post_last={post_last}"
    )
    assert "annotations" in post_last, (
        f"Expected 'annotations' in post_last warnings, got {post_last}"
    )


def test_two_yellow_warnings(pdf_dir):
    """Between-sig + post-last-sig annotations → both warning categories active."""
    from pdf_signer.validation_dialog import check_post_sig_warnings

    doc = _run_validation((pdf_dir / "08_two_yellow_warnings.pdf").read_bytes())
    post_last, between = check_post_sig_warnings(doc.revisions)

    assert post_last, (
        f"Expected post-last-sig warning, got post_last={post_last}"
    )
    assert between, (
        f"Expected between-sig warning, got between={between}"
    )
    assert "annotations" in post_last, (
        f"Expected 'annotations' in post_last, got {post_last}"
    )
    assert "annotations" in between, (
        f"Expected 'annotations' in between, got {between}"
    )
