# SPDX-License-Identifier: GPL-3.0-or-later
"""Security tests for certificate chain validation.

Verifies that forged, expired, and untrusted certificate chains are never
classified as VALID.  These tests are the automated equivalent of the manual
test PDFs in tools/create_test_pdfs.py.

## What is tested

| Test                       | Security property                                      |
|----------------------------|--------------------------------------------------------|
| test_untrusted_root        | Unknown CA root → chain must NOT be VALID              |
| test_spoofed_root_dn       | Same DN as certifi root, different key → NOT CERTIFI   |
| test_expired_signing_cert  | Expired leaf cert → status must be INVALID             |
| test_expired_ca_cert       | Expired intermediate CA → status must be INVALID       |
| test_self_signed           | Self-signed cert, not in certifi → NOT VALID           |
| test_tampered_content      | Bytes modified after signing → crypto_status INVALID   |

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
    """An expired leaf (signing) certificate must never produce a VALID result.

    Note: with an untrusted root, pyhanko returns UNKNOWN (not INVALID) because
    it cannot verify the chain to a trusted anchor.  UNKNOWN is correct here —
    the certificate is not trusted and must not show as VALID.
    """
    doc = _run_validation((pdf_dir / "03_expired_signing_cert.pdf").read_bytes())
    sig = _first_sig(doc)
    assert sig.status != ValidationStatus.VALID, (
        f"Expired signing cert must NOT be VALID, got status={sig.status}"
    )
    # Additionally confirm the leaf cert is recognised as expired
    leaf = sig.cert_chain[0] if sig.cert_chain else None
    if leaf is not None:
        from datetime import datetime, timezone
        now = datetime.now(tz=timezone.utc)
        assert leaf.valid_until < now, (
            f"Expected expired cert, but valid_until={leaf.valid_until} is in the future"
        )


def test_expired_ca_cert_not_valid(pdf_dir):
    """An expired intermediate CA certificate must never produce a VALID result.

    Note: same caveat as for the expired leaf — with an untrusted root pyhanko
    returns UNKNOWN.  UNKNOWN is the safe, correct result.
    """
    doc = _run_validation((pdf_dir / "04_expired_ca_cert.pdf").read_bytes())
    sig = _first_sig(doc)
    assert sig.status != ValidationStatus.VALID, (
        f"Expired CA cert must NOT be VALID, got status={sig.status}"
    )
    # Confirm that the intermediate CA cert is recognised as expired
    ca_certs = [c for c in sig.cert_chain if c.is_ca and not c.is_root]
    expired_cas = [c for c in ca_certs
                   if c.valid_until < __import__("datetime").datetime.now(
                       tz=__import__("datetime").timezone.utc)]
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
