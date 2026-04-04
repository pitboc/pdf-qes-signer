#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate test PDFs with manipulated certificate chains for security testing.

Usage:
    python tools/create_test_pdfs.py [output_dir]

Default output: /tmp/pdf_signer_test/

## Test scenarios

Each test PDF documents its EXPECTED validation result so the manual tester
knows what the application should show.

| File                          | Expected chain_status | Notes                          |
|-------------------------------|----------------------|--------------------------------|
| 01_untrusted_root.pdf         | UNKNOWN (yellow)     | Fake CA root, not in certifi   |
| 02_spoofed_root_dn.pdf        | UNKNOWN (yellow)     | Same DN as certifi root, diff key |
| 03_expired_signing_cert.pdf   | INVALID (red)        | Signer cert expired            |
| 04_expired_ca_cert.pdf        | INVALID (red)        | Intermediate CA cert expired   |
| 05_self_signed.pdf            | UNKNOWN (yellow)     | Leaf is self-signed            |
| 06_tampered_content.pdf       | INVALID crypto (red) | Content changed after signing  |

## Security note

02_spoofed_root_dn.pdf is the most important test: it verifies that the
validator does NOT classify a fake cert as trusted just because it has the
same Subject DN as a real certifi root.  Trust confirmation MUST use the
full certificate fingerprint (SHA-256 of DER bytes), not the DN alone.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Certificate creation helpers ─────────────────────────────────────────────

def _build_chain(
    common_name: str,
    org: str = "Test Org",
    country: str = "DE",
    ca_name: str = "Test Root CA",
    ca_org: str = "Test CA Org",
    not_valid_after_delta: timedelta = timedelta(days=365),
    signer_not_valid_after_delta: timedelta = timedelta(days=365),
    intermediate_not_valid_after_delta: timedelta = timedelta(days=3650),
) -> tuple:
    """Return (root_cert, intermediate_cert, signer_cert, signer_key) as
    cryptography objects for a 3-level chain.

    All date offsets are relative to *now*.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.now(tz=timezone.utc)

    def _key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _name(cn, o, c):
        return x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, c),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])

    # Root CA
    root_key = _key()
    root_name = _name(ca_name, ca_org, country)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + not_valid_after_delta)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
                       critical=False)
        .sign(root_key, hashes.SHA256())
    )

    # Intermediate CA
    int_key = _key()
    int_name = _name(f"{ca_name} Intermediate", ca_org, country)
    int_cert = (
        x509.CertificateBuilder()
        .subject_name(int_name)
        .issuer_name(root_name)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + intermediate_not_valid_after_delta)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
                       critical=False)
        .sign(root_key, hashes.SHA256())
    )

    # Signer cert
    signer_key = _key()
    signer_name = _name(common_name, org, country)
    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(signer_name)
        .issuer_name(int_name)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + signer_not_valid_after_delta)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(int_key, hashes.SHA256())
    )

    return root_cert, int_cert, signer_cert, signer_key


def _to_p12(root_cert, int_cert, signer_cert, signer_key,
            password: bytes = b"test") -> bytes:
    """Return PKCS#12 bundle bytes."""
    from cryptography.hazmat.primitives.serialization import pkcs12
    return pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=signer_key,
        cert=signer_cert,
        cas=[int_cert, root_cert],
        encryption_algorithm=_best_encryption(password),
    )


def _best_encryption(password: bytes):
    """Return a PKCS12 KeySerializationEncryption instance."""
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
    return BestAvailableEncryption(password)


# ── Minimal base PDF ──────────────────────────────────────────────────────────

def _make_base_pdf() -> bytes:
    """Return a minimal but valid PDF created with pyhanko's writer."""
    from pyhanko.pdf_utils.writer import PdfFileWriter
    from pyhanko.pdf_utils import generic

    w = PdfFileWriter()
    page_dict = generic.DictionaryObject({
        generic.NameObject('/Type'): generic.NameObject('/Page'),
        generic.NameObject('/MediaBox'): generic.ArrayObject([
            generic.NumberObject(0), generic.NumberObject(0),
            generic.NumberObject(595), generic.NumberObject(842),
        ]),
    })
    w.insert_page(page_dict)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


_BASE_PDF: bytes = _make_base_pdf()


def _sign_pdf(pdf_bytes: bytes, p12_bytes: bytes, field_name: str,
              password: bytes = b"test") -> bytes:
    """Sign *pdf_bytes* with the PKCS#12 key material and return the signed PDF."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign import signers, fields as sig_fields
    from pyhanko.sign.signers.pdf_cms import SimpleSigner
    from pyhanko.sign.fields import SigFieldSpec
    import asyncio

    reader = PdfFileReader(io.BytesIO(pdf_bytes), strict=False)
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes))

    # Add signature field
    sig_fields.append_signature_field(writer, SigFieldSpec(field_name, box=(72, 600, 300, 660)))

    signer = SimpleSigner.load_pkcs12_data(p12_bytes, other_certs=[], passphrase=password)
    meta = signers.PdfSignatureMetadata(field_name=field_name)
    out = io.BytesIO()
    asyncio.run(signers.async_sign_pdf(writer, meta, signer=signer, output=out))
    return out.getvalue()


def _tamper_pdf(pdf_bytes: bytes) -> bytes:
    """Flip a byte in the content covered by the signature hash.

    Modifies a byte in the PDF page object dictionary (outside the signature
    /Contents hex field) to invalidate the signature hash.
    """
    data = bytearray(pdf_bytes)

    # Find the /MediaBox in the page dict – always present, always in the
    # signed byte range, never inside the /Contents hex string.
    idx = data.find(b"/MediaBox")
    if idx != -1:
        # Flip a digit in the width value (safe: stays valid ASCII, breaks hash)
        digit_idx = idx + len(b"/MediaBox [")
        if digit_idx < len(data) and data[digit_idx:digit_idx+1].isdigit():
            data[digit_idx] ^= 1
            return bytes(data)

    # Fallback: flip a byte near the beginning, well inside signed content
    data[20] ^= 0xFF
    return bytes(data)


# ── Individual test generators ────────────────────────────────────────────────

def gen_01_untrusted_root(out_dir: Path) -> None:
    """Complete fake chain: root not in certifi/LOTL.
    Expected: chain UNKNOWN (yellow), source DOWNLOADED for root.
    """
    root, intermediate, signer, key = _build_chain("Fake Signer", ca_name="Fake Root CA")
    p12 = _to_p12(root, intermediate, signer, key)
    signed = _sign_pdf(_BASE_PDF, p12, "Sig1")
    (out_dir / "01_untrusted_root.pdf").write_bytes(signed)
    print("  01_untrusted_root.pdf  → chain UNKNOWN (root not in certifi)")


def gen_02_spoofed_root_dn(out_dir: Path) -> None:
    """SECURITY TEST: Fake root with same DN as a real certifi root but different key.

    The validator MUST NOT classify this as CERTIFI.
    Trust confirmation must use the full cert fingerprint, not the DN alone.
    Expected: chain UNKNOWN (yellow) — NOT green/CERTIFI.
    """
    import certifi
    from asn1crypto import pem as asn1_pem, x509 as asn1_x509
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509 import load_der_x509_certificate

    # Pick the first certifi root and copy its exact Subject DN
    with open(certifi.where(), "rb") as fh:
        pem_data = fh.read()
    real_root_der = None
    for _, _, der in asn1_pem.unarmor(pem_data, multiple=True):
        real_root_der = der
        break
    assert real_root_der is not None
    real_root = load_der_x509_certificate(real_root_der)
    real_subject = real_root.subject  # exact DN from certifi

    now = datetime.now(tz=timezone.utc)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # Generate a NEW key – same DN but different key material
    fake_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake_root_cert = (
        x509.CertificateBuilder()
        .subject_name(real_subject)     # same DN as real certifi root!
        .issuer_name(real_subject)
        .public_key(fake_root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(fake_root_key, hashes.SHA256())
    )

    # Intermediate and signer signed by fake root
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    int_name = x509.Name([*real_subject, x509.NameAttribute(
        x509.oid.NameOID.COMMON_NAME, "Spoofed Intermediate")])
    int_cert = (
        x509.CertificateBuilder()
        .subject_name(int_name)
        .issuer_name(real_subject)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(fake_root_key, hashes.SHA256())
    )
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Spoofed Signer"),
        ]))
        .issuer_name(int_name)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(int_key, hashes.SHA256())
    )

    p12 = _to_p12(fake_root_cert, int_cert, signer_cert, signer_key)
    signed = _sign_pdf(_BASE_PDF, p12, "Sig1")

    # Embed the spoofed root fingerprint info in the file for reference
    real_fp = hashlib.sha256(real_root_der).hexdigest()[:16]
    from cryptography.hazmat.primitives.serialization import Encoding
    fake_fp = hashlib.sha256(fake_root_cert.public_bytes(Encoding.DER)).hexdigest()[:16]

    (out_dir / "02_spoofed_root_dn.pdf").write_bytes(signed)
    print(f"  02_spoofed_root_dn.pdf → MUST show UNKNOWN (not CERTIFI!)")
    print(f"    Real root fingerprint prefix:  {real_fp}")
    print(f"    Fake root fingerprint prefix:  {fake_fp}")
    print(f"    Same DN: {real_root.subject.rfc4514_string()[:60]}")


def gen_03_expired_signing_cert(out_dir: Path) -> None:
    """Signer cert expired 1 day ago.
    Expected: chain INVALID (red) – date check fails.
    """
    root, intermediate, signer, key = _build_chain(
        "Expired Signer",
        signer_not_valid_after_delta=timedelta(hours=-1),  # expired
    )
    p12 = _to_p12(root, intermediate, signer, key)
    signed = _sign_pdf(_BASE_PDF, p12, "Sig1")
    (out_dir / "03_expired_signing_cert.pdf").write_bytes(signed)
    print("  03_expired_signing_cert.pdf → chain INVALID (signer cert expired)")


def gen_04_expired_ca_cert(out_dir: Path) -> None:
    """Intermediate CA cert expired 1 day ago, signer cert still valid.
    Expected: chain INVALID (red).
    """
    root, intermediate, signer, key = _build_chain(
        "Signer with Expired CA",
        intermediate_not_valid_after_delta=timedelta(hours=-1),  # expired CA
    )
    p12 = _to_p12(root, intermediate, signer, key)
    signed = _sign_pdf(_BASE_PDF, p12, "Sig1")
    (out_dir / "04_expired_ca_cert.pdf").write_bytes(signed)
    print("  04_expired_ca_cert.pdf → chain INVALID (intermediate CA expired)")


def gen_05_self_signed(out_dir: Path) -> None:
    """Signer cert is self-signed (no chain).
    Expected: UNKNOWN chain, displayed as self-signed.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.now(tz=timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Self-Signed Signer"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import pkcs12
    p12 = pkcs12.serialize_key_and_certificates(
        name=b"test", key=key, cert=cert, cas=[],
        encryption_algorithm=_best_encryption(b"test"),
    )
    signed = _sign_pdf(_BASE_PDF, p12, "Sig1")
    (out_dir / "05_self_signed.pdf").write_bytes(signed)
    print("  05_self_signed.pdf → UNKNOWN chain (self-signed, not in certifi)")


def gen_06_tampered_content(out_dir: Path) -> None:
    """Valid signature, then content modified after signing.
    Expected: crypto_status INVALID (red).
    """
    root, intermediate, signer, key = _build_chain("Tampered Doc Signer")
    p12 = _to_p12(root, intermediate, signer, key)
    signed = _sign_pdf(_BASE_PDF, p12, "Sig1")
    tampered = _tamper_pdf(signed)
    (out_dir / "06_tampered_content.pdf").write_bytes(tampered)
    print("  06_tampered_content.pdf → crypto INVALID (content modified after signing)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("output_dir", nargs="?", default="/tmp/pdf_signer_test",
                        help="Directory for generated test PDFs (default: /tmp/pdf_signer_test)")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating test PDFs in {out_dir}/")
    errors = []
    for gen_fn in [
        gen_01_untrusted_root,
        gen_02_spoofed_root_dn,
        gen_03_expired_signing_cert,
        gen_04_expired_ca_cert,
        gen_05_self_signed,
        gen_06_tampered_content,
    ]:
        try:
            gen_fn(out_dir)
        except Exception as exc:
            import traceback
            print(f"  ERROR in {gen_fn.__name__}: {exc}")
            traceback.print_exc()
            errors.append(gen_fn.__name__)

    print()
    if errors:
        print(f"FAILED: {', '.join(errors)}")
        sys.exit(1)
    else:
        print("All test PDFs generated successfully.")
        print()
        print("Expected results when opening each file in PDF QES Signer:")
        print("  01 → Signaturprüfung: Kette UNKNOWN (gelb), Root 'Heruntergeladen'")
        print("  02 → SECURITY: Kette UNKNOWN (gelb), Root NICHT als certifi angezeigt")
        print("  03 → Signaturprüfung: INVALID (rot), Signaturzertifikat abgelaufen")
        print("  04 → Signaturprüfung: INVALID (rot), Zwischenzertifikat abgelaufen")
        print("  05 → Signaturprüfung: UNKNOWN (gelb), selbstsigniert")
        print("  06 → Signaturprüfung: INVALID (rot), Inhalt nach Signatur verändert")


if __name__ == "__main__":
    main()
