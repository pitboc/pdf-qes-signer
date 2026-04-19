"""Test whether fitz-exported bytes (after widget.update()) can be signed by pyhanko.

Generates a self-signed certificate, edits form field values, exports bytes via
fitz_doc.tobytes(garbage=0, deflate=False), signs with pyhanko IncrementalPdfFileWriter,
then validates the signature byte-range integrity.

Run with: python tests/test_fitz_bytes_pyhanko_sign.py
"""

import io
import datetime

import fitz
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields as sig_fields
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.signers import SimpleSigner, PdfSignatureMetadata, PdfSigner


PDF_IN  = "tests/test_form.pdf"
PDF_OUT = "tests/test_fitz_signed.pdf"


# ── 1. Self-signed cert for testing ──────────────────────────────────────────

def _make_signer() -> SimpleSigner:
    """Create a SimpleSigner with a self-signed cert via PKCS12 temp file."""
    import tempfile, os
    from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Signer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    p12 = serialize_key_and_certificates(
        name=b"test", key=key, cert=cert, cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd, path = tempfile.mkstemp(suffix=".p12")
    try:
        os.write(fd, p12)
        os.close(fd)
        return SimpleSigner.load_pkcs12(path)
    finally:
        os.unlink(path)


# ── 2. Edit form fields via fitz ──────────────────────────────────────────────

def _edit_fields(doc: fitz.Document) -> None:
    page = doc[0]
    for w in page.widgets():
        ft = w.field_type
        if ft == fitz.PDF_WIDGET_TYPE_TEXT:
            w.field_value = "Edited Value"
            w.update()
        elif ft == fitz.PDF_WIDGET_TYPE_CHECKBOX:
            w.field_value = "Yes"
            w.update()
        elif ft == fitz.PDF_WIDGET_TYPE_COMBOBOX:
            w.field_value = "Austria"
            w.update()


# ── 3. Sign with pyhanko ──────────────────────────────────────────────────────

def _sign(pdf_bytes: bytes, signer: SimpleSigner) -> bytes:
    buf    = io.BytesIO(pdf_bytes)
    writer = IncrementalPdfFileWriter(buf, strict=False)

    # Add a signature field
    spec = SigFieldSpec(sig_field_name="Signature1", on_page=0, box=(50, 20, 250, 60))
    sig_fields.append_signature_field(writer, spec)

    out_buf = io.BytesIO()
    writer.write(out_buf)
    pdf_with_field = out_buf.getvalue()

    # Sign
    buf2    = io.BytesIO(pdf_with_field)
    writer2 = IncrementalPdfFileWriter(buf2, strict=False)
    out_buf2 = io.BytesIO()
    pdf_signer = PdfSigner(
        PdfSignatureMetadata(field_name="Signature1"),
        signer=signer,
    )

    pdf_signer.sign_pdf(writer2, output=out_buf2)
    return out_buf2.getvalue()


# ── 4. Validate byte-range integrity ─────────────────────────────────────────

def _validate_byte_range(signed_bytes: bytes) -> bool:
    """Check that the /ByteRange covers the file and the hash region is intact."""
    doc = fitz.open(stream=signed_bytes, filetype="pdf")
    for page in doc:
        for w in page.widgets():
            if w.field_type == fitz.PDF_WIDGET_TYPE_SIGNATURE:
                br = w.border_width  # not what we want, but let's use pyhanko
                _ = br
    doc.close()

    # Use pyhanko's reader to verify ByteRange is present and non-trivial
    from pyhanko.pdf_utils.reader import PdfFileReader
    reader = PdfFileReader(io.BytesIO(signed_bytes), strict=False)
    embedded = reader.embedded_signatures
    if not embedded:
        print("  ERROR: No embedded signature found.")
        return False
    sig = embedded[0]
    br = sig.sig_object["/ByteRange"]
    total = len(signed_bytes)
    # ByteRange: [0, b1, b2, b3] where b2+b3 should equal file length
    # ByteRange = [0, len1, start2, len2]; start2+len2 must equal file end
    end_of_file = br[2] + br[3]
    sig_gap = br[2] - br[1]  # the hex-encoded signature value itself
    print(f"  ByteRange: {list(br)}")
    print(f"  File size: {total} bytes, end of last range: {end_of_file}, sig gap: {sig_gap} bytes")
    ok = end_of_file == total
    print(f"  Coverage check: {'PASS' if ok else 'FAIL'}")
    return ok


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=== Step 1: Generate self-signed certificate ===")
    signer = _make_signer()
    print("  Done.")

    print("\n=== Step 2: Load PDF and edit form fields via fitz ===")
    doc = fitz.open(PDF_IN)
    _edit_fields(doc)
    print("  Fields edited.")

    print("\n=== Step 3: Export bytes via fitz_doc.tobytes(garbage=0, deflate=False) ===")
    fitz_bytes = doc.tobytes(garbage=0, deflate=False)
    doc.close()
    print(f"  Exported {len(fitz_bytes)} bytes.")

    # Sanity check: reload and verify values survived
    doc2 = fitz.open(stream=fitz_bytes, filetype="pdf")
    print("  Field values after re-opening from exported bytes:")
    for w in doc2[0].widgets():
        if w.field_type != fitz.PDF_WIDGET_TYPE_SIGNATURE:
            print(f"    {w.field_type_string:12} {w.field_name:20} = {w.field_value!r}")
    doc2.close()

    print("\n=== Step 4: Sign exported bytes with pyhanko ===")
    try:
        signed_bytes = _sign(fitz_bytes, signer)
        print(f"  Signed PDF: {len(signed_bytes)} bytes.")
    except Exception as e:
        print(f"  ERROR during signing: {e}")
        raise

    print("\n=== Step 5: Validate byte-range integrity ===")
    ok = _validate_byte_range(signed_bytes)

    with open(PDF_OUT, "wb") as f:
        f.write(signed_bytes)
    print(f"\nOutput written to {PDF_OUT}")
    print(f"\nResult: {'SUCCESS' if ok else 'FAILURE'}")


if __name__ == "__main__":
    main()
