# SPDX-License-Identifier: GPL-3.0-or-later
"""
PDF signing workers for PDF QES Signer.

Provides:
  - _pyhanko_available / _pkcs11_available  – runtime capability flags
  - SaveFieldsWorker   – embeds signature field annotations via pyhanko
  - SignWorker         – applies a QES signature via PKCS#11
  - _make_pdf_font()   – helper to build a SimpleFontEngineFactory
  - _prepare_pdf_with_appearance() – low-level fitz helper (internal)

PKCS#11 session design:
  The session is opened exactly once per signing operation and kept open until
  the signature is written.  This ensures that a PIN-pad reader (e.g. CyberJack)
  prompts the user only once, regardless of how many internal key/cert lookups
  are performed.
"""

from __future__ import annotations

import re
import sys
import traceback
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

# ── Runtime availability flags ────────────────────────────────────────────────

_pyhanko_available = False
_pkcs11_available  = False

try:
    from pyhanko.sign import fields
    from pyhanko.sign.fields import SigFieldSpec
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.pkcs11 import open_pkcs11_session  # noqa: F401 (availability check)
    _pyhanko_available = True
    _pkcs11_available  = True
except ImportError:
    try:
        from pyhanko.sign import fields
        from pyhanko.sign.fields import SigFieldSpec
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        _pyhanko_available = True
    except ImportError:
        pass


# ── Helper functions ──────────────────────────────────────────────────────────

def _make_pdf_font(pdf_name: str, avg_width: float):
    """Return a SimpleFontEngineFactory for a PDF-14 standard font."""
    from pyhanko.pdf_utils.font import SimpleFontEngineFactory
    return SimpleFontEngineFactory(pdf_name, avg_width)


def _prepare_pdf_with_appearance(src_path: str, dst_path: str,
                                  fdef,
                                  appearance_png: Optional[str]) -> None:
    """Copy *src_path* to *dst_path*, add the signature field, and attach the
    appearance stream from *appearance_png*.

    Strategy (pure fitz, no pyhanko internals):
      1. Embed the PNG as an image XObject via an off-page rect.
      2. Create a Form XObject that scales the image to the field dimensions.
      3. Point /AP /N of the widget annotation to the Form XObject.
      4. Save as a normal (non-incremental) PDF so that pyhanko can append its
         own incremental revision cleanly.

    Args:
        fdef:           SignatureFieldDef instance or None (invisible signature).
        appearance_png: Path to a rendered PNG file, or None.
    """
    import fitz as _fitz

    doc = _fitz.open(src_path)

    if fdef is not None:
        fw = abs(fdef.x2 - fdef.x1)
        fh = abs(fdef.y2 - fdef.y1)
        page   = doc[fdef.page]
        page_h = page.rect.height

        # Add the widget annotation if it does not already exist
        field_exists = any(w.field_name == fdef.name for w in page.widgets())
        if not field_exists:
            annot_xref = doc.get_new_xref()
            x0, y0, x1, y1 = fdef.x1, fdef.y1, fdef.x2, fdef.y2
            doc.update_object(annot_xref,
                f"<< /Type /Annot /Subtype /Widget "
                f"/FT /Sig "
                f"/Rect [{x0:.2f} {y0:.2f} {x1:.2f} {y1:.2f}] "
                f"/T ({fdef.name}) "
                f"/F 4 "
                f"/P {page.xref} 0 R >>")

            # Add widget reference to the page's /Annots array
            page_obj = doc.xref_object(page.xref, compressed=False)
            if "/Annots" in page_obj:
                page_obj = page_obj.replace(
                    "/Annots [",
                    f"/Annots [{annot_xref} 0 R ")
            else:
                page_obj = (page_obj.rstrip().rstrip(">").rstrip()
                            + f" /Annots [{annot_xref} 0 R ] >>")
            doc.update_object(page.xref, page_obj)

            # Register in the AcroForm
            root     = doc.pdf_catalog()
            root_obj = doc.xref_object(root, compressed=False)
            if "/AcroForm" not in root_obj:
                root_obj = (root_obj.rstrip().rstrip(">").rstrip()
                            + f" /AcroForm << /Fields [{annot_xref} 0 R]"
                              f" /SigFlags 3 >> >>")
                doc.update_object(root, root_obj)

            w_xref = annot_xref
        else:
            w_xref = next(
                w.xref for w in page.widgets() if w.field_name == fdef.name)

        # Attach appearance stream from PNG if available
        if appearance_png and Path(appearance_png).exists() and fw > 1 and fh > 1:
            pix = _fitz.Pixmap(appearance_png)

            # Embed image via off-page rect to obtain an xref
            off_rect = _fitz.Rect(0, page_h + 10, fw, page_h + 10 + fh)
            img_xref = page.insert_image(off_rect, pixmap=pix)

            # Build a Form XObject that draws the image at field size
            img_res  = "Im0"
            xobj_cs  = (f"q {fw:.4f} 0 0 {fh:.4f} 0 0 cm "
                        f"/{img_res} Do Q").encode()
            form_xref = doc.get_new_xref()
            doc.update_object(form_xref,
                f"<< /Type /XObject /Subtype /Form "
                f"/BBox [0 0 {fw:.4f} {fh:.4f}] "
                f"/Resources << /XObject << /{img_res} {img_xref} 0 R >> >> "
                f"/Length {len(xobj_cs)} >>")
            doc.update_stream(form_xref, xobj_cs)

            # Point the widget's /AP /N to the Form XObject
            w_obj    = doc.xref_object(w_xref, compressed=False)
            ap_entry = f"/AP << /N {form_xref} 0 R >>"
            if re.search(r"/AP", w_obj):
                w_obj = re.sub(r"/AP\s*<<[^>]*>>", ap_entry, w_obj)
            else:
                w_obj = w_obj.rstrip()
                w_obj = (w_obj[:-2].rstrip() + f" {ap_entry} >>") \
                    if w_obj.endswith(">>") else (w_obj + f" {ap_entry}")
            doc.update_object(w_xref, w_obj)

    # Save as a regular (non-incremental) PDF; pyhanko appends its revision.
    doc.save(dst_path)
    doc.close()


# ── Worker threads ────────────────────────────────────────────────────────────

class SaveFieldsWorker(QThread):
    """Embed signature field annotations into a PDF copy using pyhanko."""

    finished = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, pdf_path: str, out_path: str, sig_fields: list) -> None:
        super().__init__()
        self.pdf_path   = pdf_path
        self.out_path   = out_path
        self.sig_fields = sig_fields

    def run(self) -> None:
        try:
            with open(self.pdf_path, "rb") as inf:
                writer = IncrementalPdfFileWriter(inf)
                for fdef in self.sig_fields:
                    spec = SigFieldSpec(
                        sig_field_name=fdef.name,
                        on_page=fdef.page,
                        box=(fdef.x1, fdef.y1, fdef.x2, fdef.y2),
                    )
                    fields.append_signature_field(writer, spec)
                with open(self.out_path, "wb") as outf:
                    writer.write(outf)
            self.finished.emit(self.out_path)
        except Exception as exc:
            self.error.emit(str(exc))


class SignWorker(QThread):
    """Apply a QES signature to a PDF via PKCS#11 in a background thread.

    The PKCS#11 session is opened once and kept alive for the entire operation
    so that PIN-pad readers only prompt the user a single time.
    """

    finished = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, pdf_path: str, out_path: str, fdef,
                 lib_path: str, pin: str, key_label: str,
                 appearance=None) -> None:
        super().__init__()
        self.pdf_path   = pdf_path
        self.out_path   = out_path
        self.fdef       = fdef
        self.lib_path   = lib_path
        self.pin        = pin
        self.key_label  = key_label
        self.appearance = appearance  # SigAppearance instance or None

    def run(self) -> None:
        try:
            import pkcs11 as p11
            from pyhanko.sign.pkcs11 import open_pkcs11_session, PKCS11Signer, PROTECTED_AUTH
            from pyhanko.sign.signers import PdfSignatureMetadata, PdfSigner
            from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
            import pyhanko.sign.fields as sig_fields_mod
            from pyhanko.sign.fields import SigFieldSpec

            user_pin = self.pin if self.pin else PROTECTED_AUTH

            # ── Single session: key/cert lookup + signing ─────────────────────
            # The session stays open until the signature is written so that a
            # PIN-pad reader (e.g. CyberJack) is prompted only once.
            key_id = cert_id = cert_label_found = cert_cn = None

            session = open_pkcs11_session(
                lib_location=self.lib_path, slot_no=0, user_pin=user_pin)

            # Locate private key
            priv_keys = list(session.get_objects(
                {p11.Attribute.CLASS: p11.ObjectClass.PRIVATE_KEY}))
            for k in priv_keys:
                try:
                    lbl = k[p11.Attribute.LABEL]
                except Exception:
                    lbl = None
                if lbl == self.key_label or key_id is None:
                    try:
                        key_id = bytes(k[p11.Attribute.ID])
                    except Exception:
                        pass
                    if lbl == self.key_label:
                        break

            # Locate matching certificate
            all_certs = list(session.get_objects(
                {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}))
            if not all_certs:
                raise RuntimeError("No certificate found on the token.")

            matched = None
            if key_id:
                for c in all_certs:
                    try:
                        if bytes(c[p11.Attribute.ID]) == key_id:
                            matched = c
                            break
                    except Exception:
                        pass
            if not matched:
                for c in all_certs:
                    try:
                        if c[p11.Attribute.LABEL] == self.key_label:
                            matched = c
                            break
                    except Exception:
                        pass
            if not matched:
                matched = all_certs[0]

            try:
                cert_id = bytes(matched[p11.Attribute.ID])
            except Exception:
                pass
            try:
                cert_label_found = matched[p11.Attribute.LABEL]
            except Exception:
                pass

            # Extract CN from the certificate (no second session needed)
            try:
                from cryptography import x509
                raw_cert = bytes(matched[p11.Attribute.VALUE])
                cert_obj = x509.load_der_x509_certificate(raw_cert)
                cn_attrs = cert_obj.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME)
                cert_cn = cn_attrs[0].value if cn_attrs else (cert_label_found or "")
            except Exception:
                cert_cn = cert_label_found or ""

            signer = PKCS11Signer(
                pkcs11_session=session,
                key_label=self.key_label,
                key_id=key_id,
                cert_id=cert_id,
                cert_label=cert_label_found,
                other_certs_to_pull=(),
            )

            # ── Build signature metadata ───────────────────────────────────────
            field_name = self.fdef.name if self.fdef else "Signature"
            app = self.appearance
            sig_name = (cert_cn
                        if (app and app.show_name and app.name_mode == "cert")
                        else (app.name_custom if app and app.show_name else None))
            sig_location = app.location if app and app.show_location else None
            sig_reason   = app.reason   if app and app.show_reason   else None

            sig_meta = PdfSignatureMetadata(
                field_name=field_name,
                name=sig_name     or None,
                location=sig_location or None,
                reason=sig_reason   or None,
            )

            # ── Build TextStampStyle for visual appearance ─────────────────────
            from pyhanko.stamp import TextStampStyle
            from pyhanko.pdf_utils.text import TextBoxStyle
            from pyhanko.pdf_utils.layout import (
                SimpleBoxLayoutRule, AxisAlignment, Margins,
            )

            stamp_style = None
            try:
                # Compose text content
                text_lines: list[str] = []
                if app and app.show_name:
                    name_val = (cert_cn if app.name_mode == "cert" and cert_cn
                                else app.name_custom)
                    if name_val:
                        text_lines.append(name_val)
                if app and app.show_location and app.location:
                    text_lines.append(app.location)
                if app and app.show_reason and app.reason:
                    text_lines.append(app.reason)

                # Use pyhanko's %(ts)s placeholder for the timestamp
                if app and app.show_date:
                    text_lines.append("%(ts)s")
                    ts_format = app.date_format or "%d.%m.%Y %H:%M"
                else:
                    ts_format = "%d.%m.%Y %H:%M"

                stamp_text = "\n".join(text_lines) if text_lines else " "

                # Prepare background image if configured
                from .appearance import _make_background_image
                background_image = None
                img_path = app.image_path if app else ""
                if img_path and Path(img_path).exists():
                    background_image = _make_background_image(
                        img_path,
                        layout=app.layout if app else "img_left",
                        img_ratio=app.img_ratio if app else 40,
                    )

                style_kwargs: dict = dict(
                    border_width=1 if (app and app.show_border) else 0,
                    stamp_text=stamp_text,
                    timestamp_format=ts_format,
                    text_box_style=TextBoxStyle(
                        font=_make_pdf_font(
                            app.font_pdf_name  if app else "Helvetica",
                            app.font_avg_width if app else 0.5,
                        ),
                        font_size=app.font_size if app else 8,
                        border_width=0,
                    ),
                )
                if background_image is not None:
                    style_kwargs["background"]         = background_image
                    style_kwargs["background_opacity"] = 1.0
                    # Align text away from the image
                    x_align = (AxisAlignment.ALIGN_MAX
                                if app and app.layout == "img_left"
                                else AxisAlignment.ALIGN_MIN)
                    style_kwargs["inner_content_layout"] = SimpleBoxLayoutRule(
                        x_align=x_align,
                        y_align=AxisAlignment.ALIGN_MID,
                        margins=Margins(left=4, right=4, top=4, bottom=4),
                    )

                stamp_style = TextStampStyle(**style_kwargs)

            except Exception:
                traceback.print_exc(file=sys.stderr)

            # ── Sign the PDF ───────────────────────────────────────────────────
            with open(self.pdf_path, "rb") as inf:
                writer = IncrementalPdfFileWriter(inf)

                if self.fdef:
                    try:
                        spec = SigFieldSpec(
                            sig_field_name=self.fdef.name,
                            on_page=self.fdef.page,
                            box=(self.fdef.x1, self.fdef.y1,
                                 self.fdef.x2, self.fdef.y2),
                        )
                        sig_fields_mod.append_signature_field(writer, spec)
                    except Exception:
                        pass  # Field already exists – that is fine

                pdf_signer = PdfSigner(
                    signature_meta=sig_meta,
                    signer=signer,
                    stamp_style=stamp_style,  # None → no visual appearance
                )
                with open(self.out_path, "wb") as outf:
                    pdf_signer.sign_pdf(writer, output=outf)

            session.close()
            self.finished.emit(self.out_path)

        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self.error.emit(str(exc))
