# SPDX-License-Identifier: GPL-3.0-or-later
"""
PDF signing workers for PDF QES Signer.

Provides:
  - _pyhanko_available / _pkcs11_available  – runtime capability flags
  - SaveFieldsWorker   – embeds signature field annotations via pyhanko
  - SignWorker         – applies a QES signature via PKCS#11
  - _make_pdf_font()   – helper to build a SimpleFontEngineFactory

## Incremental write strategy

PDF signatures are cryptographically tied to a specific byte range.  Rewriting
or compressing a signed PDF breaks those signatures.  pyhanko therefore always
appends a new incremental revision at the end of the file (`IncrementalPdfFileWriter`).
The original bytes remain untouched; only a new cross-reference table and the
signature object are appended.  This is why `_working_bytes` is always passed
to workers as-is – it must not be modified or garbage-collected beforehand.

## Two-phase embed-then-sign in SignWorker

`SaveFieldsWorker` only embeds signature field annotations; it does not sign.
`SignWorker` combines both steps in one operation:

1. All free unsigned fields (`all_fields`) are embedded into an incremental
   revision of the working bytes via `append_signature_field`.
2. The target field is signed in the same pyhanko pass.

Locked fields are already present in the PDF bytes and are therefore skipped
during embedding (pyhanko raises an error for duplicate fields, which is
silently ignored).

## PKCS#11 session design

The PKCS#11 session is opened exactly once per signing operation and kept open
until the signature is written.  This ensures that a PIN-pad reader (e.g.
CyberJack) prompts the user only once, regardless of how many internal
key/cert lookups are performed.  Key and certificate are located by matching
label and/or key-ID attributes; the first available object is used as fallback.

## Visual appearance pipeline

The appearance of the signed field (name, location, reason, date, image) is
rendered by pyhanko's `TextStampStyle`.  When a background image is configured,
`_make_background_image()` (see `appearance.py`) builds a canvas wider than the
source image with a transparent strip on the text side.  pyhanko places this
canvas as the field background and renders the text block into the transparent
area.  See `appearance.py` for the image-padding strategy.
"""

from __future__ import annotations

import io
import sys
import traceback
from pathlib import Path

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



# ── Rotated appearance helper ─────────────────────────────────────────────────

def _build_rotated_appearance(app, cert_cn: str, fdef):
    """Return a TextStampStyle with a pre-rotated background image.

    Used when the page has a non-zero /Rotate value.  pyhanko renders the
    appearance stream in the PDF native (unrotated) coordinate space.  The PDF
    viewer then rotates the page – and with it the appearance content – making
    text and images appear tilted.

    Fix: render the full appearance at the *visual* (displayed) dimensions using
    the Pillow-based renderer, then rotate the image by ``-page_rotation`` (CW)
    so that after the viewer's CCW page rotation the content appears upright.
    The rotated image has exactly the native field dimensions and is passed to
    pyhanko as a full-coverage background; stamp_text is set to a single space
    at 1 pt so pyhanko does not add its own text layer.

    Args:
        app:      SigAppearance instance.
        cert_cn:  Signer CN extracted from the certificate (may be empty).
        fdef:     SignatureFieldDef with page_rotation set.
    """
    import os
    from PIL import Image as PILImage
    from pyhanko.pdf_utils.images import PdfImage
    from pyhanko.pdf_utils.layout import BoxConstraints, SimpleBoxLayoutRule, AxisAlignment, Margins
    from pyhanko.stamp import TextStampStyle
    from pyhanko.pdf_utils.text import TextBoxStyle

    native_w = abs(fdef.x2 - fdef.x1)
    native_h = abs(fdef.y2 - fdef.y1)
    rot = fdef.page_rotation

    # Visual (displayed) dimensions: 90°/270° swap width and height
    if rot in (90, 270):
        vis_w, vis_h = native_h, native_w
    else:
        vis_w, vis_h = native_w, native_h

    # Render at visual dimensions using the Pillow renderer (thread-safe, no Qt)
    from .appearance import _render_appearance_to_png
    png_path = _render_appearance_to_png(app, cert_cn, vis_w, vis_h)
    if png_path is None:
        return None  # fall back to caller's default stamp_style = None

    try:
        img = PILImage.open(png_path).convert("RGBA")
        # PDF /Rotate=N means the viewer rotates the page N° CW.
        # PIL.rotate(angle) rotates CCW.  To compensate the viewer's CW rotation
        # we pre-rotate the image by the same amount CCW = PIL.rotate(rot).
        pil_angle = rot % 360
        if pil_angle:
            img = img.rotate(pil_angle, expand=True)

        return TextStampStyle(
            border_width=0,
            stamp_text=" ",
            background=PdfImage(img, box=BoxConstraints(native_w, native_h)),
            background_opacity=1.0,
            background_layout=SimpleBoxLayoutRule(
                x_align=AxisAlignment.ALIGN_MID,
                y_align=AxisAlignment.ALIGN_MID,
                margins=Margins.uniform(0),
            ),
            text_box_style=TextBoxStyle(
                font=_make_pdf_font("Helvetica", 0.5),
                font_size=1,
                border_width=0,
            ),
        )
    finally:
        try:
            os.unlink(png_path)
        except Exception:
            pass


# ── Worker threads ────────────────────────────────────────────────────────────

class SaveFieldsWorker(QThread):
    """Embed signature field annotations into a PDF copy using pyhanko."""

    finished = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, pdf_bytes: bytes, out_path: str, sig_fields: list) -> None:
        super().__init__()
        self.pdf_bytes  = pdf_bytes
        self.out_path   = out_path
        self.sig_fields = sig_fields

    def run(self) -> None:
        try:
            buf = io.BytesIO(self.pdf_bytes)
            writer = IncrementalPdfFileWriter(buf, strict=False)
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

    def __init__(self, pdf_bytes: bytes, out_path: str, fdef,
                 lib_path: str, pin: str, key_label: str,
                 appearance=None, all_fields: list | None = None,
                 tsa_url: str = "", field_name: str = "Signature") -> None:
        super().__init__()
        self.pdf_bytes  = pdf_bytes
        self.out_path   = out_path
        self.fdef       = fdef
        self.field_name = field_name  # used only when fdef is None (invisible)
        self.lib_path   = lib_path
        self.pin        = pin
        self.key_label  = key_label
        self.appearance = appearance   # SigAppearance instance or None
        self.all_fields = all_fields or []  # all unsigned fields to embed
        self.tsa_url    = tsa_url      # RFC 3161 TSA URL, or "" to disable

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
            field_name = self.fdef.name if self.fdef else self.field_name
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
            page_rotation = self.fdef.page_rotation if self.fdef else 0

            # For rotated pages use a pre-rotated Pillow image as background so
            # that the appearance content appears upright after the viewer applies
            # the page rotation.  The normal pyhanko TextStampStyle path renders
            # in the native (unrotated) field coordinate space which causes text
            # and images to appear tilted when the page has /Rotate != 0.
            if page_rotation != 0 and self.fdef is not None:
                try:
                    stamp_style = _build_rotated_appearance(
                        app, cert_cn, self.fdef)
                except Exception:
                    traceback.print_exc(file=sys.stderr)

            if stamp_style is None and page_rotation == 0:
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
            buf    = io.BytesIO(self.pdf_bytes)
            writer = IncrementalPdfFileWriter(buf, strict=False)

            # Embed free unsigned fields (locked fields are already in the PDF bytes)
            fields_to_embed = list(self.all_fields)
            if self.fdef and not any(f is self.fdef for f in fields_to_embed):
                fields_to_embed.append(self.fdef)
            for f in fields_to_embed:
                try:
                    spec = SigFieldSpec(
                        sig_field_name=f.name,
                        on_page=f.page,
                        box=(f.x1, f.y1, f.x2, f.y2),
                    )
                    sig_fields_mod.append_signature_field(writer, spec)
                except Exception:
                    pass  # Field already exists – that is fine

            timestamper = None
            if self.tsa_url:
                from pyhanko.sign.timestamps import HTTPTimeStamper
                timestamper = HTTPTimeStamper(self.tsa_url)

            pdf_signer = PdfSigner(
                signature_meta=sig_meta,
                signer=signer,
                stamp_style=stamp_style,  # None → no visual appearance
                timestamper=timestamper,
            )
            with open(self.out_path, "wb") as outf:
                pdf_signer.sign_pdf(writer, output=outf)

            session.close()
            self.finished.emit(self.out_path)

        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self.error.emit(str(exc))
