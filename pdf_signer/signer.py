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

# Diese Flags werden beim Modulimport gesetzt und zeigen an, welche optionalen
# Bibliotheken verfügbar sind.  Die Hauptanwendung prüft sie vor Signieroperationen
# und zeigt ggf. einen Hinweis auf fehlende Abhängigkeiten.
_pyhanko_available = False
_pkcs11_available  = False

try:
    # Vollständiger Import: pyhanko + PKCS#11-Unterstützung vorhanden
    from pyhanko.sign import fields
    from pyhanko.sign.fields import SigFieldSpec
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.pkcs11 import open_pkcs11_session  # noqa: F401 (availability check)
    _pyhanko_available = True
    _pkcs11_available  = True
except ImportError:
    try:
        # Fallback: nur pyhanko ohne PKCS#11 (z.B. python-pkcs11 nicht installiert)
        from pyhanko.sign import fields
        from pyhanko.sign.fields import SigFieldSpec
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        _pyhanko_available = True
    except ImportError:
        # pyhanko gar nicht installiert – nur Anzeige möglich, kein Signieren
        pass


# ── Helper functions ──────────────────────────────────────────────────────────

def _make_pdf_font(pdf_name: str, avg_width: float):
    """Return a SimpleFontEngineFactory for a PDF-14 standard font."""
    # pyhanko benötigt eine Font-Fabrik für die Textdarstellung im Stempel.
    # SimpleFontEngineFactory kapselt einen der 14 PDF-Standardschriften
    # (z.B. Helvetica, Times-Roman) ohne eingebettete Schriftdaten.
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

    # native_w/native_h: Feldgröße im nativen (unrotierten) PDF-Koordinatensystem
    native_w = abs(fdef.x2 - fdef.x1)
    native_h = abs(fdef.y2 - fdef.y1)
    rot = fdef.page_rotation

    # Visual (displayed) dimensions: 90°/270° swap width and height
    # Bei 90° oder 270° Seitenrotation sind Breite und Höhe des visuellen
    # Erscheinungsbildes gegenüber dem nativen Koordinatensystem vertauscht
    if rot in (90, 270):
        vis_w, vis_h = native_h, native_w
    else:
        vis_w, vis_h = native_w, native_h

    # Render at visual dimensions using the Pillow renderer (thread-safe, no Qt)
    # Pillow-Renderer statt Qt-Renderer verwenden, da dieser im Worker-Thread
    # aufgerufen wird und Qt-Objekte nicht thread-sicher sind
    from .appearance import _render_appearance_to_png
    png_path = _render_appearance_to_png(app, cert_cn, vis_w, vis_h)
    if png_path is None:
        return None  # fall back to caller's default stamp_style = None

    try:
        img = PILImage.open(png_path).convert("RGBA")
        # PDF /Rotate=N means the viewer rotates the page N° CW.
        # PIL.rotate(angle) rotates CCW.  To compensate the viewer's CW rotation
        # we pre-rotate the image by the same amount CCW = PIL.rotate(rot).
        # Gegenrotation: Wenn der Betrachter die Seite um N° im UZS dreht,
        # muss das Bild vorher um N° gegen den UZS gedreht werden, damit der
        # Inhalt nach der Drehung wieder aufrecht erscheint
        pil_angle = rot % 360
        if pil_angle:
            img = img.rotate(pil_angle, expand=True)

        # Vollflächiger Hintergrund: stamp_text=" " (1 Zeichen, 1pt) unterdrückt
        # pyhanko's eigenen Text-Layer – der Inhalt steckt komplett im Bild
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
        # Temporäre PNG-Datei immer löschen, auch im Fehlerfall
        try:
            os.unlink(png_path)
        except Exception:
            pass


# ── Worker threads ────────────────────────────────────────────────────────────

class SaveFieldsWorker(QThread):
    """Embed signature field annotations into a PDF copy using pyhanko."""

    # finished: Pfad zur erfolgreich geschriebenen Datei
    finished = pyqtSignal(str)
    # error: Fehlermeldung als String
    error    = pyqtSignal(str)

    def __init__(self, pdf_bytes: bytes, out_path: str, sig_fields: list) -> None:
        super().__init__()
        # pdf_bytes: Arbeitskopie des PDFs als In-Memory-Bytes (ohne freie Felder)
        self.pdf_bytes  = pdf_bytes
        # out_path: Zieldatei-Pfad; der Worker schreibt nur hierhin, nie auf
        # die Quelldatei (kein überschreiben des Originals)
        self.out_path   = out_path
        # sig_fields: Liste der freien unsigned SignatureFieldDef-Objekte,
        # die als Annotationen in die PDF-Datei eingebettet werden sollen
        self.sig_fields = sig_fields

    def run(self) -> None:
        try:
            # PDF-Bytes in einen BytesIO-Puffer laden; pyhanko erwartet ein
            # file-like object, kein bytes-Objekt direkt
            buf = io.BytesIO(self.pdf_bytes)
            # IncrementalPdfFileWriter: Änderungen werden als neue Revision
            # am Ende der Datei angehängt, ohne bestehende Bytes zu verändern
            writer = IncrementalPdfFileWriter(buf, strict=False)
            for fdef in self.sig_fields:
                # SigFieldSpec beschreibt ein Signaturfeld: Name, Seite, Koordinaten
                spec = SigFieldSpec(
                    sig_field_name=fdef.name,
                    on_page=fdef.page,
                    box=(fdef.x1, fdef.y1, fdef.x2, fdef.y2),
                )
                # Signaturfeld als Widget-Annotation in die PDF-Struktur einfügen
                fields.append_signature_field(writer, spec)
            with open(self.out_path, "wb") as outf:
                writer.write(outf)
            # Erfolg-Signal mit dem Pfad zur geschriebenen Datei senden
            self.finished.emit(self.out_path)
        except Exception as exc:
            self.error.emit(str(exc))


class SignWorker(QThread):
    """Apply a QES or file-certificate signature to a PDF in a background thread.

    Two signing modes are supported:

    - ``mode="pkcs11"`` (default): PKCS#11 hardware token.  The session is
      opened once and kept alive for the entire operation so that PIN-pad
      readers only prompt the user a single time.

    - ``mode="pfx"``: PKCS#12 / PFX file certificate.  The private key and
      certificate are loaded from *pfx_path*; *pin* is used as the file
      passphrase (empty = unprotected file).  A PFX file typically contains
      exactly one private key and one signing certificate; if the file
      contains multiple keys the first one is used (python-cryptography
      limitation – see README for details).
    """

    # finished: Pfad zur signierten Ausgabedatei
    finished = pyqtSignal(str)
    # error: Fehlermeldung im Fehlerfall (z.B. falsche PIN, Token nicht vorhanden)
    error    = pyqtSignal(str)

    def __init__(self, pdf_bytes: bytes, out_path: str, fdef,
                 lib_path: str, pin: str, key_id: str, cert_cn: str = "",
                 appearance=None, all_fields: list | None = None,
                 tsa_url: str = "", field_name: str = "Signature",
                 mode: str = "pkcs11", pfx_path: str = "") -> None:
        super().__init__()
        # pdf_bytes: Arbeitskopie des PDFs (ohne freie Signaturfelder);
        # Workers re-embedden sig_fields vor dem Signieren
        self.pdf_bytes  = pdf_bytes
        # out_path: Zieldatei für das signierte PDF
        self.out_path   = out_path
        # fdef: das zu signierende SignatureFieldDef; None bei unsichtbarer Signatur
        self.fdef       = fdef
        self.field_name = field_name  # used only when fdef is None (invisible)
        # lib_path: Pfad zur PKCS#11-Bibliothek (.so / .dll) – nur im pkcs11-Modus
        self.lib_path   = lib_path
        # pin: PIN-String (pkcs11) oder Datei-Passphrase (pfx);
        # leer → Hardware-PIN-Pad / ungeschützte PFX-Datei
        self.pin        = pin
        # key_id: CKA_ID des privaten Schlüssels als Hex-String; leer → erstes Objekt
        self.key_id     = key_id      # hex CKA_ID of the private key
        # cert_cn: CN aus dem Zertifikat-Subject (für Anzeigenamen in der Signatur)
        self.cert_cn    = cert_cn     # CN from cert subject (for appearance)
        # appearance: SigAppearance-Instanz mit allen visuellen Einstellungen;
        # None → keine visuelle Erscheinung (unsichtbare Signatur)
        self.appearance = appearance   # SigAppearance instance or None
        # all_fields: alle freien unsigned Felder, die vor dem Signieren eingebettet
        # werden müssen (locked_fields sind bereits in den PDF-Bytes enthalten)
        self.all_fields = all_fields or []  # all unsigned fields to embed
        # tsa_url: URL der RFC-3161-Zeitstempelbehörde; leer → kein Zeitstempel
        self.tsa_url    = tsa_url      # RFC 3161 TSA URL, or "" to disable
        # mode: "pkcs11" (Hardware-Token) oder "pfx" (Zertifikatsdatei)
        self.mode       = mode
        # pfx_path: Pfad zur PFX/PKCS#12-Datei – nur im pfx-Modus
        self.pfx_path   = pfx_path

    # ── Shared helpers ────────────────────────────────────────────────────────

    def _build_sig_meta(self, field_name: str, cert_cn: str):
        """Build PdfSignatureMetadata from appearance settings and cert CN."""
        from pyhanko.sign.signers import PdfSignatureMetadata
        app = self.appearance
        # Name in der Signatur: bei "cert"-Modus der CN aus dem Zertifikat,
        # bei "custom"-Modus der benutzerdefinierte Text
        sig_name = (cert_cn
                    if (app and app.show_name and app.name_mode == "cert")
                    else (app.name_custom if app and app.show_name else None))
        sig_location = app.location if app and app.show_location else None
        sig_reason   = app.reason   if app and app.show_reason   else None
        return PdfSignatureMetadata(
            field_name=field_name,
            name=sig_name     or None,
            location=sig_location or None,
            reason=sig_reason   or None,
        )

    def _build_stamp_style(self, cert_cn: str):
        """Build TextStampStyle for visual appearance, or None for invisible."""
        from pyhanko.stamp import TextStampStyle
        from pyhanko.pdf_utils.text import TextBoxStyle
        from pyhanko.pdf_utils.layout import (
            SimpleBoxLayoutRule, AxisAlignment, Margins,
        )

        app = self.appearance
        page_rotation = self.fdef.page_rotation if self.fdef else 0

        # For rotated pages use a pre-rotated Pillow image as background so
        # that the appearance content appears upright after the viewer applies
        # the page rotation.  The normal pyhanko TextStampStyle path renders
        # in the native (unrotated) field coordinate space which causes text
        # and images to appear tilted when the page has /Rotate != 0.
        # Bei rotierten Seiten: Pillow-Bild vorher gegendrehen, damit der
        # Inhalt nach der Seitendrehung durch den PDF-Betrachter aufrecht erscheint
        if page_rotation != 0 and self.fdef is not None:
            try:
                return _build_rotated_appearance(app, cert_cn, self.fdef)
            except Exception:
                traceback.print_exc(file=sys.stderr)
                return None

        if page_rotation != 0:
            return None

        try:
            # Textzeilen sammeln: je nach Konfiguration Name, Ort, Grund und Datum
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
            # pyhanko ersetzt %(ts)s beim Signieren durch den aktuellen
            # Zeitstempel im angegebenen Format
            if app and app.show_date:
                text_lines.append("%(ts)s")
                ts_format = app.date_format or "%d.%m.%Y %H:%M"
            else:
                ts_format = "%d.%m.%Y %H:%M"

            # Leerer Text → einzelnes Leerzeichen damit pyhanko keinen
            # Fallback-Text einfügt
            stamp_text = "\n".join(text_lines) if text_lines else " "

            # Hintergrundbild mit transparentem Text-Streifen aufbauen
            # (Image-Padding-Trick, siehe appearance.py)
            from .appearance import _make_background_image
            background_image = None
            img_path = app.image_path if app else ""
            if img_path and Path(img_path).exists():
                background_image = _make_background_image(
                    img_path,
                    layout=app.layout if app else "img_left",
                    img_ratio=app.img_ratio if app else 40,
                )

            # Basis-Argumente für den TextStampStyle
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
                # Hintergrundbild hinzufügen und Textausrichtung anpassen:
                # Bei Bild links → Text rechtsbündig (ALIGN_MAX),
                # bei Bild rechts → Text linksbündig (ALIGN_MIN)
                style_kwargs["background"]         = background_image
                style_kwargs["background_opacity"] = 1.0
                x_align = (AxisAlignment.ALIGN_MAX
                            if app and app.layout == "img_left"
                            else AxisAlignment.ALIGN_MIN)
                style_kwargs["inner_content_layout"] = SimpleBoxLayoutRule(
                    x_align=x_align,
                    y_align=AxisAlignment.ALIGN_MID,
                    margins=Margins(left=4, right=4, top=4, bottom=4),
                )
            return TextStampStyle(**style_kwargs)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            return None

    def _embed_fields(self, writer) -> None:
        """Embed all free unsigned fields into *writer* (locked fields already present)."""
        from pyhanko.sign.fields import SigFieldSpec
        import pyhanko.sign.fields as sig_fields_mod
        fields_to_embed = list(self.all_fields)
        # Sicherstellen dass das zu signierende Feld ebenfalls eingebettet wird
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

    def _make_timestamper(self):
        """Return HTTPTimeStamper if tsa_url is set, else None."""
        if self.tsa_url:
            from pyhanko.sign.timestamps import HTTPTimeStamper
            return HTTPTimeStamper(self.tsa_url)
        return None

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        if self.mode == "pfx":
            self._run_pfx()
        else:
            self._run_pkcs11()

    # ── PKCS#11 path ──────────────────────────────────────────────────────────

    def _run_pkcs11(self) -> None:
        try:
            import pkcs11 as p11
            from pyhanko.sign.pkcs11 import open_pkcs11_session, PKCS11Signer, PROTECTED_AUTH
            from pyhanko.sign.signers import PdfSigner
            from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

            # Leere PIN → PROTECTED_AUTH-Sentinel, der pyhanko anweist, die
            # PIN-Eingabe an das Hardware-PIN-Pad zu delegieren (CyberJack etc.)
            user_pin = self.pin if self.pin else PROTECTED_AUTH

            # ── Single session: signing ───────────────────────────────────────
            # The session stays open until the signature is written so that a
            # PIN-pad reader (e.g. CyberJack) is prompted only once.
            # Key and certificate are located by their shared CKA_ID.
            # Ziel-CKA_ID: Hex-String in Bytes umwandeln; None → erstes Objekt
            target_id = bytes.fromhex(self.key_id) if self.key_id else None

            # PKCS#11-Session auf Slot 0 öffnen; PIN-Eingabe wird hier ausgelöst
            # (bei Hardware-PIN-Pad leuchtet das Gerät auf / wartet auf Eingabe)
            session = open_pkcs11_session(
                lib_location=self.lib_path, slot_no=0, user_pin=user_pin)

            # Use the stored CN; fall back to reading it from the certificate.
            # CN aus der gespeicherten Konfig nutzen; falls leer, direkt vom
            # Token lesen (z.B. nach Tokentest ohne Auswahl in TokenInfoDialog)
            cert_cn = self.cert_cn
            if not cert_cn and target_id:
                try:
                    from cryptography import x509
                    # Alle Zertifikate im Token durchsuchen, das mit der Ziel-ID finden
                    for c in session.get_objects(
                            {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}):
                        try:
                            if bytes(c[p11.Attribute.ID]) == target_id:
                                raw = bytes(c[p11.Attribute.VALUE])
                                obj = x509.load_der_x509_certificate(raw)
                                # CN (Common Name) aus dem Subject extrahieren
                                attrs = obj.subject.get_attributes_for_oid(
                                    x509.NameOID.COMMON_NAME)
                                cert_cn = attrs[0].value if attrs else ""
                                break
                        except Exception:
                            pass
                except Exception:
                    pass

            # PKCS11Signer: Verknüpft Schlüssel und Zertifikat über die gemeinsame
            # CKA_ID; other_certs_to_pull=() → keine Zwischenzertifikate einfügen
            signer = PKCS11Signer(
                pkcs11_session=session,
                key_id=target_id,
                cert_id=target_id,
                other_certs_to_pull=(),
            )

            field_name = self.fdef.name if self.fdef else self.field_name
            sig_meta   = self._build_sig_meta(field_name, cert_cn)
            stamp_style = self._build_stamp_style(cert_cn)

            # PDF-Bytes in BytesIO laden und als inkrementellen Writer öffnen
            buf    = io.BytesIO(self.pdf_bytes)
            writer = IncrementalPdfFileWriter(buf, strict=False)
            self._embed_fields(writer)

            # PdfSigner: kombiniert Signatur-Metadaten, PKCS#11-Signer,
            # visuelles Erscheinungsbild und optionalen Zeitstempel
            pdf_signer = PdfSigner(
                signature_meta=sig_meta,
                signer=signer,
                stamp_style=stamp_style,  # None → no visual appearance
                timestamper=self._make_timestamper(),
            )
            # Signatur in einem Schritt anwenden und Ergebnis direkt auf Disk schreiben
            with open(self.out_path, "wb") as outf:
                pdf_signer.sign_pdf(writer, output=outf)

            # PKCS#11-Session explizit schließen (gibt das Session-Handle zurück)
            session.close()
            # Erfolg-Signal mit Pfad zur signierten Datei senden
            self.finished.emit(self.out_path)

        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self.error.emit(str(exc))

    # ── PFX / PKCS#12 path ────────────────────────────────────────────────────

    def _run_pfx(self) -> None:
        """Sign using a PFX/PKCS#12 file certificate (SimpleSigner).

        The passphrase is taken from *self.pin*; empty string means the file
        is not password-protected.  If loading with the provided passphrase
        fails and the passphrase is empty, a second attempt with b"" is made
        to handle tools that write an explicit empty-password marker.

        Note: python-cryptography's load_pkcs12() returns only the first
        private key found.  PFX files with multiple keys (extremely rare) are
        silently handled by using the first one.  See README for details.
        """
        try:
            from cryptography.hazmat.primitives.serialization.pkcs12 import (
                load_pkcs12 as _load_pfx,
            )
            from cryptography import x509 as cx509
            from pyhanko.sign.signers import SimpleSigner, PdfSigner
            from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

            passphrase: bytes | None = self.pin.encode() if self.pin else None

            # PFX laden – erster Versuch mit dem angegebenen Passwort
            with open(self.pfx_path, "rb") as fh:
                pfx_data = fh.read()
            try:
                pkcs12 = _load_pfx(pfx_data, passphrase)
            except Exception:
                # Zweiter Versuch: explizites leeres Passwort (b"") für
                # PFX-Dateien die mit leerem Passwort-Marker erstellt wurden
                if passphrase is not None:
                    raise
                pkcs12 = _load_pfx(pfx_data, b"")
                passphrase = b""  # für SimpleSigner-Aufruf unten übernehmen

            # CN aus dem Signing-Zertifikat lesen wenn nicht in Konfig vorhanden
            cert_cn = self.cert_cn
            if not cert_cn and pkcs12.cert:
                try:
                    attrs = pkcs12.cert.certificate.subject.get_attributes_for_oid(
                        cx509.NameOID.COMMON_NAME)
                    cert_cn = attrs[0].value if attrs else ""
                except Exception:
                    pass

            # SimpleSigner: lädt Schlüssel und Zertifikat aus der PFX-Datei;
            # additional_certs (Zertifikatskette) werden automatisch eingebettet
            signer = SimpleSigner.load_pkcs12(self.pfx_path, passphrase=passphrase)

            field_name  = self.fdef.name if self.fdef else self.field_name
            sig_meta    = self._build_sig_meta(field_name, cert_cn)
            stamp_style = self._build_stamp_style(cert_cn)

            buf    = io.BytesIO(self.pdf_bytes)
            writer = IncrementalPdfFileWriter(buf, strict=False)
            self._embed_fields(writer)

            pdf_signer = PdfSigner(
                signature_meta=sig_meta,
                signer=signer,
                stamp_style=stamp_style,
                timestamper=self._make_timestamper(),
            )
            with open(self.out_path, "wb") as outf:
                pdf_signer.sign_pdf(writer, output=outf)

            self.finished.emit(self.out_path)

        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self.error.emit(str(exc))
