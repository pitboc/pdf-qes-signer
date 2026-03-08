# SPDX-License-Identifier: GPL-3.0-or-later
"""
Signature field appearance rendering for PDF QES Signer.

Provides:
  - SigAppearance            – encapsulates all visual settings; renders Qt previews
  - render_preview()         – method on SigAppearance
  - _make_background_image() – compose Pillow image for pyhanko's TextStampStyle
  - _render_appearance_to_png() – Pillow-based PNG renderer (alternative path)

## Image-padding trick for flexible positioning

A signature field is a fixed rectangle inside the PDF.  pyhanko's
`TextStampStyle` renders a background image and a text block side by side, but
the image is always stretched to fill the full field height.  To place the
image on the left or right *and* control the image-to-text ratio, a wider
canvas is constructed:

    total_width = image_width / (img_ratio / 100)

The source image is pasted at position 0 (left layout) or at
`total_width - image_width` (right layout).  The rest of the canvas is
fully transparent.  pyhanko scales this wide canvas to fit the signature
field rectangle and renders the text block into the transparent strip.

This means the "width" of the canvas encodes the desired split ratio, not a
pixel count – the final result is always scaled to the actual field dimensions.

## Rendering paths

| Path                       | Used by                                                          | Technology        |
|----------------------------|------------------------------------------------------------------|-------------------|
| `render_preview()`         | Live Qt canvas overlay and the preview panel on the right        | Qt (QPainter)     |
| `_make_background_image()` | pyhanko at signing time – non-rotated pages                      | Pillow / PdfImage |
| `_render_appearance_to_png()` | pyhanko at signing time – rotated pages (via `_build_rotated_appearance` in `signer.py`) | Pillow (PNG file) |

The Qt preview deliberately mirrors the pyhanko layout so the user sees an
accurate representation before committing to a PKCS#11 signing operation.

### Why rotated pages need a separate path

pyhanko renders a signature appearance stream in the PDF's native (unrotated)
coordinate space.  When a page carries a ``/Rotate`` entry the PDF viewer
rotates the *entire page* – including the appearance content – so text and
images inside the signature field appear tilted.

Fix: for pages with ``/Rotate != 0``, `_build_rotated_appearance` (in
`signer.py`) calls `_render_appearance_to_png()` at the *visual* (displayed)
dimensions, then counter-rotates the resulting image so that after the viewer
applies its rotation the content appears upright.  The pre-rotated PNG is
passed to pyhanko as a full-coverage background; the text layer is suppressed
(1 pt space) so pyhanko does not add its own tilted text on top.
"""

from __future__ import annotations

import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QPointF, QRectF
from PyQt6.QtGui import (
    QPixmap, QPainter, QPen, QColor, QFont, QFontMetricsF,
)

from .config import AppConfig, PDF_STANDARD_FONTS


class SigAppearance:
    """Encapsulates all appearance settings and renders the signature field preview."""

    def __init__(self, config: AppConfig) -> None:
        # config: AppConfig-Instanz; alle Einstellungen werden daraus gelesen.
        # SigAppearance hält keine eigene Kopie der Werte – alle Properties
        # delegieren direkt an die Konfig, damit Änderungen sofort wirksam sind.
        self.config = config

    # ── Settings accessors ────────────────────────────────────────────────

    @property
    def image_path(self) -> str:
        # Pfad zum Hintergrundbild des Signaturfelds (leer = kein Bild)
        return self.config.get("appearance", "image_path")

    @property
    def layout(self) -> str:
        # Layout-Variante: "img_left" (Bild links) oder "img_right" (Bild rechts)
        return self.config.get("appearance", "layout")

    @property
    def show_location(self) -> bool:
        return self.config.getbool("appearance", "show_location")

    @property
    def location(self) -> str:
        # Ort der Signatur (z.B. "Berlin") – wird in der Signaturanzeige gezeigt
        return self.config.get("appearance", "location")

    @property
    def show_reason(self) -> bool:
        return self.config.getbool("appearance", "show_reason")

    @property
    def reason(self) -> str:
        # Signaturgrund (z.B. "Genehmigung") – wird im Signaturfeld angezeigt
        return self.config.get("appearance", "reason")

    @property
    def show_name(self) -> bool:
        return self.config.getbool("appearance", "show_name")

    @property
    def name_mode(self) -> str:
        # Namensquelle: "cert" = CN aus dem Zertifikat, "custom" = Freitext
        return self.config.get("appearance", "name_mode")

    @property
    def name_custom(self) -> str:
        # Benutzerdefinierter Anzeigename (nur relevant wenn name_mode == "custom")
        return self.config.get("appearance", "name_custom")

    @property
    def show_date(self) -> bool:
        return self.config.getbool("appearance", "show_date")

    @property
    def date_format(self) -> str:
        # Python-strftime-Format für den Zeitstempel im Signaturfeld
        return self.config.get("appearance", "date_format")

    @property
    def font_size(self) -> int:
        # Schriftgröße in Punkten; Fallback auf 8pt bei ungültigem Wert
        try:
            return int(self.config.get("appearance", "font_size"))
        except ValueError:
            return 8

    @property
    def font_pdf_name(self) -> str:
        """PDF font name for pyhanko (e.g. 'Helvetica-Bold')."""
        # Gespeicherten PDF-Fontnamen aus der Konfig holen und validieren;
        # nur bekannte PDF-14-Standardschriften sind gültig
        saved = self.config.get("appearance", "font_family") or "Helvetica"
        for _, pdf_name, _, _ in PDF_STANDARD_FONTS:
            if pdf_name == saved:
                return pdf_name
        return "Helvetica"

    @property
    def font_avg_width(self) -> float:
        # Durchschnittliche Zeichenbreite (relativ zur Schriftgröße) für pyhanko.
        # Wird von SimpleFontEngineFactory für die Textbreitenberechnung benötigt.
        saved = self.config.get("appearance", "font_family") or "Helvetica"
        for _, pdf_name, avg_w, _ in PDF_STANDARD_FONTS:
            if pdf_name == saved:
                return avg_w
        return 0.5

    @property
    def font_qt_family(self) -> str:
        """Qt font family for preview rendering."""
        # Qt-seitige Font-Familie für die Canvas-Vorschau; muss zur PDF-Schrift
        # passen, damit die Vorschau das endgültige PDF-Erscheinungsbild widerspiegelt
        saved = self.config.get("appearance", "font_family") or "Helvetica"
        for _, pdf_name, _, qt_fam in PDF_STANDARD_FONTS:
            if pdf_name == saved:
                return qt_fam
        return "Helvetica"

    @property
    def img_ratio(self) -> int:
        # Prozentualer Anteil des Bildes an der Gesamtbreite des Signaturfelds.
        # Gültig: 10–70 %; Werte außerhalb werden geclampt.
        try:
            return max(10, min(70, int(
                self.config.get("appearance", "img_ratio") or "40")))
        except ValueError:
            return 40

    @property
    def show_border(self) -> bool:
        # True → dünner Rahmen um das Signaturfeld zeichnen
        return self.config.getbool("appearance", "show_border")

    # ── Qt preview rendering ──────────────────────────────────────────────

    def render_preview(self, width: int, height: int,
                       cert_name: str = "",
                       pixels_per_point: float = 1.0) -> QPixmap:
        """Render a QPixmap of the signature field at the given pixel size.

        Args:
            width, height:      Target size in pixels.
            cert_name:          Subject CN from the signing certificate (may be
                                empty when not yet known).
            pixels_per_point:   How many pixels correspond to one PDF point.
                                Use ZOOM (e.g. 1.5) for the canvas overlay and
                                96/72 ≈ 1.333 for the preview panel.
        """
        # Transparenter Canvas: Das Signaturfeld wird auf den PDF-Seitenhintergrund
        # gelegt; Bereiche ohne Inhalt müssen durchsichtig bleiben
        pixmap = QPixmap(width, height)
        pixmap.fill(Qt.GlobalColor.transparent)

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

        rect = QRectF(0, 0, width, height)

        # Background tint
        # Schwacher Blau-Schimmer als Hintergrundtönung des Signaturfelds
        painter.fillRect(rect, QColor(208, 228, 255, 60))

        # Optional border
        # Gestrichelter blauer Rahmen (nur wenn konfiguriert)
        if self.show_border:
            pen = QPen(QColor("#1a73e8"), 1.5, Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.drawRect(rect.adjusted(1, 1, -1, -1))

        # Load signature image if configured
        # Hintergrundbild laden; None wenn kein Pfad konfiguriert oder Datei fehlt
        img_pixmap: Optional[QPixmap] = None
        if self.image_path and Path(self.image_path).exists():
            img_pixmap = QPixmap(self.image_path)

        # Assemble text lines
        # Namensauflösung: bei "cert"-Modus erst übergebenen cert_name versuchen,
        # dann cert_cn aus der Konfig; bei "custom"-Modus direkt name_custom
        lines: list[str] = []
        resolved_cert_name = cert_name or (
            self.config.get("pkcs11", "cert_cn") if self.name_mode == "cert" else "")
        name = resolved_cert_name if self.name_mode == "cert" and resolved_cert_name \
               else self.name_custom
        if self.show_name and name:
            lines.append(name)
        if self.show_location and self.location:
            lines.append(self.location)
        if self.show_reason and self.reason:
            lines.append(self.reason)
        if self.show_date:
            try:
                # Aktuelles Datum/Uhrzeit mit dem konfigurierten Format formatieren
                lines.append(datetime.now().strftime(self.date_format))
            except Exception:
                # Ungültiges Format → Fallback auf einfaches Datumsformat
                lines.append(datetime.now().strftime("%d.%m.%Y"))

        # Split into image area and text area
        # Bildbereich und Textbereich berechnen basierend auf Bild-Text-Verhältnis
        PADDING = 4  # innerer Abstand in Pixeln
        ratio = self.img_ratio / 100.0
        if img_pixmap and not img_pixmap.isNull():
            # Aufteilung der Breite: split-Pixel für Bild, Rest für Text
            split = int(width * ratio)
            if self.layout == "img_left":
                # Bild links, Text rechts
                img_rect  = QRectF(PADDING, PADDING,
                                   split - 2 * PADDING, height - 2 * PADDING)
                text_rect = QRectF(split + PADDING, PADDING,
                                   width - split - 2 * PADDING, height - 2 * PADDING)
            else:
                # Text links, Bild rechts
                text_rect = QRectF(PADDING, PADDING,
                                   width - split - 2 * PADDING, height - 2 * PADDING)
                img_rect  = QRectF(width - split + PADDING, PADDING,
                                   split - 2 * PADDING, height - 2 * PADDING)
            # Bild unter Wahrung des Seitenverhältnisses in den Bildbereich zeichnen
            self._draw_image_aspect(painter, img_pixmap, img_rect)
        else:
            # Kein Bild → gesamte Breite für Text nutzen
            text_rect = QRectF(PADDING, PADDING,
                               width - 2 * PADDING, height - 2 * PADDING)

        # Draw text lines, vertically centred
        # Textzeilen vertikal zentriert im Textbereich zeichnen
        if lines:
            painter.setPen(QPen(QColor("#1a3060")))
            font = QFont(self.font_qt_family)
            # Schriftgröße in Pixeln skaliert mit dem Zoom-Faktor;
            # Minimum 4px damit Text sichtbar bleibt
            font.setPixelSize(max(4, round(self.font_size * pixels_per_point)))
            painter.setFont(font)
            fm = QFontMetricsF(font)
            # Compact line spacing matching pyhanko: ascent + descent only
            # Zeilenhöhe ohne Leading (Zwischenraum zwischen Zeilen), um das
            # pyhanko-Layout möglichst genau zu spiegeln
            line_h = fm.ascent() + fm.descent()
            total_h = line_h * len(lines)
            # Y-Startposition für vertikale Zentrierung berechnen
            y_start = (text_rect.top()
                       + (text_rect.height() - total_h) / 2
                       + fm.ascent())
            # Fixed horizontal indent in pixels
            x_start = text_rect.left() + 15
            y = y_start
            for line in lines:
                # Zeilen abschneiden die über den Textbereich hinausgehen
                if y - fm.ascent() > text_rect.bottom():
                    break
                # Zu lange Zeilen mit "…" abkürzen (Ellipsis am Ende)
                elided = fm.elidedText(
                    line, Qt.TextElideMode.ElideRight, text_rect.width())
                painter.drawText(QPointF(x_start, y), elided)
                y += line_h
        elif not img_pixmap:
            # Fallback placeholder
            # Weder Text noch Bild konfiguriert → Platzhalter-Text anzeigen
            painter.setPen(QPen(QColor("#1a73e8")))
            painter.setFont(QFont("Arial", 9, QFont.Weight.Bold))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "✍ Signature")

        painter.end()
        return pixmap

    @staticmethod
    def _draw_image_aspect(painter: QPainter, pixmap: QPixmap,
                           target: QRectF) -> None:
        """Draw *pixmap* into *target* rect, preserving aspect ratio, centred."""
        pw, ph = pixmap.width(), pixmap.height()
        tw, th = target.width(), target.height()
        # Ungültige Dimensionen verhindern Division durch Null
        if pw <= 0 or ph <= 0 or tw <= 0 or th <= 0:
            return
        # Einheitlicher Skalierungsfaktor: kleinstmögliche Skalierung
        # damit das Bild vollständig in den Zielbereich passt
        scale = min(tw / pw, th / ph)
        dw, dh = pw * scale, ph * scale
        # Bild im Zielbereich zentrieren
        dx = target.left() + (tw - dw) / 2
        dy = target.top()  + (th - dh) / 2
        painter.drawPixmap(QRectF(dx, dy, dw, dh), pixmap, QRectF(pixmap.rect()))


# ── Pillow-based PNG renderer (alternative, not used by default) ──────────────

def _render_appearance_to_png(appearance: SigAppearance, cert_name: str,
                               width_pt: float, height_pt: float) -> Optional[str]:
    """Render the configured appearance as a PNG to a temp file using Pillow.

    Returns the file path, or None on failure.
    This function provides an alternative rendering path independent of Qt.
    """
    # Temporäre Datei für das PNG-Bild; wird von _build_rotated_appearance
    # geöffnet und nach dem Einlesen gelöscht
    import tempfile
    try:
        from PIL import Image as PILImage, ImageDraw, ImageFont
        import glob as _glob

        # Namensauflösung wie in render_preview(): cert oder custom
        name = cert_name if appearance.name_mode == "cert" and cert_name \
               else appearance.name_custom
        lines: list[str] = []
        if appearance.show_name and name:
            lines.append(name)
        if appearance.show_location and appearance.location:
            lines.append(appearance.location)
        if appearance.show_reason and appearance.reason:
            lines.append(appearance.reason)
        if appearance.show_date:
            try:
                lines.append(datetime.now().strftime(appearance.date_format))
            except Exception:
                lines.append(datetime.now().strftime("%d.%m.%Y"))

        # SCALE: Überabtastungsfaktor für schärferes Rendering; das Ergebnis
        # wird von pyhanko auf die tatsächliche Feldgröße herunterskaliert
        SCALE = 3
        px_w = max(4, int(width_pt  * SCALE))
        px_h = max(4, int(height_pt * SCALE))
        PADDING = int(4 * SCALE)

        # RGBA with transparent base: empty areas and text background stay
        # transparent (page content shows through), only the image area gets
        # an opaque white backing so the signature graphic appears clearly.
        # Transparenter RGBA-Canvas: Seiteninhalt scheint durch leere Bereiche durch
        img = PILImage.new("RGBA", (px_w, px_h), (255, 255, 255, 0))
        draw = ImageDraw.Draw(img)
        # Optionaler schwarzer Rahmen (1px * SCALE Breite für gute Sichtbarkeit)
        if appearance.show_border:
            draw.rectangle([1, 1, px_w - 2, px_h - 2],
                           outline=(0, 0, 0, 255), width=max(1, SCALE))

        img_path = appearance.image_path
        has_image = bool(img_path and Path(img_path).exists())

        if has_image:
            # Bildbereich und Textbereich berechnen (analog zu render_preview)
            split = int(px_w * (appearance.img_ratio / 100.0))
            if appearance.layout == "img_left":
                img_box  = (PADDING, PADDING, split - PADDING, px_h - PADDING)
                text_box = (split + PADDING, PADDING, px_w - PADDING, px_h - PADDING)
            else:
                text_box = (PADDING, PADDING, px_w - split - PADDING, px_h - PADDING)
                img_box  = (px_w - split + PADDING, PADDING,
                            px_w - PADDING, px_h - PADDING)

            # Quellbild öffnen, skalieren und in den Bildbereich einfügen
            src = PILImage.open(img_path).convert("RGBA")
            bw = img_box[2] - img_box[0]
            bh = img_box[3] - img_box[1]
            if bw > 0 and bh > 0:
                # Seitenverhältnis wahren (analog zu _draw_image_aspect)
                scale_f = min(bw / src.width, bh / src.height)
                nw = max(1, int(src.width  * scale_f))
                nh = max(1, int(src.height * scale_f))
                # LANCZOS: hochwertiger Resampling-Filter für scharfe Bilder
                src_s = src.resize((nw, nh), PILImage.LANCZOS)
                # Bild im Bildbereich zentrieren
                ox = img_box[0] + (bw - nw) // 2
                oy = img_box[1] + (bh - nh) // 2
                # Bild mit Alpha-Maske einfügen (src_s = Maske für Transparenz)
                img.paste(src_s, (ox, oy), src_s)
        else:
            # Kein Bild → gesamte Breite (minus Padding) für Text nutzen
            text_box = (PADDING, PADDING, px_w - PADDING, px_h - PADDING)

        # Schriftgröße skaliert mit SCALE; Minimum 8px für Lesbarkeit
        font_size_px = max(8, appearance.font_size * SCALE)
        # Passenden System-Font suchen (plattformübergreifende Kandidatenliste)
        font = None
        for candidate in [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "C:/Windows/Fonts/arial.ttf",
        ]:
            if Path(candidate).exists():
                try:
                    font = ImageFont.truetype(candidate, font_size_px)
                    break
                except Exception:
                    pass
        # Fallback: ersten verfügbaren TrueType-Font aus dem System-Font-Ordner
        if font is None:
            ttfs = _glob.glob("/usr/share/fonts/**/*.ttf", recursive=True)
            if ttfs:
                try:
                    font = ImageFont.truetype(ttfs[0], font_size_px)
                except Exception:
                    pass
        # Letzter Fallback: Pillow-Eingebetteter Bitmap-Font (sehr kleine Auflösung)
        if font is None:
            font = ImageFont.load_default()

        # Textbereich-Koordinaten extrahieren
        text_color = (0, 0, 0, 255)
        tb_x0, tb_y0, tb_x1, tb_y1 = text_box
        tb_w = tb_x1 - tb_x0
        tb_h = tb_y1 - tb_y0
        line_gap = int(1 * SCALE)  # kleiner Zeilenabstand

        # Pre-compute line heights for vertical centering
        # Zeilenhöhen vorberechnen und zu lange Zeilen kürzen (mit Ellipsis)
        line_data: list[tuple[str, int]] = []
        for line in lines:
            bbox = draw.textbbox((0, 0), line, font=font)
            lw = bbox[2] - bbox[0]
            lh = bbox[3] - bbox[1]
            # Zeile kürzen wenn sie breiter als der Textbereich ist
            if lw > tb_w and len(line) > 3:
                while len(line) > 1:
                    line = line[:-1]
                    bbox = draw.textbbox((0, 0), line + "…", font=font)
                    if bbox[2] - bbox[0] <= tb_w:
                        line += "…"
                        break
                lh = draw.textbbox((0, 0), line, font=font)[3]
            line_data.append((line, lh))

        # Gesamthöhe aller Zeilen für vertikale Zentrierung berechnen
        total_h = sum(lh for _, lh in line_data) + line_gap * max(0, len(line_data) - 1)
        y = tb_y0 + max(int(2 * SCALE), (tb_h - total_h) // 2)
        for line, lh in line_data:
            # Zeilen abschneiden die über den Textbereich hinausgehen
            if y + lh > tb_y1:
                break
            draw.text((tb_x0, y), line, font=font, fill=text_color)
            y += lh + line_gap

        # Gerendertes Bild in temporäre PNG-Datei schreiben
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        img.save(tmp.name, "PNG")
        tmp.close()
        # Pfad zurückgeben; Aufrufer ist verantwortlich für das Löschen der Datei
        return tmp.name

    except Exception:
        traceback.print_exc(file=sys.stderr)
        return None


def _make_background_image(img_path: str, layout: str = "img_left",
                            img_ratio: int = 40):
    """Compose a pyhanko PdfImage from *img_path* with a transparent text strip.

    The source image occupies *img_ratio* % of the total width; the remaining
    width is transparent so pyhanko's TextStampStyle can render text beside it.

    Args:
        layout:    "img_left"  – image on the left, transparent strip on the right.
                   "img_right" – transparent strip on the left, image on the right.
        img_ratio: Percentage of total width occupied by the image (10–70).
    """
    from pyhanko.pdf_utils.images import PdfImage
    from PIL import Image as PILImage

    # Quellbild als RGBA laden (Transparenz wird für den Text-Strip benötigt)
    src = PILImage.open(img_path).convert("RGBA")
    iw, ih = src.size

    # Total width: image takes img_ratio % → canvas = iw / (img_ratio / 100)
    # Canvas breiter als das Quellbild: Das Verhältnis Bild/Gesamtbreite
    # entspricht img_ratio/100.  Die Breite des Canvas kodiert also die
    # gewünschte Aufteilung (Trick statt pixel count – pyhanko skaliert Canvas
    # auf die tatsächliche Feldgröße).
    total_w = int(iw / (img_ratio / 100.0))
    # Transparenter Canvas: Text-Strip bleibt leer damit pyhanko Text einbettet
    canvas = PILImage.new("RGBA", (total_w, ih), (255, 255, 255, 0))

    # Bild an der richtigen Position auf den Canvas kleben
    if layout == "img_left":
        # Bild links (Position 0): transparenter Strip rechts für Text
        canvas.paste(src, (0, 0))
    else:
        # Bild rechts (Ende des Canvas): transparenter Strip links für Text
        canvas.paste(src, (total_w - iw, 0))

    # PdfImage-Wrapper für pyhanko; wird als TextStampStyle.background übergeben
    return PdfImage(canvas)
