# SPDX-License-Identifier: GPL-3.0-or-later
"""
Signature field appearance rendering for PDF QES Signer.

Provides:
  - SigAppearance        – encapsulates all visual settings; renders Qt previews
  - render_preview()     – method on SigAppearance
  - _make_background_image() – compose Pillow image for pyhanko's TextStampStyle
  - _render_appearance_to_png() – Pillow-based PNG renderer (alternative path)
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
        self.config = config

    # ── Settings accessors ────────────────────────────────────────────────

    @property
    def image_path(self) -> str:
        return self.config.get("appearance", "image_path")

    @property
    def layout(self) -> str:
        return self.config.get("appearance", "layout")

    @property
    def show_location(self) -> bool:
        return self.config.getbool("appearance", "show_location")

    @property
    def location(self) -> str:
        return self.config.get("appearance", "location")

    @property
    def show_reason(self) -> bool:
        return self.config.getbool("appearance", "show_reason")

    @property
    def reason(self) -> str:
        return self.config.get("appearance", "reason")

    @property
    def show_name(self) -> bool:
        return self.config.getbool("appearance", "show_name")

    @property
    def name_mode(self) -> str:
        return self.config.get("appearance", "name_mode")

    @property
    def name_custom(self) -> str:
        return self.config.get("appearance", "name_custom")

    @property
    def show_date(self) -> bool:
        return self.config.getbool("appearance", "show_date")

    @property
    def date_format(self) -> str:
        return self.config.get("appearance", "date_format")

    @property
    def font_size(self) -> int:
        try:
            return int(self.config.get("appearance", "font_size"))
        except ValueError:
            return 8

    @property
    def font_pdf_name(self) -> str:
        """PDF font name for pyhanko (e.g. 'Helvetica-Bold')."""
        saved = self.config.get("appearance", "font_family") or "Helvetica"
        for _, pdf_name, _, _ in PDF_STANDARD_FONTS:
            if pdf_name == saved:
                return pdf_name
        return "Helvetica"

    @property
    def font_avg_width(self) -> float:
        saved = self.config.get("appearance", "font_family") or "Helvetica"
        for _, pdf_name, avg_w, _ in PDF_STANDARD_FONTS:
            if pdf_name == saved:
                return avg_w
        return 0.5

    @property
    def font_qt_family(self) -> str:
        """Qt font family for preview rendering."""
        saved = self.config.get("appearance", "font_family") or "Helvetica"
        for _, pdf_name, _, qt_fam in PDF_STANDARD_FONTS:
            if pdf_name == saved:
                return qt_fam
        return "Helvetica"

    @property
    def img_ratio(self) -> int:
        try:
            return max(10, min(70, int(
                self.config.get("appearance", "img_ratio") or "40")))
        except ValueError:
            return 40

    @property
    def show_border(self) -> bool:
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
        pixmap = QPixmap(width, height)
        pixmap.fill(Qt.GlobalColor.transparent)

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

        rect = QRectF(0, 0, width, height)

        # Background tint
        painter.fillRect(rect, QColor(208, 228, 255, 60))

        # Optional border
        if self.show_border:
            pen = QPen(QColor("#1a73e8"), 1.5, Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.drawRect(rect.adjusted(1, 1, -1, -1))

        # Load signature image if configured
        img_pixmap: Optional[QPixmap] = None
        if self.image_path and Path(self.image_path).exists():
            img_pixmap = QPixmap(self.image_path)

        # Assemble text lines
        lines: list[str] = []
        name = cert_name if self.name_mode == "cert" and cert_name \
               else self.name_custom
        if self.show_name and name:
            lines.append(name)
        if self.show_location and self.location:
            lines.append(self.location)
        if self.show_reason and self.reason:
            lines.append(self.reason)
        if self.show_date:
            try:
                lines.append(datetime.now().strftime(self.date_format))
            except Exception:
                lines.append(datetime.now().strftime("%d.%m.%Y"))

        # Split into image area and text area
        PADDING = 4
        ratio = self.img_ratio / 100.0
        if img_pixmap and not img_pixmap.isNull():
            split = int(width * ratio)
            if self.layout == "img_left":
                img_rect  = QRectF(PADDING, PADDING,
                                   split - 2 * PADDING, height - 2 * PADDING)
                text_rect = QRectF(split + PADDING, PADDING,
                                   width - split - 2 * PADDING, height - 2 * PADDING)
            else:
                text_rect = QRectF(PADDING, PADDING,
                                   width - split - 2 * PADDING, height - 2 * PADDING)
                img_rect  = QRectF(width - split + PADDING, PADDING,
                                   split - 2 * PADDING, height - 2 * PADDING)
            self._draw_image_aspect(painter, img_pixmap, img_rect)
        else:
            text_rect = QRectF(PADDING, PADDING,
                               width - 2 * PADDING, height - 2 * PADDING)

        # Draw text lines, vertically centred
        if lines:
            painter.setPen(QPen(QColor("#1a3060")))
            font = QFont(self.font_qt_family)
            font.setPixelSize(max(4, round(self.font_size * pixels_per_point)))
            painter.setFont(font)
            fm = QFontMetricsF(font)
            # Compact line spacing matching pyhanko: ascent + descent only
            line_h = fm.ascent() + fm.descent()
            total_h = line_h * len(lines)
            y_start = (text_rect.top()
                       + (text_rect.height() - total_h) / 2
                       + fm.ascent())
            # Fixed horizontal indent in pixels
            x_start = text_rect.left() + 15
            y = y_start
            for line in lines:
                if y - fm.ascent() > text_rect.bottom():
                    break
                elided = fm.elidedText(
                    line, Qt.TextElideMode.ElideRight, text_rect.width())
                painter.drawText(QPointF(x_start, y), elided)
                y += line_h
        elif not img_pixmap:
            # Fallback placeholder
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
        if pw <= 0 or ph <= 0 or tw <= 0 or th <= 0:
            return
        scale = min(tw / pw, th / ph)
        dw, dh = pw * scale, ph * scale
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
    import tempfile
    try:
        from PIL import Image as PILImage, ImageDraw, ImageFont
        import glob as _glob

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

        SCALE = 3
        px_w = max(4, int(width_pt  * SCALE))
        px_h = max(4, int(height_pt * SCALE))
        PADDING = int(4 * SCALE)

        img = PILImage.new("RGBA", (px_w, px_h), (255, 255, 255, 0))
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, px_w - 1, px_h - 1], fill=(208, 228, 255, 120))
        if appearance.show_border:
            draw.rectangle([1, 1, px_w - 2, px_h - 2],
                           outline=(26, 115, 232, 255), width=max(1, SCALE))

        img_path = appearance.image_path
        has_image = bool(img_path and Path(img_path).exists())

        if has_image:
            split = int(px_w * 0.40)
            if appearance.layout == "img_left":
                img_box  = (PADDING, PADDING, split - PADDING, px_h - PADDING)
                text_box = (split + PADDING, PADDING, px_w - PADDING, px_h - PADDING)
            else:
                text_box = (PADDING, PADDING, px_w - split - PADDING, px_h - PADDING)
                img_box  = (px_w - split + PADDING, PADDING,
                            px_w - PADDING, px_h - PADDING)

            src = PILImage.open(img_path).convert("RGBA")
            bw = img_box[2] - img_box[0]
            bh = img_box[3] - img_box[1]
            if bw > 0 and bh > 0:
                scale_f = min(bw / src.width, bh / src.height)
                nw = max(1, int(src.width  * scale_f))
                nh = max(1, int(src.height * scale_f))
                src_s = src.resize((nw, nh), PILImage.LANCZOS)
                ox = img_box[0] + (bw - nw) // 2
                oy = img_box[1] + (bh - nh) // 2
                img.paste(src_s, (ox, oy), src_s)
        else:
            text_box = (PADDING, PADDING, px_w - PADDING, px_h - PADDING)

        font_size_px = max(8, appearance.font_size * SCALE)
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
        if font is None:
            ttfs = _glob.glob("/usr/share/fonts/**/*.ttf", recursive=True)
            if ttfs:
                try:
                    font = ImageFont.truetype(ttfs[0], font_size_px)
                except Exception:
                    pass
        if font is None:
            font = ImageFont.load_default()

        text_color = (26, 48, 96, 255)
        tb_x0, tb_y0, tb_x1, tb_y1 = text_box
        tb_w = tb_x1 - tb_x0
        y = tb_y0 + int(2 * SCALE)
        for line in lines:
            bbox = draw.textbbox((0, 0), line, font=font)
            lw = bbox[2] - bbox[0]
            lh = bbox[3] - bbox[1]
            if lw > tb_w and len(line) > 3:
                while len(line) > 1:
                    line = line[:-1]
                    bbox = draw.textbbox((0, 0), line + "…", font=font)
                    if bbox[2] - bbox[0] <= tb_w:
                        line += "…"
                        break
            if y + lh > tb_y1:
                break
            draw.text((tb_x0, y), line, font=font, fill=text_color)
            y += lh + int(1 * SCALE)

        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        img.save(tmp.name, "PNG")
        tmp.close()
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

    src = PILImage.open(img_path).convert("RGBA")
    iw, ih = src.size

    # Total width: image takes img_ratio % → canvas = iw / (img_ratio / 100)
    total_w = int(iw / (img_ratio / 100.0))
    canvas = PILImage.new("RGBA", (total_w, ih), (255, 255, 255, 0))

    if layout == "img_left":
        canvas.paste(src, (0, 0))
    else:
        canvas.paste(src, (total_w - iw, 0))

    return PdfImage(canvas)
