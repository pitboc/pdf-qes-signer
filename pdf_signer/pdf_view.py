# SPDX-License-Identifier: GPL-3.0-or-later
"""
PDF canvas widget and signature field data model for PDF QES Signer.

Provides:
  - DPI_SCALE         – screen pixels per PDF point for preview rendering (96/72)
  - SignatureFieldDef – data class holding one signature field in PDF coordinates
  - PDFViewWidget     – interactive Qt widget for displaying a PDF page and
                        drawing/deleting signature fields

## Coordinate systems

Two coordinate systems are in use simultaneously:

| Space       | Origin      | Y direction | Unit           | Used in                    |
|-------------|-------------|-------------|----------------|----------------------------|
| Widget/Qt   | Top-left    | Down        | pixels         | Mouse events, painting     |
| PDF native  | Bottom-left | Up          | points (1/72") | SignatureFieldDef, pyhanko |

`PDFViewWidget._w_to_pdf()` converts a mouse position to PDF native coordinates.
`PDFViewWidget._pdf_to_w()` converts PDF native coordinates back to widget pixels.

Both methods use `page.derotation_matrix` / `page.rotation_matrix` (fitz) to
handle pages with a `/Rotate` entry (common in scanned documents).  Without
this, a 90°-rotated page would cause fields to be placed at a mirrored or
transposed position in the signed output.

Conversion pipeline for `_w_to_pdf`:
  widget pixels → fitz canonical (rotated, y-down) → derotate → flip Y → PDF native

Conversion pipeline for `_pdf_to_w`:
  PDF native → flip Y → rotate → fitz canonical (rotated, y-down) → widget pixels

## Zoom and DPI

`PDFViewWidget.ZOOM = 1.5` is the default zoom factor; each instance stores
`_zoom` (initially `PDFViewWidget.ZOOM`), so zoom can be changed at runtime
without affecting other instances.  The canvas widget size is therefore
`page_width_pt × _zoom` by `page_height_pt × _zoom` pixels.

`DPI_SCALE = 96/72 ≈ 1.333` is used by the *preview panel* on the right side
of the main window, which renders appearance thumbnails at 96 screen DPI.

## Mouse wheel events

- No modifier       : passes through to the parent scroll area (vertical scroll).
- `Shift` + wheel   : emits `hscroll_requested(int)` – horizontal scroll.
- `Ctrl`  + wheel   : emits `zoom_requested(int, QPointF)` – zoom in/out
                      centred on the cursor position in widget coordinates.

## Visual differentiation of field types

Fields are painted with different colours to reflect their edit state:

| Field type    | Colour            | Interaction          |
|---------------|-------------------|----------------------|
| sig_fields    | Blue (#1a73e8)    | Draw, delete, rename |
| locked_fields | Orange (#e67e00)  | Sign only            |
| signed_fields | Grey (#888888)    | Display only (✓)     |
"""

from __future__ import annotations

from typing import Optional

import fitz  # PyMuPDF

from PyQt6.QtCore import Qt, QPointF, QRectF
from PyQt6.QtGui import (
    QPixmap, QImage, QPainter, QPen, QColor, QBrush, QFont,
)
from PyQt6.QtWidgets import QWidget, QSizePolicy, QInputDialog, QMessageBox

from .appearance import SigAppearance
from .i18n import t

# Pixels per PDF point for the off-canvas preview panel (96 screen DPI / 72 pt DPI)
DPI_SCALE: float = 96.0 / 72.0


class SignatureFieldDef:
    """A signature field definition in PDF coordinates (72 DPI points).

    Coordinates are native PDF points with the origin at the bottom-left of
    the page.  They are *not* screen pixels.

    Attributes:
        page:       Zero-based page index.
        x1, y1:     Bottom-left corner (PDF points).
        x2, y2:     Top-right corner (PDF points).
        name:       Unique field name embedded in the PDF.
    """

    def __init__(self, page: int,
                 x1: float, y1: float,
                 x2: float, y2: float,
                 name: str = "Signature",
                 rotation: int = 0) -> None:
        self.page = page
        self.x1, self.y1 = x1, y1
        self.x2, self.y2 = x2, y2
        self.name = name
        self.page_rotation = rotation  # /Rotate value of the page (0/90/180/270)

    def __repr__(self) -> str:
        return (f"<SigField '{self.name}' page={self.page + 1} "
                f"[{self.x1:.0f},{self.y1:.0f},{self.x2:.0f},{self.y2:.0f}]>")


class PDFViewWidget(QWidget):
    """Interactive widget that renders a PDF page and lets the user draw and
    delete signature fields by mouse interaction.

    Left-click + drag        → draw a new signature field rectangle.
    Ctrl + left-click + drag → rubber-band zoom: drag a rectangle and the view
                               zooms to fit it in the viewport.
    Right-click on field     → delete that field (with confirmation dialog).

    Coordinate system:
        *Widget* space uses pixel coordinates (origin top-left, Y down).
        *PDF* space uses point coordinates (origin bottom-left, Y up).
        The ``_pdf_to_w`` / ``_w_to_pdf`` helpers convert between the two.

    Signals:
        field_added(SignatureFieldDef):   emitted after a new field is confirmed.
        field_deleted(SignatureFieldDef): emitted after a field is deleted.
        zoom_rect_requested(QRectF):      Ctrl+drag rubber-band rectangle
                                          (widget coordinates).
    """

    # Default zoom factor (class constant – instances shadow it via _zoom).
    ZOOM: float = 1.5

    from PyQt6.QtCore import pyqtSignal
    field_added         = pyqtSignal(object)
    field_deleted       = pyqtSignal(object)
    field_clicked       = pyqtSignal(object)       # click on existing field
    zoom_requested      = pyqtSignal(int, QPointF) # Ctrl+wheel: (angleDelta.y, cursor_in_widget)
    hscroll_requested   = pyqtSignal(int)          # Shift+wheel: angleDelta.y
    zoom_rect_requested = pyqtSignal(QRectF)       # Ctrl+drag: rubber-band rect (widget coords)
    pan_started         = pyqtSignal()             # middle button pressed: pan begins
    pan_requested       = pyqtSignal(int, int)     # middle-drag: (dx, dy) total offset from pan start

    def __init__(self, appearance: SigAppearance, parent=None) -> None:
        super().__init__(parent)
        self.appearance = appearance
        self._zoom: float = PDFViewWidget.ZOOM  # instance zoom, may differ from class default
        self.setCursor(Qt.CursorShape.CrossCursor)
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        self._pixmap:       Optional[QPixmap] = None
        self._page_w = self._page_h = 1.0
        self._img_w  = self._img_h  = 1
        self._page_rotation: int     = 0        # current page /Rotate value
        self._mediabox_h: float     = 1.0      # unrotated page height (PDF points)
        self._derot_mat: fitz.Matrix = fitz.Matrix()  # rotated → unrotated fitz coords
        self._rot_mat:   fitz.Matrix = fitz.Matrix()  # unrotated → rotated fitz coords
        self._drag_start: Optional[QPointF] = None
        self._drag_end:   Optional[QPointF] = None
        self._rb_start:   Optional[QPointF] = None   # Ctrl+drag rubber-band start
        self._rb_end:     Optional[QPointF] = None   # Ctrl+drag rubber-band end
        self._pan_start:  Optional[QPointF] = None   # middle-drag panning start
        self.drawing_enabled: bool = True             # False → no new field drag
        self._sig_fields:    list[SignatureFieldDef] = []
        self._locked_fields: list[SignatureFieldDef] = []
        self._signed_fields: list[SignatureFieldDef] = []
        self._current_page = 0
        self._selected_field: Optional[SignatureFieldDef] = None

    def set_page(self, page: fitz.Page,
                 sig_fields: list[SignatureFieldDef],
                 current_page: int,
                 locked_fields: list[SignatureFieldDef] | None = None,
                 signed_fields: list[SignatureFieldDef] | None = None) -> None:
        """Render *page* at ``_zoom`` and store the field lists for painting."""
        mat = fitz.Matrix(self._zoom, self._zoom)
        pix = page.get_pixmap(matrix=mat, alpha=False)
        img = QImage(pix.samples, pix.width, pix.height,
                     pix.stride, QImage.Format.Format_RGB888)
        self._pixmap        = QPixmap.fromImage(img)
        self._img_w         = pix.width
        self._img_h         = pix.height
        self._page_w        = page.rect.width
        self._page_h        = page.rect.height
        self._page_rotation = page.rotation
        self._mediabox_h    = page.mediabox.height
        self._derot_mat     = page.derotation_matrix
        self._rot_mat       = page.rotation_matrix
        self._sig_fields    = sig_fields
        self._locked_fields = locked_fields or []
        self._signed_fields = signed_fields or []
        self._current_page  = current_page
        self.setFixedSize(pix.width, pix.height)
        self.update()

    def refresh(self) -> None:
        """Repaint the overlay (e.g. after an appearance change)."""
        self.update()

    def update_fields(self,
                      sig_fields: list[SignatureFieldDef],
                      locked_fields: list[SignatureFieldDef],
                      signed_fields: list[SignatureFieldDef]) -> None:
        """Update field lists and repaint without re-rasterizing the page."""
        self._sig_fields    = sig_fields
        self._locked_fields = locked_fields
        self._signed_fields = signed_fields
        self.update()

    def set_selected_field(self, fdef: Optional[SignatureFieldDef]) -> None:
        """Set which field shows the full appearance preview (None = none)."""
        self._selected_field = fdef
        self.update()

    # ── Field hit-testing ─────────────────────────────────────────────────

    def _field_at(self, pos: QPointF) -> Optional["SignatureFieldDef"]:
        """Return the topmost field at widget position *pos*, or None."""
        cx, cy = pos.x(), pos.y()
        for collection in (self._locked_fields, self._sig_fields, self._signed_fields):
            for fdef in reversed(collection):
                if fdef.page != self._current_page:
                    continue
                tl = self._pdf_to_w(fdef.x1, fdef.y2)
                br = self._pdf_to_w(fdef.x2, fdef.y1)
                if QRectF(tl, br).normalized().contains(cx, cy):
                    return fdef
        return None

    # ── Coordinate conversion ─────────────────────────────────────────────

    def _pdf_to_w(self, x: float, y: float) -> QPointF:
        """Convert PDF native coordinates (unrotated, y-up) to widget pixels."""
        sx = self._img_w / self._page_w
        sy = self._img_h / self._page_h
        p = fitz.Point(x, self._mediabox_h - y) * self._rot_mat
        return QPointF(p.x * sx, p.y * sy)

    def _w_to_pdf(self, cx: float, cy: float) -> tuple[float, float]:
        """Convert widget pixel coordinates to PDF native coordinates (unrotated, y-up)."""
        sx = self._img_w / self._page_w
        sy = self._img_h / self._page_h
        p = fitz.Point(cx / sx, cy / sy) * self._derot_mat
        return p.x, self._mediabox_h - p.y

    # ── Painting ──────────────────────────────────────────────────────────

    def paintEvent(self, _) -> None:
        painter = QPainter(self)

        if self._pixmap:
            painter.drawPixmap(0, 0, self._pixmap)

        for fdef in self._sig_fields:
            if fdef.page != self._current_page:
                continue
            tl   = self._pdf_to_w(fdef.x1, fdef.y2)
            br   = self._pdf_to_w(fdef.x2, fdef.y1)
            rect = QRectF(tl, br).normalized()
            w, h = int(rect.width()), int(rect.height())
            is_selected = (fdef is self._selected_field)
            if is_selected and w > 4 and h > 4:
                # Full appearance preview only for the selected field
                px = self.appearance.render_preview(
                    w, h, pixels_per_point=self._zoom)
                painter.drawPixmap(rect.toRect(), px)
                # Bold highlight border around the selected field
                pen = QPen(QColor("#1a73e8"), 3, Qt.PenStyle.SolidLine)
                painter.setPen(pen)
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawRect(rect.adjusted(1, 1, -2, -2))
            else:
                # Other fields: light fill + dashed border only
                painter.fillRect(rect, QColor(208, 228, 255, 30))
                pen = QPen(QColor("#1a73e8"), 1, Qt.PenStyle.DashLine)
                painter.setPen(pen)
                painter.drawRect(rect.adjusted(1, 1, -1, -1))
            # Field name label in top-left corner
            painter.setPen(QPen(QColor("#1a73e8")))
            painter.setFont(QFont("Arial", 7))
            painter.drawText(QPointF(rect.left() + 2, rect.top() + 10),
                             fdef.name)

        # Locked unsigned fields: orange border, not deletable
        for fdef in self._locked_fields:
            if fdef.page != self._current_page:
                continue
            tl   = self._pdf_to_w(fdef.x1, fdef.y2)
            br   = self._pdf_to_w(fdef.x2, fdef.y1)
            rect = QRectF(tl, br).normalized()
            is_selected = (fdef is self._selected_field)
            painter.fillRect(rect, QColor(255, 180, 0, 50 if is_selected else 30))
            pen_width = 3 if is_selected else 1
            pen_style = Qt.PenStyle.SolidLine if is_selected else Qt.PenStyle.DashLine
            pen = QPen(QColor("#e67e00"), pen_width, pen_style)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(rect.adjusted(1, 1, -1, -1))
            painter.setPen(QPen(QColor("#e67e00")))
            painter.setFont(QFont("Arial", 7))
            painter.drawText(QPointF(rect.left() + 2, rect.top() + 10),
                             f"🔒 {fdef.name}")

        # Already-signed fields: grey outline + lock indicator
        for fdef in self._signed_fields:
            if fdef.page != self._current_page:
                continue
            tl   = self._pdf_to_w(fdef.x1, fdef.y2)
            br   = self._pdf_to_w(fdef.x2, fdef.y1)
            rect = QRectF(tl, br).normalized()
            painter.fillRect(rect, QColor(200, 200, 200, 40))
            pen = QPen(QColor("#888888"), 1, Qt.PenStyle.DotLine)
            painter.setPen(pen)
            painter.drawRect(rect.adjusted(1, 1, -1, -1))
            painter.setPen(QPen(QColor("#666666")))
            painter.setFont(QFont("Arial", 7))
            painter.drawText(QPointF(rect.left() + 2, rect.top() + 10),
                             f"✓ {fdef.name}")

        # Drag-to-draw preview rectangle (signature field)
        if self._drag_start and self._drag_end:
            pen = QPen(QColor("#1a73e8"), 2, Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.setBrush(QBrush(QColor(208, 228, 255, 40)))
            painter.drawRect(
                QRectF(self._drag_start, self._drag_end).normalized())

        # Rubber-band zoom selection rectangle (Ctrl+drag)
        if self._rb_start and self._rb_end:
            pen = QPen(QColor("#00aa44"), 2, Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.setBrush(QBrush(QColor(0, 200, 80, 30)))
            painter.drawRect(
                QRectF(self._rb_start, self._rb_end).normalized())

        painter.end()

    # ── Mouse events ──────────────────────────────────────────────────────

    def mousePressEvent(self, ev) -> None:
        if ev.button() == Qt.MouseButton.LeftButton:
            if ev.modifiers() & Qt.KeyboardModifier.ControlModifier:
                # Ctrl+drag: start rubber-band zoom selection
                self._rb_start = QPointF(ev.position())
                self._rb_end   = None
            else:
                fdef = self._field_at(ev.position())
                if fdef is not None:
                    # Click on an existing field → select it, don't start a drag
                    self.field_clicked.emit(fdef)
                elif self.drawing_enabled:
                    self._drag_start = QPointF(ev.position())
                    self._drag_end   = None
        elif ev.button() == Qt.MouseButton.MiddleButton:
            self._pan_start = QPointF(ev.globalPosition())
            self.setCursor(Qt.CursorShape.SizeAllCursor)
            self.pan_started.emit()
        elif ev.button() == Qt.MouseButton.RightButton:
            self._right_click(ev.position())

    def mouseMoveEvent(self, ev) -> None:
        if self._pan_start:
            pos = QPointF(ev.globalPosition())
            self.pan_requested.emit(
                int(pos.x() - self._pan_start.x()),
                int(pos.y() - self._pan_start.y()),
            )
            return
        if self._rb_start:
            self._rb_end = QPointF(ev.position())
            self.update()
        elif self._drag_start:
            self._drag_end = QPointF(ev.position())
            self.update()
        else:
            # Change cursor when hovering over a clickable field
            fdef = self._field_at(ev.position())
            self.setCursor(
                Qt.CursorShape.PointingHandCursor if fdef is not None
                else Qt.CursorShape.CrossCursor
            )

    def mouseReleaseEvent(self, ev) -> None:
        if ev.button() == Qt.MouseButton.MiddleButton:
            self._pan_start = None
            self.setCursor(Qt.CursorShape.CrossCursor)
            return
        if ev.button() != Qt.MouseButton.LeftButton:
            return

        # Rubber-band zoom release
        if self._rb_start:
            end   = QPointF(ev.position())
            start = self._rb_start
            self._rb_start = self._rb_end = None
            self.update()
            rect = QRectF(start, end).normalized()
            if rect.width() >= 20 and rect.height() >= 10:
                self.zoom_rect_requested.emit(rect)
            return

        if not self._drag_start:
            return
        end = QPointF(ev.position())
        x0, y0 = self._drag_start.x(), self._drag_start.y()
        x1, y1 = end.x(), end.y()
        self._drag_start = self._drag_end = None
        self.update()

        # Ignore accidental single clicks (minimum drag size)
        if abs(x1 - x0) < 20 or abs(y1 - y0) < 10:
            return

        px0, py0 = self._w_to_pdf(min(x0, x1), min(y0, y1))
        px1, py1 = self._w_to_pdf(max(x0, x1), max(y0, y1))
        # Find the first unused default name for this page
        all_names = ({f.name for f in self._sig_fields}
                     | {f.name for f in self._locked_fields}
                     | {f.name for f in self._signed_fields})
        n = sum(1 for f in self._sig_fields if f.page == self._current_page) + 1
        while True:
            candidate = t("dlg_field_name_default",
                          page=self._current_page + 1, count=n)
            if candidate not in all_names:
                break
            n += 1
        default = candidate
        name, ok = QInputDialog.getText(
            self, t("dlg_field_name_title"), t("dlg_field_name_prompt"),
            text=default)
        if not ok or not name:
            return

        # Reject duplicate names (check against all field categories)
        existing_names = ({f.name for f in self._sig_fields}
                          | {f.name for f in self._locked_fields}
                          | {f.name for f in self._signed_fields})
        if name in existing_names:
            QMessageBox.warning(
                self, t("dlg_field_name_title"),
                t("dlg_field_name_duplicate", name=name))
            return

        fdef = SignatureFieldDef(self._current_page, px0, py0, px1, py1, name,
                                rotation=self._page_rotation)
        self._sig_fields.append(fdef)
        self.update()
        self.field_added.emit(fdef)

    def wheelEvent(self, event) -> None:
        mods = event.modifiers()
        if mods & Qt.KeyboardModifier.ControlModifier:
            self.zoom_requested.emit(event.angleDelta().y(), event.position())
            event.accept()
        elif mods & Qt.KeyboardModifier.ShiftModifier:
            self.hscroll_requested.emit(event.angleDelta().y())
            event.accept()
        else:
            event.ignore()  # propagate to parent QScrollArea → vertical scroll

    def _right_click(self, pos: QPointF) -> None:
        """Delete a free signature field, or inform the user about locked ones."""
        cx, cy = pos.x(), pos.y()
        # Check locked fields first (they are visually on top of free fields)
        for fdef in reversed(self._locked_fields):
            if fdef.page != self._current_page:
                continue
            tl = self._pdf_to_w(fdef.x1, fdef.y2)
            br = self._pdf_to_w(fdef.x2, fdef.y1)
            if QRectF(tl, br).normalized().contains(cx, cy):
                QMessageBox.information(
                    self, t("dlg_locked_field_title"),
                    t("dlg_locked_field_msg", name=fdef.name))
                return
        for fdef in reversed(self._sig_fields):
            if fdef.page != self._current_page:
                continue
            tl = self._pdf_to_w(fdef.x1, fdef.y2)
            br = self._pdf_to_w(fdef.x2, fdef.y1)
            if QRectF(tl, br).normalized().contains(cx, cy):
                if QMessageBox.question(
                    self, t("dlg_delete_title"),
                    t("dlg_delete_msg", name=fdef.name),
                ) == QMessageBox.StandardButton.Yes:
                    self._sig_fields.remove(fdef)
                    self.update()
                    self.field_deleted.emit(fdef)
                return
