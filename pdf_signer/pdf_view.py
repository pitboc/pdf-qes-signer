# SPDX-License-Identifier: GPL-3.0-or-later
"""
PDF canvas widget and signature field data model for PDF QES Signer.

Provides:
  - DPI_SCALE         – screen pixels per PDF point for preview rendering (96/72)
  - SignatureFieldDef – data class holding one signature field in PDF coordinates
  - PDFViewWidget     – interactive Qt widget for displaying a PDF page and
                        drawing/deleting signature fields
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
                 name: str = "Signature") -> None:
        self.page = page
        self.x1, self.y1 = x1, y1
        self.x2, self.y2 = x2, y2
        self.name = name

    def __repr__(self) -> str:
        return (f"<SigField '{self.name}' page={self.page + 1} "
                f"[{self.x1:.0f},{self.y1:.0f},{self.x2:.0f},{self.y2:.0f}]>")


class PDFViewWidget(QWidget):
    """Interactive widget that renders a PDF page and lets the user draw and
    delete signature fields by mouse interaction.

    Left-click + drag  → draw a new signature field rectangle.
    Right-click on field → delete that field (with confirmation dialog).

    Coordinate system:
        *Widget* space uses pixel coordinates (origin top-left, Y down).
        *PDF* space uses point coordinates (origin bottom-left, Y up).
        The ``_pdf_to_w`` / ``_w_to_pdf`` helpers convert between the two.

    Signals:
        field_added(SignatureFieldDef):   emitted after a new field is confirmed.
        field_deleted(SignatureFieldDef): emitted after a field is deleted.
    """

    # Canvas zoom factor: PDF points × ZOOM = rendered pixels.
    ZOOM: float = 1.5

    from PyQt6.QtCore import pyqtSignal
    field_added   = pyqtSignal(object)
    field_deleted = pyqtSignal(object)

    def __init__(self, appearance: SigAppearance, parent=None) -> None:
        super().__init__(parent)
        self.appearance = appearance
        self.setCursor(Qt.CursorShape.CrossCursor)
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        self._pixmap:       Optional[QPixmap] = None
        self._page_w = self._page_h = 1.0
        self._img_w  = self._img_h  = 1
        self._drag_start: Optional[QPointF] = None
        self._drag_end:   Optional[QPointF] = None
        self._sig_fields: list[SignatureFieldDef] = []
        self._current_page = 0

    def set_page(self, page: fitz.Page,
                 sig_fields: list[SignatureFieldDef],
                 current_page: int) -> None:
        """Render *page* at ZOOM and store the field list for painting."""
        mat = fitz.Matrix(self.ZOOM, self.ZOOM)
        pix = page.get_pixmap(matrix=mat, alpha=False)
        img = QImage(pix.samples, pix.width, pix.height,
                     pix.stride, QImage.Format.Format_RGB888)
        self._pixmap      = QPixmap.fromImage(img)
        self._img_w       = pix.width
        self._img_h       = pix.height
        self._page_w      = page.rect.width
        self._page_h      = page.rect.height
        self._sig_fields  = sig_fields
        self._current_page = current_page
        self.setFixedSize(pix.width, pix.height)
        self.update()

    def refresh(self) -> None:
        """Repaint the overlay (e.g. after an appearance change)."""
        self.update()

    # ── Coordinate conversion ─────────────────────────────────────────────

    def _pdf_to_w(self, x: float, y: float) -> QPointF:
        """Convert PDF point coordinates to widget pixel coordinates."""
        sx = self._img_w / self._page_w
        sy = self._img_h / self._page_h
        return QPointF(x * sx, (self._page_h - y) * sy)

    def _w_to_pdf(self, cx: float, cy: float) -> tuple[float, float]:
        """Convert widget pixel coordinates to PDF point coordinates."""
        sx = self._img_w / self._page_w
        sy = self._img_h / self._page_h
        return cx / sx, self._page_h - (cy / sy)

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
            if w > 4 and h > 4:
                px = self.appearance.render_preview(
                    w, h, pixels_per_point=self.ZOOM)
                painter.drawPixmap(rect.toRect(), px)
            # Field name label in top-left corner
            painter.setPen(QPen(QColor("#1a73e8")))
            painter.setFont(QFont("Arial", 7))
            painter.drawText(QPointF(rect.left() + 2, rect.top() + 10),
                             fdef.name)

        # Drag-to-draw preview rectangle
        if self._drag_start and self._drag_end:
            pen = QPen(QColor("#1a73e8"), 2, Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.setBrush(QBrush(QColor(208, 228, 255, 40)))
            painter.drawRect(
                QRectF(self._drag_start, self._drag_end).normalized())

        painter.end()

    # ── Mouse events ──────────────────────────────────────────────────────

    def mousePressEvent(self, ev) -> None:
        if ev.button() == Qt.MouseButton.LeftButton:
            self._drag_start = QPointF(ev.position())
            self._drag_end   = None
        elif ev.button() == Qt.MouseButton.RightButton:
            self._right_click(ev.position())

    def mouseMoveEvent(self, ev) -> None:
        if self._drag_start:
            self._drag_end = QPointF(ev.position())
            self.update()

    def mouseReleaseEvent(self, ev) -> None:
        if ev.button() != Qt.MouseButton.LeftButton or not self._drag_start:
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
        count = sum(1 for f in self._sig_fields if f.page == self._current_page)
        default = t("dlg_field_name_default",
                    page=self._current_page + 1, count=count + 1)
        name, ok = QInputDialog.getText(
            self, t("dlg_field_name_title"), t("dlg_field_name_prompt"),
            text=default)
        if not ok or not name:
            return

        fdef = SignatureFieldDef(self._current_page, px0, py0, px1, py1, name)
        self._sig_fields.append(fdef)
        self.update()
        self.field_added.emit(fdef)

    def _right_click(self, pos: QPointF) -> None:
        """Delete a signature field under the cursor after user confirmation."""
        cx, cy = pos.x(), pos.y()
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
