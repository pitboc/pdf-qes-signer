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

from dataclasses import dataclass, field as _dc_field
from typing import Optional

import fitz  # PyMuPDF

from PyQt6.QtCore import QEvent, Qt, QPoint, QPointF, QRectF, QTimer
from PyQt6.QtGui import (
    QGuiApplication,
    QPixmap, QImage, QPainter, QPen, QColor, QBrush, QFont,
    QTextCharFormat, QTextCursor,
)
from PyQt6.QtWidgets import (
    QFrame, QInputDialog, QMessageBox, QSizePolicy, QTextEdit, QWidget,
)

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


@dataclass
class TextAnnotDef:
    """Free-form text annotation placed on a PDF page.

    ``x``, ``y`` are the baseline-left coordinates of the first line in PDF
    native space (origin bottom-left, y-up, 72-dpi points) – the same point
    that ``page.insert_text()`` expects.  The overlay widget derives its
    screen position from these coordinates plus the current zoom factor.
    """
    page:         int
    x:            float          # baseline-left x  (PDF points)
    y:            float          # baseline y       (PDF points, y-up)
    text:         str   = ""
    font_size:    float = 10.0
    font_name:    str   = "helv"  # helv=Helvetica, tiro=Times, cour=Courier
    color:        tuple = _dc_field(default_factory=lambda: (0.0, 0.0, 0.0))
    char_spacing: float = 0.0


class TextAnnotOverlay(QWidget):
    """Editable text overlay positioned as a child widget of PDFViewWidget.

    The widget renders a thin border and a small red drag-handle in the
    top-left corner.  Dragging the handle repositions the overlay; on
    mouse-release the parent view updates the stored PDF baseline coordinates.

    Signals:
        content_changed:          emitted on every text change (text is kept
                                  in sync with ``annot.text`` automatically).
        delete_requested(object): right-click – caller should confirm and
                                  remove the overlay.
    """

    from PyQt6.QtCore import pyqtSignal
    content_changed  = pyqtSignal()
    delete_requested = pyqtSignal(object)   # passes self
    focused          = pyqtSignal(object)   # passes self when edit gains focus

    HANDLE: int = 10  # red handle side length in pixels

    # Font-name → CSS font-family list
    _FAMILIES: dict[str, str] = {
        "helv": '"Helvetica","Arial",sans-serif',
        "tiro": '"Times New Roman","Times",serif',
        "cour": '"Courier New","Courier",monospace',
    }

    def __init__(self, annot: TextAnnotDef, zoom: float,
                 parent: QWidget) -> None:
        super().__init__(parent)
        self._annot      = annot
        self._zoom       = zoom
        self._dragging   = False
        self._drag_off   = QPoint()
        self._is_focused = False
        self._char_fmt   = QTextCharFormat()   # cached; rebuilt by _apply_style

        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAutoFillBackground(False)

        self._edit = QTextEdit(self)
        self._edit.setFrameShape(QFrame.Shape.NoFrame)
        self._edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self._edit.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._edit.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._edit.setPlainText(annot.text)
        self._edit.document().contentsChanged.connect(self._on_change)
        self._edit.installEventFilter(self)

        self._apply_style()
        self._relayout()
        self.raise_()
        self.show()
        # Note: setFocus() is NOT called here intentionally.
        # The caller must connect focused() FIRST, then call _edit.setFocus()
        # so that the FocusIn event arrives after the signal is wired up and
        # _focused_overlay is correctly assigned.

    @property
    def annot(self) -> TextAnnotDef:
        return self._annot

    def update_zoom(self, zoom: float) -> None:
        """Call after a zoom change to rescale the font rendering."""
        self._zoom = zoom
        self._apply_style()
        self._relayout()

    # Qt font family names for each PDF base font
    _QT_FAMILIES: dict[str, str] = {
        "helv": "Arial",
        "tiro": "Times New Roman",
        "cour": "Courier New",
    }

    def _apply_style(self) -> None:
        """Apply font, size, color and char-spacing to the QTextEdit.

        Three complementary mechanisms ensure the format is always correct:

        1. ``document().setDefaultFont(font)`` – controls the cursor appearance
           in an **empty** document and after deleting all text.
        2. ``mergeCharFormat`` on the full document – updates any **existing**
           text in one pass.  Signals are blocked to prevent a recursion via
           ``contentsChanged`` → ``_on_change``.
        3. ``setCurrentCharFormat(fmt)`` + storing in ``_char_fmt`` – ensures
           the **next typed character** (and the cursor blink) uses the right
           format.  ``_on_change`` re-applies this every time the text changes
           so the format is never lost after deleting all characters.
        """
        family = self._QT_FAMILIES.get(self._annot.font_name, "Arial")
        # Schriftgröße als Float-Punktgröße setzen um Quantisierungsfehler zu vermeiden.
        # setPixelSize() erfordert int → bis zu 1px Sprung bei Zoom-Änderungen.
        # setPointSizeF() arbeitet mit float; Qt konvertiert intern via Screen-DPI.
        # Umrechnung: pt = px_desired * 72 / screen_dpi
        #   wobei px_desired = font_size * zoom (PDF-Punkte × Zoom-Faktor)
        screen = QGuiApplication.primaryScreen()
        dpi    = screen.logicalDotsPerInch() if screen else 96.0
        pt     = max(4.0, self._annot.font_size * self._zoom * 72.0 / dpi)
        r, g, b = (int(c * 255) for c in self._annot.color)

        font = QFont(family)
        font.setPointSizeF(pt)
        if self._annot.char_spacing > 0.0:
            font.setLetterSpacing(
                QFont.SpacingType.AbsoluteSpacing,
                self._annot.char_spacing * self._zoom,
            )

        fmt = QTextCharFormat()
        fmt.setFont(font)
        fmt.setForeground(QColor(r, g, b))
        self._char_fmt = fmt

        # 1 – document default (empty-state cursor size)
        self._edit.document().setDefaultFont(font)

        # 2 – existing text
        cur = QTextCursor(self._edit.document())
        cur.select(QTextCursor.SelectionType.Document)
        self._edit.document().blockSignals(True)
        cur.mergeCharFormat(fmt)
        self._edit.document().blockSignals(False)

        # 3 – cursor / next input
        self._edit.setCurrentCharFormat(fmt)

        self._edit.setStyleSheet(
            "QTextEdit { background: transparent; border: none; }"
        )

    def _relayout(self) -> None:
        """Resize the widget to fit the current text content.

        ``setLineWrapMode(NoWrap)`` keeps ``textWidth`` at -1 so that
        ``doc.size()`` always returns the natural (unwrapped) dimensions.
        Explicit newlines still create multiple lines.
        """
        doc = self._edit.document()
        # textWidth == -1 (NoWrap) → size() reflects natural content dimensions
        size    = doc.size()
        font_px = max(6, round(self._annot.font_size * self._zoom))
        w = max(60, round(size.width()) + self.HANDLE + 10)
        h = max(font_px + 8, round(size.height()) + 8)
        self._edit.setGeometry(self.HANDLE + 2, 2,
                               w - self.HANDLE - 4, h - 4)
        self.resize(w, h)

    def _on_change(self) -> None:
        self._annot.text = self._edit.toPlainText()
        # Re-apply cursor format after every change so it is not lost when
        # the user deletes all text and the cursor reverts to document default.
        self._edit.setCurrentCharFormat(self._char_fmt)
        self._relayout()
        self.content_changed.emit()

    # ── Focus tracking ────────────────────────────────────────────────────

    def eventFilter(self, obj, event) -> bool:
        if obj is self._edit:
            if event.type() == QEvent.Type.FocusIn:
                self._is_focused = True
                self.update()
                self.focused.emit(self)
            elif event.type() == QEvent.Type.FocusOut:
                self._is_focused = False
                self.update()
                # No auto-delete on focus-out: empty-box cleanup is triggered
                # only by explicit deselect events (new box focused / text mode off).
        return False  # do not consume the event

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        if self._is_focused:
            p.fillRect(self.rect(), QColor(208, 228, 255, 60))
            p.setPen(QPen(QColor("#1a73e8"), 2))
        else:
            p.fillRect(self.rect(), QColor(255, 255, 180, 35))
            p.setPen(QPen(QColor("#888888"), 1, Qt.PenStyle.DashLine))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRect(self.rect().adjusted(1, 1, -1, -1))
        p.fillRect(0, 0, self.HANDLE, self.HANDLE, QColor("#cc2200"))
        p.end()

    def mousePressEvent(self, ev) -> None:
        if ev.button() == Qt.MouseButton.LeftButton:
            if (ev.position().x() <= self.HANDLE
                    and ev.position().y() <= self.HANDLE):
                self._dragging = True
                self._drag_off = ev.position().toPoint()
            else:
                self._edit.setFocus()
                super().mousePressEvent(ev)
        elif ev.button() == Qt.MouseButton.RightButton:
            self.delete_requested.emit(self)

    def mouseMoveEvent(self, ev) -> None:
        if self._dragging:
            par = self.parent()
            np  = self.pos() + ev.position().toPoint() - self._drag_off
            if par:
                np.setX(max(0, min(np.x(), par.width()  - self.width())))
                np.setY(max(0, min(np.y(), par.height() - self.height())))
            self.move(np)
        else:
            super().mouseMoveEvent(ev)

    def mouseReleaseEvent(self, ev) -> None:
        if self._dragging and ev.button() == Qt.MouseButton.LeftButton:
            self._dragging = False
            # Translate new widget position back to PDF baseline coordinates
            par = self.parent()
            if par and hasattr(par, '_w_to_pdf'):
                wx = self.pos().x() + self.HANDLE
                wy = self.pos().y() + round(self._annot.font_size * self._zoom)
                self._annot.x, self._annot.y = par._w_to_pdf(wx, wy)
                self._annot.page = par._current_page
        else:
            super().mouseReleaseEvent(ev)


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
        text_annot_placed(int,float,float): text mode click – page, x_pdf, y_pdf.
        text_annot_deleted(TextAnnotDef):   overlay deleted by the user.
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
    text_annot_placed   = pyqtSignal(int, float, float)  # page, x_pdf, y_pdf
    text_annot_deleted  = pyqtSignal(object)             # TextAnnotDef

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
        self._mediabox_w: float     = 1.0      # unrotated page width  (PDF points)
        self._mediabox_h: float     = 1.0      # unrotated page height (PDF points)
        self._derot_mat: fitz.Matrix = fitz.Matrix()  # rotated → unrotated fitz coords
        self._rot_mat:   fitz.Matrix = fitz.Matrix()  # unrotated → rotated fitz coords
        self._drag_start: Optional[QPointF] = None
        self._drag_end:   Optional[QPointF] = None
        self._rb_start:   Optional[QPointF] = None   # Ctrl+drag rubber-band start
        self._rb_end:     Optional[QPointF] = None   # Ctrl+drag rubber-band end
        self._pan_start:  Optional[QPointF] = None   # middle-drag panning start
        self.drawing_enabled: bool = True             # False → no new field drag
        self.text_mode:       bool = False            # True → click places text annotation
        self._sig_fields:    list[SignatureFieldDef] = []
        self._locked_fields: list[SignatureFieldDef] = []
        self._signed_fields: list[SignatureFieldDef] = []
        self._text_overlays: list[TextAnnotOverlay]  = []
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
        self._mediabox_w    = page.mediabox.width
        self._mediabox_h    = page.mediabox.height
        self._derot_mat     = page.derotation_matrix
        self._rot_mat       = page.rotation_matrix
        self._sig_fields    = sig_fields
        self._locked_fields = locked_fields or []
        self._signed_fields = signed_fields or []
        self._current_page  = current_page
        self.setFixedSize(pix.width, pix.height)
        self.reposition_overlays()
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

    # ── Text annotation overlays ──────────────────────────────────────────

    def add_text_overlay(self, annot: TextAnnotDef) -> TextAnnotOverlay:
        """Create a new TextAnnotOverlay for *annot* and display it."""
        ov = TextAnnotOverlay(annot, self._zoom, self)
        ov.delete_requested.connect(self._on_overlay_delete_requested)
        self._text_overlays.append(ov)
        self._position_overlay(ov)
        return ov

    def clear_text_overlays(self) -> None:
        """Destroy all overlays (called when a new PDF is opened)."""
        for ov in self._text_overlays:
            ov.hide()
            ov.deleteLater()
        self._text_overlays.clear()

    def reposition_overlays(self) -> None:
        """Show / hide / reposition all overlays for the current page + zoom."""
        for ov in self._text_overlays:
            self._position_overlay(ov)

    def _position_overlay(self, ov: TextAnnotOverlay,
                          update_style: bool = True) -> None:
        """Move *ov* so its baseline-left aligns with ``annot.x / annot.y``.

        *update_style* should be ``True`` on zoom changes (calls
        ``update_zoom`` to rescale fonts) and ``False`` when only the
        position needs to be refreshed after a font-size edit (style was
        already applied by the caller).
        """
        if ov.annot.page != self._current_page:
            ov.hide()
            return
        base    = self._pdf_to_w(ov.annot.x, ov.annot.y)
        font_px = round(ov.annot.font_size * self._zoom)
        wx      = round(base.x()) - TextAnnotOverlay.HANDLE
        wy      = round(base.y()) - font_px
        ov.move(max(0, wx), max(0, wy))
        if update_style:
            ov.update_zoom(self._zoom)
        ov.show()

    def delete_overlay_silent(self, ov: TextAnnotOverlay) -> None:
        """Remove *ov* immediately without a confirmation dialog."""
        if ov in self._text_overlays:
            self._text_overlays.remove(ov)
        ann = ov.annot
        try:
            ov.delete_requested.disconnect()
        except RuntimeError:
            pass
        ov.hide()
        ov.deleteLater()
        self.text_annot_deleted.emit(ann)

    def _on_overlay_delete_requested(self, ov: TextAnnotOverlay) -> None:
        if QMessageBox.question(
            self, t("dlg_delete_title"),
            t("dlg_text_annot_delete_msg"),
        ) != QMessageBox.StandardButton.Yes:
            return
        self.delete_overlay_silent(ov)

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
            elif self.text_mode:
                # Text mode: single click places a new text annotation
                px, py = self._w_to_pdf(ev.position().x(), ev.position().y())
                self.text_annot_placed.emit(self._current_page, px, py)
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

        # Clamp to page boundaries using unrotated (mediabox) dimensions,
        # because _w_to_pdf returns coordinates in the unrotated PDF space.
        px0 = max(0.0, min(px0, self._mediabox_w))
        py0 = max(0.0, min(py0, self._mediabox_h))
        px1 = max(0.0, min(px1, self._mediabox_w))
        py1 = max(0.0, min(py1, self._mediabox_h))
        if abs(px1 - px0) < 5 or abs(py1 - py0) < 3:
            return  # too small after clamping

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
