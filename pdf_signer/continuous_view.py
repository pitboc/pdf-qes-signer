# SPDX-License-Identifier: GPL-3.0-or-later
"""
Continuous-scroll PDF viewer for PDF QES Signer.

## ContinuousView – lazy-rendering scroll widget for multi-page PDF display

### Overview

ContinuousView displays all pages of a PDF document in a vertically scrolling
widget.  Pages are rendered on demand (lazy) rather than all at once, so large
documents (100+ pages) open instantly and use a bounded amount of memory.

### Architecture

The scroll area contains a single container widget whose height equals the sum
of all page heights plus gaps.  Each page slot has a fixed, pre-calculated
y-offset stored in ``_page_y_offsets``.  Page heights are estimated from the PDF
MediaBox (``page.rect``) before any rendering takes place, using the same
``PDFViewWidget.ZOOM`` factor so placeholder sizes match rendered sizes exactly.

Only pages that currently intersect the visible viewport (plus a configurable
look-ahead band of ``LOOKAHEAD_PX`` pixels above and below) are rendered as
``PDFViewWidget`` instances.  All other slots hold lightweight
``_PagePlaceholder`` instances that carry the correct size but contain no
rasterised image.

### Rendering lifecycle

1. **open(doc, appearance, ...)** – called when a new document is loaded or the
   view is switched to continuous mode.  Calculates ``_page_y_offsets`` from
   ``page.rect`` scaled by ``PDFViewWidget.ZOOM``.  Creates
   ``_PagePlaceholder`` widgets for all pages, resizes the container, then
   calls ``_update_visible()`` to render the initially visible pages.

2. **_on_scroll(value)** – connected to the vertical scroll bar's
   ``valueChanged`` signal.  Updates the current-page indicator and calls
   ``_update_visible()`` to render newly visible pages and unrender pages that
   have left the lookahead band.

3. **_update_visible()** – determines the set of pages that should be rendered
   via ``_visible_range()``, then for each slot:
   - In range + placeholder → ``_render_page()``.
   - Out of range + rendered → ``_unrender_page()``.

4. **_render_page(idx)** – replaces the ``_PagePlaceholder`` at *idx* with a
   freshly rendered ``PDFViewWidget``.  Restores the selected-field highlight if
   ``_selected_field`` is on that page.

5. **_unrender_page(idx)** – replaces the ``PDFViewWidget`` at *idx* with a
   ``_PagePlaceholder`` to free the rasterised image from memory.

6. **update_fields(sig_fields, locked_fields, signed_fields)** – updates the
   stored field lists and calls ``PDFViewWidget.update_fields()`` on all
   *currently rendered* slots (placeholders need no update).

7. **scroll_to_field(fdef)** – scrolls the viewport so that the field is
   positioned in the lower 80 % of the visible area.  No additional clamping
   to the page top is applied; the scrollbar's natural minimum (y = 0) already
   prevents scrolling above the document start.  (The page-top constraint used
   in single-page mode – ``PDFSignerApp._scroll_to_field()`` in
   ``main_window.py`` – is not meaningful here, because adjacent pages are
   visible above and below.  Each mode has its own implementation.)

### Placeholder widget

``_PagePlaceholder(QWidget)`` – a minimal QWidget with:

- Fixed size matching the expected rendered page size
  (``int(page.rect.width * ZOOM)`` × ``int(page.rect.height * ZOOM)``).
- ``paintEvent`` that fills the background with ``BG_COLOR`` so the scroll
  area looks uniform before pages are rendered.
- No PDF data; replaced by a ``PDFViewWidget`` when it enters the lookahead
  band.

### Selected-field highlight across lazy transitions

``_selected_field`` is stored on ``ContinuousView`` itself.  When
``_render_page()`` creates a new ``PDFViewWidget``, it immediately calls
``set_selected_field()`` on it if the selected field belongs to that page.
This ensures the highlight is never lost when a placeholder is promoted to a
rendered widget.

### Zoom

``set_zoom(factor: float)`` – recalculates all ``_page_y_offsets``, rebuilds
placeholder/rendered widgets at new sizes, preserves the relative scroll
position (the page at the centre of the viewport stays centred after zoom).
*Zoom support is not yet implemented; this method is a planned extension point.*

### Thread safety

All rendering happens on the Qt main thread via ``_on_scroll``.  If rendering
a page becomes slow (e.g. very large pages at high zoom), a worker-thread
approach can be added later without changing the public interface.

### Constants

- ``LOOKAHEAD_PX = 1000``  – pixels above/below viewport to keep rendered
- ``PAGE_GAP = 10``        – vertical gap between pages in pixels
- ``BG_COLOR = "#404040"`` – background colour of the container
"""

from __future__ import annotations

from typing import Optional

import fitz

from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import QScrollArea, QWidget

from .pdf_view import PDFViewWidget, SignatureFieldDef
from .appearance import SigAppearance


LOOKAHEAD_PX = 1000
PAGE_GAP = 10
BG_COLOR = "#404040"


class _PagePlaceholder(QWidget):
    """Lightweight stand-in for a not-yet-rendered page.

    Carries the correct pixel size so the container height and scrollbar range
    remain accurate before and after lazy rendering fills in the real content.
    """

    def __init__(self, w: int, h: int, parent: QWidget) -> None:
        super().__init__(parent)
        self.setFixedSize(w, h)

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(BG_COLOR))
        p.end()


class ContinuousView(QScrollArea):
    """Lazy-rendering continuous-scroll PDF viewer.

    Renders only the pages currently near the visible viewport; the rest are
    held as lightweight ``_PagePlaceholder`` instances.

    Signals mirror those of ``PDFViewWidget`` so ``PDFSignerApp`` can connect
    to either widget using the same slots.
    """

    page_changed  = pyqtSignal(int)    # 0-based page index while scrolling
    field_clicked = pyqtSignal(object) # SignatureFieldDef
    field_added   = pyqtSignal(object) # SignatureFieldDef
    field_deleted = pyqtSignal(object) # SignatureFieldDef

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(False)
        self.setStyleSheet(f"QScrollArea {{ background: {BG_COLOR}; }}")
        # Centre the container horizontally in the viewport, just like the
        # single-page scroll area does.  This avoids a visual jump when
        # switching from single-page (centred) to continuous mode.
        self.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        self._container = QWidget()
        self._container.setObjectName("cvContainer")
        self._container.setStyleSheet(
            f"#cvContainer {{ background: {BG_COLOR}; }}")
        self.setWidget(self._container)

        # Per-slot state: one entry per page; each is either a
        # _PagePlaceholder or a rendered PDFViewWidget
        self._slots:         list[QWidget]           = []
        self._page_y_offsets: list[int]              = []
        self._max_w:         int                     = 0
        self._doc_id:        int                     = 0

        # Stored for lazy rendering and field updates
        self._doc:            Optional[fitz.Document]          = None
        self._appearance:     Optional[SigAppearance]          = None
        self._sig_fields:     list[SignatureFieldDef]          = []
        self._locked_fields:  list[SignatureFieldDef]          = []
        self._signed_fields:  list[SignatureFieldDef]          = []
        self._selected_field: Optional[SignatureFieldDef]      = None

        self.verticalScrollBar().valueChanged.connect(self._on_scroll)

    # ── Public API ────────────────────────────────────────────────────────

    def open(
        self,
        doc: fitz.Document,
        appearance: SigAppearance,
        sig_fields: list[SignatureFieldDef],
        locked_fields: list[SignatureFieldDef],
        signed_fields: list[SignatureFieldDef],
    ) -> None:
        """Populate the view for *doc*.  Creates placeholders for all pages,
        then renders the initially visible ones."""
        # Store references for lazy rendering
        self._doc           = doc
        self._appearance    = appearance
        self._sig_fields    = sig_fields
        self._locked_fields = locked_fields
        self._signed_fields = signed_fields
        self._selected_field = None

        # Remove old slots
        for w in self._slots:
            w.hide()
            w.deleteLater()
        self._slots          = []
        self._page_y_offsets = []

        # Calculate page sizes from MediaBox (no rendering yet)
        zoom   = PDFViewWidget.ZOOM
        y      = 0
        max_w  = 0
        sizes: list[tuple[int, int]] = []
        for page_num in range(len(doc)):
            page = doc[page_num]
            w = int(page.rect.width  * zoom)
            h = int(page.rect.height * zoom)
            sizes.append((w, h))
            self._page_y_offsets.append(y)
            y += h + PAGE_GAP
            max_w = max(max_w, w)

        self._max_w = max_w
        total_h = y - PAGE_GAP if sizes else 0

        # Create placeholder for every page
        for i, (w, h) in enumerate(sizes):
            ph = _PagePlaceholder(w, h, self._container)
            x  = (max_w - w) // 2
            ph.move(x, self._page_y_offsets[i])
            ph.show()
            self._slots.append(ph)

        self._container.resize(max_w, total_h)
        self._doc_id = id(doc)

        # Render the initially visible pages
        self._update_visible()

    def is_open_for(self, doc: fitz.Document) -> bool:
        """Return True if the view currently displays *doc*."""
        return self._doc_id == id(doc) and bool(self._slots)

    def update_fields(
        self,
        sig_fields: list[SignatureFieldDef],
        locked_fields: list[SignatureFieldDef],
        signed_fields: list[SignatureFieldDef],
    ) -> None:
        """Refresh field overlays on rendered pages; update stored lists."""
        self._sig_fields    = sig_fields
        self._locked_fields = locked_fields
        self._signed_fields = signed_fields
        for slot in self._slots:
            if isinstance(slot, PDFViewWidget):
                slot.update_fields(sig_fields, locked_fields, signed_fields)

    def set_selected_field(self, fdef: SignatureFieldDef | None) -> None:
        """Highlight *fdef* on its page widget; clear highlight on all others."""
        self._selected_field = fdef
        for slot in self._slots:
            if isinstance(slot, PDFViewWidget):
                slot.set_selected_field(None)
        if fdef is not None and fdef.page < len(self._slots):
            slot = self._slots[fdef.page]
            if isinstance(slot, PDFViewWidget):
                slot.set_selected_field(fdef)

    def scroll_to_page(self, page_idx: int) -> None:
        """Scroll so that the top of *page_idx* is at the viewport top."""
        if page_idx < len(self._page_y_offsets):
            self.verticalScrollBar().setValue(self._page_y_offsets[page_idx])

    def page_edge_visibility(self, page_idx: int) -> tuple[bool, bool]:
        """Return (top_visible, bottom_visible) for *page_idx*.

        Used by the view-mode toggle to decide how to set the vertical scroll
        position in single-page view when switching from continuous mode.
        """
        if page_idx >= len(self._slots):
            return False, False
        vbar         = self.verticalScrollBar()
        vp_top       = vbar.value()
        vp_bottom    = vp_top + self.viewport().height()
        page_top     = self._page_y_offsets[page_idx]
        page_bottom  = page_top + self._slots[page_idx].height()
        return (vp_top <= page_top <= vp_bottom,
                vp_top <= page_bottom <= vp_bottom)

    def scroll_to_field(self, fdef: SignatureFieldDef) -> None:
        """Scroll so that *fdef* appears in the lower 80 % of the viewport.

        No page-top clamping is applied (see module docstring for rationale).
        The target page is rendered before computing pixel coordinates.
        """
        if fdef.page >= len(self._slots):
            return

        # Ensure the target page is rendered so we can convert coordinates
        self._render_page(fdef.page)

        vbar       = self.verticalScrollBar()
        viewport_h = self.viewport().height()
        slot       = self._slots[fdef.page]
        page_top   = self._page_y_offsets[fdef.page]

        if not isinstance(slot, PDFViewWidget):
            # Fallback: scroll to page top
            vbar.setValue(page_top)
            return

        tl = slot._pdf_to_w(fdef.x1, fdef.y2)
        br = slot._pdf_to_w(fdef.x2, fdef.y1)
        field_top_y    = page_top + min(tl.y(), br.y())
        field_bottom_y = page_top + max(tl.y(), br.y())

        cur = vbar.value()
        if cur <= field_top_y and field_bottom_y <= cur + viewport_h:
            return  # already fully visible

        target = int(field_bottom_y - viewport_h * 0.80)
        target = max(0, min(target, vbar.maximum()))
        vbar.setValue(target)

    def set_zoom(self, factor: float) -> None:  # noqa: ARG002
        """Planned extension point for variable zoom – not yet implemented."""

    # ── Private: lazy rendering ───────────────────────────────────────────

    def _visible_range(self) -> tuple[int, int]:
        """Return (first, last) page indices that intersect the lookahead band."""
        if not self._slots:
            return 0, 0
        scroll_top = self.verticalScrollBar().value()
        band_top   = max(0, scroll_top - LOOKAHEAD_PX)
        band_bot   = scroll_top + self.viewport().height() + LOOKAHEAD_PX
        first = len(self._slots) - 1
        last  = 0
        for i, (y, slot) in enumerate(zip(self._page_y_offsets, self._slots)):
            page_bot = y + slot.height()
            if page_bot >= band_top and y <= band_bot:
                first = min(first, i)
                last  = max(last,  i)
        return first, last

    def _update_visible(self) -> None:
        """Render pages entering the lookahead band; unrender those leaving it."""
        if not self._slots:
            return
        first, last = self._visible_range()
        for i, slot in enumerate(self._slots):
            in_range = first <= i <= last
            if in_range and isinstance(slot, _PagePlaceholder):
                self._render_page(i)
            elif not in_range and isinstance(slot, PDFViewWidget):
                self._unrender_page(i)

    def _render_page(self, idx: int) -> None:
        """Replace the placeholder at *idx* with a rendered PDFViewWidget."""
        if idx >= len(self._slots):
            return
        slot = self._slots[idx]
        if not isinstance(slot, _PagePlaceholder):
            return  # already rendered

        x, y = slot.x(), slot.y()
        slot.hide()
        slot.deleteLater()

        pv = PDFViewWidget(self._appearance)
        pv.set_page(
            self._doc[idx],
            self._sig_fields, idx,
            self._locked_fields,
            self._signed_fields,
        )
        pv.field_added.connect(self.field_added)
        pv.field_deleted.connect(self.field_deleted)
        pv.field_clicked.connect(self.field_clicked)
        pv.setParent(self._container)
        pv.move(x, y)
        pv.show()
        self._slots[idx] = pv

        # Restore selected-field highlight if it belongs to this page
        if (self._selected_field is not None
                and self._selected_field.page == idx):
            pv.set_selected_field(self._selected_field)

    def _unrender_page(self, idx: int) -> None:
        """Replace the rendered widget at *idx* with a placeholder."""
        if idx >= len(self._slots):
            return
        slot = self._slots[idx]
        if not isinstance(slot, PDFViewWidget):
            return  # already a placeholder

        w, h = slot.width(), slot.height()
        x, y = slot.x(), slot.y()
        slot.hide()
        slot.deleteLater()

        ph = _PagePlaceholder(w, h, self._container)
        ph.move(x, y)
        ph.show()
        self._slots[idx] = ph

    # ── Private: scroll handling ──────────────────────────────────────────

    def _on_scroll(self, value: int) -> None:
        """Update the page indicator and trigger lazy render/unrender."""
        if not self._page_y_offsets:
            return
        viewport_mid = value + self.viewport().height() // 2
        current = 0
        for i, y_off in enumerate(self._page_y_offsets):
            if y_off <= viewport_mid:
                current = i
            else:
                break
        self.page_changed.emit(current)
        self._update_visible()
