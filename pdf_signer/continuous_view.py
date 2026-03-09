# SPDX-License-Identifier: GPL-3.0-or-later
"""
Continuous-scroll PDF viewer for PDF QES Signer.

## ContinuousView – lazy-rendering scroll widget for multi-page PDF display

### Overview

ContinuousView displays all pages of a PDF document in a vertically scrolling
widget.  Pages are rendered on demand (lazy) rather than all at once, so large
documents (100+ pages) open instantly and use a bounded amount of memory.

**Current state:** All pages are rendered immediately on ``open()`` – the same
behaviour as the previous implementation in ``main_window.py``.  Lazy rendering
(replacing off-screen pages with ``_PagePlaceholder`` instances) is the planned
next step and will be added without changing the public interface.

### Architecture

The scroll area contains a single container widget whose height equals the sum
of all page heights plus gaps.  Each page slot has a fixed, pre-calculated
y-offset stored in ``_page_y_offsets``.  Page heights are estimated from the PDF
MediaBox before any rendering takes place.

Only pages that currently intersect the visible viewport (plus a configurable
look-ahead band of ``LOOKAHEAD_PX`` pixels above and below) are rendered as
``PDFViewWidget`` instances.  All other slots are occupied by lightweight
placeholder widgets that carry the correct size but contain no rasterised image.

### Rendering lifecycle

1. **open(doc, appearance, ...)** – called when a new document is loaded or the
   view is switched to continuous mode.  Calculates ``_page_y_offsets`` from PDF
   MediaBox dimensions scaled to the current zoom factor.  Currently renders all
   pages immediately; will render only the initially visible pages once lazy
   rendering is enabled.

2. **_on_scroll(value)** – connected to the vertical scroll bar's
   ``valueChanged`` signal.  Updates the current-page indicator.  Will also
   trigger render/unrender of pages once lazy rendering is enabled:
   - If a page enters the viewport ± ``LOOKAHEAD_PX``: replace placeholder with
     a freshly rendered ``PDFViewWidget``.
   - If a page leaves the band: replace rendered widget with placeholder to free
     GPU/memory resources.

3. **update_fields(sig_fields, locked_fields, signed_fields)** – called after
   any field-list change.  Calls ``PDFViewWidget.update_fields()`` on all
   *currently rendered* page widgets (placeholders need no update).

4. **scroll_to_field(fdef)** – scrolls the viewport so that the field is
   positioned in the lower 80 % of the visible area.  No additional clamping
   to the page top is applied; the scrollbar's natural minimum (y = 0) already
   prevents scrolling above the document start.  (The page-top constraint used
   in single-page mode – ``PDFSignerApp._scroll_to_field()`` in
   ``main_window.py`` – is not meaningful here, because adjacent pages are
   visible above and below.  Each mode has its own implementation.)

### Placeholder widget

``_PagePlaceholder(QWidget)`` – a minimal QWidget with:

- Fixed size matching the expected rendered page size.
- ``paintEvent`` that fills the background with the same dark colour as the
  container, so the scroll area looks uniform before pages are rendered.
- No PDF data; replaced by a ``PDFViewWidget`` when it enters the lookahead band.

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

import fitz

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QScrollArea, QWidget

from .pdf_view import PDFViewWidget, SignatureFieldDef
from .appearance import SigAppearance


LOOKAHEAD_PX = 1000
PAGE_GAP = 10
BG_COLOR = "#404040"


class _PagePlaceholder(QWidget):
    """Lightweight stand-in for a not-yet-rendered page."""

    # TODO: implement paintEvent with BG_COLOR fill


class ContinuousView(QScrollArea):
    """Continuous-scroll PDF viewer.

    Renders all pages of a document vertically.  Signals mirror those of
    ``PDFViewWidget`` so ``PDFSignerApp`` can connect to either widget
    using the same slots.
    """

    page_changed  = pyqtSignal(int)    # 0-based page index while scrolling
    field_clicked = pyqtSignal(object) # SignatureFieldDef
    field_added   = pyqtSignal(object) # SignatureFieldDef
    field_deleted = pyqtSignal(object) # SignatureFieldDef

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(False)

        self._container = QWidget()
        self._container.setObjectName("cvContainer")
        self._container.setStyleSheet(
            f"#cvContainer {{ background: {BG_COLOR}; }}")
        self.setWidget(self._container)

        self._page_widgets:  list[PDFViewWidget] = []
        self._page_y_offsets: list[int]          = []
        self._doc_id: int = 0  # id(doc) of the currently displayed document

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
        """Render all pages of *doc* and display them in the scroll area.

        May be called again with the same document to refresh after field changes
        or with a new document to replace the current content.
        """
        # Clean up previous page widgets
        for pw in self._page_widgets:
            pw.hide()
            pw.deleteLater()
        self._page_widgets    = []
        self._page_y_offsets  = []

        # Render all pages and collect sizes
        y = 0
        max_w = 0
        for page_num in range(len(doc)):
            page = doc[page_num]
            pv = PDFViewWidget(appearance)
            pv.set_page(page, sig_fields, page_num, locked_fields, signed_fields)
            pv.field_added.connect(self.field_added)
            pv.field_deleted.connect(self.field_deleted)
            pv.field_clicked.connect(self.field_clicked)
            # Direct parent assignment (not via layout) for reliable positioning
            pv.setParent(self._container)
            self._page_y_offsets.append(y)
            y += pv.height() + PAGE_GAP
            max_w = max(max_w, pv.width())
            self._page_widgets.append(pv)

        # Centre pages horizontally and position at exact y offsets
        total_h = y - PAGE_GAP if self._page_widgets else 0
        for i, pv in enumerate(self._page_widgets):
            x = (max_w - pv.width()) // 2
            pv.move(x, self._page_y_offsets[i])
            pv.show()

        # Resize container explicitly – do not rely on adjustSize() which uses
        # sizeHint() and is unreliable for manually positioned children
        self._container.resize(max_w, total_h)
        self._doc_id = id(doc)

    def is_open_for(self, doc: fitz.Document) -> bool:
        """Return True if the view currently displays *doc*."""
        return self._doc_id == id(doc) and bool(self._page_widgets)

    def update_fields(
        self,
        sig_fields: list[SignatureFieldDef],
        locked_fields: list[SignatureFieldDef],
        signed_fields: list[SignatureFieldDef],
    ) -> None:
        """Refresh field overlays on all rendered pages without re-rasterising."""
        for pw in self._page_widgets:
            pw.update_fields(sig_fields, locked_fields, signed_fields)

    def set_selected_field(self, fdef: SignatureFieldDef | None) -> None:
        """Highlight *fdef* on its page widget; clear highlight on all others."""
        for pw in self._page_widgets:
            pw.set_selected_field(None)
        if fdef is not None and fdef.page < len(self._page_widgets):
            self._page_widgets[fdef.page].set_selected_field(fdef)

    def scroll_to_page(self, page_idx: int) -> None:
        """Scroll so that the top of *page_idx* is at the viewport top."""
        if page_idx < len(self._page_y_offsets):
            self.verticalScrollBar().setValue(self._page_y_offsets[page_idx])

    def scroll_to_field(self, fdef: SignatureFieldDef) -> None:
        """Scroll so that *fdef* appears in the lower 80 % of the viewport.

        No page-top clamping is applied (see module docstring for rationale).
        """
        if fdef.page >= len(self._page_widgets):
            return
        vbar       = self.verticalScrollBar()
        viewport_h = self.viewport().height()
        pw         = self._page_widgets[fdef.page]
        page_top   = self._page_y_offsets[fdef.page]

        tl = pw._pdf_to_w(fdef.x1, fdef.y2)
        br = pw._pdf_to_w(fdef.x2, fdef.y1)
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

    # ── Private helpers ───────────────────────────────────────────────────

    def _on_scroll(self, value: int) -> None:
        """Update the current-page indicator while the user scrolls."""
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

    def _visible_range(self) -> tuple[int, int]:
        """Return (first, last) page indices intersecting the lookahead band.

        Used by lazy rendering (not yet implemented).
        """
        top    = self.verticalScrollBar().value() - LOOKAHEAD_PX
        bottom = top + self.viewport().height() + 2 * LOOKAHEAD_PX
        first  = 0
        last   = max(0, len(self._page_y_offsets) - 1)
        for i, y in enumerate(self._page_y_offsets):
            if y + (self._page_widgets[i].height() if i < len(self._page_widgets) else 0) < top:
                first = i + 1
            if y > bottom and last == max(0, len(self._page_y_offsets) - 1):
                last = i
                break
        return first, last

    def _render_page(self, page_idx: int) -> None:
        """Replace the placeholder at *page_idx* with a rendered PDFViewWidget.

        Not yet called – prepared for lazy rendering.
        """

    def _unrender_page(self, page_idx: int) -> None:
        """Replace the rendered widget at *page_idx* with a placeholder.

        Not yet called – prepared for lazy rendering.
        """
