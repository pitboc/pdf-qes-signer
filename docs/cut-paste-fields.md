# Cut / Copy / Paste for Signature Fields and Text Annotations

## Overview

Free signature fields (`sig_fields`) and text annotations (`text_annots`) can
be cut, copied, and pasted — on the same page, on another page, or in a
**different document** opened later in the same session — and moved with the
arrow keys in addition to mouse-drag. `locked_fields`, `signed_fields`, and
`form_fields` are excluded (see Scope).

| Object type | Copy | Cut | Paste | Arrow-key move |
|---|---|---|---|---|
| `sig_fields` (free, unsigned) | ✅ | ✅ | ✅ (new `sig_fields` entry) | ✅ |
| `text_annots` | ✅ | ✅ | ✅ | ✅ |
| `locked_fields` | ❌ | ❌ | – | ❌ (unchanged, sign-only) |
| `signed_fields` | ❌ | ❌ | – | ❌ (unchanged, display-only) |
| `form_fields` (existing PDF form widgets) | ❌ | ❌ | – | – |

**Why `locked_fields`/`signed_fields` are excluded:** they are frozen by an
existing signature hash (see the three-category model in `main_window.py`'s
module docstring). A "paste" can never recreate the signed identity — only a
brand-new, freely-editable field. `form_fields` are pre-existing PDF form
widgets with their own edit model (`docs/form-fields.md`) — a different
concept.

---

## Unified selection: `_active_object`

`PDFSignerApp._active_object: SignatureFieldDef | TextAnnotDef | None` is the
single "what would Ctrl+C/X/Delete act on right now" pointer. It replaces two
independent per-type selection questions with one:

- A `SignatureFieldDef` becomes `_active_object` when its row is selected in
  the field list (`_on_field_selection_changed`, only for a row in the
  `sig_fields` range — a `locked`/`signed` row still highlights but is not
  clipboard-eligible) or when it's clicked directly in the canvas
  (`_on_field_clicked_in_view`).
- A `TextAnnotDef` becomes `_active_object` when its overlay receives focus
  (`_on_text_overlay_focused`, driven by `TextAnnotOverlay.focused`).
- Pasting an object makes the newly created object `_active_object`
  immediately (`_paste_sig_field`, `_paste_text_annot`).

`_update_clipboard_actions()` re-evaluates the Edit-menu action
enabled-state (`_act_cut`/`_act_copy`/`_act_edit_delete` from
`_active_object is not None`; `_act_paste` from `_clipboard is not None and
self.pdf_doc is not None`) and mirrors "clipboard holds something" onto
`ContinuousView.clipboard_available`, which the canvas needs to enable its
own "Paste" context-menu entry.

### Selection-sync pitfall: `QListWidget.setCurrentRow()` is a silent no-op on the current row

`QListWidget.setCurrentRow(row)` does **not** emit `currentRowChanged` when
`row` already equals the current row — a plain Qt behaviour, not a bug in
this app, but one that bit three independent call sites here before the
selection model settled:

1. **Canvas click on an already-selected field** (`_on_field_clicked_in_view`)
   — used to call only `setCurrentRow(row)`; if the row didn't change, the
   canvas highlight and `_active_object` never updated, so re-clicking an
   already-selected field silently did nothing, and a stale `_active_object`
   (e.g. a previously focused text annotation) stayed the Ctrl+C target.
2. **Initial selection after opening a document** — `_open_pdf()` sets the
   list row to the last free field, but `ContinuousView.open()` (called from
   `_render_current_page()`) unconditionally resets its own
   `_selected_field` to `None` when a new document loads. Highlighting the
   initial field therefore cannot happen inline in `_open_pdf()` — it has to
   happen *after* the new page slots exist.
3. Both are fixed the same way: every "select field X" call site pairs
   `setCurrentRow(row)` with an **explicit** call to
   `_on_field_selection_changed(row)`, instead of relying on the signal.
   `_fit_and_jump_after_open()` (deferred via `QTimer.singleShot(0, ...)` so
   it runs after `_render_current_page()` has built the new slots) is where
   the initial highlight and `_active_object` are set for a freshly opened
   document.

See the "Field-list ↔ canvas selection sync" section of `main_window.py`'s
module docstring for the current, authoritative summary of this rule.

### Text annotations: selection vs. editing must stay distinguishable

`TextAnnotOverlay` sending every click into `_edit.setFocus()` would make
the child `QTextEdit` always own keyboard focus once an overlay is touched —
arrow keys would move the text caret, not the box. Instead:

- Clicking the small red **handle** (top-left corner, `HANDLE = 10px`)
  selects the overlay for *moving* (`set_selected(True)`, `setFocus()` on
  the overlay itself, not the child `QTextEdit`) and emits `focused` to sync
  `_active_object` — mirrors what dragging already does, without forcing
  edit mode.
- Clicking the **body** enters edit mode (`_edit.setFocus()`); arrow keys
  move the caret as expected while typing.
- `Escape` while editing calls `setFocus()` on the overlay itself
  (`eventFilter` on the child `QTextEdit`), dropping back to "selected, not
  editing" without leaving text mode; a second `Escape` propagates up to
  `PDFViewWidget.keyPressEvent` and exits text mode entirely.

Signature fields don't have this problem — they're painted directly on the
canvas, not backed by a text-input child widget, so `_selected_field` is
already an unambiguous move target.

---

## Arrow-key move (nudge)

`PDFViewWidget.keyPressEvent` (signature fields) and
`TextAnnotOverlay.keyPressEvent` (text annotations, only while selected —
see above) both call `_nudge_step_pt(modifiers)`:

```python
NUDGE_STEP_MM:       float = 5.0   # plain arrow key
NUDGE_STEP_CTRL_MM:  float = 2.5   # Ctrl+arrow (medium)
NUDGE_STEP_SHIFT_MM: float = 1.0   # Shift+arrow (fine)
```

Steps are metric (mm), not points, so they line up with how a user thinks
about nudging a printed stamp — converted to PDF points (`MM_TO_PT = 72/25.4`)
before being applied. Movement is clamped to the page's MediaBox (same bound
used by mouse-drag) and marks `_has_unsaved_changes`; each nudge emits the
existing `field_moved` (signature fields) or triggers
`PDFViewWidget.nudge_text_annot()` → `content_changed` (text annotations), so
nothing downstream needs to know whether a move came from a key or the mouse.

---

## Clipboard data model

A single-slot, in-memory clipboard on `PDFSignerApp` — not on the document or
the view, so it survives `_open_pdf()` switching to a different file:

```python
@dataclass
class _ClipboardEntry:
    kind:       str      # "sig_field" | "text_annot"
    width:      float    # PDF points (0 for text annots — text reflows)
    height:     float
    corner:     str      # nearest page corner at copy time: tl/tr/bl/br
    dx:         float    # distance from that corner, x (PDF points)
    dy:         float    # distance from that corner, y (PDF points)
    name_hint:  str  = ""    # sig_field only: seed for unique-name generation
    text:         str   = ""
    font_size:    float = 10.0
    font_name:    str   = "helv"
    color:        tuple = (0.0, 0.0, 0.0)
    char_spacing: float = 0.0

self._clipboard: Optional[_ClipboardEntry] = None
```

Deliberately **not** a raw copy of `SignatureFieldDef`/`TextAnnotDef`: those
carry absolute page coordinates and a `page` index that are meaningless on a
differently sized target page or in another document — the clipboard entry
must be self-contained and page-agnostic (see below for why corner-relative
rather than absolute). Cut = Copy, then delete via the existing removal path,
so it reuses whatever guard rails deletion already has.

---

## Paste placement: corner-relative, occupancy-cascaded

Paste must **not** depend on mouse position or scroll offset — it's a page
coordinate operation that has to survive differently sized target pages (A4
vs. Letter, portrait vs. landscape, a different document entirely).

**Size** is trivial: PDF points are a physical unit (1/72") shared by every
PDF regardless of page size, so `width`/`height` apply unchanged — a stamp
keeps its real-world size.

**Position** uses **corner-relative anchoring**: at copy time,
`_corner_dist_from_rect`/`_corner_dist_from_point` find the nearest page
corner and record the physical distance to it (`dx`, `dy` in PDF points,
`corner` ∈ `{tl, tr, bl, br}`). At paste time, `_rect_from_corner`/
`_point_from_corner` re-anchor to the same corner of the *target* page, then
clamp fully inside the target MediaBox. This matches how people actually
think about stamp placement ("bottom-right, a couple cm in") and is stable
across page-size and orientation changes — unlike an absolute bottom-left
offset (breaks on a differently sized page) or a page-fraction offset
(visually drifts far from the intended corner on a much larger page).

**Target page** is whatever page is currently shown
(`PDFSignerApp.current_page`) at the moment paste happens — not the page the
object was copied from.

**Cascade on occupied slot:** if the reconstructed position would land
exactly on top of an object already on the target page, `_next_free_slot_rect`
(signature fields) / the cascade loop in `_paste_text_annot` (text
annotations) nudges the candidate by `PASTE_CASCADE_MM = 5.0` mm right/down,
repeating (bounded at 200 iterations) until the slot is free, clamping into
the page bounds at each step. "Occupied" is checked with `_same_slot()`, a
tolerance comparison (`PASTE_SLOT_TOLERANCE_PT = PASTE_CASCADE_PT × 0.25`) on
the object's anchor point, **against whatever already occupies that page** —
not only against repeats of the same source object. This is a deliberate
correction after first manual testing: checking only "same source, same
page, Nth repeat" would leave two independently pasted objects stacked
exactly on top of each other if they happened to land on the same slot by
coincidence (e.g. pasting onto a different page twice in a row, or pasting
onto a page that already has a field in that corner). Comparing the anchor
point rather than testing for any rectangle overlap is intentional too: two
same-sized, page-filling stamps only one cascade step apart still overlap
heavily, so a genuine "no overlap at all" test would need many steps to
clear and produce a far bigger jump than the intended 5 mm.

---

## Name uniqueness on paste (`sig_fields` only)

Signature field names must stay unique across `sig_fields ∪ locked_fields ∪
signed_fields`. `_unique_sig_field_name()` reuses `entry.name_hint` if it's
still free, otherwise falls back to the same default-name generator already
used for hand-drawn fields (`t("dlg_field_name_default", page=..., count=...)`,
incrementing until free) — paste never interrupts the flow with a rename
dialog; the user can rename afterward via the existing field-list rename
path exactly as for a hand-drawn field. `text_annots` have no name field, so
no collision handling is needed there.

---

## Guard rails reused, not reinvented

- **docMDP P=1** (document locked against new fields): `_paste_sig_field`
  routes the new field through `_on_field_added(fdef)`, the same path a
  hand-drawn field goes through, so the existing rollback-on-P=1 check
  applies without duplication.
- **`_has_unsaved_changes`**: set by paste/cut/nudge exactly as
  `_on_field_moved`/`_on_field_added`/`_on_field_deleted` already do.
- **Field list sync**: a pasted field goes through `_on_field_added`, so it
  appears in the field list and becomes the current selection the same way a
  freshly drawn field does.

---

## Cross-document paste

The clipboard lives on `PDFSignerApp`, not inside `pdf_doc`/`_working_bytes`/
the view, so `_open_pdf()` replacing the current document does not clear it
— only `_active_object` is reset to `None` on open (old object references
are invalid against the new document; see the comment in `_open_pdf`).
Copying in file A, then opening file B and pressing Ctrl+V pastes what was
copied from A. Not in scope: syncing through the OS clipboard (`QClipboard`)
— only needed for a second, separate app instance or across a restart, not
for switching files within one running session.

---

## UI entry points

- **Keyboard:** `Ctrl+C` / `Ctrl+X` / `Ctrl+V` (`QKeySequence.StandardKey.Copy`
  / `Cut` / `Paste`), installed as `QAction`s on the main window itself (not
  a child widget), so they fire regardless of which widget currently has Qt
  focus — including while the field list has focus.
- **Edit menu:** Cut/Copy/Paste/Delete, enabled/disabled via
  `_update_clipboard_actions()`.
- **Canvas context menu** (`PDFViewWidget._right_click`): right-click on a
  free field offers Cut/Copy/Delete (Cut/Delete disabled while
  `drawing_enabled` is off, e.g. in text mode); right-click on a locked
  field shows an info dialog instead; right-click anywhere else (empty
  canvas, a signed field, a form field) offers Paste, enabled only when the
  clipboard holds something and drawing is enabled. In continuous-view mode
  these signals (`field_copy_requested`/`field_cut_requested`/
  `paste_requested`) are relayed up through `ContinuousView`, which also
  propagates `clipboard_available` to every rendered page slot.
- **Text overlay context menu** (`TextAnnotOverlay.mousePressEvent`,
  right-click): Cut/Copy/Delete only — no Paste entry here, pasting text
  annotations always goes through the canvas/menu/keyboard paths above.
- **Field list panel:** no dedicated context menu — Cut/Copy/Paste/Delete
  reach it only via the main-window-level keyboard shortcuts and the Edit
  menu, both of which work regardless of focus.

---

## Not implemented / deliberately out of scope

- Multi-select cut/copy — the field list supports single-row selection only;
  the clipboard model generalizes to a list if ever needed.
- Undo/redo — the app has none; a second Cut/Copy silently discards
  whatever was in the clipboard slot before it, matching OS clipboard
  conventions (a status-bar message on copy/cut mitigates the silence).
- System-clipboard (`QClipboard`) interop — see Cross-document paste above.
- "Copy visual template" from `locked_fields`/`signed_fields` (position/size
  only, not identity) — would need clearly separate semantics from Copy/Cut
  on free fields to avoid implying something the app can't deliver.

---

## Files Changed

| File                          | Change                                                              |
|-------------------------------|---------------------------------------------------------------------|
| `pdf_signer/main_window.py`   | `_active_object`, `_clipboard`, `_ClipboardEntry`, corner-math helpers (`_corner_dist_from_rect`/`_rect_from_corner`/`_corner_dist_from_point`/`_point_from_corner`), Edit menu, `_copy_*`/`_cut_*`/`_paste_*`/`_delete_active_object`, `_update_clipboard_actions`, selection-sync fixes in `_on_field_clicked_in_view` / `_fit_and_jump_after_open` |
| `pdf_signer/pdf_view.py`      | `MM_TO_PT`, `NUDGE_STEP_*`, `_nudge_step_pt`; `PDFViewWidget.keyPressEvent` arrow-key move; `_right_click` context menu; `field_copy_requested`/`field_cut_requested`/`paste_requested`/`clipboard_available`; `TextAnnotOverlay` handle-vs-body click split, `keyPressEvent`, context menu, `copy_requested`/`cut_requested` |
| `pdf_signer/continuous_view.py` | Relays `field_copy_requested`/`field_cut_requested`/`paste_requested`; propagates `clipboard_available` to all rendered slots |
