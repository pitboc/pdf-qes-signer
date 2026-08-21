# Concept: Cut / Copy / Paste for Signature Fields and Text Annotations

**Status:** Draft
**Date:** 2026-08-18

---

## Goal

Let the user cut/copy a signature field or a text annotation and paste it again —
on the same page, on another page, or in a **different document** opened later in
the same session. Moving the selected object must also work with the **arrow
keys**, in addition to the existing mouse-drag.

---

## Scope

| Object type | Copy | Cut | Paste | Arrow-key move |
|---|---|---|---|---|
| `sig_fields` (free, unsigned) | ✅ | ✅ | ✅ (creates new `sig_fields` entry) | ✅ (new) |
| `text_annots` | ✅ | ✅ | ✅ | ✅ (new) |
| `locked_fields` | ❌ | ❌ | – | ❌ (unchanged, sign-only) |
| `signed_fields` | ❌ | ❌ | – | ❌ (unchanged, display-only) |
| `form_fields` (existing PDF form widgets) | ❌ | ❌ | – | – |

**Why exclude `locked_fields`/`signed_fields`:** these are frozen by an existing
signature hash (see the three-category model in `main_window.py`). A "paste"
can never recreate the signed identity — only a brand-new, freely-editable
field. Offering Copy on them would imply something we can't deliver. If the
user wants a field "in the same spot" as a locked one, they can draw a new one
next to it; a template-duplication convenience could be a later, clearly
separate feature ("copy position only").

`form_fields` are pre-existing PDF form widgets (text/checkbox/combobox), a
different concept (`docs/form-fields-concept.md`) with their own edit model —
out of scope here.

---

## 1. Unified selection

Today, `SignatureFieldDef` selection already exists
(`PDFViewWidget._selected_field` / `ContinuousView._selected_field`,
set via `set_selected_field()`), and `TextAnnotOverlay` already has its own
`_selected` flag independent of text-edit focus (`_is_focused`).

New: a single **active clipboard-eligible selection**, tracked on
`PDFSignerApp` as

```python
self._active_object: SignatureFieldDef | TextAnnotDef | None = None
```

kept in sync with the existing per-type selection state (both already flow
through `_on_field_clicked_in_view` / `TextAnnotOverlay.focused`). This is the
object that Cut/Copy/Delete/arrow-keys act on. It replaces having two parallel
"what's selected" questions with one.

### Text annotations: selection vs. editing must be distinguishable

This is the one real conflict in the existing code. `TextAnnotOverlay`
currently sends **every** click — including the drag-handle — into
`_edit.setFocus()` (`pdf_view.py:444`), so the `QTextEdit` always owns
keyboard focus once an overlay is touched. Arrow keys typed there move the
text caret, not the field — by design, and correctly, while the user is
typing.

To make arrow-key **move** possible without hijacking text editing:

- Clicking the **handle** selects the overlay for *moving* (`set_selected(True)`,
  focus stays on the overlay widget itself, not the child `QTextEdit`) —
  mirrors what dragging already does today, just without forcing edit mode.
- Clicking the **body** keeps today's behavior: enters edit mode
  (`_edit.setFocus()`), arrow keys move the caret as expected.
- `Escape` while editing drops back to "selected, not editing" (already a
  common pattern elsewhere in the app, e.g. text-mode `Escape` handling).

Signature fields don't have this problem — they're painted directly on the
canvas, not backed by a text-input child widget, so `_selected_field` is
already an unambiguous "move target."

---

## 2. Moving with arrow keys

New behavior in `PDFViewWidget.keyPressEvent` (canvas) and on the
`TextAnnotOverlay` (when selected, not editing):

- Arrow keys nudge the active object by **1 pt**; **Shift+Arrow** by **10 pt**
  (both easy to tune once it's tried out — see open questions).
- Clamp to the page's MediaBox, same bounds logic already used for the
  mouse-drag path (`mouseMoveEvent` / `_dragging_field`, and the parent-bounds
  clamp in `TextAnnotOverlay.mouseMoveEvent`).
- Each nudge marks `_has_unsaved_changes = True` and emits the existing
  `field_moved` / `content_changed` signal, so nothing downstream (save/sign
  pipeline) needs to know the move came from a key instead of a mouse.
- Requires the canvas / overlay to actually hold Qt focus after a click —
  today's `PDFViewWidget`/`ContinuousView` already receive `keyPressEvent`
  (used for Page-Up/Down), so this is additive, not new plumbing.

---

## 3. Clipboard data model

A single-slot, in-memory clipboard living on `PDFSignerApp` (not on the
document, not on the view — so it survives `_open_pdf()` switching to a
different file):

```python
@dataclass
class _ClipboardEntry:
    kind: Literal["sig_field", "text_annot"]
    width: float             # PDF points — physical size, preserved as-is
    height: float
    corner: Literal["tl", "tr", "bl", "br"]  # nearest corner at copy time
    dx: float                 # distance from that corner, x (PDF points)
    dy: float                 # distance from that corner, y (PDF points)
    name_hint: str = ""       # sig_fields only, for auto-rename on paste
    # text_annot only — everything needed to recreate it standalone:
    text: str = ""
    font_size: float = 10.0
    font_name: str = "helv"
    color: tuple = (0.0, 0.0, 0.0)
    char_spacing: float = 0.0

self._clipboard: _ClipboardEntry | None = None
```

Deliberately **not** a raw copy of `SignatureFieldDef`/`TextAnnotDef`: those
carry absolute page coordinates and a `page` index that are meaningless once
you paste into a different page or a different document. The clipboard entry
must be self-contained and page-agnostic — see next section for why
corner-relative rather than absolute.

Cut = Copy, then delete via the existing removal path (`sig_fields.remove()` /
`text_annots.remove()`), so it reuses whatever guard rails deletion already
has (locked-field rejection, etc. — moot here since only free objects are
cuttable).

---

## 4. Where paste places the object ("page-relative", not cursor-relative)

This is the core requirement: paste must **not** depend on mouse position or
scroll offset — it's a page-coordinate operation, and it must survive
differently-sized target pages (A4 vs. Letter, portrait vs. landscape,
different document entirely).

**Size** is trivial: PDF points are a physical unit (1/72") shared by every
PDF regardless of page size, so `width`/`height` from the clipboard apply
unchanged — a signature stamp keeps its real-world size.

**Position** is the interesting part. Two candidate models:

- *Absolute bottom-left offset* (reuse `x1,y1` as-is): breaks as soon as the
  target page is a different size — e.g. a field placed near the top of a
  short page could land off the top edge of a taller one, or float
  awkwardly far from any edge on a much larger one.
- *Proportional (fraction of page width/height)*: keeps the object "in the
  same relative spot," but distorts the mental model for a stamp that's
  supposed to sit "2 cm from the bottom-right corner" — on a much larger
  page it would drift visually far from that corner.
- **Corner-relative offset (recommended):** at copy time, find the nearest
  page corner and record the physical distance to it (`dx`, `dy` in PDF
  points, stored in `corner`). At paste time, re-anchor to the same corner
  of the *target* page. This matches how people actually think about stamp
  placement ("bottom-right, a couple cm in") and is stable across page-size
  and orientation changes. Clamp into the target MediaBox afterward in case
  the target page is smaller than `dx`/`dy` allow.

Rotation: computed and re-applied in each page's own **unrotated** coordinate
frame, consistent with how `SignatureFieldDef.page_rotation` already isolates
rotation per field — a field copied from a `/Rotate 90` page and pasted onto
an unrotated page ends up correctly placed, not mirrored.

**Target page** = the page currently shown (`PDFSignerApp.current_page` /
`ContinuousView._current_page_sp` in single-page mode, or the page centered
in the viewport in continuous mode) at the moment `Ctrl+V` is pressed — not
the page the object was copied from.

**Same-page repeat-paste cascade:** pasting onto the *exact same page* the
object was copied/cut from, at the exact same anchor, would visually overlap
the original — indistinguishable, and impossible to grab with the mouse.
When target page == source page, cascade by a small fixed offset (e.g.
+12 pt right/down) per consecutive paste, exactly like Office/Acrobat "paste
in place" cascading. When target page differs (different page, or different
document entirely), place at the exact anchored position — no cascade —
since that's precisely the "stamp this in the same spot on every document"
workflow the corner-relative model exists for.

---

## 5. Name uniqueness on paste (`sig_fields` only)

Signature field names must be unique across `sig_fields ∪ locked_fields ∪
signed_fields` (already enforced when drawing a field, `pdf_view.py:1250`).
Paste should **not** interrupt the flow with a rename dialog — it reuses the
same default-name generator already used for hand-drawn fields
(`t("dlg_field_name_default", page=..., count=...)`), seeded from
`name_hint`, incrementing until free. The user can rename afterward via the
existing field-list rename path exactly as for a hand-drawn field.

`text_annots` have no name field — no collision handling needed.

---

## 6. Guard rails to reuse, not reinvent

- **docMDP P=1** (document locked against new fields): `_on_field_added`
  already rejects hand-drawn fields and rolls them back
  (`main_window.py:1252-1260`). Paste of a `sig_field` must run through the
  same check — cheapest way is to route pasted fields through the same
  `field_added`-equivalent path rather than appending to `sig_fields`
  directly.
- **`_has_unsaved_changes`**: paste/cut/arrow-move must set it, same as
  `_on_field_moved`/`_on_field_added`/`_on_field_deleted` already do.
- **Field list sync** (`_update_field_list`, `_on_field_clicked_in_view`):
  a pasted field must appear in the right-hand list and become the current
  selection, same as a freshly drawn one already does
  (`_field_list.setCurrentRow(len(self.sig_fields))`).

---

## 7. Cross-document paste

The clipboard lives on `PDFSignerApp`, not inside `pdf_doc`/`_working_bytes`/
the view — so `_open_pdf()` replacing the current document does not clear it.
Copy in file A, open file B (the app is single-document, so "open" replaces
the working document as it already does today), `Ctrl+V` in file B pastes
what was copied from A. No extra plumbing needed beyond keeping the clipboard
attribute off anything that gets torn down on document switch.

**Not** in scope for v1: syncing through the OS clipboard (`QClipboard`).
That would only matter for pasting into a *second, separate instance* of the
app or across a restart — not needed for "file boundary" within one running
session. Worth flagging as a cheap future extension (serialize
`_ClipboardEntry` to JSON via `QMimeData`), but adds a security-adjacent
question (should copied data be exposed to arbitrary other clipboard readers
on the system?) that's better decided if actually needed.

---

## 8. UI entry points

- **Keyboard:** `Ctrl+C` / `Ctrl+X` / `Ctrl+V`, standard `QKeySequence`
  (`Copy`/`Cut`/`Paste`), installed on the main window so they work
  regardless of which child widget has focus, guarded by
  "`self._active_object is not None`" for Copy/Cut and
  "`self._clipboard is not None`" for Paste.
- **Context menu:** extend the existing right-click handling
  (`PDFViewWidget._right_click`, `TextAnnotOverlay.delete_requested`) — today
  right-click on a free field deletes immediately after a confirm dialog;
  this becomes a small context menu (Cut / Copy / Delete / — Paste when
  right-clicking empty canvas).
- **Menu bar:** no "Edit" menu exists yet (`main_window.py` only has
  File/Settings/Help, `main_window.py:419-472`) — add one with
  Cut/Copy/Paste/Delete, enabled/disabled based on `_active_object`/
  `_clipboard`, which also gives keyboard-only users a discoverable path.
- **Field list panel:** right-click already implicitly supported via
  `delete_selected_field` (`main_window.py:1879`) — extend the same context
  menu there for consistency (list and canvas should offer the same actions
  for the same selection).

---

## 9. Out of scope / later extensions

- Multi-select cut/copy (list currently supports single-row selection only;
  clipboard model here already generalizes to a list if needed later).
- Undo/redo — the app has none today (delete relies on a confirm dialog
  instead); cut/paste doesn't change that calculus, but a single-slot
  clipboard means a second Cut silently discards the first — acceptable,
  matches OS clipboard conventions, but worth a status-bar message
  ("Copied — clipboard now holds …") so it isn't silent.
- System-clipboard (`QClipboard`) interop, see §7.
- "Copy visual template" from `locked_fields`/`signed_fields` (position/size
  only, not identity) — plausible follow-up, deliberately excluded from v1
  to keep the copy/cut semantics unambiguous (see §Scope).

---

## Open questions (subjective calls worth confirming before implementation)

1. **Nudge step size:** 1 pt / 10 pt with Shift proposed — fine, or should it
   snap to something document-relevant (e.g. mm-based: 1 mm ≈ 2.83 pt)?
2. **Cascade offset on same-page repeat-paste:** 12 pt proposed — purely a
   "does it feel right" call, easiest to tune after trying it.
3. **Corner-relative anchoring** (§4) is the recommended model — confirm
   this matches the intended meaning of "always page-position-relative,"
   versus a simpler absolute-bottom-left-origin model that only works well
   when source and target pages are the same size.
