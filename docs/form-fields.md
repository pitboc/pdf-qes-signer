# Interactive PDF Form Fields

## Overview

If an opened PDF already contains form fields (text, checkbox, radio button,
combobox — created in Word, LibreOffice, Acrobat, …), they can be filled in
directly on the canvas, with no separate "edit mode": every editable field is
highlighted green as soon as the document opens. At signing time, all form
fields are **flattened** — their current value is burned into the page
content and the interactive widgets are removed, so the signed document
contains no more form fields, only static content that no other application
can silently change afterward.

## Supported field types

| Type | fitz constant | Editable in UI | Flattened how |
|------|---------------|-----------------|----------------|
| Text (single/multi-line) | `PDF_WIDGET_TYPE_TEXT` | ✅ | `TextWriter` (selectable text) |
| Checkbox | `PDF_WIDGET_TYPE_CHECKBOX` | ✅ | Page-clip pixmap |
| Radio button | `PDF_WIDGET_TYPE_RADIOBUTTON` | ✅ | Page-clip pixmap |
| Combo box | `PDF_WIDGET_TYPE_COMBOBOX` | ✅ | `TextWriter` (selectable text) |
| List box | `PDF_WIDGET_TYPE_LISTBOX` | ❌ (`SUPPORTED_FORM_TYPES` excludes it) | Page-clip pixmap (still flattened at sign time even though never editable) |
| Push button, unknown types | – | ❌ | Left as-is by the form-field code path |

Unsupported-but-present field types trigger a status-bar hint
(`t("form_fields_hint_unsupported")`) telling the user to verify their
content in another viewer before signing; they still render normally via
fitz's own page rendering, just without an edit overlay.

`SUPPORTED_FORM_TYPES` (`pdf_view.py`) is the editability set; a second,
narrower module-level set, `MANUAL_PAINT_FORM_TYPES = {TEXT, COMBOBOX}`, marks
which field types the app draws its own value for (see "Avoiding double
rendering" below) — checkboxes and radio buttons are not in it, since their
selected state is a glyph/dot supplied by fitz's own appearance stream, not
text the app draws itself.

---

## Why flatten instead of freeze

DocMDP P=2 (used to allow multiple signatures) explicitly *permits* form
field values to change after signing — other viewers (Acrobat etc.) allow
post-signature form filling, so a "frozen in this app's UI only" policy
would be a UI-only restriction other applications wouldn't respect.
Flattening solves this structurally: once there are no interactive fields
left, nothing can be filled in "afterward" because there is nothing left to
fill. What the user signs is exactly what the signed document shows,
permanently — the same reasoning already applied to text annotations
(`_burn_in_freetext`, see `docs/text-annotations-rendering.md`).

---

## Editability rule

Form fields are editable only when the document has **no** signatures yet:

```python
self._form_fields_editable = not bool(self.signed_fields or self.locked_fields)
```

If the document already contains signed or locked fields at load time, all
form fields are shown read-only and no edit overlay is offered — not a
cryptographic enforcement, but a UX policy: editing a form field in an
already-signed document would mean the first signature covers the
*unfilled* state while the visible content shows the *filled* state, which
would be misleading. The correct workflow is filling in all fields before
placing the first signature.

---

## Data model: `FormFieldDef`

```python
@dataclass
class FormFieldDef:
    field_name:    str
    field_type:    int          # fitz PDF_WIDGET_TYPE_* constant (compared directly, never mapped to a string)
    page:          int
    rect:          tuple[float, float, float, float]   # PDF native coords, y-up
    value:         str   = ""
    options:       list  = field(default_factory=list)  # combobox choices
    multiline:     bool  = False
    xref:          int   = 0
    orig_fontsize: float = 0.0   # /DA font size, 0 = auto-size
    font_name:     str   = ""    # fitz short name from /DA, e.g. "helv", "tiro"
```

Radio button groups share a `field_name`; each option is its own
`FormFieldDef` with the same name. The fitz `doc` object is the live source
of truth for widget state — `_form_fields` is the Python-side mirror, kept
in sync after every edit.

---

## Loading form fields

`_load_existing_fields()` (`main_window.py`) loops every page's
`page.widgets()`; a `PDF_WIDGET_TYPE_SIGNATURE` widget goes through the
existing signature-field classification, anything in `SUPPORTED_FORM_TYPES`
becomes a `FormFieldDef`, and an unsupported type sets `has_unsupported =
True` (driving the status-bar hint). Form-field widgets are deliberately
**not** stripped from the fitz document the way free signature fields are —
they stay in place so fitz can render their base appearance underneath the
app's own overlay:

> Formular-Widgets werden nicht aus dem fitz-Dokument entfernt – fitz
> rendert deren aktuelle Appearance automatisch.

For radio buttons specifically, `_normalize_radio_groups(doc)` (a
module-level function, called only when the document is still unsigned) runs
first — see "Radio button structure" below.

---

## Editing: click detection and overlays

`PDFViewWidget.mousePressEvent`'s real hit-test order (fuller than "signature
→ form → empty canvas" might suggest) is:

1. `Ctrl`+drag → rubber-band zoom
2. Signature-field drag handle
3. Text mode active → place a new text annotation
4. Signature-field body (`_field_at`)
5. Form-field body (`_form_field_at`, only when `form_fields_editable`)
6. Empty canvas → start drawing a new signature field

There are no dedicated `FormTextOverlay`/`FormComboOverlay` classes. Instead
`PDFViewWidget` keeps a single-slot `_form_overlay: Optional[QWidget]` /
`_form_overlay_fdef`, and `_on_form_field_click()` creates a raw
`QLineEdit` (single-line text), `QPlainTextEdit` (multiline text), or
`QComboBox` (combobox) directly, parented to the view, positioned over the
field's rect via `_pdf_to_w()`; `_close_form_overlay()` tears it down. A
small `_TextFilter(QObject)` event filter, installed per overlay, ensures the
edit commits reliably on focus-out (Qt's own `focusOutEvent` timing is not
sufficient on its own for this teardown-and-commit sequence).

**Checkbox:** toggled directly on click, no overlay — `widget.field_value`
flips and `widget.update()` regenerates the appearance stream immediately.

**Radio button:** clicking a widget does not touch fitz state inline.
Instead, `_on_form_field_click` emits the existing `form_field_changed`
signal with the field's identity **and** a select-request encoded into the
name itself: `field_name = f"\x01{fdef.field_name}\x00{fdef.xref}"`, `value
= "select"`. `_apply_form_field_edit` decodes this sentinel-prefixed form to
recognize "this is a radio selection, not a text/checkbox/combobox value" —
see below.

**Combo box:** `QComboBox` overlay pre-populated with `widget.choice_values`;
selecting an option commits immediately.

**Tab / Shift+Tab:** `focusNextPrevChild()` walks form-field overlays sorted
top-to-bottom, left-to-right, skipping checkbox/radio/combobox (Tab order is
meant for typing through text fields, mirroring the same convention used for
text-annotation boxes).

**Saving without losing an open edit:** `flush_form_overlay()` commits
whatever overlay is currently open before Save/Sign proceeds, so a value
being typed isn't silently lost if the user triggers Save/Sign without
first clicking away from the field.

Multiline text overlays auto-shrink their displayed font size to keep all
typed lines visible within the field's rect height — mirroring the same
auto-shrink logic the burn-in step applies at signing time (see below).

---

## Applying an edit: `_apply_form_field_edit`

Central update method in `main_window.py`. First decodes the `field_name`
for the `\x01name\x00xref` radio-select sentinel; then:

- **Radio selection:** calls `widget.update()` on the target widget, then
  manually resets every sibling in the group to `/AS /Off` — fitz's
  `widget.update()` incorrectly sets `/AS` to the *target's* on-state on all
  sibling widgets too, not just the one clicked, so the siblings must be
  corrected afterward. `/V` handling is more involved — see "Radio button
  structure" below.
- **Multiline text:** auto-shrinks `widget.text_fontsize` to fit all lines
  within the field rect height, then calls `widget.update()`.
- **Checkbox / single-line text / combobox:** sets `widget.field_value` and
  calls `widget.update()` directly.

In every case: `_has_unsaved_changes = True`, the corresponding
`FormFieldDef.value` is updated, `_render_current_page()` re-renders, and
**an explicit `self._cv.refresh_page_pixmap(edited_page)`** follows —
checkbox/radio state lives only in fitz's rasterized appearance stream
(unlike text/combobox, which the app also paints itself), so without this
forced refresh a toggle wouldn't visually update until the page was
scrolled away and back.

---

## Avoiding double rendering (`NoView` trick)

`page.get_pixmap()` renders with `annots=True` by default, which bakes
fitz's own committed appearance stream for a widget into the base pixmap
*in addition to* the value `PDFViewWidget.paintEvent` draws itself for
`MANUAL_PAINT_FORM_TYPES` fields (text/combobox) — but only once a field has
been edited at least once (`widget.update()` is what creates that
appearance stream in the first place). Left alone, this produces a visible,
slightly misaligned second copy of the text once a field has been touched.

`_render_base_pixmap()` works around it by temporarily setting the
annotation `NoView` flag (bit 6) on every `MANUAL_PAINT_FORM_TYPES` widget
right before rasterizing the base page pixmap, then restoring the flag —
fitz's renderer skips a `NoView`-flagged annotation, leaving only the app's
own `paintEvent` drawing visible. Checkboxes/radio buttons are deliberately
excluded from this trick: their selected-state glyph comes from fitz's own
appearance stream and has no app-drawn equivalent to conflict with (a
checkbox does additionally get a small "✓" the app draws on top when
`value == "Yes"`, purely as a supplementary highlight, not a replacement).

---

## Radio button structure

Radio button groups need two independent fixes to render correctly across
viewers; both live in `main_window.py`.

### Merged structure → parent/kids (`_normalize_radio_groups`)

fitz creates radio groups as **merged** objects (widget annotation and field
dictionary in the same PDF object, no `/Parent`). Adobe Acrobat requires the
standard parent/kids hierarchy instead. `_normalize_radio_groups(doc)`
converts merged groups in-place — combined radio flag `/Ff 49152` (both the
fitz convention, bit 16, and the ISO 32000 Table 227 convention, bit 15) on
a new parent field dict, widgets keep `/FT /Btn`/`/Rect`/`/AP`/`/AS` and gain
a `/Parent` back-reference, `/T`/`/V`/`/Ff`/`/DA`/`/BS` are dropped from the
widgets themselves, and `AcroForm /Fields` lists only the parent xref. It
runs from `_load_existing_fields`, **only for still-unsigned documents** —
a signed document's structure must not be modified.

### `/V` value: per-viewer reader disagreement

Different viewers read radio state from different keys:

| Viewer | Key read | Consequence if wrong |
|---|---|---|
| Chromium / PDFium | `/AS` per widget | Correct as long as `/AS` is set right |
| Firefox / PDF.js | `/V` of the field | Shows nothing if `/V` doesn't match any `/AP/N` key |
| Adobe Acrobat | Parent/kids structure (see above) | Requires the normalized structure to render at all |

fitz's `widget.update()` writes `/V` as the PDF string `(Yes)` — wrong both
in value (doesn't match the option-specific `/AP/N` keys, e.g. `Opt1`) and in
type (a button field's `/V` should be a PDF name, not a string).
`_apply_form_field_edit` corrects this, branching on whether
`_normalize_radio_groups` already converted the group:

- **Parent/kids present** (normalized, unsigned document): `/V` is set as a
  PDF name (e.g. `/Opt1`) **only on the parent** field dict — matches how
  Acrobat expects a proper radio group to be structured.
- **No `/Parent`** (merged/legacy — e.g. a group from a PDF authored by
  another application, not run through normalization): falls back to the
  pattern observed in Firefox-saved PDFs — each sibling widget gets **its
  own** on-state as `/V`, derived by parsing that sibling's own `/AP/N`
  keys, rather than one shared group value.

Verified in `tests/test_radio_button_save.py` (28 assertions): correct
`/AS`/`/V` after either selection direction, three-option groups, no `(Yes)`
string ever remaining, and round-trip compatibility with Firefox- and
Chromium-saved PDFs (`tests/analyze_radio_pdf.py`,
`tests/create_radio_test_pdfs.py`, plus reference files
`tests/radio_ff_opt2.pdf` / `tests/radio_chromium_opt2.pdf` /
`tests/interaktiver_radio_test.pdf`).

---

## Signing integration: the flatten phase

`SignWorker._burn_in_form_fields(self, pdf_bytes) -> bytes` runs before
`_burn_in_freetext()`, which runs before the existing pyhanko signing
pipeline — only when `_form_fields` is non-empty; documents without form
fields are unaffected.

For every widget still present at signing time:

| Field type | Method |
|---|---|
| Text, combobox | `SignWorker._write_field_text(page, widget)` — writes the value as real, selectable text via `fitz.TextWriter` |
| Checkbox, radio button, list box | `page.get_pixmap(clip=widget.rect, dpi=216)` **of the page**, inserted as an image — captures the field's actual on-page rendered appearance (not the annotation's isolated AP stream), preserving whatever visual design the PDF author chose (✓, ✗, filled square, dot, …) |

Every widget is then removed (`page.delete_widget(widget)`) and the document
saved with `doc.save(out, garbage=4, deflate=True)`.

`_write_field_text` mirrors the positioning logic in
`_apply_form_field_edit`'s multiline auto-shrink: font size auto-sizes to
72% of the field rect height (capped at 12pt, floored at 4pt) when no
explicit `/DA` size is set, the baseline is vertically centered using the
font's ascender metric, multiline text auto-shrinks to fit, PDF `/DA` font
aliases are mapped to fitz short names (`Helv` → `helv`, etc.), and rotated
pages use the same `TextWriter(morph=...)` counter-rotation trick documented
in `docs/text-annotations-rendering.md`.

After signing, the signed bytes become the new `_working_bytes`; reloading
from them finds no form-field widgets left, so `_form_fields` is empty and
no overlays are shown — there is no explicit "frozen" state to track.

---

## Visual design

| State | Border | Fill | Notes |
|-------|--------|------|-------|
| Editable, empty or filled | Green `#2e7d32` | Light green tint | Value drawn in `paintEvent` for text/combobox, using the field's own `/DA` font via `make_form_field_qfont()`; checkbox additionally draws a "✓" glyph when checked |
| Focused (overlay active) | Green, 2px | White | `QLineEdit`/`QPlainTextEdit`/`QComboBox` overlay visible |
| Not editable (document already signed) | No overlay | – | fitz renders the field's appearance as-is |

Form-field overlays render below signature-field overlays in Z-order.

---

## Out of scope

- Creating new form fields — only existing PDF fields can be filled.
- List boxes — never editable in the UI (still flattened at sign time).
- JavaScript / calculated fields — displayed read-only, never evaluated.
- Digital form submission (FDF/XFDF export).
- Editing form fields in an already-signed PDF.
- Field tab order / appearance-stream customization beyond fitz's defaults.

---

## Files Changed

| File | Change |
|---|---|
| `pdf_signer/pdf_view.py` | `FormFieldDef`, `SUPPORTED_FORM_TYPES`, `MANUAL_PAINT_FORM_TYPES`; form-field hit-testing and overlay creation/teardown in `mousePressEvent`/`_on_form_field_click`/`_close_form_overlay`; `_TextFilter`; `focusNextPrevChild`; `flush_form_overlay`; `NoView`-flag handling in `_render_base_pixmap` |
| `pdf_signer/main_window.py` | `_form_fields`, `_form_fields_editable`; form-field loading in `_load_existing_fields`; `_normalize_radio_groups`; `_apply_form_field_edit` (incl. radio `\x01`/`\x00` sentinel decoding and the parent/no-parent `/V` branches) |
| `pdf_signer/signer.py` (`SignWorker`) | `_burn_in_form_fields`, `_write_field_text`; integration point in `run()` before `_burn_in_freetext()` |
| `pdf_signer/i18n/` | `form_fields_hint_unsupported` |
| `tests/` | `test_widget_ap_update.py`, `test_fitz_bytes_pyhanko_sign.py`, `test_radio_button_save.py`, `analyze_radio_pdf.py`, `create_radio_test_pdfs.py`, `create_test_form.py`, plus fixture PDFs (`test_form.pdf`, `interaktiver_radio_test.pdf`, `radio_ff_opt2.pdf`, `radio_chromium_opt2.pdf`) |
