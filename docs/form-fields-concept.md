# Concept: Interactive PDF Form Fields

**Status:** Draft  
**Date:** 2026-04-19

---

## Goal

Allow users to fill in PDF form fields (text, checkbox, radio button, combo box) before signing. At signing time, all form fields are **flattened** – their visual appearance is burned into the page content and the interactive widgets are removed. The signed document contains no more form fields, only static content.

---

## Supported Field Types

| Type | PDF Constant | Use Case |
|------|-------------|----------|
| Text (single-line) | `PDF_WIDGET_TYPE_TEXT` | Name, address, date |
| Text (multi-line) | `PDF_WIDGET_TYPE_TEXT` + `PDF_TX_FIELD_IS_MULTILINE` | Notes, remarks |
| Checkbox | `PDF_WIDGET_TYPE_CHECKBOX` | Accept terms, yes/no flags |
| Radio button | `PDF_WIDGET_TYPE_RADIOBUTTON` | Exclusive choice within a group |
| Combo box | `PDF_WIDGET_TYPE_COMBOBOX` | Country, category dropdown |

List boxes (`PDF_WIDGET_TYPE_LISTBOX`) are deferred – rare in practice and add UI complexity.

Push buttons are not interactive data fields and are ignored.

### Unsupported Field Types

Fields of unsupported types (ListBox, PushButton, unknown types) are **never editable** in this app. They are rendered read-only via fitz's normal page rendering – their appearance and current value are visible to the user exactly as they will be signed. A status bar hint informs the user if such fields exist: "This document contains fields that cannot be edited here. Please verify their content before signing."

If unsupported fields need to be filled first, the recommended workflow is:
1. Fill unsupported fields in another application (e.g. LibreOffice, Adobe Acrobat)
2. Save (without signing) 
3. Reopen in pdf-signer and sign

---

## Why Flatten Instead of Freeze

The PDF standard (ISO 32000) with DocMDP P=2 – which we use to allow multiple signatures – explicitly **permits** form field values to be changed after signing. Other PDF viewers (Adobe Acrobat etc.) enforce this and allow post-signature form filling. A "frozen in UI" approach would be a UI-only policy that other apps would not respect.

Flattening solves this structurally: after flattening there are no interactive fields left in the document. No other application can fill in "more" because there is nothing to fill. What the user signs is exactly what the signed document will show, permanently.

Flattening is analogous to the existing `_burn_in_freetext()` step in `signer.py`, which rasterizes text annotations before signing for the same reason.

---

## Editability Rule

Form fields are editable **only when the document has no signatures**. If the document already contains signatures at load time (`signed_fields` or `locked_fields` non-empty), all form fields are shown read-only and the edit overlays are suppressed.

This is not a cryptographic enforcement but a UX policy: editing form fields in an already-signed document would require flattening them into a post-signature incremental revision. The first signature would then cover the original (unfilled) field state, not the filled state – which is misleading. The correct workflow is to fill all fields before signing.

```python
_form_fields_editable: bool = not (signed_fields or locked_fields)
```

---

## Data Model

### `FormFieldDef` (new dataclass)

```python
@dataclass
class FormFieldDef:
    field_name: str          # PDF /T name (unique within the document)
    field_type: str          # "text" | "checkbox" | "radio" | "combobox"
    page: int                # 0-based page index
    rect: tuple[float,float,float,float]  # PDF native coords (x0,y0,x1,y1), y-up
    value: str               # Current field value (always string; "Yes"/"Off" for checkbox/radio)
    options: list[str]       # ComboBox choices; empty for other types
    multiline: bool          # Text fields only
```

Radio button groups share a `field_name` in PDF. Each option is a separate widget. We store them as individual `FormFieldDef` objects with the same `field_name`.

### Storage in `PDFSignerApp`

```python
self._form_fields: list[FormFieldDef] = []
self._form_fields_editable: bool = True
```

The fitz `doc` object is the live source of truth for widget state. `_form_fields` is the Python-side mirror, kept in sync after every user edit.

---

## Loading Form Fields

`_load_existing_fields()` (in `main_window.py`) is extended:

```python
for page_idx in range(len(doc)):
    page = doc[page_idx]
    for widget in page.widgets():
        if widget.field_type == fitz.PDF_WIDGET_TYPE_SIGNATURE:
            ...  # existing logic
        elif widget.field_type in SUPPORTED_FORM_TYPES:
            self._form_fields.append(_widget_to_form_field_def(widget, page_idx))

self._form_fields_editable = not bool(self._signed_fields or self._locked_fields)
```

Form fields are **not stripped** from the fitz doc – they remain so fitz can render their current appearance automatically.

---

## Editing: Strategy

When `_form_fields_editable` is True, clicks on form field areas open lightweight in-place editors. The approach mirrors the `TextAnnotOverlay` pattern.

### Click Detection

`pdf_view.py::mousePressEvent` is extended. Priority order:

1. Signature field drag handle
2. Signature field body
3. Form field body (editable only)
4. Empty canvas → begin drawing new signature field

### Per-Type Interaction

**Text field:**  
A `QLineEdit` (single-line) or `QPlainTextEdit` (multiline) overlay is positioned over the field rect (via `_pdf_to_w()`). On `focusOut` or Enter: `widget.field_value = new_value; widget.update()`, then re-render.

**Checkbox:**  
Toggle on single click. No overlay needed. `widget.field_value = "Yes" if current == "Off" else "Off"; widget.update()`, then re-render.

**Radio button:**  
On click: set clicked widget to `widget.on_state()`, all siblings with same `field_name` to `"Off"`. Call `widget.update()` for each. Re-render.  
Note: fitz does **not** auto-reset siblings – must be done manually.

**Combo box:**  
`QComboBox` overlay pre-populated with `widget.choice_values`. On selection: `widget.field_value = selected; widget.update()`, re-render.

### `_apply_form_field_edit(field_name, new_value)`

Central update method in `main_window.py`:
1. Finds the fitz widget on the relevant page.
2. Calls `widget.field_value = new_value; widget.update()`.
3. Updates the corresponding `FormFieldDef` in `_form_fields`.
4. Triggers page re-render in `pdf_view.py`.
5. Sets `_unsaved_changes = True`.

---

## Signing Integration

### Flatten Phase (new, before existing signing steps)

At signing time, a new phase is inserted before the existing signing pipeline, analogous to `_burn_in_freetext()`:

```
_burn_in_form_fields(pdf_bytes) → flattened_bytes
flattened_bytes → [existing pipeline] → sign
```

**Hybrid rendering strategy – field type determines method:**

| Field type | Method | Rationale |
|------------|--------|-----------|
| Text (single/multi-line) | `fitz.TextWriter` | Value is text; must remain selectable and searchable in the signed PDF |
| Combo box | `fitz.TextWriter` | Selected value is text; same rationale |
| Checkbox | Render AP stream → pixmap → embed as image | No text content; AP stream captures the exact visual design (checkmark style, colors) defined by the PDF author |
| Radio button | Render AP stream → pixmap → embed as image | Same rationale as checkbox |

Drawing our own vector shapes for checkboxes/radio buttons would impose a fixed visual standard and ignore the PDF author's intended appearance (which varies: ✓, ✗, filled square, dot, etc.). Rendering the existing AP stream preserves the original design exactly.

**Implementation sketch for `_burn_in_form_fields()`:**

```python
def _burn_in_form_fields(self, pdf_bytes: bytes) -> bytes:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    for page in doc:
        for widget in list(page.widgets()):
            ft = widget.field_type
            rect = widget.rect
            if ft == fitz.PDF_WIDGET_TYPE_TEXT or ft == fitz.PDF_WIDGET_TYPE_COMBOBOX:
                # Embed value as selectable text via TextWriter
                _write_field_text(page, widget)
            elif ft in (fitz.PDF_WIDGET_TYPE_CHECKBOX, fitz.PDF_WIDGET_TYPE_RADIOBUTTON):
                # Render AP stream as pixmap, insert as image
                pix = widget.annot.get_pixmap(dpi=216)
                page.insert_image(rect, pixmap=pix)
            page.delete_widget(widget)
    out = io.BytesIO()
    doc.save(out, garbage=0, deflate=False)
    return out.getvalue()
```

`_write_field_text()` extracts font name and size from the widget's `/DA` (Default Appearance) string – the same parsing already used for text annotations – and writes the field value at the correct baseline position within the widget rect.

### Full Signing Flow (when form fields present)

```
fitz_doc.tobytes(garbage=0, deflate=False)   # export edited field values
→ _burn_in_form_fields()                      # flatten: widgets → static content
→ IncrementalPdfFileWriter                    # existing pyhanko pipeline
→ embed signature fields → sign
```

This is only needed when `_form_fields` is non-empty. When the document has no form fields, the existing flow is unchanged.

### After Signing

- Signed bytes stored as new `_working_bytes`.
- On reload from signed bytes: no form field widgets exist → `_form_fields` is empty, no overlays shown.
- No explicit "freeze" state needed.

---

## Visual Design

Form fields use a single visual style (editable) plus the implicit read-only state (no overlay, just fitz rendering):

| State | Border | Fill | Notes |
|-------|--------|------|-------|
| Editable | Green `#2e7d32` | Light green tint | Cursor `IBeam` / `PointingHand` |
| Focused | Green, 2px | White | Overlay widget visible |
| Not editable (already signed doc) | No overlay | – | fitz renders field appearance as-is |

Form field overlays are rendered **below** signature field overlays in Z-order.

---

## Changes per Module

### `main_window.py`
- Add `FormFieldDef` dataclass.
- Add `_form_fields: list[FormFieldDef]` and `_form_fields_editable: bool`.
- Extend `_load_existing_fields()` to populate `_form_fields`.
- Add `_apply_form_field_edit()`.
- Pass `_form_fields` and `_form_fields_editable` to `PDFViewWidget` on page load.
- Pass `fitz_doc.tobytes(...)` as base bytes to `SignWorker` when form fields present.

### `pdf_view.py`
- Receive `form_fields` and `form_fields_editable` from parent.
- Extend `mousePressEvent` with form field hit-testing (only when editable).
- Add overlay widgets: `FormTextOverlay`, `FormComboOverlay`.
- Add `_draw_form_fields()` pass in `paintEvent` (green borders when editable).

### `signer.py` (`SignWorker`)
- Add `_burn_in_form_fields(pdf_bytes) → bytes` using `doc.bake(widgets=True)`.
- Insert call at start of signing pipeline when form fields are present.
- Accept pre-exported fitz bytes as `pdf_bytes` when form fields were edited.

### `pdf_signer/i18n/`
- `form_fields_hint_unsupported` – "This document contains fields that cannot be edited here. Please verify their content before signing."
- `form_fields_editable_status` – "Fill in form fields before signing."

---

## What is Explicitly Out of Scope

- **Creating new form fields**: Only existing PDF fields can be filled.
- **List boxes**: Deferred.
- **JavaScript / calculated fields**: Displayed read-only, not evaluated.
- **Digital form submission** (FDF/XFDF export): Not supported.
- **Form field editing in already-signed PDFs**: Not supported; fill before signing.
- **Field tab order / appearance stream customization**: Rely on fitz defaults.

---

## Open Questions

### Resolved

**1. AP Regeneration** ✓  
`widget.update()` (not `page.update_widget()` – does not exist) correctly regenerates the Appearance Stream for text, checkbox, and combo box. Verified empirically in `tests/test_widget_ap_update.py`.

**2. Radio button group identity and mutual exclusion** ✓  
`widget.button_caption` is unreliable (returns `None`). Use `widget.on_state()` to identify each radio option. Fitz does not auto-reset siblings – must be done manually by iterating all widgets with the same `field_name`.

**3. fitz export + pyhanko signing** ✓  
`fitz_doc.tobytes(garbage=0, deflate=False)` after `widget.update()` produces bytes pyhanko can sign correctly. ByteRange integrity verified (`br[2] + br[3] == file_size`). Tested in `tests/test_fitz_bytes_pyhanko_sign.py`.

### Open

**4. `_write_field_text()` positioning** – Verify that baseline position, font name, and font size extracted from the widget's `/DA` string produce correct visual alignment within the field rect for the common cases (single-line, multiline with word wrap). Test with the `test_form.pdf` fixture before integration.

**5. Unsaved-changes warning** – Verify that `_check_unsaved_changes()` correctly triggers when the user has edited form fields and tries to open a new file. Covered by `_unsaved_changes = True` in `_apply_form_field_edit()`, but needs integration test.

---

## Radio Button /V Bug – Investigation & Fix (2026-04-20)

### Symptom

After saving a PDF with a changed radio button selection in pdf-signer, Firefox/PDF.js showed no button as selected, while Chromium/PDFium showed the correct selection.

### Root Cause

**fitz creates radio button widgets as "merged" objects** (widget annotation and field dictionary in the same PDF object, no separate `/Parent` field).  In this structure each widget contains both `/AS` (appearance state, per-widget) and `/V` (group value, conceptually shared).

fitz's `widget.update()` sets `/V` as the PDF string `(Yes)` – in round brackets – instead of a PDF name like `/Opt1`.  This is wrong in two ways:

1. The value `Yes` does not match any key in `/AP/N` (which was patched by `_fix_radio_group` to use option-specific names like `Opt1`, `Opt2`).
2. The encoding as a string `(Yes)` instead of a name `/Yes` is technically incorrect for `/V` in a button field.

**How each browser reads radio button state:**

| Browser | Primary key used | Effect |
|---------|-----------------|--------|
| Chromium / PDFium | `/AS` per widget | Correct – we set `/AS` properly |
| Firefox / PDF.js | `/V` of the field | Wrong – fitz wrote `(Yes)`, no `/AP/N` key matches → no button shown |
| Adobe Acrobat | Unknown (pending Windows VM test) | – |

**Additional fitz bug** (already known, workaround in place): `widget.update()` on the target button also sets `/AS` to `on_state()` on *all* sibling buttons, not only the target. The existing fix resets sibling `/AS` to `/Off` via `xref_set_key` afterwards.

### Investigation Method

Test PDFs were created in two sets:

- **Set A** – `/AS` correct per widget, `/V` left as fitz default `(Yes)` → Chromium correct, Firefox shows nothing (confirms root cause)
- **Set B** – `/AS` correct, `/V` set as PDF name `/Opt1` / `/Opt2` on all widgets → both browsers correct (confirms fix)

Browser-saved PDFs were then analysed with `tests/analyze_radio_pdf.py`:

| Browser saves Opt2 selected | Widget (Opt1, off) | Widget (Opt2, selected) |
|---|---|---|
| **Firefox** | `/AS /Off`, `/V /Opt1` (unchanged) | `/AS /Opt2`, `/V /Opt2` (own name) |
| **Chromium** | `/AS /Off`, `/V /Opt2` (group value) | `/AS /Opt2`, `/V /Opt1` (sibling name) |

Firefox sets `/V` only on the selected widget to its own export name; other widgets keep their previous `/V`.  
Chromium's `/V` behaviour is inconsistent (appears to swap values), but since Chromium itself reads `/AS`, it renders correctly regardless.

### Fix

In `_update_form_field` (`main_window.py`), after the existing sibling `/AS` correction, `/V` is now explicitly set as a PDF name on every widget in the group and on the parent field dict (if one exists):

```python
if is_radio and radio_on_state:
    v_val = f"/{radio_on_state}"                          # e.g. "/Opt1"
    self.pdf_doc.xref_set_key(target_xref, "V", v_val)
    for _xref in radio_sibling_xrefs:
        self.pdf_doc.xref_set_key(_xref, "V", v_val)
    _parent_m = re.search(r'/Parent\s+(\d+)\s+0\s+R',
                          self.pdf_doc.xref_object(target_xref, compressed=False))
    if _parent_m:
        self.pdf_doc.xref_set_key(int(_parent_m.group(1)), "V", v_val)
```

Verified: `radio_a_opt1_fixed.pdf` (set A + `/V` patched) shows Opt1 correctly in Firefox.

### Test Coverage

`tests/test_radio_button_save.py` (28 assertions, all pass):

| Test | What it checks |
|------|---------------|
| `test_select_opt2_from_opt1` | `/AS` and `/V` after direction change; save+reload |
| `test_select_opt1_from_opt2` | Reverse direction |
| `test_three_options` | Group with 3 buttons, middle selected; all `/V` match |
| `test_no_v_string_remains` | `/V (Yes)` string never present; `/V` is always a name |
| `test_firefox_saved_roundtrip` | Firefox-saved PDF: `/AS` readable by fitz |
| `test_chromium_saved_roundtrip` | Chromium-saved PDF: `/AS` readable by fitz |

### Tools

- `tests/create_radio_test_pdfs.py` – generates Set A / Set B test PDFs
- `tests/analyze_radio_pdf.py` – dumps raw `/AS`, `/V`, `/AP/N`, `/Ff`, parent structure for any PDF
- `tests/radio_ff_opt2.pdf` / `tests/radio_chromium_opt2.pdf` – reference saves from browsers

### Resolved

**6. Adobe Acrobat Reader – merged structure not supported** ✓ (2026-04-20)

All existing test files failed in Acrobat because fitz creates radio buttons in a
*merged* structure (widget = field, both listed in AcroForm /Fields).  Acrobat
requires the standard *parent/kids* hierarchy.

Reference file `tests/interaktiver_radio_test.pdf` (works in all viewers) revealed
the required structure:

- **Parent field dict** (`/FT /Btn /Ff 49152 /T /V /DV /Kids`): both Radio-flag
  conventions must be set: `32768` (bit 16, fitz) **and** `16384` (bit 15, spec
  ISO 32000 Table 227) → combined `/Ff 49152`.  No `/DA` (only for text fields).
- **Widget annotations** (`/Subtype /Widget /FT /Btn /Rect /AP /AS /Parent`):
  keep `/FT /Btn`, drop `/T /V /Ff /DA /BS`; add `/Parent` back-reference.
- **AcroForm /Fields**: only the parent xref, not individual widgets.

**Fix:** `_normalize_radio_groups(doc)` in `main_window.py` (module-level function)
converts merged groups in-place.  Called from `_load_existing_fields` for unsigned
documents only (signed documents must not be structurally modified).

After normalization, `_apply_form_field_edit` detects the parent via `/Parent`
and sets `/V` only on the parent dict, not on individual widgets.
