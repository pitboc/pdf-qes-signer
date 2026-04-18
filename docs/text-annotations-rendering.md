# Text Annotations: Rendering Pipeline and Font Handling

## Overview

Text annotations placed by the user before signing are embedded into the PDF as
**real, selectable text** using pyMuPDF's `TextWriter` API.  Earlier versions
rasterized the annotation appearance to a pixmap (≈ 216 dpi image) and inserted
that image into the page content stream, which made the text non-selectable.

---

## Why the Old Approach Rasterized

The original pipeline used `page.add_freetext_annot()` to create a PDF FreeText
annotation, then called `annot.get_pixmap()` and `page.insert_image()` to burn
the appearance into the page content as an image.  The motivation was
simplicity: pyMuPDF generates a correct appearance stream for FreeText
annotations, including font metrics and the `Tc` character-spacing operator.
Converting that appearance to a pixmap and inserting it required no knowledge
of PDF text operators.

The downside: text became a raster image, identical in principle to a scan.
No copy-paste, no search, no screen-reader access.

---

## New Approach: TextWriter with Per-Character Placement

### Core Mechanism

`fitz.TextWriter` writes native PDF text operators (`BT … Tf Td Tj ET`) directly
into the page content stream.  Text placed this way is fully selectable and
searchable, and fitz embeds the font as a **Type0/CID subset** so rendering is
viewer-independent (no dependency on locally installed fonts).

### Character Spacing

PDF's `Tc` (character spacing) operator adds a fixed offset after every glyph.
`TextWriter` has no `Tc` parameter, so character spacing is implemented as
**explicit per-character absolute positioning**:

```python
for char in line:
    tw.append((cx, y_line), char, font=font, fontsize=ann.font_size)
    adv = font.char_lengths(char, ann.font_size)
    cx += (adv[0] if adv else ann.font_size * 0.6) + ann.char_spacing
```

Each character is placed at an absolute `(cx, y)` coordinate.  After appending
the character, `cx` advances by `glyph_advance + char_spacing`.  The result is
visually identical to `Tc` because the inter-glyph gaps are the same; the
difference is that the spacing is baked into the x-positions rather than carried
in a text-state operator.

### Accuracy of `font.char_lengths()`

Testing confirmed that `fitz.Font.char_lengths(char, size)` returns the **exact**
advance width that `TextWriter` uses internally (delta = 0.000 pt across all
Base-14 font variants, measured via `page.get_text("rawdict")` position
extraction).  This means the per-character placement is pixel-perfect — no
approximation is involved.

### Coordinate System and Page Rotation

`TextAnnotDef.x` / `.y` are stored in **PDF native coordinates** (origin
bottom-left, y-up, unrotated).  `TextWriter` expects the same unrotated
coordinate space — a simple y-axis flip is the only conversion needed:

```python
x0 = ann.x
y0 = page.mediabox.height - ann.y
```

#### `page.mediabox.height` vs `page.rect.height`

This distinction is critical for rotated pages.  For a `/Rotate 90` A4 page:

| Property | Value | Meaning |
|---|---|---|
| `page.mediabox.height` | 842 pt | original (unrotated) page height — always the taller dimension |
| `page.rect.height` | 595 pt | visual height after rotation — the shorter dimension |

Using `page.rect.height` on a rotated page gives `595 − y`, which for typical
`y` values in the portrait range (e.g. `y = 700`) yields a **negative
coordinate** (`−105`), placing the text entirely outside the page.
`page.mediabox.height` is always the correct denominator.

For a non-rotated page `rect.height == mediabox.height`, so the formula is
safe for all pages.

For multi-line text each subsequent line shifts down by `font_size × 1.2`
(fitz default line height, y increases downward):

```python
y_line = y0 + line_index * ann.font_size * 1.2
```

#### Glyph direction: `morph` counter-rotation

`TextWriter.write_text(page)` does **not** automatically counter-rotate glyphs
for any page rotation value.  The content stream always receives a standard
horizontal text matrix; when the PDF viewer applies `/Rotate N`, the text
appears rotated by N degrees.

**Fix**: pass `morph=(Point(x0, y0), Matrix(-rot))` to `write_text()`.
This rotates every glyph by `−rot` degrees around the annotation's baseline
origin `(x0, y0)` in the content stream.  After the viewer applies its `rot`
rotation, each glyph is upright and reads left-to-right:

```python
rot = page.rotation   # 0, 90, 180, or 270
if rot:
    tw.write_text(page, morph=(fitz.Point(x0, y0), fitz.Matrix(rot)))
else:
    tw.write_text(page)
```

Note: the sign is `+rot`, not `−rot`.  Empirically, `Matrix(−rot)` produces the
wrong glyph direction for 90° and 270°.  For 180° both signs are equivalent.

**Why the coordinate formula stays the same for all rotations**: the pivot
`(x0, y0) = (ann.x, mediabox.height − ann.y)` is the fitz-unrotated
equivalent of the PDF-native annotation position.  After the viewer applies
the page rotation matrix, this pivot is mapped to exactly the correct visual
position — so no coordinate adjustment is needed alongside the morph.

Verified: 0° (no change), 90°, 180°, 270°.

#### Why signature field appearances cannot use the same trick

Signature field appearances are stored in a **Form XObject** (the `/AP`
entry of the annotation dictionary).  An XObject has its own independent
coordinate system; the PDF viewer renders it directly into the field rectangle
**without** applying the page `/Rotate` transform.  Any text written
horizontally in the XObject will therefore appear rotated on a rotated page.

pyhanko's `TextStampStyle` does not expose the XObject's internal transform
matrix, so it is not possible to inject a counter-rotation through the API.
The workaround used in `_build_rotated_appearance` is to render the full
appearance with Pillow at the visual (displayed) dimensions, rotate the
resulting bitmap by the page rotation angle, and pass it to pyhanko as a
pre-rendered background image.  pyhanko stores this bitmap as the XObject
content without modification.

### Font Embedding

When `TextWriter.write_text(page)` is called, fitz automatically embeds the
font as a **Type0/CID** resource in the PDF.  This was verified by inspecting
`page.get_fonts()` after the call:

```
basefont=Helvetica-Bold   type=Type0
basefont=Courier          type=Type0
basefont=Times-Italic     type=Type0
```

All 12 Base-14 variants produce properly embedded fonts, so the visual
appearance is identical regardless of which fonts are installed on the viewer's
system.

---

## Supported Font Variants

All 12 PDF Base-14 variants are supported, identified by their fitz short names:

| fitz short name | PDF Base-14 name       | Bold | Italic/Oblique |
|-----------------|------------------------|------|----------------|
| `helv`          | Helvetica              |      |                |
| `hebo`          | Helvetica-Bold         | ✓    |                |
| `heit`          | Helvetica-Oblique      |      | ✓              |
| `hebi`          | Helvetica-BoldOblique  | ✓    | ✓              |
| `tiro`          | Times-Roman            |      |                |
| `tibo`          | Times-Bold             | ✓    |                |
| `tiit`          | Times-Italic           |      | ✓              |
| `tibi`          | Times-BoldItalic       | ✓    | ✓              |
| `cour`          | Courier                |      |                |
| `cobo`          | Courier-Bold           | ✓    |                |
| `coit`          | Courier-Oblique        |      | ✓              |
| `cobi`          | Courier-BoldOblique    | ✓    | ✓              |

Note: `coob` is **not** a valid fitz short name for Courier-Oblique — the
correct alias is `coit`.  This was discovered during testing.

---

## Qt Preview (TextAnnotOverlay)

The editable overlay widget uses Qt's `QFont` to mirror the fitz rendering as
closely as possible.  The URW font family (e.g. "Nimbus Sans") is tried first
because it is the exact font that MuPDF/fitz uses internally for the Base-14
Helvetica/Times/Courier equivalents — giving the best WYSIWYG match.

Bold and italic are applied via `QFont.setBold()` / `QFont.setItalic()` based
on lookup tables in `TextAnnotOverlay`:

```python
_FONT_BASE   = {"helv": "helv", "hebo": "helv", …}   # variant → base family
_FONT_BOLD   = frozenset({"hebo", "hebi", "tibo", "tibi", "cobo", "cobi"})
_FONT_ITALIC = frozenset({"heit", "hebi", "tiit", "tibi", "coit", "cobi"})
```

---

## Font Roundtrip in Saved (Unsigned) PDFs

When the user saves a PDF without signing, `SaveFieldsWorker` embeds text
annotations as FreeText annotations so they can be re-loaded on the next open.

**Problem:** `page.add_freetext_annot(fontname="hebo")` always writes `/Helv`
into the annotation's `/DA` string regardless of the requested font variant.
This is a pyMuPDF limitation — it normalizes all Helvetica variants to `/Helv`
in the Default Appearance.

**Solution:** A custom PDF key `/QESFontName` stores the exact fitz short name
alongside the annotation object:

```python
doc.xref_set_key(xref, "QESFontName", f"({ann.font_name})")
```

On reload, `_load_existing_fields` reads `/QESFontName` first and only falls
back to `_parse_da_string` (which reads `/DA`) if the key is absent (e.g. for
annotations created by an older version):

```python
if _fnk[0] == "string" and _fnk[1] in _TEXT_SHORT_TO_FONT:
    _fn = _fnk[1]   # reliable; overrides whatever /DA says
```

The other custom keys follow the same pattern:

| Key              | Content                        | Type        |
|------------------|--------------------------------|-------------|
| `/Subj`          | `"QESTextAnnot"` (marker)      | string      |
| `/QESBaselineX`  | baseline-left x (PDF points)   | float       |
| `/QESBaselineY`  | baseline-left y (PDF points)   | float       |
| `/QESCharSpacing`| character spacing (PDF points) | float       |
| `/QESFontName`   | fitz short name, e.g. `"hebo"` | string      |

---

## Foreign FreeText Annotations

FreeText annotations already present in the PDF (not created by this
application, i.e. without `/Subj "QESTextAnnot"`) are still handled by the
original rasterization path in `_burn_in_freetext` Phase 2.  They are rendered
to a 216-dpi pixmap and inserted as page-content images before signing so they
cannot be removed or altered after the signature is applied.

This is intentional: we do not attempt to parse foreign annotation appearance
streams, and their font/spacing properties are unknown to us.

---

## Files Changed

| File                          | Change                                                              |
|-------------------------------|---------------------------------------------------------------------|
| `pdf_signer/pdf_view.py`      | `_FONT_BASE`, `_FONT_BOLD`, `_FONT_ITALIC`; bold/italic in `_apply_style` and `baseline_offset_px` |
| `pdf_signer/main_window.py`   | `_TEXT_FONT_ITEMS` (12 variants); toolbar dropdown; `/QESFontName` on reload |
| `pdf_signer/signer.py`        | `_burn_in_freetext` Phase 1 → `TextWriter` with rotation-aware coordinate transform; `SaveFieldsWorker` writes `/QESFontName` |
