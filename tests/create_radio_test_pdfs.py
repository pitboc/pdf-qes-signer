"""Create minimal test PDFs with radio buttons in proper parent/kids structure.

Generates three variants of a two-option radio group ("Opt1" / "Opt2"):

  radio_none.pdf  – no option selected
  radio_opt1.pdf  – Opt1 selected
  radio_opt2.pdf  – Opt2 selected

All files use the standard parent/kids hierarchy required by Adobe Acrobat
Reader (and compatible with Firefox, Chromium, and other viewers).

Usage (from project root, with venv active):
    python tests/create_radio_test_pdfs.py
"""

import os
import re

import fitz

OUT_DIR = os.path.dirname(__file__)


def _build_radio_pdf(selected: str) -> fitz.Document:
    """Build a PDF with 2 radio buttons in parent/kids structure.

    *selected* – ``"Opt1"``, ``"Opt2"``, or ``""`` (nothing selected).
    """
    doc  = fitz.open()
    page = doc.new_page(width=595, height=842)
    options = ["Opt1", "Opt2"]

    page.insert_text((50, 80),  "Radio Button Test", fontsize=14)
    page.insert_text((50, 110), f"Selected: {selected or '(none)'}", fontsize=10)

    y_positions = [150, 190]
    for opt, y in zip(options, y_positions):
        page.insert_text((90, y + 14), opt, fontsize=10)
        w = fitz.Widget()
        w.field_type     = fitz.PDF_WIDGET_TYPE_RADIOBUTTON
        w.field_name     = "choice"
        w.button_caption = opt
        w.field_value    = "Off"
        w.rect           = fitz.Rect(50, y, 80, y + 20)
        page.add_widget(w)

    xrefs = [w.xref for w in page.widgets()
             if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON]

    # Patch /AP/N: replace fitz's generic /Yes key with option-specific names
    for xref, opt in zip(xrefs, options):
        obj   = doc.xref_object(xref, compressed=False)
        off_m = re.search(r'/Off\s+(\d+)\s+0\s+R', obj)
        yes_m = re.search(r'/Yes\s+(\d+)\s+0\s+R', obj)
        if off_m and yes_m:
            doc.xref_set_key(xref, "AP",
                             f"<< /N << /Off {off_m.group(1)} 0 R "
                             f"/{opt} {yes_m.group(1)} 0 R >> >>")
        doc.xref_set_key(xref, "AS", f"/{opt}" if opt == selected else "/Off")

    # Convert to parent/kids structure (Acrobat-compatible)
    current_v   = f"/{selected}" if selected else "/Off"
    kids_str    = " ".join(f"{x} 0 R" for x in xrefs)
    parent_xref = doc.get_new_xref()
    doc.update_object(parent_xref, (
        f"<< /FT /Btn /Ff 49152 /T (choice) /V {current_v} "
        f"/DV {current_v} /Kids [ {kids_str} ] >>"
    ))

    # Rebuild each widget: annotation-level keys only, no /Ff /DA /BS + /Parent
    _KEEP = {"Type", "Subtype", "Rect", "F", "AP", "AS", "FT", "MK", "H"}
    for xref in xrefs:
        lines = ["<<"]
        for key in doc.xref_get_keys(xref):
            if key not in _KEEP:
                continue
            ktype, kval = doc.xref_get_key(xref, key)
            if ktype not in ("null",) and kval not in ("null",):
                lines.append(f"  /{key} {kval}")
        lines.append(f"  /Parent {parent_xref} 0 R")
        lines.append(">>")
        doc.update_object(xref, "\n".join(lines))

    # Update AcroForm /Fields to list only the parent xref
    root_xref   = int(re.search(r'/Root\s+(\d+)\s+\d+\s+R',
                                doc.pdf_trailer()).group(1))
    af_type, af_val = doc.xref_get_key(root_xref, "AcroForm")
    if af_type == "dict":
        af_xref = doc.get_new_xref()
        doc.update_object(af_xref, af_val)
        doc.xref_set_key(root_xref, "AcroForm", f"{af_xref} 0 R")
    else:
        af_xref = int(re.search(r'(\d+)\s+0\s+R', af_val).group(1))
    doc.xref_set_key(af_xref, "Fields", f"[ {parent_xref} 0 R ]")

    return doc


def main() -> None:
    variants = [
        ("radio_none.pdf", ""),
        ("radio_opt1.pdf", "Opt1"),
        ("radio_opt2.pdf", "Opt2"),
    ]

    for filename, selected in variants:
        out_path = os.path.join(OUT_DIR, filename)
        doc = _build_radio_pdf(selected)
        doc.save(out_path)
        doc.close()
        print(f"  → {out_path}  (selected={selected or 'none'})")

    print("\nDone. All files use parent/kids structure compatible with Acrobat Reader.")


if __name__ == "__main__":
    main()
