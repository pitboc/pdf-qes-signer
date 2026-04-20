"""Create minimal test PDFs with 2 radio buttons in different states.

Each PDF has one radio group "choice" with two options: "Opt1" and "Opt2".
We create TWO sets of variants:

Set A – "broken" (mirrors current pdf-signer behaviour):
  /AS  set correctly per widget
  /V   left as fitz default → (Yes) string, wrong

  radio_a_none.pdf  – /AS /Off  on both,  /V (Yes) on both
  radio_a_opt1.pdf  – /AS /Opt1 on w1,    /V (Yes) on both
  radio_a_opt2.pdf  – /AS /Opt2 on w2,    /V (Yes) on both

Set B – "corrected" (hypothesis: /V must match /AS):
  /AS  set correctly per widget
  /V   set to selected option name on ALL widgets of the group (PDF name, not string)

  radio_b_none.pdf  – /AS /Off  on both,  /V /Off  on both
  radio_b_opt1.pdf  – /AS /Opt1 on w1,    /V /Opt1 on both
  radio_b_opt2.pdf  – /AS /Opt2 on w2,    /V /Opt2 on both

Expected: Set A = Chromium ok, Firefox wrong.
          Set B = both browsers show correct selection.
"""

import re
import fitz
import os

OUT_DIR = os.path.join(os.path.dirname(__file__))


def _dump_radio_fields(doc: fitz.Document, label: str) -> None:
    page = doc[0]
    radios = [w for w in page.widgets()
              if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON]

    print(f"\n{'='*60}")
    print(f"  {label}")
    print('='*60)

    parent_xref = _get_parent_xref(doc, radios[0].xref) if radios else None
    if parent_xref:
        print(f"\n  Parent field (xref {parent_xref}):")
        for line in doc.xref_object(parent_xref, compressed=False).splitlines():
            print(f"    {line}")
    else:
        print("  (no parent field – merged widget+field objects)")

    for w in radios:
        obj = doc.xref_object(w.xref, compressed=False)
        as_m = re.search(r'/AS\s+(\S+)', obj)
        v_m  = re.search(r'/V\s+(\S+)', obj)
        print(f"\n  xref={w.xref}  on_state={w.on_state()!r}"
              f"  /AS={as_m.group(1) if as_m else '?'}"
              f"  /V={v_m.group(1) if v_m else '?'}")


def _get_parent_xref(doc: fitz.Document, widget_xref: int) -> int | None:
    obj = doc.xref_object(widget_xref, compressed=False)
    m = re.search(r'/Parent\s+(\d+)\s+0\s+R', obj)
    return int(m.group(1)) if m else None


def _build_radio_pdf(selected: str, fix_v: bool) -> fitz.Document:
    """Build a PDF with 2 radio buttons.

    selected – 'Opt1', 'Opt2', or '' (none selected)
    fix_v    – if True, set /V correctly on every widget (set B);
               if False, leave fitz default /V (set A)
    """
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    options = ["Opt1", "Opt2"]
    v_variant = "B (fixed /V)" if fix_v else "A (broken /V)"

    page.insert_text((50, 80), "Radio Button Test", fontsize=14)
    page.insert_text((50, 110),
                     f"Variant {v_variant} – expected: {selected or '(none)'}",
                     fontsize=10)

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

    radio_xrefs = [
        w.xref for w in page.widgets()
        if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON
        and w.field_name == "choice"
    ]

    for xref, opt in zip(radio_xrefs, options):
        obj = doc.xref_object(xref, compressed=False)
        off_m = re.search(r'/Off\s+(\d+)\s+0\s+R', obj)
        yes_m = re.search(r'/Yes\s+(\d+)\s+0\s+R', obj)
        if off_m and yes_m:
            new_ap = (f"<< /N << /Off {off_m.group(1)} 0 R "
                      f"/{opt} {yes_m.group(1)} 0 R >> >>")
            doc.xref_set_key(xref, "AP", new_ap)

        # /AS: correct in both variants
        if opt == selected:
            doc.xref_set_key(xref, "AS", f"/{opt}")
        else:
            doc.xref_set_key(xref, "AS", "/Off")

        # /V: only fixed in variant B
        if fix_v:
            v_val = f"/{selected}" if selected else "/Off"
            doc.xref_set_key(xref, "V", v_val)
        # variant A: leave fitz default /V (Yes) → intentionally wrong

    return doc


def main() -> None:
    variants = [
        # (filename,          selected,  fix_v)
        ("radio_a_none.pdf",  "",       False),
        ("radio_a_opt1.pdf",  "Opt1",   False),
        ("radio_a_opt2.pdf",  "Opt2",   False),
        ("radio_b_none.pdf",  "",       True),
        ("radio_b_opt1.pdf",  "Opt1",   True),
        ("radio_b_opt2.pdf",  "Opt2",   True),
    ]

    for filename, selected, fix_v in variants:
        out_path = os.path.join(OUT_DIR, filename)
        doc = _build_radio_pdf(selected, fix_v)
        label = f"{filename}  selected={selected or 'none'}  fix_v={fix_v}"
        _dump_radio_fields(doc, label)
        doc.save(out_path)
        doc.close()
        print(f"  → Saved: {out_path}")

    print("\nDone.")
    print("\nExpected behaviour:")
    print("  Set A (radio_a_*): Chromium correct, Firefox wrong  (current bug)")
    print("  Set B (radio_b_*): Both browsers correct            (hypothesis)")


if __name__ == "__main__":
    main()
