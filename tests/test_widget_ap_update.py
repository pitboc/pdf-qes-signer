"""Test whether fitz regenerates the Appearance Stream (/AP) after update_widget().

Run with: python tests/test_widget_ap_update.py
Produces test_ap_before.png and test_ap_after.png for visual comparison.
"""

import fitz


PDF = "tests/test_form.pdf"
OUT_BEFORE = "tests/test_ap_before.png"
OUT_AFTER = "tests/test_ap_after.png"
OUT_SAVED = "tests/test_ap_saved.pdf"


def has_ap(widget: fitz.Widget) -> bool:
    """Check whether the widget's xref has an /AP entry in the PDF xref table."""
    doc = widget.parent.parent  # page → doc
    xref = widget.xref
    if xref <= 0:
        return False
    keys = doc.xref_get_keys(xref)
    return "AP" in keys


def render_page(doc: fitz.Document, path: str) -> None:
    page = doc[0]
    pix = page.get_pixmap(dpi=150)
    pix.save(path)
    print(f"  Rendered → {path}")


def main() -> None:
    doc = fitz.open(PDF)
    page = doc[0]

    print("=== Before edits ===")
    render_page(doc, OUT_BEFORE)

    for w in page.widgets():
        print(f"  {w.field_type_string:12} {w.field_name:20} /AP present: {has_ap(w)}")

    print("\n=== Applying edits ===")
    for w in page.widgets():
        ft = w.field_type

        if ft == fitz.PDF_WIDGET_TYPE_TEXT:
            w.field_value = "Hello World"
            w.update()
            print(f"  Text      {w.field_name}: set to 'Hello World', /AP now: {has_ap(w)}")

        elif ft == fitz.PDF_WIDGET_TYPE_CHECKBOX:
            w.field_value = "Yes"
            w.update()
            print(f"  Checkbox  {w.field_name}: set to 'Yes',         /AP now: {has_ap(w)}")

        elif ft == fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
            # Only set the first one
            if w.field_name == "priority" and w.button_caption == "High":
                w.field_value = "Yes"
                w.update()
                print(f"  Radio     {w.field_name}/{w.button_caption}: set to 'Yes', /AP now: {has_ap(w)}")

        elif ft == fitz.PDF_WIDGET_TYPE_COMBOBOX:
            w.field_value = "Austria"
            w.update()
            print(f"  ComboBox  {w.field_name}: set to 'Austria',     /AP now: {has_ap(w)}")

    print("\n=== After edits (in-memory render) ===")
    render_page(doc, OUT_AFTER)

    # Save and reload to check persistence
    doc.save(OUT_SAVED)
    doc2 = fitz.open(OUT_SAVED)
    print("\n=== After save+reload ===")
    for w in doc2[0].widgets():
        print(f"  {w.field_type_string:12} {w.field_name:20} value={w.field_value!r:15} /AP: {has_ap(w)}")

    doc.close()
    doc2.close()
    print("\nDone. Compare test_ap_before.png and test_ap_after.png visually.")


if __name__ == "__main__":
    main()
