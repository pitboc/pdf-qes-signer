"""Generate a test PDF with common form field types for development/testing."""

import re
import fitz  # PyMuPDF


def _fix_radio_group(doc: fitz.Document, xrefs: list[int],
                     options: list[str], selected: str = "") -> None:
    """Rename each radio button's on_state from the generic 'Yes' to a unique
    option name.

    fitz's add_widget() creates all radio buttons with on_state='Yes', which
    makes them indistinguishable within a group.  This function patches each
    widget's /AP/N dictionary and /AS entry so that:
      - button i has on_state = options[i]  (e.g. 'Low', 'Medium', 'High')
      - /AS is set to the option name for the pre-selected button, /Off for others
      - /V mirrors /AS

    Implementation: uses xref_set_key() with raw PDF syntax to rewrite /AP and
    /AS in each widget object after add_widget() has created the streams.
    """
    for xref, option in zip(xrefs, options):
        obj = doc.xref_object(xref, compressed=False)

        # Extract the xref numbers of the /Off and /Yes appearance streams
        off_m = re.search(r'/Off\s+(\d+)\s+0\s+R', obj)
        yes_m = re.search(r'/Yes\s+(\d+)\s+0\s+R', obj)
        if not off_m or not yes_m:
            continue
        off_xref = off_m.group(1)
        yes_xref = yes_m.group(1)

        # Rebuild /AP with the option name replacing 'Yes'
        new_ap = f"<< /N << /Off {off_xref} 0 R /{option} {yes_xref} 0 R >> >>"
        doc.xref_set_key(xref, "AP", new_ap)

        # /AS and /V: selected option is active, others are Off
        if option == selected:
            doc.xref_set_key(xref, "AS", f"/{option}")
            doc.xref_set_key(xref, "V",  f"/{option}")
        else:
            doc.xref_set_key(xref, "AS", "/Off")
            doc.xref_set_key(xref, "V",  "/Off")


def create_test_form(output_path: str = "test_form.pdf") -> None:
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # A4

    def label(text: str, x: float, y: float) -> None:
        page.insert_text((x, y), text, fontsize=10, color=(0, 0, 0))

    y = 60
    label("PDF Form Field Test", 180, y)

    # ── Text fields ──────────────────────────────────────────────────────────
    y = 110
    label("Text Fields", 50, y)

    label("First name:", 50, y + 22)
    widget = fitz.Widget()
    widget.field_type  = fitz.PDF_WIDGET_TYPE_TEXT
    widget.field_name  = "first_name"
    widget.field_value = ""
    widget.rect        = fitz.Rect(150, y + 10, 350, y + 30)
    page.add_widget(widget)

    label("Last name:", 50, y + 52)
    widget = fitz.Widget()
    widget.field_type  = fitz.PDF_WIDGET_TYPE_TEXT
    widget.field_name  = "last_name"
    widget.field_value = ""
    widget.rect        = fitz.Rect(150, y + 40, 350, y + 60)
    page.add_widget(widget)

    label("Multiline notes:", 50, y + 82)
    widget = fitz.Widget()
    widget.field_type  = fitz.PDF_WIDGET_TYPE_TEXT
    widget.field_name  = "notes"
    widget.field_value = ""
    widget.field_flags = fitz.PDF_TX_FIELD_IS_MULTILINE
    widget.rect        = fitz.Rect(150, y + 70, 500, y + 130)
    page.add_widget(widget)

    # ── Checkboxes ───────────────────────────────────────────────────────────
    y = 300
    label("Checkboxes", 50, y)

    for i, option in enumerate(["Accept terms", "Subscribe to newsletter",
                                 "Remember me"]):
        label(option, 80, y + 22 + i * 25)
        widget = fitz.Widget()
        widget.field_type  = fitz.PDF_WIDGET_TYPE_CHECKBOX
        widget.field_name  = f"checkbox_{i}"
        widget.field_value = "Off"
        widget.rect        = fitz.Rect(50, y + 10 + i * 25, 70, y + 28 + i * 25)
        page.add_widget(widget)

    # ── Radio buttons ────────────────────────────────────────────────────────
    y = 400
    label("Radio Buttons (Priority)", 50, y)

    radio_options = ["Low", "Medium", "High"]
    for i, opt in enumerate(radio_options):
        label(opt, 80, y + 22 + i * 25)
        widget = fitz.Widget()
        widget.field_type     = fitz.PDF_WIDGET_TYPE_RADIOBUTTON
        widget.field_name     = "priority"
        widget.button_caption = opt
        widget.field_value    = "Off"
        widget.rect           = fitz.Rect(50, y + 10 + i * 25, 70, y + 28 + i * 25)
        page.add_widget(widget)

    # Collect xrefs via page.widgets() – widget.xref is 0 directly after add_widget()
    radio_xrefs = [
        w.xref for w in page.widgets()
        if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON
        and w.field_name == "priority"
    ]

    # Patch radio group so each button has a unique on_state name; pre-select "Low"
    _fix_radio_group(doc, radio_xrefs, radio_options, selected="Low")

    # ── Dropdown (Combo box) ─────────────────────────────────────────────────
    y = 530
    label("Dropdown", 50, y)

    label("Country:", 50, y + 22)
    widget = fitz.Widget()
    widget.field_type    = fitz.PDF_WIDGET_TYPE_COMBOBOX
    widget.field_name    = "country"
    widget.field_value   = "Germany"
    widget.choice_values = ["Germany", "Austria", "Switzerland", "France", "Other"]
    widget.rect          = fitz.Rect(150, y + 10, 350, y + 30)
    page.add_widget(widget)

    # ── List box ─────────────────────────────────────────────────────────────
    y = 600
    label("List Box (multi-select)", 50, y)

    label("Skills:", 50, y + 22)
    widget = fitz.Widget()
    widget.field_type    = fitz.PDF_WIDGET_TYPE_LISTBOX
    widget.field_name    = "skills"
    widget.field_value   = ""
    widget.choice_values = ["Python", "JavaScript", "Java", "C++", "Rust", "Go"]
    widget.rect          = fitz.Rect(150, y + 10, 350, y + 100)
    page.add_widget(widget)

    doc.save(output_path)
    doc.close()
    print(f"Saved: {output_path}")


if __name__ == "__main__":
    import os
    out = os.path.join(os.path.dirname(__file__), "test_form.pdf")
    create_test_form(out)
