"""Tests for radio button PDF structure and selection logic.

Verifies that:
- Radio button groups are stored in proper parent/kids structure
  (Acrobat-compatible), not fitz's default merged structure.
- The structure matches LibreOffice output: parent has /FT /Ff /T /V /DV /Kids
  (no /DA); widgets have no /Ff, /DA, or /BS.
- After selecting a button, /AS is correct on each widget and /V is
  set on the parent field dict (not on individual widgets).
- No fitz artefact string "(Yes)" remains anywhere in the group.
- _normalize_radio_groups leaves already-correct PDFs (LibreOffice) unchanged.

Run with: pytest tests/test_radio_button_save.py
"""

import io
import re

import fitz
import pytest


# ── PDF building ──────────────────────────────────────────────────────────────

def _build_radio_pdf(options: list[str], initial: str = "") -> fitz.Document:
    """Return an in-memory fitz.Document with a radio group in parent/kids structure.

    *options* – list of export-value names, e.g. ``["Opt1", "Opt2"]``.
    *initial* – which option is pre-selected; ``""`` means nothing selected.
    """
    doc  = fitz.open()
    page = doc.new_page(width=595, height=842)

    for i, opt in enumerate(options):
        w = fitz.Widget()
        w.field_type     = fitz.PDF_WIDGET_TYPE_RADIOBUTTON
        w.field_name     = "choice"
        w.button_caption = opt
        w.field_value    = "Off"
        w.rect           = fitz.Rect(50, 100 + i * 30, 70, 118 + i * 30)
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
        doc.xref_set_key(xref, "AS", f"/{opt}" if opt == initial else "/Off")

    # Convert to parent/kids structure – LibreOffice style (no /DA, has /DV)
    current_v   = f"/{initial}" if initial else "/Off"
    kids_str    = " ".join(f"{x} 0 R" for x in xrefs)
    parent_xref = doc.get_new_xref()
    doc.update_object(parent_xref, (
        f"<< /FT /Btn /Ff 49152 /T (choice) /V {current_v} "
        f"/DV {current_v} /Kids [ {kids_str} ] >>"
    ))

    # Rebuild each widget: keep annotation keys only (no /Ff, /DA, /BS), add /Parent
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


# ── Selection logic (mirrors _apply_form_field_edit for radio buttons) ────────

def _select_radio(doc: fitz.Document, target_xref: int) -> None:
    """Apply the radio selection logic from main_window._apply_form_field_edit."""
    radio_on_state    = ""
    sibling_xrefs: list[int] = []

    for w in doc[0].widgets():
        if w.field_type != fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
            continue
        if w.xref == target_xref:
            radio_on_state = w.on_state()
            w.field_value  = radio_on_state
            w.update()
        else:
            sibling_xrefs.append(w.xref)

    # Fix sibling /AS (fitz bug: widget.update() sets /AS on all siblings too)
    for xref in sibling_xrefs:
        doc.xref_set_key(xref, "AS", "/Off")

    # Set /V on parent only (parent/kids structure)
    if radio_on_state:
        target_obj = doc.xref_object(target_xref, compressed=False)
        parent_m   = re.search(r'/Parent\s+(\d+)\s+0\s+R', target_obj)
        if parent_m:
            doc.xref_set_key(int(parent_m.group(1)), "V", f"/{radio_on_state}")


# ── State helpers ─────────────────────────────────────────────────────────────

def _get_radio_state(doc: fitz.Document) -> dict[int, dict]:
    """Return ``{xref: {on_state, AS, widget_V, parent_V}}`` for all radio widgets."""
    result: dict[int, dict] = {}
    for w in doc[0].widgets():
        if w.field_type != fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
            continue
        obj    = doc.xref_object(w.xref, compressed=False)
        as_m   = re.search(r'/AS\s+(/\S+)', obj)
        v_m    = re.search(r'/V\s+(/\S+)', obj)
        par_m  = re.search(r'/Parent\s+(\d+)\s+0\s+R', obj)
        par_v  = None
        if par_m:
            par_obj = doc.xref_object(int(par_m.group(1)), compressed=False)
            pv_m    = re.search(r'/V\s+(/\S+)', par_obj)
            par_v   = pv_m.group(1) if pv_m else None
        result[w.xref] = {
            "on_state": w.on_state(),
            "AS":       as_m.group(1) if as_m  else None,
            "widget_V": v_m.group(1)  if v_m   else None,
            "parent_V": par_v,
        }
    return result


def _no_yes_string(doc: fitz.Document) -> bool:
    """Return True if no widget in the group contains the fitz artefact /V (Yes)."""
    for w in doc[0].widgets():
        if w.field_type != fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
            continue
        obj = doc.xref_object(w.xref, compressed=False)
        if re.search(r'/V\s*\(Yes\)', obj):
            return False
    return True


def _save_reload(doc: fitz.Document) -> fitz.Document:
    buf = io.BytesIO(doc.tobytes(garbage=0, deflate=False))
    return fitz.open(stream=buf, filetype="pdf")


def _has_parent_kids(doc: fitz.Document) -> bool:
    """Return True if all radio widgets have a /Parent reference."""
    for w in doc[0].widgets():
        if w.field_type != fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
            continue
        obj = doc.xref_object(w.xref, compressed=False)
        if not re.search(r'/Parent\s+\d+', obj):
            return False
    return True


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_build_produces_parent_kids_structure():
    """_build_radio_pdf must produce parent/kids, not fitz's merged structure."""
    doc = _build_radio_pdf(["Opt1", "Opt2"])
    assert _has_parent_kids(doc), "widgets must have /Parent reference"

    # Parent must be in AcroForm /Fields, not individual widgets
    root_xref = int(re.search(r'/Root\s+(\d+)\s+\d+\s+R',
                              doc.pdf_trailer()).group(1))
    _, af_val = doc.xref_get_key(root_xref, "AcroForm")
    af_xref   = int(re.search(r'(\d+)\s+0\s+R', af_val).group(1))
    af_obj    = doc.xref_object(af_xref, compressed=False)
    fields_m  = re.search(r'/Fields\s*\[([^\]]*)\]', af_obj)
    assert fields_m, "/Fields not found in AcroForm"
    field_xrefs = [int(x) for x in re.findall(r'(\d+)\s+\d+\s+R', fields_m.group(1))]
    widget_xrefs = [w.xref for w in doc[0].widgets()
                    if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON]
    # None of the individual widget xrefs should appear in /Fields
    assert not any(x in field_xrefs for x in widget_xrefs), \
        "individual widgets must not be in AcroForm /Fields"
    doc.close()


def test_parent_ff_has_both_radio_bits():
    """/Ff on the parent must have both Radio flag conventions set (49152)."""
    doc = _build_radio_pdf(["Opt1", "Opt2"])
    w   = next(w for w in doc[0].widgets()
               if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON)
    par_m = re.search(r'/Parent\s+(\d+)\s+0\s+R',
                      doc.xref_object(w.xref, compressed=False))
    assert par_m
    par_obj = doc.xref_object(int(par_m.group(1)), compressed=False)
    ff_m    = re.search(r'/Ff\s+(\d+)', par_obj)
    assert ff_m
    ff = int(ff_m.group(1))
    assert ff & 32768, "/Ff must have bit 32768 (fitz Radio)"
    assert ff & 16384, "/Ff must have bit 16384 (ISO 32000 Radio)"
    doc.close()


def test_select_opt2_from_opt1():
    doc = _build_radio_pdf(["Opt1", "Opt2"], initial="Opt1")
    xrefs = {w.on_state(): w.xref for w in doc[0].widgets()
             if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON}
    _select_radio(doc, xrefs["Opt2"])

    state = _get_radio_state(doc)
    opt1  = next(s for s in state.values() if s["on_state"] == "Opt1")
    opt2  = next(s for s in state.values() if s["on_state"] == "Opt2")

    assert opt1["AS"]       == "/Off",  f"Opt1 /AS: {opt1['AS']}"
    assert opt2["AS"]       == "/Opt2", f"Opt2 /AS: {opt2['AS']}"
    assert opt1["parent_V"] == "/Opt2", f"parent /V: {opt1['parent_V']}"
    assert _no_yes_string(doc), "fitz (Yes) artefact must not be present"

    doc2  = _save_reload(doc)
    state2 = _get_radio_state(doc2)
    opt1r  = next(s for s in state2.values() if s["on_state"] == "Opt1")
    opt2r  = next(s for s in state2.values() if s["on_state"] == "Opt2")
    assert opt1r["AS"]       == "/Off",  f"(reload) Opt1 /AS: {opt1r['AS']}"
    assert opt2r["AS"]       == "/Opt2", f"(reload) Opt2 /AS: {opt2r['AS']}"
    assert opt1r["parent_V"] == "/Opt2", f"(reload) parent /V: {opt1r['parent_V']}"
    doc.close(); doc2.close()


def test_select_opt1_from_opt2():
    doc = _build_radio_pdf(["Opt1", "Opt2"], initial="Opt2")
    xrefs = {w.on_state(): w.xref for w in doc[0].widgets()
             if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON}
    _select_radio(doc, xrefs["Opt1"])

    state = _get_radio_state(doc)
    opt1  = next(s for s in state.values() if s["on_state"] == "Opt1")
    opt2  = next(s for s in state.values() if s["on_state"] == "Opt2")

    assert opt1["AS"]       == "/Opt1", f"Opt1 /AS: {opt1['AS']}"
    assert opt2["AS"]       == "/Off",  f"Opt2 /AS: {opt2['AS']}"
    assert opt1["parent_V"] == "/Opt1", f"parent /V: {opt1['parent_V']}"
    assert _no_yes_string(doc)
    doc.close()


def test_three_options():
    options = ["Low", "Medium", "High"]
    doc = _build_radio_pdf(options, initial="Low")
    xrefs = {w.on_state(): w.xref for w in doc[0].widgets()
             if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON}
    _select_radio(doc, xrefs["Medium"])

    state = _get_radio_state(doc)
    for opt in options:
        s = next(v for v in state.values() if v["on_state"] == opt)
        expected_as = f"/{opt}" if opt == "Medium" else "/Off"
        assert s["AS"]       == expected_as, f"{opt} /AS: {s['AS']}"
        assert s["parent_V"] == "/Medium",   f"{opt} parent /V: {s['parent_V']}"
    assert _no_yes_string(doc)
    doc.close()


def test_no_yes_string_after_selection():
    """fitz's default /V (Yes) string must never appear after selection."""
    doc = _build_radio_pdf(["Opt1", "Opt2"], initial="")
    xrefs = {w.on_state(): w.xref for w in doc[0].widgets()
             if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON}
    _select_radio(doc, xrefs["Opt1"])
    assert _no_yes_string(doc), "fitz (Yes) artefact found after selection"
    doc.close()


def test_parent_v_set_correctly_on_selection():
    """/V on parent must equal the selected option after selection."""
    doc = _build_radio_pdf(["A", "B", "C"], initial="")
    xrefs = {w.on_state(): w.xref for w in doc[0].widgets()
             if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON}
    _select_radio(doc, xrefs["C"])

    state = _get_radio_state(doc)
    for s in state.values():
        assert s["parent_V"] == "/C", f"parent /V should be /C, got {s['parent_V']}"
    doc.close()


def test_firefox_saved_roundtrip():
    """Firefox-saved PDF: /AS must be readable and one button selected."""
    import os
    path = os.path.join(os.path.dirname(__file__), "radio_ff_opt2.pdf")
    if not os.path.exists(path):
        pytest.skip("radio_ff_opt2.pdf not found")

    doc      = fitz.open(path)
    state    = _get_radio_state(doc)
    selected = [s for s in state.values() if s["AS"] != "/Off"]
    assert len(selected) == 1, f"expected 1 selected, got {len(selected)}"
    assert selected[0]["AS"] == "/Opt2", f"AS: {selected[0]['AS']}"
    doc.close()


def test_chromium_saved_roundtrip():
    """Chromium-saved PDF: exactly one button selected via /AS."""
    import os
    path = os.path.join(os.path.dirname(__file__), "radio_chromium_opt2.pdf")
    if not os.path.exists(path):
        pytest.skip("radio_chromium_opt2.pdf not found")

    doc      = fitz.open(path)
    state    = _get_radio_state(doc)
    selected = [s for s in state.values() if s["AS"] != "/Off"]
    assert len(selected) == 1, f"expected 1 selected, got {len(selected)}"
    assert selected[0]["AS"] == "/Opt2", f"AS: {selected[0]['AS']}"
    doc.close()


def test_interaktiver_radio_roundtrip():
    """Reference PDF (works in all viewers): structure must be parent/kids."""
    import os
    path = os.path.join(os.path.dirname(__file__), "interaktiver_radio_test.pdf")
    if not os.path.exists(path):
        pytest.skip("interaktiver_radio_test.pdf not found")

    doc = fitz.open(path)
    assert _has_parent_kids(doc), "reference PDF must have parent/kids structure"
    doc.close()


# ── LibreOffice-style structure tests ─────────────────────────────────────────

def _get_parent_xref(doc: fitz.Document) -> int:
    """Return the xref of the radio group parent field dict."""
    root_xref = int(re.search(r'/Root\s+(\d+)\s+\d+\s+R',
                              doc.pdf_trailer()).group(1))
    af_type, af_val = doc.xref_get_key(root_xref, "AcroForm")
    if af_type == "xref":
        af_xref = int(re.search(r'(\d+)\s+0\s+R', af_val).group(1))
    else:
        # inline dict: externalized during normalize
        af_xref = int(re.search(r'(\d+)\s+0\s+R', af_val).group(1))
    af_obj = doc.xref_object(af_xref, compressed=False)
    fields_m = re.search(r'/Fields\s*\[([^\]]*)\]', af_obj)
    assert fields_m, "/Fields not found"
    field_xrefs = [int(x) for x in re.findall(r'(\d+)\s+\d+\s+R', fields_m.group(1))]
    for fxref in field_xrefs:
        obj = doc.xref_object(fxref, compressed=False)
        if re.search(r'/Kids\s*\[', obj):
            return fxref
    raise AssertionError("no parent field dict found in /Fields")


def test_normalize_produces_libreoffice_style():
    """_normalize_radio_groups must produce a LibreOffice-compatible structure.

    Parent: /FT /Ff /T /V /DV /Kids – no /DA.
    Widgets: no /Ff, no /DA, no /BS.
    """
    import sys
    sys.path.insert(0, ".")
    from pdf_signer.main_window import _normalize_radio_groups

    # Build a raw fitz PDF (merged structure, not yet normalized)
    doc  = fitz.open()
    page = doc.new_page(width=595, height=842)
    for i, opt in enumerate(["Opt1", "Opt2"]):
        w = fitz.Widget()
        w.field_type     = fitz.PDF_WIDGET_TYPE_RADIOBUTTON
        w.field_name     = "choice"
        w.button_caption = opt
        w.field_value    = "Off"
        w.rect           = fitz.Rect(50, 100 + i * 40, 70, 118 + i * 40)
        page.add_widget(w)

    xrefs = [w.xref for w in page.widgets()
             if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON]
    for xref, opt in zip(xrefs, ["Opt1", "Opt2"]):
        obj = doc.xref_object(xref, compressed=False)
        off_m = re.search(r'/Off\s+(\d+)\s+0\s+R', obj)
        yes_m = re.search(r'/Yes\s+(\d+)\s+0\s+R', obj)
        if off_m and yes_m:
            doc.xref_set_key(xref, "AP",
                             f"<< /N << /Off {off_m.group(1)} 0 R "
                             f"/{opt} {yes_m.group(1)} 0 R >> >>")
        doc.xref_set_key(xref, "AS", "/Opt1" if opt == "Opt1" else "/Off")

    _normalize_radio_groups(doc)

    # Check parent
    par_xref = _get_parent_xref(doc)
    par_obj  = doc.xref_object(par_xref, compressed=False)
    assert re.search(r'/FT\s*/Btn',   par_obj), "parent missing /FT /Btn"
    assert re.search(r'/Ff\s+\d+',    par_obj), "parent missing /Ff"
    assert re.search(r'/T\s*\(',      par_obj), "parent missing /T"
    assert re.search(r'/V\s+/\S+',    par_obj), "parent missing /V"
    assert re.search(r'/DV\s+/\S+',   par_obj), "parent missing /DV"
    assert re.search(r'/Kids\s*\[',   par_obj), "parent missing /Kids"
    assert not re.search(r'/DA\s*\(', par_obj), "parent must not have /DA"

    # Check widgets
    for w in doc[0].widgets():
        if w.field_type != fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
            continue
        wobj = doc.xref_object(w.xref, compressed=False)
        assert not re.search(r'/Ff\s',    wobj), f"widget {w.xref} must not have /Ff"
        assert not re.search(r'/DA\s*\(', wobj), f"widget {w.xref} must not have /DA"
        assert not re.search(r'/BS\s*<<', wobj), f"widget {w.xref} must not have /BS"
        assert re.search(r'/Parent\s+\d+', wobj), f"widget {w.xref} missing /Parent"

    doc.close()


def test_normalize_leaves_libreoffice_pdf_unchanged():
    """_normalize_radio_groups must not touch a PDF that already has parent/kids.

    Specifically: widgets must not gain /Ff, /DA, or /BS after normalize.
    """
    import os, sys
    sys.path.insert(0, ".")
    from pdf_signer.main_window import _normalize_radio_groups

    path = os.path.join(os.path.dirname(__file__), "RadioButton-libreoffice.pdf")
    if not os.path.exists(path):
        pytest.skip("RadioButton-libreoffice.pdf not found")

    doc = fitz.open(path)

    # Snapshot widget objects before normalize
    before = {w.xref: doc.xref_object(w.xref, compressed=False)
              for w in doc[0].widgets()
              if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON}

    _normalize_radio_groups(doc)

    # Widgets must be byte-identical after normalize
    for xref, obj_before in before.items():
        obj_after = doc.xref_object(xref, compressed=False)
        assert obj_before == obj_after, (
            f"widget xref={xref} was modified by _normalize_radio_groups\n"
            f"before:\n{obj_before}\nafter:\n{obj_after}"
        )

    doc.close()
