"""Smoke test: radio button /AS and /V consistency after selection.

Tests the fix in _update_form_field that sets /V as a PDF name on all
widgets of a radio group (fitz bug: leaves /V as the string "(Yes)").

Run with: python tests/test_radio_button_save.py
"""

import io
import re
import sys
import fitz


# ── PDF building (mirrors create_test_form._fix_radio_group) ─────────────────

def _build_radio_pdf(options: list[str], initial: str = "") -> fitz.Document:
    """Return an in-memory fitz.Document with one radio group."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    for opt in options:
        w = fitz.Widget()
        w.field_type     = fitz.PDF_WIDGET_TYPE_RADIOBUTTON
        w.field_name     = "choice"
        w.button_caption = opt
        w.field_value    = "Off"
        w.rect           = fitz.Rect(50, 100 + options.index(opt) * 30,
                                     70, 118 + options.index(opt) * 30)
        page.add_widget(w)

    xrefs = [w.xref for w in page.widgets()
              if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON]

    # Patch /AP/N so each button has its own name (same as _fix_radio_group)
    for xref, opt in zip(xrefs, options):
        obj = doc.xref_object(xref, compressed=False)
        off_m = re.search(r'/Off\s+(\d+)\s+0\s+R', obj)
        yes_m = re.search(r'/Yes\s+(\d+)\s+0\s+R', obj)
        if off_m and yes_m:
            doc.xref_set_key(xref, "AP",
                             f"<< /N << /Off {off_m.group(1)} 0 R "
                             f"/{opt} {yes_m.group(1)} 0 R >> >>")
        # initial /AS and /V
        if opt == initial:
            doc.xref_set_key(xref, "AS", f"/{opt}")
            doc.xref_set_key(xref, "V",  f"/{opt}")
        else:
            doc.xref_set_key(xref, "AS", "/Off")
            doc.xref_set_key(xref, "V",  f"/{initial}" if initial else "/Off")

    return doc


# ── Selection logic (mirrors _update_form_field for radio buttons) ───────────

def _select_radio(doc: fitz.Document, target_xref: int) -> None:
    """Apply the fixed radio selection logic from main_window._update_form_field."""
    page = doc[0]
    radio_sibling_xrefs: list[int] = []
    radio_on_state = ""

    for w in page.widgets():
        if w.field_type != fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
            continue
        if w.xref == target_xref:
            radio_on_state = w.on_state()
            w.field_value = radio_on_state
            w.update()
        else:
            radio_sibling_xrefs.append(w.xref)

    # Fix sibling /AS (fitz bug: sets all to on_state after update())
    for xref in radio_sibling_xrefs:
        doc.xref_set_key(xref, "AS", "/Off")

    # Fix /V on all widgets and parent (fitz leaves /V as string "(Yes)")
    if radio_on_state:
        v_val = f"/{radio_on_state}"
        doc.xref_set_key(target_xref, "V", v_val)
        for xref in radio_sibling_xrefs:
            doc.xref_set_key(xref, "V", v_val)
        _parent_m = re.search(
            r'/Parent\s+(\d+)\s+0\s+R',
            doc.xref_object(target_xref, compressed=False))
        if _parent_m:
            doc.xref_set_key(int(_parent_m.group(1)), "V", v_val)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_radio_state(doc: fitz.Document) -> dict[int, dict]:
    """Return {xref: {on_state, AS, V}} for all radio widgets."""
    result = {}
    for w in doc[0].widgets():
        if w.field_type != fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
            continue
        obj = doc.xref_object(w.xref, compressed=False)
        as_m = re.search(r'/AS\s+(/\S+)', obj)
        v_m  = re.search(r'/V\s+(/\S+)', obj)
        result[w.xref] = {
            "on_state": w.on_state(),
            "AS": as_m.group(1) if as_m else None,
            "V":  v_m.group(1)  if v_m  else None,
        }
    return result


def _save_reload(doc: fitz.Document) -> fitz.Document:
    """Serialise doc to bytes and reload – verifies persistence."""
    buf = io.BytesIO(doc.tobytes(garbage=0, deflate=False))
    return fitz.open(stream=buf, filetype="pdf")


# ── Test cases ───────────────────────────────────────────────────────────────

PASS = 0
FAIL = 0


def _check(label: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}" + (f"  ({detail})" if detail else ""))


def test_select_opt2_from_opt1() -> None:
    print("\n─── select Opt2 when Opt1 was pre-selected ───")
    options = ["Opt1", "Opt2"]
    doc = _build_radio_pdf(options, initial="Opt1")

    # Find Opt2 xref
    xrefs = {w.on_state(): w.xref
              for w in doc[0].widgets()
              if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON}
    _select_radio(doc, xrefs["Opt2"])

    state = _get_radio_state(doc)
    opt1 = next(s for s in state.values() if s["on_state"] == "Opt1")
    opt2 = next(s for s in state.values() if s["on_state"] == "Opt2")

    _check("Opt1 /AS = /Off",  opt1["AS"] == "/Off",  f"got {opt1['AS']}")
    _check("Opt2 /AS = /Opt2", opt2["AS"] == "/Opt2", f"got {opt2['AS']}")
    _check("Opt1 /V  = /Opt2", opt1["V"]  == "/Opt2", f"got {opt1['V']}")
    _check("Opt2 /V  = /Opt2", opt2["V"]  == "/Opt2", f"got {opt2['V']}")

    # Verify after save+reload
    doc2 = _save_reload(doc)
    state2 = _get_radio_state(doc2)
    opt1r = next(s for s in state2.values() if s["on_state"] == "Opt1")
    opt2r = next(s for s in state2.values() if s["on_state"] == "Opt2")
    _check("(reload) Opt1 /AS = /Off",  opt1r["AS"] == "/Off",  f"got {opt1r['AS']}")
    _check("(reload) Opt2 /AS = /Opt2", opt2r["AS"] == "/Opt2", f"got {opt2r['AS']}")
    _check("(reload) Opt1 /V  = /Opt2", opt1r["V"]  == "/Opt2", f"got {opt1r['V']}")
    _check("(reload) Opt2 /V  = /Opt2", opt2r["V"]  == "/Opt2", f"got {opt2r['V']}")
    doc.close(); doc2.close()


def test_select_opt1_from_opt2() -> None:
    print("\n─── select Opt1 when Opt2 was pre-selected ───")
    options = ["Opt1", "Opt2"]
    doc = _build_radio_pdf(options, initial="Opt2")

    xrefs = {w.on_state(): w.xref
              for w in doc[0].widgets()
              if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON}
    _select_radio(doc, xrefs["Opt1"])

    state = _get_radio_state(doc)
    opt1 = next(s for s in state.values() if s["on_state"] == "Opt1")
    opt2 = next(s for s in state.values() if s["on_state"] == "Opt2")

    _check("Opt1 /AS = /Opt1", opt1["AS"] == "/Opt1", f"got {opt1['AS']}")
    _check("Opt2 /AS = /Off",  opt2["AS"] == "/Off",  f"got {opt2['AS']}")
    _check("Opt1 /V  = /Opt1", opt1["V"]  == "/Opt1", f"got {opt1['V']}")
    _check("Opt2 /V  = /Opt1", opt2["V"]  == "/Opt1", f"got {opt2['V']}")
    doc.close()


def test_three_options() -> None:
    print("\n─── three-option group, select middle ───")
    options = ["Low", "Medium", "High"]
    doc = _build_radio_pdf(options, initial="Low")

    xrefs = {w.on_state(): w.xref
              for w in doc[0].widgets()
              if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON}
    _select_radio(doc, xrefs["Medium"])

    state = _get_radio_state(doc)
    for opt in options:
        s = next(v for v in state.values() if v["on_state"] == opt)
        expected_as = f"/{opt}" if opt == "Medium" else "/Off"
        _check(f"{opt} /AS = {expected_as}", s["AS"] == expected_as, f"got {s['AS']}")
        _check(f"{opt} /V  = /Medium",       s["V"]  == "/Medium",   f"got {s['V']}")
    doc.close()


def test_no_v_string_remains() -> None:
    """Ensure fitz's default (Yes) string is fully replaced by a PDF name."""
    print("\n─── /V must be a PDF name, never the string (Yes) ───")
    options = ["Opt1", "Opt2"]
    doc = _build_radio_pdf(options, initial="")  # start unselected

    xrefs = {w.on_state(): w.xref
              for w in doc[0].widgets()
              if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON}
    _select_radio(doc, xrefs["Opt1"])

    for w in doc[0].widgets():
        if w.field_type != fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
            continue
        obj = doc.xref_object(w.xref, compressed=False)
        has_yes_string = bool(re.search(r'/V\s*\(Yes\)', obj))
        _check(f"xref={w.xref} /V is not string (Yes)",
               not has_yes_string, "fitz default string not cleaned up")
        v_is_name = bool(re.search(r'/V\s*/', obj))
        _check(f"xref={w.xref} /V is a PDF name (/...)",
               v_is_name, f"raw: {re.search(r'/V\\s*(\\S+)', obj).group(1) if re.search(r'/V\\s*(\\S+)', obj) else 'missing'}")
    doc.close()


def test_firefox_saved_roundtrip() -> None:
    """Load Firefox-saved radio_ff_opt2.pdf and verify fitz reads /AS correctly."""
    print("\n─── Firefox-saved PDF: verify /AS readable by fitz ───")
    import os
    path = os.path.join(os.path.dirname(__file__), "radio_ff_opt2.pdf")
    if not os.path.exists(path):
        print("  SKIP  radio_ff_opt2.pdf not found")
        return

    doc = fitz.open(path)
    state = _get_radio_state(doc)
    selected = [s for s in state.values() if s["AS"] != "/Off"]
    unselected = [s for s in state.values() if s["AS"] == "/Off"]

    _check("exactly one button selected", len(selected) == 1,
           f"selected count = {len(selected)}")
    if selected:
        _check("selected button /AS matches /AP/N key",
               selected[0]["AS"] == "/Opt2", f"got {selected[0]['AS']}")
        _check("selected button /V  = /Opt2",
               selected[0]["V"] == "/Opt2", f"got {selected[0]['V']}")
    _check("unselected count = 1", len(unselected) == 1)
    doc.close()


def test_chromium_saved_roundtrip() -> None:
    """Load Chromium-saved radio_chromium_opt2.pdf and verify /AS readable."""
    print("\n─── Chromium-saved PDF: verify /AS readable by fitz ───")
    import os
    path = os.path.join(os.path.dirname(__file__), "radio_chromium_opt2.pdf")
    if not os.path.exists(path):
        print("  SKIP  radio_chromium_opt2.pdf not found")
        return

    doc = fitz.open(path)
    state = _get_radio_state(doc)
    selected = [s for s in state.values() if s["AS"] != "/Off"]
    _check("exactly one button selected via /AS",
           len(selected) == 1, f"count = {len(selected)}")
    if selected:
        _check("selected button /AS = /Opt2",
               selected[0]["AS"] == "/Opt2", f"got {selected[0]['AS']}")
    doc.close()


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    test_select_opt2_from_opt1()
    test_select_opt1_from_opt2()
    test_three_options()
    test_no_v_string_remains()
    test_firefox_saved_roundtrip()
    test_chromium_saved_roundtrip()

    print(f"\n{'='*40}")
    print(f"  {PASS} passed, {FAIL} failed")
    print('='*40)
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
