"""Analyse the raw PDF structure of radio button fields in a given file.

Usage:
    python tests/analyze_radio_pdf.py <pdf-file> [<pdf-file> ...]

For each file the script prints:
  - AcroForm /Fields list
  - For every radio widget annotation: all relevant entries
  - For every parent field dict: all entries
  - The raw xref object text (uncompressed)

This lets us compare what Firefox and Chromium write when saving a radio
button selection and spot any structural differences from what pdf-signer
produces.
"""

import re
import sys
import fitz


# Keys we highlight in the one-line summary (others still appear in raw dump)
SUMMARY_KEYS = ("AS", "V", "Ff", "FT", "T", "Parent", "Kids", "AP")


def _parse_name_or_string(token: str) -> str:
    """Return a human-readable label for a PDF name (/Foo) or string ((Foo))."""
    token = token.strip()
    if token.startswith("/"):
        return token
    if token.startswith("("):
        return token
    return token


def _extract_key(obj_text: str, key: str) -> str:
    """Extract the first value for *key* from raw PDF object text."""
    # Try: /Key /Value  or  /Key (string)  or  /Key << … >>  or  /Key N G R
    m = re.search(rf'/{re.escape(key)}\s+(\S+)', obj_text)
    return m.group(1) if m else "—"


def _has_parent(obj_text: str) -> bool:
    return bool(re.search(r'/Parent\s+\d+\s+\d+\s+R', obj_text))


def _get_parent_xref(obj_text: str) -> int | None:
    m = re.search(r'/Parent\s+(\d+)\s+\d+\s+R', obj_text)
    return int(m.group(1)) if m else None


def _get_kids_xrefs(obj_text: str) -> list[int]:
    m = re.search(r'/Kids\s*\[([^\]]*)\]', obj_text)
    if not m:
        return []
    return [int(x) for x in re.findall(r'(\d+)\s+\d+\s+R', m.group(1))]


def _ff_flags(ff_val: str) -> str:
    """Decode /Ff bit flags for button fields.

    PDF spec uses 1-indexed bit positions; fitz uses 0-indexed:
      PDF bit 15 (1-idx) = 0-idx bit 14 = 16384 → Radio
      PDF bit 16 (1-idx) = 0-idx bit 15 = 32768 → PushButton
      PDF bit 26 (1-idx) = 0-idx bit 25 = 33554432 → RadiosInUnison

    Note: fitz.PDF_BTN_FIELD_IS_RADIO == 32768, which matches the
    PushButton position in the 1-indexed PDF spec.  Both conventions
    are shown so browser-saved files can be compared directly.
    """
    try:
        v = int(ff_val)
    except ValueError:
        return ff_val
    flags = []
    if v & 16384:   # bit 14 (0-idx) – Radio per PDF spec (1-idx bit 15)
        flags.append("Radio(spec)")
    if v & 32768:   # bit 15 (0-idx) – fitz PDF_BTN_FIELD_IS_RADIO / PushButton(spec)
        flags.append("Radio(fitz)/PushButton(spec)")
    if v & 33554432:  # bit 25 (0-idx) – RadiosInUnison
        flags.append("RadiosInUnison")
    return f"{v} ({', '.join(flags) or 'none'})"


def analyze(path: str) -> None:
    print(f"\n{'#'*70}")
    print(f"  FILE: {path}")
    print(f"{'#'*70}")

    doc = fitz.open(path)

    # ── AcroForm /Fields ──────────────────────────────────────────────────
    trailer = doc.pdf_trailer()
    root_m  = re.search(r'/Root\s+(\d+)\s+\d+\s+R', trailer)
    if root_m:
        catalog = doc.xref_object(int(root_m.group(1)), compressed=False)
        af_m = re.search(r'/AcroForm\s+(\d+)\s+\d+\s+R', catalog)
        if af_m:
            af_obj = doc.xref_object(int(af_m.group(1)), compressed=False)
            fields_m = re.search(r'/Fields\s*\[([^\]]*)\]', af_obj)
            print(f"\nAcroForm /Fields: {fields_m.group(1).strip() if fields_m else '(inline or missing)'}")
        else:
            # AcroForm might be inline in catalog
            af_inline = re.search(r'/AcroForm\s*<<', catalog)
            print(f"\nAcroForm: {'inline in catalog' if af_inline else 'not found'}")

    # ── Collect radio widgets per page ────────────────────────────────────
    seen_parent_xrefs: set[int] = set()

    for page_num in range(len(doc)):
        page = doc[page_num]
        radios = [w for w in page.widgets()
                  if w.field_type == fitz.PDF_WIDGET_TYPE_RADIOBUTTON]
        if not radios:
            continue

        print(f"\n{'─'*60}")
        print(f"  Page {page_num + 1}: {len(radios)} radio widget(s)")
        print(f"{'─'*60}")

        for w in radios:
            xref = w.xref
            obj  = doc.xref_object(xref, compressed=False)

            # One-line summary
            as_val  = _extract_key(obj, "AS")
            v_val   = _extract_key(obj, "V")
            ff_val  = _extract_key(obj, "Ff")
            t_val   = _extract_key(obj, "T")
            has_par = _has_parent(obj)

            print(f"\n  Widget xref={xref}  field_name={w.field_name!r}"
                  f"  on_state={w.on_state()!r}")
            print(f"    /T      = {t_val}")
            print(f"    /AS     = {as_val}")
            print(f"    /V      = {v_val}")
            print(f"    /Ff     = {_ff_flags(ff_val)}")
            print(f"    /Parent = {'yes → see below' if has_par else 'none (merged field+widget)'}")

            # AP/N keys
            ap_m = re.search(r'/AP\s*<<\s*/N\s*<<([^>]*)>>', obj)
            if ap_m:
                ap_keys = re.findall(r'/(\w+)', ap_m.group(1))
                print(f"    /AP/N keys = {ap_keys}")
            else:
                print(f"    /AP/N      = (not found or complex ref)")

            # Raw dump
            print(f"\n    --- raw xref {xref} ---")
            for line in obj.splitlines():
                print(f"    {line}")

            # Parent field (if any, printed once per unique parent xref)
            par_xref = _get_parent_xref(obj)
            if par_xref and par_xref not in seen_parent_xrefs:
                seen_parent_xrefs.add(par_xref)
                par_obj = doc.xref_object(par_xref, compressed=False)
                v_par   = _extract_key(par_obj, "V")
                ff_par  = _extract_key(par_obj, "Ff")
                kids    = _get_kids_xrefs(par_obj)
                print(f"\n  Parent field xref={par_xref}:")
                print(f"    /V    = {v_par}")
                print(f"    /Ff   = {_ff_flags(ff_par)}")
                print(f"    /Kids = {kids}")
                print(f"\n    --- raw xref {par_xref} ---")
                for line in par_obj.splitlines():
                    print(f"    {line}")

    doc.close()


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python tests/analyze_radio_pdf.py <file.pdf> [<file.pdf> ...]")
        sys.exit(1)
    for path in sys.argv[1:]:
        analyze(path)


if __name__ == "__main__":
    main()
