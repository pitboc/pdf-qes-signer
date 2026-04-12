#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Compile locale .po files to .mo for PDF QES Signer.

Usage (from project root, with venv active):
    python tools/build_locales.py --compile-only

The .po files under pdf_signer/locale/<lang>/LC_MESSAGES/ are the source of
truth.  Edit them directly (e.g. with Poedit) and re-run with --compile-only
to regenerate the binary .mo files:
    python tools/build_locales.py --compile-only
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent
LOCALE_DIR = PROJECT_ROOT / "pdf_signer" / "locale"
DOMAIN = "pdf_signer"

# ---------------------------------------------------------------------------
# Language metadata
# ---------------------------------------------------------------------------
LANGUAGES: dict[str, dict] = {
    "de": {
        "name": "Deutsch",
        "plural": "nplurals=2; plural=(n != 1);",
        "translator": "Pit Muß <codeberg.org@muss.eu>",
        "revision": "2026-04-11",
    },
    "en": {
        "name": "English",
        "plural": "nplurals=2; plural=(n != 1);",
        "translator": "Pit Muß <codeberg.org@muss.eu>",
        "revision": "2026-04-11",
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _escape(s: str) -> str:
    """Escape a string for use in a .po file msgstr value."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_msgstr(value: str) -> str:
    """Format a translation value as a .po msgstr block.

    Trailing newlines are stripped because msgid is always a plain key
    (no trailing ``\\n``), so msgid and msgstr must agree on that.
    """
    escaped = _escape(value.rstrip("\n"))
    # Split on escaped newlines to produce multi-line .po entries
    parts = escaped.split("\\n")
    if len(parts) == 1:
        return f'msgstr "{escaped}"'
    lines = ['msgstr ""']
    for i, part in enumerate(parts):
        suffix = "\\n" if i < len(parts) - 1 else ""
        lines.append(f'"{part}{suffix}"')
    # Remove trailing empty string line if value ended with \n
    if lines[-1] == '""':
        lines.pop()
    return "\n".join(lines)


def make_po(lang: str, translations: dict[str, str]) -> str:
    """Generate the full content of a .po file."""
    meta = LANGUAGES.get(lang, {})
    plural = meta.get("plural", "nplurals=2; plural=(n != 1);")
    translator = meta.get("translator", "AI-generated – needs native review")
    revision = meta.get("revision", "2026-04-11")

    lines: list[str] = [
        f"# PDF QES Signer – {meta.get('name', lang)} translations",
        "# SPDX-License-Identifier: GPL-3.0-or-later",
        "#",
        f"# Translators: {translator}",
        "#",
        'msgid ""',
        'msgstr ""',
        f'"Project-Id-Version: pdf-qes-signer\\n"',
        f'"Report-Msgid-Bugs-To: https://codeberg.org/pitbo/pdf-qes-signer/issues\\n"',
        f'"PO-Revision-Date: {revision}\\n"',
        f'"Last-Translator: {translator}\\n"',
        f'"Language: {lang}\\n"',
        '"MIME-Version: 1.0\\n"',
        '"Content-Type: text/plain; charset=UTF-8\\n"',
        '"Content-Transfer-Encoding: 8bit\\n"',
        f'"Plural-Forms: {plural}\\n"',
        "",
    ]

    for key, value in translations.items():
        lines.append(f'msgid "{key}"')
        lines.append(_format_msgstr(value))
        lines.append("")

    return "\n".join(lines)


def write_po(lang: str, translations: dict[str, str]) -> Path:
    """Write the .po file for *lang* and return its path."""
    po_dir = LOCALE_DIR / lang / "LC_MESSAGES"
    po_dir.mkdir(parents=True, exist_ok=True)
    po_path = po_dir / f"{DOMAIN}.po"
    po_path.write_text(make_po(lang, translations), encoding="utf-8")
    print(f"  wrote {po_path.relative_to(PROJECT_ROOT)}")
    return po_path


def compile_po(po_path: Path) -> None:
    """Compile *po_path* to a .mo file using msgfmt."""
    mo_path = po_path.with_suffix(".mo")
    result = subprocess.run(
        ["msgfmt", "-o", str(mo_path), str(po_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  ERROR compiling {po_path.name}: {result.stderr}", file=sys.stderr)
    else:
        print(f"  compiled → {mo_path.relative_to(PROJECT_ROOT)}")


# ---------------------------------------------------------------------------
# Import existing Python translation dicts
# ---------------------------------------------------------------------------

def load_existing() -> dict[str, dict[str, str]]:
    """Import TRANSLATIONS from de.py and en.py."""
    sys.path.insert(0, str(PROJECT_ROOT))
    result: dict[str, dict[str, str]] = {}
    for lang in ("de", "en"):
        try:
            mod = __import__(f"pdf_signer.i18n.{lang}", fromlist=["TRANSLATIONS"])
            result[lang] = mod.TRANSLATIONS
            print(f"  loaded {lang}.py ({len(mod.TRANSLATIONS)} strings)")
        except ImportError as exc:
            print(f"  WARNING: could not import {lang}.py: {exc}", file=sys.stderr)
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compile-only",
        action="store_true",
        help="Skip .po generation; only (re-)compile existing .po files to .mo",
    )
    args = parser.parse_args()

    if args.compile_only:
        print("Compiling existing .po files…")
        for po_path in sorted(LOCALE_DIR.glob(f"*/LC_MESSAGES/{DOMAIN}.po")):
            compile_po(po_path)
        return

    print("Loading existing Python translation dicts…")
    existing = load_existing()

    print("\nGenerating .po files…")
    for lang, translations in existing.items():
        po_path = write_po(lang, translations)
        compile_po(po_path)

    print("\nDone.")
    print("\nNext step: add FR/ES/IT/NL/PL/PT .po files,")
    print("then run: python tools/build_locales.py --compile-only")


if __name__ == "__main__":
    main()
