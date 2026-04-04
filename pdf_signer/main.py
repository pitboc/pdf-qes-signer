# SPDX-License-Identifier: GPL-3.0-or-later
"""
Entry point for PDF QES Signer.

Run via:
    python -m pdf_signer [PDF_FILE]
or:
    ./start_signer.sh [PDF_FILE]
"""

from __future__ import annotations

import sys


def main() -> None:
    """Parse arguments, initialise Qt, and launch the main window."""
    import argparse

    parser = argparse.ArgumentParser(
        description="PDF QES Signer – visually place signature fields and "
                    "apply qualified electronic signatures via PKCS#11.")
    parser.add_argument(
        "pdf", nargs="?", default=None,
        help="PDF file to open on startup")
    parser.add_argument(
        "--debug", metavar="MODULE", default=None,
        help="Enable debug logging for a module. "
             "Use 'certchain' for certificate chain diagnostics.")
    args = parser.parse_args()

    if args.debug:
        import logging
        _debug_loggers = {
            "certchain": [
                "pdf_signer.validation_worker",
                "pdf_signer.validation_extractor",
                "pdf_signer.lotl_trust",
            ],
        }
        names = _debug_loggers.get(args.debug, [f"pdf_signer.{args.debug}"])
        _handler = logging.StreamHandler(sys.stderr)
        _handler.setFormatter(
            logging.Formatter("%(name)s %(levelname)s: %(message)s"))
        for _name in names:
            _lg = logging.getLogger(_name)
            _lg.setLevel(logging.DEBUG)
            _lg.addHandler(_handler)
        print(f"[debug] Logging aktiviert für: {', '.join(names)}",
              file=sys.stderr)

    # Check required dependencies before importing Qt modules
    _check_imports()

    from PyQt6.QtWidgets import QApplication
    from .config import AppConfig
    from .i18n import i18n
    from .main_window import PDFSignerApp

    app = QApplication(sys.argv)
    app.setApplicationName("PDF QES Signer")
    app.setOrganizationName("pdf-signer")
    try:
        app.setStyle("Fusion")
    except Exception:
        pass

    config   = AppConfig()
    i18n.lang = config.get("app", "language")

    window = PDFSignerApp(config, initial_pdf=args.pdf)
    window.show()
    sys.exit(app.exec())


def _check_imports() -> None:
    """Abort with a helpful message if a hard dependency is missing."""
    missing = []
    try:
        import fitz  # noqa: F401
    except ImportError:
        missing.append("pymupdf        → pip install pymupdf")
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        missing.append("Pillow         → pip install Pillow")
    try:
        from PyQt6.QtWidgets import QApplication  # noqa: F401
    except ImportError:
        missing.append("PyQt6          → pip install PyQt6")

    if missing:
        print("ERROR: Required packages not found:\n")
        for m in missing:
            print(f"  • {m}")
        print()
        sys.exit(1)


if __name__ == "__main__":
    main()
