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

# Module-level handle kept open so faulthandler can write to it at any time.
_crash_log_fh = None


def _install_crash_handler() -> None:
    """Write unhandled exceptions and C-level faults to a persistent log file.

    Two mechanisms are combined:
    - ``faulthandler``: catches SIGSEGV / SIGABRT / SIGFPE (C-level crashes).
      The file handle must stay open for the entire process lifetime, hence the
      module-level ``_crash_log_fh``.
    - ``sys.excepthook``: catches unhandled Python exceptions that reach the
      top of the call stack (e.g. a Qt slot that raises and is not caught).
    """
    import datetime
    import faulthandler
    import traceback
    from pathlib import Path

    global _crash_log_fh

    log_dir = Path.home() / ".local" / "share" / "pdf-signer"
    log_dir.mkdir(parents=True, exist_ok=True)
    crash_log = log_dir / "crash.log"

    _crash_log_fh = open(crash_log, "a", encoding="utf-8")
    _crash_log_fh.write(
        f"\n{'=' * 60}\n"
        f"Session started: {datetime.datetime.now().isoformat()}\n"
    )
    _crash_log_fh.flush()

    faulthandler.enable(_crash_log_fh)

    _orig_hook = sys.excepthook

    def _excepthook(exc_type, exc_value, exc_tb):
        try:
            with open(crash_log, "a", encoding="utf-8") as f:
                f.write(
                    f"\n{'=' * 60}\n"
                    f"Unhandled exception: {datetime.datetime.now().isoformat()}\n"
                )
                traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
        except Exception:
            pass
        _orig_hook(exc_type, exc_value, exc_tb)

    sys.excepthook = _excepthook
    print(f"[crash handler] Log: {crash_log}", file=sys.stderr)


def main() -> None:
    """Parse arguments, initialise Qt, and launch the main window."""
    _install_crash_handler()

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

    from pathlib import Path
    from PyQt6.QtGui import QIcon, QPalette
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

    # Ensure placeholder text is visible regardless of system theme.
    # Qt's PlaceholderText role is not set by all themes (e.g. KDE Plasma);
    # fall back to the Disabled/Text colour which is always set correctly.
    _pal = app.palette()
    _pal.setColor(
        QPalette.ColorRole.PlaceholderText,
        _pal.color(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text),
    )
    app.setPalette(_pal)

    _icon_path = Path(__file__).parent / "icons" / "app.png"
    if _icon_path.exists():
        app.setWindowIcon(QIcon(str(_icon_path)))

    config   = AppConfig()
    i18n.lang = config.get("app", "language")

    # Load Qt's own translations (file dialogs, standard buttons, etc.)
    # so that native Qt widgets use the same language as the app.
    from PyQt6.QtCore import QTranslator, QLibraryInfo
    _qt_translator = QTranslator(app)
    _qt_lang = i18n.lang if i18n.lang else "de"
    _qt_translations_path = QLibraryInfo.path(
        QLibraryInfo.LibraryPath.TranslationsPath)
    if _qt_translator.load(f"qt_{_qt_lang}", _qt_translations_path):
        app.installTranslator(_qt_translator)

    window = PDFSignerApp(config, initial_pdf=args.pdf)
    # Expose the startup translator on the window so _set_language can remove it
    # on the first runtime language switch (otherwise the old translator stays installed).
    window._qt_translator = _qt_translator
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
