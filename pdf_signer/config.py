# SPDX-License-Identifier: GPL-3.0-or-later
"""
Application configuration for PDF QES Signer.

Provides:
  - PDF_STANDARD_FONTS  – list of (display name, PDF name, avg_width, Qt family)
  - AppConfig           – INI-based persistent configuration
"""

from __future__ import annotations

import configparser
from pathlib import Path

# PDF-14 standard fonts: (display name, PDF font name, avg_width, Qt family)
PDF_STANDARD_FONTS: list[tuple[str, str, float, str]] = [
    ("Helvetica",         "Helvetica",         0.5,  "Helvetica"),
    ("Helvetica Bold",    "Helvetica-Bold",     0.5,  "Helvetica"),
    ("Helvetica Oblique", "Helvetica-Oblique",  0.5,  "Helvetica"),
    ("Times Roman",       "Times-Roman",        0.44, "Times New Roman"),
    ("Times Bold",        "Times-Bold",         0.44, "Times New Roman"),
    ("Times Italic",      "Times-Italic",       0.44, "Times New Roman"),
    ("Courier",           "Courier",            0.6,  "Courier New"),
    ("Courier Bold",      "Courier-Bold",       0.6,  "Courier New"),
    ("Courier Oblique",   "Courier-Oblique",    0.6,  "Courier New"),
]

CONFIG_DIR  = Path.home() / ".config" / "pdf-signer"
CONFIG_FILE = CONFIG_DIR / "pdf_signer.ini"


class AppConfig:
    """Persistent INI-based application configuration."""

    DEFAULTS: dict[str, dict[str, str]] = {
        "pkcs11": {
            "lib_path":  "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
            "key_label": "",
        },
        "paths": {
            "last_open_dir": str(Path.home()),
            "last_save_dir": str(Path.home()),
            "last_lib_dir":  "/usr/lib",
            "last_img_dir":  str(Path.home()),
        },
        "app": {
            "language": "de",
        },
        "appearance": {
            "image_path":    "",
            "layout":        "img_left",  # img_left | img_right
            "show_location": "1",
            "location":      "",
            "show_reason":   "1",
            "reason":        "",
            "show_name":     "1",
            "name_mode":     "cert",      # cert | custom
            "name_custom":   "",
            "show_date":     "1",
            "date_format":   "%d.%m.%Y %H:%M",
            "font_size":     "8",
            "font_family":   "Helvetica", # PDF font name
            "show_border":   "1",
            "img_ratio":     "40",
        },
    }

    def __init__(self) -> None:
        self._cfg = configparser.RawConfigParser()
        for section, values in self.DEFAULTS.items():
            if not self._cfg.has_section(section):
                self._cfg.add_section(section)
            for k, v in values.items():
                self._cfg.set(section, k, v)
        self.load()

    def load(self) -> None:
        """Load configuration from disk (if file exists)."""
        if CONFIG_FILE.exists():
            self._cfg.read(CONFIG_FILE, encoding="utf-8")

    def save(self) -> None:
        """Persist the current configuration to disk."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            self._cfg.write(f)

    def get(self, section: str, key: str) -> str:
        return self._cfg.get(
            section, key,
            fallback=self.DEFAULTS.get(section, {}).get(key, ""))

    def set(self, section: str, key: str, value: str) -> None:
        if not self._cfg.has_section(section):
            self._cfg.add_section(section)
        self._cfg.set(section, key, value)

    def getbool(self, section: str, key: str) -> bool:
        return self.get(section, key) == "1"

    def setbool(self, section: str, key: str, value: bool) -> None:
        self.set(section, key, "1" if value else "0")
