# SPDX-License-Identifier: GPL-3.0-or-later
"""
Application configuration for PDF QES Signer.

Provides:
  - PDF_STANDARD_FONTS     – list of (display name, PDF name, avg_width, Qt families)
  - CONFIG_SCHEMA_VERSION  – integer, bumped only when the config structure changes
  - AppConfig              – INI-based persistent configuration with profile support

## File layout

    ~/.config/pdf-signer/
        settings.ini          ← global settings (language, channel, active profile name)
        profiles/
            default.ini       ← default profile
            <name>.ini        ← additional profiles

## Schema versioning and migration

``settings.ini`` stores ``[meta] schema_version`` (an integer).  On startup
``AppConfig`` compares this value against ``CONFIG_SCHEMA_VERSION``:

- **Upgrade or same version:** ``_cleanup()`` removes unknown keys; ``_init_parser()``
  fills in missing keys with defaults.  No explicit migration step needed for
  simple key additions or removals.
- **Downgrade (stored > current):** A timestamped backup of ``settings.ini`` is
  written (``settings.ini.bak_YYYYMMDD_HHMMSS``), then cleanup proceeds normally.
  ``AppConfig.downgrade_detected`` is set to ``True`` so the caller can show a
  warning dialog.

More complex migrations (changed data structures, renamed keys) must be handled
by adding explicit code to ``_run_schema_migrations()`` before the cleanup step,
keyed on the stored version number.

## Release channels

``[update] channel`` selects the update channel:

- ``stable``  – only non-pre-release tags (``/releases/latest`` API)
- ``develop`` – latest tag including pre-releases (``/releases`` API)

## Migration from the old single-file format

If ``settings.ini`` does not exist but the legacy ``pdf_signer.ini`` is found,
the application migrates automatically on first start:

- Profile settings (pkcs11, paths, tsa, appearance) are copied to
  ``profiles/default.ini``.
- ``language`` is transferred to the new ``settings.ini``.
- The old file is renamed to ``pdf_signer.ini.migrated`` as a backup.

## Keeping the example file in sync

NOTE: Keep ``pdf_signer.ini.example`` in sync whenever sections or keys are
added, removed, or renamed in GLOBAL_DEFAULTS or PROFILE_DEFAULTS.
"""

from __future__ import annotations

import os
import sys
import shutil
import configparser
from datetime import datetime
from pathlib import Path

#: Increment this integer whenever the structure of GLOBAL_DEFAULTS or
#: PROFILE_DEFAULTS changes in a way that requires migration logic.
#: Pure additions or removals of keys do NOT require a bump – cleanup and
#: defaults handle those automatically.
CONFIG_SCHEMA_VERSION = 1

# PDF-14 standard fonts: (display name, PDF font name, avg_width, Qt family)
# Qt family priority lists per PDF Base-14 font group.
# MuPDF (fitz) uses the URW fonts (Nimbus …) internally, so listing them first
# gives the closest possible match between the Qt preview and the burned-in PDF.
# On Windows the URW fonts are absent; Arial / Times New Roman / Courier New
# serve as metrically compatible fallbacks.
_HELV_QT = ["Nimbus Sans",     "Arial",          "Liberation Sans"]
_TIRO_QT = ["Nimbus Roman",    "Times New Roman", "Liberation Serif"]
_COUR_QT = ["Nimbus Mono PS",  "Courier New",     "Courier Std",
             "Courier 10 Pitch", "Liberation Mono", "monospace"]

PDF_STANDARD_FONTS: list[tuple[str, str, float, list[str]]] = [
    ("Helvetica",         "Helvetica",          0.5,  _HELV_QT),
    ("Helvetica Bold",    "Helvetica-Bold",     0.5,  _HELV_QT),
    ("Helvetica Oblique", "Helvetica-Oblique",  0.5,  _HELV_QT),
    ("Times Roman",       "Times-Roman",        0.44, _TIRO_QT),
    ("Times Bold",        "Times-Bold",         0.44, _TIRO_QT),
    ("Times Italic",      "Times-Italic",       0.44, _TIRO_QT),
    ("Courier",           "Courier",            0.6,  _COUR_QT),
    ("Courier Bold",      "Courier-Bold",       0.6,  _COUR_QT),
    ("Courier Oblique",   "Courier-Oblique",    0.6,  _COUR_QT),
]

# Mapping from fitz widget.text_font short names (case-insensitive) to
# (Qt family candidates, bold, italic).  Covers all 14 Base-14 PDF fonts.
# Qt tries each family in order and uses the first one installed.
_PDF_DA_FONT_MAP: dict[str, tuple[list[str], bool, bool]] = {
    "helv": (_HELV_QT, False, False),
    "hebo": (_HELV_QT, True,  False),
    "heit": (_HELV_QT, False, True),
    "hebi": (_HELV_QT, True,  True),
    "tiro": (_TIRO_QT, False, False),
    "tibo": (_TIRO_QT, True,  False),
    "tiit": (_TIRO_QT, False, True),
    "tibi": (_TIRO_QT, True,  True),
    "cour": (_COUR_QT, False, False),
    "cobo": (_COUR_QT, True,  False),
    "coit": (_COUR_QT, False, True),
    "cobi": (_COUR_QT, True,  True),
    "symb": (["Symbol"],        False, False),
    "zadb": (["ZapfDingbats"],  False, False),
}


def make_form_field_qfont(font_name: str, pixel_size: int) -> "QFont":
    """Return a QFont for a PDF form field /DA font name at *pixel_size* px.

    *font_name* is the value of ``fitz.Widget.text_font`` (e.g. ``"Helv"``,
    ``"TiRo"``).  Unknown names fall back to the system default font.
    """
    from PyQt6.QtGui import QFont
    key = font_name.strip("/").lower()
    families, bold, italic = _PDF_DA_FONT_MAP.get(key, ([], False, False))
    f = QFont(families) if families else QFont()
    f.setBold(bold)
    f.setItalic(italic)
    f.setPixelSize(max(6, pixel_size))
    return f

if sys.platform == "win32":
    CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "pdf-signer"
else:
    CONFIG_DIR = Path.home() / ".config" / "pdf-signer"

_SETTINGS_FILE = CONFIG_DIR / "settings.ini"
_PROFILES_DIR  = CONFIG_DIR / "profiles"
_LEGACY_FILE   = CONFIG_DIR / "pdf_signer.ini"


class AppConfig:
    """Persistent INI-based application configuration with profile support.

    Global settings (language, active profile) are stored in ``settings.ini``.
    All other settings (pkcs11, paths, tsa, appearance) are stored in the
    active profile file under ``profiles/<name>.ini``.

    The public API (get/set/getbool/setbool/save) is identical to the old
    single-file implementation so callers need no changes.
    """

    # Global settings – stored in settings.ini, shared across all profiles
    GLOBAL_DEFAULTS: dict[str, dict[str, str]] = {
        "meta": {
            # Schema version written by this installation.  Used to detect
            # downgrades (stored > CONFIG_SCHEMA_VERSION).
            "schema_version": str(CONFIG_SCHEMA_VERSION),
        },
        "app": {
            "language":       "de",
            "active_profile": "default",
        },
        "validation": {
            # "always" – fetch OCSP/AIA from network when not embedded
            # "never"  – use only data already present in the PDF
            "auto_fetch_revocation": "always",
        },
        "update": {
            # "true"  – beim Start einmal im Hintergrund prüfen
            # "false" – nur manuell über Hilfe → Über prüfen
            "check_on_startup": "0",
            # Release channel: "stable" (non-pre-release only) or "develop"
            # (latest tag including pre-releases).
            "channel": "stable",
        },
        "cert_detail_window": {
            # Last-known geometry of the certificate chain detail window.
            # -1 means "not yet placed" → centre on first open.
            "x":      "-1",
            "y":      "-1",
            "width":  "520",
            "height": "420",
        },
    }

    # Profile settings – stored in profiles/<name>.ini
    PROFILE_DEFAULTS: dict[str, dict[str, str]] = {
        "pkcs11": {
            "signer_mode":   "pfx",
            "lib_path": ("P11TCOSSigGx64.dll"
                         if sys.platform == "win32"
                         else "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"),
            "key_id":        "",
            "cert_cn":       "",
            "pfx_path":      "",
        },
        "paths": {
            "last_open_dir": str(Path.home()),
            "last_lib_dir":  ("." if sys.platform == "win32" else "/usr/lib"),
            "last_img_dir":  str(Path.home()),
        },
        "tsa": {
            "enabled":              "0",
            "url":                  "http://tsa.baltstamp.lt",
            "embed_validation_info": "0",
        },
        "signing": {
            # docMDP: Document Modification Detection and Prevention
            # "none" – keine Einschränkung (kein certify-Flag)
            # "p2"   – Formularfelder + weitere Signaturen erlaubt (PAdES-empfohlen)
            # "p1"   – keine Änderungen nach der Signatur
            "docmdp": "p2",
            # chain_complete_via_aia: Root-CA-Zertifikat beim Signieren via AIA
            # nachladen und in der Signatur einbetten (empfohlen für PAdES-LT /
            # ETSI EN 319 132).  Das Zertifikat wird nach Nutzerbestätigung lokal
            # gecacht; spätere Signaturen betten es ohne Rückfrage ein.
            # "1" – aktiv (Standard), "0" – deaktiviert
            "chain_complete_via_aia": "1",
        },
        "appearance": {
            "image_path":    "",
            "layout":        "img_left",
            "show_location": "1",
            "location":      "",
            "show_reason":   "1",
            "reason":        "",
            "show_name":     "1",
            "name_mode":     "cert",
            "name_custom":   "",
            "show_date":     "1",
            "date_format":   "%Y-%m-%d %H:%M",
            "font_size":     "8",
            "font_family":   "Helvetica",
            "show_border":   "1",
            "img_ratio":     "40",
        },
    }

    def __init__(self) -> None:
        self._downgrade_detected:    bool            = False
        self._downgrade_backup_path: Path | None     = None
        self._global  = configparser.RawConfigParser()
        self._profile = configparser.RawConfigParser()
        self._init_parser(self._global,  self.GLOBAL_DEFAULTS)
        self._init_parser(self._profile, self.PROFILE_DEFAULTS)
        self._migrate_if_needed()
        self._load_settings()
        self._load_profile(self.active_profile)

    # ── Internal helpers ───────────────────────────────────────────────────

    @staticmethod
    def _init_parser(parser: configparser.RawConfigParser,
                     defaults: dict[str, dict[str, str]]) -> None:
        """Populate *parser* with *defaults* (does not overwrite existing values)."""
        for section, values in defaults.items():
            if not parser.has_section(section):
                parser.add_section(section)
            for k, v in values.items():
                if not parser.has_option(section, k):
                    parser.set(section, k, v)

    @staticmethod
    def _cleanup(parser: configparser.RawConfigParser,
                 defaults: dict[str, dict[str, str]]) -> None:
        """Remove sections and keys not present in *defaults*."""
        for section in parser.sections():
            if section not in defaults:
                parser.remove_section(section)
                continue
            for key in list(parser.options(section)):
                if key not in defaults[section]:
                    parser.remove_option(section, key)

    def _profile_file(self, name: str) -> Path:
        return _PROFILES_DIR / f"{name}.ini"

    def _check_schema_version(self) -> None:
        """Detect downgrades; backup settings.ini when one is found.

        Must be called after reading the settings file but before ``_cleanup()``,
        so the stored ``schema_version`` value is still present in the parser.
        """
        stored = self._global.getint("meta", "schema_version", fallback=0)
        if stored > CONFIG_SCHEMA_VERSION:
            self._downgrade_detected = True
            ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup = _SETTINGS_FILE.with_name(f"settings.ini.bak_{ts}")
            shutil.copy2(_SETTINGS_FILE, backup)
            self._downgrade_backup_path = backup
        # Always overwrite with the current schema version so that the on-disk
        # file reflects the version actually running.
        if not self._global.has_section("meta"):
            self._global.add_section("meta")
        self._global.set("meta", "schema_version", str(CONFIG_SCHEMA_VERSION))

    def _run_schema_migrations(self, stored_version: int) -> None:
        """Apply explicit key-level migrations for structural changes.

        This method is intentionally empty for schema version 1 – cleanup and
        defaults are sufficient.  Add ``if stored_version < N:`` blocks here
        when data structures change in future versions.
        """

    def _load_settings(self) -> None:
        if _SETTINGS_FILE.exists():
            self._global.read(_SETTINGS_FILE, encoding="utf-8-sig")
            stored = self._global.getint("meta", "schema_version", fallback=0)
            self._run_schema_migrations(stored)
            self._check_schema_version()
        self._cleanup(self._global, self.GLOBAL_DEFAULTS)

    def _load_profile(self, name: str) -> None:
        """Load *name*.ini into a fresh profile parser (resets to defaults first)."""
        self._profile = configparser.RawConfigParser()
        self._init_parser(self._profile, self.PROFILE_DEFAULTS)
        f = self._profile_file(name)
        if f.exists():
            self._profile.read(f, encoding="utf-8-sig")
        self._cleanup(self._profile, self.PROFILE_DEFAULTS)

    def _migrate_if_needed(self) -> None:
        """Migrate legacy pdf_signer.ini to the new profile-based layout."""
        if _SETTINGS_FILE.exists() or not _LEGACY_FILE.exists():
            return

        old = configparser.RawConfigParser()
        old.read(_LEGACY_FILE, encoding="utf-8-sig")

        # Build profile file from legacy profile sections
        prof = configparser.RawConfigParser()
        self._init_parser(prof, self.PROFILE_DEFAULTS)
        for section, keys in self.PROFILE_DEFAULTS.items():
            if old.has_section(section):
                for key in keys:
                    if old.has_option(section, key):
                        prof.set(section, key, old.get(section, key))

        _PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        with open(self._profile_file("default"), "w", encoding="utf-8") as f:
            prof.write(f)

        # Build settings file – transfer language if present
        glob = configparser.RawConfigParser()
        self._init_parser(glob, self.GLOBAL_DEFAULTS)
        if old.has_option("app", "language"):
            glob.set("app", "language", old.get("app", "language"))

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
            glob.write(f)

        # Keep legacy file as backup
        _LEGACY_FILE.rename(_LEGACY_FILE.with_suffix(".ini.migrated"))

    # ── Schema version / downgrade info ───────────────────────────────────

    @property
    def downgrade_detected(self) -> bool:
        """``True`` if the settings file was written by a newer app version."""
        return self._downgrade_detected

    @property
    def downgrade_backup_path(self) -> Path | None:
        """Path to the timestamped backup created on downgrade, or ``None``."""
        return self._downgrade_backup_path

    # ── Profile management ─────────────────────────────────────────────────

    @property
    def active_profile(self) -> str:
        """Name of the currently active profile."""
        return self._global.get("app", "active_profile", fallback="default")

    def list_profiles(self) -> list[str]:
        """Return sorted list of available profile names."""
        if not _PROFILES_DIR.exists():
            return ["default"]
        names = sorted(p.stem for p in _PROFILES_DIR.glob("*.ini"))
        return names if names else ["default"]

    def switch_profile(self, name: str) -> None:
        """Switch to *name* and reload profile settings from disk."""
        self._global.set("app", "active_profile", name)
        self._load_profile(name)

    def new_profile_from_current(self, name: str) -> None:
        """Create a new profile by copying current profile settings, then switch to it."""
        _PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        with open(self._profile_file(name), "w", encoding="utf-8") as f:
            self._profile.write(f)
        self._global.set("app", "active_profile", name)

    def rename_profile(self, old: str, new: str) -> None:
        """Rename profile file on disk; update active_profile if needed."""
        self._profile_file(old).rename(self._profile_file(new))
        if self.active_profile == old:
            self._global.set("app", "active_profile", new)

    def delete_profile(self, name: str) -> None:
        """Delete profile *name* from disk."""
        f = self._profile_file(name)
        if f.exists():
            f.unlink()

    def reset_profile(self, name: str) -> None:
        """Overwrite *name* with default values; reload if it is the active profile."""
        prof = configparser.RawConfigParser()
        self._init_parser(prof, self.PROFILE_DEFAULTS)
        _PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        with open(self._profile_file(name), "w", encoding="utf-8") as f:
            prof.write(f)
        if name == self.active_profile:
            self._load_profile(name)

    # ── Public config API (unchanged from single-file version) ─────────────

    def get(self, section: str, key: str) -> str:
        if section in self.GLOBAL_DEFAULTS:
            return self._global.get(
                section, key,
                fallback=self.GLOBAL_DEFAULTS.get(section, {}).get(key, ""))
        return self._profile.get(
            section, key,
            fallback=self.PROFILE_DEFAULTS.get(section, {}).get(key, ""))

    def set(self, section: str, key: str, value: str) -> None:
        if section in self.GLOBAL_DEFAULTS:
            if not self._global.has_section(section):
                self._global.add_section(section)
            self._global.set(section, key, value)
        else:
            if not self._profile.has_section(section):
                self._profile.add_section(section)
            self._profile.set(section, key, value)

    def getbool(self, section: str, key: str) -> bool:
        return self.get(section, key) == "1"

    def setbool(self, section: str, key: str, value: bool) -> None:
        self.set(section, key, "1" if value else "0")

    def save(self) -> None:
        """Persist global settings and active profile to disk."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
            self._global.write(f)
        _PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        with open(self._profile_file(self.active_profile), "w", encoding="utf-8") as f:
            self._profile.write(f)
