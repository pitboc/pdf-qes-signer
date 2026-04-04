# SPDX-License-Identifier: GPL-3.0-or-later
"""
Application configuration for PDF QES Signer.

Provides:
  - PDF_STANDARD_FONTS  – list of (display name, PDF name, avg_width, Qt family)
  - AppConfig           – INI-based persistent configuration with profile support

## File layout

    ~/.config/pdf-signer/
        settings.ini          ← global settings (language, active profile name)
        profiles/
            default.ini       ← default profile
            <name>.ini        ← additional profiles

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
import configparser
from pathlib import Path

# PDF-14 standard fonts: (display name, PDF font name, avg_width, Qt family)
PDF_STANDARD_FONTS: list[tuple[str, str, float, str]] = [
    ("Helvetica",         "Helvetica",          0.5,  "Helvetica"),
    ("Helvetica Bold",    "Helvetica-Bold",     0.5,  "Helvetica"),
    ("Helvetica Oblique", "Helvetica-Oblique",  0.5,  "Helvetica"),
    ("Times Roman",       "Times-Roman",        0.44, "Times New Roman"),
    ("Times Bold",        "Times-Bold",         0.44, "Times New Roman"),
    ("Times Italic",      "Times-Italic",       0.44, "Times New Roman"),
    ("Courier",           "Courier",            0.6,  "Courier New"),
    ("Courier Bold",      "Courier-Bold",       0.6,  "Courier New"),
    ("Courier Oblique",   "Courier-Oblique",    0.6,  "Courier New"),
]

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
        "app": {
            "language":       "de",
            "active_profile": "default",
        },
        "validation": {
            # "always" – fetch OCSP/AIA from network when not embedded
            # "never"  – use only data already present in the PDF
            "auto_fetch_revocation": "always",
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
            "docmdp": "none",
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
            "date_format":   "%d.%m.%Y %H:%M",
            "font_size":     "8",
            "font_family":   "Helvetica",
            "show_border":   "1",
            "img_ratio":     "40",
        },
    }

    def __init__(self) -> None:
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

    def _load_settings(self) -> None:
        if _SETTINGS_FILE.exists():
            self._global.read(_SETTINGS_FILE, encoding="utf-8")
        self._cleanup(self._global, self.GLOBAL_DEFAULTS)

    def _load_profile(self, name: str) -> None:
        """Load *name*.ini into a fresh profile parser (resets to defaults first)."""
        self._profile = configparser.RawConfigParser()
        self._init_parser(self._profile, self.PROFILE_DEFAULTS)
        f = self._profile_file(name)
        if f.exists():
            self._profile.read(f, encoding="utf-8")
        self._cleanup(self._profile, self.PROFILE_DEFAULTS)

    def _migrate_if_needed(self) -> None:
        """Migrate legacy pdf_signer.ini to the new profile-based layout."""
        if _SETTINGS_FILE.exists() or not _LEGACY_FILE.exists():
            return

        old = configparser.RawConfigParser()
        old.read(_LEGACY_FILE, encoding="utf-8")

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
