#!/usr/bin/env python3
"""
PDF QES Signer v2.5
===================
Ein GUI-Tool zum visuellen Platzieren von Signaturfeldern in PDFs
und zum Einfügen qualifizierter elektronischer Signaturen (QES) via PKCS#11.

Neu in v2.1:
  - PIN-Eingabe im Hauptfenster (rechtes Panel)
  - PKCS#11-Dialog: nur Library-Pfad + Key-Label + Token-Test
  - Signaturfeld-Darstellung konfigurierbar:
      · PNG-Bild (mit Transparenz, Seitenverhältnis erhalten)
      · Textfelder: Ort, Grund, Datum, Name
      · Layout-Umschaltung Bild-Links / Bild-Rechts im Hauptfenster

Abhängigkeiten:
    pip install pymupdf pyhanko pyhanko-certvalidator python-pkcs11 Pillow PyQt6
"""

from __future__ import annotations

import configparser
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Abhängigkeiten prüfen ─────────────────────────────────────
try:
    import fitz  # PyMuPDF
except ImportError:
    print("FEHLER: pymupdf nicht gefunden. Bitte installieren: pip install pymupdf")
    sys.exit(1)

try:
    from PIL import Image
except ImportError:
    print("FEHLER: Pillow nicht gefunden. Bitte installieren: pip install Pillow")
    sys.exit(1)

try:
    from PyQt6.QtCore import (Qt, QThread, pyqtSignal, QSize,
                               QPointF, QRectF, QSizeF)
    from PyQt6.QtGui import (QPixmap, QImage, QPainter, QPen, QColor,
                              QBrush, QFont, QAction, QKeySequence,
                              QFontMetricsF)
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QScrollArea, QLabel, QListWidget, QPushButton, QFileDialog,
        QDialog, QDialogButtonBox, QLineEdit, QComboBox, QMessageBox,
        QSplitter, QGroupBox, QFormLayout, QSizePolicy, QInputDialog,
        QAbstractItemView, QCheckBox, QSpinBox, QTabWidget, QFrame,
        QToolBar, QSlider, QGridLayout
    )
except ImportError:
    print("FEHLER: PyQt6 nicht gefunden. Bitte installieren: pip install PyQt6")
    sys.exit(1)

_pyhanko_available = False
_pkcs11_available = False

try:
    from pyhanko.sign import fields
    from pyhanko.sign.fields import SigFieldSpec
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.pkcs11 import open_pkcs11_session
    _pyhanko_available = True
    _pkcs11_available = True
except ImportError:
    try:
        from pyhanko.sign import fields
        from pyhanko.sign.fields import SigFieldSpec
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        _pyhanko_available = True
    except ImportError:
        pass


# ══════════════════════════════════════════════════════════════
#  Internationalisierung (i18n)
# ══════════════════════════════════════════════════════════════

TRANSLATIONS: dict[str, dict[str, str]] = {
    "de": {
        # Menü
        "menu_file": "Datei",
        "menu_file_open": "PDF öffnen…",
        "menu_file_save_fields": "Felder speichern (Kopie)…",
        "menu_file_quit": "Beenden",
        "menu_sign": "Signieren",
        "menu_sign_document": "Dokument signieren (QES)…",
        "menu_settings": "Einstellungen",
        "menu_settings_pkcs11": "PKCS#11 / Token konfigurieren…",
        "menu_settings_appearance": "Signaturfeld-Darstellung…",
        "menu_settings_language": "Sprache / Language",
        "menu_help": "Hilfe",
        "menu_help_about": "Über…",
        # Toolbar
        "tb_open": "PDF öffnen",
        "tb_prev": "◀",
        "tb_next": "▶",
        "tb_sign": "✍ Signieren (QES)",
        "tb_save_fields": "💾 Felder speichern",
        # Rechtes Panel – Felder
        "panel_fields": "Signaturfelder",
        "btn_delete_field": "🗑 Löschen",
        "btn_save_fields": "💾 Als PDF speichern",
        # Rechtes Panel – Token / PIN
        "panel_token": "Token / PIN",
        "pin_label": "PIN:",
        "pin_hint": "leer lassen für PIN-Pad",
        # Rechtes Panel – Signaturfeld-Erscheinung
        "panel_appearance": "Signatur-Erscheinung",
        "app_layout_label": "Anordnung:",
        "app_layout_img_left": "Bild Links | Text Rechts",
        "app_layout_img_right": "Text Links | Bild Rechts",
        "app_location_label": "Ort:",
        "app_reason_label": "Grund:",
        "app_name_label": "Name:",
        "app_name_cert": "(aus Zertifikat)",
        "app_date_label": "Datumsformat:",
        "app_show_date": "Datum anzeigen",
        # Signaturfeld-Darstellungs-Dialog
        "appdlg_title": "Signaturfeld-Darstellung konfigurieren",
        "appdlg_tab_image": "Bild",
        "appdlg_tab_text": "Text",
        "appdlg_tab_layout": "Layout",
        "appdlg_img_path": "PNG-Bild:",
        "appdlg_img_browse": "…",
        "appdlg_img_clear": "Entfernen",
        "appdlg_img_preview": "Vorschau",
        "appdlg_img_hint": "Transparenz wird unterstützt. Seitenverhältnis bleibt erhalten.",
        "appdlg_img_filter": "PNG-Bilder (*.png);;Alle Bilder (*.png *.jpg *.jpeg *.bmp);;Alle Dateien (*)",
        "appdlg_browse_img": "Signaturbild wählen",
        "appdlg_font_size": "Schriftgröße (pt):",
        "appdlg_text_color": "Textfarbe:",
        "appdlg_border": "Rahmen anzeigen",
        "appdlg_bg_color": "Hintergrundfarbe:",
        "appdlg_save": "Speichern",
        "appdlg_cancel": "Abbrechen",
        # Status
        "status_ready": "Bereit. Öffnen Sie eine PDF-Datei.",
        "status_opened": "Geöffnet: {path}  ({pages} Seiten)",
        "status_field_added": "Signaturfeld '{name}' auf Seite {page} hinzugefügt.",
        "status_field_deleted": "Feld '{name}' gelöscht.",
        "status_saving_fields": "Signaturfelder werden eingebettet…",
        "status_saved": "Gespeichert: {path}",
        "status_signing": "Signierung läuft…",
        "status_signed": "Dokument signiert: {path}",
        "status_sign_failed": "Signierung fehlgeschlagen.",
        "status_save_failed": "Fehler beim Speichern.",
        "status_token_ok": "Token OK: {label} | {keys} Key(s), {certs} Zertifikat(e)",
        "status_token_failed": "Token-Test fehlgeschlagen.",
        "status_token_reading": "Token wird gelesen…",
        # Dialoge
        "dlg_field_name_title": "Feldname",
        "dlg_field_name_prompt": "Name des Signaturfeldes:",
        "dlg_field_name_default": "Sig_{page}_{count}",
        "dlg_delete_title": "Löschen",
        "dlg_delete_msg": "Signaturfeld '{name}' löschen?",
        "dlg_delete_sel_msg": "Feld '{name}' wirklich löschen?",
        "dlg_no_doc": "Kein Dokument",
        "dlg_no_doc_msg": "Bitte zuerst ein PDF öffnen.",
        "dlg_no_fields": "Keine Felder",
        "dlg_no_fields_msg": "Bitte zuerst Signaturfelder zeichnen.",
        "dlg_no_field_sel": "Kein Feld ausgewählt",
        "dlg_no_field_sel_msg": "Bitte ein Feld in der Liste auswählen.",
        "dlg_missing_deps": "Fehlende Abhängigkeiten",
        "dlg_missing_deps_msg": (
            "Folgende Pakete fehlen für QES-Signierung:\n\n{packages}\n\n"
            "Das Platzieren von Signaturfeldern ist trotzdem möglich."
        ),
        "dlg_open_pdf_title": "PDF öffnen",
        "dlg_save_fields_title": "Speichern als…",
        "dlg_save_fields_suffix": "_mit_feldern",
        "dlg_save_signed_title": "Signiertes PDF speichern als…",
        "dlg_save_signed_suffix": "_signiert",
        "dlg_pdf_filter": "PDF-Dateien (*.pdf);;Alle Dateien (*)",
        "dlg_lib_filter": "Shared Libraries (*.so *.so.*);;DLL (*.dll);;Alle Dateien (*)",
        "dlg_open_error_title": "Fehler",
        "dlg_open_error_msg": "PDF konnte nicht geöffnet werden:\n{error}",
        "dlg_save_error_title": "Fehler",
        "dlg_save_error_msg": "Fehler:\n{error}",
        "dlg_save_success_title": "Erfolg",
        "dlg_save_success_msg": "PDF mit Signaturfeldern gespeichert:\n{path}",
        "dlg_sign_success_title": "Signierung erfolgreich ✓",
        "dlg_sign_success_msg": "QES-Signatur erfolgreich eingefügt.\n\nDatei: {path}",
        "dlg_sign_error_title": "Signierungsfehler",
        "dlg_sign_error_msg": (
            "Fehler bei der QES-Signierung:\n\n{error}\n\n"
            "Häufige Ursachen:\n"
            "• PIN-Feld leer lassen für CyberJack PIN-Pad\n"
            "• Token nicht eingesteckt\n"
            "• Falscher Library-Pfad\n"
            "• Key-Label stimmt nicht überein\n"
            "• Kein Zertifikat auf dem Token\n\n"
            "Vollständiger Traceback in der Konsole (stderr)."
        ),
        "dlg_pyhanko_missing": "pyhanko ist nicht installiert.\npip install pyhanko python-pkcs11",
        "dlg_choose_field_title": "Signaturfeld wählen",
        "dlg_choose_field_label": "Mit welchem Feld signieren?",
        "dlg_invisible_field": "Neues unsichtbares Feld",
        # PKCS#11-Dialog
        "cfg_title": "PKCS#11 / Token konfigurieren",
        "cfg_lib_label": "Library-Pfad (.so / .dll):",
        "cfg_lib_browse": "…",
        "cfg_key_label": "Key-Label:",
        "cfg_key_hint": "↑ wird beim Token-Test automatisch gefüllt",
        "cfg_test_btn": "🔑 Token testen",
        "cfg_save_btn": "Speichern",
        "cfg_cancel_btn": "Abbrechen",
        "dlg_browse_lib": "PKCS#11 Library wählen",
        "dlg_token_error_title": "Token-Fehler",
        "dlg_token_info_title": "Token-Inhalt",
        "dlg_token_info_label": "Name: {label}    Hersteller: {manufacturer}",
        "dlg_token_keys_title": "Private Keys  (Doppelklick → übernehmen)",
        "dlg_token_certs_title": "Zertifikat-Labels",
        "dlg_token_use_key": "✓ Key-Label übernehmen",
        "dlg_token_copy_key": "📋 Key kopieren",
        "dlg_token_copy_cert": "📋 Zert. kopieren",
        "dlg_token_close": "Schließen",
        "dlg_token_auto_label": "Key-Label automatisch gesetzt: {label}",
        # About
        "about_title": "Über PDF QES Signer",
        "about_msg": (
            "PDF QES Signer v2.5\n\n"
            "Visuelles Platzieren von Signaturfeldern\n"
            "und qualifizierte elektronische Signatur (QES)\n"
            "via PKCS#11 / Smartcard.\n\n"
            "Benötigte Pakete:\n"
            "  pip install pymupdf pyhanko python-pkcs11 Pillow PyQt6\n\n"
            "Linksklick + Ziehen → Signaturfeld zeichnen\n"
            "Rechtsklick auf Feld → Feld löschen"
        ),
    },
    "en": {
        "menu_file": "File",
        "menu_file_open": "Open PDF…",
        "menu_file_save_fields": "Save with fields (copy)…",
        "menu_file_quit": "Quit",
        "menu_sign": "Sign",
        "menu_sign_document": "Sign document (QES)…",
        "menu_settings": "Settings",
        "menu_settings_pkcs11": "Configure PKCS#11 / Token…",
        "menu_settings_appearance": "Signature Field Appearance…",
        "menu_settings_language": "Language / Sprache",
        "menu_help": "Help",
        "menu_help_about": "About…",
        "tb_open": "Open PDF",
        "tb_prev": "◀",
        "tb_next": "▶",
        "tb_sign": "✍ Sign (QES)",
        "tb_save_fields": "💾 Save fields",
        "panel_fields": "Signature Fields",
        "btn_delete_field": "🗑 Delete",
        "btn_save_fields": "💾 Save as PDF",
        "panel_token": "Token / PIN",
        "pin_label": "PIN:",
        "pin_hint": "leave empty for PIN pad",
        "panel_appearance": "Signature Appearance",
        "app_layout_label": "Layout:",
        "app_layout_img_left": "Image Left | Text Right",
        "app_layout_img_right": "Text Left | Image Right",
        "app_location_label": "Location:",
        "app_reason_label": "Reason:",
        "app_name_label": "Name:",
        "app_name_cert": "(from certificate)",
        "app_date_label": "Date format:",
        "app_show_date": "Show date",
        "appdlg_title": "Configure Signature Field Appearance",
        "appdlg_tab_image": "Image",
        "appdlg_tab_text": "Text",
        "appdlg_tab_layout": "Layout",
        "appdlg_img_path": "PNG image:",
        "appdlg_img_browse": "…",
        "appdlg_img_clear": "Remove",
        "appdlg_img_preview": "Preview",
        "appdlg_img_hint": "Transparency supported. Aspect ratio preserved.",
        "appdlg_img_filter": "PNG Images (*.png);;All Images (*.png *.jpg *.jpeg *.bmp);;All Files (*)",
        "appdlg_browse_img": "Choose Signature Image",
        "appdlg_font_size": "Font size (pt):",
        "appdlg_text_color": "Text color:",
        "appdlg_border": "Show border",
        "appdlg_bg_color": "Background color:",
        "appdlg_save": "Save",
        "appdlg_cancel": "Cancel",
        "status_ready": "Ready. Open a PDF file.",
        "status_opened": "Opened: {path}  ({pages} pages)",
        "status_field_added": "Signature field '{name}' added on page {page}.",
        "status_field_deleted": "Field '{name}' deleted.",
        "status_saving_fields": "Embedding signature fields…",
        "status_saved": "Saved: {path}",
        "status_signing": "Signing in progress…",
        "status_signed": "Document signed: {path}",
        "status_sign_failed": "Signing failed.",
        "status_save_failed": "Error while saving.",
        "status_token_ok": "Token OK: {label} | {keys} key(s), {certs} certificate(s)",
        "status_token_failed": "Token test failed.",
        "status_token_reading": "Reading token…",
        "dlg_field_name_title": "Field Name",
        "dlg_field_name_prompt": "Signature field name:",
        "dlg_field_name_default": "Sig_{page}_{count}",
        "dlg_delete_title": "Delete",
        "dlg_delete_msg": "Delete signature field '{name}'?",
        "dlg_delete_sel_msg": "Really delete field '{name}'?",
        "dlg_no_doc": "No Document",
        "dlg_no_doc_msg": "Please open a PDF file first.",
        "dlg_no_fields": "No Fields",
        "dlg_no_fields_msg": "Please draw at least one signature field first.",
        "dlg_no_field_sel": "No Field Selected",
        "dlg_no_field_sel_msg": "Please select a field in the list.",
        "dlg_missing_deps": "Missing Dependencies",
        "dlg_missing_deps_msg": (
            "The following packages are missing for QES signing:\n\n{packages}\n\n"
            "Placing signature fields is still possible."
        ),
        "dlg_open_pdf_title": "Open PDF",
        "dlg_save_fields_title": "Save As…",
        "dlg_save_fields_suffix": "_with_fields",
        "dlg_save_signed_title": "Save signed PDF as…",
        "dlg_save_signed_suffix": "_signed",
        "dlg_pdf_filter": "PDF Files (*.pdf);;All Files (*)",
        "dlg_lib_filter": "Shared Libraries (*.so *.so.*);;DLL (*.dll);;All Files (*)",
        "dlg_open_error_title": "Error",
        "dlg_open_error_msg": "Could not open PDF:\n{error}",
        "dlg_save_error_title": "Error",
        "dlg_save_error_msg": "Error:\n{error}",
        "dlg_save_success_title": "Success",
        "dlg_save_success_msg": "PDF with signature fields saved:\n{path}",
        "dlg_sign_success_title": "Signing successful ✓",
        "dlg_sign_success_msg": "QES signature successfully applied.\n\nFile: {path}",
        "dlg_sign_error_title": "Signing Error",
        "dlg_sign_error_msg": (
            "Error during QES signing:\n\n{error}\n\n"
            "Common causes:\n"
            "• Leave PIN empty for CyberJack PIN pad\n"
            "• Token not inserted\n"
            "• Wrong library path\n"
            "• Key label mismatch\n"
            "• No certificate on token\n\n"
            "Full traceback in console (stderr)."
        ),
        "dlg_pyhanko_missing": "pyhanko is not installed.\npip install pyhanko python-pkcs11",
        "dlg_choose_field_title": "Choose Signature Field",
        "dlg_choose_field_label": "Sign with which field?",
        "dlg_invisible_field": "New invisible field",
        "cfg_title": "Configure PKCS#11 / Token",
        "cfg_lib_label": "Library path (.so / .dll):",
        "cfg_lib_browse": "…",
        "cfg_key_label": "Key Label:",
        "cfg_key_hint": "↑ filled automatically on token test",
        "cfg_test_btn": "🔑 Test Token",
        "cfg_save_btn": "Save",
        "cfg_cancel_btn": "Cancel",
        "dlg_browse_lib": "Choose PKCS#11 Library",
        "dlg_token_error_title": "Token Error",
        "dlg_token_info_title": "Token Contents",
        "dlg_token_info_label": "Name: {label}    Manufacturer: {manufacturer}",
        "dlg_token_keys_title": "Private Keys  (double-click → apply)",
        "dlg_token_certs_title": "Certificate Labels",
        "dlg_token_use_key": "✓ Use Key Label",
        "dlg_token_copy_key": "📋 Copy Key",
        "dlg_token_copy_cert": "📋 Copy Cert",
        "dlg_token_close": "Close",
        "dlg_token_auto_label": "Key label auto-set: {label}",
        "about_title": "About PDF QES Signer",
        "about_msg": (
            "PDF QES Signer v2.5\n\n"
            "Visual placement of signature fields\n"
            "and qualified electronic signature (QES)\n"
            "via PKCS#11 / Smartcard.\n\n"
            "Required packages:\n"
            "  pip install pymupdf pyhanko python-pkcs11 Pillow PyQt6\n\n"
            "Left-click + drag → draw signature field\n"
            "Right-click on field → delete field"
        ),
    },
}

AVAILABLE_LANGUAGES = {"de": "Deutsch", "en": "English"}


class I18n:
    def __init__(self, lang: str = "de"):
        self._lang = lang if lang in TRANSLATIONS else "de"

    @property
    def lang(self) -> str:
        return self._lang

    @lang.setter
    def lang(self, value: str):
        if value in TRANSLATIONS:
            self._lang = value

    def t(self, key: str, **kwargs) -> str:
        text = TRANSLATIONS[self._lang].get(key, TRANSLATIONS["de"].get(key, key))
        if kwargs:
            try:
                return text.format(**kwargs)
            except KeyError:
                return text
        return text


i18n = I18n("de")


def t(key: str, **kwargs) -> str:
    return i18n.t(key, **kwargs)


# ══════════════════════════════════════════════════════════════
#  Konfiguration
# ══════════════════════════════════════════════════════════════

# PDF-14-Standardfonts: (Anzeigename, PDF-Font-Name, avg_width, Qt-Familie)
PDF_STANDARD_FONTS = [
    ("Helvetica",            "Helvetica",              0.5,  "Helvetica"),
    ("Helvetica Bold",       "Helvetica-Bold",          0.5,  "Helvetica"),
    ("Helvetica Oblique",    "Helvetica-Oblique",       0.5,  "Helvetica"),
    ("Times Roman",          "Times-Roman",             0.44, "Times New Roman"),
    ("Times Bold",           "Times-Bold",              0.44, "Times New Roman"),
    ("Times Italic",         "Times-Italic",            0.44, "Times New Roman"),
    ("Courier",              "Courier",                 0.6,  "Courier New"),
    ("Courier Bold",         "Courier-Bold",            0.6,  "Courier New"),
    ("Courier Oblique",      "Courier-Oblique",         0.6,  "Courier New"),
]



CONFIG_DIR  = Path.home() / ".config" / "pdf-signer"
CONFIG_FILE = CONFIG_DIR / "pdf_signer.ini"


class AppConfig:
    DEFAULTS = {
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
            "image_path":   "",
            "layout":       "img_left",   # img_left | img_right
            "show_location": "1",
            "location":     "",
            "show_reason":  "1",
            "reason":       "",
            "show_name":    "1",
            "name_mode":    "cert",       # cert | custom
            "name_custom":  "",
            "show_date":    "1",
            "date_format":  "%d.%m.%Y %H:%M",
            "font_size":    "8",
            "font_family":  "Helvetica",  # PDF-Font-Name
            "show_border":  "1",
            "img_ratio":    "40",
        },
    }

    def __init__(self):
        self._cfg = configparser.RawConfigParser()
        for section, values in self.DEFAULTS.items():
            if not self._cfg.has_section(section):
                self._cfg.add_section(section)
            for k, v in values.items():
                self._cfg.set(section, k, v)
        self.load()

    def load(self):
        if CONFIG_FILE.exists():
            self._cfg.read(CONFIG_FILE, encoding="utf-8")

    def save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            self._cfg.write(f)

    def get(self, section: str, key: str) -> str:
        return self._cfg.get(
            section, key,
            fallback=self.DEFAULTS.get(section, {}).get(key, ""))

    def set(self, section: str, key: str, value: str):
        if not self._cfg.has_section(section):
            self._cfg.add_section(section)
        self._cfg.set(section, key, value)

    def getbool(self, section: str, key: str) -> bool:
        return self.get(section, key) == "1"

    def setbool(self, section: str, key: str, value: bool):
        self.set(section, key, "1" if value else "0")


# ══════════════════════════════════════════════════════════════
#  Signaturfeld-Erscheinungsbild
# ══════════════════════════════════════════════════════════════

class SigAppearance:
    """Kapselt alle Darstellungs-Einstellungen und rendert das Signaturfeld-Vorschaubild."""

    def __init__(self, config: AppConfig):
        self.config = config

    # ── Einstellungen lesen ───────────────────────────────
    @property
    def image_path(self) -> str:
        return self.config.get("appearance", "image_path")

    @property
    def layout(self) -> str:
        return self.config.get("appearance", "layout")

    @property
    def show_location(self) -> bool:
        return self.config.getbool("appearance", "show_location")

    @property
    def location(self) -> str:
        return self.config.get("appearance", "location")

    @property
    def show_reason(self) -> bool:
        return self.config.getbool("appearance", "show_reason")

    @property
    def reason(self) -> str:
        return self.config.get("appearance", "reason")

    @property
    def show_name(self) -> bool:
        return self.config.getbool("appearance", "show_name")

    @property
    def name_mode(self) -> str:
        return self.config.get("appearance", "name_mode")

    @property
    def name_custom(self) -> str:
        return self.config.get("appearance", "name_custom")

    @property
    def show_date(self) -> bool:
        return self.config.getbool("appearance", "show_date")

    @property
    def date_format(self) -> str:
        return self.config.get("appearance", "date_format")

    @property
    def font_size(self) -> int:
        try:
            return int(self.config.get("appearance", "font_size"))
        except ValueError:
            return 8

    @property
    def font_pdf_name(self) -> str:
        """PDF-Font-Name für pyhanko (z.B. 'Helvetica-Bold')."""
        saved = self.config.get("appearance", "font_family") or "Helvetica"
        for _, pdf_name, _, _ in PDF_STANDARD_FONTS:
            if pdf_name == saved:
                return pdf_name
        return "Helvetica"

    @property
    def font_avg_width(self) -> float:
        saved = self.config.get("appearance", "font_family") or "Helvetica"
        for _, pdf_name, avg_w, _ in PDF_STANDARD_FONTS:
            if pdf_name == saved:
                return avg_w
        return 0.5

    @property
    def font_qt_family(self) -> str:
        """Qt-Schriftfamilie für die Vorschau."""
        saved = self.config.get("appearance", "font_family") or "Helvetica"
        for _, pdf_name, _, qt_fam in PDF_STANDARD_FONTS:
            if pdf_name == saved:
                return qt_fam
        return "Helvetica"

    @property
    def img_ratio(self) -> int:
        try:
            return max(10, min(70, int(
                self.config.get("appearance", "img_ratio") or "40")))
        except ValueError:
            return 40

    @property
    def show_border(self) -> bool:
        return self.config.getbool("appearance", "show_border")

    # ── Render ins QPixmap (Canvas-Preview) ─────────────
    def render_preview(self, width: int, height: int,
                       cert_name: str = "",
                       pixels_per_point: float = 1.0) -> QPixmap:
        """Erzeugt ein QPixmap in der gewünschten Feldgröße.
        pixels_per_point: Wie viele Pixel einem PDF-Punkt entsprechen
        (z.B. ZOOM=1.5 im Canvas, 96/72≈1.333 im Vorschau-Label)."""
        pixmap = QPixmap(width, height)
        pixmap.fill(Qt.GlobalColor.transparent)

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

        rect = QRectF(0, 0, width, height)

        # Hintergrund
        painter.fillRect(rect, QColor(208, 228, 255, 60))

        # Rahmen
        if self.show_border:
            pen = QPen(QColor("#1a73e8"), 1.5, Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.drawRect(rect.adjusted(1, 1, -1, -1))

        # Bild laden
        img_pixmap: Optional[QPixmap] = None
        if self.image_path and Path(self.image_path).exists():
            img_pixmap = QPixmap(self.image_path)

        # Text aufbauen
        lines = []
        name = cert_name if self.name_mode == "cert" and cert_name else self.name_custom
        if self.show_name and name:
            lines.append(name)
        if self.show_location and self.location:
            lines.append(self.location)
        if self.show_reason and self.reason:
            lines.append(self.reason)
        if self.show_date:
            try:
                lines.append(datetime.now().strftime(self.date_format))
            except Exception:
                lines.append(datetime.now().strftime("%d.%m.%Y"))

        # Bereiche aufteilen
        PADDING = 4
        ratio = self.img_ratio / 100.0
        if img_pixmap and not img_pixmap.isNull():
            split = int(width * ratio)
            if self.layout == "img_left":
                img_rect  = QRectF(PADDING, PADDING, split - 2*PADDING, height - 2*PADDING)
                text_rect = QRectF(split + PADDING, PADDING, width - split - 2*PADDING, height - 2*PADDING)
            else:
                text_rect = QRectF(PADDING, PADDING, width - split - 2*PADDING, height - 2*PADDING)
                img_rect  = QRectF(width - split + PADDING, PADDING,
                                   split - 2*PADDING, height - 2*PADDING)
            self._draw_image_aspect(painter, img_pixmap, img_rect)
        else:
            text_rect = QRectF(PADDING, PADDING, width - 2*PADDING, height - 2*PADDING)

        # Text zeichnen – vertikal mittig
        if lines:
            painter.setPen(QPen(QColor("#1a3060")))
            font = QFont(self.font_qt_family)
            font.setPixelSize(max(4, round(self.font_size * pixels_per_point)))
            painter.setFont(font)
            fm = QFontMetricsF(font)
            # Kompakter Zeilenabstand wie pyhanko: nur Ascent+Descent, kein Leading
            line_h = fm.ascent() + fm.descent()
            total_h = line_h * len(lines)
            y_start = text_rect.top() + (text_rect.height() - total_h) / 2 + fm.ascent()
            # Fester Einzug in PDF-Punkten, unabhängig von Schriftgröße
            x_start = text_rect.left() + 15  # fester Einzug in Pixeln
            y = y_start
            for line in lines:
                if y - fm.ascent() > text_rect.bottom():
                    break
                elided = fm.elidedText(line, Qt.TextElideMode.ElideRight,
                                       text_rect.width())
                painter.drawText(QPointF(x_start, y), elided)
                y += line_h
        elif not img_pixmap:
            # Fallback-Label
            painter.setPen(QPen(QColor("#1a73e8")))
            painter.setFont(QFont("Arial", 9, QFont.Weight.Bold))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "✍ Signature")

        painter.end()
        return pixmap

    @staticmethod
    def _draw_image_aspect(painter: QPainter, pixmap: QPixmap, target: QRectF):
        """Zeichnet Pixmap in target-Rect, Seitenverhältnis erhalten, zentriert."""
        pw, ph = pixmap.width(), pixmap.height()
        tw, th = target.width(), target.height()
        if pw <= 0 or ph <= 0 or tw <= 0 or th <= 0:
            return
        scale = min(tw / pw, th / ph)
        dw = pw * scale
        dh = ph * scale
        dx = target.left() + (tw - dw) / 2
        dy = target.top()  + (th - dh) / 2
        dest = QRectF(dx, dy, dw, dh)
        painter.drawPixmap(dest, pixmap, QRectF(pixmap.rect()))


# ══════════════════════════════════════════════════════════════
#  Datenmodell
# ══════════════════════════════════════════════════════════════

class SignatureFieldDef:
    def __init__(self, page: int, x1: float, y1: float,
                 x2: float, y2: float, name: str = "Signature"):
        self.page = page
        self.x1, self.y1 = x1, y1
        self.x2, self.y2 = x2, y2
        self.name = name

    def __repr__(self):
        return (f"<SigField '{self.name}' page={self.page + 1} "
                f"[{self.x1:.0f},{self.y1:.0f},{self.x2:.0f},{self.y2:.0f}]>")


# ══════════════════════════════════════════════════════════════
#  Worker Threads
# ══════════════════════════════════════════════════════════════

class SaveFieldsWorker(QThread):
    finished = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, pdf_path, out_path, sig_fields):
        super().__init__()
        self.pdf_path   = pdf_path
        self.out_path   = out_path
        self.sig_fields = sig_fields

    def run(self):
        try:
            with open(self.pdf_path, "rb") as inf:
                writer = IncrementalPdfFileWriter(inf)
                for fdef in self.sig_fields:
                    spec = SigFieldSpec(
                        sig_field_name=fdef.name,
                        on_page=fdef.page,
                        box=(fdef.x1, fdef.y1, fdef.x2, fdef.y2),
                    )
                    fields.append_signature_field(writer, spec)
                with open(self.out_path, "wb") as outf:
                    writer.write(outf)
            self.finished.emit(self.out_path)
        except Exception as exc:
            self.error.emit(str(exc))


def _render_appearance_to_png(appearance: "SigAppearance", cert_name: str,
                              width_pt: float, height_pt: float) -> Optional[str]:
    """
    Rendert das konfigurierte Erscheinungsbild als PNG in eine Temp-Datei.
    Gibt den Pfad zurück oder None bei Fehler.
    Nutzt Pillow – ist sowieso bereits als Abhängigkeit installiert.
    """
    import tempfile
    try:
        from PIL import Image as PILImage, ImageDraw, ImageFont

        name = cert_name if appearance.name_mode == "cert" and cert_name \
               else appearance.name_custom
        lines: list[str] = []
        if appearance.show_name and name:
            lines.append(name)
        if appearance.show_location and appearance.location:
            lines.append(appearance.location)
        if appearance.show_reason and appearance.reason:
            lines.append(appearance.reason)
        if appearance.show_date:
            try:
                lines.append(datetime.now().strftime(appearance.date_format))
            except Exception:
                lines.append(datetime.now().strftime("%d.%m.%Y"))

        SCALE = 3
        px_w = max(4, int(width_pt  * SCALE))
        px_h = max(4, int(height_pt * SCALE))
        PADDING = int(4 * SCALE)

        img = PILImage.new("RGBA", (px_w, px_h), (255, 255, 255, 0))
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, px_w - 1, px_h - 1], fill=(208, 228, 255, 120))
        if appearance.show_border:
            draw.rectangle([1, 1, px_w - 2, px_h - 2],
                           outline=(26, 115, 232, 255), width=max(1, SCALE))

        img_path = appearance.image_path
        has_image = bool(img_path and Path(img_path).exists())

        if has_image:
            split = int(px_w * 0.40)
            if appearance.layout == "img_left":
                img_box  = (PADDING, PADDING, split - PADDING, px_h - PADDING)
                text_box = (split + PADDING, PADDING, px_w - PADDING, px_h - PADDING)
            else:
                text_box = (PADDING, PADDING, px_w - split - PADDING, px_h - PADDING)
                img_box  = (px_w - split + PADDING, PADDING, px_w - PADDING, px_h - PADDING)

            src = PILImage.open(img_path).convert("RGBA")
            bw = img_box[2] - img_box[0]
            bh = img_box[3] - img_box[1]
            if bw > 0 and bh > 0:
                scale_f = min(bw / src.width, bh / src.height)
                nw = max(1, int(src.width  * scale_f))
                nh = max(1, int(src.height * scale_f))
                src_s = src.resize((nw, nh), PILImage.LANCZOS)
                ox = img_box[0] + (bw - nw) // 2
                oy = img_box[1] + (bh - nh) // 2
                img.paste(src_s, (ox, oy), src_s)
        else:
            text_box = (PADDING, PADDING, px_w - PADDING, px_h - PADDING)

        font_size_px = max(8, appearance.font_size * SCALE)
        font = None
        for candidate in [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "C:/Windows/Fonts/arial.ttf",
        ]:
            if Path(candidate).exists():
                try:
                    font = ImageFont.truetype(candidate, font_size_px)
                    break
                except Exception:
                    pass
        if font is None:
            import glob
            ttfs = glob.glob("/usr/share/fonts/**/*.ttf", recursive=True)
            if ttfs:
                try:
                    font = ImageFont.truetype(ttfs[0], font_size_px)
                except Exception:
                    pass
        if font is None:
            font = ImageFont.load_default()

        text_color = (26, 48, 96, 255)
        tb_x0, tb_y0, tb_x1, tb_y1 = text_box
        tb_w = tb_x1 - tb_x0
        y = tb_y0 + int(2 * SCALE)
        for line in lines:
            bbox = draw.textbbox((0, 0), line, font=font)
            lw = bbox[2] - bbox[0]
            lh = bbox[3] - bbox[1]
            if lw > tb_w and len(line) > 3:
                while len(line) > 1:
                    line = line[:-1]
                    bbox = draw.textbbox((0, 0), line + "…", font=font)
                    if bbox[2] - bbox[0] <= tb_w:
                        line += "…"
                        break
            if y + lh > tb_y1:
                break
            draw.text((tb_x0, y), line, font=font, fill=text_color)
            y += lh + int(1 * SCALE)

        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        img.save(tmp.name, "PNG")
        tmp.close()
        return tmp.name

    except Exception:
        traceback.print_exc(file=sys.stderr)
        return None


def _make_background_image(img_path: str, layout: str = "img_left", img_ratio: int = 40):
    """
    Lädt das PNG und erweitert es mit einem transparenten Streifen
    auf der Textseite (60% Breite), damit pyhanko's TextStampStyle
    Bild (40%) und Text (60%) nebeneinander anzeigt.

    layout="img_left"  → Bild links, transparenter Streifen rechts
    layout="img_right" → transparenter Streifen links, Bild rechts
    """
    from pyhanko.pdf_utils.images import PdfImage
    from PIL import Image as PILImage

    src = PILImage.open(img_path).convert("RGBA")
    iw, ih = src.size

    # Gesamtbreite: Bild nimmt 40% ein → Canvas = iw / 0.4
    total_w = int(iw / (img_ratio / 100.0))
    canvas = PILImage.new("RGBA", (total_w, ih), (255, 255, 255, 0))

    if layout == "img_left":
        canvas.paste(src, (0, 0))
    else:
        canvas.paste(src, (total_w - iw, 0))

    return PdfImage(canvas)


def _prepare_pdf_with_appearance(src_path: str, dst_path: str,
                                  fdef: Optional["SignatureFieldDef"],
                                  appearance_png: Optional[str]):
    """
    Kopiert src_path nach dst_path, legt das Signaturfeld an und
    setzt den AP/N-Appearance-Stream auf das gerenderte PNG.

    Strategie (rein mit fitz, keine pyhanko-Interna):
    1. Bild-XObject ins Dokument einbetten (über unsichtbares Off-Page-Rect)
    2. Form-XObject anlegen der das Bild auf Feldgröße skaliert
    3. /AP /N des Widget-Annotations-Objekts auf den Form-XObject zeigen
    4. Als normales (nicht-inkrementelles) PDF speichern –
       pyhanko signiert es danach inkrementell, was sauber ist.
    """
    import fitz as _fitz, re

    doc  = _fitz.open(src_path)

    if fdef is not None:
        fw = abs(fdef.x2 - fdef.x1)
        fh = abs(fdef.y2 - fdef.y1)
        page = doc[fdef.page]
        page_h = page.rect.height

        # Signaturfeld als leere Annotation anlegen falls noch nicht vorhanden
        # (pyhanko macht das normalerweise – hier tun wir es mit fitz)
        field_exists = any(
            w.field_name == fdef.name for w in page.widgets()
        )
        if not field_exists:
            # Widget-Annotation manuell anlegen
            annot_xref = doc.get_new_xref()
            # PDF-Koordinaten: fitz Rect hat y=0 oben, PDF y=0 unten
            # fdef speichert native PDF-Koords → direkt verwenden
            x0, y0, x1, y1 = fdef.x1, fdef.y1, fdef.x2, fdef.y2
            doc.update_object(annot_xref,
                f"<< /Type /Annot /Subtype /Widget "
                f"/FT /Sig "
                f"/Rect [{x0:.2f} {y0:.2f} {x1:.2f} {y1:.2f}] "
                f"/T ({fdef.name}) "
                f"/F 4 "
                f"/P {page.xref} 0 R >>")
            # Widget zur Seite hinzufügen
            page_obj = doc.xref_object(page.xref, compressed=False)
            if "/Annots" in page_obj:
                page_obj = page_obj.replace(
                    "/Annots [",
                    f"/Annots [{annot_xref} 0 R ")
            else:
                page_obj = page_obj.rstrip().rstrip(">").rstrip() +                     f" /Annots [{annot_xref} 0 R ] >>"
            doc.update_object(page.xref, page_obj)
            # AcroForm-Eintrag ergänzen
            root = doc.pdf_catalog()
            root_obj = doc.xref_object(root, compressed=False)
            if "/AcroForm" not in root_obj:
                root_obj = root_obj.rstrip().rstrip(">").rstrip() +                     f" /AcroForm << /Fields [{annot_xref} 0 R] /SigFlags 3 >> >>"
                doc.update_object(root, root_obj)
            w_xref = annot_xref
        else:
            w_xref = next(
                w.xref for w in page.widgets() if w.field_name == fdef.name
            )

        # ── Appearance-Stream einbetten wenn PNG vorhanden ────────────
        if appearance_png and Path(appearance_png).exists() and fw > 1 and fh > 1:
            # 1) Pixmap laden
            pix = _fitz.Pixmap(appearance_png)

            # 2) Bild über Off-Page-Rect einbetten → gibt img_xref zurück
            off_rect = _fitz.Rect(0, page_h + 10, fw, page_h + 10 + fh)
            img_xref = page.insert_image(off_rect, pixmap=pix)

            # 3) Form-XObject anlegen
            img_res  = "Im0"
            xobj_cs  = f"q {fw:.4f} 0 0 {fh:.4f} 0 0 cm /{img_res} Do Q".encode()
            form_xref = doc.get_new_xref()
            doc.update_object(form_xref,
                f"<< /Type /XObject /Subtype /Form "
                f"/BBox [0 0 {fw:.4f} {fh:.4f}] "
                f"/Resources << /XObject << /{img_res} {img_xref} 0 R >> >> "
                f"/Length {len(xobj_cs)} >>")
            doc.update_stream(form_xref, xobj_cs)

            # 4) /AP /N des Widgets setzen
            w_obj = doc.xref_object(w_xref, compressed=False)
            ap_entry = f"/AP << /N {form_xref} 0 R >>"
            if re.search(r"/AP", w_obj):
                w_obj = re.sub(r"/AP\s*<<[^>]*>>", ap_entry, w_obj)
            else:
                w_obj = w_obj.rstrip()
                w_obj = (w_obj[:-2].rstrip() + f" {ap_entry} >>")                     if w_obj.endswith(">>") else (w_obj + f" {ap_entry}")
            doc.update_object(w_xref, w_obj)

    # Als normales PDF speichern (nicht inkrementell –
    # pyhanko hängt seine inkrementelle Revision danach an)
    doc.save(dst_path)
    doc.close()


def _make_pdf_font(pdf_name: str, avg_width: float):
    """Gibt eine SimpleFontEngineFactory für einen PDF-14-Standardfont zurück."""
    from pyhanko.pdf_utils.font import SimpleFontEngineFactory
    return SimpleFontEngineFactory(pdf_name, avg_width)


class SignWorker(QThread):
    finished = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, pdf_path, out_path, fdef, lib_path, pin, key_label,
                 appearance: Optional["SigAppearance"] = None):
        super().__init__()
        self.pdf_path   = pdf_path
        self.out_path   = out_path
        self.fdef       = fdef
        self.lib_path   = lib_path
        self.pin        = pin
        self.key_label  = key_label
        self.appearance = appearance   # SigAppearance-Instanz oder None

    def run(self):
        try:
            import pkcs11 as p11
            from pyhanko.sign.pkcs11 import open_pkcs11_session, PKCS11Signer, PROTECTED_AUTH
            from pyhanko.sign.signers import sign_pdf, PdfSignatureMetadata, PdfSigner
            from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
            import pyhanko.sign.fields as sig_fields_mod
            from pyhanko.sign.fields import SigFieldSpec

            user_pin = self.pin if self.pin else PROTECTED_AUTH

            # ── Einzige Session: Key/Cert-IDs + CN + Signierung ───────────
            # Session wird NUR EINMAL geöffnet und bleibt bis zum Ende
            # offen. So wird die PIN (auch am PIN-Pad) nur einmal abgefragt.
            key_id = cert_id = cert_label_found = cert_cn = None

            session = open_pkcs11_session(
                lib_location=self.lib_path, slot_no=0, user_pin=user_pin)

            priv_keys = list(session.get_objects(
                {p11.Attribute.CLASS: p11.ObjectClass.PRIVATE_KEY}))
            for k in priv_keys:
                try:
                    lbl = k[p11.Attribute.LABEL]
                except Exception:
                    lbl = None
                if lbl == self.key_label or key_id is None:
                    try:
                        key_id = bytes(k[p11.Attribute.ID])
                    except Exception:
                        pass
                    if lbl == self.key_label:
                        break

            all_certs = list(session.get_objects(
                {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}))
            if not all_certs:
                raise RuntimeError("Kein Zertifikat auf dem Token gefunden.")

            matched = None
            if key_id:
                for c in all_certs:
                    try:
                        if bytes(c[p11.Attribute.ID]) == key_id:
                            matched = c; break
                    except Exception:
                        pass
            if not matched:
                for c in all_certs:
                    try:
                        if c[p11.Attribute.LABEL] == self.key_label:
                            matched = c; break
                    except Exception:
                        pass
            if not matched:
                matched = all_certs[0]

            try:
                cert_id = bytes(matched[p11.Attribute.ID])
            except Exception:
                pass
            try:
                cert_label_found = matched[p11.Attribute.LABEL]
            except Exception:
                pass

            # CN aus Zertifikat (keine zweite Session nötig)
            try:
                from cryptography import x509
                raw_cert = bytes(matched[p11.Attribute.VALUE])
                cert_obj = x509.load_der_x509_certificate(raw_cert)
                cn_attrs = cert_obj.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME)
                cert_cn = cn_attrs[0].value if cn_attrs else (cert_label_found or "")
            except Exception:
                cert_cn = cert_label_found or ""

            signer = PKCS11Signer(
                pkcs11_session=session,
                key_label=self.key_label,
                key_id=key_id,
                cert_id=cert_id,
                cert_label=cert_label_found,
                other_certs_to_pull=(),
            )

            # ── Metadaten zusammenstellen ─────────────────────────────────
            field_name = self.fdef.name if self.fdef else "Signature"
            app = self.appearance
            sig_name     = cert_cn if (app and app.show_name and
                                       app.name_mode == "cert")                            else (app.name_custom if app and app.show_name else None)
            sig_location = app.location if app and app.show_location else None
            sig_reason   = app.reason   if app and app.show_reason   else None

            sig_meta = PdfSignatureMetadata(
                field_name=field_name,
                name=sig_name     or None,
                location=sig_location or None,
                reason=sig_reason   or None,
            )

            # ── stamp_style aufbauen ──────────────────────────────────────
            from pyhanko.stamp import TextStampStyle
            from pyhanko.pdf_utils.images import PdfImage
            from pyhanko.pdf_utils.text import TextBoxStyle
            from pyhanko.pdf_utils.layout import SimpleBoxLayoutRule, AxisAlignment, Margins
            from pyhanko.sign.signers import PdfSigner

            stamp_style = None
            try:
                # ── Text zusammenstellen ──────────────────────────────────
                text_lines = []
                if app and app.show_name:
                    name_val = cert_cn if app.name_mode == "cert" and cert_cn                                else app.name_custom
                    if name_val:
                        text_lines.append(name_val)
                if app and app.show_location and app.location:
                    text_lines.append(app.location)
                if app and app.show_reason and app.reason:
                    text_lines.append(app.reason)

                # Datum via pyhanko-Platzhalter %(ts)s
                if app and app.show_date:
                    text_lines.append("%(ts)s")
                    ts_format = app.date_format or "%d.%m.%Y %H:%M"
                else:
                    ts_format = "%d.%m.%Y %H:%M"

                stamp_text = "\n".join(text_lines) if text_lines else " "

                # ── Hintergrundbild vorbereiten ───────────────────────────
                # Falls ein PNG konfiguriert ist: Bild je nach Layout
                # mit transparentem Streifen auf der Textseite erweitern,
                # damit Text und Bild nebeneinander erscheinen.
                background_image = None
                img_path = app.image_path if app else ""
                if img_path and Path(img_path).exists():
                    background_image = _make_background_image(
                        img_path,
                        layout=app.layout if app else "img_left",
                        img_ratio=app.img_ratio if app else 40,
                    )

                # ── TextStampStyle ────────────────────────────────────────
                style_kwargs = dict(
                    border_width=1 if (app and app.show_border) else 0,
                    stamp_text=stamp_text,
                    timestamp_format=ts_format,
                    text_box_style=TextBoxStyle(
                        font=_make_pdf_font(
                            app.font_pdf_name  if app else "Helvetica",
                            app.font_avg_width if app else 0.5,
                        ),
                        font_size=app.font_size if app else 8,
                        border_width=0,
                    ),
                )
                if background_image is not None:
                    style_kwargs["background"] = background_image
                    style_kwargs["background_opacity"] = 1.0
                    # Text rechtsbündig wenn Bild links, linksbündig wenn Bild rechts
                    x_align = AxisAlignment.ALIGN_MAX if app and app.layout == "img_left"                               else AxisAlignment.ALIGN_MIN
                    style_kwargs["inner_content_layout"] = SimpleBoxLayoutRule(
                        x_align=x_align,
                        y_align=AxisAlignment.ALIGN_MID,
                        margins=Margins(left=4, right=4, top=4, bottom=4),
                    )

                stamp_style = TextStampStyle(**style_kwargs)

            except Exception:
                traceback.print_exc(file=sys.stderr)

            # ── PDF signieren via PdfSigner ───────────────────────────────
            # PdfSigner(sig_meta, signer, stamp_style=...) ist der
            # offizielle Weg um das Erscheinungsbild zu setzen.
            with open(self.pdf_path, "rb") as inf:
                writer = IncrementalPdfFileWriter(inf)

                if self.fdef:
                    try:
                        spec = SigFieldSpec(
                            sig_field_name=self.fdef.name,
                            on_page=self.fdef.page,
                            box=(self.fdef.x1, self.fdef.y1,
                                 self.fdef.x2, self.fdef.y2),
                        )
                        sig_fields_mod.append_signature_field(writer, spec)
                    except Exception:
                        pass  # Feld existiert bereits

                pdf_signer = PdfSigner(
                    signature_meta=sig_meta,
                    signer=signer,
                    stamp_style=stamp_style,  # None → kein Erscheinungsbild
                )
                with open(self.out_path, "wb") as outf:
                    pdf_signer.sign_pdf(writer, output=outf)

            session.close()
            self.finished.emit(self.out_path)
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self.error.emit(str(exc))

    # _patch_appearance entfernt – Erscheinungsbild wird jetzt
    # innerhalb von sign_pdf() über _build_png_appearance() gesetzt.


# ══════════════════════════════════════════════════════════════
#  PKCS#11 Konfigurationsdialog  (nur Library + Key-Label)
# ══════════════════════════════════════════════════════════════

class TokenInfoDialog(QDialog):
    key_selected = pyqtSignal(str)

    def __init__(self, parent, token, key_labels, cert_labels):
        super().__init__(parent)
        self.token = token
        self.key_labels  = key_labels
        self.cert_labels = cert_labels
        self.setWindowTitle(t("dlg_token_info_title"))
        self.resize(540, 420)
        self._build_ui()

    def _build_ui(self):
        lay = QVBoxLayout(self)
        info = QGroupBox()
        QHBoxLayout(info).addWidget(QLabel(
            t("dlg_token_info_label",
              label=self.token.label.strip(),
              manufacturer=self.token.manufacturer_id.strip())))
        lay.addWidget(info)

        split = QSplitter(Qt.Orientation.Horizontal)

        kg = QGroupBox(t("dlg_token_keys_title"))
        kl = QVBoxLayout(kg)
        self.key_list = QListWidget()
        self.key_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        for lbl in self.key_labels:
            self.key_list.addItem(lbl)
        if self.key_labels:
            self.key_list.setCurrentRow(0)
        self.key_list.itemDoubleClicked.connect(self._use_selected)
        kl.addWidget(self.key_list)
        split.addWidget(kg)

        cg = QGroupBox(t("dlg_token_certs_title"))
        cl = QVBoxLayout(cg)
        self.cert_list = QListWidget()
        for lbl in self.cert_labels:
            self.cert_list.addItem(lbl)
        cl.addWidget(self.cert_list)
        split.addWidget(cg)
        lay.addWidget(split)

        btn_row = QHBoxLayout()
        b1 = QPushButton(t("dlg_token_use_key"))
        b1.clicked.connect(self._use_selected)
        b2 = QPushButton(t("dlg_token_copy_key"))
        b2.clicked.connect(lambda: self._copy(self.key_list))
        b3 = QPushButton(t("dlg_token_copy_cert"))
        b3.clicked.connect(lambda: self._copy(self.cert_list))
        b4 = QPushButton(t("dlg_token_close"))
        b4.clicked.connect(self.accept)
        btn_row.addWidget(b1); btn_row.addWidget(b2); btn_row.addWidget(b3)
        btn_row.addStretch(); btn_row.addWidget(b4)
        lay.addLayout(btn_row)

    def _use_selected(self):
        items = self.key_list.selectedItems()
        if items:
            self.key_selected.emit(items[0].text())
        self.accept()

    def _copy(self, lw: QListWidget):
        items = lw.selectedItems()
        if items:
            QApplication.clipboard().setText(items[0].text())


class Pkcs11ConfigDialog(QDialog):
    """Nur Library-Pfad, Key-Label und Token-Test. Kein PIN mehr hier."""

    def __init__(self, parent, config: AppConfig):
        super().__init__(parent)
        self.config = config
        self.setWindowTitle(t("cfg_title"))
        self.setMinimumWidth(520)
        self._build_ui()
        self._load_values()

    def _build_ui(self):
        lay = QVBoxLayout(self)
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        # Library
        lib_row = QHBoxLayout()
        self.lib_edit = QLineEdit()
        self.lib_edit.setPlaceholderText("/usr/lib/.../opensc-pkcs11.so")
        bb = QPushButton(t("cfg_lib_browse")); bb.setFixedWidth(36)
        bb.clicked.connect(self._browse_lib)
        lib_row.addWidget(self.lib_edit); lib_row.addWidget(bb)
        form.addRow(t("cfg_lib_label"), lib_row)

        # Key label
        self.key_edit = QLineEdit()
        hint = QLabel(t("cfg_key_hint"))
        hint.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow(t("cfg_key_label"), self.key_edit)
        form.addRow("", hint)
        lay.addLayout(form)

        test_btn = QPushButton(t("cfg_test_btn"))
        test_btn.clicked.connect(self._test_token)
        lay.addWidget(test_btn)

        self.status_lbl = QLabel("")
        self.status_lbl.setWordWrap(True)
        lay.addWidget(self.status_lbl)

        # Buttons – kein PIN im Dialog
        bb2 = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel)
        bb2.button(QDialogButtonBox.StandardButton.Save).setText(t("cfg_save_btn"))
        bb2.button(QDialogButtonBox.StandardButton.Cancel).setText(t("cfg_cancel_btn"))
        bb2.accepted.connect(self._save_and_close)
        bb2.rejected.connect(self.reject)
        lay.addWidget(bb2)

    def _load_values(self):
        self.lib_edit.setText(self.config.get("pkcs11", "lib_path"))
        self.key_edit.setText(self.config.get("pkcs11", "key_label"))

    def _browse_lib(self):
        start = self.config.get("paths", "last_lib_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("dlg_browse_lib"), start, t("dlg_lib_filter"))
        if path:
            self.lib_edit.setText(path)
            self.config.set("paths", "last_lib_dir", str(Path(path).parent))

    def _save_and_close(self):
        self.config.set("pkcs11", "lib_path",  self.lib_edit.text().strip())
        self.config.set("pkcs11", "key_label", self.key_edit.text().strip())
        self.config.save()
        self.accept()

    def _test_token(self):
        lib_path = self.lib_edit.text().strip()
        # PIN temporär aus dem Hauptfenster holen
        pin = ""
        mw = self.parent()
        if hasattr(mw, "_pin_edit"):
            pin = mw._pin_edit.text().strip()
        self.status_lbl.setText(t("status_token_reading"))
        QApplication.processEvents()
        try:
            import pkcs11 as p11
            lib = p11.lib(lib_path)
            slots = lib.get_slots(token_present=True)
            if not slots:
                raise RuntimeError("Kein Token gefunden.")
            token = slots[0].get_token()
            with token.open(user_pin=pin if pin else None, rw=True) as session:
                keys = list(session.get_objects(
                    {p11.Attribute.CLASS: p11.ObjectClass.PRIVATE_KEY}))
                key_labels = []
                for k in keys:
                    try:   key_labels.append(k[p11.Attribute.LABEL])
                    except Exception: key_labels.append("(unknown)")
                certs = list(session.get_objects(
                    {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}))
                cert_labels = []
                for c in certs:
                    try:   cert_labels.append(c[p11.Attribute.LABEL])
                    except Exception: cert_labels.append("(no label)")

            status = t("status_token_ok",
                       label=token.label.strip(),
                       keys=len(keys), certs=len(certs))
            self.status_lbl.setText(status)

            if len(key_labels) == 1 and not self.key_edit.text().strip():
                self.key_edit.setText(key_labels[0])
                self.status_lbl.setText(
                    status + "\n" + t("dlg_token_auto_label", label=key_labels[0]))

            dlg = TokenInfoDialog(self, token, key_labels, cert_labels)
            dlg.key_selected.connect(self.key_edit.setText)
            dlg.exec()

        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self.status_lbl.setText(t("status_token_failed"))
            QMessageBox.critical(self, t("dlg_token_error_title"), str(exc))


# ══════════════════════════════════════════════════════════════
#  Signaturfeld-Darstellungs-Dialog
# ══════════════════════════════════════════════════════════════

class AppearanceConfigDialog(QDialog):
    """Konfiguriert die Darstellung des Signaturfeldes."""

    DATE_FORMATS = [
        ("%d.%m.%Y %H:%M",    "31.12.2025 14:30"),
        ("%d.%m.%Y",          "31.12.2025"),
        ("%Y-%m-%d %H:%M:%S", "2025-12-31 14:30:00"),
        ("%Y-%m-%d",          "2025-12-31"),
        ("%d/%m/%Y %H:%M",    "31/12/2025 14:30"),
        ("%B %d, %Y",         "December 31, 2025"),
    ]
    CUSTOM_FMT = "__custom__"

    def __init__(self, parent, config: AppConfig, appearance: SigAppearance,
                 selected_fdef=None):
        super().__init__(parent)
        self.config        = config
        self.appearance    = appearance
        self.selected_fdef = selected_fdef   # für Vorschau-Größe
        self.setWindowTitle(t("appdlg_title"))
        self.setMinimumSize(600, 500)
        self.resize(660, 560)
        self._build_ui()
        self._load_values()
        self._update_preview()

    # ── UI-Aufbau ─────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(4)

        # Obere Hälfte: Tabs
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, stretch=3)

        self._build_tab_image()
        self._build_tab_text()

        # Untere Hälfte: Vorschau (immer sichtbar)
        prev_grp = QGroupBox(t("appdlg_img_preview"))
        prev_lay = QVBoxLayout(prev_grp)
        prev_lay.setContentsMargins(6, 4, 6, 4)
        self.full_preview = QLabel()
        self.full_preview.setMinimumHeight(80)
        self.full_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.full_preview.setStyleSheet(
            "background: #f0f0f0; border: 1px solid #ccc;")
        prev_lay.addWidget(self.full_preview)
        root.addWidget(prev_grp, stretch=2)

        # Buttons
        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Save).setText(t("appdlg_save"))
        bb.button(QDialogButtonBox.StandardButton.Cancel).setText(t("appdlg_cancel"))
        bb.accepted.connect(self._save_and_close)
        bb.rejected.connect(self.reject)
        root.addWidget(bb)

    def _build_tab_image(self):
        """Tab: Bild + Layout (zusammengelegt)."""
        tab = QWidget()
        vl  = QVBoxLayout(tab)
        vl.setSpacing(8)

        # ── Bild-Auswahl ──────────────────────────────────────────────────
        img_grp = QGroupBox(t("appdlg_tab_image"))
        ig = QVBoxLayout(img_grp)

        img_row = QHBoxLayout()
        self.img_path_edit = QLineEdit()
        self.img_path_edit.setReadOnly(True)
        self.img_path_edit.setPlaceholderText("(kein Bild)")
        bb_btn = QPushButton(t("appdlg_img_browse")); bb_btn.setFixedWidth(36)
        bb_btn.clicked.connect(self._browse_image)
        clr = QPushButton(t("appdlg_img_clear"))
        clr.clicked.connect(self._clear_image)
        img_row.addWidget(self.img_path_edit)
        img_row.addWidget(bb_btn)
        img_row.addWidget(clr)
        ig.addLayout(img_row)

        hint = QLabel(t("appdlg_img_hint"))
        hint.setStyleSheet("color: gray; font-size: 10px;")
        ig.addWidget(hint)
        vl.addWidget(img_grp)

        # ── Layout ────────────────────────────────────────────────────────
        lay_grp = QGroupBox(t("appdlg_tab_layout"))
        lg = QFormLayout(lay_grp)
        lg.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self.layout_combo = QComboBox()
        self.layout_combo.addItem(t("app_layout_img_left"),  "img_left")
        self.layout_combo.addItem(t("app_layout_img_right"), "img_right")
        self.layout_combo.currentIndexChanged.connect(self._on_layout_changed_dlg)
        lg.addRow(t("app_layout_label"), self.layout_combo)

        self.chk_border = QCheckBox(t("appdlg_border"))
        self.chk_border.toggled.connect(self._update_preview)
        lg.addRow("", self.chk_border)

        # Schieberegler Text/Bild-Verhältnis
        ratio_row = QHBoxLayout()
        self._ratio_lbl_img  = QLabel("Bild 30%")
        self._ratio_lbl_img.setFixedWidth(60)
        self.ratio_slider = QSlider(Qt.Orientation.Horizontal)
        self.ratio_slider.setRange(10, 70)   # Bild-Anteil in %
        self.ratio_slider.setValue(40)
        self.ratio_slider.setTickInterval(10)
        self.ratio_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.ratio_slider.valueChanged.connect(self._on_ratio_changed)
        self._ratio_lbl_txt = QLabel("Text 70%")
        self._ratio_lbl_txt.setFixedWidth(60)
        ratio_row.addWidget(self._ratio_lbl_img)
        ratio_row.addWidget(self.ratio_slider)
        ratio_row.addWidget(self._ratio_lbl_txt)
        lg.addRow("Bild/Text:", ratio_row)
        vl.addWidget(lay_grp)

        vl.addStretch()
        self.tabs.addTab(tab, t("appdlg_tab_image") + " / " + t("appdlg_tab_layout"))

    def _build_tab_text(self):
        """Tab: Text-Felder mit Checkbox + Eingabe in einer Zeile."""
        tab = QWidget()
        gl  = QGridLayout(tab)
        gl.setColumnStretch(1, 1)
        gl.setSpacing(6)

        row = 0

        # ── Name ──────────────────────────────────────────────────────────
        self.chk_name = QCheckBox(t("app_name_label"))
        self.name_mode_combo = QComboBox()
        self.name_mode_combo.addItem(t("app_name_cert"), "cert")
        self.name_mode_combo.addItem("Benutzerdefiniert", "custom")
        self.name_custom_edit = QLineEdit()
        self.name_custom_edit.setPlaceholderText("Max Mustermann")
        name_row = QHBoxLayout()
        name_row.addWidget(self.name_mode_combo)
        name_row.addWidget(self.name_custom_edit)
        gl.addWidget(self.chk_name,         row, 0)
        gl.addLayout(name_row,              row, 1)
        row += 1

        # ── Ort ───────────────────────────────────────────────────────────
        self.chk_location = QCheckBox(t("app_location_label"))
        self.location_edit = QLineEdit()
        gl.addWidget(self.chk_location, row, 0)
        gl.addWidget(self.location_edit, row, 1)
        row += 1

        # ── Grund ─────────────────────────────────────────────────────────
        self.chk_reason = QCheckBox(t("app_reason_label"))
        self.reason_edit = QLineEdit()
        gl.addWidget(self.chk_reason, row, 0)
        gl.addWidget(self.reason_edit, row, 1)
        row += 1

        # ── Datum ─────────────────────────────────────────────────────────
        self.chk_date = QCheckBox(t("app_date_label"))
        date_col = QVBoxLayout()
        self.date_fmt_combo = QComboBox()
        for fmt, example in self.DATE_FORMATS:
            self.date_fmt_combo.addItem(f"{fmt}  →  {example}", fmt)
        self.date_fmt_combo.addItem("Benutzerdefiniert…", self.CUSTOM_FMT)
        self.date_fmt_combo.currentIndexChanged.connect(self._on_date_fmt_changed)
        self.date_fmt_custom = QLineEdit()
        self.date_fmt_custom.setPlaceholderText("%d.%m.%Y %H:%M")
        self.date_fmt_custom.setVisible(False)
        self.date_fmt_custom.textChanged.connect(self._update_preview)
        date_col.addWidget(self.date_fmt_combo)
        date_col.addWidget(self.date_fmt_custom)
        gl.addWidget(self.chk_date, row, 0)
        gl.addLayout(date_col,      row, 1)
        row += 1

        # ── Schriftgröße ──────────────────────────────────────────────────
        lbl_font = QLabel(t("appdlg_font_size"))
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(5, 24)
        self.font_size_spin.valueChanged.connect(self._update_preview)
        gl.addWidget(lbl_font,          row, 0)
        gl.addWidget(self.font_size_spin, row, 1, alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        gl.setRowStretch(row, 1)

        # Checkboxen steuern Aktivierung der Eingabefelder
        self.chk_name.toggled.connect(self._on_checks_changed)
        self.chk_location.toggled.connect(self._on_checks_changed)
        self.chk_reason.toggled.connect(self._on_checks_changed)
        self.chk_date.toggled.connect(self._on_checks_changed)
        # Textänderungen → Vorschau
        for w in (self.location_edit, self.reason_edit,
                  self.name_custom_edit):
            w.textChanged.connect(self._update_preview)
        self.name_mode_combo.currentIndexChanged.connect(self._on_checks_changed)

        self.tabs.addTab(tab, t("appdlg_tab_text"))

    # ── Slots ─────────────────────────────────────────────────────────────

    def _on_checks_changed(self):
        """Eingabefelder ausgrauen wenn Checkbox deaktiviert oder Modus Zertifikat."""
        name_on = self.chk_name.isChecked()
        self.name_mode_combo.setEnabled(name_on)
        # Freitextfeld nur aktiv wenn Checkbox AN und Modus "custom"
        self.name_custom_edit.setEnabled(
            name_on and self.name_mode_combo.currentData() == "custom")
        self.location_edit.setEnabled(self.chk_location.isChecked())
        self.reason_edit.setEnabled(self.chk_reason.isChecked())
        self.date_fmt_combo.setEnabled(self.chk_date.isChecked())
        self.date_fmt_custom.setEnabled(self.chk_date.isChecked())
        self._update_preview()

    def _on_layout_changed_dlg(self):
        self._update_ratio_labels()
        self._update_preview()

    def _on_date_fmt_changed(self):
        is_custom = self.date_fmt_combo.currentData() == self.CUSTOM_FMT
        self.date_fmt_custom.setVisible(is_custom)
        self._update_preview()

    def _on_ratio_changed(self, value: int):
        self._update_ratio_labels(value)
        self._update_preview()

    def _update_ratio_labels(self, value: int = None):
        if value is None:
            value = self.ratio_slider.value()
        layout = self.layout_combo.currentData() or "img_left"
        if layout == "img_left":
            self._ratio_lbl_img.setText(f"◀ Bild {value}%")
            self._ratio_lbl_txt.setText(f"Text {100-value}% ▶")
        else:
            self._ratio_lbl_img.setText(f"◀ Text {100-value}%")
            self._ratio_lbl_txt.setText(f"Bild {value}% ▶")

    def _browse_image(self):
        start = self.config.get("paths", "last_img_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("appdlg_browse_img"), start, t("appdlg_img_filter"))
        if path:
            self.img_path_edit.setText(path)
            self.config.set("paths", "last_img_dir", str(Path(path).parent))
            self._update_img_preview()
            self._update_preview()

    def _clear_image(self):
        self.img_path_edit.clear()
        self.img_preview.clear()
        self.img_preview.setText("(kein Bild)")
        self._update_preview()

    def _update_img_preview(self):
        pass  # Kleine Vorschau entfernt – Vollvorschau unten genügt

    def _update_preview(self):
        """Rendert die Vorschau – Größe aus selektiertem Signaturfeld."""
        self._apply_to_config(save=False)
        fdef = self.selected_fdef
        if fdef is None:
            self.full_preview.clear()
            self.full_preview.setText(
                "Für Vorschau bitte Signaturfeld einfügen.")
            self.full_preview.setStyleSheet(
                "background: #f0f0f0; border: 1px solid #ccc; color: gray;")
            return
        # Seitenverhältnis des Feldes beibehalten, in verfügbare Fläche einpassen
        fw = abs(fdef.x2 - fdef.x1)
        fh = abs(fdef.y2 - fdef.y1)
        avail_w = max(10, self.full_preview.width()  - 4)
        avail_h = max(10, self.full_preview.height() - 4)
        scale   = min(avail_w / max(fw, 1), avail_h / max(fh, 1))
        pw = max(10, int(fw * scale))
        ph = max(10, int(fh * scale))
        px = self.appearance.render_preview(pw, ph,
            pixels_per_point=DPI_SCALE * scale)
        # Ins Label einpassen (zentriert mit grauem Hintergrund)
        canvas = QPixmap(avail_w, avail_h)
        canvas.fill(QColor("#f0f0f0"))
        from PyQt6.QtGui import QPainter as _P
        p = _P(canvas)
        ox = (avail_w - pw) // 2
        oy = (avail_h - ph) // 2
        p.drawPixmap(ox, oy, px)
        p.end()
        self.full_preview.setPixmap(canvas)
        self.full_preview.setStyleSheet(
            "background: #f0f0f0; border: 1px solid #ccc;")

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        self._update_preview()

    # ── Werte laden / speichern ───────────────────────────────────────────

    def _date_fmt_value(self) -> str:
        """Gibt das aktuell gewählte Datumsformat zurück."""
        if self.date_fmt_combo.currentData() == self.CUSTOM_FMT:
            return self.date_fmt_custom.text().strip() or "%d.%m.%Y %H:%M"
        return self.date_fmt_combo.currentData() or "%d.%m.%Y %H:%M"

    def _load_values(self):
        # Bild
        self.img_path_edit.setText(self.config.get("appearance", "image_path"))
        self._update_img_preview()

        # Layout
        idx = self.layout_combo.findData(self.config.get("appearance", "layout"))
        self.layout_combo.setCurrentIndex(max(0, idx))
        self.chk_border.setChecked(self.config.getbool("appearance", "show_border"))

        # Ratio
        try:
            ratio = int(self.config.get("appearance", "img_ratio") or "40")
        except ValueError:
            ratio = 40
        self.ratio_slider.setValue(max(10, min(70, ratio)))
        self._update_ratio_labels(max(10, min(70, ratio)))

        # Text-Felder
        self.chk_name.setChecked(self.config.getbool("appearance", "show_name"))
        nm_idx = self.name_mode_combo.findData(
            self.config.get("appearance", "name_mode"))
        self.name_mode_combo.setCurrentIndex(max(0, nm_idx))
        self.name_custom_edit.setText(self.config.get("appearance", "name_custom"))

        self.chk_location.setChecked(self.config.getbool("appearance", "show_location"))
        self.location_edit.setText(self.config.get("appearance", "location"))

        self.chk_reason.setChecked(self.config.getbool("appearance", "show_reason"))
        self.reason_edit.setText(self.config.get("appearance", "reason"))

        self.chk_date.setChecked(self.config.getbool("appearance", "show_date"))
        saved_fmt = self.config.get("appearance", "date_format") or "%d.%m.%Y %H:%M"
        fmt_idx = self.date_fmt_combo.findData(saved_fmt)
        if fmt_idx >= 0:
            self.date_fmt_combo.setCurrentIndex(fmt_idx)
        else:
            # Benutzerdefiniert
            custom_idx = self.date_fmt_combo.findData(self.CUSTOM_FMT)
            self.date_fmt_combo.setCurrentIndex(custom_idx)
            self.date_fmt_custom.setText(saved_fmt)
            self.date_fmt_custom.setVisible(True)

        try:
            fs = int(self.config.get("appearance", "font_size") or "8")
        except (ValueError, TypeError):
            fs = 8
        self.font_size_spin.setValue(max(5, min(24, fs)))

        # Aktivierungszustand der Felder aktualisieren + Vorschau
        self._on_checks_changed()

    def _apply_to_config(self, save: bool = True):
        self.config.set("appearance", "image_path",
                        self.img_path_edit.text().strip())
        self.config.set("appearance", "layout",
                        self.layout_combo.currentData())
        self.config.setbool("appearance", "show_border",
                             self.chk_border.isChecked())
        self.config.set("appearance", "img_ratio",
                        str(self.ratio_slider.value()))
        self.config.setbool("appearance", "show_name",
                             self.chk_name.isChecked())
        self.config.set("appearance", "name_mode",
                        self.name_mode_combo.currentData())
        self.config.set("appearance", "name_custom",
                        self.name_custom_edit.text().strip())
        self.config.setbool("appearance", "show_location",
                             self.chk_location.isChecked())
        self.config.set("appearance", "location",
                        self.location_edit.text().strip())
        self.config.setbool("appearance", "show_reason",
                             self.chk_reason.isChecked())
        self.config.set("appearance", "reason",
                        self.reason_edit.text().strip())
        self.config.setbool("appearance", "show_date",
                             self.chk_date.isChecked())
        self.config.set("appearance", "date_format",
                        self._date_fmt_value())
        self.config.set("appearance", "font_size",
                        str(self.font_size_spin.value()))
        if save:
            self.config.save()

    def _save_and_close(self):
        self._apply_to_config(save=True)
        self.accept()


# ══════════════════════════════════════════════════════════════
#  PDF-Viewer Widget
# ══════════════════════════════════════════════════════════════

class PDFViewWidget(QWidget):
    ZOOM = 1.5

    field_added   = pyqtSignal(object)
    field_deleted = pyqtSignal(object)

    def __init__(self, appearance: SigAppearance, parent=None):
        super().__init__(parent)
        self.appearance = appearance
        self.setCursor(Qt.CursorShape.CrossCursor)
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        self._pixmap: Optional[QPixmap] = None
        self._page_w = self._page_h = 1.0
        self._img_w  = self._img_h  = 1
        self._drag_start: Optional[QPointF] = None
        self._drag_end:   Optional[QPointF] = None
        self._sig_fields: list[SignatureFieldDef] = []
        self._current_page = 0

    def set_page(self, page: fitz.Page, sig_fields: list, current_page: int):
        mat = fitz.Matrix(self.ZOOM, self.ZOOM)
        pix = page.get_pixmap(matrix=mat, alpha=False)
        img = QImage(pix.samples, pix.width, pix.height,
                     pix.stride, QImage.Format.Format_RGB888)
        self._pixmap     = QPixmap.fromImage(img)
        self._img_w      = pix.width
        self._img_h      = pix.height
        self._page_w     = page.rect.width
        self._page_h     = page.rect.height
        self._sig_fields = sig_fields
        self._current_page = current_page
        self.setFixedSize(pix.width, pix.height)
        self.update()

    def refresh(self):
        """Neuzeichnen der Felder (z. B. nach Erscheinungsänderung)."""
        self.update()

    # ── Koordinaten ───────────────────────────────────────
    def _pdf_to_w(self, x, y):
        sx = self._img_w / self._page_w
        sy = self._img_h / self._page_h
        return QPointF(x * sx, (self._page_h - y) * sy)

    def _w_to_pdf(self, cx, cy):
        sx = self._img_w / self._page_w
        sy = self._img_h / self._page_h
        return cx / sx, self._page_h - (cy / sy)

    # ── Paint ─────────────────────────────────────────────
    def paintEvent(self, _):
        painter = QPainter(self)
        if self._pixmap:
            painter.drawPixmap(0, 0, self._pixmap)

        for fdef in self._sig_fields:
            if fdef.page != self._current_page:
                continue
            tl = self._pdf_to_w(fdef.x1, fdef.y2)
            br = self._pdf_to_w(fdef.x2, fdef.y1)
            rect = QRectF(tl, br).normalized()
            w, h = int(rect.width()), int(rect.height())
            if w > 4 and h > 4:
                px = self.appearance.render_preview(w, h,
                    pixels_per_point=self.ZOOM)
                painter.drawPixmap(rect.toRect(), px)
            # Feldname-Label oben links
            painter.setPen(QPen(QColor("#1a73e8")))
            painter.setFont(QFont("Arial", 7))
            painter.drawText(
                QPointF(rect.left() + 2, rect.top() + 10), fdef.name)

        # Drag-Vorschau
        if self._drag_start and self._drag_end:
            pen = QPen(QColor("#1a73e8"), 2, Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.setBrush(QBrush(QColor(208, 228, 255, 40)))
            painter.drawRect(
                QRectF(self._drag_start, self._drag_end).normalized())

        painter.end()

    # ── Maus ──────────────────────────────────────────────
    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.LeftButton:
            self._drag_start = QPointF(ev.position())
            self._drag_end   = None
        elif ev.button() == Qt.MouseButton.RightButton:
            self._right_click(ev.position())

    def mouseMoveEvent(self, ev):
        if self._drag_start:
            self._drag_end = QPointF(ev.position())
            self.update()

    def mouseReleaseEvent(self, ev):
        if ev.button() != Qt.MouseButton.LeftButton or not self._drag_start:
            return
        end = QPointF(ev.position())
        x0, y0 = self._drag_start.x(), self._drag_start.y()
        x1, y1 = end.x(), end.y()
        self._drag_start = self._drag_end = None
        self.update()

        if abs(x1 - x0) < 20 or abs(y1 - y0) < 10:
            return

        px0, py0 = self._w_to_pdf(min(x0, x1), min(y0, y1))
        px1, py1 = self._w_to_pdf(max(x0, x1), max(y0, y1))
        count = sum(1 for f in self._sig_fields if f.page == self._current_page)
        default = t("dlg_field_name_default",
                    page=self._current_page + 1, count=count + 1)
        name, ok = QInputDialog.getText(
            self, t("dlg_field_name_title"), t("dlg_field_name_prompt"),
            text=default)
        if not ok or not name:
            return
        fdef = SignatureFieldDef(self._current_page, px0, py0, px1, py1, name)
        self._sig_fields.append(fdef)
        self.update()
        self.field_added.emit(fdef)

    def _right_click(self, pos: QPointF):
        cx, cy = pos.x(), pos.y()
        for fdef in reversed(self._sig_fields):
            if fdef.page != self._current_page:
                continue
            tl = self._pdf_to_w(fdef.x1, fdef.y2)
            br = self._pdf_to_w(fdef.x2, fdef.y1)
            if QRectF(tl, br).normalized().contains(cx, cy):
                if QMessageBox.question(
                    self, t("dlg_delete_title"),
                    t("dlg_delete_msg", name=fdef.name)
                ) == QMessageBox.StandardButton.Yes:
                    self._sig_fields.remove(fdef)
                    self.update()
                    self.field_deleted.emit(fdef)
                return


# ══════════════════════════════════════════════════════════════
#  Haupt-Fenster
# ══════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):

    def __init__(self, config: AppConfig, initial_pdf: Optional[str] = None):
        super().__init__()
        self.config     = config
        self.appearance = SigAppearance(config)
        self.pdf_doc:   Optional[fitz.Document] = None
        self.pdf_path   = ""
        self.current_page = 0
        self.sig_fields: list[SignatureFieldDef] = []
        self._worker = self._sign_worker = None

        self._build_ui()
        self._apply_language()
        self.statusBar().showMessage(t("status_ready"))
        self._check_dependencies()

        if initial_pdf:
            self._open_pdf(initial_pdf)

    # ── UI aufbauen ────────────────────────────────────────

    def _build_ui(self):
        self.setMinimumSize(980, 660)
        self.resize(1340, 840)

        # ── Menüleiste ──────────────────────────────────
        self._menu_file = self.menuBar().addMenu("")
        self._act_open  = QAction(self); self._act_open.setShortcut(QKeySequence.StandardKey.Open)
        self._act_open.triggered.connect(self.open_pdf)
        self._menu_file.addAction(self._act_open)
        self._act_save_fields = QAction(self)
        self._act_save_fields.triggered.connect(self.save_with_fields)
        self._menu_file.addAction(self._act_save_fields)
        self._menu_file.addSeparator()
        self._act_quit = QAction(self); self._act_quit.setShortcut(QKeySequence.StandardKey.Quit)
        self._act_quit.triggered.connect(self.close)
        self._menu_file.addAction(self._act_quit)

        self._menu_sign = self.menuBar().addMenu("")
        self._act_sign = QAction(self)
        self._act_sign.triggered.connect(self.sign_document)
        self._menu_sign.addAction(self._act_sign)

        self._menu_settings = self.menuBar().addMenu("")
        self._act_pkcs11 = QAction(self)
        self._act_pkcs11.triggered.connect(self.open_pkcs11_config)
        self._menu_settings.addAction(self._act_pkcs11)
        self._act_appearance = QAction(self)
        self._act_appearance.triggered.connect(self.open_appearance_config)
        self._menu_settings.addAction(self._act_appearance)

        self._menu_lang = self.menuBar().addMenu("")    # wird in _apply_language gesetzt
        self._lang_actions: dict[str, QAction] = {}
        for code, label in AVAILABLE_LANGUAGES.items():
            act = QAction(label, self); act.setCheckable(True)
            act.setChecked(code == i18n.lang)
            act.triggered.connect(lambda _, c=code: self._set_language(c))
            self._lang_actions[code] = act
            self._menu_lang.addAction(act)
        self._menu_settings.addMenu(self._menu_lang)

        self._menu_help = self.menuBar().addMenu("")
        self._act_about = QAction(self)
        self._act_about.triggered.connect(self._show_about)
        self._menu_help.addAction(self._act_about)

        # ── Toolbar ─────────────────────────────────────
        tb = self.addToolBar("main"); tb.setMovable(False)
        self._tb_open = QAction(self); self._tb_open.triggered.connect(self.open_pdf)
        tb.addAction(self._tb_open)
        tb.addSeparator()
        self._tb_prev = QAction(self); self._tb_prev.triggered.connect(self.prev_page)
        tb.addAction(self._tb_prev)
        self._page_label = QLabel("  –/–  ")
        self._page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._page_label.setMinimumWidth(70)
        tb.addWidget(self._page_label)
        self._tb_next = QAction(self); self._tb_next.triggered.connect(self.next_page)
        tb.addAction(self._tb_next)
        tb.addSeparator()
        self._tb_sign = QAction(self); self._tb_sign.triggered.connect(self.sign_document)
        tb.addAction(self._tb_sign)
        self._tb_save_fields = QAction(self)
        self._tb_save_fields.triggered.connect(self.save_with_fields)
        tb.addAction(self._tb_save_fields)

        # ── Zentraler Splitter ───────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(splitter)

        scroll = QScrollArea()
        scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        scroll.setStyleSheet("QScrollArea { background: #404040; }")
        self._pdf_view = PDFViewWidget(self.appearance)
        self._pdf_view.field_added.connect(self._on_field_added)
        self._pdf_view.field_deleted.connect(self._on_field_deleted)
        scroll.setWidget(self._pdf_view)
        scroll.setWidgetResizable(False)
        splitter.addWidget(scroll)

        # ── Rechtes Panel ────────────────────────────────
        right = QWidget(); right.setMinimumWidth(240); right.setMaximumWidth(310)
        rl = QVBoxLayout(right); rl.setContentsMargins(4, 4, 4, 4); rl.setSpacing(6)

        # Signaturfelder-Liste
        self._fields_group = QGroupBox()
        fl = QVBoxLayout(self._fields_group)
        self._field_list = QListWidget()
        self._field_list.setFont(QFont("Courier", 9))
        self._field_list.currentRowChanged.connect(
            lambda _: self._ap_update_preview())
        fl.addWidget(self._field_list)
        btn_row = QHBoxLayout()
        self._btn_delete = QPushButton(); self._btn_delete.clicked.connect(self.delete_selected_field)
        self._btn_save   = QPushButton(); self._btn_save.clicked.connect(self.save_with_fields)
        btn_row.addWidget(self._btn_delete); btn_row.addWidget(self._btn_save)
        fl.addLayout(btn_row)
        rl.addWidget(self._fields_group)

        # Token / PIN
        self._token_group = QGroupBox()
        tl2 = QFormLayout(self._token_group)
        tl2.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        self._pin_edit = QLineEdit()
        self._pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pin_lbl_widget = QLabel()
        tl2.addRow(self._pin_lbl_widget, self._pin_edit)
        self._pin_hint_lbl = QLabel()
        self._pin_hint_lbl.setStyleSheet("color: gray; font-size: 10px;")
        tl2.addRow("", self._pin_hint_lbl)
        rl.addWidget(self._token_group)

        # Signatur-Erscheinung – vollständige Tab-UI direkt im Hauptfenster
        self._app_group = QGroupBox()
        ag = QVBoxLayout(self._app_group)
        ag.setContentsMargins(4, 4, 4, 4)
        ag.setSpacing(4)
        self._app_tabs = QTabWidget()
        self._app_tabs.setTabPosition(QTabWidget.TabPosition.North)
        ag.addWidget(self._app_tabs, stretch=2)

        self._build_appearance_tabs()
        rl.addWidget(self._app_group, stretch=1)
        rl.addStretch()

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 1)

        # Werte aus Config laden
        self._load_appearance_panel()

    # ── Sprachunterstützung ────────────────────────────────

    def _set_language(self, code: str):
        i18n.lang = code
        self.config.set("app", "language", code)
        self.config.save()
        for c, act in self._lang_actions.items():
            act.setChecked(c == code)
        self._apply_language()

    def _apply_language(self):
        self.setWindowTitle("PDF QES Signer")
        self._menu_file.setTitle(t("menu_file"))
        self._act_open.setText(t("menu_file_open"))
        self._act_save_fields.setText(t("menu_file_save_fields"))
        self._act_quit.setText(t("menu_file_quit"))
        self._menu_sign.setTitle(t("menu_sign"))
        self._act_sign.setText(t("menu_sign_document"))
        self._menu_settings.setTitle(t("menu_settings"))
        self._act_pkcs11.setText(t("menu_settings_pkcs11"))
        self._act_appearance.setText(t("menu_settings_appearance"))
        self._menu_lang.setTitle(t("menu_settings_language"))
        self._menu_help.setTitle(t("menu_help"))
        self._act_about.setText(t("menu_help_about"))
        self._tb_open.setText(t("tb_open"))
        self._tb_prev.setText(t("tb_prev"))
        self._tb_next.setText(t("tb_next"))
        self._tb_sign.setText(t("tb_sign"))
        self._tb_save_fields.setText(t("tb_save_fields"))
        self._fields_group.setTitle(t("panel_fields"))
        self._btn_delete.setText(t("btn_delete_field"))
        self._btn_save.setText(t("btn_save_fields"))
        self._token_group.setTitle(t("panel_token"))
        self._pin_lbl_widget.setText(t("pin_label"))
        self._pin_hint_lbl.setText(t("pin_hint"))
        self._app_group.setTitle(t("panel_appearance"))

    DATE_FORMATS = [
        ("%d.%m.%Y %H:%M",    "31.12.2025 14:30"),
        ("%d.%m.%Y",          "31.12.2025"),
        ("%Y-%m-%d %H:%M:%S", "2025-12-31 14:30:00"),
        ("%Y-%m-%d",          "2025-12-31"),
        ("%d/%m/%Y %H:%M",    "31/12/2025 14:30"),
        ("%B %d, %Y",         "December 31, 2025"),
    ]
    CUSTOM_FMT = "__custom__"

    def _build_appearance_tabs(self):
        """Baut die zwei Tabs (Text / Bild+Layout) im rechten Panel."""

        # ── Tab 1: Text ───────────────────────────────────────────────────
        txt_tab = QWidget()
        gl = QGridLayout(txt_tab)
        gl.setColumnStretch(1, 1)
        gl.setSpacing(4)
        gl.setContentsMargins(4, 4, 4, 4)
        row = 0

        # Name
        self._ap_chk_name = QCheckBox("Name")
        self._ap_name_mode = QComboBox()
        self._ap_name_mode.addItem("Aus Zertifikat", "cert")
        self._ap_name_mode.addItem("Benutzerdefiniert", "custom")
        self._ap_name_custom = QLineEdit()
        self._ap_name_custom.setPlaceholderText("Max Mustermann")
        name_row = QHBoxLayout(); name_row.setSpacing(3)
        name_row.addWidget(self._ap_name_mode)
        name_row.addWidget(self._ap_name_custom)
        gl.addWidget(self._ap_chk_name, row, 0)
        gl.addLayout(name_row,          row, 1); row += 1

        # Ort
        self._ap_chk_loc = QCheckBox("Ort")
        self._ap_loc = QLineEdit()
        gl.addWidget(self._ap_chk_loc, row, 0)
        gl.addWidget(self._ap_loc,     row, 1); row += 1

        # Grund
        self._ap_chk_reason = QCheckBox("Grund")
        self._ap_reason = QLineEdit()
        gl.addWidget(self._ap_chk_reason, row, 0)
        gl.addWidget(self._ap_reason,     row, 1); row += 1

        # Datum
        self._ap_chk_date = QCheckBox("Datum")
        date_vl = QVBoxLayout(); date_vl.setSpacing(2)
        self._ap_date_combo = QComboBox()
        for fmt, ex in self.DATE_FORMATS:
            self._ap_date_combo.addItem(f"{fmt}  →  {ex}", fmt)
        self._ap_date_combo.addItem("Benutzerdefiniert…", self.CUSTOM_FMT)
        self._ap_date_custom = QLineEdit()
        self._ap_date_custom.setPlaceholderText("%d.%m.%Y %H:%M")
        self._ap_date_custom.setVisible(False)
        date_vl.addWidget(self._ap_date_combo)
        date_vl.addWidget(self._ap_date_custom)
        gl.addWidget(self._ap_chk_date, row, 0)
        gl.addLayout(date_vl,           row, 1); row += 1

        # Schriftgröße
        self._ap_font_spin = QSpinBox()
        self._ap_font_spin.setRange(5, 24)
        gl.addWidget(QLabel("Schrift (pt):"), row, 0)
        gl.addWidget(self._ap_font_spin,      row, 1,
                     alignment=Qt.AlignmentFlag.AlignLeft); row += 1

        self._ap_font_combo = QComboBox()
        for disp, pdf_name, _, _ in PDF_STANDARD_FONTS:
            self._ap_font_combo.addItem(disp, pdf_name)
        gl.addWidget(QLabel("Schriftart:"), row, 0)
        gl.addWidget(self._ap_font_combo,    row, 1); row += 1
        gl.setRowStretch(row, 1)

        self._app_tabs.addTab(txt_tab, "Text")

        # ── Tab 2: Bild / Layout ──────────────────────────────────────────
        img_tab = QWidget()
        vl = QVBoxLayout(img_tab)
        vl.setContentsMargins(4, 4, 4, 4)
        vl.setSpacing(6)

        # Bildpfad
        img_row = QHBoxLayout(); img_row.setSpacing(3)
        self._ap_img_path = QLineEdit()
        self._ap_img_path.setReadOnly(True)
        self._ap_img_path.setPlaceholderText("(kein Bild)")
        bb_btn = QPushButton("…"); bb_btn.setFixedWidth(28)
        bb_btn.clicked.connect(self._ap_browse_image)
        clr_btn = QPushButton("Entfernen")
        clr_btn.clicked.connect(self._ap_clear_image)
        img_row.addWidget(self._ap_img_path)
        img_row.addWidget(bb_btn)
        img_row.addWidget(clr_btn)
        vl.addLayout(img_row)

        hint = QLabel("Transparenz wird unterstützt.")
        hint.setStyleSheet("color:gray; font-size:10px;")
        vl.addWidget(hint)

        # Layout-Combo
        lay_row = QHBoxLayout()
        lay_row.addWidget(QLabel("Anordnung:"))
        self._ap_layout = QComboBox()
        self._ap_layout.addItem("Bild links",  "img_left")
        self._ap_layout.addItem("Bild rechts", "img_right")
        lay_row.addWidget(self._ap_layout)
        vl.addLayout(lay_row)

        # Rahmen
        self._ap_border = QCheckBox("Rahmen anzeigen")
        vl.addWidget(self._ap_border)

        # Schieberegler Bild/Text-Verhältnis
        ratio_row = QHBoxLayout()
        self._ap_ratio_lbl_l = QLabel("◀ Bild 40%")
        self._ap_ratio_lbl_l.setFixedWidth(72)
        self._ap_ratio = QSlider(Qt.Orientation.Horizontal)
        self._ap_ratio.setRange(10, 70)
        self._ap_ratio.setValue(40)
        self._ap_ratio.setTickInterval(10)
        self._ap_ratio.setTickPosition(QSlider.TickPosition.TicksBelow)
        self._ap_ratio_lbl_r = QLabel("Text 60% ▶")
        self._ap_ratio_lbl_r.setFixedWidth(72)
        ratio_row.addWidget(self._ap_ratio_lbl_l)
        ratio_row.addWidget(self._ap_ratio)
        ratio_row.addWidget(self._ap_ratio_lbl_r)
        vl.addLayout(ratio_row)
        vl.addStretch()

        self._app_tabs.addTab(img_tab, "Bild / Layout")

        # ── Signale ───────────────────────────────────────────────────────
        for chk in (self._ap_chk_name, self._ap_chk_loc,
                    self._ap_chk_reason, self._ap_chk_date):
            chk.toggled.connect(self._ap_on_checks)

        self._ap_name_mode.currentIndexChanged.connect(self._ap_on_checks)
        self._ap_date_combo.currentIndexChanged.connect(self._ap_on_date_fmt)

        for w in (self._ap_loc, self._ap_reason, self._ap_name_custom,
                  self._ap_date_custom):
            w.textChanged.connect(self._ap_save_and_refresh)

        self._ap_font_spin.valueChanged.connect(self._ap_save_and_refresh)
        self._ap_font_combo.currentIndexChanged.connect(self._ap_save_and_refresh)
        self._ap_layout.currentIndexChanged.connect(self._ap_on_layout)
        self._ap_border.toggled.connect(self._ap_save_and_refresh)
        self._ap_ratio.valueChanged.connect(self._ap_on_ratio)

    # ── Slots für eingebettetes Erscheinungs-Panel ─────────────────────────

    def _ap_on_checks(self):
        name_on = self._ap_chk_name.isChecked()
        self._ap_name_mode.setEnabled(name_on)
        self._ap_name_custom.setEnabled(
            name_on and self._ap_name_mode.currentData() == "custom")
        self._ap_loc.setEnabled(self._ap_chk_loc.isChecked())
        self._ap_reason.setEnabled(self._ap_chk_reason.isChecked())
        self._ap_date_combo.setEnabled(self._ap_chk_date.isChecked())
        self._ap_date_custom.setEnabled(self._ap_chk_date.isChecked())
        self._ap_save_and_refresh()

    def _ap_on_date_fmt(self):
        is_custom = self._ap_date_combo.currentData() == self.CUSTOM_FMT
        self._ap_date_custom.setVisible(is_custom)
        self._ap_save_and_refresh()

    def _ap_on_layout(self):
        """Layout geändert: Slider-Richtung und Labels anpassen."""
        val = self._ap_layout.currentData() or "img_left"
        img_right = (val == "img_right")
        # Slider invertieren: bei Bild-rechts bedeutet rechts = weniger Bild
        self._ap_ratio.setInvertedAppearance(img_right)
        self._ap_update_ratio_labels()
        self._ap_save_and_refresh()

    def _ap_on_ratio(self, _v: int):
        self._ap_update_ratio_labels()
        self._ap_save_and_refresh()

    def _ap_update_ratio_labels(self):
        val = self._ap_layout.currentData() or "img_left"
        v   = self._ap_ratio.value()
        if val == "img_left":
            self._ap_ratio_lbl_l.setText(f"◀ Bild {v}%")
            self._ap_ratio_lbl_r.setText(f"Text {100-v}% ▶")
        else:
            # Slider ist invertiert: links = hoher Wert (viel Text), rechts = wenig Text
            self._ap_ratio_lbl_l.setText(f"Text {100-v}% ▶")
            self._ap_ratio_lbl_r.setText(f"◀ Bild {v}%")

    def _ap_browse_image(self):
        start = self.config.get("paths", "last_img_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, "Signaturbild wählen", start,
            "Bilder (*.png *.jpg *.jpeg *.bmp);;Alle Dateien (*)")
        if path:
            self._ap_img_path.setText(path)
            self.config.set("paths", "last_img_dir", str(Path(path).parent))
            self._ap_save_and_refresh()

    def _ap_clear_image(self):
        self._ap_img_path.clear()
        self._ap_save_and_refresh()

    def _ap_date_fmt_value(self) -> str:
        if self._ap_date_combo.currentData() == self.CUSTOM_FMT:
            return self._ap_date_custom.text().strip() or "%d.%m.%Y %H:%M"
        return self._ap_date_combo.currentData() or "%d.%m.%Y %H:%M"

    def _ap_save_and_refresh(self):
        """Schreibt alle Erscheinungs-Werte in Config und aktualisiert Vorschau."""
        cfg = self.config
        cfg.set("appearance", "image_path",   self._ap_img_path.text().strip())
        cfg.set("appearance", "layout",       self._ap_layout.currentData() or "img_left")
        cfg.setbool("appearance", "show_border",  self._ap_border.isChecked())
        cfg.set("appearance", "img_ratio",    str(self._ap_ratio.value()))
        cfg.setbool("appearance", "show_name",    self._ap_chk_name.isChecked())
        cfg.set("appearance", "name_mode",    self._ap_name_mode.currentData() or "cert")
        cfg.set("appearance", "name_custom",  self._ap_name_custom.text().strip())
        cfg.setbool("appearance", "show_location", self._ap_chk_loc.isChecked())
        cfg.set("appearance", "location",     self._ap_loc.text().strip())
        cfg.setbool("appearance", "show_reason",  self._ap_chk_reason.isChecked())
        cfg.set("appearance", "reason",       self._ap_reason.text().strip())
        cfg.setbool("appearance", "show_date",    self._ap_chk_date.isChecked())
        cfg.set("appearance", "date_format",  self._ap_date_fmt_value())
        cfg.set("appearance", "font_size",    str(self._ap_font_spin.value()))
        cfg.set("appearance", "font_family",  self._ap_font_combo.currentData() or "Helvetica")
        cfg.save()
        self._pdf_view.refresh()
        self._ap_update_preview()

    def _ap_update_preview(self):
        pass  # Vorschau entfernt – Signaturfeld im PDF-Canvas zeigt Vorschau


    # ── Erscheinungs-Panel laden ──────────────────────────

    def _load_appearance_panel(self):
        """Lädt Config-Werte in die eingebetteten Appearance-Widgets."""
        cfg = self.config

        # Alle Signale blockieren während dem Laden
        widgets = [self._ap_chk_name, self._ap_name_mode, self._ap_name_custom,
                   self._ap_chk_loc, self._ap_loc, self._ap_chk_reason, self._ap_reason,
                   self._ap_chk_date, self._ap_date_combo, self._ap_date_custom,
                   self._ap_font_spin, self._ap_font_combo, self._ap_img_path,
                   self._ap_layout, self._ap_border, self._ap_ratio]
        for w in widgets:
            w.blockSignals(True)

        # Text-Tab
        self._ap_chk_name.setChecked(cfg.getbool("appearance", "show_name"))
        nm_idx = self._ap_name_mode.findData(cfg.get("appearance", "name_mode"))
        self._ap_name_mode.setCurrentIndex(max(0, nm_idx))
        self._ap_name_custom.setText(cfg.get("appearance", "name_custom"))

        self._ap_chk_loc.setChecked(cfg.getbool("appearance", "show_location"))
        self._ap_loc.setText(cfg.get("appearance", "location"))

        self._ap_chk_reason.setChecked(cfg.getbool("appearance", "show_reason"))
        self._ap_reason.setText(cfg.get("appearance", "reason"))

        self._ap_chk_date.setChecked(cfg.getbool("appearance", "show_date"))
        saved_fmt = cfg.get("appearance", "date_format") or "%d.%m.%Y %H:%M"
        fmt_idx   = self._ap_date_combo.findData(saved_fmt)
        if fmt_idx >= 0:
            self._ap_date_combo.setCurrentIndex(fmt_idx)
        else:
            custom_idx = self._ap_date_combo.findData(self.CUSTOM_FMT)
            self._ap_date_combo.setCurrentIndex(custom_idx)
            self._ap_date_custom.setText(saved_fmt)
            self._ap_date_custom.setVisible(True)

        try:
            fs = int(cfg.get("appearance", "font_size") or "8")
        except (ValueError, TypeError):
            fs = 8
        self._ap_font_spin.setValue(max(5, min(24, fs)))
        ff = cfg.get("appearance", "font_family") or "Helvetica"
        ff_idx = self._ap_font_combo.findData(ff)
        self._ap_font_combo.setCurrentIndex(max(0, ff_idx))

        # Bild/Layout-Tab
        self._ap_img_path.setText(cfg.get("appearance", "image_path"))

        lay_idx = self._ap_layout.findData(cfg.get("appearance", "layout"))
        self._ap_layout.setCurrentIndex(max(0, lay_idx))

        self._ap_border.setChecked(cfg.getbool("appearance", "show_border"))

        try:
            ratio = int(cfg.get("appearance", "img_ratio") or "40")
        except (ValueError, TypeError):
            ratio = 40
        self._ap_ratio.setValue(max(10, min(70, ratio)))
        # Slider-Richtung nach geladenem Layout setzen
        lay = self._ap_layout.currentData() or "img_left"
        self._ap_ratio.setInvertedAppearance(lay == "img_right")

        # Signale wieder freigeben
        for w in widgets:
            w.blockSignals(False)

        # Zustand der Felder (ausgrauen) und Vorschau aktualisieren
        self._ap_on_checks()
        self._ap_on_layout()

    # ── Hilfsmethoden ──────────────────────────────────────

    def _set_status(self, msg: str):
        self.statusBar().showMessage(msg)

    INVISIBLE_ROW_TEXT = "✦ Signatur ohne Feld (unsichtbar)"

    def _update_field_list(self):
        prev_row = self._field_list.currentRow()
        self._field_list.clear()
        # Erstes Element: unsichtbare Signatur
        self._field_list.addItem(self.INVISIBLE_ROW_TEXT)
        for fdef in self.sig_fields:
            self._field_list.addItem(
                f"S.{fdef.page + 1}  {fdef.name}  [{fdef.x1:.0f},{fdef.y1:.0f}]")
        n = self._field_list.count()
        if n > 0:
            # Nach Hinzufügen: letztes sichtbares Feld wählen (Index 1+)
            row = prev_row if 0 <= prev_row < n else (n - 1 if n > 1 else 0)
            self._field_list.setCurrentRow(row)

    def _check_dependencies(self):
        missing = []
        if not _pyhanko_available:
            missing.append("pyhanko  (pip install pyhanko)")
        if not _pkcs11_available:
            missing.append("python-pkcs11  (pip install python-pkcs11)")
        if missing:
            QMessageBox.warning(self, t("dlg_missing_deps"),
                                t("dlg_missing_deps_msg",
                                  packages="\n".join(f"  • {m}" for m in missing)))

    def _render_current_page(self):
        if not self.pdf_doc:
            return
        page = self.pdf_doc[self.current_page]
        self._pdf_view.set_page(page, self.sig_fields, self.current_page)
        self._page_label.setText(f"  {self.current_page + 1} / {len(self.pdf_doc)}  ")

    # ── Signale ────────────────────────────────────────────

    def _on_field_added(self, fdef):
        self._update_field_list()
        # Neu hinzugefügtes Feld selektieren (letztes, nach dem Invisible-Item)
        self._field_list.setCurrentRow(self._field_list.count() - 1)
        self._set_status(t("status_field_added", name=fdef.name, page=fdef.page + 1))

    def _on_field_deleted(self, fdef):
        self._update_field_list()
        self._set_status(t("status_field_deleted", name=fdef.name))

    # ── PDF öffnen / navigieren ────────────────────────────

    def open_pdf(self):
        start = self.config.get("paths", "last_open_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("dlg_open_pdf_title"), start, t("dlg_pdf_filter"))
        if path:
            self._open_pdf(path)

    def _open_pdf(self, path: str):
        try:
            doc = fitz.open(path)
            self.pdf_doc = doc
            self.pdf_path = path
            self.current_page = 0
            self.sig_fields.clear()
            self._update_field_list()
            self._render_current_page()
            self.setWindowTitle(f"PDF QES Signer – {os.path.basename(path)}")
            self._set_status(t("status_opened", path=path, pages=len(doc)))
            self.config.set("paths", "last_open_dir", str(Path(path).parent))
            self.config.save()
        except Exception as exc:
            QMessageBox.critical(self, t("dlg_open_error_title"),
                                 t("dlg_open_error_msg", error=str(exc)))

    def prev_page(self):
        if self.pdf_doc and self.current_page > 0:
            self.current_page -= 1
            self._render_current_page()

    def next_page(self):
        if self.pdf_doc and self.current_page < len(self.pdf_doc) - 1:
            self.current_page += 1
            self._render_current_page()

    # ── Felder verwalten ───────────────────────────────────

    def delete_selected_field(self):
        row = self._field_list.currentRow()
        if row < 0 or row >= len(self.sig_fields):
            QMessageBox.information(self, t("dlg_no_field_sel"),
                                    t("dlg_no_field_sel_msg"))
            return
        fdef = self.sig_fields[row]
        if QMessageBox.question(
            self, t("dlg_delete_title"),
            t("dlg_delete_sel_msg", name=fdef.name)
        ) == QMessageBox.StandardButton.Yes:
            del self.sig_fields[row]
            self._update_field_list()
            self._render_current_page()

    def save_with_fields(self):
        if not self.pdf_doc:
            QMessageBox.warning(self, t("dlg_no_doc"), t("dlg_no_doc_msg")); return
        if not self.sig_fields:
            QMessageBox.warning(self, t("dlg_no_fields"), t("dlg_no_fields_msg")); return
        if not _pyhanko_available:
            QMessageBox.critical(self, t("dlg_save_error_title"),
                                 t("dlg_pyhanko_missing")); return
        stem = Path(self.pdf_path).stem
        start = self.config.get("paths", "last_save_dir")
        default = str(Path(start) / (stem + t("dlg_save_fields_suffix") + ".pdf"))
        out, _ = QFileDialog.getSaveFileName(
            self, t("dlg_save_fields_title"), default, t("dlg_pdf_filter"))
        if not out:
            return
        self.config.set("paths", "last_save_dir", str(Path(out).parent))
        self.config.save()
        self._set_status(t("status_saving_fields"))
        self._worker = SaveFieldsWorker(self.pdf_path, out, list(self.sig_fields))
        self._worker.finished.connect(self._on_save_done)
        self._worker.error.connect(self._on_save_error)
        self._worker.start()

    def _on_save_done(self, path):
        self._set_status(t("status_saved", path=path))
        QMessageBox.information(self, t("dlg_save_success_title"),
                                t("dlg_save_success_msg", path=path))

    def _on_save_error(self, msg):
        self._set_status(t("status_save_failed"))
        QMessageBox.critical(self, t("dlg_save_error_title"),
                             t("dlg_save_error_msg", error=msg))

    # ── Konfigurationsdialoge ──────────────────────────────

    def open_pkcs11_config(self):
        dlg = Pkcs11ConfigDialog(self, self.config)
        dlg.exec()

    def open_appearance_config(self):
        # Konfiguration jetzt direkt im Hauptfenster – kein separater Dialog
        pass

    # ── Signieren ──────────────────────────────────────────

    def sign_document(self):
        if not self.pdf_doc:
            QMessageBox.warning(self, t("dlg_no_doc"), t("dlg_no_doc_msg")); return
        if not _pyhanko_available:
            QMessageBox.critical(self, t("dlg_sign_error_title"),
                                 t("dlg_pyhanko_missing")); return

        # Row 0 = unsichtbare Signatur, Row 1+ = sig_fields[row-1]
        row  = self._field_list.currentRow()
        fdef: Optional[SignatureFieldDef] = None
        if row <= 0:
            # Unsichtbare Signatur oder nichts selektiert
            fdef = None
        elif 1 <= row <= len(self.sig_fields):
            fdef = self.sig_fields[row - 1]

        stem = Path(self.pdf_path).stem
        start = self.config.get("paths", "last_save_dir")
        default = str(Path(start) / (stem + t("dlg_save_signed_suffix") + ".pdf"))
        out, _ = QFileDialog.getSaveFileName(
            self, t("dlg_save_signed_title"), default, t("dlg_pdf_filter"))
        if not out:
            return

        self.config.set("paths", "last_save_dir", str(Path(out).parent))
        self.config.save()

        pin = self._pin_edit.text().strip()
        lib = self.config.get("pkcs11", "lib_path")
        key = self.config.get("pkcs11", "key_label")

        self._set_status(t("status_signing"))
        self._sign_worker = SignWorker(
            self.pdf_path, out, fdef, lib, pin, key, self.appearance)
        self._sign_worker.finished.connect(self._on_sign_done)
        self._sign_worker.error.connect(self._on_sign_error)
        self._sign_worker.start()

    def _on_sign_done(self, path):
        self._set_status(t("status_signed", path=path))
        QMessageBox.information(self, t("dlg_sign_success_title"),
                                t("dlg_sign_success_msg", path=path))

    def _on_sign_error(self, msg):
        self._set_status(t("status_sign_failed"))
        QMessageBox.critical(self, t("dlg_sign_error_title"),
                             t("dlg_sign_error_msg", error=msg))

    def _show_about(self):
        QMessageBox.about(self, t("about_title"), t("about_msg"))


# ══════════════════════════════════════════════════════════════
#  Einstiegspunkt
# ══════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(description="PDF QES Signer")
    parser.add_argument("pdf", nargs="?", default=None,
                        help="PDF-Datei, die beim Start geöffnet werden soll")
    args = parser.parse_args()

    app = QApplication(sys.argv)
    app.setApplicationName("PDF QES Signer")
    app.setOrganizationName("pdf-signer")
    try:
        app.setStyle("Fusion")
    except Exception:
        pass

    config = AppConfig()
    i18n.lang = config.get("app", "language")

    window = MainWindow(config, initial_pdf=args.pdf)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
