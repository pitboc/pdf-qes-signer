# SPDX-License-Identifier: GPL-3.0-or-later
"""German UI translations for PDF QES Signer."""

TRANSLATIONS: dict[str, str] = {
    # Menu
    "menu_file": "Datei",
    "menu_file_open": "PDF öffnen…",
    "menu_file_save_fields": "Felder speichern (Kopie)…",
    "menu_file_quit": "Beenden",
    "menu_sign": "Signieren",
    "menu_sign_document": "Dokument signieren (QES)…",
    "menu_settings": "Einstellungen",
    "menu_settings_pkcs11": "PKCS#11 / Token & TSA konfigurieren…",
    "menu_settings_language": "Sprache / Language",
    "menu_help": "Hilfe",
    "menu_help_about": "Über…",
    "menu_help_license": "Lizenz…",
    # Toolbar
    "tb_open": "PDF öffnen",
    "tb_prev": "◀",
    "tb_next": "▶",
    "tb_zoom_out":    "Verkleinern  (Ctrl+Mausrad)",
    "tb_zoom_in":     "Vergrößern  (Ctrl+Mausrad)",
    "tb_fit_width":   "Seitenbreite anpassen",
    "tb_fit_height":  "Seitenhöhe anpassen",
    "tb_sign": "✍ Signieren (QES)",
    "tb_save_fields": "💾 Felder speichern",
    # Right panel – Fields
    "panel_fields": "Signaturfelder",
    "btn_delete_field": "🗑 Löschen",
    "btn_save_fields": "💾 Als PDF speichern",
    # Right panel – Token / PIN
    "panel_token": "Token / PIN",
    "pin_label": "PIN:",
    "pin_hint": "leer lassen für PIN-Pad",
    # Right panel – Signature appearance
    "panel_appearance": "Signatur-Erscheinung",
    "app_layout_label": "Anordnung:",
    "app_layout_img_left": "Bild Links | Text Rechts",
    "app_layout_img_right": "Text Links | Bild Rechts",
    "app_location_label": "Ort:",
    "app_reason_label": "Grund:",
    "app_name_label": "Name:",
    "app_name_cert": "(aus Zertifikat)",
    "app_date_label": "Datum:",
    "app_show_date": "Datum anzeigen",
    # Appearance config dialog
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
    # Status bar
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
    # Dialogs
    "dlg_field_name_title": "Feldname",
    "dlg_field_name_prompt": "Name des Signaturfeldes:",
    "dlg_field_name_default": "Sig_{page}_{count}",
    "dlg_field_name_duplicate": "Ein Feld mit dem Namen '{name}' existiert bereits. Bitte einen anderen Namen wählen.",
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
    "dlg_field_already_signed": "Dieses Feld ist bereits signiert und kann nicht erneut verwendet werden.",
    "dlg_locked_field_title": "Feld gesperrt",
    "dlg_locked_field_msg": (
        "Das Feld '{name}' ist durch eine bestehende Signatur im Dokument geschützt\n"
        "und kann nicht gelöscht oder verschoben werden.\n\n"
        "Es kann nur signiert werden."
    ),
    "dlg_pyhanko_missing": "pyhanko ist nicht installiert.\npip install pyhanko python-pkcs11",
    "dlg_choose_field_title": "Signaturfeld wählen",
    "dlg_choose_field_label": "Mit welchem Feld signieren?",
    "dlg_invisible_field": "✦ Signatur ohne Feld (unsichtbar)",
    "tsa_enabled_label": "🕐 Zeitstempel (TSA) aktivieren",
    # PKCS#11 dialog
    "cfg_title": "PKCS#11 / Token & TSA konfigurieren",
    "cfg_tab_pkcs11": "PKCS#11 / Token",
    "cfg_tab_tsa": "Zeitstempel (TSA)",
    "cfg_tsa_url": "TSA-URL:",
    "cfg_tsa_hint": "RFC 3161 Zeitstempel-Dienst. Leer lassen für Standard (BaltStamp).",
    "cfg_lib_label": "Library-Pfad (.so / .dll):",
    "cfg_lib_browse": "…",
    "cfg_key_id_label":       "Schlüssel-ID:",
    "cfg_key_id_placeholder": "hex-ID (wird beim Token-Test automatisch gefüllt)",
    "cfg_key_id_hint":        "↑ CKA_ID des privaten Schlüssels (aus Token-Dialog)",
    "cfg_cert_cn_label":      "Name:",
    "cfg_pin_label": "PIN (nur Test):",
    "cfg_pin_placeholder": "leer lassen für PIN-Pad",
    "cfg_pin_hint": "↑ nur für Token-Test, wird nicht gespeichert",
    "cfg_test_btn_no_pin": "🔑 Token testen (ohne PIN)",
    "cfg_test_btn_with_pin": "🔑 Token testen (mit PIN)",
    "cfg_pinpad_test_title": "PIN-Pad nicht testbar",
    "cfg_pinpad_test_msg": (
        "Das PIN-Pad kann im Token-Test nicht ausgelöst werden,\n"
        "da python-pkcs11 keinen separaten Login-Aufruf erlaubt.\n\n"
        "Alternativen:\n"
        "• PIN hier eingeben, um private Keys direkt aufzulisten\n"
        "• 'Token testen (ohne PIN)' – ermittelt Key-ID aus Zertifikat\n"
        "• PIN-Pad funktioniert normal beim Signieren"
    ),
    "cfg_save_btn": "Speichern",
    "cfg_cancel_btn": "Abbrechen",
    "dlg_browse_lib": "PKCS#11 Library wählen",
    "dlg_token_error_title": "Token-Fehler",
    "dlg_token_info_title": "Token-Inhalt",
    "dlg_token_info_label": "Name: {label}    Hersteller: {manufacturer}",
    "dlg_token_class_private_key":         "Private Schlüssel",
    "dlg_token_class_private_key_derived": "Private Schlüssel (abgeleitet aus Öffentlichem Schlüssel)",
    "dlg_token_class_certificate":         "Zertifikate",
    "dlg_token_class_public_key":          "Öffentliche Schlüssel",
    "dlg_token_use_key": "ID übernehmen",
    "dlg_token_close": "Schließen",
    "dlg_token_no_key_title": "Kein privater Schlüssel gefunden",
    "dlg_token_no_key_msg": (
        "Kein privater Schlüssel gefunden.\n\n"
        "Möglicherweise ist eine PIN-Eingabe erforderlich, um den Schlüssel anzuzeigen.\n\n"
        "Alternativ kann das Key-Label aus den vorhandenen öffentlichen Schlüsseln abgeleitet werden."
    ),
    "dlg_token_derive_btn": "Key-Label aus öffentlichem Schlüssel ableiten",
    "dlg_token_cancel_pin_btn": "Abbrechen – Token mit PIN lesen",
    # Appearance panel (main window)
    "ap_tab_text": "Text",
    "ap_tab_image_layout": "Bild / Layout",
    "ap_name_from_cert": "Zertifikat",
    "ap_name_custom": "Eigener",
    "ap_font_pt": "Größe (pt):",
    "ap_font_family": "Schriftart:",
    "ap_img_none": "(kein Bild)",
    "ap_img_hint": "Transparenz wird unterstützt.",
    "ap_layout_left": "Bild links",
    "ap_layout_right": "Bild rechts",
    "ap_border": "Rahmen anzeigen",
    "ap_date_custom": "Eigenes Format…",
    "ap_img_label": "◀ Bild {v}%",
    "ap_txt_label": "Text {r}% ▶",
    "ap_txt_label_left": "Text {r}% ▶",
    "ap_img_label_right": "◀ Bild {v}%",
    "ap_preview_hint": "Für Vorschau bitte Signaturfeld einfügen.",
    "ap_browse_img": "Signaturbild wählen",
    "ap_img_filter": "Bilder (*.png *.jpg *.jpeg *.bmp);;Alle Dateien (*)",
    # About / License
    "about_title": "Über PDF QES Signer",
    "about_msg": (
        "PDF QES Signer  v{version}  (commit: {commit})\n\n"
        "Visuelles Platzieren von Signaturfeldern\n"
        "und qualifizierte elektronische Signatur (QES)\n"
        "via PKCS#11 / Smartcard.\n\n"
        "Lizenz: GNU General Public License v3 oder später (GPL-3.0-or-later)\n\n"
        "Benötigte Pakete:\n"
        "  pip install pymupdf pyhanko python-pkcs11 Pillow PyQt6 cryptography\n\n"
        "Linksklick + Ziehen  →  Signaturfeld zeichnen\n"
        "Rechtsklick auf Feld →  Optionen / Löschen"
    ),
    "license_title": "Lizenzinformationen",
    "license_msg": (
        "PDF QES Signer\n"
        "Copyright (C) PDF QES Signer contributors\n\n"
        "Dieses Programm ist freie Software: Sie können es unter den Bedingungen\n"
        "der GNU General Public License, wie von der Free Software Foundation\n"
        "veröffentlicht, weitergeben und/oder modifizieren, entweder gemäß\n"
        "Version 3 der Lizenz oder (nach Ihrer Wahl) jeder späteren Version.\n\n"
        "Dieses Programm wird in der Hoffnung bereitgestellt, dass es nützlich ist,\n"
        "aber OHNE JEDE GEWÄHR; sogar ohne die implizite Gewähr der MARKTFÄHIGKEIT\n"
        "oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.\n"
        "Siehe die GNU General Public License für weitere Details.\n\n"
        "Den vollständigen Lizenztext finden Sie unter:\n"
        "  https://www.gnu.org/licenses/gpl-3.0.html\n\n"
        "──────────────────────────────────────────────\n"
        "Verwendete Bibliotheken:\n\n"
        "  PyMuPDF (fitz)   GNU AGPL v3\n"
        "    https://pymupdf.readthedocs.io\n\n"
        "  pyhanko          MIT License\n"
        "    https://pyhanko.readthedocs.io\n\n"
        "  PyQt6            GPL v3 / Kommerziell\n"
        "    https://www.riverbankcomputing.com\n\n"
        "  python-pkcs11    MIT License\n"
        "    https://python-pkcs11.readthedocs.io\n\n"
        "  Pillow           HPND License\n"
        "    https://python-pillow.org\n\n"
        "  cryptography     Apache 2.0 / BSD\n"
        "    https://cryptography.io\n"
    ),
    "license_close": "Schließen",
}
