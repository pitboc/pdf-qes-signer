# SPDX-License-Identifier: GPL-3.0-or-later
"""German UI translations for PDF QES Signer."""

TRANSLATIONS: dict[str, str] = {
    # Generic buttons (used wherever QDialogButtonBox standard buttons need translated text)
    "btn_ok":     "OK",
    "btn_cancel": "Abbrechen",
    "btn_close":  "Schließen",
    "btn_yes":    "Ja",
    "btn_no":     "Nein",

    # Profile menu
    "menu_profile":        "Profile…",
    "dlg_profile_mgr_title":   "Profile verwalten",
    "dlg_profile_new_short":   "Neu",
    # Profile dialogs
    "dlg_profile_select_title":      "Profil auswählen",
    "dlg_profile_active":            "(aktiv)",
    "dlg_profile_activate":          "Aktivieren",
    "dlg_profile_new_title":         "Neues Profil",
    "dlg_profile_new_label":         "Profilname:",
    "dlg_profile_new_btn":           "Erstellen",
    "dlg_profile_exists_title":      "Profil existiert bereits",
    "dlg_profile_exists_msg":        "Ein Profil mit dem Namen '{name}' existiert bereits.\nSoll es überschrieben werden?",
    "dlg_profile_rename_title":      "Profil umbenennen",
    "dlg_profile_rename_label":      "Neuer Name:",
    "dlg_profile_rename_btn":        "Umbenennen",
    "dlg_profile_delete_title":      "Profil löschen",
    "dlg_profile_delete_btn":        "Löschen",
    "dlg_profile_delete_active_msg": "'{name}' ist das aktive Profil.\nNach dem Löschen wird auf '{next}' umgeschaltet.\nWirklich löschen?",
    "dlg_profile_delete_confirm_msg":"Profil '{name}' wirklich löschen?",
    "dlg_profile_last_title":        "Letztes Profil",
    "dlg_profile_last_msg":          "Mindestens ein Profil muss vorhanden sein.\n\nMöchten Sie die Parameter auf die Voreinstellungen zurücksetzen?",
    "dlg_profile_reset_btn":         "Voreinstellungen setzen",
    "dlg_profile_invalid_name":      "Ungültiger Profilname. Bitte nur Buchstaben, Ziffern, Leerzeichen, Bindestrich und Unterstrich verwenden.",
    "dlg_profile_empty_name":        "Bitte einen Profilnamen eingeben.",
    "dlg_profile_name_exists":       "Ein Profil mit diesem Namen existiert bereits.",
    "status_profile":                "Profil",
    # Menu
    "menu_file": "Datei",
    "menu_file_open": "PDF öffnen…",
    "menu_file_save_fields": "Felder speichern (Kopie)…",
    "menu_file_quit": "Beenden",
    "menu_sign": "Signieren",
    "menu_sign_document": "Dokument signieren…",
    "menu_settings": "Einstellungen",
    "menu_settings_pkcs11": "Signatur / Token konfigurieren…",
    "menu_settings_language": "Sprache / Language",
    "menu_help": "Hilfe",
    "menu_help_about": "Über…",
    "menu_help_license": "Lizenz…",
    # Toolbar
    "tb_open": "PDF öffnen",
    "tb_prev": "Vorherige Seite",
    "tb_next": "Nächste Seite",
    "tb_zoom_out":    "Verkleinern  (Ctrl+Mausrad)",
    "tb_zoom_in":     "Vergrößern  (Ctrl+Mausrad)",
    "tb_fit_width":   "Seitenbreite anpassen",
    "tb_fit_height":  "Seitenhöhe anpassen",
    "tb_sign": "✍ Signieren",
    "tb_check_sigs": "🔍 Signatur prüfen",
    "tb_save_fields": "💾 PDF speichern",
    # Right panel – Fields
    "panel_fields": "Signaturfelder",
    "btn_delete_field": "🗑 Löschen",
    "btn_save_fields": "💾 Als PDF speichern",
    # Right panel – Token / PIN
    "panel_token":     "Token / PIN",
    "panel_token_pfx": "P12/PFX-Datei / Passwort",
    "pin_label":       "PIN:",
    "pin_hint":        "leer lassen für PIN-Pad",
    "pin_label_pfx":   "Passwort:",
    "pin_hint_pfx":    "leer lassen wenn nicht passwortgeschützt",
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
        "Folgende Pakete fehlen für die Signierung:\n\n{packages}\n\n"
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
    "dlg_sign_success_msg": "Signatur erfolgreich eingefügt.\n\nDatei: {path}",
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
    "dlg_sign_error_msg_pfx": (
        "Fehler bei der Signierung:\n\n{error}\n\n"
        "Häufige Ursachen:\n"
        "• Falsches Passwort (oder leer lassen wenn nicht geschützt)\n"
        "• P12/PFX-Datei nicht gefunden oder beschädigt\n"
        "• Kein privater Schlüssel in der Datei enthalten\n\n"
        "Vollständiger Traceback in der Konsole (stderr)."
    ),
    "dlg_field_already_signed": "Dieses Feld ist bereits signiert und kann nicht erneut verwendet werden.",
    "warn_crypto_invalid_short": "⚠  Kryptografische Integritätsprüfung fehlgeschlagen ({count}) –"
                                " Inhalt möglicherweise manipuliert oder Datei beschädigt."
                                "  Signaturen prüfen.",
    "warn_docmdp_p1":     "Dokument gesperrt – keine Änderungen erlaubt (docMDP P=1)",
    "warn_docmdp_p2":     "Dokument eingeschränkt – nur Formularfelder & Signaturen erlaubt (docMDP P=2)",
    "dlg_docmdp_title":   "Dokument-Einschränkung",
    "dlg_docmdp_info":    (
        "Dies ist die erste Signatur in diesem Dokument.\n"
        "Legen Sie fest, welche Änderungen danach noch erlaubt sind:"
    ),
    "dlg_docmdp_none":    "Keine Einschränkung",
    "dlg_docmdp_p2":      "Formularfelder & weitere Signaturen erlaubt (empfohlen)",
    "dlg_docmdp_p1":      "Keine weiteren Änderungen erlaubt",
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
    "tsa_enabled_label":   "🕐 Zeitstempel (TSA) aktivieren",
    "cfg_chain_aia_label": "Zertifikatskette beim Signieren vervollständigen (AIA)",
    "cfg_chain_aia_hint": (
        "Lädt fehlendes Root-CA-Zertifikat beim Signieren über AIA (Authority "
        "Information Access) nach und bettet es in die Signatur ein. "
        "Empfohlen für Langzeitarchivierung (PAdES-LT / ETSI EN 319 132). "
        "Beim ersten Signieren wird eine Bestätigung angefragt; das Zertifikat "
        "wird dann lokal gespeichert und zukünftig ohne Rückfrage eingebettet."
    ),
    "dlg_root_fetch_title": "Root-CA-Zertifikat einbetten",
    "dlg_root_fetch_msg": (
        "Die Signatur enthält kein Root-CA-Zertifikat.\n\n"
        "Soll es jetzt über das Internet (AIA) nachgeladen und eingebettet werden?\n\n"
        "Root-CA: {subject}\n\n"
        "Das Zertifikat wird lokal gespeichert. Beim nächsten Signieren "
        "wird es ohne Rückfrage eingebettet.\n\n"
        "Hinweis: Diese Frage kann in der Signatur-Konfiguration deaktiviert werden."
    ),
    "cfg_ocsp_lta_label":  "Widerrufsstatus für Langzeitarchivierung einbetten (OCSP/PAdES-LTA)",
    "cfg_ocsp_lta_hint": (
        "Bettet den aktuellen Widerrufsstatus aller Zertifikate ein und fügt "
        "einen Archivzeitstempel hinzu. Erfordert ein von einer "
        "Zertifizierungsstelle ausgestelltes Zertifikat mit OCSP-Dienst."
    ),
    "cfg_ocsp_self_signed_hint": (
        "Nicht verfügbar: Das gewählte Zertifikat ist selbstsigniert. "
        "Für Langzeitarchivierung wird ein CA-ausgestelltes Zertifikat benötigt."
    ),
    "dlg_ocsp_warning_title": "Langzeitarchivierung nicht eingebettet",
    "dlg_ocsp_warning_msg": (
        "Der Widerrufsstatus konnte nicht abgerufen werden – "
        "das Dokument wurde ohne Langzeitarchivierungsdaten signiert.\n\n"
        "Zeitstempel und Signatur wurden erfolgreich eingefügt.\n\n"
        "Technische Ursache: {error}"
    ),
    # Signatur-Konfigurationsdialog
    "cfg_title":       "Signatur / Token konfigurieren",
    "cfg_tab_pkcs11":  "Signatur-Methode",
    "cfg_tab_tsa":     "Zeitstempel (TSA)",
    "cfg_mode_label":  "Methode:",
    "cfg_mode_pkcs11": "Hardware-Token (PKCS#11)",
    "cfg_mode_pfx":    "Schlüssel & Zertifikat (P12/PFX)",
    "cfg_pfx_path_label":    "P12/PFX-Datei:",
    "cfg_pfx_browse_title":  "P12/PFX-Datei wählen",
    "cfg_pfx_filter":        "P12/PFX-Dateien (*.p12 *.pfx);;Alle Dateien (*)",
    "cfg_pfx_show_cert_btn": "Zertifikat anzeigen",
    "cfg_pfx_keygen_btn":   "Schlüssel erzeugen…",
    "cfg_pfx_keygen_tip":   (
        "Öffnet den Dialog zur Erzeugung eines selbstsignierten Zertifikats.\n"
        "Der erzeugte Schlüssel wird als P12/PFX-Datei gespeichert und\n"
        "automatisch in dieses Feld übernommen."
    ),
    "cfg_pfx_encrypted_yes": "Passwortgeschützt",
    "cfg_pfx_encrypted_no":  "Nicht passwortgeschützt",
    "cfg_pfx_no_file":        "Keine P12/PFX-Datei ausgewählt.",
    "cfg_pfx_password_title": "Passwort erforderlich",
    "cfg_pfx_password_prompt": (
        "Die P12/PFX-Datei ist passwortgeschützt.\n"
        "Passwort eingeben (wird nicht gespeichert):"
    ),
    "cfg_pfx_wrong_password_prompt": (
        "Falsches Passwort. Bitte erneut eingeben:"
    ),
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
    "dlg_token_close":   "Schließen",
    # PFX info dialog
    "dlg_pfx_info_title":       "Zertifikat-Informationen",
    "dlg_pfx_private_key":      "Privater Schlüssel",
    "dlg_pfx_signing_cert":     "Signaturzertifikat",
    "dlg_pfx_subject":          "Inhaber:",
    "dlg_pfx_issuer":           "Aussteller:",
    "dlg_pfx_valid_from":       "Gültig ab:",
    "dlg_pfx_valid_to":         "Gültig bis:",
    "dlg_pfx_serial":           "Seriennummer:",
    "dlg_pfx_self_signed":      "(selbstsigniert)",
    "dlg_pfx_chain_header":     "Zertifikatskette ({n} Zertifikat(e))",
    "dlg_pfx_use_cn":           "CN übernehmen",
    "dlg_pfx_load_error_title": "Fehler",
    "dlg_pfx_load_error":       "P12/PFX-Datei konnte nicht geladen werden:\n{error}",
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
        "PDF QES Signer  v{version}{commit}\n\n"
        "Visuelles Platzieren von Signaturfeldern\n"
        "und qualifizierte elektronische Signatur (QES)\n"
        "via PKCS#11 / Smartcard.\n\n"
        "Lizenz: GNU General Public License v3 oder später (GPL-3.0-or-later)\n\n"
        "Benötigte Pakete:\n"
        "  pip install pymupdf pyhanko python-pkcs11 Pillow PyQt6 cryptography\n\n"
        "Linksklick + Ziehen  →  Signaturfeld zeichnen\n"
        "Rechtsklick auf Feld →  Optionen / Löschen\n"
        "Strg + Ziehen        →  In Auswahl zoomen\n"
        "Mittlere Maustaste   →  Ansicht verschieben"
    ),
    "about_check_update":        "Nach Updates suchen",
    "about_update_checking":     "Suche läuft…",
    "about_update_available":    "Neue Release-Version verfügbar: {version}",
    "about_update_current":      "Version aktuell – kein Update verfügbar.",
    "settings_check_on_startup": "Beim Start automatisch nach Updates suchen",
    # Update-Installations-Dialog
    "update_btn_install":        "Update installieren",
    "update_btn_retry":          "Erneut versuchen",
    "update_btn_cancel":         "Abbrechen",
    "update_btn_restart":        "Neu starten",
    "update_dlg_title":          "Update installieren",
    "update_dlg_info":           "Version {version} ist verfügbar (aktuell: {current}).",
    "update_dry_run_hint":       "Test-Modus: --dry-run, es wird nichts installiert.",
    "update_status_downloading": "Wird heruntergeladen…",
    "update_status_installing":  "Wird installiert…",
    "update_status_success":     "Installation abgeschlossen – bitte Anwendung neu starten.",
    "update_status_error":       "Installation fehlgeschlagen. Bitte manuell ausführen:",
    "update_dry_run_success":    "Test erfolgreich (--dry-run, nichts installiert).",
    "update_no_asset":           "Kein Download-Asset für diese Version gefunden.",
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

    # ── Signaturprüfung ───────────────────────────────────────────────────
    "menu_check_sigs":          "Signaturen prüfen…",
    "menu_trust_cache":              "Vertrauensspeicher-Cache…",
    "trust_cache_title":             "Vertrauensspeicher-Cache (LOTL/TSL)",
    "trust_cache_lotl_header":       "EU List of Trusted Lists (LOTL)",
    "trust_cache_lotl_explain":      "Verzeichnis aller nationalen Vertrauenslisten – wird für QES-Validierung benötigt.",
    "trust_cache_lotl_urls_valid":   "  URL-Liste:  {count} Einträge  ({size} KB)  –  gültig bis {date}",
    "trust_cache_lotl_urls_expired": "  URL-Liste:  {count} Einträge  ({size} KB)  –  ABGELAUFEN am {date}",
    "trust_cache_lotl_urls_no_date": "  URL-Liste:  {count} Einträge  ({size} KB)  –  Gültigkeit unbekannt",
    "trust_cache_no_lotl_urls":      "  URL-Liste:  nicht vorhanden",
    "trust_cache_tsl_section":       "Nationale Trust Service Lists (TSL)",
    "trust_cache_tsl_explain":       "Zertifikat-Fingerabdrücke offiziell anerkannter QES-Vertrauensdiensteanbieter.",
    "trust_cache_tsl_header":        "Gespeicherte Länder:",
    "trust_cache_no_tsl":            "  (Kein TSL-Cache vorhanden)",
    "trust_cache_tsl_valid":         "  {country}  –  gültig bis {date}  ({size} KB)",
    "trust_cache_tsl_expired":       "  {country}  –  abgelaufen am {date}  ({size} KB)",
    "trust_cache_btn_clear_tsl":     "TSL-Dateien löschen",
    "trust_cache_btn_clear_all":     "Alles löschen",
    "trust_cache_btn_clear_aia":     "Root-Zertifikate löschen",
    "trust_cache_aia_section":       "Root-CA-Zertifikate (AIA-Cache)",
    "trust_cache_aia_explain":       "Beim Signieren nachgeladene Root-CA-Zertifikate für Einbettung in zukünftige Signaturen.",
    "trust_cache_aia_empty":         "  (Kein Root-Zertifikat im Cache)",
    "trust_cache_aia_entry":         "  {subject}  ·  {fp}  ({size} KB)",
    "val_dlg_title":            "Signaturprüfung",
    "val_col_item":             "Element",
    "val_col_source":           "Ursprung",
    "val_col_status":           "Gültig",
    "val_col_rev":              "Rev",
    "val_col_element":          "Element",
    "val_col_name":             "Name",
    "val_col_tsa":              "TSA",
    "val_col_time":             "Zeit",
    "val_col_valid_until":      "Gültigkeit",
    "val_sub_field":            "Bezeichner: {value}",
    "val_sub_name":             "Name: {value}",
    "val_sub_issuer":           "Aussteller: {value}",
    "val_overall_valid":        "GÜLTIG",
    "val_overall_unknown":      "UNBEKANNT",
    "val_overall_invalid":      "UNGÜLTIG",
    "val_overall_not_checked":  "…",
    "val_rev_label":            "Rev {n} / {total}",
    "val_sig_type_signature":   "Signatur",
    "val_sig_type_timestamp":   "Archiv-Zeitstempel",
    "val_sig_type_lta":         "TSA (LTA) Zeitstempel",
    "val_signer":               "Unterzeichner",
    "val_signing_time":         "Zeitpunkt",
    "val_tsa_time":             "TSA-Zeitstempel",
    "val_checks":               "Krypto: {crypto}  Kette: {chain}  Widerruf: {revoc}",
    "val_cert_chain":           "Zertifikatskette",
    "val_cert_root":            "Root-CA",
    "val_cert_self_signed":     "selbstsigniert",
    "val_cert_intermediate":    "CA",
    "val_cert_end_entity":      "Signaturzertifikat",
    "val_ocsp":                 "OCSP: {status}",
    "val_ocsp_good":            "gültig",
    "val_ocsp_revoked":         "widerrufen",
    "val_ocsp_unknown":         "unbekannt",
    "val_src_embedded":         "eingebettet",
    "val_src_system":           "Mozilla",
    "val_src_eu_tsl":           "nat. TSL",
    "val_src_downloaded":       "heruntergeladen",
    "val_src_not_found":        "nicht gefunden",
    "val_tsa_is_tsa":           "(ist TSA)",
    "val_col_integrity":        "Integrität",
    "val_integrity_ok":         "✓ unverändert",
    "val_integrity_fail":       "✗ Signatur ungültig",
    "val_field_name":           "Feld: {name}",
    "val_self_reported":        "Selbst gemeldet: {time}",
    "val_doc_info":             "{n} Revision(en)",
    "val_doc_dss":              "  · DSS",
    "val_doc_lta":              "  · LTA",
    "val_phase2_running":       "Online-Prüfung läuft…",
    "val_phase2_done":          "Prüfung abgeschlossen.",
    "val_phase2_error":         "Fehler: {msg}",
    "val_btn_recheck":          "Erneut prüfen",
    "val_btn_fetch_certs":      "Online-Zertifikate abrufen",
    "val_no_sigs":              "Keine Signaturen im Dokument gefunden.",
    "val_no_pdf":               "Kein PDF geöffnet.",

    # Typen unsigned Revisionen
    "val_rev_type_original":    "Original-Dokument",
    "val_rev_type_form_fields": "Formularfelder",
    "val_rev_type_annotations": "Annotationen",
    "val_rev_type_dss":         "Validierungsdaten (DSS)",
    "val_rev_type_metadata":    "Dokumentmetadaten (XMP)",
    "val_rev_type_unknown":     "Inkrementelles Update",

    # Warnung: Änderungen nach letzter Signatur
    "val_warn_post_sig_title":  "Dokument nach letzter Signatur verändert",
    "val_warn_post_sig_body":   "Folgende Änderungen wurden nach der letzten Signatur hinzugefügt"
                                " und sind durch keine Signatur abgedeckt: {types}\n"
                                "Der aktuell angezeigte Inhalt stimmt möglicherweise nicht"
                                " mit dem signierten Stand überein.",
    "val_warn_post_sig_short":  "⚠  Dokument nach der letzten Signatur verändert ({types})."
                                "  Bitte Signaturen prüfen.",
    "val_warn_between_sig_title": "Änderungen zwischen Signaturen",
    "val_warn_between_sig_body":  "Folgende Änderungen wurden nach der ersten Signatur"
                                  " hinzugefügt und sind nur durch eine spätere Signatur"
                                  " abgedeckt: {types}\n"
                                  "Die erste Signatur deckt diesen Inhalt nicht ab.",
    "val_warn_between_sig_short": "⚠  Änderungen zwischen Signaturen ({types}) –"
                                  " nicht durch alle Signaturen abgedeckt.",

    # Hauptliste (neue Baumansicht)
    "val_sig_type_doc_ts":          "Dokumentzeitstempel",
    "val_rev_no_sig":               "–  (keine Signatur)",
    "val_show_all_revisions":       "Alle Revisionen anzeigen",
    "val_detail_date":              "Datum",
    "val_detail_integrity":         "Integrität",
    "val_detail_profile":           "Profil",
    "val_date_tsa":                 "{time}  (TSA-bestätigt)",
    "val_date_self":                "{time}  (selbst gemeldet)",
    "val_date_doc_ts":              "{time}",
    "val_profile_is_doc_ts":        "–  (ist selbst der Dokumentzeitstempel)",
    "val_profile_details_B":        "TSA-Token –, DSS –",
    "val_profile_details_T":        "TSA-Token ✓, DSS –",
    "val_profile_details_LT":       "TSA-Token ✓, DSS ✓, LTA-Zeitstempel –",
    "val_profile_details_LTA":      "TSA-Token ✓, DSS ✓, LTA-Zeitstempel ✓",
    "val_profile_meaning_B":        "Keine zusätzlichen Validierungsdaten eingebettet",
    "val_profile_meaning_T":        "Signierzeitpunkt gesichert, Validierungsdaten nicht eingebettet",
    "val_profile_meaning_LT":       "Validierungsdaten eingebettet, aber nicht kryptographisch gesichert",
    "val_profile_meaning_LTA":      "Alle Validierungsdaten eingebettet und kryptographisch gesichert",

    # Certificate chain summary rows in validation tree
    "val_detail_sig_chain":         "Signaturkette",
    "val_detail_tsa_chain":         "TSA-Kette",
    "val_chain_details_btn":        "Details →",

    # Chain status labels (shown in tree + detail window)
    "val_chain_valid":              "✓ Gültig",
    "val_chain_incomplete":         "✗ Unvollständig",
    "val_chain_expired":            "✗ Abgelaufen",
    "val_chain_revoked":            "✗ Widerrufen",
    "val_chain_unknown_root":       "Vollständig · Root unbekannt",
    "val_chain_unknown_revoc":      "Vollständig · Widerruf unbekannt",
    "val_chain_not_checked":        "–",

    # Tooltips for chain status labels
    "val_chain_valid_tip":          "Kette vollständig, Root vertrauenswürdig (certifi/Mozilla-Bundle), Widerruf eingebettet und gültig.",
    "val_chain_incomplete_tip":     "Die Zertifikatskette bricht ab – ein Intermediate-Zertifikat fehlt.",
    "val_chain_expired_tip":        "Mindestens ein Zertifikat der Kette war zum Signierzeitpunkt außerhalb seiner Gültigkeitsdauer.",
    "val_chain_revoked_tip":        "Laut eingebetteter OCSP-Antwort wurde das Signaturzertifikat gesperrt.",
    "val_chain_unknown_root_tip":   "Die Kette ist vollständig, aber das Root-Zertifikat wurde weder im certifi/Mozilla-Bundle noch in der EU-Vertrauensliste (LOTL/TSL) gefunden.",
    "val_chain_unknown_revoc_tip":  "Das Root-Zertifikat ist vertrauenswürdig (certifi/Mozilla-Bundle), aber der Widerrufsstatus des Signaturzertifikats wurde nicht geprüft.",

    # AdES subindication labels (shown instead of generic "Widerruf unbekannt")
    "val_chain_indic_out_of_bounds":            "Vollständig · Zertifikat abgelaufen, kein Zeitnachweis",
    "val_chain_indic_out_of_bounds_tip":        "Das Signaturzertifikat war zum Online-Prüfzeitpunkt abgelaufen. Ohne eingebettete OCSP-Antwort (PAdES-LT/LTA) kann nicht nachgewiesen werden, dass es zum Signierdatum noch gültig war.",
    "val_chain_indic_revoked_no_poe":           "Vollständig · Widerruf ohne Zeitnachweis",
    "val_chain_indic_revoked_no_poe_tip":       "Das Zertifikat ist widerrufen, aber ohne Zeitnachweis (PAdES-LT/LTA) kann nicht bestimmt werden, ob der Widerruf vor oder nach der Signatur erfolgte.",
    "val_chain_indic_try_later":                "Vollständig · OCSP-Dienst nicht erreichbar",
    "val_chain_indic_try_later_tip":            "Der OCSP-Dienst des Ausstellers war zum Prüfzeitpunkt nicht erreichbar. Eine spätere Prüfung könnte erfolgreich sein.",
    "val_chain_indic_no_poe":                   "Vollständig · Kein Existenznachweis",
    "val_chain_indic_no_poe_tip":               "Für den Signierdatum fehlt ein kryptografischer Existenznachweis (z. B. ein RFC-3161-Zeitstempel).",
    "val_chain_indic_crypto_no_poe":            "Vollständig · Kryptografische Einschränkung ohne Zeitnachweis",
    "val_chain_indic_crypto_no_poe_tip":        "Ein verwendeter Algorithmus entspricht nicht mehr den aktuellen Anforderungen und es fehlt ein Zeitnachweis, der die Verwendung zum Signierdatum belegt.",

    "val_chain_self_signed":        "Selbstsigniert · kein CA-Vertrauen",
    "val_chain_self_signed_tip":    "Das Zertifikat ist selbst ausgestellt – es gibt keine übergeordnete Zertifizierungsstelle. Das Zertifikat ist eingebettet, aber nicht in einem bekannten Vertrauensspeicher vorhanden.",

    # Certificate chain detail window
    "cert_win_title_sig":           "Signaturkette – {cn}",
    "cert_win_title_tsa":           "TSA-Kette – {cn}",
    "cert_win_role_ee":             "End-Entity",
    "cert_win_role_intermediate":   "Intermediate",
    "cert_win_role_root":           "Root",
    "cert_win_role_self_signed":    "Selbstsigniert",
    "cert_win_self_signed_issuer":  "(selbstsigniert)",
    "cert_win_label_issuer":        "Aussteller",
    "cert_win_label_valid":         "Gültig",
    "cert_win_label_source":        "Quelle",
    "cert_win_label_trust":         "Vertrauen",
    "cert_win_label_fingerprint":   "Fingerabdruck (SHA-256)",
    "cert_win_label_ocsp":          "OCSP",
    "cert_win_label_overall":       "Gesamtstatus",
    "cert_win_lotl_confirmed":      "EU LOTL bestätigt (Trust Anchor)",
    "cert_win_root_informational":  "Nur informativ · nicht geprüft",
    "cert_win_not_found_trust":     "Nicht vorhanden · Vertrauen nicht prüfbar",
    "cert_win_trust_verified":      "Durch Aussteller kryptografisch verifiziert",
    "cert_win_issuer_sig_invalid":  "Aussteller-Signatur ungültig!",
    "cert_win_source_embedded":     "Eingebettet (PDF)",
    "cert_win_source_certifi":      "certifi (Mozilla-Bundle)",
    "cert_win_source_system":       "System-Vertrauensspeicher",
    "cert_win_source_eu_tsl":       "EU-Vertrauensliste (LOTL/TSL)",
    "cert_win_source_downloaded":   "Heruntergeladen (AIA)",
    "cert_win_source_not_found":    "Nicht gefunden",
    "cert_win_source_unknown":      "Unbekannt",
    "cert_win_ocsp_good":           "gut ✓",
    "cert_win_ocsp_revoked":        "widerrufen ✗",
    "cert_win_ocsp_unknown":        "unbekannt",
    "cert_win_ocsp_not_checked":    "nicht geprüft",
    "cert_win_close":               "Schließen",

    # ── KeygenDialog – Schlüssel & selbstsigniertes Zertifikat erzeugen ───────
    "keygen_title":             "Schlüssel & Zertifikat erzeugen",
    "keygen_section_key":       "Schlüsselparameter",
    "keygen_section_subject":   "Zertifikatsinhaber",
    "keygen_section_file":      "Ausgabedatei & Passwortschutz",

    # Schlüsselparameter
    "keygen_keytype_label": "Schlüsseltyp:",
    "keygen_keytype_tip": (
        "Kryptografischer Algorithmus und Schlüssellänge.\n\n"
        "EC P-521 ★ (Voreinstellung)\n"
        "  Höchste EC-Sicherheitsstufe (≈ 260 Bit). Ab 2027 BSI-Mindeststandard\n"
        "  ist P-384 – P-521 liegt dauerhaft darüber. Softwaresignatur mit\n"
        "  P-521 ist deutlich schneller als jede Smartcard.\n\n"
        "EC P-384\n"
        "  Ab 2027 BSI-Mindeststandard (TR-02102-1). Gute Wahl wenn maximale\n"
        "  Kompatibilität mit etwas älterer Software wichtig ist.\n\n"
        "EC P-256\n"
        "  Schnellste Option, aber nur bis Ende 2026 BSI-konform für neue\n"
        "  Signaturen. Ab 2027 nicht mehr ausreichend (BSI TR-02102-1).\n\n"
        "RSA 3072 / 4096\n"
        "  Klassischer Algorithmus; maximal kompatibel mit alter Software.\n"
        "  BSI-Minimum: 3000 Bit. Erzeugung dauert einige Sekunden länger als EC."
    ),
    "keygen_smime_enc_label": "Auch für S/MIME-Verschlüsselung verwenden",
    "keygen_smime_enc_tip": (
        "Setzt zusätzliche Key-Usage-Bits für S/MIME-E-Mail-Verschlüsselung:\n"
        "  EC-Schlüssel:  keyAgreement (ECDH-Schlüsselaustausch)\n"
        "  RSA-Schlüssel: keyEncipherment (direkter Schlüsseltransport)\n\n"
        "Damit kann dasselbe Schlüsselpaar für Signatur und Verschlüsselung\n"
        "verwendet werden – analog zu GnuPG/OpenPGP.\n\n"
        "Für reine PDF-Signaturen nicht benötigt."
    ),
    "keygen_fixed_attrs": (
        "Fest gesetzt: Key Usage = digitalSignature + nonRepudiation  ·  "
        "Extended Key Usage = emailProtection  ·  Basic Constraints: CA=Nein"
    ),
    "keygen_fixed_attrs_tip": (
        "Diese Zertifikatsattribute werden immer gesetzt:\n\n"
        "Key Usage (Schlüsselverwendung):\n"
        "  digitalSignature – Signatur von Dokumenten und Daten\n"
        "  nonRepudiation   – Nicht-Abstreitbarkeit (eIDAS: Verbindlichkeit)\n"
        "  + keyAgreement / keyEncipherment wenn S/MIME-Verschlüsselung aktiv\n\n"
        "Extended Key Usage:\n"
        "  emailProtection  – S/MIME und PDF-Signaturen\n\n"
        "Basic Constraints: CA=Nein\n"
        "  Das Zertifikat darf keine anderen Zertifikate ausstellen."
    ),
    "keygen_validity_label": "Gültigkeit:",
    "keygen_validity_tip": (
        "Wie lange das Zertifikat gültig ist.\n\n"
        "Hinweis: Selbstsignierte Zertifikate können nach Ablauf nicht mehr\n"
        "für neue Signaturen verwendet werden. Bestehende Signaturen bleiben\n"
        "jedoch weiterhin kryptografisch gültig – sofern sie zum Zeitpunkt\n"
        "der Signatur innerhalb der Gültigkeitsdauer lagen.\n\n"
        "Empfehlung:\n"
        "• 3 Jahre für allgemeinen Gebrauch\n"
        "• 10 Jahre für Archivdokumente mit langer Aufbewahrungspflicht\n\n"
        "Für qualifizierte Signaturen (QES) nach eIDAS ist ein Zertifikat\n"
        "einer akkreditierten Vertrauensdienstleisterin (TSP) erforderlich."
    ),
    # Die eigentlichen Jahrestexte werden per Format-String erzeugt:
    # keygen_validity_years wird mit n=1..10 aufgerufen
    "keygen_validity_years": "{n} Jahr(e)",

    # Zertifikatsinhaber
    "keygen_cn_label": "Name (CN):",
    "keygen_cn_tip": (
        "Common Name (CN) – der Hauptname im Zertifikat.\n\n"
        "Dieser Name erscheint in PDF-Betrachtern als Unterzeichner und\n"
        "in der Signaturfeld-Darstellung (sofern 'Name aus Zertifikat' gewählt).\n\n"
        "Beispiele:\n"
        "  Max Mustermann\n"
        "  Dr. Anna Beispiel\n"
        "  Musterfirma GmbH – Geschäftsführung\n\n"
        "Pflichtfeld – kann nicht leer bleiben."
    ),
    "keygen_org_label": "Organisation (O):",
    "keygen_org_tip": (
        "Organisation (O) – optionaler Firmen- oder Behördenname.\n\n"
        "Wird in der Zertifikats-Detailansicht angezeigt und kann helfen,\n"
        "das Zertifikat einer Organisation zuzuordnen.\n\n"
        "Beispiele:\n"
        "  Musterfirma GmbH\n"
        "  Bundesbehörde für Beispielwesen\n\n"
        "Kann leer gelassen werden."
    ),
    "keygen_country_label":   "Land (C):",
    "keygen_country_invalid": "ungültiger Code",
    "keygen_country_tip": (
        "Ländercode (C) – zweistelliger ISO-3166-1-Alpha-2-Code.\n\n"
        "Beispiele: DE, AT, CH, FR, US\n\n"
        "Der Ländercode ist in vielen PKI-Infrastrukturen und Zertifikatsprüfern\n"
        "ein Pflichtfeld. Leer lassen ist möglich, kann aber Kompatibilitätsprobleme\n"
        "mit mancher Software verursachen.\n\n"
        "Groß-/Kleinschreibung wird automatisch in Großbuchstaben umgewandelt."
    ),
    "keygen_email_label": "E-Mail:",
    "keygen_email_tip": (
        "E-Mail-Adresse als Subject Alternative Name (SAN, rfc822Name).\n\n"
        "Die E-Mail wird nicht im Subject-DN eingetragen, sondern als\n"
        "SAN-Extension, was dem aktuellen Standard entspricht.\n\n"
        "Bedeutung:\n"
        "• Erleichtert die Zuordnung des Zertifikats zu einer Person\n"
        "• Wird von einigen E-Mail-Clients (S/MIME) als Pflichtfeld erwartet\n"
        "• Für reine PDF-Signaturen optional\n\n"
        "Kann leer gelassen werden."
    ),

    # Datei & Passwort
    "keygen_path_label": "Speicherpfad:",
    "keygen_path_tip": (
        "Dateipfad für die PKCS#12-Datei (.p12 oder .pfx).\n\n"
        "PKCS#12 ist ein Containerformat, das den privaten Schlüssel und das\n"
        "Zertifikat in einer einzigen Datei bündelt. Diese Datei wird dann\n"
        "in der Signatur-Konfiguration als 'P12/PFX-Datei' angegeben.\n\n"
        "Empfehlung: Datei an einem sicheren, gesicherten Ort speichern.\n"
        "Der private Schlüssel ist das Kernelement Ihrer Signatur.\n"
        "Verlust bedeutet, dass keine neuen Signaturen erstellt werden können.\n"
        "Kopieren Sie die Datei auf ein Backup-Medium."
    ),
    "keygen_password_label":       "Passwort:",
    "keygen_password_placeholder": "Passwort für den privaten Schlüssel",
    "keygen_password_tip": (
        "Passwort zum Schutz des privaten Schlüssels in der P12-Datei.\n\n"
        "Der private Schlüssel wird mit AES-256 verschlüsselt, wenn ein\n"
        "Passwort angegeben wird.\n\n"
        "Empfehlung: Immer ein starkes Passwort vergeben!\n"
        "Wer die P12-Datei ohne Passwortschutz erlangt, kann sofort\n"
        "Signaturen in Ihrem Namen erstellen.\n\n"
        "Ohne Passwort (Feld leer lassen): Datei ist unverschlüsselt.\n"
        "Nur sinnvoll wenn die Datei auf einem verschlüsselten Laufwerk liegt."
    ),
    "keygen_password2_label":       "Passwort (wdh.):",
    "keygen_password2_placeholder": "Passwort zur Bestätigung wiederholen",
    "keygen_password2_tip": (
        "Wiederholung des Passworts zur Bestätigung.\n\n"
        "Muss mit dem Passwort im Feld 'Passwort' übereinstimmen."
    ),

    # Buttons & Meldungen
    "keygen_btn_generate":      "Erzeugen",
    "keygen_save_title":        "Schlüsseldatei speichern unter…",
    "keygen_save_filter":       "PKCS#12-Dateien (*.p12 *.pfx);;Alle Dateien (*)",
    "keygen_error_title":       "Eingabefehler",
    "keygen_error_cn_empty":    "Bitte einen Namen (CN) eingeben.",
    "keygen_error_path_empty":  "Bitte einen Speicherpfad angeben.",
    "keygen_error_pw_mismatch": "Die Passwörter stimmen nicht überein.",
    "keygen_error_country_len": "Der Ländercode muss genau 2 Buchstaben lang sein (z.B. DE).",
    "keygen_error_failed":      "Schlüsselerzeugung fehlgeschlagen:\n\n{error}",
    "keygen_success_title":     "Schlüssel erzeugt ✓",
    "keygen_success_msg": (
        "Schlüssel und selbstsigniertes Zertifikat wurden erfolgreich erzeugt.\n\n"
        "Datei: {path}\n\n"
        "Der Pfad wurde automatisch in die Konfiguration übernommen.\n"
        "Klicken Sie auf 'Speichern', um die Einstellungen zu sichern."
    ),

    # openssl-Äquivalent-Abschnitt
    "keygen_section_openssl": "openssl-Äquivalent",
    "keygen_openssl_tip": (
        "Äquivalenter openssl-Befehl zur Erzeugung derselben Datei – "
        "zur Transparenz und für die manuelle Ausführung.\n"
        "openssl fragt beim Ausführen interaktiv nach dem Passwort."
    ),
    "keygen_btn_run":      "Ausführen",
    "keygen_btn_run_tip":  (
        "openssl in einem Terminalfenster ausführen.\n"
        "openssl fragt dort interaktiv nach dem Passwort –\n"
        "kein Passwort wird aus der Maske übertragen.\n"
        "Benötigt: openssl und einen Terminal-Emulator (xterm o.ä.)."
    ),
    "keygen_btn_copy":     "Kopieren",
    "keygen_btn_copy_tip": "openssl-Befehl in die Zwischenablage kopieren.",
    "keygen_openssl_not_found": (
        "openssl wurde nicht im Systempfad (PATH) gefunden.\n\n"
        "Bitte installieren Sie openssl oder verwenden Sie die Schaltfläche "
        "'Erzeugen' (interne Implementierung ohne externe Abhängigkeiten)."
    ),
    "keygen_openssl_no_terminal": (
        "Kein Terminal-Emulator im Systempfad gefunden.\n\n"
        "Gesucht: x-terminal-emulator, xterm, konsole, xfce4-terminal, "
        "mate-terminal, gnome-terminal.\n\n"
        "Bitte installieren Sie einen Terminal-Emulator oder kopieren Sie den "
        "Befehl und führen Sie ihn manuell in einem Terminal aus."
    ),
    "keygen_openssl_failed": "openssl-Ausführung fehlgeschlagen:\n\n{error}",
}
