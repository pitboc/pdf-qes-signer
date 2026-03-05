# SPDX-License-Identifier: GPL-3.0-or-later
"""English UI translations for PDF QES Signer."""

TRANSLATIONS: dict[str, str] = {
    # Menu
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
    "menu_help_license": "License…",
    # Toolbar
    "tb_open": "Open PDF",
    "tb_prev": "◀",
    "tb_next": "▶",
    "tb_sign": "✍ Sign (QES)",
    "tb_save_fields": "💾 Save fields",
    # Right panel – Fields
    "panel_fields": "Signature Fields",
    "btn_delete_field": "🗑 Delete",
    "btn_save_fields": "💾 Save as PDF",
    # Right panel – Token / PIN
    "panel_token": "Token / PIN",
    "pin_label": "PIN:",
    "pin_hint": "leave empty for PIN pad",
    # Right panel – Signature appearance
    "panel_appearance": "Signature Appearance",
    "app_layout_label": "Layout:",
    "app_layout_img_left": "Image Left | Text Right",
    "app_layout_img_right": "Text Left | Image Right",
    "app_location_label": "Location:",
    "app_reason_label": "Reason:",
    "app_name_label": "Name:",
    "app_name_cert": "(from certificate)",
    "app_date_label": "Date:",
    "app_show_date": "Show date",
    # Appearance config dialog
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
    # Status bar
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
    # Dialogs
    "dlg_field_name_title": "Field Name",
    "dlg_field_name_prompt": "Signature field name:",
    "dlg_field_name_default": "Sig_{page}_{count}",
    "dlg_field_name_duplicate": "A field named '{name}' already exists. Please choose a different name.",
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
    "dlg_field_already_signed": "This field is already signed and cannot be used again.",
    "dlg_locked_field_title": "Field locked",
    "dlg_locked_field_msg": (
        "The field '{name}' is protected by an existing signature in the document\n"
        "and cannot be deleted or moved.\n\n"
        "It can only be signed."
    ),
    "dlg_pyhanko_missing": "pyhanko is not installed.\npip install pyhanko python-pkcs11",
    "dlg_choose_field_title": "Choose Signature Field",
    "dlg_choose_field_label": "Sign with which field?",
    "dlg_invisible_field": "✦ Signature without field (invisible)",
    # PKCS#11 dialog
    "cfg_title": "Configure PKCS#11 / Token",
    "cfg_lib_label": "Library path (.so / .dll):",
    "cfg_lib_browse": "…",
    "cfg_key_label": "Key Label:",
    "cfg_key_hint": "↑ filled automatically on token test",
    "cfg_pin_label": "PIN (test only):",
    "cfg_pin_placeholder": "leave empty for PIN pad",
    "cfg_pin_hint": "↑ for token test only, not saved",
    "cfg_test_btn_no_pin": "🔑 Test Token (no PIN)",
    "cfg_test_btn_with_pin": "🔑 Test Token (with PIN)",
    "cfg_pinpad_test_title": "PIN pad not testable",
    "cfg_pinpad_test_msg": (
        "The PIN pad cannot be triggered in the token test,\n"
        "because python-pkcs11 does not expose a separate login call.\n\n"
        "Alternatives:\n"
        "• Enter your PIN here to list private keys directly\n"
        "• 'Test Token (no PIN)' – determines key label without PIN\n"
        "• PIN pad works normally during signing"
    ),
    "cfg_save_btn": "Save",
    "cfg_cancel_btn": "Cancel",
    "dlg_browse_lib": "Choose PKCS#11 Library",
    "dlg_token_error_title": "Token Error",
    "dlg_token_info_title": "Token Contents",
    "dlg_token_info_label": "Name: {label}    Manufacturer: {manufacturer}",
    "dlg_token_keys_title": "Private Keys  (derived, double-click → apply)",
    "dlg_token_certs_title": "Certificate Labels",
    "dlg_token_use_key": "✓ Use Key Label",
    "dlg_token_copy_key": "📋 Copy Key",
    "dlg_token_copy_cert": "📋 Copy Cert",
    "dlg_token_close": "Close",
    "dlg_token_auto_label": "Key label auto-set: {label}",
    # Appearance panel (main window)
    "ap_tab_text": "Text",
    "ap_tab_image_layout": "Image / Layout",
    "ap_name_from_cert": "Certificate",
    "ap_name_custom": "Custom",
    "ap_font_pt": "Size (pt):",
    "ap_font_family": "Font:",
    "ap_img_none": "(no image)",
    "ap_img_hint": "Transparency supported.",
    "ap_layout_left": "Image left",
    "ap_layout_right": "Image right",
    "ap_border": "Show border",
    "ap_date_custom": "Custom format…",
    "ap_img_label": "◀ Image {v}%",
    "ap_txt_label": "Text {r}% ▶",
    "ap_txt_label_left": "Text {r}% ▶",
    "ap_img_label_right": "◀ Image {v}%",
    "ap_preview_hint": "Please add a signature field for preview.",
    "ap_browse_img": "Choose signature image",
    "ap_img_filter": "Images (*.png *.jpg *.jpeg *.bmp);;All Files (*)",
    # About / License
    "about_title": "About PDF QES Signer",
    "about_msg": (
        "PDF QES Signer  v{version}  (commit: {commit})\n\n"
        "Visual placement of signature fields\n"
        "and qualified electronic signature (QES)\n"
        "via PKCS#11 / Smartcard.\n\n"
        "License: GNU General Public License v3 or later (GPL-3.0-or-later)\n\n"
        "Required packages:\n"
        "  pip install pymupdf pyhanko python-pkcs11 Pillow PyQt6 cryptography\n\n"
        "Left-click + drag   →  draw signature field\n"
        "Right-click on field →  options / delete"
    ),
    "license_title": "License Information",
    "license_msg": (
        "PDF QES Signer\n"
        "Copyright (C) PDF QES Signer contributors\n\n"
        "This program is free software: you can redistribute it and/or modify\n"
        "it under the terms of the GNU General Public License as published by\n"
        "the Free Software Foundation, either version 3 of the License, or\n"
        "(at your option) any later version.\n\n"
        "This program is distributed in the hope that it will be useful,\n"
        "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
        "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
        "See the GNU General Public License for more details.\n\n"
        "You should have received a copy of the GNU General Public License\n"
        "along with this program. If not, see:\n"
        "  https://www.gnu.org/licenses/gpl-3.0.html\n\n"
        "──────────────────────────────────────────────\n"
        "Third-party libraries:\n\n"
        "  PyMuPDF (fitz)   GNU AGPL v3\n"
        "    https://pymupdf.readthedocs.io\n\n"
        "  pyhanko          MIT License\n"
        "    https://pyhanko.readthedocs.io\n\n"
        "  PyQt6            GPL v3 / Commercial\n"
        "    https://www.riverbankcomputing.com\n\n"
        "  python-pkcs11    MIT License\n"
        "    https://python-pkcs11.readthedocs.io\n\n"
        "  Pillow           HPND License\n"
        "    https://python-pillow.org\n\n"
        "  cryptography     Apache 2.0 / BSD\n"
        "    https://cryptography.io\n"
    ),
    "license_close": "Close",
}
