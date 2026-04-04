# SPDX-License-Identifier: GPL-3.0-or-later
"""English UI translations for PDF QES Signer."""

TRANSLATIONS: dict[str, str] = {
    # Generic buttons
    "btn_ok":     "OK",
    "btn_cancel": "Cancel",
    "btn_close":  "Close",

    # Profile menu
    "menu_profile":        "Profiles…",
    "dlg_profile_mgr_title":   "Manage Profiles",
    "dlg_profile_new_short":   "New",
    # Profile dialogs
    "dlg_profile_select_title":      "Select Profile",
    "dlg_profile_active":            "(active)",
    "dlg_profile_activate":          "Activate",
    "dlg_profile_new_title":         "New Profile",
    "dlg_profile_new_label":         "Profile name:",
    "dlg_profile_new_btn":           "Create",
    "dlg_profile_exists_title":      "Profile already exists",
    "dlg_profile_exists_msg":        "A profile named '{name}' already exists.\nDo you want to overwrite it?",
    "dlg_profile_rename_title":      "Rename Profile",
    "dlg_profile_rename_label":      "New name:",
    "dlg_profile_rename_btn":        "Rename",
    "dlg_profile_delete_title":      "Delete Profile",
    "dlg_profile_delete_btn":        "Delete",
    "dlg_profile_delete_active_msg": "'{name}' is the active profile.\nAfter deletion, '{next}' will become active.\nReally delete?",
    "dlg_profile_delete_confirm_msg":"Really delete profile '{name}'?",
    "dlg_profile_last_title":        "Last Profile",
    "dlg_profile_last_msg":          "At least one profile must exist.\n\nWould you like to reset the parameters to their defaults?",
    "dlg_profile_reset_btn":         "Reset to defaults",
    "dlg_profile_invalid_name":      "Invalid profile name. Please use only letters, digits, spaces, hyphens and underscores.",
    "dlg_profile_empty_name":        "Please enter a profile name.",
    "dlg_profile_name_exists":       "A profile with this name already exists.",
    "status_profile":                "Profile",
    # Menu
    "menu_file": "File",
    "menu_file_open": "Open PDF…",
    "menu_file_save_fields": "Save with fields (copy)…",
    "menu_file_quit": "Quit",
    "menu_sign": "Sign",
    "menu_sign_document": "Sign document…",
    "menu_settings": "Settings",
    "menu_settings_pkcs11": "Configure Signing / Token…",
    "menu_settings_language": "Language / Sprache",
    "menu_help": "Help",
    "menu_help_about": "About…",
    "menu_help_license": "License…",
    # Toolbar
    "tb_open": "Open PDF",
    "tb_prev": "Previous page",
    "tb_next": "Next page",
    "tb_zoom_out":   "Zoom Out  (Ctrl+wheel)",
    "tb_zoom_in":    "Zoom In  (Ctrl+wheel)",
    "tb_fit_width":  "Fit Page Width",
    "tb_fit_height": "Fit Page Height",
    "tb_sign": "✍ Sign",
    "tb_check_sigs": "🔍 Check signatures",
    "tb_save_fields": "💾 Save PDF",
    # Right panel – Fields
    "panel_fields": "Signature Fields",
    "btn_delete_field": "🗑 Delete",
    "btn_save_fields": "💾 Save as PDF",
    # Right panel – Token / PIN
    "panel_token":     "Token / PIN",
    "panel_token_pfx": "P12/PFX File / Password",
    "pin_label":       "PIN:",
    "pin_hint":        "leave empty for PIN pad",
    "pin_label_pfx":   "Password:",
    "pin_hint_pfx":    "leave empty if not password protected",
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
        "The following packages are missing for signing:\n\n{packages}\n\n"
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
    "dlg_sign_success_msg": "Signature successfully applied.\n\nFile: {path}",
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
    "dlg_sign_error_msg_pfx": (
        "Error during signing:\n\n{error}\n\n"
        "Common causes:\n"
        "• Wrong password (or leave empty if not protected)\n"
        "• P12/PFX file not found or corrupt\n"
        "• No private key found in the file\n\n"
        "Full traceback in console (stderr)."
    ),
    "dlg_field_already_signed": "This field is already signed and cannot be used again.",
    "warn_docmdp_p1":     "Document locked – no changes allowed (docMDP P=1)",
    "warn_docmdp_p2":     "Document restricted – form fields & signatures only (docMDP P=2)",
    "dlg_docmdp_title":   "Document Restriction",
    "dlg_docmdp_info":    (
        "This is the first signature in this document.\n"
        "Choose what changes are still allowed afterwards:"
    ),
    "dlg_docmdp_none":    "No restriction",
    "dlg_docmdp_p2":      "Form fields & further signatures allowed (recommended)",
    "dlg_docmdp_p1":      "No further changes allowed",
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
    "tsa_enabled_label":   "🕐 Enable Timestamp (TSA)",
    "cfg_ocsp_lta_label":  "Embed revocation status for long-term archival (OCSP/PAdES-LTA)",
    "cfg_ocsp_lta_hint": (
        "Embeds the current revocation status of all certificates and adds an "
        "archival timestamp. Requires a CA-issued certificate with OCSP service."
    ),
    "cfg_ocsp_self_signed_hint": (
        "Not available: the selected certificate is self-signed. "
        "A CA-issued certificate is required for long-term archival."
    ),
    "dlg_ocsp_warning_title": "Long-term archival not embedded",
    "dlg_ocsp_warning_msg": (
        "The revocation status could not be retrieved — "
        "the document was signed without long-term archival data.\n\n"
        "Timestamp and signature were added successfully.\n\n"
        "Technical cause: {error}"
    ),
    # Signing configuration dialog
    "cfg_title":       "Configure Signing / Token",
    "cfg_tab_pkcs11":  "Signing Method",
    "cfg_tab_tsa":     "Timestamp (TSA)",
    "cfg_mode_label":  "Method:",
    "cfg_mode_pkcs11": "Hardware Token (PKCS#11)",
    "cfg_mode_pfx":    "Key & Certificate (P12/PFX)",
    "cfg_pfx_path_label":    "P12/PFX file:",
    "cfg_pfx_browse_title":  "Choose P12/PFX file",
    "cfg_pfx_filter":        "P12/PFX Files (*.p12 *.pfx);;All Files (*)",
    "cfg_pfx_show_cert_btn": "Show Certificate",
    "cfg_pfx_encrypted_yes": "Password protected",
    "cfg_pfx_encrypted_no":  "Not password protected",
    "cfg_pfx_no_file":        "No P12/PFX file selected.",
    "cfg_pfx_password_title": "Password required",
    "cfg_pfx_password_prompt": (
        "The P12/PFX file is password protected.\n"
        "Enter password (will not be stored):"
    ),
    "cfg_pfx_wrong_password_prompt": (
        "Wrong password. Please try again:"
    ),
    "cfg_tsa_url": "TSA URL:",
    "cfg_tsa_hint": "RFC 3161 timestamp service. Leave empty for default (BaltStamp).",
    "cfg_lib_label": "Library path (.so / .dll):",
    "cfg_lib_browse": "…",
    "cfg_key_id_label":       "Key ID:",
    "cfg_key_id_placeholder": "hex ID (filled automatically on token test)",
    "cfg_key_id_hint":        "↑ CKA_ID of the private key (from token dialog)",
    "cfg_cert_cn_label":      "Name:",
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
        "• 'Test Token (no PIN)' – reads key ID from certificate\n"
        "• PIN pad works normally during signing"
    ),
    "cfg_save_btn": "Save",
    "cfg_cancel_btn": "Cancel",
    "dlg_browse_lib": "Choose PKCS#11 Library",
    "dlg_token_error_title": "Token Error",
    "dlg_token_info_title": "Token Contents",
    "dlg_token_info_label": "Name: {label}    Manufacturer: {manufacturer}",
    "dlg_token_class_private_key":         "Private Keys",
    "dlg_token_class_private_key_derived": "Private Keys (derived from public key)",
    "dlg_token_class_certificate":         "Certificates",
    "dlg_token_class_public_key":          "Public Keys",
    "dlg_token_use_key": "Use ID",
    "dlg_token_close":   "Close",
    # PFX info dialog
    "dlg_pfx_info_title":       "Certificate Information",
    "dlg_pfx_private_key":      "Private Key",
    "dlg_pfx_signing_cert":     "Signing Certificate",
    "dlg_pfx_subject":          "Subject:",
    "dlg_pfx_issuer":           "Issuer:",
    "dlg_pfx_valid_from":       "Valid from:",
    "dlg_pfx_valid_to":         "Valid to:",
    "dlg_pfx_serial":           "Serial number:",
    "dlg_pfx_self_signed":      "(self-signed)",
    "dlg_pfx_chain_header":     "Certificate Chain ({n} certificate(s))",
    "dlg_pfx_use_cn":           "Use CN",
    "dlg_pfx_load_error_title": "Error",
    "dlg_pfx_load_error":       "Could not load P12/PFX file:\n{error}",
    "dlg_token_no_key_title": "No Private Key Found",
    "dlg_token_no_key_msg": (
        "No private key found.\n\n"
        "A PIN may be required to access the key.\n\n"
        "Alternatively, the key label can be derived from the available public keys."
    ),
    "dlg_token_derive_btn": "Derive key label from public key",
    "dlg_token_cancel_pin_btn": "Cancel – read token with PIN",
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
        "Left-click + drag    →  draw signature field\n"
        "Right-click on field →  options / delete\n"
        "Ctrl + drag          →  zoom into selection\n"
        "Middle-drag          →  pan the view"
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

    # ── Signature validation ──────────────────────────────────────────────
    "menu_check_sigs":          "Check Signatures…",
    "val_dlg_title":            "Signature Validation",
    "val_col_item":             "Item",
    "val_col_source":           "Origin",
    "val_col_status":           "Valid",
    "val_col_rev":              "Rev",
    "val_col_element":          "Element",
    "val_col_name":             "Name",
    "val_col_tsa":              "TSA",
    "val_col_time":             "Time",
    "val_col_valid_until":      "Validity",
    "val_sub_field":            "Identifier: {value}",
    "val_sub_name":             "Name: {value}",
    "val_sub_issuer":           "Issuer: {value}",
    "val_overall_valid":        "VALID",
    "val_overall_unknown":      "UNKNOWN",
    "val_overall_invalid":      "INVALID",
    "val_overall_not_checked":  "…",
    "val_rev_label":            "Rev {n} / {total}",
    "val_sig_type_signature":   "Signature",
    "val_sig_type_timestamp":   "Archival Timestamp",
    "val_sig_type_lta":         "TSA (LTA) Timestamp",
    "val_signer":               "Signer",
    "val_signing_time":         "Signing time",
    "val_tsa_time":             "TSA timestamp",
    "val_checks":               "Crypto: {crypto}  Chain: {chain}  Revocation: {revoc}",
    "val_cert_chain":           "Certificate chain",
    "val_cert_root":            "Root CA",
    "val_cert_self_signed":     "self-signed",
    "val_cert_intermediate":    "CA",
    "val_cert_end_entity":      "Signing certificate",
    "val_ocsp":                 "OCSP: {status}",
    "val_ocsp_good":            "good",
    "val_ocsp_revoked":         "revoked",
    "val_ocsp_unknown":         "unknown",
    "val_src_embedded":         "embedded",
    "val_src_system":           "Mozilla",
    "val_src_eu_tsl":           "nat. TSL",
    "val_src_downloaded":       "downloaded",
    "val_src_not_found":        "not found",
    "val_tsa_is_tsa":           "(is TSA)",
    "val_col_integrity":        "Integrity",
    "val_integrity_ok":         "✓ unchanged",
    "val_integrity_fail":       "✗ signature invalid",
    "val_field_name":           "Field: {name}",
    "val_self_reported":        "Self-reported: {time}",
    "val_doc_info":             "{n} revision(s)",
    "val_doc_dss":              "  · DSS",
    "val_doc_lta":              "  · LTA",
    "val_phase2_running":       "Online validation running…",
    "val_phase2_done":          "Validation complete.",
    "val_phase2_error":         "Error: {msg}",
    "val_btn_recheck":          "Re-check",
    "val_no_sigs":              "No signatures found in document.",
    "val_no_pdf":               "No PDF open.",

    # Unsigned revision types
    "val_rev_type_original":    "Original document",
    "val_rev_type_form_fields": "Form fields",
    "val_rev_type_annotations": "Annotations",
    "val_rev_type_dss":         "Validation data (DSS)",
    "val_rev_type_metadata":    "Document metadata (XMP)",
    "val_rev_type_unknown":     "Incremental update",

    # Warning: changes after last signature
    "val_warn_post_sig_title":  "Document modified after last signature",
    "val_warn_post_sig_body":   "The following changes were added after the last signature"
                                " and are not covered by any signature: {types}\n"
                                "The currently displayed content may differ from the signed state.",
    "val_warn_post_sig_short":  "⚠  Document modified after the last signature ({types})."
                                "  Please check the signatures.",
    "val_warn_between_sig_title": "Changes between signatures",
    "val_warn_between_sig_body":  "The following changes were added after the first signature"
                                  " and are only covered by a later signature: {types}\n"
                                  "The first signature does not cover this content.",
    "val_warn_between_sig_short": "⚠  Changes between signatures ({types}) –"
                                  " not covered by all signatures.",

    # Main list (new tree view)
    "val_sig_type_doc_ts":          "Document Timestamp",
    "val_rev_no_sig":               "–  (no signature)",
    "val_show_all_revisions":       "Show all revisions",
    "val_detail_date":              "Date",
    "val_detail_integrity":         "Integrity",
    "val_detail_profile":           "Profile",
    "val_date_tsa":                 "{time}  (TSA-confirmed)",
    "val_date_self":                "{time}  (self-reported)",
    "val_date_doc_ts":              "{time}",
    "val_profile_is_doc_ts":        "–  (is itself the document timestamp)",
    "val_profile_details_B":        "TSA token –, DSS –",
    "val_profile_details_T":        "TSA token ✓, DSS –",
    "val_profile_details_LT":       "TSA token ✓, DSS ✓, LTA timestamp –",
    "val_profile_details_LTA":      "TSA token ✓, DSS ✓, LTA timestamp ✓",
    "val_profile_meaning_B":        "No additional validation data embedded",
    "val_profile_meaning_T":        "Signing time secured, validation data not embedded",
    "val_profile_meaning_LT":       "Validation data embedded, but not cryptographically secured",
    "val_profile_meaning_LTA":      "All validation data embedded and cryptographically secured",

    # Certificate chain summary rows in validation tree
    "val_detail_sig_chain":         "Sig. chain",
    "val_detail_tsa_chain":         "TSA chain",
    "val_chain_details_btn":        "Details →",

    # Chain status labels
    "val_chain_valid":              "✓ Valid",
    "val_chain_incomplete":         "✗ Incomplete",
    "val_chain_expired":            "✗ Expired",
    "val_chain_revoked":            "✗ Revoked",
    "val_chain_unknown_root":       "Complete · Root unknown",
    "val_chain_unknown_revoc":      "Complete · Revocation unknown",
    "val_chain_not_checked":        "–",

    # Tooltips for chain status labels
    "val_chain_valid_tip":          "Chain complete, root trusted (certifi/Mozilla bundle), revocation embedded and good.",
    "val_chain_incomplete_tip":     "The certificate chain is broken – an intermediate CA certificate is missing.",
    "val_chain_expired_tip":        "At least one certificate in the chain was outside its validity period at signing time.",
    "val_chain_revoked_tip":        "The signing certificate was revoked according to the embedded OCSP response.",
    "val_chain_unknown_root_tip":   "The chain is complete but the root certificate is only embedded in the document and not found in a known trust store (certifi/Mozilla bundle).",
    "val_chain_unknown_revoc_tip":  "The root certificate is trusted (certifi/Mozilla bundle) but the revocation status of the signing certificate has not been checked.",
    "val_chain_self_signed":        "Self-signed · no CA trust",
    "val_chain_self_signed_tip":    "The certificate is self-issued – there is no issuing certificate authority. The certificate is embedded in the document but is not present in any known trust store.",

    # Certificate chain detail window
    "cert_win_title_sig":           "Signature chain – {cn}",
    "cert_win_title_tsa":           "TSA chain – {cn}",
    "cert_win_role_ee":             "End-Entity",
    "cert_win_role_intermediate":   "Intermediate",
    "cert_win_role_root":           "Root",
    "cert_win_role_self_signed":    "Self-signed",
    "cert_win_self_signed_issuer":  "(self-signed)",
    "cert_win_label_issuer":        "Issuer",
    "cert_win_label_valid":         "Valid",
    "cert_win_label_source":        "Source",
    "cert_win_label_ocsp":          "OCSP",
    "cert_win_label_overall":       "Overall status",
    "cert_win_source_embedded":     "Embedded (PDF)",
    "cert_win_source_certifi":      "certifi (Mozilla bundle)",
    "cert_win_source_system":       "System trust store",
    "cert_win_source_downloaded":   "Downloaded (AIA)",
    "cert_win_source_not_found":    "Not found",
    "cert_win_source_unknown":      "Unknown",
    "cert_win_ocsp_good":           "good ✓",
    "cert_win_ocsp_revoked":        "revoked ✗",
    "cert_win_ocsp_unknown":        "unknown",
    "cert_win_ocsp_not_checked":    "not checked",
    "cert_win_close":               "Close",
}
