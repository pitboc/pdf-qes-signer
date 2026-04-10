# SPDX-License-Identifier: GPL-3.0-or-later
"""
Consolidated settings dialog for PDF QES Signer.

Firefox-style: left navigation list, right stacked pages.
Changes are written to the config object immediately (live save);
config.save() is called once when the dialog closes.

Pages
-----
0 – Token / Signatur   replaces Pkcs11ConfigDialog Tab 1
1 – Zeitstempel        replaces Pkcs11ConfigDialog Tab 2
2 – Validierung        auto_fetch_revocation
3 – Trust Store Cache  replaces TrustStoreCacheDialog
4 – Updates            check_on_startup + channel
5 – Allgemein          language selection
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QDialog, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QMessageBox,
    QPushButton, QRadioButton, QStackedWidget, QVBoxLayout, QWidget,
    QCheckBox, QComboBox,
)

from .config import AppConfig
from .i18n import t, AVAILABLE_LANGUAGES


class SettingsDialog(QDialog):
    """Consolidated settings dialog with Firefox-style left navigation.

    Save strategy: every widget signal immediately writes to *config*
    (in-memory); ``config.save()`` is called once in ``closeEvent``.
    """

    language_changed = pyqtSignal(str)

    PAGE_TOKEN      = 0
    PAGE_TSA        = 1
    PAGE_VALIDATION = 2
    PAGE_CACHE      = 3
    PAGE_UPDATES    = 4
    PAGE_GENERAL    = 5

    def __init__(self, config: AppConfig, parent=None,
                 initial_page: int = 0) -> None:
        super().__init__(parent)
        self.config = config
        self._pfx_info: dict | None = None
        self.setWindowTitle(t("settings_title"))
        self.setMinimumWidth(700)
        self.setMinimumHeight(500)
        self._build_ui()
        self._load_values()
        self._nav.setCurrentRow(initial_page)

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        main_lay = QHBoxLayout(self)

        self._nav = QListWidget()
        self._nav.setFixedWidth(155)
        self._nav.setFrameShape(QListWidget.Shape.NoFrame)
        for key in ("settings_nav_token", "settings_nav_tsa",
                    "settings_nav_validation", "settings_nav_cache",
                    "settings_nav_updates", "settings_nav_general"):
            self._nav.addItem(t(key))
        self._nav.setCurrentRow(0)
        main_lay.addWidget(self._nav)

        sep = QWidget()
        sep.setFixedWidth(1)
        sep.setStyleSheet("background-color: #c0c0c0;")
        main_lay.addWidget(sep)

        right_lay = QVBoxLayout()
        right_lay.setContentsMargins(8, 0, 0, 0)

        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_page_token())
        self._stack.addWidget(self._build_page_tsa())
        self._stack.addWidget(self._build_page_validation())
        self._stack.addWidget(self._build_page_cache())
        self._stack.addWidget(self._build_page_updates())
        self._stack.addWidget(self._build_page_general())
        right_lay.addWidget(self._stack)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._close_btn = QPushButton(t("dlg_token_close"))
        self._close_btn.clicked.connect(self.accept)
        btn_row.addWidget(self._close_btn)
        right_lay.addLayout(btn_row)

        main_lay.addLayout(right_lay, 1)

        self._nav.currentRowChanged.connect(self._on_page_changed)

    def _on_page_changed(self, idx: int) -> None:
        self._stack.setCurrentIndex(idx)
        if idx == self.PAGE_CACHE:
            self._refresh_cache()

    # ── Page builders ─────────────────────────────────────────────────────

    def _build_page_token(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)

        mode_row = QHBoxLayout()
        self._mode_combo = QComboBox()
        self._mode_combo.addItem(t("cfg_mode_pfx"),    "pfx")
        self._mode_combo.addItem(t("cfg_mode_pkcs11"), "pkcs11")
        mode_row.addWidget(QLabel(t("cfg_mode_label")))
        mode_row.addWidget(self._mode_combo, 1)
        lay.addLayout(mode_row)

        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        # PKCS#11-specific
        lib_row = QHBoxLayout()
        self._lib_edit = QLineEdit()
        self._lib_edit.setPlaceholderText(
            "C:\\Windows\\System32\\P11TCOSSigGx64.dll"
            if sys.platform == "win32"
            else "/usr/lib/.../opensc-pkcs11.so"
        )
        bb = QPushButton(t("cfg_lib_browse"))
        bb.setFixedWidth(36)
        bb.clicked.connect(self._browse_lib)
        lib_row.addWidget(self._lib_edit)
        lib_row.addWidget(bb)
        self._lib_lbl    = QLabel(t("cfg_lib_label"))
        self._lib_widget = QWidget()
        self._lib_widget.setLayout(lib_row)
        form.addRow(self._lib_lbl, self._lib_widget)

        self._key_id_edit = QLineEdit()
        self._key_id_edit.setPlaceholderText(t("cfg_key_id_placeholder"))
        self._key_id_lbl  = QLabel(t("cfg_key_id_label"))
        self._key_id_hint = QLabel(t("cfg_key_id_hint"))
        self._key_id_hint.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow(self._key_id_lbl, self._key_id_edit)
        form.addRow("", self._key_id_hint)

        self._pin_edit = QLineEdit()
        self._pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pin_edit.setPlaceholderText(t("cfg_pin_placeholder"))
        self._pin_lbl  = QLabel(t("cfg_pin_label"))
        self._pin_hint = QLabel(t("cfg_pin_hint"))
        self._pin_hint.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow(self._pin_lbl, self._pin_edit)
        form.addRow("", self._pin_hint)

        # PFX-specific
        pfx_row = QHBoxLayout()
        self._pfx_edit = QLineEdit()
        self._pfx_edit.setPlaceholderText(t("cfg_pfx_path_label"))
        self._pfx_edit.textChanged.connect(self._on_pfx_path_changed)
        pfx_bb = QPushButton(t("cfg_lib_browse"))
        pfx_bb.setFixedWidth(36)
        pfx_bb.clicked.connect(self._browse_pfx)
        pfx_row.addWidget(self._pfx_edit)
        pfx_row.addWidget(pfx_bb)
        self._pfx_lbl    = QLabel(t("cfg_pfx_path_label"))
        self._pfx_widget = QWidget()
        self._pfx_widget.setLayout(pfx_row)
        self._pfx_hint = QLabel("")
        self._pfx_hint.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow(self._pfx_lbl, self._pfx_widget)
        form.addRow("", self._pfx_hint)

        # Common CN (read-only)
        self._cert_cn_edit = QLineEdit()
        self._cert_cn_edit.setReadOnly(True)
        self._cert_cn_edit.setStyleSheet("color: gray;")
        self._cert_cn_lbl = QLabel(t("cfg_cert_cn_label"))
        form.addRow(self._cert_cn_lbl, self._cert_cn_edit)
        lay.addLayout(form)

        # PKCS#11 test buttons
        self._pkcs11_test_widget = QWidget()
        test_row = QHBoxLayout(self._pkcs11_test_widget)
        test_row.setContentsMargins(0, 0, 0, 0)
        test_no_pin   = QPushButton(t("cfg_test_btn_no_pin"))
        test_with_pin = QPushButton(t("cfg_test_btn_with_pin"))
        test_no_pin.clicked.connect(lambda: self._test_token(with_pin=False))
        test_with_pin.clicked.connect(lambda: self._test_token(with_pin=True))
        test_row.addWidget(test_no_pin)
        test_row.addWidget(test_with_pin)
        lay.addWidget(self._pkcs11_test_widget)

        # PFX action buttons
        self._pfx_action_widget = QWidget()
        pfx_act_row = QHBoxLayout(self._pfx_action_widget)
        pfx_act_row.setContentsMargins(0, 0, 0, 0)
        self._pfx_show_cert_btn = QPushButton(t("cfg_pfx_show_cert_btn"))
        self._pfx_show_cert_btn.clicked.connect(self._show_pfx_cert)
        self._pfx_keygen_btn = QPushButton(t("cfg_pfx_keygen_btn"))
        self._pfx_keygen_btn.setToolTip(t("cfg_pfx_keygen_tip"))
        self._pfx_keygen_btn.clicked.connect(self._open_keygen)
        pfx_act_row.addWidget(self._pfx_show_cert_btn)
        pfx_act_row.addWidget(self._pfx_keygen_btn)
        pfx_act_row.addStretch()
        lay.addWidget(self._pfx_action_widget)

        # AIA (shared for both modes)
        self._chain_aia_chk = QCheckBox(t("cfg_chain_aia_label"))
        chain_aia_hint = QLabel(t("cfg_chain_aia_hint"))
        chain_aia_hint.setWordWrap(True)
        chain_aia_hint.setStyleSheet("color: gray; font-size: 10px;")
        lay.addWidget(self._chain_aia_chk)
        lay.addWidget(chain_aia_hint)

        self._tok_status_lbl = QLabel("")
        self._tok_status_lbl.setWordWrap(True)
        lay.addWidget(self._tok_status_lbl)

        # docMDP default
        docmdp_grp = QGroupBox(t("settings_tok_docmdp_label"))
        docmdp_lay = QVBoxLayout(docmdp_grp)
        self._rb_docmdp_none = QRadioButton(t("dlg_docmdp_none"))
        self._rb_docmdp_p2   = QRadioButton(t("dlg_docmdp_p2"))
        self._rb_docmdp_p1   = QRadioButton(t("dlg_docmdp_p1"))
        for rb in (self._rb_docmdp_none, self._rb_docmdp_p2, self._rb_docmdp_p1):
            docmdp_lay.addWidget(rb)
        lay.addWidget(docmdp_grp)
        lay.addStretch()

        # Live-save signals
        self._mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self._mode_combo.currentIndexChanged.connect(
            lambda _: self.config.set(
                "pkcs11", "signer_mode",
                self._mode_combo.currentData() or "pfx"))
        self._lib_edit.editingFinished.connect(
            lambda: self.config.set("pkcs11", "lib_path",
                                    self._lib_edit.text().strip()))
        self._key_id_edit.editingFinished.connect(
            lambda: self.config.set("pkcs11", "key_id",
                                    self._key_id_edit.text().strip()))
        self._pfx_edit.editingFinished.connect(self._on_pfx_editing_finished)
        self._chain_aia_chk.toggled.connect(
            lambda v: self.config.setbool("signing", "chain_complete_via_aia", v))
        self._rb_docmdp_none.toggled.connect(
            lambda v: self.config.set("signing", "docmdp", "none") if v else None)
        self._rb_docmdp_p2.toggled.connect(
            lambda v: self.config.set("signing", "docmdp", "p2") if v else None)
        self._rb_docmdp_p1.toggled.connect(
            lambda v: self.config.set("signing", "docmdp", "p1") if v else None)

        return page

    def _build_page_tsa(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self._tsa_url_edit = QLineEdit()
        self._tsa_url_edit.setPlaceholderText("http://tsa.baltstamp.lt")
        tsa_hint = QLabel(t("cfg_tsa_hint"))
        tsa_hint.setStyleSheet("color: gray; font-size: 10px;")
        tsa_hint.setWordWrap(True)
        form.addRow(t("cfg_tsa_url"), self._tsa_url_edit)
        form.addRow("", tsa_hint)

        self._ocsp_lta_chk = QCheckBox(t("cfg_ocsp_lta_label"))
        self._ocsp_hint_lbl = QLabel()
        self._ocsp_hint_lbl.setWordWrap(True)
        self._ocsp_hint_lbl.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow("", self._ocsp_lta_chk)
        form.addRow("", self._ocsp_hint_lbl)

        self._tsa_url_edit.editingFinished.connect(self._on_tsa_url_finished)
        self._ocsp_lta_chk.toggled.connect(
            lambda v: self.config.setbool("tsa", "embed_validation_info", v))

        return page

    def _build_page_validation(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)

        self._auto_fetch_chk = QCheckBox(t("settings_val_auto_fetch_label"))
        hint = QLabel(t("settings_val_auto_fetch_hint"))
        hint.setWordWrap(True)
        hint.setStyleSheet("color: gray; font-size: 10px;")
        lay.addWidget(self._auto_fetch_chk)
        lay.addWidget(hint)
        lay.addStretch()

        self._auto_fetch_chk.toggled.connect(
            lambda v: self.config.setbool("validation", "auto_fetch_revocation", v))

        return page

    def _build_page_cache(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setSpacing(8)

        self._cache_info_lbl = QLabel()
        self._cache_info_lbl.setTextFormat(Qt.TextFormat.PlainText)
        self._cache_info_lbl.setWordWrap(True)
        self._cache_info_lbl.setAlignment(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self._cache_info_lbl.setStyleSheet("font-family: monospace;")
        lay.addWidget(self._cache_info_lbl, 1)

        btn_row = QHBoxLayout()
        self._btn_clear_tsl = QPushButton(t("trust_cache_btn_clear_tsl"))
        self._btn_clear_tsl.clicked.connect(self._clear_tsl)
        self._btn_clear_all = QPushButton(t("trust_cache_btn_clear_all"))
        self._btn_clear_all.clicked.connect(self._clear_all)
        self._btn_clear_aia = QPushButton(t("trust_cache_btn_clear_aia"))
        self._btn_clear_aia.clicked.connect(self._clear_aia)
        btn_row.addWidget(self._btn_clear_tsl)
        btn_row.addWidget(self._btn_clear_all)
        btn_row.addWidget(self._btn_clear_aia)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        return page

    def _build_page_updates(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)

        self._check_on_startup_chk = QCheckBox(t("settings_check_on_startup"))
        lay.addWidget(self._check_on_startup_chk)

        channel_grp = QGroupBox(t("settings_upd_channel_label"))
        channel_lay = QVBoxLayout(channel_grp)
        self._rb_stable  = QRadioButton(t("settings_upd_stable"))
        self._rb_develop = QRadioButton(t("settings_upd_develop"))
        channel_lay.addWidget(self._rb_stable)
        channel_lay.addWidget(self._rb_develop)
        lay.addWidget(channel_grp)
        lay.addStretch()

        self._check_on_startup_chk.toggled.connect(
            lambda v: self.config.setbool("update", "check_on_startup", v))
        self._rb_stable.toggled.connect(
            lambda v: self.config.set("update", "channel", "stable") if v else None)
        self._rb_develop.toggled.connect(
            lambda v: self.config.set("update", "channel", "develop") if v else None)

        return page

    def _build_page_general(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)

        lang_grp = QGroupBox(t("settings_gen_lang_label"))
        lang_lay = QVBoxLayout(lang_grp)
        self._lang_rbs: dict[str, QRadioButton] = {}
        for code, label in AVAILABLE_LANGUAGES.items():
            rb = QRadioButton(label)
            rb.toggled.connect(
                lambda checked, c=code:
                    self._on_lang_changed(c) if checked else None)
            lang_lay.addWidget(rb)
            self._lang_rbs[code] = rb
        lay.addWidget(lang_grp)
        lay.addStretch()

        return page

    # ── Value loading ─────────────────────────────────────────────────────

    def _load_values(self) -> None:
        # ── Token ────────────────────────────────────────────────────────
        mode = self.config.get("pkcs11", "signer_mode")
        self._mode_combo.blockSignals(True)
        self._mode_combo.setCurrentIndex(1 if mode == "pkcs11" else 0)
        self._mode_combo.blockSignals(False)

        self._lib_edit.setText(self.config.get("pkcs11", "lib_path"))
        self._key_id_edit.setText(self.config.get("pkcs11", "key_id"))
        self._cert_cn_edit.setText(self.config.get("pkcs11", "cert_cn"))

        self._pfx_edit.blockSignals(True)
        self._pfx_edit.setText(self.config.get("pkcs11", "pfx_path"))
        self._pfx_edit.blockSignals(False)

        self._chain_aia_chk.blockSignals(True)
        self._chain_aia_chk.setChecked(
            self.config.getbool("signing", "chain_complete_via_aia"))
        self._chain_aia_chk.blockSignals(False)

        for rb in (self._rb_docmdp_none, self._rb_docmdp_p2, self._rb_docmdp_p1):
            rb.blockSignals(True)
        docmdp = self.config.get("signing", "docmdp")
        {"p2": self._rb_docmdp_p2, "p1": self._rb_docmdp_p1}.get(
            docmdp, self._rb_docmdp_none).setChecked(True)
        for rb in (self._rb_docmdp_none, self._rb_docmdp_p2, self._rb_docmdp_p1):
            rb.blockSignals(False)

        self._on_mode_changed()
        self._update_pfx_hint()
        pfx_path = self._pfx_edit.text().strip()
        if pfx_path and mode == "pfx":
            try:
                from .dialogs import _pfx_load_cert_info
                self._pfx_info = _pfx_load_cert_info(pfx_path)
            except Exception:
                pass
        self._update_ocsp_state()

        # ── TSA ──────────────────────────────────────────────────────────
        self._tsa_url_edit.setText(self.config.get("tsa", "url"))
        self._ocsp_lta_chk.blockSignals(True)
        self._ocsp_lta_chk.setChecked(
            self.config.getbool("tsa", "embed_validation_info"))
        self._ocsp_lta_chk.blockSignals(False)

        # ── Validation ───────────────────────────────────────────────────
        self._auto_fetch_chk.blockSignals(True)
        self._auto_fetch_chk.setChecked(
            self.config.getbool("validation", "auto_fetch_revocation"))
        self._auto_fetch_chk.blockSignals(False)

        # ── Cache ────────────────────────────────────────────────────────
        self._refresh_cache()

        # ── Updates ──────────────────────────────────────────────────────
        self._check_on_startup_chk.blockSignals(True)
        self._check_on_startup_chk.setChecked(
            self.config.getbool("update", "check_on_startup"))
        self._check_on_startup_chk.blockSignals(False)

        for rb in (self._rb_stable, self._rb_develop):
            rb.blockSignals(True)
        channel = self.config.get("update", "channel")
        (self._rb_develop if channel == "develop"
         else self._rb_stable).setChecked(True)
        for rb in (self._rb_stable, self._rb_develop):
            rb.blockSignals(False)

        # ── General ──────────────────────────────────────────────────────
        from .i18n import i18n as _i18n
        for rb in self._lang_rbs.values():
            rb.blockSignals(True)
        lang = _i18n.lang
        if lang in self._lang_rbs:
            self._lang_rbs[lang].setChecked(True)
        for rb in self._lang_rbs.values():
            rb.blockSignals(False)

    # ── Token page helpers ────────────────────────────────────────────────

    def _on_mode_changed(self) -> None:
        pkcs11 = (self._mode_combo.currentData() == "pkcs11")
        for w in (self._lib_lbl, self._lib_widget,
                  self._key_id_lbl, self._key_id_edit, self._key_id_hint,
                  self._pin_lbl, self._pin_edit, self._pin_hint,
                  self._pkcs11_test_widget):
            w.setVisible(pkcs11)
        for w in (self._pfx_lbl, self._pfx_widget, self._pfx_hint,
                  self._pfx_action_widget):
            w.setVisible(not pkcs11)
        self._tok_status_lbl.setText("")
        self._update_ocsp_state()

    def _browse_lib(self) -> None:
        start = self.config.get("paths", "last_lib_dir")
        lib_filter = ("DLL (*.dll);;Shared Libraries (*.so *.so.*);;All Files (*)"
                      if sys.platform == "win32"
                      else t("dlg_lib_filter"))
        path, _ = QFileDialog.getOpenFileName(
            self, t("dlg_browse_lib"), start, lib_filter)
        if path:
            self._lib_edit.setText(path)
            self.config.set("pkcs11", "lib_path", path)
            self.config.set("paths", "last_lib_dir", str(Path(path).parent))

    def _browse_pfx(self) -> None:
        start = self.config.get("paths", "last_open_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("cfg_pfx_browse_title"), start, t("cfg_pfx_filter"))
        if not path:
            return
        self._pfx_edit.setText(path)
        self.config.set("pkcs11", "pfx_path", path)
        self.config.set("paths", "last_open_dir", str(Path(path).parent))
        from .dialogs import _pfx_load_with_prompt
        result = _pfx_load_with_prompt(self, path)
        if result is not None:
            info, _ = result
            self._pfx_info = info
            if info.get("cn"):
                self._cert_cn_edit.setText(info["cn"])
                self.config.set("pkcs11", "cert_cn", info["cn"])
            self._update_ocsp_state()
        self._update_pfx_hint()

    def _on_pfx_path_changed(self, _text: str) -> None:
        self._pfx_info = None
        self._update_pfx_hint()
        self._update_ocsp_state()

    def _on_pfx_editing_finished(self) -> None:
        self.config.set("pkcs11", "pfx_path", self._pfx_edit.text().strip())

    def _update_pfx_hint(self) -> None:
        path = self._pfx_edit.text().strip()
        if not path or not Path(path).exists():
            self._pfx_hint.setText("")
            return
        try:
            from .dialogs import _pfx_check_encrypted
            encrypted = _pfx_check_encrypted(path)
            if encrypted:
                self._pfx_hint.setText(t("cfg_pfx_encrypted_yes"))
                self._pfx_hint.setStyleSheet("color: #c07000; font-size: 10px;")
            else:
                self._pfx_hint.setText(t("cfg_pfx_encrypted_no"))
                self._pfx_hint.setStyleSheet("color: gray; font-size: 10px;")
        except Exception:
            self._pfx_hint.setText("")

    def _update_ocsp_state(self) -> None:
        if not hasattr(self, "_ocsp_lta_chk"):
            return
        mode = self._mode_combo.currentData() or "pfx"
        if mode == "pfx":
            self_signed = bool(
                self._pfx_info and self._pfx_info.get("self_signed", False))
            if self_signed:
                self._ocsp_lta_chk.setEnabled(False)
                self._ocsp_lta_chk.setChecked(False)
                self._ocsp_hint_lbl.setText(t("cfg_ocsp_self_signed_hint"))
                self._ocsp_hint_lbl.setStyleSheet("color: #c07000; font-size: 10px;")
            else:
                self._ocsp_lta_chk.setEnabled(True)
                self._ocsp_hint_lbl.setText(t("cfg_ocsp_lta_hint"))
                self._ocsp_hint_lbl.setStyleSheet("color: gray; font-size: 10px;")
        else:
            self._ocsp_lta_chk.setEnabled(True)
            self._ocsp_hint_lbl.setText(t("cfg_ocsp_lta_hint"))
            self._ocsp_hint_lbl.setStyleSheet("color: gray; font-size: 10px;")

    def _show_pfx_cert(self) -> None:
        path = self._pfx_edit.text().strip()
        if not path:
            self._tok_status_lbl.setText(t("cfg_pfx_no_file"))
            return
        if self._pfx_info is None:
            from .dialogs import _pfx_load_with_prompt
            result = _pfx_load_with_prompt(self, path)
            if result is None:
                return
            info, _ = result
            self._pfx_info = info
        from .dialogs import PfxInfoDialog
        dlg = PfxInfoDialog(self, info=self._pfx_info)
        dlg.cn_selected.connect(self._cert_cn_edit.setText)
        dlg.cn_selected.connect(
            lambda cn: self.config.set("pkcs11", "cert_cn", cn))
        dlg.exec()

    def _open_keygen(self) -> None:
        from .dialogs import KeygenDialog
        last_dir = self.config.get("paths", "last_open_dir")
        dlg = KeygenDialog(self, save_dir=last_dir)
        dlg.pfx_generated.connect(self._on_pfx_generated)
        dlg.exec()

    def _on_pfx_generated(self, path: str, cn: str) -> None:
        self._pfx_edit.setText(path)
        self.config.set("pkcs11", "pfx_path", path)
        self._pfx_info = None
        if cn:
            self._cert_cn_edit.setText(cn)
            self.config.set("pkcs11", "cert_cn", cn)
        self._on_pfx_path_changed(path)

    def _test_token(self, with_pin: bool = False) -> None:
        lib_path = self._lib_edit.text().strip()
        self._tok_status_lbl.setText(t("status_token_reading"))
        QApplication.processEvents()
        try:
            import pkcs11 as p11
            lib   = p11.lib(lib_path)
            slots = lib.get_slots(token_present=True)
            if not slots:
                raise RuntimeError("No token found.")
            token = slots[0].get_token()
            all_items: list[dict] = []

            if with_pin:
                pin = self._pin_edit.text().strip()
                if not pin:
                    QMessageBox.information(
                        self, t("cfg_pinpad_test_title"),
                        t("cfg_pinpad_test_msg"))
                    self._tok_status_lbl.setText("")
                    return
                with token.open(rw=True, user_pin=pin) as session:
                    from .dialogs import _read_key_info, _read_cert_info
                    for k in session.get_objects(
                            {p11.Attribute.CLASS: p11.ObjectClass.PRIVATE_KEY}):
                        item = _read_key_info(k, p11)
                        item["obj_class"] = "PRIVATE_KEY"
                        all_items.append(item)
                    for c in session.get_objects(
                            {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}):
                        item = _read_cert_info(c, p11)
                        item["obj_class"] = "CERTIFICATE"
                        all_items.append(item)
                    for k in session.get_objects(
                            {p11.Attribute.CLASS: p11.ObjectClass.PUBLIC_KEY}):
                        item = _read_key_info(k, p11)
                        item["obj_class"] = "PUBLIC_KEY"
                        all_items.append(item)
            else:
                with token.open() as session:
                    from .dialogs import _read_key_info, _read_cert_info
                    pub_keys = list(session.get_objects(
                        {p11.Attribute.CLASS: p11.ObjectClass.PUBLIC_KEY}))
                    for k in session.get_objects(
                            {p11.Attribute.CLASS: p11.ObjectClass.PRIVATE_KEY}):
                        item = _read_key_info(k, p11)
                        item["obj_class"] = "PRIVATE_KEY"
                        all_items.append(item)
                    for c in session.get_objects(
                            {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}):
                        item = _read_cert_info(c, p11)
                        item["obj_class"] = "CERTIFICATE"
                        all_items.append(item)
                    for k in pub_keys:
                        item = _read_key_info(k, p11)
                        item["obj_class"] = "PUBLIC_KEY"
                        all_items.append(item)

            n_priv  = sum(1 for i in all_items if i["obj_class"] == "PRIVATE_KEY")
            n_certs = sum(1 for i in all_items if i["obj_class"] == "CERTIFICATE")
            self._tok_status_lbl.setText(
                t("status_token_ok",
                  label=token.label.strip(), keys=n_priv, certs=n_certs))
            from .dialogs import TokenInfoDialog
            dlg = TokenInfoDialog(self, token, all_items)
            dlg.key_selected.connect(
                lambda kid, cn: (
                    self._key_id_edit.setText(kid),
                    self._cert_cn_edit.setText(cn),
                    self.config.set("pkcs11", "key_id", kid),
                    self.config.set("pkcs11", "cert_cn", cn),
                ))
            dlg.exec()

        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self._tok_status_lbl.setText(t("status_token_failed"))
            QMessageBox.critical(self, t("dlg_token_error_title"), str(exc))

    # ── TSA helpers ───────────────────────────────────────────────────────

    def _on_tsa_url_finished(self) -> None:
        url = self._tsa_url_edit.text().strip()
        if not url:
            url = self._tsa_url_edit.placeholderText()
            self._tsa_url_edit.setText(url)
        self.config.set("tsa", "url", url)

    # ── Cache helpers ─────────────────────────────────────────────────────

    def _refresh_cache(self) -> None:
        try:
            from .lotl_trust import XmlCacheTrustStore, AiaCertCache
            from datetime import timezone as _tz
            info = XmlCacheTrustStore().cache_info()
            lines: list[str] = []

            lines.append(t("trust_cache_lotl_header"))
            lines.append(t("trust_cache_lotl_explain"))
            if info["has_lotl_urls"]:
                nu = info["lotl_next_update"]
                if nu is not None:
                    nu_aware = nu if nu.tzinfo else nu.replace(tzinfo=_tz.utc)
                    date_str = nu_aware.strftime("%d.%m.%Y")
                    key = ("trust_cache_lotl_urls_valid"
                           if info["lotl_urls_valid"]
                           else "trust_cache_lotl_urls_expired")
                    lines.append(t(key,
                                   count=info["lotl_url_count"],
                                   size=f"{info['lotl_urls_size_kb']:.1f}",
                                   date=date_str))
                else:
                    lines.append(t("trust_cache_lotl_urls_no_date",
                                   count=info["lotl_url_count"],
                                   size=f"{info['lotl_urls_size_kb']:.1f}"))
            else:
                lines.append(t("trust_cache_no_lotl_urls"))

            lines.append("")
            lines.append(t("trust_cache_tsl_section"))
            lines.append(t("trust_cache_tsl_explain"))
            tsls = info["tsls"]
            if not tsls:
                lines.append(t("trust_cache_no_tsl"))
            else:
                lines.append(t("trust_cache_tsl_header"))
                for tsl in tsls:
                    nu = tsl["next_update"]
                    if nu is not None:
                        nu_aware = (nu if nu.tzinfo
                                    else nu.replace(tzinfo=_tz.utc))
                        date_str = nu_aware.strftime("%d.%m.%Y")
                    else:
                        date_str = "?"
                    key = ("trust_cache_tsl_valid" if tsl["valid"]
                           else "trust_cache_tsl_expired")
                    lines.append(t(key, country=tsl["country"],
                                   date=date_str,
                                   size=f"{tsl['size_kb']:.0f}"))

            aia_certs = AiaCertCache().list_certs()
            lines.append("")
            lines.append(t("trust_cache_aia_section"))
            lines.append(t("trust_cache_aia_explain"))
            if not aia_certs:
                lines.append(t("trust_cache_aia_empty"))
            else:
                for c in aia_certs:
                    fp_abbrev = c["fp_hex"][:8] + " " + c["fp_hex"][8:16] + "…"
                    lines.append(t("trust_cache_aia_entry",
                                   subject=c["subject"],
                                   fp=fp_abbrev,
                                   size=f"{c['size_bytes'] / 1024:.1f}"))

            self._cache_info_lbl.setText("\n".join(lines))
            self._btn_clear_tsl.setEnabled(bool(tsls))
            self._btn_clear_all.setEnabled(info["has_lotl_urls"] or bool(tsls))
            self._btn_clear_aia.setEnabled(bool(aia_certs))
        except Exception as exc:
            self._cache_info_lbl.setText(str(exc))

    def _clear_tsl(self) -> None:
        from .lotl_trust import XmlCacheTrustStore
        XmlCacheTrustStore().clear_cache(keep_urls=True)
        self._refresh_cache()

    def _clear_all(self) -> None:
        from .lotl_trust import XmlCacheTrustStore
        XmlCacheTrustStore().clear_cache(keep_urls=False)
        self._refresh_cache()

    def _clear_aia(self) -> None:
        from .lotl_trust import AiaCertCache
        AiaCertCache().clear()
        self._refresh_cache()

    # ── General helpers ───────────────────────────────────────────────────

    def _on_lang_changed(self, code: str) -> None:
        self.config.set("app", "language", code)
        self.language_changed.emit(code)

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        self.config.save()
        super().closeEvent(event)

    def retranslate(self) -> None:
        """Update text labels after a language switch."""
        self.setWindowTitle(t("settings_title"))
        nav_keys = ("settings_nav_token", "settings_nav_tsa",
                    "settings_nav_validation", "settings_nav_cache",
                    "settings_nav_updates", "settings_nav_general")
        for i, key in enumerate(nav_keys):
            self._nav.item(i).setText(t(key))
        self._close_btn.setText(t("dlg_token_close"))
