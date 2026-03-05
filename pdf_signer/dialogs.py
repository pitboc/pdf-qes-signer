# SPDX-License-Identifier: GPL-3.0-or-later
"""
Qt dialogs for PDF QES Signer.

Provides:
  - TokenInfoDialog       – displays token contents; lets user select a key label
  - Pkcs11ConfigDialog    – configure PKCS#11 library path and key label
  - AppearanceConfigDialog – standalone dialog for signature appearance settings
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QMessageBox,
    QPushButton, QSizePolicy, QSlider, QSpinBox, QSplitter, QTabWidget,
    QVBoxLayout, QWidget, QCheckBox, QComboBox, QAbstractItemView,
    QGridLayout,
)

from .config import AppConfig, PDF_STANDARD_FONTS
from .appearance import SigAppearance
from .pdf_view import DPI_SCALE
from .i18n import t


# ── Token info dialog ─────────────────────────────────────────────────────────

class TokenInfoDialog(QDialog):
    """Display token contents and let the user select or copy a key label."""

    key_selected = pyqtSignal(str)

    def __init__(self, parent, token, key_labels: list[str],
                 cert_labels: list[str]) -> None:
        super().__init__(parent)
        self.token        = token
        self.key_labels   = key_labels
        self.cert_labels  = cert_labels
        self.setWindowTitle(t("dlg_token_info_title"))
        self.resize(540, 420)
        self._build_ui()

    def _build_ui(self) -> None:
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
        btn_row.addWidget(b1)
        btn_row.addWidget(b2)
        btn_row.addWidget(b3)
        btn_row.addStretch()
        btn_row.addWidget(b4)
        lay.addLayout(btn_row)

    def _use_selected(self) -> None:
        items = self.key_list.selectedItems()
        if items:
            self.key_selected.emit(items[0].text())
        self.accept()

    def _copy(self, lw: QListWidget) -> None:
        items = lw.selectedItems()
        if items:
            QApplication.clipboard().setText(items[0].text())


# ── PKCS#11 configuration dialog ──────────────────────────────────────────────

class Pkcs11ConfigDialog(QDialog):
    """Configure the PKCS#11 library path and key label.

    PIN entry is intentionally absent here – the PIN is entered in the main
    window's Token/PIN panel so that it is available before the token test.
    """

    def __init__(self, parent, config: AppConfig) -> None:
        super().__init__(parent)
        self.config = config
        self.setWindowTitle(t("cfg_title"))
        self.setMinimumWidth(520)
        self._build_ui()
        self._load_values()

    def _build_ui(self) -> None:
        lay  = QVBoxLayout(self)

        tabs = QTabWidget()

        # ── Tab 1: PKCS#11 ────────────────────────────────────────────────
        pkcs11_tab = QWidget()
        ptab_lay   = QVBoxLayout(pkcs11_tab)
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        lib_row = QHBoxLayout()
        self.lib_edit = QLineEdit()
        self.lib_edit.setPlaceholderText("/usr/lib/.../opensc-pkcs11.so")
        bb = QPushButton(t("cfg_lib_browse"))
        bb.setFixedWidth(36)
        bb.clicked.connect(self._browse_lib)
        lib_row.addWidget(self.lib_edit)
        lib_row.addWidget(bb)
        form.addRow(t("cfg_lib_label"), lib_row)

        self.key_edit = QLineEdit()
        hint = QLabel(t("cfg_key_hint"))
        hint.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow(t("cfg_key_label"), self.key_edit)
        form.addRow("", hint)

        self.pin_edit = QLineEdit()
        self.pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_edit.setPlaceholderText(t("cfg_pin_placeholder"))
        pin_hint = QLabel(t("cfg_pin_hint"))
        pin_hint.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow(t("cfg_pin_label"), self.pin_edit)
        form.addRow("", pin_hint)
        ptab_lay.addLayout(form)

        test_row = QHBoxLayout()
        test_no_pin = QPushButton(t("cfg_test_btn_no_pin"))
        test_no_pin.clicked.connect(lambda: self._test_token(with_pin=False))
        test_with_pin = QPushButton(t("cfg_test_btn_with_pin"))
        test_with_pin.clicked.connect(lambda: self._test_token(with_pin=True))
        test_row.addWidget(test_no_pin)
        test_row.addWidget(test_with_pin)
        ptab_lay.addLayout(test_row)

        self.status_lbl = QLabel("")
        self.status_lbl.setWordWrap(True)
        ptab_lay.addWidget(self.status_lbl)
        ptab_lay.addStretch()
        tabs.addTab(pkcs11_tab, t("cfg_tab_pkcs11"))

        # ── Tab 2: TSA ────────────────────────────────────────────────────
        tsa_tab = QWidget()
        tsa_form = QFormLayout(tsa_tab)
        tsa_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        self.tsa_url_edit = QLineEdit()
        self.tsa_url_edit.setPlaceholderText("http://tsa.baltstamp.lt")
        tsa_hint = QLabel(t("cfg_tsa_hint"))
        tsa_hint.setStyleSheet("color: gray; font-size: 10px;")
        tsa_hint.setWordWrap(True)
        tsa_form.addRow(t("cfg_tsa_url"), self.tsa_url_edit)
        tsa_form.addRow("", tsa_hint)
        tabs.addTab(tsa_tab, t("cfg_tab_tsa"))

        lay.addWidget(tabs)

        bb2 = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel)
        bb2.button(QDialogButtonBox.StandardButton.Save).setText(t("cfg_save_btn"))
        bb2.button(QDialogButtonBox.StandardButton.Cancel).setText(t("cfg_cancel_btn"))
        bb2.accepted.connect(self._save_and_close)
        bb2.rejected.connect(self.reject)
        lay.addWidget(bb2)

    def _load_values(self) -> None:
        self.lib_edit.setText(self.config.get("pkcs11", "lib_path"))
        self.key_edit.setText(self.config.get("pkcs11", "key_label"))
        self.tsa_url_edit.setText(self.config.get("tsa", "url"))

    def _browse_lib(self) -> None:
        start = self.config.get("paths", "last_lib_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("dlg_browse_lib"), start, t("dlg_lib_filter"))
        if path:
            self.lib_edit.setText(path)
            self.config.set("paths", "last_lib_dir", str(Path(path).parent))

    def _save_and_close(self) -> None:
        self.config.set("pkcs11", "lib_path",  self.lib_edit.text().strip())
        self.config.set("pkcs11", "key_label", self.key_edit.text().strip())
        self.config.set("tsa", "url", self.tsa_url_edit.text().strip())
        self.config.save()
        self.accept()

    def _test_token(self, with_pin: bool = False) -> None:
        lib_path = self.lib_edit.text().strip()
        self.status_lbl.setText(t("status_token_reading"))
        QApplication.processEvents()
        try:
            import pkcs11 as p11
            lib   = p11.lib(lib_path)
            slots = lib.get_slots(token_present=True)
            if not slots:
                raise RuntimeError("No token found.")
            token = slots[0].get_token()

            if with_pin:
                # Use PIN from the dialog's own PIN field; empty = PIN pad.
                # token.open(user_pin=None) does NOT call C_Login at all, so
                # we open the session first and login explicitly.  Passing None
                # to session.login() sends a NULL pin to C_Login, which triggers
                # the hardware PIN pad on tokens with CKF_PROTECTED_AUTHENTICATION_PATH.
                pin = self.pin_edit.text().strip()
                if not pin:
                    # python-pkcs11 wraps C_Login inside token.open() and
                    # exposes no separate login method, so there is no way
                    # to trigger the hardware PIN pad from the test dialog.
                    # Signing via pyhanko works because pyhanko handles this
                    # internally.  Inform the user and abort the test.
                    QMessageBox.information(
                        self, t("cfg_pinpad_test_title"),
                        t("cfg_pinpad_test_msg"))
                    self.status_lbl.setText("")
                    return
                with token.open(rw=True, user_pin=pin) as session:
                    priv_keys = list(session.get_objects(
                        {p11.Attribute.CLASS: p11.ObjectClass.PRIVATE_KEY}))
                    key_labels = []
                    for k in priv_keys:
                        try:
                            key_labels.append(k[p11.Attribute.LABEL])
                        except Exception:
                            key_labels.append("(unknown)")

                    certs = list(session.get_objects(
                        {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}))
                    cert_labels = []
                    for c in certs:
                        try:
                            cert_labels.append(c[p11.Attribute.LABEL])
                        except Exception:
                            cert_labels.append("(no label)")
            else:
                # Open without PIN – public keys and certificates are accessible
                # without authentication on TCOS cards and most PKCS#11 tokens.
                with token.open() as session:
                    pub_keys = list(session.get_objects(
                        {p11.Attribute.CLASS: p11.ObjectClass.PUBLIC_KEY}))
                    pub_labels = []
                    for k in pub_keys:
                        try:
                            pub_labels.append(k[p11.Attribute.LABEL])
                        except Exception:
                            pub_labels.append("(unknown)")

                    certs = list(session.get_objects(
                        {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}))
                    cert_labels = []
                    for c in certs:
                        try:
                            cert_labels.append(c[p11.Attribute.LABEL])
                        except Exception:
                            cert_labels.append("(no label)")

                # Derive private key labels from public key labels.
                # Telesec TCOS cards use the convention "Public X" / "Private X".
                key_labels = []
                for lbl in pub_labels:
                    if lbl.startswith("Public "):
                        key_labels.append("Private " + lbl[len("Public "):])
                    else:
                        key_labels.append(lbl)

            status = t("status_token_ok",
                       label=token.label.strip(),
                       keys=len(key_labels), certs=len(certs))
            self.status_lbl.setText(status)

            # Auto-fill key label if there is exactly one key
            if len(key_labels) == 1 and not self.key_edit.text().strip():
                self.key_edit.setText(key_labels[0])
                self.status_lbl.setText(
                    status + "\n"
                    + t("dlg_token_auto_label", label=key_labels[0]))

            dlg = TokenInfoDialog(self, token, key_labels, cert_labels)
            dlg.key_selected.connect(self.key_edit.setText)
            dlg.exec()

        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self.status_lbl.setText(t("status_token_failed"))
            QMessageBox.critical(self, t("dlg_token_error_title"), str(exc))


# ── Appearance configuration dialog ──────────────────────────────────────────

class AppearanceConfigDialog(QDialog):
    """Standalone dialog for configuring the signature field appearance.

    Note: as of the current release the appearance panel is embedded directly
    in the main window; this dialog is kept for potential future use.
    """

    DATE_FORMATS: list[tuple[str, str]] = [
        ("%d.%m.%Y %H:%M",    "31.12.2025 14:30"),
        ("%d.%m.%Y",          "31.12.2025"),
        ("%Y-%m-%d %H:%M:%S", "2025-12-31 14:30:00"),
        ("%Y-%m-%d",          "2025-12-31"),
        ("%d/%m/%Y %H:%M",    "31/12/2025 14:30"),
        ("%B %d, %Y",         "December 31, 2025"),
    ]
    CUSTOM_FMT = "__custom__"

    def __init__(self, parent, config: AppConfig,
                 appearance: SigAppearance,
                 selected_fdef=None) -> None:
        super().__init__(parent)
        self.config        = config
        self.appearance    = appearance
        self.selected_fdef = selected_fdef  # used for preview size
        self.setWindowTitle(t("appdlg_title"))
        self.setMinimumSize(600, 500)
        self.resize(660, 560)
        self._build_ui()
        self._load_values()
        self._update_preview()

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setSpacing(4)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, stretch=3)

        self._build_tab_image()
        self._build_tab_text()

        # Full-size preview (always visible below the tabs)
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

        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Save).setText(t("appdlg_save"))
        bb.button(QDialogButtonBox.StandardButton.Cancel).setText(
            t("appdlg_cancel"))
        bb.accepted.connect(self._save_and_close)
        bb.rejected.connect(self.reject)
        root.addWidget(bb)

    def _build_tab_image(self) -> None:
        """Image selection + layout tab."""
        tab = QWidget()
        vl  = QVBoxLayout(tab)
        vl.setSpacing(8)

        # Image selection group
        img_grp = QGroupBox(t("appdlg_tab_image"))
        ig = QVBoxLayout(img_grp)

        img_row = QHBoxLayout()
        self.img_path_edit = QLineEdit()
        self.img_path_edit.setReadOnly(True)
        self.img_path_edit.setPlaceholderText(t("ap_img_none"))
        bb_btn = QPushButton(t("appdlg_img_browse"))
        bb_btn.setFixedWidth(36)
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

        # Layout + border group
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

        # Image / text ratio slider
        ratio_row = QHBoxLayout()
        self._ratio_lbl_img = QLabel("Image 30%")
        self._ratio_lbl_img.setFixedWidth(70)
        self.ratio_slider = QSlider(Qt.Orientation.Horizontal)
        self.ratio_slider.setRange(10, 70)
        self.ratio_slider.setValue(40)
        self.ratio_slider.setTickInterval(10)
        self.ratio_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.ratio_slider.valueChanged.connect(self._on_ratio_changed)
        self._ratio_lbl_txt = QLabel("Text 70%")
        self._ratio_lbl_txt.setFixedWidth(70)
        ratio_row.addWidget(self._ratio_lbl_img)
        ratio_row.addWidget(self.ratio_slider)
        ratio_row.addWidget(self._ratio_lbl_txt)
        lg.addRow("Image/Text:", ratio_row)
        vl.addWidget(lay_grp)

        vl.addStretch()
        self.tabs.addTab(tab,
                         t("appdlg_tab_image") + " / " + t("appdlg_tab_layout"))

    def _build_tab_text(self) -> None:
        """Text fields tab with checkbox + input on each row."""
        tab = QWidget()
        gl  = QGridLayout(tab)
        gl.setColumnStretch(1, 1)
        gl.setSpacing(6)
        row = 0

        # Name
        self.chk_name = QCheckBox(t("app_name_label"))
        self.name_mode_combo = QComboBox()
        self.name_mode_combo.addItem(t("ap_name_from_cert"), "cert")
        self.name_mode_combo.addItem(t("ap_name_custom"),    "custom")
        self.name_custom_edit = QLineEdit()
        self.name_custom_edit.setPlaceholderText("Jane Doe")
        name_row = QHBoxLayout()
        name_row.addWidget(self.name_mode_combo)
        name_row.addWidget(self.name_custom_edit)
        gl.addWidget(self.chk_name, row, 0)
        gl.addLayout(name_row,      row, 1)
        row += 1

        # Location
        self.chk_location = QCheckBox(t("app_location_label"))
        self.location_edit = QLineEdit()
        gl.addWidget(self.chk_location, row, 0)
        gl.addWidget(self.location_edit, row, 1)
        row += 1

        # Reason
        self.chk_reason = QCheckBox(t("app_reason_label"))
        self.reason_edit = QLineEdit()
        gl.addWidget(self.chk_reason, row, 0)
        gl.addWidget(self.reason_edit, row, 1)
        row += 1

        # Date
        self.chk_date = QCheckBox(t("app_date_label"))
        date_col = QVBoxLayout()
        self.date_fmt_combo = QComboBox()
        for fmt, example in self.DATE_FORMATS:
            self.date_fmt_combo.addItem(f"{fmt}  →  {example}", fmt)
        self.date_fmt_combo.addItem("Custom…", self.CUSTOM_FMT)
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

        # Font size
        lbl_font = QLabel(t("appdlg_font_size"))
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(5, 24)
        self.font_size_spin.valueChanged.connect(self._update_preview)
        gl.addWidget(lbl_font,            row, 0)
        gl.addWidget(self.font_size_spin, row, 1,
                     alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        gl.setRowStretch(row, 1)

        # Connect signals
        self.chk_name.toggled.connect(self._on_checks_changed)
        self.chk_location.toggled.connect(self._on_checks_changed)
        self.chk_reason.toggled.connect(self._on_checks_changed)
        self.chk_date.toggled.connect(self._on_checks_changed)
        for w in (self.location_edit, self.reason_edit, self.name_custom_edit):
            w.textChanged.connect(self._update_preview)
        self.name_mode_combo.currentIndexChanged.connect(self._on_checks_changed)

        self.tabs.addTab(tab, t("appdlg_tab_text"))

    # ── Slots ─────────────────────────────────────────────────────────────

    def _on_checks_changed(self) -> None:
        """Enable/disable input fields depending on checkbox states."""
        name_on = self.chk_name.isChecked()
        self.name_mode_combo.setEnabled(name_on)
        self.name_custom_edit.setEnabled(
            name_on and self.name_mode_combo.currentData() == "custom")
        self.location_edit.setEnabled(self.chk_location.isChecked())
        self.reason_edit.setEnabled(self.chk_reason.isChecked())
        self.date_fmt_combo.setEnabled(self.chk_date.isChecked())
        self.date_fmt_custom.setEnabled(self.chk_date.isChecked())
        self._update_preview()

    def _on_layout_changed_dlg(self) -> None:
        self._update_ratio_labels()
        self._update_preview()

    def _on_date_fmt_changed(self) -> None:
        is_custom = self.date_fmt_combo.currentData() == self.CUSTOM_FMT
        self.date_fmt_custom.setVisible(is_custom)
        self._update_preview()

    def _on_ratio_changed(self, value: int) -> None:
        self._update_ratio_labels(value)
        self._update_preview()

    def _update_ratio_labels(self, value: int = None) -> None:
        if value is None:
            value = self.ratio_slider.value()
        layout = self.layout_combo.currentData() or "img_left"
        if layout == "img_left":
            self._ratio_lbl_img.setText(f"◀ Image {value}%")
            self._ratio_lbl_txt.setText(f"Text {100 - value}% ▶")
        else:
            self._ratio_lbl_img.setText(f"◀ Text {100 - value}%")
            self._ratio_lbl_txt.setText(f"Image {value}% ▶")

    def _browse_image(self) -> None:
        start = self.config.get("paths", "last_img_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("appdlg_browse_img"), start, t("appdlg_img_filter"))
        if path:
            self.img_path_edit.setText(path)
            self.config.set("paths", "last_img_dir", str(Path(path).parent))
            self._update_preview()

    def _clear_image(self) -> None:
        self.img_path_edit.clear()
        self._update_preview()

    def _update_preview(self) -> None:
        """Render preview using the currently selected signature field size."""
        self._apply_to_config(save=False)
        fdef = self.selected_fdef
        if fdef is None:
            self.full_preview.clear()
            self.full_preview.setText(t("ap_preview_hint"))
            self.full_preview.setStyleSheet(
                "background: #f0f0f0; border: 1px solid #ccc; color: gray;")
            return

        fw      = abs(fdef.x2 - fdef.x1)
        fh      = abs(fdef.y2 - fdef.y1)
        avail_w = max(10, self.full_preview.width()  - 4)
        avail_h = max(10, self.full_preview.height() - 4)
        scale   = min(avail_w / max(fw, 1), avail_h / max(fh, 1))
        pw      = max(10, int(fw * scale))
        ph      = max(10, int(fh * scale))

        px = self.appearance.render_preview(
            pw, ph, pixels_per_point=DPI_SCALE * scale)

        from PyQt6.QtGui import QPainter as _P, QColor as _C
        canvas = QPixmap(avail_w, avail_h)
        canvas.fill(_C("#f0f0f0"))
        p = _P(canvas)
        p.drawPixmap((avail_w - pw) // 2, (avail_h - ph) // 2, px)
        p.end()
        self.full_preview.setPixmap(canvas)
        self.full_preview.setStyleSheet(
            "background: #f0f0f0; border: 1px solid #ccc;")

    def resizeEvent(self, ev) -> None:
        super().resizeEvent(ev)
        self._update_preview()

    # ── Load / save ───────────────────────────────────────────────────────

    def _date_fmt_value(self) -> str:
        if self.date_fmt_combo.currentData() == self.CUSTOM_FMT:
            return self.date_fmt_custom.text().strip() or "%d.%m.%Y %H:%M"
        return self.date_fmt_combo.currentData() or "%d.%m.%Y %H:%M"

    def _load_values(self) -> None:
        self.img_path_edit.setText(self.config.get("appearance", "image_path"))

        idx = self.layout_combo.findData(self.config.get("appearance", "layout"))
        self.layout_combo.setCurrentIndex(max(0, idx))
        self.chk_border.setChecked(self.config.getbool("appearance", "show_border"))

        try:
            ratio = int(self.config.get("appearance", "img_ratio") or "40")
        except ValueError:
            ratio = 40
        self.ratio_slider.setValue(max(10, min(70, ratio)))
        self._update_ratio_labels(max(10, min(70, ratio)))

        self.chk_name.setChecked(self.config.getbool("appearance", "show_name"))
        nm_idx = self.name_mode_combo.findData(
            self.config.get("appearance", "name_mode"))
        self.name_mode_combo.setCurrentIndex(max(0, nm_idx))
        self.name_custom_edit.setText(self.config.get("appearance", "name_custom"))

        self.chk_location.setChecked(
            self.config.getbool("appearance", "show_location"))
        self.location_edit.setText(self.config.get("appearance", "location"))

        self.chk_reason.setChecked(
            self.config.getbool("appearance", "show_reason"))
        self.reason_edit.setText(self.config.get("appearance", "reason"))

        self.chk_date.setChecked(self.config.getbool("appearance", "show_date"))
        saved_fmt = self.config.get("appearance", "date_format") or "%d.%m.%Y %H:%M"
        fmt_idx   = self.date_fmt_combo.findData(saved_fmt)
        if fmt_idx >= 0:
            self.date_fmt_combo.setCurrentIndex(fmt_idx)
        else:
            custom_idx = self.date_fmt_combo.findData(self.CUSTOM_FMT)
            self.date_fmt_combo.setCurrentIndex(custom_idx)
            self.date_fmt_custom.setText(saved_fmt)
            self.date_fmt_custom.setVisible(True)

        try:
            fs = int(self.config.get("appearance", "font_size") or "8")
        except (ValueError, TypeError):
            fs = 8
        self.font_size_spin.setValue(max(5, min(24, fs)))

        self._on_checks_changed()

    def _apply_to_config(self, save: bool = True) -> None:
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
        self.config.set("appearance", "date_format", self._date_fmt_value())
        self.config.set("appearance", "font_size",
                        str(self.font_size_spin.value()))
        if save:
            self.config.save()

    def _save_and_close(self) -> None:
        self._apply_to_config(save=True)
        self.accept()
