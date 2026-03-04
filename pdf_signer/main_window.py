# SPDX-License-Identifier: GPL-3.0-or-later
"""
Main application window for PDF QES Signer.

Provides:
  - PDFSignerApp  – the QMainWindow subclass that ties all components together
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import fitz  # PyMuPDF

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QFont, QKeySequence
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QMainWindow,
    QMessageBox, QPushButton, QScrollArea, QSlider, QSpinBox,
    QSplitter, QVBoxLayout, QWidget, QCheckBox, QGridLayout, QTabWidget,
)

from .config import AppConfig, PDF_STANDARD_FONTS
from .appearance import SigAppearance
from .signer import (
    SaveFieldsWorker, SignWorker,
    _pyhanko_available, _pkcs11_available,
)
from .pdf_view import PDFViewWidget, SignatureFieldDef
from .dialogs import Pkcs11ConfigDialog
from .i18n import t, i18n, AVAILABLE_LANGUAGES


class PDFSignerApp(QMainWindow):
    """Main window of PDF QES Signer.

    Responsibilities:
      - Menu bar, toolbar, and status bar
      - Central PDF canvas (left) with scroll area
      - Right panel: field list, PIN entry, inline appearance settings
      - Dispatching PDF open, save-with-fields, and sign operations to workers
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

    def __init__(self, config: AppConfig,
                 initial_pdf: Optional[str] = None) -> None:
        super().__init__()
        self.config       = config
        self.appearance   = SigAppearance(config)
        self.pdf_doc:     Optional[fitz.Document] = None
        self.pdf_path     = ""
        self.current_page = 0
        self.sig_fields:  list[SignatureFieldDef] = []
        self._worker      = None
        self._sign_worker = None

        self._build_ui()
        self._apply_language()
        self.statusBar().showMessage(t("status_ready"))
        self._check_dependencies()

        if initial_pdf:
            self._open_pdf(initial_pdf)

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setMinimumSize(980, 660)
        self.resize(1340, 840)

        # Menu bar
        self._menu_file = self.menuBar().addMenu("")
        self._act_open  = QAction(self)
        self._act_open.setShortcut(QKeySequence.StandardKey.Open)
        self._act_open.triggered.connect(self.open_pdf)
        self._menu_file.addAction(self._act_open)
        self._act_save_fields = QAction(self)
        self._act_save_fields.triggered.connect(self.save_with_fields)
        self._menu_file.addAction(self._act_save_fields)
        self._menu_file.addSeparator()
        self._act_quit = QAction(self)
        self._act_quit.setShortcut(QKeySequence.StandardKey.Quit)
        self._act_quit.triggered.connect(self.close)
        self._menu_file.addAction(self._act_quit)

        self._menu_sign = self.menuBar().addMenu("")
        self._act_sign  = QAction(self)
        self._act_sign.triggered.connect(self.sign_document)
        self._menu_sign.addAction(self._act_sign)

        self._menu_settings  = self.menuBar().addMenu("")
        self._act_pkcs11     = QAction(self)
        self._act_pkcs11.triggered.connect(self.open_pkcs11_config)
        self._menu_settings.addAction(self._act_pkcs11)
        self._act_appearance = QAction(self)
        self._act_appearance.triggered.connect(self.open_appearance_config)
        self._menu_settings.addAction(self._act_appearance)

        # Language sub-menu
        self._menu_lang = self.menuBar().addMenu("")
        self._lang_actions: dict[str, QAction] = {}
        for code, label in AVAILABLE_LANGUAGES.items():
            act = QAction(label, self)
            act.setCheckable(True)
            act.setChecked(code == i18n.lang)
            act.triggered.connect(lambda _, c=code: self._set_language(c))
            self._lang_actions[code] = act
            self._menu_lang.addAction(act)
        self._menu_settings.addMenu(self._menu_lang)

        self._menu_help = self.menuBar().addMenu("")
        self._act_about = QAction(self)
        self._act_about.triggered.connect(self._show_about)
        self._menu_help.addAction(self._act_about)

        # Toolbar
        tb = self.addToolBar("main")
        tb.setMovable(False)
        self._tb_open = QAction(self)
        self._tb_open.triggered.connect(self.open_pdf)
        tb.addAction(self._tb_open)
        tb.addSeparator()
        self._tb_prev = QAction(self)
        self._tb_prev.triggered.connect(self.prev_page)
        tb.addAction(self._tb_prev)
        self._page_label = QLabel("  –/–  ")
        self._page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._page_label.setMinimumWidth(70)
        tb.addWidget(self._page_label)
        self._tb_next = QAction(self)
        self._tb_next.triggered.connect(self.next_page)
        tb.addAction(self._tb_next)
        tb.addSeparator()
        self._tb_sign = QAction(self)
        self._tb_sign.triggered.connect(self.sign_document)
        tb.addAction(self._tb_sign)
        self._tb_save_fields = QAction(self)
        self._tb_save_fields.triggered.connect(self.save_with_fields)
        tb.addAction(self._tb_save_fields)

        # Central splitter: PDF canvas (left) + right panel
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

        # Right panel
        right = QWidget()
        right.setMinimumWidth(240)
        right.setMaximumWidth(310)
        rl = QVBoxLayout(right)
        rl.setContentsMargins(4, 4, 4, 4)
        rl.setSpacing(6)

        # Signature field list
        self._fields_group = QGroupBox()
        fl = QVBoxLayout(self._fields_group)
        self._field_list = QListWidget()
        self._field_list.setFont(QFont("Courier", 9))
        self._field_list.currentRowChanged.connect(self._on_field_selection_changed)
        fl.addWidget(self._field_list)
        btn_row = QHBoxLayout()
        self._btn_delete = QPushButton()
        self._btn_delete.clicked.connect(self.delete_selected_field)
        self._btn_save = QPushButton()
        self._btn_save.clicked.connect(self.save_with_fields)
        btn_row.addWidget(self._btn_delete)
        btn_row.addWidget(self._btn_save)
        fl.addLayout(btn_row)
        rl.addWidget(self._fields_group)

        # Token / PIN panel
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

        # Inline appearance panel
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

        self._load_appearance_panel()

    # ── Language support ──────────────────────────────────────────────────

    def _set_language(self, code: str) -> None:
        i18n.lang = code
        self.config.set("app", "language", code)
        self.config.save()
        for c, act in self._lang_actions.items():
            act.setChecked(c == code)
        self._apply_language()

    def _apply_language(self) -> None:
        """Retranslate all UI strings to the current language."""
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
        # Appearance panel – retranslate all inline widgets
        self._ap_chk_name.setText(t("app_name_label"))
        self._ap_chk_loc.setText(t("app_location_label"))
        self._ap_chk_reason.setText(t("app_reason_label"))
        self._ap_chk_date.setText(t("app_date_label"))
        self._ap_lbl_font_size.setText(t("ap_font_pt"))
        self._ap_lbl_font_family.setText(t("ap_font_family"))
        self._ap_name_mode.setItemText(0, t("ap_name_from_cert"))
        self._ap_name_mode.setItemText(1, t("ap_name_custom"))
        self._ap_border.setText(t("ap_border"))
        self._ap_lbl_layout.setText(t("app_layout_label"))
        self._ap_layout.setItemText(0, t("ap_layout_left"))
        self._ap_layout.setItemText(1, t("ap_layout_right"))
        custom_idx = self._ap_date_combo.findData(self.CUSTOM_FMT)
        if custom_idx >= 0:
            self._ap_date_combo.setItemText(custom_idx, t("ap_date_custom"))
        self._ap_clr_btn.setText(t("appdlg_img_clear"))
        self._ap_img_hint.setText(t("ap_img_hint"))
        self._app_tabs.setTabText(0, t("ap_tab_text"))
        self._app_tabs.setTabText(1, t("ap_tab_image_layout"))

    # ── Inline appearance panel ───────────────────────────────────────────

    def _build_appearance_tabs(self) -> None:
        """Build the Text and Image/Layout tabs in the right panel."""

        # Tab 1: Text
        txt_tab = QWidget()
        gl = QGridLayout(txt_tab)
        gl.setColumnStretch(1, 1)
        gl.setSpacing(4)
        gl.setContentsMargins(4, 4, 4, 4)
        row = 0

        # Name
        self._ap_chk_name = QCheckBox(t("app_name_label"))
        self._ap_name_mode = QComboBox()
        self._ap_name_mode.addItem(t("ap_name_from_cert"), "cert")
        self._ap_name_mode.addItem(t("ap_name_custom"),    "custom")
        self._ap_name_custom = QLineEdit()
        self._ap_name_custom.setPlaceholderText("Jane Doe")
        name_row = QHBoxLayout()
        name_row.setSpacing(3)
        name_row.addWidget(self._ap_name_mode)
        name_row.addWidget(self._ap_name_custom)
        gl.addWidget(self._ap_chk_name, row, 0)
        gl.addLayout(name_row,          row, 1)
        row += 1

        # Location
        self._ap_chk_loc = QCheckBox(t("app_location_label"))
        self._ap_loc = QLineEdit()
        gl.addWidget(self._ap_chk_loc, row, 0)
        gl.addWidget(self._ap_loc,     row, 1)
        row += 1

        # Reason
        self._ap_chk_reason = QCheckBox(t("app_reason_label"))
        self._ap_reason = QLineEdit()
        gl.addWidget(self._ap_chk_reason, row, 0)
        gl.addWidget(self._ap_reason,     row, 1)
        row += 1

        # Date
        self._ap_chk_date = QCheckBox(t("app_date_label"))
        date_vl = QVBoxLayout()
        date_vl.setSpacing(2)
        self._ap_date_combo = QComboBox()
        for fmt, ex in self.DATE_FORMATS:
            self._ap_date_combo.addItem(f"{fmt}  →  {ex}", fmt)
        self._ap_date_combo.addItem(t("ap_date_custom"), self.CUSTOM_FMT)
        self._ap_date_custom = QLineEdit()
        self._ap_date_custom.setPlaceholderText("%d.%m.%Y %H:%M")
        self._ap_date_custom.setVisible(False)
        date_vl.addWidget(self._ap_date_combo)
        date_vl.addWidget(self._ap_date_custom)
        gl.addWidget(self._ap_chk_date, row, 0)
        gl.addLayout(date_vl,           row, 1)
        row += 1

        # Font size
        self._ap_font_spin = QSpinBox()
        self._ap_font_spin.setRange(5, 24)
        self._ap_lbl_font_size = QLabel(t("ap_font_pt"))
        gl.addWidget(self._ap_lbl_font_size, row, 0)
        gl.addWidget(self._ap_font_spin,     row, 1,
                     alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        # Font family
        self._ap_font_combo = QComboBox()
        for disp, pdf_name, _, _ in PDF_STANDARD_FONTS:
            self._ap_font_combo.addItem(disp, pdf_name)
        self._ap_lbl_font_family = QLabel(t("ap_font_family"))
        gl.addWidget(self._ap_lbl_font_family, row, 0)
        gl.addWidget(self._ap_font_combo,      row, 1)
        row += 1

        gl.setRowStretch(row, 1)
        self._app_tabs.addTab(txt_tab, t("ap_tab_text"))

        # Tab 2: Image / Layout
        img_tab = QWidget()
        vl = QVBoxLayout(img_tab)
        vl.setContentsMargins(4, 4, 4, 4)
        vl.setSpacing(6)

        # Image path
        img_row = QHBoxLayout()
        img_row.setSpacing(3)
        self._ap_img_path = QLineEdit()
        self._ap_img_path.setReadOnly(True)
        self._ap_img_path.setPlaceholderText(t("ap_img_none"))
        bb_btn = QPushButton("…")
        bb_btn.setFixedWidth(28)
        bb_btn.clicked.connect(self._ap_browse_image)
        self._ap_clr_btn = QPushButton(t("appdlg_img_clear"))
        self._ap_clr_btn.clicked.connect(self._ap_clear_image)
        img_row.addWidget(self._ap_img_path)
        img_row.addWidget(bb_btn)
        img_row.addWidget(self._ap_clr_btn)
        vl.addLayout(img_row)

        self._ap_img_hint = QLabel(t("ap_img_hint"))
        self._ap_img_hint.setStyleSheet("color:gray; font-size:10px;")
        vl.addWidget(self._ap_img_hint)

        # Layout combo
        lay_row = QHBoxLayout()
        self._ap_lbl_layout = QLabel(t("app_layout_label"))
        lay_row.addWidget(self._ap_lbl_layout)
        self._ap_layout = QComboBox()
        self._ap_layout.addItem(t("ap_layout_left"),  "img_left")
        self._ap_layout.addItem(t("ap_layout_right"), "img_right")
        lay_row.addWidget(self._ap_layout)
        vl.addLayout(lay_row)

        # Border checkbox
        self._ap_border = QCheckBox(t("ap_border"))
        vl.addWidget(self._ap_border)

        # Image/text ratio slider
        ratio_row = QHBoxLayout()
        self._ap_ratio_lbl_l = QLabel("◀ Image 40%")
        self._ap_ratio_lbl_l.setFixedWidth(84)
        self._ap_ratio = QSlider(Qt.Orientation.Horizontal)
        self._ap_ratio.setRange(10, 70)
        self._ap_ratio.setValue(40)
        self._ap_ratio.setTickInterval(10)
        self._ap_ratio.setTickPosition(QSlider.TickPosition.TicksBelow)
        self._ap_ratio_lbl_r = QLabel("Text 60% ▶")
        self._ap_ratio_lbl_r.setFixedWidth(84)
        ratio_row.addWidget(self._ap_ratio_lbl_l)
        ratio_row.addWidget(self._ap_ratio)
        ratio_row.addWidget(self._ap_ratio_lbl_r)
        vl.addLayout(ratio_row)
        vl.addStretch()

        self._app_tabs.addTab(img_tab, t("ap_tab_image_layout"))

        # Connect signals
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

    # ── Slots for the inline appearance panel ─────────────────────────────

    def _ap_on_checks(self) -> None:
        """Enable/disable fields based on checkbox states."""
        name_on = self._ap_chk_name.isChecked()
        self._ap_name_mode.setEnabled(name_on)
        self._ap_name_custom.setEnabled(
            name_on and self._ap_name_mode.currentData() == "custom")
        self._ap_loc.setEnabled(self._ap_chk_loc.isChecked())
        self._ap_reason.setEnabled(self._ap_chk_reason.isChecked())
        self._ap_date_combo.setEnabled(self._ap_chk_date.isChecked())
        self._ap_date_custom.setEnabled(self._ap_chk_date.isChecked())
        self._ap_save_and_refresh()

    def _ap_on_date_fmt(self) -> None:
        is_custom = self._ap_date_combo.currentData() == self.CUSTOM_FMT
        self._ap_date_custom.setVisible(is_custom)
        self._ap_save_and_refresh()

    def _ap_on_layout(self) -> None:
        """Invert slider direction when image is on the right."""
        val = self._ap_layout.currentData() or "img_left"
        self._ap_ratio.setInvertedAppearance(val == "img_right")
        self._ap_update_ratio_labels()
        self._ap_save_and_refresh()

    def _ap_on_ratio(self, _v: int) -> None:
        self._ap_update_ratio_labels()
        self._ap_save_and_refresh()

    def _ap_update_ratio_labels(self) -> None:
        val = self._ap_layout.currentData() or "img_left"
        v   = self._ap_ratio.value()
        if val == "img_left":
            self._ap_ratio_lbl_l.setText(f"◀ Image {v}%")
            self._ap_ratio_lbl_r.setText(f"Text {100 - v}% ▶")
        else:
            # Slider is inverted: left = high value (lots of text)
            self._ap_ratio_lbl_l.setText(f"Text {100 - v}% ▶")
            self._ap_ratio_lbl_r.setText(f"◀ Image {v}%")

    def _ap_browse_image(self) -> None:
        start = self.config.get("paths", "last_img_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("ap_browse_img"), start, t("ap_img_filter"))
        if path:
            self._ap_img_path.setText(path)
            self.config.set("paths", "last_img_dir", str(Path(path).parent))
            self._ap_save_and_refresh()

    def _ap_clear_image(self) -> None:
        self._ap_img_path.clear()
        self._ap_save_and_refresh()

    def _ap_date_fmt_value(self) -> str:
        if self._ap_date_combo.currentData() == self.CUSTOM_FMT:
            return self._ap_date_custom.text().strip() or "%d.%m.%Y %H:%M"
        return self._ap_date_combo.currentData() or "%d.%m.%Y %H:%M"

    def _ap_save_and_refresh(self) -> None:
        """Write all appearance values to config and repaint the canvas."""
        cfg = self.config
        cfg.set("appearance", "image_path",
                self._ap_img_path.text().strip())
        cfg.set("appearance", "layout",
                self._ap_layout.currentData() or "img_left")
        cfg.setbool("appearance", "show_border",  self._ap_border.isChecked())
        cfg.set("appearance", "img_ratio",    str(self._ap_ratio.value()))
        cfg.setbool("appearance", "show_name",    self._ap_chk_name.isChecked())
        cfg.set("appearance", "name_mode",
                self._ap_name_mode.currentData() or "cert")
        cfg.set("appearance", "name_custom",
                self._ap_name_custom.text().strip())
        cfg.setbool("appearance", "show_location", self._ap_chk_loc.isChecked())
        cfg.set("appearance", "location",     self._ap_loc.text().strip())
        cfg.setbool("appearance", "show_reason",  self._ap_chk_reason.isChecked())
        cfg.set("appearance", "reason",       self._ap_reason.text().strip())
        cfg.setbool("appearance", "show_date",    self._ap_chk_date.isChecked())
        cfg.set("appearance", "date_format",  self._ap_date_fmt_value())
        cfg.set("appearance", "font_size",    str(self._ap_font_spin.value()))
        cfg.set("appearance", "font_family",
                self._ap_font_combo.currentData() or "Helvetica")
        cfg.save()
        self._pdf_view.refresh()

    def _load_appearance_panel(self) -> None:
        """Populate the inline appearance widgets from config (no signals fired)."""
        cfg = self.config
        widgets = [
            self._ap_chk_name, self._ap_name_mode, self._ap_name_custom,
            self._ap_chk_loc, self._ap_loc, self._ap_chk_reason, self._ap_reason,
            self._ap_chk_date, self._ap_date_combo, self._ap_date_custom,
            self._ap_font_spin, self._ap_font_combo, self._ap_img_path,
            self._ap_layout, self._ap_border, self._ap_ratio,
        ]
        for w in widgets:
            w.blockSignals(True)

        # Text tab
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
        ff_idx = self._ap_font_combo.findData(
            cfg.get("appearance", "font_family") or "Helvetica")
        self._ap_font_combo.setCurrentIndex(max(0, ff_idx))

        # Image/Layout tab
        self._ap_img_path.setText(cfg.get("appearance", "image_path"))
        lay_idx = self._ap_layout.findData(cfg.get("appearance", "layout"))
        self._ap_layout.setCurrentIndex(max(0, lay_idx))
        self._ap_border.setChecked(cfg.getbool("appearance", "show_border"))

        try:
            ratio = int(cfg.get("appearance", "img_ratio") or "40")
        except (ValueError, TypeError):
            ratio = 40
        self._ap_ratio.setValue(max(10, min(70, ratio)))
        self._ap_ratio.setInvertedAppearance(
            (self._ap_layout.currentData() or "img_left") == "img_right")

        for w in widgets:
            w.blockSignals(False)

        self._ap_on_checks()
        self._ap_on_layout()

    # ── Utility methods ───────────────────────────────────────────────────

    def _set_status(self, msg: str) -> None:
        self.statusBar().showMessage(msg)

    def _update_field_list(self) -> None:
        prev_row = self._field_list.currentRow()
        self._field_list.clear()
        # Row 0: invisible signature option
        self._field_list.addItem(t("dlg_invisible_field"))
        for fdef in self.sig_fields:
            self._field_list.addItem(
                f"p.{fdef.page + 1}  {fdef.name}  [{fdef.x1:.0f},{fdef.y1:.0f}]")
        n = self._field_list.count()
        if n > 0:
            row = prev_row if 0 <= prev_row < n else (n - 1 if n > 1 else 0)
            self._field_list.setCurrentRow(row)

    def _check_dependencies(self) -> None:
        missing = []
        if not _pyhanko_available:
            missing.append("pyhanko  (pip install pyhanko)")
        if not _pkcs11_available:
            missing.append("python-pkcs11  (pip install python-pkcs11)")
        if missing:
            QMessageBox.warning(
                self, t("dlg_missing_deps"),
                t("dlg_missing_deps_msg",
                  packages="\n".join(f"  • {m}" for m in missing)))

    def _render_current_page(self) -> None:
        if not self.pdf_doc:
            return
        page = self.pdf_doc[self.current_page]
        self._pdf_view.set_page(page, self.sig_fields, self.current_page)
        self._page_label.setText(
            f"  {self.current_page + 1} / {len(self.pdf_doc)}  ")

    # ── Field list selection ──────────────────────────────────────────────

    def _on_field_selection_changed(self, row: int) -> None:
        """Show appearance preview only in the currently selected field."""
        if 1 <= row <= len(self.sig_fields):
            self._pdf_view.set_selected_field(self.sig_fields[row - 1])
        else:
            self._pdf_view.set_selected_field(None)

    # ── Signals from PDFViewWidget ────────────────────────────────────────

    def _on_field_added(self, fdef: SignatureFieldDef) -> None:
        self._update_field_list()
        self._field_list.setCurrentRow(self._field_list.count() - 1)
        # currentRowChanged fires above and calls _on_field_selection_changed
        self._set_status(
            t("status_field_added", name=fdef.name, page=fdef.page + 1))

    def _on_field_deleted(self, fdef: SignatureFieldDef) -> None:
        self._update_field_list()
        self._set_status(t("status_field_deleted", name=fdef.name))

    # ── PDF navigation ────────────────────────────────────────────────────

    def open_pdf(self) -> None:
        start = self.config.get("paths", "last_open_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("dlg_open_pdf_title"), start, t("dlg_pdf_filter"))
        if path:
            self._open_pdf(path)

    def _open_pdf(self, path: str) -> None:
        try:
            doc = fitz.open(path)
            self.pdf_doc      = doc
            self.pdf_path     = path
            self.current_page = 0
            self.sig_fields.clear()
            self._update_field_list()
            self._render_current_page()
            self.setWindowTitle(f"PDF QES Signer – {os.path.basename(path)}")
            self._set_status(t("status_opened", path=path, pages=len(doc)))
            self.config.set("paths", "last_open_dir", str(Path(path).parent))
            self.config.save()
        except Exception as exc:
            QMessageBox.critical(
                self, t("dlg_open_error_title"),
                t("dlg_open_error_msg", error=str(exc)))

    def prev_page(self) -> None:
        if self.pdf_doc and self.current_page > 0:
            self.current_page -= 1
            self._render_current_page()

    def next_page(self) -> None:
        if self.pdf_doc and self.current_page < len(self.pdf_doc) - 1:
            self.current_page += 1
            self._render_current_page()

    # ── Field management ──────────────────────────────────────────────────

    def delete_selected_field(self) -> None:
        row = self._field_list.currentRow()
        # Row 0 is the "invisible signature" placeholder, not a real field
        if row <= 0 or row > len(self.sig_fields):
            QMessageBox.information(
                self, t("dlg_no_field_sel"), t("dlg_no_field_sel_msg"))
            return
        fdef = self.sig_fields[row - 1]
        if QMessageBox.question(
            self, t("dlg_delete_title"),
            t("dlg_delete_sel_msg", name=fdef.name),
        ) == QMessageBox.StandardButton.Yes:
            del self.sig_fields[row - 1]
            self._update_field_list()
            self._render_current_page()

    def save_with_fields(self) -> None:
        if not self.pdf_doc:
            QMessageBox.warning(self, t("dlg_no_doc"), t("dlg_no_doc_msg"))
            return
        if not self.sig_fields:
            QMessageBox.warning(self, t("dlg_no_fields"), t("dlg_no_fields_msg"))
            return
        if not _pyhanko_available:
            QMessageBox.critical(
                self, t("dlg_save_error_title"), t("dlg_pyhanko_missing"))
            return

        stem    = Path(self.pdf_path).stem
        start   = self.config.get("paths", "last_save_dir")
        default = str(Path(start) / (stem + t("dlg_save_fields_suffix") + ".pdf"))
        out, _  = QFileDialog.getSaveFileName(
            self, t("dlg_save_fields_title"), default, t("dlg_pdf_filter"))
        if not out:
            return

        self.config.set("paths", "last_save_dir", str(Path(out).parent))
        self.config.save()
        self._set_status(t("status_saving_fields"))
        self._worker = SaveFieldsWorker(
            self.pdf_path, out, list(self.sig_fields))
        self._worker.finished.connect(self._on_save_done)
        self._worker.error.connect(self._on_save_error)
        self._worker.start()

    def _on_save_done(self, path: str) -> None:
        self._set_status(t("status_saved", path=path))
        QMessageBox.information(
            self, t("dlg_save_success_title"),
            t("dlg_save_success_msg", path=path))

    def _on_save_error(self, msg: str) -> None:
        self._set_status(t("status_save_failed"))
        QMessageBox.critical(
            self, t("dlg_save_error_title"),
            t("dlg_save_error_msg", error=msg))

    # ── Config dialogs ────────────────────────────────────────────────────

    def open_pkcs11_config(self) -> None:
        Pkcs11ConfigDialog(self, self.config).exec()

    def open_appearance_config(self) -> None:
        # Appearance is configured inline in the right panel; no separate dialog.
        pass

    # ── Signing ───────────────────────────────────────────────────────────

    def sign_document(self) -> None:
        if not self.pdf_doc:
            QMessageBox.warning(self, t("dlg_no_doc"), t("dlg_no_doc_msg"))
            return
        if not _pyhanko_available:
            QMessageBox.critical(
                self, t("dlg_sign_error_title"), t("dlg_pyhanko_missing"))
            return

        # Row 0 = invisible signature, row 1+ = sig_fields[row - 1]
        row  = self._field_list.currentRow()
        fdef: Optional[SignatureFieldDef] = None
        if 1 <= row <= len(self.sig_fields):
            fdef = self.sig_fields[row - 1]

        stem    = Path(self.pdf_path).stem
        start   = self.config.get("paths", "last_save_dir")
        default = str(Path(start) / (stem + t("dlg_save_signed_suffix") + ".pdf"))
        out, _  = QFileDialog.getSaveFileName(
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

    def _on_sign_done(self, path: str) -> None:
        self._set_status(t("status_signed", path=path))
        QMessageBox.information(
            self, t("dlg_sign_success_title"),
            t("dlg_sign_success_msg", path=path))

    def _on_sign_error(self, msg: str) -> None:
        self._set_status(t("status_sign_failed"))
        QMessageBox.critical(
            self, t("dlg_sign_error_title"),
            t("dlg_sign_error_msg", error=msg))

    def _show_about(self) -> None:
        QMessageBox.about(self, t("about_title"), t("about_msg"))
