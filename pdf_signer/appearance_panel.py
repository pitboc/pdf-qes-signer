# SPDX-License-Identifier: GPL-3.0-or-later
"""
Inline appearance-settings panel for PDF QES Signer.

Provides:
  - AppearancePanel  – a QWidget containing the Text and Image/Layout tabs
                       for configuring the visual appearance of a signature field.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSlider, QSpinBox, QTabWidget,
    QVBoxLayout, QWidget,
)

from .config import AppConfig, PDF_STANDARD_FONTS
from .i18n import t


class AppearancePanel(QWidget):
    """Inline appearance-settings panel (Text tab + Image/Layout tab).

    Emits ``appearance_changed`` whenever any setting is saved to the config,
    so the caller can repaint the PDF canvas without this widget needing a
    reference back to the main window.

    Constructor arguments:
      config  – the application's AppConfig instance (read/write)
      tr      – translation function (called as ``tr("key")``)
      parent  – optional Qt parent widget
    """

    # Emitted after every save-to-config; connect to _render_current_page
    appearance_changed = pyqtSignal()

    # Vordefinierte Datumsformate für die Erscheinungsbild-Einstellungen.
    # Erstes Element: Python-strftime-Format; Zweites: Beispiel-String für Anzeige.
    DATE_FORMATS: list[tuple[str, str]] = [
        ("%d.%m.%Y %H:%M",    "31.12.2025 14:30"),
        ("%d.%m.%Y",          "31.12.2025"),
        ("%Y-%m-%d %H:%M:%S", "2025-12-31 14:30:00"),
        ("%Y-%m-%d",          "2025-12-31"),
        ("%d/%m/%Y %H:%M",    "31/12/2025 14:30"),
        ("%B %d, %Y",         "December 31, 2025"),
    ]
    # Sentinel-Wert für den "Benutzerdefiniert"-Eintrag in der Datumsformat-Combobox
    CUSTOM_FMT = "__custom__"

    def __init__(self, config: AppConfig, tr: Callable, parent=None) -> None:
        super().__init__(parent)
        self._config = config
        self._tr = tr

        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        self._app_tabs = QTabWidget()
        self._app_tabs.setTabPosition(QTabWidget.TabPosition.North)
        vl.addWidget(self._app_tabs)

        self._build_ui()
        self._load_appearance_panel()

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Build the Text and Image/Layout tabs."""

        # Tab 1: Text
        # Steuerung der Textinhalte im Signaturfeld: Name, Ort, Grund, Datum, Schrift
        txt_tab = QWidget()
        gl = QGridLayout(txt_tab)
        gl.setColumnStretch(1, 1)
        gl.setSpacing(4)
        gl.setContentsMargins(4, 4, 4, 4)
        row = 0

        # Name
        # Checkbox aktiviert Namensanzeige; Combobox wählt Quelle (Zertifikat oder Freitext)
        self._ap_chk_name = QCheckBox(t("app_name_label"))
        self._ap_name_mode = QComboBox()
        self._ap_name_mode.addItem(t("ap_name_from_cert"), "cert")
        self._ap_name_mode.addItem(t("ap_name_custom"),    "custom")
        # Freitext-Eingabe für benutzerdefinierten Namen (nur im "custom"-Modus aktiv)
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
        # Signierort (z.B. "Berlin"); wird in den PDF-Signatur-Metadaten gespeichert
        self._ap_chk_loc = QCheckBox(t("app_location_label"))
        self._ap_loc = QLineEdit()
        gl.addWidget(self._ap_chk_loc, row, 0)
        gl.addWidget(self._ap_loc,     row, 1)
        row += 1

        # Reason
        # Signaturgrund (z.B. "Genehmigung"); wird in den PDF-Signatur-Metadaten gespeichert
        self._ap_chk_reason = QCheckBox(t("app_reason_label"))
        self._ap_reason = QLineEdit()
        gl.addWidget(self._ap_chk_reason, row, 0)
        gl.addWidget(self._ap_reason,     row, 1)
        row += 1

        # Date
        # Datum/Uhrzeit: pyhanko ersetzt %(ts)s beim Signieren durch den
        # kryptographischen Zeitstempel aus dem Signaturprozess
        self._ap_chk_date = QCheckBox(t("app_date_label"))
        date_vl = QVBoxLayout()
        date_vl.setSpacing(2)
        # Vordefinierte Datumsformate in der Combobox
        self._ap_date_combo = QComboBox()
        for fmt, ex in self.DATE_FORMATS:
            self._ap_date_combo.addItem(f"{fmt}  →  {ex}", fmt)
        # "Benutzerdefiniert"-Eintrag ermöglicht freie Formatangabe
        self._ap_date_combo.addItem(t("ap_date_custom"), self.CUSTOM_FMT)
        # Freitext-Eingabe für das Datumsformat (anfangs ausgeblendet)
        self._ap_date_custom = QLineEdit()
        self._ap_date_custom.setPlaceholderText("%d.%m.%Y %H:%M")
        self._ap_date_custom.setVisible(False)
        date_vl.addWidget(self._ap_date_combo)
        date_vl.addWidget(self._ap_date_custom)
        gl.addWidget(self._ap_chk_date, row, 0)
        gl.addLayout(date_vl,           row, 1)
        row += 1

        # Font size
        # Schriftgröße in Punkten: Bereich 5–24pt; Spinbox mit direkter Eingabe
        self._ap_font_spin = QSpinBox()
        self._ap_font_spin.setRange(5, 24)
        self._ap_lbl_font_size = QLabel(t("ap_font_pt"))
        gl.addWidget(self._ap_lbl_font_size, row, 0)
        gl.addWidget(self._ap_font_spin,     row, 1,
                     alignment=Qt.AlignmentFlag.AlignLeft)
        row += 1

        # Font family
        # Schriftfamilie: nur PDF-14-Standardschriften (keine Einbettung nötig)
        self._ap_font_combo = QComboBox()
        for disp, pdf_name, _, _ in PDF_STANDARD_FONTS:
            self._ap_font_combo.addItem(disp, pdf_name)
        self._ap_lbl_font_family = QLabel(t("ap_font_family"))
        gl.addWidget(self._ap_lbl_font_family, row, 0)
        gl.addWidget(self._ap_font_combo,      row, 1)
        row += 1

        # Restlicher Platz im Grid-Layout als Stretch-Zeile
        gl.setRowStretch(row, 1)
        self._app_tabs.addTab(txt_tab, t("ap_tab_text"))

        # Tab 2: Image / Layout
        # Steuerung des Bildes und Layouts (links/rechts, Rahmen, Verhältnis)
        img_tab = QWidget()
        vl = QVBoxLayout(img_tab)
        vl.setContentsMargins(4, 4, 4, 4)
        vl.setSpacing(6)

        # Image path
        # Zeile mit Bildpfad-Anzeige (read-only), Datei-Auswahl-Button und Löschen-Button
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

        # Hinweistext in grau: unterstützte Bildformate oder Empfehlungen
        self._ap_img_hint = QLabel(t("ap_img_hint"))
        self._ap_img_hint.setStyleSheet("color:gray; font-size:10px;")
        vl.addWidget(self._ap_img_hint)

        # Layout combo
        # Wählt ob das Bild links oder rechts vom Text erscheint
        lay_row = QHBoxLayout()
        self._ap_lbl_layout = QLabel(t("app_layout_label"))
        lay_row.addWidget(self._ap_lbl_layout)
        self._ap_layout = QComboBox()
        self._ap_layout.addItem(t("ap_layout_left"),  "img_left")
        self._ap_layout.addItem(t("ap_layout_right"), "img_right")
        lay_row.addWidget(self._ap_layout)
        vl.addLayout(lay_row)

        # Border checkbox
        # Dünner Rahmen um das gesamte Signaturfeld (optional)
        self._ap_border = QCheckBox(t("ap_border"))
        vl.addWidget(self._ap_border)

        # Image/text ratio slider
        # Slider steuert den Anteil des Bildes an der Gesamtbreite (10–70 %).
        # Linkes und rechtes Label zeigen den aktuellen Wert.
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
        # Alle Checkboxen lösen bei Aktivierung/Deaktivierung einen Speicher- und
        # Vorschau-Refresh aus; dabei werden abhängige Eingabefelder en-/deaktiviert
        for chk in (self._ap_chk_name, self._ap_chk_loc,
                    self._ap_chk_reason, self._ap_chk_date):
            chk.toggled.connect(self._ap_on_checks)
        # Name-Modus-Wechsel (cert/custom) beeinflusst den Freitext-Inhalt
        self._ap_name_mode.currentIndexChanged.connect(self._ap_on_checks)
        # Datumsformat-Wechsel: "Custom…"-Feld ein-/ausblenden
        self._ap_date_combo.currentIndexChanged.connect(self._ap_on_date_fmt)
        # Texteingaben lösen sofortiges Speichern und Canvas-Refresh aus
        for w in (self._ap_loc, self._ap_reason, self._ap_name_custom,
                  self._ap_date_custom):
            w.textChanged.connect(self._ap_save_and_refresh)
        self._ap_font_spin.valueChanged.connect(self._ap_save_and_refresh)
        self._ap_font_combo.currentIndexChanged.connect(self._ap_save_and_refresh)
        # Layout-Wechsel invertiert ggf. den Slider (Bild rechts → invertierte Anzeige)
        self._ap_layout.currentIndexChanged.connect(self._ap_on_layout)
        self._ap_border.toggled.connect(self._ap_save_and_refresh)
        # Slider-Wertänderung: Labels und Vorschau aktualisieren
        self._ap_ratio.valueChanged.connect(self._ap_on_ratio)

    # ── Slots ─────────────────────────────────────────────────────────────

    def _ap_on_checks(self) -> None:
        """Enable/disable fields based on checkbox states."""
        name_on = self._ap_chk_name.isChecked()
        self._ap_name_mode.setEnabled(name_on)
        is_cert_mode = self._ap_name_mode.currentData() == "cert"
        # Freitext-Eingabe nur aktiv wenn Name aktiviert UND Modus "custom"
        self._ap_name_custom.setEnabled(name_on and not is_cert_mode)
        # Set field text based on mode (block signals to avoid triggering saves)
        # Signale blockieren damit das programmatische Setzen des Textes keinen
        # weiteren _ap_save_and_refresh auslöst
        self._ap_name_custom.blockSignals(True)
        if is_cert_mode:
            # Im Cert-Modus: cert_cn aus Konfig anzeigen (read-only)
            self._ap_name_custom.setText(self._config.get("pkcs11", "cert_cn"))
            self._ap_name_custom.setPlaceholderText("")
        else:
            # Im Custom-Modus: gespeicherten benutzerdefinierten Namen wiederherstellen
            self._ap_name_custom.setText(self._config.get("appearance", "name_custom"))
            self._ap_name_custom.setPlaceholderText("Jane Doe")
        self._ap_name_custom.blockSignals(False)
        # Eingabefelder entsprechend den Checkbox-Zuständen aktivieren/deaktivieren
        self._ap_loc.setEnabled(self._ap_chk_loc.isChecked())
        self._ap_reason.setEnabled(self._ap_chk_reason.isChecked())
        self._ap_date_combo.setEnabled(self._ap_chk_date.isChecked())
        self._ap_date_custom.setEnabled(self._ap_chk_date.isChecked())
        self._ap_save_and_refresh()

    def _ap_on_date_fmt(self) -> None:
        # "Custom…" ausgewählt → Freitext-Eingabe einblenden; sonst ausblenden
        is_custom = self._ap_date_combo.currentData() == self.CUSTOM_FMT
        self._ap_date_custom.setVisible(is_custom)
        self._ap_save_and_refresh()

    def _ap_on_layout(self) -> None:
        """Invert slider direction when image is on the right."""
        # Bei Bild rechts: Slider-Erscheinung invertieren, damit der Slider
        # intuitiv funktioniert (nach rechts schieben = mehr Bild)
        val = self._ap_layout.currentData() or "img_left"
        self._ap_ratio.setInvertedAppearance(val == "img_right")
        self._ap_update_ratio_labels()
        self._ap_save_and_refresh()

    def _ap_on_ratio(self, _v: int) -> None:
        # Slider-Wert geändert: Beschriftungen und Canvas-Vorschau aktualisieren
        self._ap_update_ratio_labels()
        self._ap_save_and_refresh()

    def _ap_update_ratio_labels(self) -> None:
        # Beschriftungen links und rechts des Ratio-Sliders aktualisieren.
        # Semantik hängt vom Layout ab: bei "img_left" zeigt linkes Label den
        # Bildanteil, bei "img_right" ist es umgekehrt.
        val = self._ap_layout.currentData() or "img_left"
        v   = self._ap_ratio.value()
        if val == "img_left":
            self._ap_ratio_lbl_l.setText(f"◀ Image {v}%")
            self._ap_ratio_lbl_r.setText(f"Text {100 - v}% ▶")
        else:
            # Slider is inverted: left = high value (lots of text)
            # Slider ist invertiert: hoher Wert → mehr Bild, aber auf der rechten Seite
            self._ap_ratio_lbl_l.setText(f"Text {100 - v}% ▶")
            self._ap_ratio_lbl_r.setText(f"◀ Image {v}%")

    def _ap_browse_image(self) -> None:
        # Bilddatei-Dialog öffnen; Startverzeichnis aus letztem gespeicherten Pfad
        start = self._config.get("paths", "last_img_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("ap_browse_img"), start, t("ap_img_filter"))
        if path:
            self._ap_img_path.setText(path)
            # Letztes Bildverzeichnis für künftige Dialoge speichern
            self._config.set("paths", "last_img_dir", str(Path(path).parent))
            self._ap_save_and_refresh()

    def _ap_clear_image(self) -> None:
        # Bildpfad löschen und Vorschau ohne Bild neu rendern
        self._ap_img_path.clear()
        self._ap_save_and_refresh()

    def _ap_date_fmt_value(self) -> str:
        # Aktuell gewähltes Datumsformat zurückgeben.
        # Bei "Custom…": aus dem Freitext-Feld lesen, Fallback auf Standard
        if self._ap_date_combo.currentData() == self.CUSTOM_FMT:
            return self._ap_date_custom.text().strip() or "%d.%m.%Y %H:%M"
        return self._ap_date_combo.currentData() or "%d.%m.%Y %H:%M"

    def _ap_save_and_refresh(self) -> None:
        """Write all appearance values to config and emit appearance_changed."""
        # Alle aktuellen Widget-Werte in die AppConfig schreiben und auf Disk speichern.
        # Danach appearance_changed-Signal aussenden damit der Aufrufer den Canvas
        # neu zeichnen kann.
        cfg = self._config
        cfg.set("appearance", "image_path",
                self._ap_img_path.text().strip())
        cfg.set("appearance", "layout",
                self._ap_layout.currentData() or "img_left")
        cfg.setbool("appearance", "show_border",  self._ap_border.isChecked())
        cfg.set("appearance", "img_ratio",    str(self._ap_ratio.value()))
        cfg.setbool("appearance", "show_name",    self._ap_chk_name.isChecked())
        cfg.set("appearance", "name_mode",
                self._ap_name_mode.currentData() or "cert")
        # Only overwrite the custom name when in custom mode;
        # in cert mode the field displays cert_cn which must not clobber name_custom.
        # Im Cert-Modus zeigt das Feld den cert_cn an – dieser darf name_custom
        # nicht überschreiben, da er beim nächsten Wechsel zu "custom" verloren wäre
        if self._ap_name_mode.currentData() != "cert":
            cfg.set("appearance", "name_custom", self._ap_name_custom.text().strip())
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
        # Signal statt direktem Canvas-Zugriff
        self.appearance_changed.emit()

    def _load_appearance_panel(self) -> None:
        """Populate the inline appearance widgets from config (no signals fired)."""
        # Alle Widgets aus der Konfig befüllen ohne dabei Signale auszulösen,
        # die vorzeitig Speicher- und Refresh-Operationen anstoßen würden.
        cfg = self._config
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
        # Alle Text-bezogenen Einstellungen aus der Konfig laden
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
            # Format direkt in der Combobox gefunden → auswählen
            self._ap_date_combo.setCurrentIndex(fmt_idx)
        else:
            # Format nicht in der Liste → "Custom…" wählen und Freitext-Feld füllen
            custom_idx = self._ap_date_combo.findData(self.CUSTOM_FMT)
            self._ap_date_combo.setCurrentIndex(custom_idx)
            self._ap_date_custom.setText(saved_fmt)
            self._ap_date_custom.setVisible(True)

        # Schriftgröße laden; ungültige Werte auf gültigen Bereich clampen
        try:
            fs = int(cfg.get("appearance", "font_size") or "8")
        except (ValueError, TypeError):
            fs = 8
        self._ap_font_spin.setValue(max(5, min(24, fs)))
        # Schriftfamilie: gespeicherten PDF-Fontnamen in der Combobox suchen
        ff_idx = self._ap_font_combo.findData(
            cfg.get("appearance", "font_family") or "Helvetica")
        self._ap_font_combo.setCurrentIndex(max(0, ff_idx))

        # Image/Layout tab
        self._ap_img_path.setText(cfg.get("appearance", "image_path"))
        lay_idx = self._ap_layout.findData(cfg.get("appearance", "layout"))
        self._ap_layout.setCurrentIndex(max(0, lay_idx))
        self._ap_border.setChecked(cfg.getbool("appearance", "show_border"))

        # Verhältnis-Slider: ungültige Werte auf gültigen Bereich clampen
        try:
            ratio = int(cfg.get("appearance", "img_ratio") or "40")
        except (ValueError, TypeError):
            ratio = 40
        self._ap_ratio.setValue(max(10, min(70, ratio)))
        # Slider invertieren wenn Bild rechts ausgewählt ist
        self._ap_ratio.setInvertedAppearance(
            (self._ap_layout.currentData() or "img_left") == "img_right")

        # Signale wieder freigeben
        for w in widgets:
            w.blockSignals(False)

        # Checkbox-abhängige Felder aktivieren/deaktivieren und Slider-Labels setzen
        self._ap_on_checks()
        self._ap_on_layout()

    # ── Public API ─────────────────────────────────────────────────────────

    def reload_from_config(self) -> None:
        """Reload all UI controls from the current config (e.g. after a profile switch)."""
        self._load_appearance_panel()

    def retranslate(self, tr: Callable) -> None:
        """Retranslate all widget texts to the current language.

        Called by the main window's ``_apply_language`` whenever the user
        switches the application language.
        """
        self._tr = tr
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
        # "Custom…"-Eintrag in der Datumsformat-Combobox übersetzen
        custom_idx = self._ap_date_combo.findData(self.CUSTOM_FMT)
        if custom_idx >= 0:
            self._ap_date_combo.setItemText(custom_idx, t("ap_date_custom"))
        self._ap_clr_btn.setText(t("appdlg_img_clear"))
        self._ap_img_hint.setText(t("ap_img_hint"))
        self._app_tabs.setTabText(0, t("ap_tab_text"))
        self._app_tabs.setTabText(1, t("ap_tab_image_layout"))

    def on_checks(self) -> None:
        """Public forwarder so the main window can trigger the check-state
        refresh after the PKCS#11 dialog may have changed ``cert_cn``."""
        self._ap_on_checks()
