# SPDX-License-Identifier: GPL-3.0-or-later
"""
Main application window for PDF QES Signer.

Provides:
  - PDFSignerApp  – the QMainWindow subclass that ties all components together

## Three-category field model

Every signature field in the application belongs to exactly one of three lists:

| List            | Contents                                      | Editable?               |
|-----------------|-----------------------------------------------|-------------------------|
| `sig_fields`    | Unsigned, freely editable                     | Yes – add, delete, move |
| `locked_fields` | Unsigned but frozen by an existing signature  | Sign only               |
| `signed_fields` | Already signed                                | Display only            |

### Why locked_fields?

A PDF signature covers a cryptographic hash of all bytes up to and including
the moment of signing.  Any unsigned form fields present at that time are
*inside* the signed byte range.  Deleting or moving them afterwards would
invalidate the existing signature – the hash would no longer match.  Those
fields therefore appear in `locked_fields` and can only be signed, not deleted
or repositioned.

### In-memory working copy (_working_bytes)

When a PDF is opened, all *free* unsigned fields (those in `sig_fields`) are
stripped from the in-memory fitz document.  Only their Python representations
remain in `sig_fields`.  This gives full freedom to add, delete, and rename
them without touching the file on disk.

The resulting bytes are stored as `_working_bytes`.  Workers
(`SaveFieldsWorker`, `SignWorker`) always start from these bytes and re-embed
the current `sig_fields` list just before writing to disk.  No temporary files
are created; everything stays in memory until an explicit save or sign action.

### Signing chain

After a successful signing operation the application reloads the just-written
signed PDF as the new working document.  This means:

- The freshly signed field immediately appears with the ✓ marker.
- Any subsequent signing operation uses the signed PDF as its base, so all
  previous signatures are preserved in the output chain.  A document may
  therefore accumulate multiple independent signatures, each in its own
  incremental revision.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

import fitz  # PyMuPDF

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QFont, QKeySequence
from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QMainWindow,
    QMessageBox, QPushButton, QScrollArea,
    QSplitter, QVBoxLayout, QWidget, QCheckBox,
)

from .config import AppConfig
from .appearance import SigAppearance
from .signer import (
    SaveFieldsWorker, SignWorker,
    _pyhanko_available, _pkcs11_available,
)
from .pdf_view import PDFViewWidget, SignatureFieldDef
from .dialogs import Pkcs11ConfigDialog
from .i18n import t, i18n, AVAILABLE_LANGUAGES
from .appearance_panel import AppearancePanel
from .continuous_view import ContinuousView  # noqa: F401 – imported for future use


class PDFSignerApp(QMainWindow):
    """Main window of PDF QES Signer.

    Responsibilities:
      - Menu bar, toolbar, and status bar
      - Central PDF canvas (left) with scroll area
      - Right panel: field list, PIN entry, inline appearance settings
      - Dispatching PDF open, save-with-fields, and sign operations to workers
    """

    def __init__(self, config: AppConfig,
                 initial_pdf: Optional[str] = None) -> None:
        super().__init__()
        # config: AppConfig-Instanz mit allen persistierten Einstellungen
        self.config       = config
        # appearance: kapselt alle visuellen Einstellungen des Signaturfelds;
        # liest direkt aus config → Änderungen sofort wirksam
        self.appearance   = SigAppearance(config)
        # pdf_doc: aktuell geöffnetes PyMuPDF-Dokument (None wenn kein PDF geöffnet)
        self.pdf_doc:     Optional[fitz.Document] = None
        # pdf_path: absoluter Pfad zur aktuell geöffneten PDF-Datei
        self.pdf_path     = ""
        # _working_bytes: PDF-Bytes der Arbeitskopie ohne freie unsigned Felder.
        # Worker-Threads starten immer von dieser Basis und re-embedden sig_fields.
        self._working_bytes: bytes = b""  # PDF bytes without free unsigned fields
        # current_page: 0-basierter Index der aktuell angezeigten Seite
        self.current_page = 0
        # Drei-Kategorien-Modell (siehe Modul-Docstring):
        self.sig_fields:    list[SignatureFieldDef] = []  # free unsigned (editable)
        self.locked_fields: list[SignatureFieldDef] = []  # unsigned but frozen by existing sig
        self.signed_fields: list[SignatureFieldDef] = []  # already signed (display only)
        # Worker-Referenzen halten damit GC sie nicht vorzeitig zerstört
        self._worker      = None
        self._sign_worker = None
        # Fortlaufende Ansicht: Zustand und per-Seite-Widgets
        self._continuous_mode: bool = False
        self._page_widgets:    list[PDFViewWidget]  = []
        self._page_y_offsets:  list[int]            = []  # widget-top y per page
        self._continuous_doc_id: int = 0  # id(pdf_doc) when page widgets were built

        self._build_ui()
        self._apply_language()
        self.statusBar().showMessage(t("status_ready"))
        # Fehlende Abhängigkeiten (pyhanko, python-pkcs11) beim Start prüfen
        self._check_dependencies()

        # Optionale initiale PDF-Datei direkt öffnen (z.B. per Kommandozeilenargument)
        if initial_pdf:
            self._open_pdf(initial_pdf)

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setMinimumSize(980, 660)
        self.resize(1340, 840)

        # Menu bar
        # Menü-Leiste: Datei, Signieren, Einstellungen, Hilfe
        self._menu_file = self.menuBar().addMenu("")
        self._act_open  = QAction(self)
        self._act_open.setShortcut(QKeySequence.StandardKey.Open)
        # Öffnet PDF-Dateidialog und lädt das ausgewählte Dokument
        self._act_open.triggered.connect(self.open_pdf)
        self._menu_file.addAction(self._act_open)
        self._act_save_fields = QAction(self)
        # Speichert PDF mit eingebetteten Signaturfeld-Annotationen (ohne Signatur)
        self._act_save_fields.triggered.connect(self.save_with_fields)
        self._menu_file.addAction(self._act_save_fields)
        self._menu_file.addSeparator()
        self._act_quit = QAction(self)
        self._act_quit.setShortcut(QKeySequence.StandardKey.Quit)
        self._act_quit.triggered.connect(self.close)
        self._menu_file.addAction(self._act_quit)

        self._menu_sign = self.menuBar().addMenu("")
        self._act_sign  = QAction(self)
        # Startet den Signiervorgang für das ausgewählte Signaturfeld
        self._act_sign.triggered.connect(self.sign_document)
        self._menu_sign.addAction(self._act_sign)

        self._menu_settings  = self.menuBar().addMenu("")
        self._act_pkcs11     = QAction(self)
        # Öffnet den PKCS#11-Konfigurationsdialog (Bibliothek, Schlüssel-ID, TSA)
        self._act_pkcs11.triggered.connect(self.open_pkcs11_config)
        self._menu_settings.addAction(self._act_pkcs11)

        # Language sub-menu
        # Sprachauswahl-Untermenü: für jede verfügbare Sprache eine umschaltbare Aktion
        self._menu_lang = self.menuBar().addMenu("")
        self._lang_actions: dict[str, QAction] = {}
        for code, label in AVAILABLE_LANGUAGES.items():
            act = QAction(label, self)
            act.setCheckable(True)
            # Aktuell aktive Sprache mit Häkchen markieren
            act.setChecked(code == i18n.lang)
            # Lambda mit Default-Argument um Closures-Problem mit Schleifenvariable zu vermeiden
            act.triggered.connect(lambda _, c=code: self._set_language(c))
            self._lang_actions[code] = act
            self._menu_lang.addAction(act)
        self._menu_settings.addMenu(self._menu_lang)

        self._menu_help = self.menuBar().addMenu("")
        self._act_about = QAction(self)
        self._act_about.triggered.connect(self._show_about)
        self._menu_help.addAction(self._act_about)
        self._act_license = QAction(self)
        self._act_license.triggered.connect(self._show_license)
        self._menu_help.addAction(self._act_license)

        # Toolbar
        # Werkzeugleiste mit den häufigsten Aktionen als Schaltflächen
        tb = self.addToolBar("main")
        tb.setMovable(False)
        self._tb_open = QAction(self)
        self._tb_open.triggered.connect(self.open_pdf)
        tb.addAction(self._tb_open)
        tb.addSeparator()
        # Seitennavigation: vorherige/nächste Seite
        self._tb_prev = QAction(self)
        self._tb_prev.triggered.connect(self.prev_page)
        tb.addAction(self._tb_prev)
        # Seitennummer (editierbar) und Gesamtanzahl zwischen den Navigationspfeilen
        self._page_edit = QLineEdit("–")
        self._page_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._page_edit.setFixedWidth(42)
        self._page_edit.returnPressed.connect(self._on_page_jump)
        tb.addWidget(self._page_edit)
        self._page_total_lbl = QLabel("/ –")
        self._page_total_lbl.setMinimumWidth(32)
        tb.addWidget(self._page_total_lbl)
        self._tb_next = QAction(self)
        self._tb_next.triggered.connect(self.next_page)
        tb.addAction(self._tb_next)
        # Umschalter Einzelseite ↔ Fortlaufende Ansicht
        self._tb_view_toggle = QAction("☰", self)
        self._tb_view_toggle.setCheckable(True)
        self._tb_view_toggle.setChecked(False)
        self._tb_view_toggle.setToolTip("Fortlaufende Seitenansicht")
        self._tb_view_toggle.triggered.connect(self._toggle_view_mode)
        tb.addAction(self._tb_view_toggle)
        tb.addSeparator()
        # Signieren und Felder speichern als Toolbar-Schnellzugriff
        self._tb_sign = QAction(self)
        self._tb_sign.triggered.connect(self.sign_document)
        tb.addAction(self._tb_sign)
        self._tb_save_fields = QAction(self)
        self._tb_save_fields.triggered.connect(self.save_with_fields)
        tb.addAction(self._tb_save_fields)

        # Central splitter: PDF canvas (left) + right panel
        # Haupt-Splitter: PDF-Canvas links (größerer Anteil), Steuerbereich rechts
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(splitter)

        # PDF-Canvas in ScrollArea eingebettet (kann bei hohem Zoom scrollen).
        # _outer_container ist das permanente ScrollArea-Widget (wird NIE ersetzt).
        # Beim Moduswechsel werden nur die Kinder des Containers ausgetauscht,
        # um Qt-Ownership-Probleme bei wiederholtem setWidget() zu vermeiden.
        self._scroll_area = QScrollArea()
        self._scroll_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll_area.setStyleSheet("QScrollArea { background: #404040; }")
        self._outer_container = QWidget()
        self._outer_container.setObjectName("pdfOuterContainer")
        # ID-Selektor (#name) kaskadiert nicht auf Kind-Widgets – verhindert,
        # dass QInputDialog-Dialoge den dunklen Hintergrund erben
        self._outer_container.setStyleSheet(
            "#pdfOuterContainer { background: #404040; }")
        self._outer_layout = QVBoxLayout(self._outer_container)
        self._outer_layout.setContentsMargins(0, 0, 0, 0)
        self._outer_layout.setSpacing(0)
        self._outer_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self._pdf_view = PDFViewWidget(self.appearance)
        # Signale vom PDFViewWidget: Feld hinzugefügt, gelöscht, angeklickt
        self._pdf_view.field_added.connect(self._on_field_added)
        self._pdf_view.field_deleted.connect(self._on_field_deleted)
        # Klick auf Feld im Canvas → entsprechende Zeile in der Feldliste auswählen
        self._pdf_view.field_clicked.connect(self._on_field_clicked_in_view)
        self._outer_layout.addWidget(self._pdf_view)
        self._scroll_area.setWidget(self._outer_container)
        self._scroll_area.setWidgetResizable(False)
        splitter.addWidget(self._scroll_area)
        # Scroll-Signal für fortlaufende Ansicht (Slot prüft selbst den Modus)
        self._scroll_area.verticalScrollBar().valueChanged.connect(
            self._on_continuous_scroll)

        # Right panel
        # Rechtes Panel: Feldliste, PIN-Eingabe, TSA-Checkbox, Erscheinungsbild-Tabs
        right = QWidget()
        right.setMinimumWidth(240)
        right.setMaximumWidth(310)
        rl = QVBoxLayout(right)
        rl.setContentsMargins(4, 4, 4, 4)
        rl.setSpacing(6)

        # Signature field list
        # Gruppe mit der Liste aller Signaturfelder und Bearbeitungsschaltflächen
        self._fields_group = QGroupBox()
        fl = QVBoxLayout(self._fields_group)
        # _field_list: listet alle drei Feldkategorien auf (farblich unterschieden).
        # Zeile 0 = "Unsichtbare Signatur", 1…N = sig_fields (blau/schwarz),
        # N+1…N+K = locked_fields (orange), Rest = signed_fields (grau)
        self._field_list = QListWidget()
        self._field_list.setFont(QFont("Courier", 9))
        # Auswahl-Änderung: Vorschau im Canvas aktualisieren
        self._field_list.currentRowChanged.connect(self._on_field_selection_changed)
        fl.addWidget(self._field_list)
        btn_row = QHBoxLayout()
        # "Löschen"-Schaltfläche: nur für sig_fields-Felder aktiv
        self._btn_delete = QPushButton()
        self._btn_delete.clicked.connect(self.delete_selected_field)
        # "Speichern"-Schaltfläche: speichert PDF mit Signaturfeld-Annotationen
        self._btn_save = QPushButton()
        self._btn_save.clicked.connect(self.save_with_fields)
        btn_row.addWidget(self._btn_delete)
        btn_row.addWidget(self._btn_save)
        fl.addLayout(btn_row)
        rl.addWidget(self._fields_group)

        # Token / PIN panel
        # PIN-Eingabebereich: Passwort-Modus; leer = Hardware-PIN-Pad verwenden
        self._token_group = QGroupBox()
        tl2 = QFormLayout(self._token_group)
        tl2.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        self._pin_edit = QLineEdit()
        self._pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pin_lbl_widget = QLabel()
        tl2.addRow(self._pin_lbl_widget, self._pin_edit)
        # Hinweistext in grau/klein unter der PIN-Zeile
        self._pin_hint_lbl = QLabel()
        self._pin_hint_lbl.setStyleSheet("color: gray; font-size: 10px;")
        tl2.addRow("", self._pin_hint_lbl)
        rl.addWidget(self._token_group)

        # TSA toggle
        # Checkbox zum Ein-/Ausschalten des RFC-3161-Zeitstempels.
        # Wenn aktiviert, wird beim Signieren ein Zeitstempel von der
        # konfigurierten TSA abgeholt und in die Signatur eingebettet.
        self._tsa_chk = QCheckBox()
        # Checkbox-Änderung speichert den Zustand sofort in der Konfig
        self._tsa_chk.toggled.connect(self._on_tsa_toggled)
        rl.addWidget(self._tsa_chk)

        # Inline appearance panel
        # Erscheinungsbild-Gruppe: inline in der Hauptansicht statt separatem Dialog,
        # damit Änderungen sofort in der Canvas-Vorschau sichtbar sind
        self._app_group = QGroupBox()
        ag = QVBoxLayout(self._app_group)
        ag.setContentsMargins(4, 4, 4, 4)
        ag.setSpacing(4)
        # AppearancePanel kapselt alle Erscheinungsbild-Tabs; emittiert
        # appearance_changed wenn Einstellungen gespeichert werden
        self._ap_panel = AppearancePanel(self.config, t, self)
        self._ap_panel.appearance_changed.connect(self._render_current_page)
        ag.addWidget(self._ap_panel, stretch=2)
        rl.addWidget(self._app_group, stretch=1)
        rl.addStretch()

        splitter.addWidget(right)
        # Canvas bekommt 5-fachen Anteil, rechtes Panel 1-fachen Anteil
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 1)

        # TSA-Checkbox aus Konfig initialisieren
        self._tsa_chk.setChecked(self.config.getbool("tsa", "enabled"))

    # ── Language support ──────────────────────────────────────────────────

    def _set_language(self, code: str) -> None:
        # Sprache wechseln: i18n-Singleton aktualisieren, Konfig speichern,
        # alle Sprach-Aktionen neu einrasten und UI neu beschriften
        i18n.lang = code
        self.config.set("app", "language", code)
        self.config.save()
        for c, act in self._lang_actions.items():
            act.setChecked(c == code)
        self._apply_language()

    def _apply_language(self) -> None:
        """Retranslate all UI strings to the current language."""
        # Alle sichtbaren Texte der Benutzeroberfläche auf die aktuelle Sprache setzen.
        # Wird beim Sprachenwechsel und beim ersten Aufbau aufgerufen.
        self.setWindowTitle("PDF QES Signer")
        self._menu_file.setTitle(t("menu_file"))
        self._act_open.setText(t("menu_file_open"))
        self._act_save_fields.setText(t("menu_file_save_fields"))
        self._act_quit.setText(t("menu_file_quit"))
        self._menu_sign.setTitle(t("menu_sign"))
        self._act_sign.setText(t("menu_sign_document"))
        self._menu_settings.setTitle(t("menu_settings"))
        self._act_pkcs11.setText(t("menu_settings_pkcs11"))
        self._menu_lang.setTitle(t("menu_settings_language"))
        self._menu_help.setTitle(t("menu_help"))
        self._act_about.setText(t("menu_help_about"))
        self._act_license.setText(t("menu_help_license"))
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
        self._tsa_chk.setText(t("tsa_enabled_label"))
        # Appearance panel – retranslate all inline widgets via AppearancePanel
        self._ap_panel.retranslate(t)

    # ── Utility methods ───────────────────────────────────────────────────

    def _set_status(self, msg: str) -> None:
        # Statusleiste am unteren Fensterrand aktualisieren
        self.statusBar().showMessage(msg)

    def _update_field_list(self) -> None:
        from PyQt6.QtWidgets import QListWidgetItem
        from PyQt6.QtGui import QColor
        # Aktuelle Auswahl merken damit sie nach dem Neuaufbau wiederhergestellt wird
        prev_row = self._field_list.currentRow()
        self._field_list.clear()
        # Row 0: invisible signature option
        # Zeile 0: Sonderoption "Unsichtbare Signatur" (kein Feld im Canvas)
        self._field_list.addItem(t("dlg_invisible_field"))
        # Rows 1 … len(sig_fields): free unsigned fields (blue, deletable)
        # Freie unsigned Felder: schwarz/normal, löschbar
        for fdef in self.sig_fields:
            self._field_list.addItem(
                f"p.{fdef.page + 1}  {fdef.name}  [{fdef.x1:.0f},{fdef.y1:.0f}]")
        # Rows after sig_fields: locked unsigned fields (orange, only signable)
        # Gesperrte unsigned Felder: orange markiert, nicht löschbar (durch Signatur-Hash geschützt)
        for fdef in self.locked_fields:
            item = QListWidgetItem(
                f"🔒 p.{fdef.page + 1}  {fdef.name}  [{fdef.x1:.0f},{fdef.y1:.0f}]")
            item.setForeground(QColor("#e67e00"))
            self._field_list.addItem(item)
        # Rows after: already-signed fields (grey, display only)
        # Bereits signierte Felder: grau mit ✓-Symbol, keine Aktion möglich
        for fdef in self.signed_fields:
            item = QListWidgetItem(f"✓ p.{fdef.page + 1}  {fdef.name}")
            item.setForeground(QColor("#888888"))
            self._field_list.addItem(item)
        # Letzte gültige Auswahl wiederherstellen (oder letztes Element)
        n = self._field_list.count()
        if n > 0:
            row = prev_row if 0 <= prev_row < n else (n - 1 if n > 1 else 0)
            self._field_list.setCurrentRow(row)

    def _check_dependencies(self) -> None:
        # Prüfen ob optionale Bibliotheken vorhanden sind;
        # bei fehlenden Paketen einen Warn-Dialog mit Installationshinweis zeigen
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
        """Render the current page (single-page mode) or refresh overlays
        (continuous mode).  A full rebuild of the continuous view is triggered
        whenever the loaded document changed since the last build."""
        if not self.pdf_doc:
            return
        if self._continuous_mode:
            # Rebuild wenn neues Dokument; overlay-refresh wenn selbes Dokument
            if not self._page_widgets or self._continuous_doc_id != id(self.pdf_doc):
                self._rebuild_continuous_view()
            else:
                self._refresh_continuous_view()
            return
        page = self.pdf_doc[self.current_page]
        self._pdf_view.set_page(
            page, self.sig_fields, self.current_page,
            self.locked_fields, self.signed_fields)
        # Layout-Größe sofort neu berechnen, damit die ScrollArea die
        # aktualisierte Größe des _outer_container sofort übernimmt
        self._outer_container.adjustSize()
        # Seitenzähler im Toolbar aktualisieren (1-basiert für den Benutzer)
        self._page_edit.setText(str(self.current_page + 1))
        self._page_total_lbl.setText(f"/ {len(self.pdf_doc)}")

    # ── Field list selection ──────────────────────────────────────────────

    def _on_field_selection_changed(self, row: int) -> None:
        """Show appearance preview in the selected unsigned field (free or locked)."""
        n_sig    = len(self.sig_fields)
        n_locked = len(self.locked_fields)
        n_signed = len(self.signed_fields)
        # Auswahl in der Feldliste auf das entsprechende PDFViewWidget-Feld abbilden.
        # Row 0 = unsichtbar → kein Feld hervorheben
        selected_for_scroll: Optional[SignatureFieldDef] = None
        fdef_preview: Optional[SignatureFieldDef] = None
        if 1 <= row <= n_sig:
            fdef_preview = self.sig_fields[row - 1]
            selected_for_scroll = fdef_preview
        elif n_sig + 1 <= row <= n_sig + n_locked:
            fdef_preview = self.locked_fields[row - n_sig - 1]
            selected_for_scroll = fdef_preview
        else:
            if n_sig + n_locked + 1 <= row <= n_sig + n_locked + n_signed:
                selected_for_scroll = self.signed_fields[row - n_sig - n_locked - 1]

        # Vorschau-Hervorhebung auf dem richtigen Widget setzen
        if self._continuous_mode and self._page_widgets:
            for pw in self._page_widgets:
                pw.set_selected_field(None)
            if fdef_preview is not None and fdef_preview.page < len(self._page_widgets):
                self._page_widgets[fdef_preview.page].set_selected_field(fdef_preview)
        else:
            self._pdf_view.set_selected_field(fdef_preview)

        if selected_for_scroll is not None:
            self._scroll_to_field(selected_for_scroll)

    # ── Signals from PDFViewWidget ────────────────────────────────────────

    def _on_page_jump(self) -> None:
        """Navigate to the page number entered in the editable toolbar field."""
        if not self.pdf_doc:
            return
        try:
            page = int(self._page_edit.text()) - 1
        except ValueError:
            self._page_edit.setText(str(self.current_page + 1))
            return
        page = max(0, min(page, len(self.pdf_doc) - 1))
        if self._continuous_mode and self._page_y_offsets:
            self.current_page = page
            self._scroll_area.verticalScrollBar().setValue(
                self._page_y_offsets[page])
            self._page_edit.setText(str(page + 1))
        elif page != self.current_page:
            self.current_page = page
            self._render_current_page()
        else:
            # Restore correct text if the entered value was out of range
            self._page_edit.setText(str(self.current_page + 1))

    def _scroll_to_field(self, fdef: SignatureFieldDef) -> None:
        """Ensure *fdef* is visible; if not, scroll so it appears in the lower
        portion of the viewport.  The page-top never drops below the viewport top."""
        vbar       = self._scroll_area.verticalScrollBar()
        viewport_h = self._scroll_area.viewport().height()

        if self._continuous_mode and self._page_widgets:
            # Fortlaufende Ansicht: Feld-Koordinaten relativ zur Gesamt-Scroll-Fläche
            if fdef.page >= len(self._page_widgets):
                return
            pw = self._page_widgets[fdef.page]
            page_top = self._page_y_offsets[fdef.page]
            tl = pw._pdf_to_w(fdef.x1, fdef.y2)
            br = pw._pdf_to_w(fdef.x2, fdef.y1)
            field_top_y    = page_top + min(tl.y(), br.y())
            field_bottom_y = page_top + max(tl.y(), br.y())
            cur_scroll = vbar.value()
            if cur_scroll <= field_top_y and field_bottom_y <= cur_scroll + viewport_h:
                return  # bereits vollständig sichtbar
            target = int(field_bottom_y - viewport_h * 0.80)
            # Seitenanfang darf nicht unterhalb des Viewport-Obeenrandes rutschen
            target = max(page_top, target)
            target = min(target, vbar.maximum())
            vbar.setValue(target)
            return

        # Einzelseitenansicht
        page_changed = fdef.page != self.current_page
        if page_changed:
            self.current_page = fdef.page
            self._render_current_page()
        tl = self._pdf_view._pdf_to_w(fdef.x1, fdef.y2)
        br = self._pdf_view._pdf_to_w(fdef.x2, fdef.y1)
        field_top_y    = min(tl.y(), br.y())
        field_bottom_y = max(tl.y(), br.y())
        cur_scroll = vbar.value()
        if not page_changed and cur_scroll <= field_top_y and field_bottom_y <= cur_scroll + viewport_h:
            return
        target = int(field_bottom_y - viewport_h * 0.80)
        target = max(0, target)
        target = min(target, vbar.maximum())
        vbar.setValue(target)

    # ── Continuous / single-page view toggle ──────────────────────────────

    def _toggle_view_mode(self) -> None:
        """Switch between single-page and continuous scroll view."""
        self._continuous_mode = self._tb_view_toggle.isChecked()
        if self._continuous_mode:
            self._tb_view_toggle.setToolTip("Einzelseitenansicht")
            if self.pdf_doc:
                self._rebuild_continuous_view()
        else:
            self._tb_view_toggle.setToolTip("Fortlaufende Seitenansicht")
            # Seiten-Widgets löschen (wurden direkt am _outer_container gehängt)
            for pw in self._page_widgets:
                pw.hide()
                pw.deleteLater()
            self._page_widgets    = []
            self._page_y_offsets  = []
            self._continuous_doc_id = 0
            # Einzelseitenansicht wieder ins Layout einfügen und anzeigen
            self._outer_layout.addWidget(self._pdf_view)
            self._pdf_view.show()
            self._render_current_page()

    def _rebuild_continuous_view(self) -> None:
        """Rasterize all pages and position them manually in _outer_container.

        Bypasses QVBoxLayout for the continuous view entirely to avoid Qt
        layout quirks (deferred positioning, sizeHint inaccuracies) that cause
        page overlap or wrong scrollbar ranges on large documents.

        Each page widget is parented directly to _outer_container and positioned
        with move(x, y).  Pages are centred horizontally relative to the widest
        page.  The container is resized explicitly to the exact content size.
        """
        _GAP = 10  # Abstand zwischen Seiten in Pixeln

        # Vorherige Seiten-Widgets bereinigen
        for pw in self._page_widgets:
            pw.hide()
            pw.deleteLater()
        self._page_widgets   = []
        self._page_y_offsets = []

        # Einzelseitenansicht aus dem Layout entfernen und verstecken
        if self._outer_layout.indexOf(self._pdf_view) >= 0:
            self._outer_layout.removeWidget(self._pdf_view)
        self._pdf_view.hide()

        # Alle Seiten rasterisieren und Maße sammeln
        y = 0
        max_w = 0
        for page_num in range(len(self.pdf_doc)):
            page = self.pdf_doc[page_num]
            pv = PDFViewWidget(self.appearance)
            pv.set_page(page, self.sig_fields, page_num,
                        self.locked_fields, self.signed_fields)
            pv.field_added.connect(self._on_field_added)
            pv.field_deleted.connect(self._on_field_deleted)
            pv.field_clicked.connect(self._on_field_clicked_in_view)
            # Widget direkt am Container hängen, NICHT über das Layout
            pv.setParent(self._outer_container)
            self._page_y_offsets.append(y)
            y += pv.height() + _GAP
            max_w = max(max_w, pv.width())
            self._page_widgets.append(pv)

        # Seiten horizontal zentrieren und an exakter Position platzieren
        total_h = y - _GAP if self._page_widgets else 0  # letzten Gap abziehen
        for i, pv in enumerate(self._page_widgets):
            x = (max_w - pv.width()) // 2
            pv.move(x, self._page_y_offsets[i])
            pv.show()

        # Container exakt auf Inhaltsgröße setzen – kein adjustSize(), da das
        # von sizeHint() abhängt und bei manueller Positionierung unzuverlässig ist
        self._outer_container.resize(max_w, total_h)

        self._continuous_doc_id = id(self.pdf_doc)
        self._page_edit.setText(str(self.current_page + 1))
        self._page_total_lbl.setText(f"/ {len(self.pdf_doc)}")
        if self._page_y_offsets:
            self._scroll_area.verticalScrollBar().setValue(
                self._page_y_offsets[self.current_page])

    def _refresh_continuous_view(self) -> None:
        """Update field overlays on all page widgets without re-rasterizing."""
        for pw in self._page_widgets:
            pw.update_fields(self.sig_fields, self.locked_fields, self.signed_fields)

    def _on_continuous_scroll(self, value: int) -> None:
        """Update the page indicator while scrolling in continuous mode."""
        if not self._continuous_mode or not self._page_y_offsets:
            return
        # Letzte Seite ermitteln, deren Oberkante oberhalb des Viewport-Mittelpunkts liegt
        viewport_mid = value + self._scroll_area.viewport().height() // 2
        current = 0
        for i, y_off in enumerate(self._page_y_offsets):
            if y_off <= viewport_mid:
                current = i
            else:
                break
        if self.current_page != current:
            self.current_page = current
            self._page_edit.blockSignals(True)
            self._page_edit.setText(str(current + 1))
            self._page_edit.blockSignals(False)

    def _on_field_clicked_in_view(self, fdef: SignatureFieldDef) -> None:
        """Synchronize list selection when a field is clicked in the PDF view."""
        # Wenn der Benutzer im Canvas auf ein Feld klickt, wird die entsprechende
        # Zeile in der rechten Feldliste ausgewählt (bidirektionale Synchronisation)
        n_sig    = len(self.sig_fields)
        n_locked = len(self.locked_fields)
        # Suche in sig_fields (Zeilen 1…N)
        for i, f in enumerate(self.sig_fields):
            if f is fdef:
                self._field_list.setCurrentRow(i + 1)
                return
        # Suche in locked_fields (Zeilen N+1…N+K)
        for i, f in enumerate(self.locked_fields):
            if f is fdef:
                self._field_list.setCurrentRow(n_sig + 1 + i)
                return
        # Suche in signed_fields (Zeilen N+K+1…Ende)
        for i, f in enumerate(self.signed_fields):
            if f is fdef:
                self._field_list.setCurrentRow(n_sig + n_locked + 1 + i)
                return

    def _on_field_added(self, fdef: SignatureFieldDef) -> None:
        # Feld wurde im Canvas gezeichnet → Feldliste aktualisieren und
        # das neue Feld als aktive Auswahl setzen
        self._update_field_list()
        self._field_list.setCurrentRow(self._field_list.count() - 1)
        # currentRowChanged fires above and calls _on_field_selection_changed
        self._set_status(
            t("status_field_added", name=fdef.name, page=fdef.page + 1))

    def _on_field_deleted(self, fdef: SignatureFieldDef) -> None:
        # Feld wurde per Tastatur oder Kontextmenü im Canvas gelöscht →
        # Feldliste aktualisieren und Status-Meldung anzeigen
        self._update_field_list()
        self._set_status(t("status_field_deleted", name=fdef.name))

    # ── PDF navigation ────────────────────────────────────────────────────

    def open_pdf(self) -> None:
        # Dateiauswahl-Dialog öffnen; Startverzeichnis aus letztem geöffneten Pfad
        start = self.config.get("paths", "last_open_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("dlg_open_pdf_title"), start, t("dlg_pdf_filter"))
        if path:
            self._open_pdf(path)

    def _open_pdf(self, path: str) -> None:
        try:
            # Pfad normalisieren (Symlinks auflösen, absolut machen)
            path = str(Path(path).resolve())
            doc = fitz.open(path)
            self.pdf_doc      = doc
            self.pdf_path     = path
            self.current_page = 0
            # Bestehende Signaturfelder klassifizieren und _working_bytes setzen
            self._load_existing_fields(doc)
            self._update_field_list()
            self._render_current_page()
            self.setWindowTitle(f"PDF QES Signer – {os.path.basename(path)}")
            self._set_status(t("status_opened", path=path, pages=len(doc)))
            # Letztes geöffnetes Verzeichnis speichern
            self.config.set("paths", "last_open_dir", str(Path(path).parent))
            self.config.save()
        except Exception as exc:
            QMessageBox.critical(
                self, t("dlg_open_error_title"),
                t("dlg_open_error_msg", error=str(exc)))

    def _load_existing_fields(self, doc: fitz.Document) -> None:
        """Scan all pages for existing signature widgets and classify them.

        Three categories are produced:
          sig_fields    – unsigned and outside any signed byte range
                          → free to edit, delete, or sign
          locked_fields – unsigned but within the signed byte range of at least
                          one signature; must not be modified
                          → can only be signed, not deleted or moved
          signed_fields – already signed (display only, rendered by fitz)

        For documents without any signatures, all unsigned widget annotations
        are removed from the in-memory fitz doc (so fitz does not render the
        raw "SIGN" placeholder) and stored only in sig_fields.

        For documents with existing signatures, pyhanko is used to determine
        which revision each unsigned field was introduced in.  Fields added
        *after* the most recent signature (outside its /ByteRange) go into
        sig_fields; fields present at signing time go into locked_fields.
        _working_bytes is set to the raw file bytes up to the end of the last
        signature's coverage so that post-signature incremental updates are
        excluded; workers re-embed sig_fields on top of this clean base.

        Page rotation (/Rotate entry): fitz always reports widget.rect in the
        native (unrotated) page coordinate system regardless of /Rotate.  The
        only correction needed is to flip Y using ``page.mediabox.height``
        (the native page height) rather than ``page.rect.height`` (the
        displayed height, which is swapped for 90°/270° rotations).
        """
        # Alle drei Kategorien zurücksetzen vor dem neuen Klassifizierungsdurchlauf
        self.sig_fields.clear()
        self.locked_fields.clear()
        self.signed_fields.clear()

        # First pass: collect all signature widgets
        # all_unsigned: Sammlung aller noch nicht signierten Widget-Felder mit ihrem xref.
        # Der xref wird benötigt, um das Widget später aus dem in-memory fitz-Dokument
        # zu entfernen (strip), damit fitz keine "SIGN"-Platzhalter rendert.
        all_unsigned: list[tuple[SignatureFieldDef, int]] = []  # (fdef, xref)
        for page_num in range(len(doc)):
            page   = doc[page_num]
            # mediabox.height: native Seitenhöhe unabhängig von der Rotation.
            # Wird für die Y-Achsen-Umrechnung (fitz: y-down → PDF: y-up) benötigt.
            mbox_h = page.mediabox.height
            for widget in list(page.widgets()):
                if widget.field_type != fitz.PDF_WIDGET_TYPE_SIGNATURE:
                    continue
                # fitz always reports widget.rect in the page's native (unrotated)
                # coordinate system, y-down, regardless of /Rotate.  We only need
                # to flip Y using the native page height (mediabox.height) to
                # obtain PDF native coords (y-up, bottom-left origin).
                # Y-Koordinaten von fitz (y-down, links oben) in PDF-Koordinaten
                # (y-up, links unten) umrechnen mittels nativer Seitenhöhe
                r  = widget.rect
                x1 = r.x0
                y1 = mbox_h - r.y1
                x2 = r.x1
                y2 = mbox_h - r.y0
                name = widget.field_name or f"Sig_p{page_num + 1}"
                # SignatureFieldDef mit Seitenrotation anlegen (für Rotations-Korrektur
                # beim Signieren auf rotierten Seiten, siehe signer.py)
                fdef = SignatureFieldDef(page_num, x1, y1, x2, y2, name,
                                        rotation=page.rotation)

                # Detect signed state: /V entry references a signature dict
                # Prüfen ob das Feld bereits signiert ist:
                # Ein signiertes Feld hat eine /V-Referenz auf ein Signaturobjekt
                # (Format: /V <objnum> <gennum> R)
                try:
                    obj = doc.xref_object(widget.xref, compressed=False)
                    already_signed = bool(re.search(r'/V\s+\d+\s+\d+\s+R', obj))
                except Exception:
                    already_signed = False

                if already_signed:
                    self.signed_fields.append(fdef)
                else:
                    all_unsigned.append((fdef, widget.xref))

        # Classify unsigned fields.
        # Fields added *after* the most recent signature are outside the signed
        # byte range and can be freely edited (→ sig_fields).  Only fields that
        # existed at the time of signing must be kept intact (→ locked_fields).
        has_signatures = bool(self.signed_fields)
        # unsigned_xrefs_to_strip: xrefs der Felder, die aus dem in-memory fitz-Doc
        # entfernt werden sollen (nur freie Felder, nicht locked_fields)
        unsigned_xrefs_to_strip: list[int] = []
        # signed_end: Byte-Offset bis zu dem die letzte Signatur abgedeckt ist.
        # _working_bytes wird auf diesen Bereich gekürzt damit post-signature
        # inkrementelle Updates ausgeschlossen werden.
        signed_end: int = 0  # byte offset where last signature's coverage ends

        if has_signatures:
            # Use pyhanko to separate pre-signature fields (locked) from
            # post-signature fields (still freely editable).
            # pyhanko-Reader öffnen um die Revisionen der Felder zu bestimmen:
            # Felder die vor der letzten Signatur existierten → locked_fields,
            # Felder die danach hinzugefügt wurden → sig_fields
            try:
                import io as _io
                from pyhanko.pdf_utils.reader import PdfFileReader as _PR
                from pyhanko.pdf_utils.generic import Reference as _Ref
                with open(self.pdf_path, "rb") as _f:
                    _raw = _f.read()
                _rdr = _PR(_io.BytesIO(_raw), strict=False)
                # Alle eingebetteten Signaturen und deren Revisionsnummern ermitteln
                _sigs = list(_rdr.embedded_regular_signatures)
                # Höchste Revisionsnummer = zuletzt hinzugefügte Signatur
                _max_rev = max(s.signed_revision for s in _sigs)
                # ByteRange der Signaturen auswerten, um das Ende der Abdeckung zu finden.
                # ByteRange = [offset1, len1, offset2, len2]; gesamte Abdeckung bis offset2+len2
                for _s in _sigs:
                    _br = [int(v) for v in _s.byte_range]
                    signed_end = max(signed_end, _br[2] + _br[3])
                for fdef, xref in all_unsigned:
                    try:
                        # Revision in der das Feld eingeführt wurde ermitteln
                        _intro = _rdr.xrefs.get_introducing_revision(_Ref(xref, 0))
                    except Exception:
                        _intro = 0
                    if _intro > _max_rev:
                        # Introduced after last signature → freely editable
                        # Feld wurde nach der letzten Signatur hinzugefügt → frei editierbar
                        self.sig_fields.append(fdef)
                        unsigned_xrefs_to_strip.append(xref)
                    else:
                        # Feld existierte zum Zeitpunkt der Signatur → gesperrt
                        self.locked_fields.append(fdef)
            except Exception:
                # Fehler bei der pyhanko-Analyse → konservativ: alle unsigned Felder
                # als gesperrt behandeln um bestehende Signaturen nicht zu brechen
                import traceback as _tb
                _tb.print_exc(file=sys.stderr)
                for fdef, _ in all_unsigned:
                    self.locked_fields.append(fdef)
        else:
            # Kein signiertes Feld vorhanden → alle unsigned Felder sind frei editierbar
            for fdef, xref in all_unsigned:
                self.sig_fields.append(fdef)
                unsigned_xrefs_to_strip.append(xref)

        # Strip free unsigned widgets from the in-memory fitz doc
        # Freie unsigned Felder aus dem in-memory fitz-Dokument entfernen.
        # Zweck: fitz soll keine "SIGN"-Platzhalter-Annotationen rendern;
        # die Python-Representationen bleiben in sig_fields erhalten.
        if unsigned_xrefs_to_strip:
            strip_set = set(unsigned_xrefs_to_strip)
            for page_num in range(len(doc)):
                page = doc[page_num]
                for widget in list(page.widgets()):
                    if widget.xref in strip_set:
                        page.delete_widget(widget)

        # Store working bytes.  When post-signature free fields were stripped,
        # use the raw file bytes truncated to the end of the last signature's
        # coverage so the post-signature incremental update is excluded.
        # Workers will re-embed sig_fields on top of this clean base.
        # _working_bytes setzen: bei vorhandenen Signaturen auf den Bereich
        # bis zum Ende der letzten Signaturabdeckung kürzen; sonst komplette Bytes.
        if signed_end > 0:
            self._working_bytes = _raw[:signed_end]  # type: ignore[name-defined]
        else:
            # Keine Signaturen → Bytes aus dem bereinigten fitz-Dokument exportieren
            # (garbage=0, deflate=False: keine Komprimierung, keine Bereinigung
            # damit bestehende Struktur erhalten bleibt)
            self._working_bytes = doc.tobytes(garbage=0, deflate=False)

    def prev_page(self) -> None:
        # Eine Seite zurückblättern (Minimum: Seite 0)
        if self.pdf_doc and self.current_page > 0:
            self.current_page -= 1
            if self._continuous_mode and self._page_y_offsets:
                self._scroll_area.verticalScrollBar().setValue(
                    self._page_y_offsets[self.current_page])
                self._page_edit.setText(str(self.current_page + 1))
            else:
                self._render_current_page()

    def next_page(self) -> None:
        # Eine Seite vorblättern (Maximum: letzte Seite)
        if self.pdf_doc and self.current_page < len(self.pdf_doc) - 1:
            self.current_page += 1
            if self._continuous_mode and self._page_y_offsets:
                self._scroll_area.verticalScrollBar().setValue(
                    self._page_y_offsets[self.current_page])
                self._page_edit.setText(str(self.current_page + 1))
            else:
                self._render_current_page()

    # ── Field management ──────────────────────────────────────────────────

    def delete_selected_field(self) -> None:
        row      = self._field_list.currentRow()
        n_sig    = len(self.sig_fields)
        n_locked = len(self.locked_fields)
        # Zeile 0 = "Unsichtbare Signatur" → keine Löschaktion möglich
        if row <= 0:
            QMessageBox.information(
                self, t("dlg_no_field_sel"), t("dlg_no_field_sel_msg"))
            return
        if n_sig + 1 <= row <= n_sig + n_locked:
            # Locked field – explain why it cannot be deleted
            # Gesperrtes Feld: dem Benutzer erklären warum es nicht gelöscht werden kann
            # (Kryptographischer Hash-Schutz durch bestehende Signatur)
            fdef = self.locked_fields[row - n_sig - 1]
            QMessageBox.information(
                self, t("dlg_locked_field_title"),
                t("dlg_locked_field_msg", name=fdef.name))
            return
        # Bereits signierte Felder ebenfalls nicht löschbar
        if row > n_sig:
            QMessageBox.information(
                self, t("dlg_no_field_sel"), t("dlg_no_field_sel_msg"))
            return
        # Freies unsigned Feld: Bestätigung einholen bevor gelöscht wird
        fdef = self.sig_fields[row - 1]
        if QMessageBox.question(
            self, t("dlg_delete_title"),
            t("dlg_delete_sel_msg", name=fdef.name),
        ) == QMessageBox.StandardButton.Yes:
            del self.sig_fields[row - 1]
            self._update_field_list()
            self._render_current_page()

    def save_with_fields(self) -> None:
        # Vorbedingungen prüfen: Dokument geladen, Felder vorhanden, pyhanko verfügbar
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

        # Vorschlag für den Ausgabedateinamen: Originalname + Suffix + ".pdf"
        pdf_dir = str(Path(self.pdf_path).parent)
        stem    = Path(self.pdf_path).stem
        default = str(Path(pdf_dir) / (stem + t("dlg_save_fields_suffix") + ".pdf"))
        out, _  = QFileDialog.getSaveFileName(
            self, t("dlg_save_fields_title"), default, t("dlg_pdf_filter"))
        if not out:
            return
        self._set_status(t("status_saving_fields"))
        # SaveFieldsWorker im Hintergrund-Thread starten; UI bleibt reaktionsfähig
        self._worker = SaveFieldsWorker(
            self._working_bytes, out, list(self.sig_fields))
        self._worker.finished.connect(self._on_save_done)
        self._worker.error.connect(self._on_save_error)
        self._worker.start()

    def _on_save_done(self, path: str) -> None:
        # Erfolgsmeldung in Statusleiste und Dialogfenster anzeigen
        self._set_status(t("status_saved", path=path))
        QMessageBox.information(
            self, t("dlg_save_success_title"),
            t("dlg_save_success_msg", path=path))

    def _on_save_error(self, msg: str) -> None:
        # Fehlermeldung in Statusleiste und Fehler-Dialog anzeigen
        self._set_status(t("status_save_failed"))
        QMessageBox.critical(
            self, t("dlg_save_error_title"),
            t("dlg_save_error_msg", error=msg))

    # ── Config dialogs ────────────────────────────────────────────────────

    def open_pkcs11_config(self) -> None:
        # PKCS#11-Konfigurationsdialog modal öffnen
        Pkcs11ConfigDialog(self, self.config).exec()
        # Sync TSA checkbox in case the user changed the URL in the dialog
        # TSA-Checkbox synchronisieren falls der Benutzer die URL im Dialog geändert hat
        self._tsa_chk.setChecked(self.config.getbool("tsa", "enabled"))
        # Refresh name placeholder in case cert_cn changed
        # Namen-Anzeige aktualisieren falls cert_cn im Dialog geändert wurde
        self._ap_panel.on_checks()

    def _on_tsa_toggled(self, enabled: bool) -> None:
        # TSA-Aktivierungszustand sofort in der Konfig speichern
        self.config.setbool("tsa", "enabled", enabled)
        self.config.save()

    # ── Signing ───────────────────────────────────────────────────────────

    def sign_document(self) -> None:
        # Vorbedingungen prüfen: Dokument geladen, pyhanko verfügbar
        if not self.pdf_doc:
            QMessageBox.warning(self, t("dlg_no_doc"), t("dlg_no_doc_msg"))
            return
        if not _pyhanko_available:
            QMessageBox.critical(
                self, t("dlg_sign_error_title"), t("dlg_pyhanko_missing"))
            return

        # Row 0 = invisible, 1…N = sig_fields, N+1…N+K = locked_fields, rest = signed
        # Feldlistenzeile in die entsprechende Feldkategorie übersetzen
        row      = self._field_list.currentRow()
        n_sig    = len(self.sig_fields)
        n_locked = len(self.locked_fields)
        fdef: Optional[SignatureFieldDef] = None
        # signed_offset: erste Zeile der signed_fields in der Liste
        signed_offset = 1 + n_sig + n_locked
        # Bereits signiertes Feld ausgewählt: Hinweis anzeigen
        if row >= signed_offset and self.signed_fields:
            QMessageBox.information(
                self, t("dlg_sign_error_title"),
                t("dlg_field_already_signed"))
            return
        # Ziel-Feld ermitteln: sig_fields oder locked_fields; None = unsichtbar
        if 1 <= row <= n_sig:
            fdef = self.sig_fields[row - 1]
        elif n_sig + 1 <= row <= n_sig + n_locked:
            fdef = self.locked_fields[row - n_sig - 1]

        # Vorschlag für Ausgabedateiname: Originalname + Signatur-Suffix + ".pdf"
        pdf_dir = str(Path(self.pdf_path).parent)
        stem    = Path(self.pdf_path).stem
        default = str(Path(pdf_dir) / (stem + t("dlg_save_signed_suffix") + ".pdf"))
        out, _  = QFileDialog.getSaveFileName(
            self, t("dlg_save_signed_title"), default, t("dlg_pdf_filter"))
        if not out:
            return

        # PIN, PKCS#11-Bibliothek, Schlüssel-ID und Zertifikats-CN aus der Konfig holen
        pin     = self._pin_edit.text().strip()
        lib     = self.config.get("pkcs11", "lib_path")
        key_id  = self.config.get("pkcs11", "key_id")
        cert_cn = self.config.get("pkcs11", "cert_cn")

        self._set_status(t("status_signing"))
        # TSA-URL nur übergeben wenn TSA in der Konfig aktiviert ist
        tsa_url = (self.config.get("tsa", "url")
                   if self.config.getbool("tsa", "enabled") else "")

        # Generate a unique name for invisible signatures
        # Für unsichtbare Signaturen: eindeutigen Feldnamen generieren
        # (Format: "Signature_N" wobei N die kleinste freie Nummer ist)
        if fdef is None:
            existing = ({f.name for f in self.sig_fields}
                        | {f.name for f in self.locked_fields}
                        | {f.name for f in self.signed_fields})
            n = 1
            while f"Signature_{n}" in existing:
                n += 1
            invis_name = f"Signature_{n}"
        else:
            invis_name = "Signature"

        # SignWorker im Hintergrund-Thread starten.
        # all_fields=list(self.sig_fields): alle freien Felder werden vor dem
        # Signieren eingebettet; locked_fields sind bereits in _working_bytes.
        self._sign_worker = SignWorker(
            self._working_bytes, out, fdef, lib, pin, key_id, cert_cn,
            self.appearance, all_fields=list(self.sig_fields), tsa_url=tsa_url,
            field_name=invis_name)
        # finished-Signal: signiertes PDF als neues Arbeitsdokument laden
        self._sign_worker.finished.connect(self._on_sign_done)
        self._sign_worker.error.connect(self._on_sign_error)
        self._sign_worker.start()

    def _on_sign_done(self, path: str) -> None:
        self._set_status(t("status_signed", path=path))
        QMessageBox.information(
            self, t("dlg_sign_success_title"),
            t("dlg_sign_success_msg", path=path))

        # Switch to the signed PDF as the new working document so that:
        # 1. The just-signed field is shown as already signed (grey/✓)
        # 2. Any further signing uses the signed PDF as base, preserving
        #    all previous signatures in the output chain.
        # Signiertes PDF als neues Arbeitsdokument laden:
        # - gerade signiertes Feld erscheint sofort mit ✓-Markierung
        # - weitere Signaturen bauen auf dem signierten PDF auf (Signaturkette)
        try:
            doc = fitz.open(path)
            self.pdf_doc  = doc
            self.pdf_path = path
            self.setWindowTitle(f"PDF QES Signer – {os.path.basename(path)}")
            self._load_existing_fields(doc)
            self._update_field_list()
            self._render_current_page()
        except Exception:
            pass  # Non-critical – UI stays in previous state

    def _on_sign_error(self, msg: str) -> None:
        # Fehlermeldung bei Signaturfehlern (z.B. falsche PIN, Token nicht vorhanden)
        self._set_status(t("status_sign_failed"))
        QMessageBox.critical(
            self, t("dlg_sign_error_title"),
            t("dlg_sign_error_msg", error=msg))

    def _show_about(self) -> None:
        # "Über"-Dialog mit Versionsnummer und Git-Commit-Hash anzeigen
        from . import __version__, __commit__
        QMessageBox.about(
            self, t("about_title"),
            t("about_msg", version=__version__, commit=__commit__))

    def _show_license(self) -> None:
        # Lizenzdialog mit scrollbarem Textfeld für den GPL-3.0-Lizenztext
        from PyQt6.QtWidgets import QDialog, QTextEdit, QPushButton, QVBoxLayout
        dlg = QDialog(self)
        dlg.setWindowTitle(t("license_title"))
        dlg.resize(600, 500)
        vl = QVBoxLayout(dlg)
        te = QTextEdit()
        te.setReadOnly(True)
        te.setFontFamily("monospace")
        te.setPlainText(t("license_msg"))
        vl.addWidget(te)
        btn = QPushButton(t("license_close"))
        btn.clicked.connect(dlg.accept)
        vl.addWidget(btn)
        dlg.exec()
