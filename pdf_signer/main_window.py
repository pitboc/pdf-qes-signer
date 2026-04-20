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

from PyQt6.QtCore import Qt, QPoint, QRectF, QTimer
from pdf_signer.icons import (
    svg_to_icon,
    ICON_CHEVRON_UP, ICON_CHEVRON_DOWN,
    ICON_SINGLE_PAGE, ICON_MULTI_PAGE,
    ICON_ZOOM_IN, ICON_ZOOM_OUT,
    ICON_PAGE_WIDTH, ICON_PAGE_HEIGHT,
    ICON_TEXT_MODE,
)
from PyQt6.QtGui import QAction, QColor, QFont, QKeySequence
from PyQt6.QtWidgets import (
    QApplication, QColorDialog, QComboBox, QDoubleSpinBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QMainWindow, QMessageBox, QPushButton, QScrollArea, QSizePolicy,
    QStackedWidget, QSplitter, QVBoxLayout, QWidget, QCheckBox,
)

from .config import AppConfig
from .appearance import SigAppearance
from .signer import (
    SaveFieldsWorker, SignWorker,
    _pyhanko_available, _pkcs11_available,
)
from .pdf_view import (PDFViewWidget, SignatureFieldDef, TextAnnotDef,
                       TextAnnotOverlay, FormFieldDef, SUPPORTED_FORM_TYPES)
from .dialogs import (Pkcs11ConfigDialog, ProfileManagerDialog,
                       ProfileSelectDialog, _pfx_load_cert_info,
                       DocMDPDialog)
from .i18n import t, i18n
from .appearance_panel import AppearancePanel
from .continuous_view import ContinuousView, _adjust_hscroll


# Display name → fitz short name for all 12 Base-14 text-annotation font variants
_TEXT_FONT_ITEMS: list[tuple[str, str]] = [
    ("Helvetica",              "helv"),
    ("Helvetica Bold",         "hebo"),
    ("Helvetica Oblique",      "heit"),
    ("Helvetica Bold Oblique", "hebi"),
    ("Times Roman",            "tiro"),
    ("Times Bold",             "tibo"),
    ("Times Italic",           "tiit"),
    ("Times Bold Italic",      "tibi"),
    ("Courier",                "cour"),
    ("Courier Bold",           "cobo"),
    ("Courier Oblique",        "coit"),
    ("Courier Bold Oblique",   "cobi"),
]
_TEXT_FONT_TO_SHORT: dict[str, str] = {d: s for d, s in _TEXT_FONT_ITEMS}
_TEXT_SHORT_TO_FONT: dict[str, str] = {s: d for d, s in _TEXT_FONT_ITEMS}


def _parse_da_string(da: str) -> tuple:
    """Parse a PDF /DA (Default Appearance) string into (font_name, font_size, color).

    Expected format (as written by pyMuPDF):  ``"R G B rg /FontAlias Size Tf"``
    Falls back to safe defaults when a token cannot be parsed.

    Returns:
        font_name  – internal PDF font alias  (``"helv"`` / ``"tiro"`` / ``"cour"``)
        font_size  – size in points           (float, minimum 6.0)
        color      – RGB tuple of floats 0–1  (default black)
    """
    # Mapping from pyMuPDF alias in DA (capitalized) to our internal names
    _alias_map = {"/Helv": "helv", "/TiRo": "tiro", "/Cour": "cour"}
    font_name = "helv"
    font_size = 10.0
    color     = (0.0, 0.0, 0.0)
    try:
        # Color: "R G B rg"
        m_color = re.search(
            r'([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+rg', da)
        if m_color:
            color = (float(m_color.group(1)),
                     float(m_color.group(2)),
                     float(m_color.group(3)))
        # Font + size: "/Alias size Tf"
        m_font = re.search(r'(/\w+)\s+([\d.]+)\s+Tf', da)
        if m_font:
            font_name = _alias_map.get(m_font.group(1), "helv")
            font_size = max(6.0, float(m_font.group(2)))
    except Exception:
        pass
    return font_name, font_size, color


class _PlaceStepper(QDoubleSpinBox):
    """QDoubleSpinBox that steps by the place value of the digit left of
    the cursor.

    Pressing ↑/↓ (or the spin arrows) increments / decrements the digit
    immediately to the left of the text cursor by 1.  Examples::

        "12.5|"  →  cursor after "5"  (tenths)  → step 0.1
        "12.|5"  →  cursor after "."             → fallback to singleStep
        "1|2.5"  →  cursor after "1"  (tens)     → step 10
        "12|.5"  →  cursor after "2"  (ones)     → step 1
    """

    def stepBy(self, steps: int) -> None:
        le  = self.lineEdit()
        pos = le.cursorPosition()
        txt = le.text()

        # Strip suffix so we work with the numeric part only
        sfx = self.suffix()
        if sfx and txt.endswith(sfx):
            txt = txt[: -len(sfx)]
        pos = min(pos, len(txt))

        # Only use positional stepping when a digit is directly left of cursor
        if pos == 0 or not txt[pos - 1].isdigit():
            super().stepBy(steps)
            return

        dec     = self.locale().decimalPoint()   # "." or "," depending on locale
        dec_idx = txt.find(dec)

        if dec_idx == -1:
            # No decimal separator – integer-only display
            place = 10 ** (len(txt) - pos)
        elif pos - 1 < dec_idx:
            # Digit is left of the decimal point
            place = 10 ** (dec_idx - pos)
        else:
            # Digit is right of the decimal point
            # First decimal digit (pos-1 == dec_idx+1) → n_after=1 → 10^-1=0.1
            n_after = (pos - 1) - dec_idx
            place   = 10.0 ** (-n_after)

        self.setValue(self.value() + steps * place)
        # Restore cursor (text length may have changed by ±1 character)
        le.setCursorPosition(min(pos, len(le.text()) - len(sfx)))


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
        # Text-Annotationen: editierbar bis zur ersten Signatur; beim Signieren eingebrannt
        self.text_annots:    list[TextAnnotDef]       = []
        # Formularfelder: aus bestehenden PDF-Widgets geladen; editierbar vor der Signatur
        self._form_fields:          list[FormFieldDef] = []
        self._form_fields_editable: bool               = False
        # Aktuell fokussierte Text-Overlay-Box (für Toolbar-Kopplung)
        self._focused_overlay: Optional[TextAnnotOverlay] = None
        # Ungespeicherte Änderungen: True wenn sig_fields oder text_annots verändert wurden
        self._has_unsaved_changes: bool = False
        # Schließen ausstehend (nach async Save abschließen)
        self._pending_close: bool = False
        # Worker-Referenzen halten damit GC sie nicht vorzeitig zerstört
        self._worker      = None
        self._sign_worker = None
        # Fortlaufende Ansicht: Modus-Flag; Widget wird in _build_ui erstellt
        self._continuous_mode: bool = False
        # Aktueller Zoom-Faktor (1.0 = 100 %, geteilt von Einzel- und Fortlaufend-Ansicht)
        self._zoom_factor: float = 1.5
        # Signaturprüfungs-Dialog (nicht-modal); None wenn geschlossen
        self._validation_dialog = None
        # Historisches fitz-Dokument für revisionsabhängige Anzeige; None = aktuelles Dokument
        self._historical_doc: Optional[fitz.Document] = None
        # Gecachtes Extraktionsergebnis (Phase 1); wird beim Öffnen befüllt
        self._doc_validation = None
        # Scrollbar-Startwerte für Middle-Drag-Panning (single-page mode)
        self._pan_hbar_start: int = 0
        self._pan_vbar_start: int = 0

        self._update_worker = None        # UpdateCheckWorker – Referenz halten damit GC nicht löscht
        self._update_found: str | None = None  # gefundene neue Version (Tag), oder None

        self._build_ui()
        self._apply_language()
        self.statusBar().showMessage(t("status_ready"))
        self._update_profile_label()
        # Fehlende Abhängigkeiten (pyhanko, python-pkcs11) beim Start prüfen
        self._check_dependencies()
        # Downgrade-Warnung (Konfigurationsdatei wurde von neuerer Version geschrieben)
        if self.config.downgrade_detected:
            self._warn_downgrade()
        # Optionaler Startup-Update-Check (nur wenn in Einstellungen aktiviert)
        if self.config.getbool("update", "check_on_startup"):
            self._start_update_check()

        # Optionale initiale PDF-Datei direkt öffnen (z.B. per Kommandozeilenargument)
        if initial_pdf:
            self._open_pdf(initial_pdf)

    @property
    def _active_doc(self) -> Optional[fitz.Document]:
        """Document currently shown: historical revision or the real document."""
        return self._historical_doc if self._historical_doc else self.pdf_doc

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

        self._menu_settings  = self.menuBar().addMenu("")
        self._act_settings = QAction(self)
        self._act_settings.setShortcut("Ctrl+,")
        self._act_settings.triggered.connect(self._open_settings)
        self._menu_settings.addAction(self._act_settings)

        self._menu_settings.addSeparator()

        # Profile action (single entry → combined manager dialog)
        self._act_profile = QAction(self)
        self._act_profile.triggered.connect(self._profile_manage)
        self._menu_settings.addAction(self._act_profile)

        # Profile label in status bar (permanent, right-aligned)
        self._profile_lbl = QPushButton()
        self._profile_lbl.setFlat(True)
        self._profile_lbl.setCursor(Qt.CursorShape.PointingHandCursor)
        self._profile_lbl.clicked.connect(self._profile_select)
        self.statusBar().addPermanentWidget(self._profile_lbl)

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
        self._tb_save_fields = QAction(self)
        self._tb_save_fields.triggered.connect(self.save_with_fields)
        tb.addAction(self._tb_save_fields)
        tb.addSeparator()
        # Seitennavigation: vorherige/nächste Seite
        self._tb_prev = QAction(self)
        self._tb_prev.setIcon(svg_to_icon(ICON_CHEVRON_UP))
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
        self._tb_next.setIcon(svg_to_icon(ICON_CHEVRON_DOWN))
        self._tb_next.triggered.connect(self.next_page)
        tb.addAction(self._tb_next)
        # Umschalter Einzelseite ↔ Fortlaufende Ansicht
        self._tb_view_toggle = QAction(self)
        self._tb_view_toggle.setIcon(svg_to_icon(ICON_MULTI_PAGE))
        self._tb_view_toggle.setCheckable(True)
        self._tb_view_toggle.setChecked(False)
        self._tb_view_toggle.setToolTip("Fortlaufende Seitenansicht")
        self._tb_view_toggle.triggered.connect(self._toggle_view_mode)
        tb.addAction(self._tb_view_toggle)
        tb.addSeparator()
        # Zoom-Steuerung: Verkleinern / Zoom-Eingabe / Vergrößern
        self._tb_zoom_out = QAction(self)
        self._tb_zoom_out.setIcon(svg_to_icon(ICON_ZOOM_OUT))
        self._tb_zoom_out.triggered.connect(self._on_zoom_out)
        tb.addAction(self._tb_zoom_out)
        self._zoom_edit = QLineEdit("150%")
        self._zoom_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._zoom_edit.setFixedWidth(52)
        self._zoom_edit.returnPressed.connect(self._on_zoom_enter)
        tb.addWidget(self._zoom_edit)
        self._tb_zoom_in = QAction(self)
        self._tb_zoom_in.setIcon(svg_to_icon(ICON_ZOOM_IN))
        self._tb_zoom_in.triggered.connect(self._on_zoom_in)
        tb.addAction(self._tb_zoom_in)
        self._tb_fit_width = QAction(self)
        self._tb_fit_width.setIcon(svg_to_icon(ICON_PAGE_WIDTH))
        self._tb_fit_width.triggered.connect(self._on_zoom_fit_width)
        tb.addAction(self._tb_fit_width)
        self._tb_fit_height = QAction(self)
        self._tb_fit_height.setIcon(svg_to_icon(ICON_PAGE_HEIGHT))
        self._tb_fit_height.triggered.connect(self._on_zoom_fit_height)
        tb.addAction(self._tb_fit_height)
        tb.addSeparator()
        # Textfeld-Modus: Toggle-Button öffnet zweite Toolbar
        self._tb_text_mode = QAction(self)
        self._tb_text_mode.setIcon(svg_to_icon(ICON_TEXT_MODE))
        self._tb_text_mode.setCheckable(True)
        self._tb_text_mode.setChecked(False)
        self._tb_text_mode.triggered.connect(self._toggle_text_mode)
        tb.addAction(self._tb_text_mode)
        tb.addSeparator()
        # Signieren und Felder speichern als Toolbar-Schnellzugriff
        self._tb_sign = QAction(self)
        self._tb_sign.triggered.connect(self.sign_document)
        tb.addAction(self._tb_sign)
        self._tb_check_sigs = QAction(self)
        self._tb_check_sigs.triggered.connect(self.check_signatures)
        tb.addAction(self._tb_check_sigs)

        # Zweite Toolbar: Textfeld-Steuerelemente (nur sichtbar im Textfeld-Modus)
        self._text_tb = self.addToolBar("text")
        self._text_tb.setMovable(False)
        self._text_tb.setVisible(False)
        # Font-Auswahl
        self._text_tb.addWidget(QLabel(" A "))
        self._tb2_font = QComboBox()
        self._tb2_font.addItems([d for d, _ in _TEXT_FONT_ITEMS])
        self._tb2_font.setFixedWidth(175)
        self._text_tb.addWidget(self._tb2_font)
        self._text_tb.addSeparator()
        # Schriftgröße
        self._text_tb.addWidget(QLabel(" A↕ "))
        self._tb2_font_size = _PlaceStepper()
        self._tb2_font_size.setRange(6.0, 72.0)
        self._tb2_font_size.setSingleStep(1.0)
        self._tb2_font_size.setDecimals(1)
        self._tb2_font_size.setValue(10.0)
        self._tb2_font_size.setSuffix(" pt")
        self._tb2_font_size.setFixedWidth(80)
        self._text_tb.addWidget(self._tb2_font_size)
        self._text_tb.addSeparator()
        # Zeichenabstand
        self._text_tb.addWidget(QLabel(" A↔ "))
        self._tb2_char_spacing = _PlaceStepper()
        self._tb2_char_spacing.setRange(0.0, 50.0)
        self._tb2_char_spacing.setSingleStep(0.1)
        self._tb2_char_spacing.setDecimals(2)
        self._tb2_char_spacing.setValue(0.0)
        self._tb2_char_spacing.setSuffix(" pt")
        self._tb2_char_spacing.setFixedWidth(85)
        self._text_tb.addWidget(self._tb2_char_spacing)
        self._text_tb.addSeparator()
        # Textfarbe
        self._tb2_color = QColor(0, 0, 0)
        self._tb2_color_btn = QPushButton()
        self._tb2_color_btn.setFixedSize(24, 24)
        self._tb2_color_btn.clicked.connect(self._pick_text_color)
        self._text_tb.addWidget(self._tb2_color_btn)
        self._update_text_color_btn()
        # Toolbar-Änderungen → auf fokussierte Box anwenden
        self._tb2_font.currentIndexChanged.connect(self._on_text_prop_changed)
        self._tb2_font_size.valueChanged.connect(self._on_text_prop_changed)
        self._tb2_char_spacing.valueChanged.connect(self._on_text_prop_changed)

        # Central widget: warning banner (hidden by default) + main splitter
        _central = QWidget()
        _central_layout = QVBoxLayout(_central)
        _central_layout.setContentsMargins(0, 0, 0, 0)
        _central_layout.setSpacing(0)

        self._warn_main_label = QLabel()
        self._warn_main_label.setContentsMargins(8, 4, 8, 4)
        self._warn_main_label.setWordWrap(True)
        self._warn_main_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        self._warn_main_label.hide()
        _central_layout.addWidget(self._warn_main_label)

        # Haupt-Splitter: PDF-Canvas links (größerer Anteil), Steuerbereich rechts
        splitter = QSplitter(Qt.Orientation.Horizontal)
        _central_layout.addWidget(splitter)
        self.setCentralWidget(_central)

        # Einzelseitenansicht: PDF-Canvas in ScrollArea (zoombar)
        # _outer_container ist das permanente ScrollArea-Widget (wird NIE ersetzt).
        # ID-Selektor (#name) kaskadiert nicht auf Kind-Widgets – verhindert,
        # dass QInputDialog-Dialoge den dunklen Hintergrund erben.
        self._scroll_area = QScrollArea()
        self._scroll_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll_area.setStyleSheet("QScrollArea { background: #404040; }")
        self._outer_container = QWidget()
        self._outer_container.setObjectName("pdfOuterContainer")
        self._outer_container.setStyleSheet(
            "#pdfOuterContainer { background: #404040; }")
        self._outer_layout = QVBoxLayout(self._outer_container)
        self._outer_layout.setContentsMargins(0, 0, 0, 0)
        self._outer_layout.setSpacing(0)
        self._outer_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self._pdf_view = PDFViewWidget(self.appearance)
        self._pdf_view.field_added.connect(self._on_field_added)
        self._pdf_view.field_deleted.connect(self._on_field_deleted)
        self._pdf_view.field_clicked.connect(self._on_field_clicked_in_view)
        self._pdf_view.field_moved.connect(self._on_field_moved)
        self._pdf_view.zoom_requested.connect(self._on_zoom_wheel)
        self._pdf_view.zoom_rect_requested.connect(self._on_zoom_rect_single)
        self._pdf_view.pan_started.connect(self._on_pan_started_single)
        self._pdf_view.pan_requested.connect(self._on_pan_single)
        self._pdf_view.hscroll_requested.connect(self._on_hscroll_single)
        self._pdf_view.text_annot_placed.connect(self._on_text_annot_placed)
        self._pdf_view.text_annot_deleted.connect(self._on_text_annot_deleted)
        self._pdf_view.exit_text_mode.connect(self._on_exit_text_mode)
        self._pdf_view.form_field_changed.connect(self._apply_form_field_edit)
        self._outer_layout.addWidget(self._pdf_view)
        self._scroll_area.setWidget(self._outer_container)
        self._scroll_area.setWidgetResizable(False)

        # Fortlaufende Ansicht: ContinuousView kapselt die gesamte Logik
        self._cv = ContinuousView()
        self._cv.page_changed.connect(self._on_cv_page_changed)
        self._cv.field_clicked.connect(self._on_field_clicked_in_view)
        self._cv.field_added.connect(self._on_field_added)
        self._cv.field_deleted.connect(self._on_field_deleted)
        self._cv.field_moved.connect(self._on_field_moved)
        self._cv.zoom_changed.connect(self._on_cv_zoom_changed)

        # QStackedWidget schaltet zwischen den beiden Ansichten um
        self._stacked = QStackedWidget()
        self._stacked.addWidget(self._scroll_area)  # Index 0: Einzelseite
        self._stacked.addWidget(self._cv)           # Index 1: Fortlaufend
        splitter.addWidget(self._stacked)

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
        # Auswahl-Änderung: Vorschau im Canvas aktualisieren.
        # currentRowChanged: bei Wechsel via Klick oder Tastatur.
        # itemClicked: auch bei erneutem Klick auf bereits selektierte Zeile.
        self._field_list.currentRowChanged.connect(self._on_field_selection_changed)
        self._field_list.itemClicked.connect(
            lambda _: self._on_field_selection_changed(self._field_list.currentRow()))
        fl.addWidget(self._field_list)
        btn_row = QHBoxLayout()
        # "Löschen"-Schaltfläche: nur für sig_fields-Felder aktiv; initial deaktiviert
        self._btn_delete = QPushButton()
        self._btn_delete.setEnabled(False)
        self._btn_delete.clicked.connect(self.delete_selected_field)
        btn_row.addWidget(self._btn_delete)
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
        # Qt-Übersetzer neu laden und UI neu beschriften
        i18n.lang = code
        self.config.set("app", "language", code)
        self.config.save()
        # Reload Qt's own translations (file dialogs, standard buttons, etc.)
        # so that native Qt widgets switch language at runtime too.
        from PyQt6.QtCore import QTranslator, QLibraryInfo
        app = QApplication.instance()
        if app is not None:
            if hasattr(self, "_qt_translator"):
                app.removeTranslator(self._qt_translator)
            self._qt_translator = QTranslator(app)
            _qt_lang = code if code else "de"
            _path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
            if self._qt_translator.load(f"qt_{_qt_lang}", _path):
                app.installTranslator(self._qt_translator)
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
        self._menu_settings.setTitle(t("menu_settings"))
        self._act_settings.setText(t("menu_settings_open"))
        self._act_profile.setText(t("menu_profile"))
        self._menu_help.setTitle(t("menu_help"))
        self._act_about.setText(t("menu_help_about"))
        self._act_license.setText(t("menu_help_license"))
        self._tb_open.setText(t("tb_open"))
        self._tb_prev.setToolTip(t("tb_prev"))
        self._tb_next.setToolTip(t("tb_next"))
        self._tb_sign.setText(t("tb_sign"))
        self._tb_check_sigs.setText(t("tb_check_sigs"))
        self._tb_save_fields.setText(t("tb_save_fields"))
        self._tb_zoom_out.setToolTip(t("tb_zoom_out"))
        self._tb_zoom_in.setToolTip(t("tb_zoom_in"))
        self._tb_fit_width.setToolTip(t("tb_fit_width"))
        self._tb_fit_height.setToolTip(t("tb_fit_height"))
        self._tb_text_mode.setToolTip(t("tb_text_mode"))
        self._tb2_font_size.setToolTip(t("tb2_font_size"))
        self._tb2_char_spacing.setToolTip(t("tb2_char_spacing"))
        self._tb2_color_btn.setToolTip(t("tb2_color"))
        self._fields_group.setTitle(t("panel_fields"))
        self._btn_delete.setText(t("btn_delete_field"))
        self._update_token_panel_for_mode()
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

        # Text-Modus sperren sobald das Dokument Signaturen enthält
        has_sigs = bool(self.signed_fields)
        self._tb_text_mode.setEnabled(not has_sigs)
        self._tb_text_mode.setToolTip(
            t("tb_text_mode_signed") if has_sigs else t("tb_text_mode"))
        if has_sigs and self._tb_text_mode.isChecked():
            self._tb_text_mode.setChecked(False)
            self._toggle_text_mode(False)

    def _check_dependencies(self) -> None:
        # Prüfen ob optionale Bibliotheken vorhanden sind;
        # bei fehlenden Paketen einen Warn-Dialog mit Installationshinweis zeigen.
        # python-pkcs11 wird nur im PKCS#11-Modus benötigt.
        missing = []
        if not _pyhanko_available:
            missing.append("pyhanko  (pip install pyhanko)")
        if (not _pkcs11_available
                and self.config.get("pkcs11", "signer_mode") != "pfx"):
            missing.append("python-pkcs11  (pip install python-pkcs11)")
        if missing:
            QMessageBox.warning(
                self, t("dlg_missing_deps"),
                t("dlg_missing_deps_msg",
                  packages="\n".join(f"  • {m}" for m in missing)))

    def _render_current_page(self) -> None:
        """Render the current page (single-page mode) or refresh overlays
        (continuous mode).  A full rebuild of the continuous view is triggered
        whenever the loaded document changed since the last open() call.

        Uses ``_active_doc`` so that the historical revision selected in the
        validation dialog is shown instead of the real document when applicable.
        In historical mode the signature field overlays are suppressed.
        """
        doc = self._active_doc
        if not doc:
            return
        historical = self._historical_doc is not None
        sig    = [] if historical else self.sig_fields
        locked = [] if historical else self.locked_fields
        signed = [] if historical else self.signed_fields
        if self._continuous_mode:
            if not self._cv.is_open_for(doc):
                self._cv._zoom = self._zoom_factor
                self._cv.open(doc, self.appearance, sig, locked, signed)
                self._cv.scroll_to_page(self.current_page)
            else:
                self._cv.update_fields(sig, locked, signed)
                if abs(self._cv._zoom - self._zoom_factor) > 0.001:
                    self._cv.set_zoom(self._zoom_factor)
            self._page_edit.setText(str(self.current_page + 1))
            self._page_total_lbl.setText(f"/ {len(doc)}")
            return
        self._pdf_view._zoom = self._zoom_factor
        page = doc[self.current_page]
        ff       = [] if historical else self._form_fields
        ff_edit  = (not historical) and self._form_fields_editable
        self._pdf_view.set_page(page, sig, self.current_page, locked, signed,
                                form_fields=ff, form_fields_editable=ff_edit)
        self._outer_container.adjustSize()
        self._page_edit.setText(str(self.current_page + 1))
        self._page_total_lbl.setText(f"/ {len(doc)}")

    # ── Zoom ──────────────────────────────────────────────────────────────

    def _set_zoom(self, new_zoom: float,
                  cursor_vp: "QPoint | None" = None) -> None:
        """Apply *new_zoom* to the active view.

        In continuous mode delegates to ``ContinuousView.set_zoom``.
        In single-page mode re-renders the current page and adjusts the
        scroll bars so that the content under *cursor_vp* (viewport
        coordinates) stays at the same screen position.
        """
        new_zoom = max(0.10, min(10.0, new_zoom))
        if abs(new_zoom - self._zoom_factor) < 0.001:
            return
        zoom_ratio       = new_zoom / self._zoom_factor
        self._zoom_factor = new_zoom
        self._zoom_edit.setText(f"{round(new_zoom * 100)}%")

        if self._continuous_mode:
            self._cv.set_zoom(new_zoom)   # ContinuousView handles its own centering
            return

        # ── Single-page mode ──────────────────────────────────────────────
        hbar = self._scroll_area.horizontalScrollBar()
        vbar = self._scroll_area.verticalScrollBar()
        vp   = self._scroll_area.viewport()

        if cursor_vp is not None:
            # Content coordinates under cursor before zoom.
            # cursor_vp.x() = centering_offset - hbar + wx  →  wx = hbar + cursor_vp - centering
            old_w  = self._pdf_view.width()
            old_h  = self._pdf_view.height()
            cx_old = max(0, (vp.width()  - old_w) // 2)
            cy_old = max(0, (vp.height() - old_h) // 2)
            wx = hbar.value() + cursor_vp.x() - cx_old
            wy = vbar.value() + cursor_vp.y() - cy_old

        self._render_current_page()

        if cursor_vp is not None:
            new_w  = self._pdf_view.width()
            new_h  = self._pdf_view.height()
            cx_new = max(0, (vp.width()  - new_w) // 2)
            cy_new = max(0, (vp.height() - new_h) // 2)
            hbar.setValue(int(wx * zoom_ratio + cx_new - cursor_vp.x()))
            vbar.setValue(int(wy * zoom_ratio + cy_new - cursor_vp.y()))

    def _on_zoom_wheel(self, delta: int, cursor_widget_pos) -> None:
        """Ctrl+wheel from single-page PDFViewWidget: zoom centred on cursor."""
        factor   = 1.1 if delta > 0 else 1.0 / 1.1
        new_zoom = max(0.10, min(10.0, self._zoom_factor * factor))
        cursor_vp = self._pdf_view.mapTo(
            self._scroll_area.viewport(),
            QPoint(int(cursor_widget_pos.x()), int(cursor_widget_pos.y())),
        )
        self._set_zoom(new_zoom, cursor_vp)

    def _on_zoom_rect_single(self, rect: QRectF) -> None:
        """Ctrl+drag rubber-band zoom in single-page mode."""
        if rect.width() < 1 or rect.height() < 1:
            return
        vp   = self._scroll_area.viewport()
        vp_w = vp.width()
        vp_h = vp.height()
        zoom_ratio   = min(vp_w / rect.width(), vp_h / rect.height())
        new_zoom     = max(0.10, min(10.0, self._zoom_factor * zoom_ratio))
        if abs(new_zoom - self._zoom_factor) < 0.001:
            return
        actual_ratio      = new_zoom / self._zoom_factor
        self._zoom_factor = new_zoom
        self._zoom_edit.setText(f"{round(new_zoom * 100)}%")
        cx = rect.center().x()   # rect centre in current widget coords
        cy = rect.center().y()
        self._render_current_page()
        new_w    = self._pdf_view.width()
        new_h    = self._pdf_view.height()
        cx_new   = max(0, (vp_w - new_w) // 2)
        cy_new   = max(0, (vp_h - new_h) // 2)
        hbar_max = max(0, new_w - vp_w)
        vbar_max = max(0, new_h - vp_h)
        hbar = self._scroll_area.horizontalScrollBar()
        vbar = self._scroll_area.verticalScrollBar()
        if hbar_max > 0:
            hbar.setRange(0, hbar_max)
        if vbar_max > 0:
            vbar.setRange(0, vbar_max)
        hbar.setValue(max(0, min(int(cx * actual_ratio + cx_new - vp_w / 2), hbar_max)))
        vbar.setValue(max(0, min(int(cy * actual_ratio + cy_new - vp_h / 2), vbar_max)))

    def _on_pan_started_single(self) -> None:
        """Capture scrollbar origin when middle-drag pan begins (single-page mode)."""
        self._pan_hbar_start = self._scroll_area.horizontalScrollBar().value()
        self._pan_vbar_start = self._scroll_area.verticalScrollBar().value()

    def _on_pan_single(self, dx: int, dy: int) -> None:
        """Middle-drag panning in single-page mode (dx/dy = total offset from pan start)."""
        self._scroll_area.horizontalScrollBar().setValue(self._pan_hbar_start - dx)
        self._scroll_area.verticalScrollBar().setValue(self._pan_vbar_start - dy)

    def _on_cv_zoom_changed(self, factor: float) -> None:
        """ContinuousView reports an internal zoom change (e.g. Ctrl+wheel)."""
        self._zoom_factor = factor
        self._zoom_edit.setText(f"{round(factor * 100)}%")

    def _on_hscroll_single(self, delta: int) -> None:
        """Shift+wheel from single-page PDFViewWidget: horizontal scroll."""
        hbar = self._scroll_area.horizontalScrollBar()
        step = max(20, hbar.singleStep()) * 3
        hbar.setValue(hbar.value() - delta * step // 120)

    def _on_zoom_in(self) -> None:
        self._set_zoom(self._zoom_factor * 1.25)

    def _on_zoom_out(self) -> None:
        self._set_zoom(self._zoom_factor / 1.25)

    def _on_zoom_enter(self) -> None:
        """Parse the zoom-level text field and apply the new zoom."""
        text = self._zoom_edit.text().strip().rstrip('%')
        try:
            pct = float(text)
            self._set_zoom(pct / 100.0)
        except ValueError:
            self._zoom_edit.setText(f"{round(self._zoom_factor * 100)}%")

    def _on_zoom_fit_width(self) -> None:
        """Zoom so die aktuelle Seite genau die Viewport-Breite ausfüllt."""
        if not self.pdf_doc:
            return
        page_w = self.pdf_doc[self.current_page].rect.width
        vp_w   = self._scroll_area.viewport().width()
        self._set_zoom(vp_w / page_w)
        if self._continuous_mode:
            hbar    = self._cv.horizontalScrollBar()
            cw      = self._cv.widget().width() if self._cv.widget() else 0
            vp_w_cv = self._cv.viewport().width()
            hbar.setValue(max(0, (cw - vp_w_cv) // 2))

    def _on_zoom_fit_height(self) -> None:
        """Zoom so die aktuelle Seite genau die Viewport-Höhe ausfüllt.

        Seitenoberkante und Seitenunterkante fallen mit Viewport-Top und
        Viewport-Bottom zusammen.  In der Einzelseitenansicht genügt vbar=0,
        da die Seite allein im Scroll-Bereich liegt.  In der fortlaufenden
        Ansicht wird zusätzlich zum Seitenanfang gescrollt.
        """
        if not self.pdf_doc:
            return
        page_h = self.pdf_doc[self.current_page].rect.height
        vp_h   = self._scroll_area.viewport().height()
        self._set_zoom(vp_h / page_h)
        # Scroll so Seitenanfang = Viewport-Top
        if self._continuous_mode:
            if self.current_page < len(self._cv._page_y_offsets):
                self._cv.verticalScrollBar().setValue(
                    self._cv._page_y_offsets[self.current_page])
        else:
            self._scroll_area.verticalScrollBar().setValue(0)

    # ── Field list selection ──────────────────────────────────────────────

    def _on_field_selection_changed(self, row: int) -> None:
        """Show appearance preview in the selected unsigned field (free or locked)."""
        n_sig    = len(self.sig_fields)
        n_locked = len(self.locked_fields)
        n_signed = len(self.signed_fields)
        # Löschen nur für freie unsigned Felder (sig_fields) erlauben
        self._btn_delete.setEnabled(1 <= row <= n_sig)
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
        if self._continuous_mode:
            self._cv.set_selected_field(fdef_preview)
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
        if self._continuous_mode:
            self.current_page = page
            self._cv.scroll_to_page(page)
            self._page_edit.setText(str(page + 1))
        elif page != self.current_page:
            self.current_page = page
            self._render_current_page()
        else:
            # Restore correct text if the entered value was out of range
            self._page_edit.setText(str(self.current_page + 1))

    def _scroll_to_field(self, fdef: SignatureFieldDef) -> None:
        """Ensure *fdef* is visible; scroll so it appears in the lower 80 % of
        the viewport.  In continuous mode delegates to ContinuousView.

        Single-page mode: the page top is clamped to the viewport top so that
        the page never appears to start below the visible area.
        """
        if self._continuous_mode:
            self._cv.scroll_to_field(fdef)
            return

        # Einzelseitenansicht
        vbar       = self._scroll_area.verticalScrollBar()
        viewport_h = self._scroll_area.viewport().height()
        page_changed = fdef.page != self.current_page
        if page_changed:
            self.current_page = fdef.page
            self._render_current_page()
        tl = self._pdf_view._pdf_to_w(fdef.x1, fdef.y2)
        br = self._pdf_view._pdf_to_w(fdef.x2, fdef.y1)
        field_top_y    = min(tl.y(), br.y())
        field_bottom_y = max(tl.y(), br.y())
        cur_scroll = vbar.value()
        if page_changed or cur_scroll > field_top_y or field_bottom_y > cur_scroll + viewport_h:
            target = int(field_bottom_y - viewport_h * 0.80)
            vbar.setValue(max(0, min(target, vbar.maximum())))

        hbar      = self._scroll_area.horizontalScrollBar()
        viewport_w = self._scroll_area.viewport().width()
        field_left  = self._pdf_view.x() + min(tl.x(), br.x())
        field_right = self._pdf_view.x() + max(tl.x(), br.x())
        _adjust_hscroll(hbar, viewport_w, field_left, field_right)

    # ── Continuous / single-page view toggle ──────────────────────────────

    @staticmethod
    def _apply_hscroll(src_hbar, src_cw: int,
                       dst_hbar, dst_cw: int, dst_vp_w: int) -> None:
        """Transfer the horizontal scroll position when switching view modes.

        Rules:
        - No scrollbar in source (src_cw <= viewport): centre destination.
          hbar_new = (dst_cw - dst_vp_w) / 2
        - Scrollbar in source: preserve offset from centre.
          hbar_new = (dst_cw - src_cw) / 2 + hbar_old
        Both results are clamped to [0, dst_cw - dst_vp_w].
        """
        dst_max = max(0, dst_cw - dst_vp_w)
        if dst_max > 0:
            dst_hbar.setRange(0, dst_max)
        if src_hbar.maximum() > 0:
            hval = (dst_cw - src_cw) // 2 + src_hbar.value()
        else:
            hval = dst_max // 2
        dst_hbar.setValue(max(0, min(hval, dst_max)))

    def _toggle_text_mode(self, checked: bool) -> None:
        """Show/hide the text-annotation toolbar and switch the canvas mode."""
        self._text_tb.setVisible(checked)
        self._pdf_view.text_mode = checked
        if not checked:
            # Deselect rule 2: text mode turned off.
            # Empty overlays are deleted silently; non-empty lose keyboard focus.
            for ov in list(self._pdf_view._text_overlays):
                if not ov.annot.text.strip():
                    self._pdf_view.delete_overlay_silent(ov)
                else:
                    ov._edit.clearFocus()
                    ov.set_selected(False)
            self._focused_overlay = None

    def _on_exit_text_mode(self) -> None:
        """Exit text mode via ESC key or right-click on the canvas."""
        self._tb_text_mode.setChecked(False)
        self._toggle_text_mode(False)

    def _on_text_annot_placed(self, page: int, x: float, y: float) -> None:
        """Create a TextAnnotDef from toolbar settings and add an overlay."""
        ann = TextAnnotDef(
            page=page,
            x=x,
            y=y,
            font_size=self._tb2_font_size.value(),
            font_name=_TEXT_FONT_TO_SHORT.get(self._tb2_font.currentText(), "helv"),
            color=(
                self._tb2_color.redF(),
                self._tb2_color.greenF(),
                self._tb2_color.blueF(),
            ),
            char_spacing=self._tb2_char_spacing.value(),
        )
        self.text_annots.append(ann)
        self._has_unsaved_changes = True
        ov = self._pdf_view.add_text_overlay(ann)
        # Connect BEFORE setFocus so the FocusIn event finds the signal wired up
        # and _focused_overlay is correctly assigned to this new overlay.
        ov.focused.connect(self._on_text_overlay_focused)
        ov._edit.setFocus()

    def _on_text_annot_deleted(self, ann: TextAnnotDef) -> None:
        """Remove *ann* from the list when its overlay is deleted by the user."""
        if ann in self.text_annots:
            self.text_annots.remove(ann)
            self._has_unsaved_changes = True
        if self._focused_overlay and self._focused_overlay.annot is ann:
            self._focused_overlay = None

    def _on_text_overlay_focused(self, ov: TextAnnotOverlay) -> None:
        """Update toolbar to reflect the settings of the focused overlay."""
        # Deselect rule 1: another box is focused.
        # Silently delete the previously focused overlay if it is empty.
        old = self._focused_overlay
        if old is not None and old is not ov:
            old.set_selected(False)
            if not old.annot.text.strip():
                self._pdf_view.delete_overlay_silent(old)

        self._focused_overlay = ov
        ov.set_selected(True)
        # Auto-enable text mode when an overlay receives focus so that
        # the toolbar is visible even if the user clicked without enabling it.
        if not self._tb_text_mode.isChecked():
            self._tb_text_mode.setChecked(True)
            self._text_tb.setVisible(True)
            self._pdf_view.text_mode = True
        ann = ov.annot
        # Block signals to avoid triggering _on_text_prop_changed while updating
        for w in (self._tb2_font, self._tb2_font_size, self._tb2_char_spacing):
            w.blockSignals(True)
        self._tb2_font.setCurrentText(_TEXT_SHORT_TO_FONT.get(ann.font_name, "Helvetica"))
        self._tb2_font_size.setValue(ann.font_size)
        self._tb2_char_spacing.setValue(ann.char_spacing)
        self._tb2_color = QColor(
            int(ann.color[0] * 255),
            int(ann.color[1] * 255),
            int(ann.color[2] * 255),
        )
        self._update_text_color_btn()
        for w in (self._tb2_font, self._tb2_font_size, self._tb2_char_spacing):
            w.blockSignals(False)

    def _on_text_prop_changed(self) -> None:
        """Apply current toolbar values to the focused overlay (if any).

        Prefers the overlay whose ``_is_focused`` flag is True (set by the
        FocusIn event filter) over the cached ``_focused_overlay`` reference.
        This handles the case where the toolbar widget took Qt focus from the
        overlay but the overlay is still the intended edit target.
        """
        # Primary: overlay that currently shows the active-focus border
        target = next(
            (ov for ov in self._pdf_view._text_overlays if ov._is_focused),
            self._focused_overlay,
        )
        if not target:
            return
        self._focused_overlay = target   # keep in sync
        ann = target.annot
        ann.font_name    = _TEXT_FONT_TO_SHORT.get(self._tb2_font.currentText(), "helv")
        ann.font_size    = self._tb2_font_size.value()
        ann.char_spacing = self._tb2_char_spacing.value()
        ann.color = (
            self._tb2_color.redF(),
            self._tb2_color.greenF(),
            self._tb2_color.blueF(),
        )
        target._apply_style()
        target._relayout()
        # Re-anchor: widget top = baseline_y - new_font_px, so the text
        # baseline stays at the original click position regardless of font size.
        self._pdf_view._position_overlay(target, update_style=False)

    def _pick_text_color(self) -> None:
        """Open color dialog and update text color button."""
        color = QColorDialog.getColor(self._tb2_color, self, t("tb2_color"))
        if color.isValid():
            self._tb2_color = color
            self._update_text_color_btn()
            self._on_text_prop_changed()  # apply to focused overlay

    def _update_text_color_btn(self) -> None:
        """Refresh the color swatch on the text-color button."""
        c = self._tb2_color
        self._tb2_color_btn.setStyleSheet(
            f"background-color: rgb({c.red()},{c.green()},{c.blue()});"
            " border: 1px solid #888;")

    def _toggle_view_mode(self) -> None:
        """Switch between single-page and continuous scroll view."""
        self._continuous_mode = self._tb_view_toggle.isChecked()
        if self._continuous_mode:
            # single-page → continuous
            sp_offset = self._scroll_area.verticalScrollBar().value()
            page      = self.current_page
            src_hbar  = self._scroll_area.horizontalScrollBar()
            src_cw    = self._scroll_area.widget().width() if self._scroll_area.widget() else 0
            self._tb_view_toggle.setIcon(svg_to_icon(ICON_SINGLE_PAGE))
            self._tb_view_toggle.setToolTip("Einzelseitenansicht")
            self._stacked.setCurrentIndex(1)
            if self.pdf_doc:
                self._render_current_page()
                dst_cw   = self._cv.widget().width() if self._cv.widget() else 0
                dst_vp_w = self._cv.viewport().width()
                self._apply_hscroll(src_hbar, src_cw,
                                    self._cv.horizontalScrollBar(),
                                    dst_cw, dst_vp_w)
                if page < len(self._cv._page_y_offsets):
                    target    = self._cv._page_y_offsets[page] + sp_offset
                    vbar      = self._cv.verticalScrollBar()
                    container = self._cv.widget()
                    vbar_max  = max(0, (container.height() if container else 0)
                                   - self._cv.viewport().height())
                    if vbar_max > 0:
                        vbar.setRange(0, vbar_max)
                    vbar.setValue(max(0, min(target, vbar_max)))
        else:
            # continuous → single-page
            top_vis, bot_vis = self._cv.page_edge_visibility(self.current_page)
            cv_vbar_val = self._cv.verticalScrollBar().value()
            page_top    = (self._cv._page_y_offsets[self.current_page]
                           if self.current_page < len(self._cv._page_y_offsets) else 0)
            src_hbar = self._cv.horizontalScrollBar()
            src_cw   = self._cv.widget().width() if self._cv.widget() else 0
            self._tb_view_toggle.setIcon(svg_to_icon(ICON_MULTI_PAGE))
            self._tb_view_toggle.setToolTip("Fortlaufende Seitenansicht")
            self._stacked.setCurrentIndex(0)
            self._render_current_page()
            dst_cw   = self._scroll_area.widget().width() if self._scroll_area.widget() else 0
            dst_vp_w = self._scroll_area.viewport().width()
            self._apply_hscroll(src_hbar, src_cw,
                                self._scroll_area.horizontalScrollBar(),
                                dst_cw, dst_vp_w)
            vbar      = self._scroll_area.verticalScrollBar()
            container = self._scroll_area.widget()
            vbar_max  = max(0, (container.height() if container else 0)
                           - self._scroll_area.viewport().height())
            if vbar_max > 0:
                vbar.setRange(0, vbar_max)
            if top_vis and bot_vis:
                # Whole page was visible → centre vertically
                vbar.setValue(max(0, vbar_max // 2))
            elif top_vis:
                # Only top visible → show page top
                vbar.setValue(0)
            elif bot_vis:
                # Only bottom visible → show page bottom
                vbar.setValue(vbar_max)
            else:
                # Page filled viewport entirely → transfer within-page offset
                offset = cv_vbar_val - page_top
                vbar.setValue(max(0, min(offset, vbar_max)))

    def _on_cv_page_changed(self, page: int) -> None:
        """Update toolbar page indicator when ContinuousView reports a scroll."""
        if self.current_page != page:
            self.current_page = page
            self._page_edit.blockSignals(True)
            self._page_edit.setText(str(page + 1))
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
        # docMDP P=1: Felder hinzufügen verboten → rückgängig machen
        if (self._doc_validation and self._doc_validation.docmdp_level == 1):
            try:
                self.sig_fields.remove(fdef)
            except ValueError:
                pass
            self._render_current_page()
            return
        # Feld wurde im Canvas gezeichnet → Feldliste aktualisieren und
        # das neue Feld als aktive Auswahl setzen.
        # Das neue Feld ist immer das letzte in sig_fields → Zeile len(sig_fields).
        # (Nicht count()-1, da locked/signed-Felder danach in der Liste stehen.)
        self._has_unsaved_changes = True
        self._update_field_list()
        self._field_list.setCurrentRow(len(self.sig_fields))
        # currentRowChanged fires above and calls _on_field_selection_changed
        self._set_status(
            t("status_field_added", name=fdef.name, page=fdef.page + 1))

    def _on_field_deleted(self, fdef: SignatureFieldDef) -> None:
        # Feld wurde per Tastatur oder Kontextmenü im Canvas gelöscht →
        # Feldliste aktualisieren und Status-Meldung anzeigen
        self._has_unsaved_changes = True
        self._update_field_list()
        self._set_status(t("status_field_deleted", name=fdef.name))

    def _on_field_moved(self, fdef: SignatureFieldDef) -> None:
        self._has_unsaved_changes = True

    # ── PDF navigation ────────────────────────────────────────────────────

    def open_pdf(self) -> None:
        if self._has_unsaved_changes:
            dlg = QMessageBox(self)
            dlg.setWindowTitle(t("dlg_unsaved_title"))
            dlg.setText(t("dlg_unsaved_open_msg"))
            dlg.setIcon(QMessageBox.Icon.Question)
            btn_cancel  = dlg.addButton(t("dlg_unsaved_cancel"),  QMessageBox.ButtonRole.RejectRole)
            btn_discard = dlg.addButton(t("dlg_unsaved_discard"), QMessageBox.ButtonRole.DestructiveRole)
            dlg.setDefaultButton(btn_cancel)
            dlg.exec()
            if dlg.clickedButton() is not btn_discard:
                return

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
            # Geladene Text-Annotationen als Overlays aufbauen (ohne Focus)
            for _ann in self.text_annots:
                _ov = self._pdf_view.add_text_overlay(_ann)
                _ov.focused.connect(self._on_text_overlay_focused)
            self._update_field_list()
            # Beim Öffnen immer das letzte unsigned freie Feld selektieren
            # (unabhängig von der Auswahl im vorherigen Dokument).
            # Priorität: sig_fields → locked_fields → Zeile 0 (unsichtbar)
            n_sig    = len(self.sig_fields)
            n_locked = len(self.locked_fields)
            if n_sig > 0:
                self._field_list.setCurrentRow(n_sig)          # letztes sig_field
            elif n_locked > 0:
                self._field_list.setCurrentRow(n_sig + n_locked)  # letztes locked_field
            else:
                self._field_list.setCurrentRow(0)              # unsichtbar / keine Felder
            self._has_unsaved_changes = False
            self._render_current_page()
            self.setWindowTitle(f"PDF QES Signer – {os.path.basename(path)}")
            self._set_status(t("status_opened", path=path, pages=len(doc)))
            # Phase-1-Extraktion für Warnbanner (kein Netzwerk, schnell)
            self._refresh_doc_validation()
            # Letztes geöffnetes Verzeichnis speichern
            self.config.set("paths", "last_open_dir", str(Path(path).parent))
            self.config.save()
            # Zoom auf Seitenbreite und zum ersten relevanten Feld springen.
            # Verzögert, damit Qt den Layout-Pass abschließt und
            # viewport().width() die finale Breite liefert.
            QTimer.singleShot(0, self._fit_and_jump_after_open)
        except Exception as exc:
            QMessageBox.critical(
                self, t("dlg_open_error_title"),
                t("dlg_open_error_msg", error=str(exc)))

    def _fit_and_jump_after_open(self) -> None:
        """Nach dem Öffnen eines PDFs: Zoom auf Seitenbreite setzen und
        zum aktuell selektierten Signaturfeld springen.

        Das selektierte Feld ergibt sich aus der aktuellen Zeile in
        _field_list (wird von _update_field_list gesetzt).  Zeile 0
        (unsichtbare Signatur) und leere Auswahl gelten als „kein Feld" –
        dann wird der Dokumentanfang angezeigt.
        """
        if not self.pdf_doc:
            return

        # Selektiertes Feld aus der Listenzeile ableiten (gleiche Abbildung
        # wie in _on_field_selection_changed)
        row      = self._field_list.currentRow()
        n_sig    = len(self.sig_fields)
        n_locked = len(self.locked_fields)
        if 1 <= row <= n_sig:
            target = self.sig_fields[row - 1]
        elif n_sig + 1 <= row <= n_sig + n_locked:
            target = self.locked_fields[row - n_sig - 1]
        elif n_sig + n_locked + 1 <= row:
            idx = row - n_sig - n_locked - 1
            target = self.signed_fields[idx] if idx < len(self.signed_fields) else None
        else:
            target = None   # Zeile 0 (unsichtbar) oder keine Auswahl

        target_page = target.page if target is not None else 0

        # In Einzelseitenansicht gleich auf Zielseite wechseln, damit
        # _set_zoom nur einmal rendert (statt erst Seite 0, dann Zielseite)
        if not self._continuous_mode:
            self.current_page = target_page

        # Zoom auf Breite der Zielseite anpassen
        page_w   = self.pdf_doc[target_page].rect.width
        vp_w     = self._scroll_area.viewport().width()
        new_zoom = max(0.10, min(10.0, vp_w / page_w))
        self._set_zoom(new_zoom)

        # Zum Zielfeld scrollen oder Dokumentanfang anzeigen
        if target is not None:
            self._scroll_to_field(target)
        elif self._continuous_mode:
            self._cv.verticalScrollBar().setValue(0)
        else:
            self._scroll_area.verticalScrollBar().setValue(0)

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
        self.text_annots.clear()
        self._form_fields.clear()
        self._pdf_view.clear_text_overlays()

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
                    # Exclude LTA doc-timestamps (/SubFilter /ETSI.RFC3161) –
                    # they are not user-visible signature fields.
                    try:
                        v_match = re.search(r'/V\s+(\d+)\s+\d+\s+R', obj)
                        if v_match:
                            v_obj = doc.xref_object(int(v_match.group(1)),
                                                    compressed=False)
                            if re.search(r'/SubFilter\s*/ETSI\.RFC3161', v_obj):
                                continue
                    except Exception:
                        pass
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

        # ── Schritt: eigene Text-Annotationen laden und aus fitz-Doc entfernen ───
        # FreeText-Annotationen mit /Subj "QESTextAnnot" werden als TextAnnotDef
        # rekonstruiert und aus dem in-memory fitz-Dokument entfernt, damit fitz
        # keine statischen Annotationen über den Overlays rendert.
        text_annots_stripped = False
        for _page_num in range(len(doc)):
            _page = doc[_page_num]
            for _annot in list(_page.annots(types=[fitz.PDF_ANNOT_FREE_TEXT])):
                if _annot.info.get("subject") != "QESTextAnnot":
                    continue
                _xref  = _annot.xref
                _bx    = doc.xref_get_key(_xref, "QESBaselineX")
                _by    = doc.xref_get_key(_xref, "QESBaselineY")
                _cs    = doc.xref_get_key(_xref, "QESCharSpacing")
                _da    = doc.xref_get_key(_xref, "DA")
                _fnk   = doc.xref_get_key(_xref, "QESFontName")
                _bx_v  = float(_bx[1])  if _bx[0]  in ("int", "float") else 0.0
                _by_v  = float(_by[1])  if _by[0]  in ("int", "float") else 0.0
                _cs_v  = float(_cs[1])  if _cs[0]  in ("int", "float") else 0.0
                _da_s  = _da[1]         if _da[0]  == "string"         else ""
                _fn, _fs, _col = _parse_da_string(_da_s)
                # /QESFontName zuverlässiger als /DA (pyMuPDF schreibt immer /Helv)
                if _fnk[0] == "string" and _fnk[1] in _TEXT_SHORT_TO_FONT:
                    _fn = _fnk[1]
                _text  = _annot.info.get("content", "")
                ann = TextAnnotDef(
                    page=_page_num, x=_bx_v, y=_by_v, text=_text,
                    font_size=_fs, font_name=_fn, color=_col, char_spacing=_cs_v,
                )
                self.text_annots.append(ann)
                _page.delete_annot(_annot)
                text_annots_stripped = True

        # Store working bytes.
        # For signed documents we use the full raw file bytes so that any
        # content added after the last signature (e.g. form values filled by
        # an external editor) is preserved in the new signing revision.
        # pyhanko's IncrementalPdfFileWriter picks up last_startxref from the
        # actual last %%EOF in the file, so the /Prev chain correctly includes
        # all revisions.  Duplicate sig_fields already present in the raw bytes
        # are silently ignored by pyhanko's append_signature_field.
        # _working_bytes setzen: vollständige Roh-Bytes damit externe
        # Post-Signatur-Inhalte (z.B. Okular-Formularwerte) erhalten bleiben.
        if signed_end > 0:
            if text_annots_stripped:
                # Text-Annotationen wurden aus doc entfernt → inkrementell speichern
                # damit _working_bytes unsere Annotationen nicht mehr enthält
                # und SaveFieldsWorker sie nicht doppelt einbettet.
                import io as _io2
                _out2 = _io2.BytesIO()
                doc.save(_out2, incremental=True, encryption=fitz.PDF_ENCRYPT_KEEP)
                self._working_bytes = _out2.getvalue()
            else:
                self._working_bytes = _raw  # type: ignore[name-defined]
        else:
            # Keine Signaturen → Bytes aus dem bereinigten fitz-Dokument exportieren
            # (garbage=0, deflate=False: keine Komprimierung, keine Bereinigung
            # damit bestehende Struktur erhalten bleibt)
            self._working_bytes = doc.tobytes(garbage=0, deflate=False)

        # ── Formularfelder scannen ────────────────────────────────────────
        # Formular-Widgets werden nicht aus dem fitz-Dokument entfernt –
        # fitz rendert deren aktuelle Appearance automatisch.
        has_unsupported = False
        for _page_num in range(len(doc)):
            _page  = doc[_page_num]
            _mbox_h = _page.mediabox.height
            for _widget in _page.widgets():
                _ft = _widget.field_type
                if _ft == fitz.PDF_WIDGET_TYPE_SIGNATURE:
                    continue
                if _ft not in SUPPORTED_FORM_TYPES:
                    has_unsupported = True
                    continue
                _r  = _widget.rect
                _x0 = _r.x0
                _y0 = _mbox_h - _r.y1   # fitz y-down → PDF y-up
                _x1 = _r.x1
                _y1 = _mbox_h - _r.y0
                _ff = FormFieldDef(
                    field_name=_widget.field_name or f"field_{_widget.xref}",
                    field_type=_ft,
                    page=_page_num,
                    rect=(_x0, _y0, _x1, _y1),
                    value=str(_widget.field_value or ""),
                    options=list(_widget.choice_values or []),
                    multiline=bool(_widget.field_flags & fitz.PDF_TX_FIELD_IS_MULTILINE),
                    xref=_widget.xref,
                    orig_fontsize=float(_widget.text_fontsize or 0.0),
                )
                self._form_fields.append(_ff)

        # Editierbar nur wenn kein signiertes/gesperrtes Feld vorhanden
        self._form_fields_editable = not bool(self.signed_fields or self.locked_fields)

        if has_unsupported and self._form_fields_editable:
            self.statusBar().showMessage(
                t("form_fields_hint_unsupported"), 8000)

    def _apply_form_field_edit(self, field_name: str, new_value: str) -> None:
        """Update a form field value in the live fitz document.

        Three encodings are used by the view:

        - Plain ``field_name``  → text / combobox / checkbox; ``new_value`` is
          the new string value.
        - ``"\\x01<field_name>\\x00<xref>"``  → radio button selection by xref;
          the matching widget is set to its on_state(), siblings to ``"Off"``.

        Updates the fitz widget, the ``_form_fields`` mirror, and schedules
        a page re-render.  Sets ``_has_unsaved_changes`` so the unsaved-changes
        guard triggers on the next open/close.
        """
        if not self.pdf_doc:
            return

        is_radio = field_name.startswith("\x01")
        if is_radio:
            # "\x01<name>\x00<xref>"
            rest = field_name[1:]
            actual_name, xref_str = rest.split("\x00", 1)
            target_xref = int(xref_str)
        else:
            actual_name = field_name
            target_xref = 0

        # For radio buttons: widget.update() sets /AS to on_state for ALL buttons
        # in the group (bug in fitz), regardless of field_value.  Strategy:
        # 1. Call update() on the target → generates proper appearance streams.
        # 2. Collect sibling xrefs; fix their /AS to /Off afterwards.
        # 3. Set /V as a PDF name (e.g. /Opt1) on target, siblings, and parent
        #    (if present).  fitz leaves /V as the string (Yes) which Firefox/
        #    PDF.js cannot match against the /AP/N keys → wrong display in FF.
        radio_sibling_xrefs: list[int] = []
        radio_on_state: str = ""
        for page_num in range(len(self.pdf_doc)):
            page = self.pdf_doc[page_num]
            for widget in page.widgets():
                if widget.field_name != actual_name:
                    continue
                if is_radio:
                    if widget.xref == target_xref:
                        radio_on_state = widget.on_state()
                        widget.field_value = radio_on_state
                        widget.update()
                    else:
                        radio_sibling_xrefs.append(widget.xref)
                else:
                    widget.field_value = new_value
                    # For multiline text: auto-shrink font to fit all lines,
                    # matching the burn-in appearance produced by _write_field_text.
                    if (widget.field_flags & fitz.PDF_TX_FIELD_IS_MULTILINE
                            and widget.field_type == fitz.PDF_WIDGET_TYPE_TEXT):
                        ff_orig = next(
                            (f for f in self._form_fields if f.xref == widget.xref),
                            None)
                        base_fs = (ff_orig.orig_fontsize if ff_orig else 0.0) or 0.0
                        if base_fs <= 0:
                            base_fs = min(widget.rect.height * 0.72, 12.0)
                        base_fs = max(4.0, base_fs)
                        lines = new_value.split("\n")
                        avail_h = widget.rect.height - 4
                        if len(lines) * base_fs * 1.2 > avail_h:
                            base_fs = max(4.0, avail_h / (len(lines) * 1.2))
                        widget.text_fontsize = base_fs
                    widget.update()

        # Fix sibling /AS values that widget.update() set to their on_state.
        for _xref in radio_sibling_xrefs:
            self.pdf_doc.xref_set_key(_xref, "AS", "/Off")

        # Fix /V on all widgets of the group and the parent field (if any).
        # Must be a PDF name like /Opt1, not the string (Yes) fitz writes.
        if is_radio and radio_on_state:
            v_val = f"/{radio_on_state}"
            self.pdf_doc.xref_set_key(target_xref, "V", v_val)
            for _xref in radio_sibling_xrefs:
                self.pdf_doc.xref_set_key(_xref, "V", v_val)
            _parent_m = re.search(
                r'/Parent\s+(\d+)\s+0\s+R',
                self.pdf_doc.xref_object(target_xref, compressed=False))
            if _parent_m:
                self.pdf_doc.xref_set_key(int(_parent_m.group(1)), "V", v_val)

        # Mirror update in _form_fields
        for ff in self._form_fields:
            if ff.field_name != actual_name:
                continue
            if is_radio:
                ff.value = ff.field_name if ff.xref == target_xref else "Off"
            else:
                ff.value = new_value

        self._has_unsaved_changes = True
        self._render_current_page()

    def prev_page(self) -> None:
        # Eine Seite zurückblättern (Minimum: Seite 0)
        doc = self._active_doc
        if doc and self.current_page > 0:
            self.current_page -= 1
            if self._continuous_mode:
                self._cv.scroll_to_page(self.current_page)
                self._page_edit.setText(str(self.current_page + 1))
            else:
                self._render_current_page()

    def next_page(self) -> None:
        # Eine Seite vorblättern (Maximum: letzte Seite)
        doc = self._active_doc
        if doc and self.current_page < len(doc) - 1:
            self.current_page += 1
            if self._continuous_mode:
                self._cv.scroll_to_page(self.current_page)
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
        # Vorbedingungen prüfen: Dokument geladen, etwas zum Speichern vorhanden
        if not self.pdf_doc:
            self._pending_close = False
            QMessageBox.warning(self, t("dlg_no_doc"), t("dlg_no_doc_msg"))
            return
        has_text       = bool([a for a in self.text_annots if a.text.strip()])
        has_form_edits = bool(self._form_fields and self._has_unsaved_changes)
        if not self.sig_fields and not has_text and not has_form_edits:
            self._pending_close = False
            QMessageBox.warning(self, t("dlg_no_fields"), t("dlg_no_fields_msg"))
            return
        # sig_fields benötigen pyhanko; text_annots allein brauchen es nicht
        if self.sig_fields and not _pyhanko_available:
            self._pending_close = False
            QMessageBox.critical(
                self, t("dlg_save_error_title"), t("dlg_pyhanko_missing"))
            return

        # Aktuelle pdf_doc-Bytes serialisieren – enthält Formularfeld-Änderungen
        # (Texte via widget.update(), Radio-Buttons via xref_set_key für /AS und
        # /V, die nicht in _working_bytes stehen).
        current_bytes = (self.pdf_doc.tobytes(garbage=0, deflate=False)
                         if has_form_edits else self._working_bytes)

        # Vorschlag für den Ausgabedateinamen: Originalname + Suffix + ".pdf"
        pdf_dir = str(Path(self.pdf_path).parent)
        stem    = Path(self.pdf_path).stem
        default = str(Path(pdf_dir) / (stem + t("dlg_save_fields_suffix") + ".pdf"))
        out, _  = QFileDialog.getSaveFileName(
            self, t("dlg_save_fields_title"), default, t("dlg_pdf_filter"))
        if not out:
            self._pending_close = False
            return
        self._set_status(t("status_saving_fields"))
        # SaveFieldsWorker im Hintergrund-Thread starten; UI bleibt reaktionsfähig
        self._worker = SaveFieldsWorker(
            current_bytes, out,
            list(self.sig_fields), list(self.text_annots))
        self._worker.finished.connect(self._on_save_done)
        self._worker.error.connect(self._on_save_error)
        self._worker.start()

    def _on_save_done(self, path: str) -> None:
        # Erfolgsmeldung in Statusleiste und Dialogfenster anzeigen
        self._has_unsaved_changes = False
        self._set_status(t("status_saved", path=path))
        QMessageBox.information(
            self, t("dlg_save_success_title"),
            t("dlg_save_success_msg", path=path))
        if self._pending_close:
            self._pending_close = False
            self.close()

    def _on_save_error(self, msg: str) -> None:
        # Fehlermeldung in Statusleiste und Fehler-Dialog anzeigen
        self._pending_close = False
        self._set_status(t("status_save_failed"))
        QMessageBox.critical(
            self, t("dlg_save_error_title"),
            t("dlg_save_error_msg", error=msg))

    def keyPressEvent(self, ev) -> None:  # type: ignore[override]
        if ev.key() == Qt.Key.Key_Escape and self._tb_text_mode.isChecked():
            self._on_exit_text_mode()
        else:
            super().keyPressEvent(ev)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        """Fragt bei ungespeicherten Änderungen nach: Abbrechen / Speichern / Beenden.

        "Speichern" wird angeboten wenn sig_fields oder nicht-leere text_annots
        vorhanden sind.  Für sig_fields wird zusätzlich pyhanko benötigt.
        """
        if not self._has_unsaved_changes:
            event.accept()
            return
        has_text = bool([a for a in self.text_annots if a.text.strip()])
        can_save = (has_text or bool(self.sig_fields)) and (
            not self.sig_fields or _pyhanko_available
        )
        dlg = QMessageBox(self)
        dlg.setWindowTitle(t("dlg_unsaved_title"))
        dlg.setText(t("dlg_unsaved_msg"))
        dlg.setIcon(QMessageBox.Icon.Question)
        btn_cancel = dlg.addButton(t("dlg_unsaved_cancel"), QMessageBox.ButtonRole.RejectRole)
        btn_save   = None
        if can_save:
            btn_save = dlg.addButton(t("dlg_unsaved_save"), QMessageBox.ButtonRole.AcceptRole)
        btn_quit   = dlg.addButton(t("dlg_unsaved_quit"),   QMessageBox.ButtonRole.DestructiveRole)
        dlg.setDefaultButton(btn_cancel)
        dlg.exec()
        clicked = dlg.clickedButton()
        if clicked is btn_quit:
            event.accept()
        elif btn_save is not None and clicked is btn_save:
            event.ignore()
            self._pending_close = True
            self.save_with_fields()
        else:
            event.ignore()

    # ── Config dialogs ────────────────────────────────────────────────────

    def open_pkcs11_config(self) -> None:
        # Signatur/Token-Konfigurationsdialog modal öffnen
        Pkcs11ConfigDialog(self, self.config).exec()
        # Sync TSA checkbox in case the user changed the URL in the dialog
        self._tsa_chk.setChecked(self.config.getbool("tsa", "enabled"))
        # Modus-abhängige Panel-Beschriftung und Appearance-Platzhalter aktualisieren
        self._update_token_panel_for_mode()
        self._ap_panel.on_checks()

    def _open_settings(self, initial_page: int = 0) -> None:
        """Open the consolidated settings dialog (Ctrl+,)."""
        from .settings_dialog import SettingsDialog
        dlg = SettingsDialog(self.config, parent=self,
                             initial_page=initial_page)
        dlg.language_changed.connect(
            lambda code: (self._set_language(code), dlg.retranslate()))
        dlg.exec()
        # Refresh main-window state that may have changed in settings
        self._tsa_chk.setChecked(self.config.getbool("tsa", "enabled"))
        self._update_token_panel_for_mode()
        self._ap_panel.on_checks()

    # ── Profile management ────────────────────────────────────────────────

    def _update_profile_label(self) -> None:
        self._profile_lbl.setText(
            f"  {t('status_profile')}: {self.config.active_profile}  ")

    def _apply_profile_to_ui(self) -> None:
        """Refresh all UI elements that depend on the active profile's settings."""
        self._tsa_chk.setChecked(self.config.getbool("tsa", "enabled"))
        self._ap_panel.reload_from_config()
        self._update_profile_label()
        self._update_token_panel_for_mode()
        if self.pdf_doc:
            self._render_current_page()

    def _update_token_panel_for_mode(self) -> None:
        """Set token/PIN panel title and labels based on the current signer_mode."""
        mode = self.config.get("pkcs11", "signer_mode")
        if mode == "pfx":
            self._token_group.setTitle(t("panel_token_pfx"))
            self._pin_lbl_widget.setText(t("pin_label_pfx"))
            self._pin_hint_lbl.setText(t("pin_hint_pfx"))
        else:
            self._token_group.setTitle(t("panel_token"))
            self._pin_lbl_widget.setText(t("pin_label"))
            self._pin_hint_lbl.setText(t("pin_hint"))

    def _profile_select(self) -> None:
        dlg = ProfileSelectDialog(self.config, self)
        if dlg.exec() and dlg.selected_profile:
            self.config.switch_profile(dlg.selected_profile)
            self.config.save()
            self._apply_profile_to_ui()

    def _profile_manage(self) -> None:
        dlg = ProfileManagerDialog(self.config, self)
        dlg.exec()
        if dlg.changes_made:
            self._apply_profile_to_ui()

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

        # Zertifikatsquelle prüfen – vor jedem weiteren Dialog
        _mode = self.config.get("pkcs11", "signer_mode")
        _cert_ok = (
            bool(self.config.get("pkcs11", "pfx_path").strip())
            if _mode == "pfx"
            else bool(self.config.get("pkcs11", "lib_path").strip())
        )
        if not _cert_ok:
            _msg_key = "dlg_no_cert_msg_pfx" if _mode == "pfx" else "dlg_no_cert_msg_pkcs11"
            _mb = QMessageBox(
                QMessageBox.Icon.Warning,
                t("dlg_no_cert_title"),
                t(_msg_key),
                parent=self,
            )
            _btn_settings = _mb.addButton(
                t("dlg_no_cert_open_settings"), QMessageBox.ButtonRole.ActionRole)
            _mb.addButton(t("dlg_unsaved_cancel"), QMessageBox.ButtonRole.RejectRole)
            _mb.exec()
            if _mb.clickedButton() is _btn_settings:
                from .settings_dialog import SettingsDialog
                self._open_settings(initial_page=SettingsDialog.PAGE_TOKEN)
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

        # Erste Signatur: docMDP-Einschränkung vom User abfragen
        docmdp = "none"
        if not self.signed_fields:
            dlg = DocMDPDialog(
                initial=self.config.get("signing", "docmdp"), parent=self)
            if dlg.exec() != DocMDPDialog.DialogCode.Accepted:
                return
            docmdp = dlg.docmdp
            self.config.set("signing", "docmdp", docmdp)
            self.config.save()

        # Signaturmodus und zugehörige Parameter aus der Konfig holen
        mode     = self.config.get("pkcs11", "signer_mode")
        pin      = self._pin_edit.text().strip()
        lib      = self.config.get("pkcs11", "lib_path")
        key_id   = self.config.get("pkcs11", "key_id")
        cert_cn  = self.config.get("pkcs11", "cert_cn")
        pfx_path = self.config.get("pkcs11", "pfx_path")

        # PFX-Modus: Passwort vor dem Start des Workers validieren.
        # Bei leerem Feld oder falschem Passwort wird das Popup wiederholt bis
        # das Passwort korrekt ist oder der User abbricht.
        # Datei-Fehler (nicht gefunden etc.) werden dem SignWorker überlassen.
        if mode == "pfx":
            from PyQt6.QtWidgets import QInputDialog, QLineEdit
            passphrase: bytes | None = pin.encode() if pin else None
            first = True
            while True:
                try:
                    _pfx_load_cert_info(pfx_path, passphrase)
                    pin = passphrase.decode() if passphrase else ""
                    break  # Passwort korrekt
                except Exception as exc:
                    err = str(exc).lower()
                    if "password" in err or "pkcs12" in err or "mac" in err:
                        prompt_key = ("cfg_pfx_password_prompt" if first
                                      else "cfg_pfx_wrong_password_prompt")
                        pw, ok = QInputDialog.getText(
                            self,
                            t("cfg_pfx_password_title"),
                            t(prompt_key),
                            QLineEdit.EchoMode.Password,
                        )
                        if not ok:
                            return
                        passphrase = pw.encode() if pw else b""
                        pin = pw
                        first = False
                    else:
                        break  # anderer Fehler – SignWorker meldet ihn

        self._set_status(t("status_signing"))
        # TSA-URL nur übergeben wenn TSA in der Konfig aktiviert ist
        tsa_on  = self.config.getbool("tsa", "enabled")
        tsa_url = self.config.get("tsa", "url") if tsa_on else ""
        # OCSP/LTA nur wenn TSA aktiv (use_pades_lta erfordert Timestamper)
        embed_vi = tsa_on and self.config.getbool("tsa", "embed_validation_info")

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
        chain_aia = self.config.getbool("signing", "chain_complete_via_aia")
        # Wenn Formularfelder vorhanden: aktuellen fitz-Doc-Stand exportieren
        # damit die bearbeiteten Widget-Werte in den Signing-Flow einfließen.
        _fitz_bytes = (self.pdf_doc.tobytes(garbage=0, deflate=False)
                       if self._form_fields and self.pdf_doc else None)
        self._sign_worker = SignWorker(
            self._working_bytes, out, fdef, lib, pin, key_id, cert_cn,
            self.appearance, all_fields=list(self.sig_fields), tsa_url=tsa_url,
            field_name=invis_name, mode=mode, pfx_path=pfx_path,
            embed_validation_info=embed_vi, docmdp=docmdp,
            chain_complete_via_aia=chain_aia,
            text_annots=list(self.text_annots),
            fitz_bytes=_fitz_bytes)
        # finished-Signal: signiertes PDF als neues Arbeitsdokument laden
        self._sign_worker.finished.connect(self._on_sign_done)
        self._sign_worker.error.connect(self._on_sign_error)
        self._sign_worker.warning.connect(self._on_sign_warning)
        self._sign_worker.root_fetch_needed.connect(self._on_root_fetch_needed)
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
            self._refresh_doc_validation()
            self._has_unsaved_changes = False
        except Exception:
            pass  # Non-critical – UI stays in previous state

    def _on_sign_error(self, msg: str) -> None:
        # Fehlermeldung bei Signaturfehlern; Text je nach Signaturmodus
        self._set_status(t("status_sign_failed"))
        mode = self.config.get("pkcs11", "signer_mode")
        err_key = "dlg_sign_error_msg_pfx" if mode == "pfx" else "dlg_sign_error_msg"
        QMessageBox.critical(
            self, t("dlg_sign_error_title"),
            t(err_key, error=msg))

    def _on_sign_warning(self, msg: str) -> None:
        # Hinweis: Signatur und Zeitstempel erfolgreich, aber OCSP-Einbettung fehlgeschlagen
        QMessageBox.warning(
            self, t("dlg_ocsp_warning_title"),
            t("dlg_ocsp_warning_msg", error=msg))

    def _on_root_fetch_needed(self, root_subject: str) -> None:
        """Zeigt Rückfrage ob Root-CA-Zertifikat via AIA nachgeladen werden soll.

        Wird vom SignWorker aus dem Worker-Thread via Qt-Signal (Queued Connection)
        aufgerufen.  Der Worker-Thread wartet auf allow_root_fetch()/deny_root_fetch().
        """
        mb = QMessageBox(self)
        mb.setWindowTitle(t("dlg_root_fetch_title"))
        mb.setText(t("dlg_root_fetch_msg", subject=root_subject))
        mb.setIcon(QMessageBox.Icon.Question)
        yes_btn = mb.addButton(t("btn_yes"), QMessageBox.ButtonRole.YesRole)
        no_btn  = mb.addButton(t("btn_no"),  QMessageBox.ButtonRole.NoRole)
        mb.setDefaultButton(yes_btn)
        mb.exec()
        if mb.clickedButton() == yes_btn:
            self._sign_worker.allow_root_fetch()
        else:
            self._sign_worker.deny_root_fetch()

    def _warn_downgrade(self) -> None:
        """Warnung anzeigen wenn settings.ini von einer neueren App-Version stammt."""
        from PyQt6.QtWidgets import QMessageBox
        backup = self.config.downgrade_backup_path
        backup_info = (f"\n\n{t('downgrade_backup')}: {backup}"
                       if backup else "")
        QMessageBox.warning(
            self,
            t("downgrade_title"),
            t("downgrade_msg") + backup_info,
        )

    def _start_update_check(self) -> None:
        """Startup-Update-Prüfung im Hintergrund starten.

        Bei verfügbarem Update erscheint automatisch der UpdateAvailableDialog.
        Wenn kein Update gefunden wird, passiert nichts (kein Hinweis).
        """
        from . import __version__
        from .updater import UpdateCheckWorker
        channel = self.config.get("update", "channel")
        self._update_worker = UpdateCheckWorker(__version__, channel=channel,
                                                parent=self)
        self._update_worker.update_available.connect(self._on_update_available)
        self._update_worker.start()

    def _on_update_available(self, tag: str, url: str, body: str) -> None:
        """Startup-Check hat Update gefunden – Dialog anzeigen."""
        self._update_found = tag
        self._show_update_available(tag, url, body)

    def _show_update_available(self, tag: str, url: str, body: str) -> None:
        """UpdateAvailableDialog öffnen (Startup-Check und manueller Check)."""
        from .dialogs import UpdateAvailableDialog
        channel = self.config.get("update", "channel")
        UpdateAvailableDialog(tag, url, body, channel=channel, parent=self).exec()

    def _show_about(self) -> None:
        """Über-Dialog mit Update-Suchen- und Update-Installieren-Button."""
        from PyQt6.QtWidgets import (QDialog, QLabel, QVBoxLayout,
                                      QHBoxLayout, QPushButton)
        from PyQt6.QtCore import Qt
        from . import __version__, __commit__

        dlg = QDialog(self)
        dlg.setWindowTitle(t("about_title"))
        dlg.setMinimumWidth(420)

        vl = QVBoxLayout(dlg)
        vl.setSpacing(12)

        commit_str = f"  (commit: {__commit__})" if __commit__ != "unknown" else ""
        lbl = QLabel(t("about_msg", version=__version__, commit=commit_str))
        lbl.setTextFormat(Qt.TextFormat.PlainText)
        lbl.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        vl.addWidget(lbl)

        # Status-Zeile für laufende Prüfung
        status_lbl = QLabel("")
        status_lbl.setTextFormat(Qt.TextFormat.PlainText)
        status_lbl.setWordWrap(True)
        vl.addWidget(status_lbl)

        hl = QHBoxLayout()
        hl.setSpacing(6)
        btn_check = QPushButton(t("about_check_update"))
        btn_close = QPushButton(t("dlg_token_close"))
        btn_close.clicked.connect(dlg.accept)
        hl.addWidget(btn_check)
        hl.addStretch()
        hl.addWidget(btn_close)
        vl.addLayout(hl)

        def _do_check():
            from .updater import check_for_update
            btn_check.setEnabled(False)
            status_lbl.setText(t("about_update_checking"))
            dlg.repaint()
            channel = self.config.get("update", "channel")
            result = check_for_update(__version__, channel=channel)
            if result is None:
                status_lbl.setText(t("about_update_current"))
            else:
                tag, url, body = result
                self._update_found = tag
                status_lbl.setText("")
                dlg.accept()
                self._show_update_available(tag, url, body)
            btn_check.setEnabled(True)

        btn_check.clicked.connect(_do_check)
        dlg.exec()

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

    def _set_modifying_actions_enabled(self, enabled: bool) -> None:
        """Enable or disable all actions that would modify or replace the PDF."""
        for act in (self._tb_sign,
                    self._act_save_fields, self._tb_save_fields,
                    self._act_open, self._tb_open,
                    self._tb_check_sigs):
            act.setEnabled(enabled)
        # Delete button: only active when enabled AND a free field is selected
        if enabled:
            row   = self._field_list.currentRow()
            n_sig = len(self.sig_fields)
            self._btn_delete.setEnabled(1 <= row <= n_sig)
        else:
            self._btn_delete.setEnabled(False)

    def _on_validation_revision_selected(self, revision_bytes: bytes) -> None:
        """Show the PDF as it looked at the selected revision."""
        if self._historical_doc:
            self._historical_doc.close()
            self._historical_doc = None
        try:
            self._historical_doc = fitz.open(stream=revision_bytes, filetype="pdf")
            self.current_page = min(self.current_page,
                                    max(0, len(self._historical_doc) - 1))
        except Exception:
            self._historical_doc = None
        self._render_current_page()

    def _on_validation_dialog_finished(self, _result: int = 0) -> None:
        """Restore normal view and re-enable actions when the dialog closes."""
        if self._historical_doc:
            self._historical_doc.close()
            self._historical_doc = None
        self._validation_dialog = None
        self._render_current_page()
        self._set_modifying_actions_enabled(True)
        # Re-apply docMDP restrictions if the document is locked
        self._update_main_warning()

    def _refresh_doc_validation(self) -> None:
        """Phase-1-Extraktion ausführen und Warnbanner aktualisieren.

        Liest von self.pdf_path (Disk), damit auch nach dem Signieren der
        aktuelle Dateistand berücksichtigt wird.  Bei Fehler wird
        _doc_validation auf None gesetzt und das Banner versteckt.
        """
        self._doc_validation = None
        self._warn_main_label.hide()
        if not self.pdf_path:
            return
        try:
            from .validation_extractor import extract
            with open(self.pdf_path, "rb") as fh:
                full_bytes = fh.read()
            self._doc_validation = extract(full_bytes)
            self._update_main_warning()
        except Exception:
            pass

    def _set_doc_edit_enabled(self, enabled: bool) -> None:
        """Enable/disable sign and field-editing actions (open/check_sigs unaffected).

        Also propagates to the field-drawing views so that no drag/name-dialog
        can be started when *enabled* is False.
        """
        for act in (self._tb_sign,
                    self._act_save_fields, self._tb_save_fields):
            act.setEnabled(enabled)
        if enabled:
            row   = self._field_list.currentRow()
            n_sig = len(self.sig_fields)
            self._btn_delete.setEnabled(1 <= row <= n_sig)
        else:
            self._btn_delete.setEnabled(False)
        self._pdf_view.drawing_enabled = enabled
        self._cv.drawing_enabled       = enabled

    def _update_main_warning(self) -> None:
        """Warnbanner im Hauptfenster ein- oder ausblenden; docMDP-Sperre anwenden.

        docMDP P=1: alle Änderungs-Aktionen deaktivieren, Banner zeigen (rot).
        Alle anderen Warnungen werden gesammelt und zusammen angezeigt.
        Farbe: Rot wenn mindestens eine rote Warnung vorliegt, sonst Gelb.
        """
        _STYLE_RED    = ("background-color: #f8d7da; color: #721c24;"
                         " border-bottom: 1px solid #f5c6cb;")
        _STYLE_YELLOW = ("background-color: #fff3cd; color: #6a4200;"
                         " border-bottom: 1px solid #e0a800;")

        if self._doc_validation is None:
            self._warn_main_label.hide()
            self._set_doc_edit_enabled(True)
            return

        level = self._doc_validation.docmdp_level

        if level == 1:
            # P=1: vollständige Sperre – keine Signatur, kein Feld-Zeichnen, kein Speichern
            self._warn_main_label.setStyleSheet(_STYLE_RED)
            self._warn_main_label.setText(t("warn_docmdp_p1"))
            line_h = self._warn_main_label.fontMetrics().height()
            self._warn_main_label.setMaximumHeight(line_h + 10)
            self._warn_main_label.show()
            self._set_doc_edit_enabled(False)
            return

        # P=2 oder keine MDP-Einschränkung: Aktionen freigeben
        self._set_doc_edit_enabled(True)

        warnings: list[tuple[str, str]] = []  # (severity, text)  severity: "red"|"yellow"

        # 1. Kryptografische Integritätsfehler (Manipulation oder Dateidefekt)
        from .validation_result import ValidationStatus
        broken = [rev.signed_by for rev in self._doc_validation.revisions
                  if rev.signed_by is not None
                  and rev.signed_by.crypto_status == ValidationStatus.INVALID]
        if broken:
            warnings.append(("red", t("warn_crypto_invalid_short", count=len(broken))))

        # 2. Verdächtige unsignierte Revisionen nach/zwischen Signaturen
        from .validation_dialog import check_post_sig_warnings
        post_last, between = check_post_sig_warnings(self._doc_validation.revisions)
        if post_last:
            labels = ", ".join(t(f"val_rev_type_{ct}") for ct in sorted(post_last))
            warnings.append(("yellow", t("val_warn_post_sig_short", types=labels)))
        if between:
            labels = ", ".join(t(f"val_rev_type_{ct}") for ct in sorted(between))
            warnings.append(("yellow", t("val_warn_between_sig_short", types=labels)))

        if not warnings:
            self._warn_main_label.hide()
            return

        has_red = any(sev == "red" for sev, _ in warnings)
        self._warn_main_label.setStyleSheet(_STYLE_RED if has_red else _STYLE_YELLOW)
        self._warn_main_label.setText("\n".join(msg for _, msg in warnings))
        # Fix height to content: one font line per warning + vertical margins.
        line_h = self._warn_main_label.fontMetrics().height()
        self._warn_main_label.setMaximumHeight(len(warnings) * line_h + 10)
        self._warn_main_label.show()

    def check_signatures(self) -> None:
        """Signaturprüfungs-Dialog öffnen (nicht-modal, Phase 1 offline).

        Öffnet das Dokument auch wenn keine Signaturen vorhanden sind; in
        diesem Fall wird "Alle Revisionen anzeigen" automatisch aktiviert.
        Alle PDF-verändernden Aktionen werden für die Dauer des Dialogs gesperrt.
        """
        if not self.pdf_path:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, t("val_dlg_title"), t("val_no_pdf"))
            return

        # Use full file bytes (not _working_bytes which may be trimmed to the
        # last regular signature and exclude later LTA timestamp revisions).
        try:
            with open(self.pdf_path, "rb") as fh:
                full_bytes = fh.read()
        except Exception as exc:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(self, t("val_dlg_title"), str(exc))
            return

        from .validation_dialog import ValidationDialog
        # Gecachtes Ergebnis nutzen wenn vorhanden, sonst neu extrahieren
        if self._doc_validation is None:
            from .validation_extractor import extract
            self._doc_validation = extract(full_bytes)
        doc = self._doc_validation

        has_signatures = any(r.signed_by for r in doc.revisions)
        has_warning = self._warn_main_label.isVisible()

        self._validation_dialog = ValidationDialog(
            self, doc, full_bytes,
            show_all_initially=not has_signatures or has_warning,
            config=self.config,
        )
        self._validation_dialog.revision_selected.connect(
            self._on_validation_revision_selected)
        self._validation_dialog.finished.connect(
            self._on_validation_dialog_finished)
        self._set_modifying_actions_enabled(False)
        self._validation_dialog.show()

    def open_trust_cache_dialog(self) -> None:
        """Vertrauensspeicher-Cache-Dialog öffnen (modal)."""
        from .dialogs import TrustStoreCacheDialog
        dlg = TrustStoreCacheDialog(parent=self)
        dlg.exec()
