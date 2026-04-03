# SPDX-License-Identifier: GPL-3.0-or-later
"""Dialog for displaying PDF signature validation results.

Shows a tree of PDF revisions (newest first).  Each revision with a signature
has an expandable row with three detail lines: date, integrity, and PAdES
profile.  Revisions without a signature are shown only when the user enables
the "show all revisions" checkbox.

## Tree structure

    ▼ Rev 3 / 3   Signatur · Erika Musterfrau          ← top-level, 2 cols
          Datum        10.01.2024 14:32  (TSA-bestätigt)
          Integrität   ✓ Unverändert
          Profil       PAdES-LTA  (TSA-Token ✓, DSS ✓, LTA-Zeitstempel ✓)
                       Alle Validierungsdaten eingebettet und kryptographisch gesichert

    ▼ Rev 2 / 3   Dokumentzeitstempel · BalTstamp TSU1
          Datum        15.01.2024 09:00
          Integrität   ✓ Unverändert
          Profil       –  (ist selbst der Dokumentzeitstempel)

      Rev 1 / 3   –  (keine Signatur)                  ← only with "show all"

Column 0 carries the Rev label (top-level) or a grey detail label (sub-item).
Column 1 carries the type·name summary (top-level) or the detail value.
The column header is hidden; column 0 auto-sizes, column 1 stretches.

Integrity failure turns the top-level row red.
Double-click on a signed revision is reserved for the future detail window.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QHBoxLayout,
    QLabel, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)

from .i18n import t
from .validation_result import DocumentValidation, PadesProfile, RevisionInfo, SignatureInfo, ValidationStatus


_RED    = "#9a0000"
_GREEN  = "#1a7a1a"
_GREY   = "#666666"
_WARN_BG = "#fff3cd"   # amber background for warning banner
_WARN_FG = "#6a4200"   # dark brown text
_WARN_BD = "#e0a800"   # amber border

# Change types that are suspicious after a signature (not benign infrastructure)
_SUSPICIOUS_TYPES = {"form_fields", "annotations", "unknown"}


def _bold() -> QFont:
    f = QFont()
    f.setBold(True)
    return f


def _fmt_dt(dt: Optional[datetime]) -> str:
    if dt is None:
        return "–"
    return dt.strftime("%d.%m.%Y %H:%M")


def _parse_dn(dn: str) -> dict[str, str]:
    """Parse an asn1crypto human-friendly DN string into a field dict."""
    sep = ";" if ";" in dn else ","
    result: dict[str, str] = {}
    for part in dn.split(sep):
        part = part.strip()
        colon = part.find(":")
        if colon > 0:
            result[part[:colon].strip()] = part[colon + 1:].strip()
    return result


def _extract_cn(subject: str) -> str:
    """Return the CN value from a human-friendly subject DN string."""
    fields = _parse_dn(subject)
    cn = fields.get("Common Name") or fields.get("CN")
    if cn:
        return cn
    return subject.split(",")[0].strip()


def _auth_time(sig: SignatureInfo) -> Optional[datetime]:
    """Return the authoritative signing time (TSA-confirmed if available)."""
    if sig.timestamp:
        return sig.timestamp.time
    return sig.signing_time


def _date_text(sig: SignatureInfo) -> str:
    """Format the signing date with source qualifier."""
    auth = _auth_time(sig)
    time_str = _fmt_dt(auth)
    if sig.sig_type == "doc_timestamp":
        return t("val_date_doc_ts", time=time_str)
    if sig.timestamp:
        return t("val_date_tsa", time=time_str)
    return t("val_date_self", time=time_str)


def _profile_text(sig: SignatureInfo) -> tuple[str, str]:
    """Return (profile_label, meaning_text) for the Profil detail line.

    For document timestamps returns a special label and empty meaning.
    """
    if sig.sig_type == "doc_timestamp":
        return t("val_profile_is_doc_ts"), ""
    profile = sig.pades_profile
    key = profile.value  # "B", "T", "LT", "LTA"
    label = f"PAdES-{key}  ({t('val_profile_details_' + key)})"
    meaning = t("val_profile_meaning_" + key)
    return label, meaning


# ── ValidationDialog ──────────────────────────────────────────────────────────

class ValidationDialog(QDialog):
    """Non-modal dialog showing PDF signature objects (offline, Phase 1).

    Tree of revisions (newest first) with expandable detail lines per
    signed revision.  An optional checkbox reveals unsigned revisions.
    No network access is performed.

    Signals:
        revision_selected(bytes): emitted when the user clicks a revision;
            carries the PDF bytes sliced up to and including that revision.
    """

    revision_selected = pyqtSignal(bytes)

    def __init__(self, parent,
                 doc: DocumentValidation,
                 pdf_bytes: bytes,
                 auto_fetch: bool = False,
                 show_all_initially: bool = False) -> None:
        super().__init__(parent)
        self._doc = doc
        self._pdf_bytes = pdf_bytes
        self._show_all = show_all_initially

        self.setWindowTitle(t("val_dlg_title"))
        self.setMinimumSize(680, 320)
        self.resize(860, 460)

        self._setup_ui()
        self._build_tree()

    # ── UI ────────────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        # Warning banner – shown only when suspicious post-signature changes are detected
        self._warn_label = QLabel()
        self._warn_label.setWordWrap(True)
        self._warn_label.setContentsMargins(8, 6, 8, 6)
        self._warn_label.setStyleSheet(
            f"background-color: {_WARN_BG}; color: {_WARN_FG};"
            f" border: 1px solid {_WARN_BD}; border-radius: 4px;"
        )
        self._warn_label.hide()
        layout.addWidget(self._warn_label)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(2)
        self._tree.header().hide()
        self._tree.setAlternatingRowColors(True)
        self._tree.setSelectionMode(QTreeWidget.SelectionMode.SingleSelection)
        self._tree.header().setStretchLastSection(True)
        self._tree.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._tree)

        bottom = QHBoxLayout()
        self._show_all_cb = QCheckBox(t("val_show_all_revisions"))
        self._show_all_cb.setChecked(self._show_all)
        self._show_all_cb.toggled.connect(self._on_show_all_toggled)
        bottom.addWidget(self._show_all_cb)
        bottom.addStretch()
        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn_box.rejected.connect(self.reject)
        bottom.addWidget(btn_box)
        layout.addLayout(bottom)

    # ── Slots ─────────────────────────────────────────────────────────────

    def _on_show_all_toggled(self, checked: bool) -> None:
        self._show_all = checked
        self._build_tree()

    # ── Tree ──────────────────────────────────────────────────────────────

    def _build_tree(self) -> None:
        self._tree.clear()
        self._update_warning()

        revisions = self._doc.revisions
        if not self._show_all:
            revisions = [r for r in revisions if r.signed_by is not None]

        if not revisions:
            item = QTreeWidgetItem(self._tree)
            item.setText(0, t("val_no_sigs"))
            return

        for rev in reversed(revisions):
            self._build_rev_item(rev)

        self._tree.resizeColumnToContents(0)

    def _update_warning(self) -> None:
        """Show or hide the post-signature modification warning banner."""
        suspicious = self._suspicious_post_sig_types()
        if not suspicious:
            self._warn_label.hide()
            return
        type_labels = [t(f"val_rev_type_{ct}") for ct in sorted(suspicious)]
        body = t("val_warn_post_sig_body", types=", ".join(type_labels))
        title = t("val_warn_post_sig_title")
        self._warn_label.setText(f"⚠  <b>{title}</b><br>{body}")
        self._warn_label.show()

    def _suspicious_post_sig_types(self) -> set:
        """Return the set of suspicious change types that appear after the last signature."""
        revisions = self._doc.revisions  # oldest-first
        # Find index of last signed revision
        last_sig_idx = -1
        for i, rev in enumerate(revisions):
            if rev.signed_by is not None:
                last_sig_idx = i
        if last_sig_idx == -1:
            return set()
        found: set = set()
        for rev in revisions[last_sig_idx + 1:]:
            for ct in rev.change_types:
                if ct in _SUSPICIOUS_TYPES:
                    found.add(ct)
        return found

    def _on_selection_changed(self) -> None:
        """Emit revision_selected with the PDF bytes sliced at the selected revision."""
        items = self._tree.selectedItems()
        if not items:
            return
        item = items[0]
        # Sub-items have no UserRole – walk up to the top-level item
        rev_num = item.data(0, Qt.ItemDataRole.UserRole)
        if rev_num is None:
            parent = item.parent()
            if parent:
                rev_num = parent.data(0, Qt.ItemDataRole.UserRole)
        if rev_num is None:
            return
        idx = rev_num - 1   # 0-based
        offsets = self._doc.revision_end_offsets
        if idx < len(offsets) and self._pdf_bytes:
            self.revision_selected.emit(self._pdf_bytes[:offsets[idx]])

    def _build_rev_item(self, rev: RevisionInfo) -> None:
        item = QTreeWidgetItem(self._tree)
        item.setData(0, Qt.ItemDataRole.UserRole, rev.revision_number)
        rev_label = t("val_rev_label", n=rev.revision_number, total=rev.total_revisions)
        item.setText(0, rev_label)
        item.setFont(0, _bold())

        sig = rev.signed_by
        if sig is None:
            if rev.change_types:
                parts = [t(f"val_rev_type_{ct}") for ct in rev.change_types]
                item.setText(1, ", ".join(parts))
            else:
                item.setText(1, t("val_rev_no_sig"))
            item.setForeground(1, QColor(_GREY))
            return

        # Top-level: type · CN
        if sig.sig_type == "doc_timestamp":
            sig_type = t("val_sig_type_doc_ts")
        else:
            sig_type = t("val_sig_type_signature")
        cn = _extract_cn(sig.signer_subject)
        item.setText(1, f"{sig_type}  ·  {cn}")
        item.setFont(1, _bold())

        # Integrity failure → paint top-level row red
        if sig.crypto_status == ValidationStatus.INVALID:
            red = QColor(_RED)
            item.setForeground(0, red)
            item.setForeground(1, red)

        # Sub-items
        self._add_sub(item, t("val_detail_date"), _date_text(sig))
        self._add_integrity_sub(item, sig)
        self._add_profile_sub(item, sig)

        item.setExpanded(True)

    def _add_sub(self, parent: QTreeWidgetItem,
                 label: str, value: str) -> QTreeWidgetItem:
        """Add a non-selectable detail sub-item with label/value columns."""
        sub = QTreeWidgetItem(parent)
        sub.setFlags(sub.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        sub.setText(0, label)
        sub.setForeground(0, QColor(_GREY))
        sub.setText(1, value)
        return sub

    def _add_integrity_sub(self, parent: QTreeWidgetItem,
                            sig: SignatureInfo) -> None:
        sub = self._add_sub(parent, t("val_detail_integrity"), "")
        if sig.crypto_status == ValidationStatus.VALID:
            sub.setText(1, t("val_integrity_ok"))
            sub.setForeground(1, QColor(_GREEN))
            sub.setFont(1, _bold())
        elif sig.crypto_status == ValidationStatus.INVALID:
            sub.setText(1, t("val_integrity_fail"))
            sub.setForeground(1, QColor(_RED))
            sub.setFont(1, _bold())
        # NOT_CHECKED / UNKNOWN: leave value empty

    def _add_profile_sub(self, parent: QTreeWidgetItem,
                          sig: SignatureInfo) -> None:
        profile_label, meaning = _profile_text(sig)
        self._add_sub(parent, t("val_detail_profile"), profile_label)
        if meaning:
            self._add_sub(parent, "", meaning)
