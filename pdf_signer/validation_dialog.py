# SPDX-License-Identifier: GPL-3.0-or-later
"""Dialog for displaying PDF signature objects.

Shows a flat list of PDF revisions (newest first).  Each row spans seven
columns for easy vertical alignment.  Sub-items are collapsed by default
and reveal field name, full subject DN, and (for signatures with an
embedded TSA token) the self-reported CMS signing time.

No certificate chains, no revocation data, no network access.

## Columns

    Rev      | Element               | Name             | TSA          | Zeit             | Gültig bis | Integrität
    ---------|---------------------- |------------------|--------------|------------------|------------|------------------
    Rev 3/3  | TSA (LTA) Zeitstempel | BalTstamp TSU1   | –            | 15.01.2024 09:00 | 31.12.2025 | ✓ unverändert
    Rev 2/3  | Signatur              | Erika Musterfrau | BalTstamp    | 10.01.2024 14:32 | 31.12.2026 | ✓ unverändert
    Rev 1/3  | Signatur              | Max Mustermann   | –            | 05.01.2024 11:15 | 31.12.2025 | ✓ unverändert

Integrity failure turns the entire row red.
Certificate expiry at signing time turns the "Gültig bis" cell red.
Sub-item text appears in the Element column (col 1) to avoid the narrow
Rev column; other columns are empty for sub-items.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QDialog, QDialogButtonBox, QHBoxLayout, QLabel,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)

from .i18n import t
from .validation_result import DocumentValidation, RevisionInfo, SignatureInfo, ValidationStatus


_RED   = "#9a0000"
_GREEN = "#1a7a1a"
_GREY  = "#555555"

# Column indices
_COL_REV         = 0
_COL_ELEMENT     = 1
_COL_NAME        = 2
_COL_TSA         = 3
_COL_TIME        = 4
_COL_VALID_UNTIL = 5
_COL_INTEGRITY   = 6
_NUM_COLS        = 7


def _fmt_dt(dt: Optional[datetime]) -> str:
    if dt is None:
        return "–"
    return dt.strftime("%d.%m.%Y %H:%M")


def _fmt_date(dt: Optional[datetime]) -> str:
    if dt is None:
        return "–"
    return dt.strftime("%d.%m.%Y")


def _parse_dn(dn: str) -> dict[str, str]:
    """Parse an asn1crypto human-friendly DN string into a field dict.

    asn1crypto uses '; ' as separator when any value contains a comma
    (e.g. 'Musterfrau, Erika'), otherwise ', '.  We detect the separator
    by checking for a semicolon in the string.
    """
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


def _compact_dn(dn: str) -> str:
    """Return a compact 'CN, O, C' summary from a human-friendly DN string.

    Uses _parse_dn so that values with commas (e.g. 'Musterfrau, Erika') are
    extracted correctly.  Falls back to the raw string if no fields found.
    """
    fields = _parse_dn(dn)
    parts = []
    cn = fields.get("Common Name") or fields.get("CN")
    if cn:
        parts.append(cn)
    o = fields.get("Organization")
    if o:
        parts.append(o)
    c = fields.get("Country")
    if c:
        parts.append(c)
    return ", ".join(parts) if parts else dn


def _auth_time(sig: SignatureInfo) -> Optional[datetime]:
    """Return the authoritative signing time (TSA-confirmed if available)."""
    if sig.timestamp:
        return sig.timestamp.time
    return sig.signing_time


# ── Row builders ──────────────────────────────────────────────────────────────

def _apply_integrity(item: QTreeWidgetItem,
                     status: ValidationStatus) -> None:
    """Populate col-6 integrity badge; paint whole row red on failure."""
    bold = QFont()
    bold.setBold(True)

    if status == ValidationStatus.VALID:
        item.setText(_COL_INTEGRITY, t("val_integrity_ok"))
        item.setForeground(_COL_INTEGRITY, QColor(_GREEN))
        item.setFont(_COL_INTEGRITY, bold)

    elif status == ValidationStatus.INVALID:
        item.setText(_COL_INTEGRITY, t("val_integrity_fail"))
        red = QColor(_RED)
        for col in range(_NUM_COLS):
            item.setForeground(col, red)
        item.setFont(_COL_INTEGRITY, bold)

    # NOT_CHECKED / UNKNOWN: leave column empty


def _build_sig_subitems(parent: QTreeWidgetItem,
                         sig: SignatureInfo) -> None:
    """Add detail sub-items with text in col 0 (will be spanned full-width)."""
    no_sel = ~Qt.ItemFlag.ItemIsSelectable
    grey   = QColor(_GREY)

    def _sub(text: str) -> QTreeWidgetItem:
        it = QTreeWidgetItem(parent)
        it.setText(0, text)
        it.setFlags(it.flags() & no_sel)
        it.setForeground(0, grey)
        return it

    _sub(t("val_sub_field",   value=sig.field_name))
    _sub(t("val_sub_name",    value=_compact_dn(sig.signer_subject)))
    if sig.cert_chain:
        _sub(t("val_sub_issuer", value=_compact_dn(sig.cert_chain[0].issuer)))


def _build_rev_item(rev: RevisionInfo, parent) -> QTreeWidgetItem:
    """Build one revision row across all seven columns."""
    item = QTreeWidgetItem(parent)
    bold = QFont()
    bold.setBold(True)

    # Col 0 – Rev label
    item.setText(_COL_REV, t("val_rev_label",
                              n=rev.revision_number,
                              total=rev.total_revisions))
    item.setFont(_COL_REV, bold)

    sig = rev.signed_by
    if sig is None:
        item.setExpanded(False)
        return item

    # Col 1 – Element type
    sig_type_key = ("val_sig_type_lta"
                    if sig.sig_type == "doc_timestamp"
                    else "val_sig_type_signature")
    item.setText(_COL_ELEMENT, t(sig_type_key))
    item.setFont(_COL_ELEMENT, bold)

    # Col 2 – Signer / TSA name (CN)
    item.setText(_COL_NAME, _extract_cn(sig.signer_subject))
    item.setFont(_COL_NAME, bold)

    # Col 3 – TSA name (only for regular signature with embedded timestamp)
    if sig.sig_type == "signature" and sig.timestamp:
        item.setText(_COL_TSA, _extract_cn(sig.timestamp.tsa_subject))
    elif sig.sig_type == "doc_timestamp":
        item.setText(_COL_TSA, t("val_tsa_is_tsa"))
    else:
        item.setText(_COL_TSA, "–")

    # Col 4 – Authoritative time
    auth = _auth_time(sig)
    item.setText(_COL_TIME, _fmt_dt(auth))
    item.setFont(_COL_TIME, bold)

    # Col 5 – Certificate validity range (date only); red if expired at signing time
    if sig.cert_chain:
        valid_from  = sig.cert_chain[0].valid_from
        valid_until = sig.cert_chain[0].valid_until
        item.setText(_COL_VALID_UNTIL,
                     f"{_fmt_date(valid_from)} – {_fmt_date(valid_until)}")
        if auth and valid_until and valid_until < auth:
            item.setForeground(_COL_VALID_UNTIL, QColor(_RED))
            item.setFont(_COL_VALID_UNTIL, bold)
    else:
        item.setText(_COL_VALID_UNTIL, "–")

    # Col 6 – Integrity (may override row colour)
    _apply_integrity(item, sig.crypto_status)

    _build_sig_subitems(item, sig)
    item.setExpanded(False)
    return item


# ── ValidationDialog ──────────────────────────────────────────────────────────

class ValidationDialog(QDialog):
    """Modal dialog showing PDF signature objects (offline, Phase 1 only).

    Displays a flat list of revisions (newest first) with structured columns
    for type, signer, TSA, time, certificate expiry, and byte-integrity.
    No network access is performed.
    """

    def __init__(self, parent,
                 doc: DocumentValidation,
                 pdf_bytes: bytes,
                 auto_fetch: bool = False) -> None:
        super().__init__(parent)
        self._doc = doc

        self.setWindowTitle(t("val_dlg_title"))
        self.setMinimumSize(860, 380)
        self.resize(1020, 460)

        self._setup_ui()
        self._build_tree()

    # ── UI ────────────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        self._header = QLabel()
        self._header.setWordWrap(True)
        layout.addWidget(self._header)
        self._update_header()

        self._tree = QTreeWidget()
        self._tree.setColumnCount(_NUM_COLS)
        self._tree.setHeaderLabels([
            t("val_col_rev"),
            t("val_col_element"),
            t("val_col_name"),
            t("val_col_tsa"),
            t("val_col_time"),
            t("val_col_valid_until"),
            t("val_col_integrity"),
        ])
        self._tree.setAlternatingRowColors(True)
        self._tree.setSelectionMode(QTreeWidget.SelectionMode.NoSelection)
        self._tree.header().setStretchLastSection(False)
        layout.addWidget(self._tree)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn_box.rejected.connect(self.reject)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_row.addWidget(btn_box)
        layout.addLayout(btn_row)

    def _update_header(self) -> None:
        doc = self._doc
        info = t("val_doc_info", n=len(doc.revisions))
        if doc.has_dss:
            info += t("val_doc_dss")
        if doc.is_lta:
            info += t("val_doc_lta")
        self._header.setText(f"<span style='color:#444;'>{info}</span>")

    # ── Tree ──────────────────────────────────────────────────────────────

    def _build_tree(self) -> None:
        self._tree.clear()

        if not self._doc.revisions:
            QTreeWidgetItem(self._tree, [t("val_no_sigs")])
            return

        for rev in reversed(self._doc.revisions):
            item = _build_rev_item(rev, self._tree)
            item.setData(0, Qt.ItemDataRole.UserRole, rev.revision_number)
            # Span sub-item text across all columns
            for i in range(item.childCount()):
                self._tree.setFirstColumnSpanned(
                    i, self._tree.indexFromItem(item), True)

        self._tree.resizeColumnToContents(_COL_REV)
        self._tree.resizeColumnToContents(_COL_ELEMENT)
        self._tree.resizeColumnToContents(_COL_NAME)
        self._tree.resizeColumnToContents(_COL_TSA)
        self._tree.resizeColumnToContents(_COL_TIME)
        self._tree.resizeColumnToContents(_COL_VALID_UNTIL)
        self._tree.resizeColumnToContents(_COL_INTEGRITY)
