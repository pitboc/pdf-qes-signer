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
    QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)

from .i18n import t
from .validation_result import (
    CertSource, DocumentValidation, PadesProfile, RevisionInfo,
    SignatureInfo, TimestampInfo, ValidationStatus,
)


_RED    = "#9a0000"
_GREEN  = "#1a7a1a"
_GREY   = "#666666"
_WARN_BG = "#fff3cd"   # amber background for warning banner
_WARN_FG = "#6a4200"   # dark brown text
_WARN_BD = "#e0a800"   # amber border

# Change types that are suspicious after a signature (not benign infrastructure)
_SUSPICIOUS_TYPES = {"form_fields", "annotations", "unknown"}


def check_post_sig_warnings(revisions: list) -> tuple[set, set]:
    """Prüfe auf verdächtige unsignierte Revisionen nach der ersten Signatur.

    Returns:
        ``(post_last, between)`` – Mengen verdächtiger Change-Types:

        - *post_last*: Typen in Revisionen **nach der letzten** Signatur
          (durch keine Signatur abgedeckt – kritisch).
        - *between*: Typen in Revisionen **zwischen** zwei Signaturen
          (durch eine spätere Signatur abgedeckt, nicht durch die erste).
    """
    signed_indices = [i for i, r in enumerate(revisions) if r.signed_by is not None]
    if not signed_indices:
        return set(), set()

    first_sig_idx = signed_indices[0]
    last_sig_idx  = signed_indices[-1]

    between:   set = set()
    post_last: set = set()

    for i, rev in enumerate(revisions):
        if rev.signed_by is not None or i <= first_sig_idx:
            continue
        suspicious = {ct for ct in rev.change_types if ct in _SUSPICIOUS_TYPES}
        if i > last_sig_idx:
            post_last.update(suspicious)
        else:
            between.update(suspicious)

    return post_last, between


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


def _is_self_signed_chain(chain: list) -> bool:
    """Return True when the chain consists of exactly one self-signed certificate."""
    return len(chain) == 1 and chain[0].is_root


def _chain_label_tip(chain: list, status: ValidationStatus) -> tuple[str, str]:
    """Return (label, tooltip) for a chain status row."""
    if not chain or status == ValidationStatus.NOT_CHECKED:
        return t("val_chain_not_checked"), ""
    if status == ValidationStatus.VALID:
        return t("val_chain_valid"), t("val_chain_valid_tip")
    if status == ValidationStatus.INVALID:
        if any(c.source == CertSource.NOT_FOUND for c in chain):
            return t("val_chain_incomplete"), t("val_chain_incomplete_tip")
        ee = chain[0] if chain else None
        if ee and ee.ocsp and ee.ocsp.cert_status == "revoked":
            return t("val_chain_revoked"), t("val_chain_revoked_tip")
        return t("val_chain_expired"), t("val_chain_expired_tip")
    # UNKNOWN
    if _is_self_signed_chain(chain):
        return t("val_chain_self_signed"), t("val_chain_self_signed_tip")
    root = chain[-1] if chain else None
    if root and root.source == CertSource.CERTIFI:
        return t("val_chain_unknown_revoc"), t("val_chain_unknown_revoc_tip")
    return t("val_chain_unknown_root"), t("val_chain_unknown_root_tip")


def _extract_cn_from_chain(chain: list) -> str:
    """Return CN of the end-entity certificate, or '?' if chain is empty."""
    if not chain:
        return "?"
    subj = chain[0].subject
    sep = ";" if ";" in subj else ","
    for part in subj.split(sep):
        part = part.strip()
        colon = part.find(":")
        if colon > 0 and part[:colon].strip() in ("Common Name", "CN"):
            return part[colon + 1:].strip()
    return subj.split(sep)[0].strip() or "?"


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
                 show_all_initially: bool = False,
                 config=None) -> None:
        super().__init__(parent)
        self._doc = doc
        self._pdf_bytes = pdf_bytes
        self._show_all = show_all_initially
        self._config = config
        self._cert_detail_win = None   # CertChainDetailWindow singleton

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

    def closeEvent(self, event) -> None:
        if self._cert_detail_win is not None:
            self._cert_detail_win.close()
            self._cert_detail_win = None
        super().closeEvent(event)

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
        post_last, between = check_post_sig_warnings(self._doc.revisions)
        lines: list[str] = []
        if post_last:
            labels = ", ".join(t(f"val_rev_type_{ct}") for ct in sorted(post_last))
            lines.append(
                f"⚠  <b>{t('val_warn_post_sig_title')}</b><br>"
                f"{t('val_warn_post_sig_body', types=labels)}"
            )
        if between:
            labels = ", ".join(t(f"val_rev_type_{ct}") for ct in sorted(between))
            lines.append(
                f"⚠  <b>{t('val_warn_between_sig_title')}</b><br>"
                f"{t('val_warn_between_sig_body', types=labels)}"
            )
        if lines:
            self._warn_label.setText("<br><br>".join(lines))
            self._warn_label.show()
        else:
            self._warn_label.hide()

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

        # Certificate chain rows
        if sig.sig_type != "doc_timestamp":
            self._add_chain_sub(item, "val_detail_sig_chain",
                                 sig.cert_chain, sig.chain_status,
                                 "cert_win_title_sig")
        if sig.timestamp is not None:
            tsa_chain  = sig.timestamp.cert_chain
            tsa_status = sig.timestamp.chain_status
            self._add_chain_sub(item, "val_detail_tsa_chain",
                                 tsa_chain, tsa_status,
                                 "cert_win_title_tsa")
        elif sig.sig_type == "doc_timestamp":
            # LTA doc timestamp: only TSA chain
            self._add_chain_sub(item, "val_detail_tsa_chain",
                                 sig.cert_chain, sig.chain_status,
                                 "cert_win_title_tsa")

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

    def _add_chain_sub(self, parent: QTreeWidgetItem,
                       label_key: str,
                       chain: list,
                       status: ValidationStatus,
                       title_key: str) -> None:
        """Add one chain summary row with status colour, tooltip, and Details button."""
        text, tip = _chain_label_tip(chain, status)
        sub = self._add_sub(parent, t(label_key), text)
        if tip:
            sub.setToolTip(1, tip)

        # Colour
        if status == ValidationStatus.VALID:
            sub.setForeground(1, QColor(_GREEN))
            sub.setFont(1, _bold())
        elif status == ValidationStatus.INVALID:
            sub.setForeground(1, QColor(_RED))
            sub.setFont(1, _bold())
        elif status == ValidationStatus.UNKNOWN:
            sub.setForeground(1, QColor("#8a6000"))

        # "Details →" button only when there is something to show.
        # Clear column-1 text first so Qt doesn't draw it behind the widget.
        if chain and self._config is not None:
            sub.setText(1, "")
            btn = QPushButton(t("val_chain_details_btn"))
            btn.setFlat(True)
            btn.setStyleSheet("color: #1a73e8; text-decoration: underline;")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(
                lambda _checked, c=chain, s=status, tk=title_key:
                    self._open_chain_detail(c, s, tk))
            self._tree.setItemWidget(sub, 1,
                                     self._wrap_btn(text, tip, btn, status))

    @staticmethod
    def _wrap_btn(text: str, tip: str, btn: QPushButton,
                  status: ValidationStatus) -> "QWidget":
        """Return a widget with the status label and the Details button side by side."""
        from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel as _QLabel
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        lbl = _QLabel(text)
        if tip:
            lbl.setToolTip(tip)
        if status == ValidationStatus.VALID:
            lbl.setStyleSheet("color: #1a7a1a; font-weight: bold;")
        elif status == ValidationStatus.INVALID:
            lbl.setStyleSheet("color: #9a0000; font-weight: bold;")
        elif status == ValidationStatus.UNKNOWN:
            lbl.setStyleSheet("color: #8a6000;")
        lay.addWidget(lbl)
        lay.addWidget(btn)
        lay.addStretch()
        return w

    def _open_chain_detail(self, chain: list, status: ValidationStatus,
                           title_key: str) -> None:
        """Open or update the CertChainDetailWindow."""
        from .dialogs import CertChainDetailWindow
        cn = _extract_cn_from_chain(chain)
        title = t(title_key, cn=cn)
        if self._cert_detail_win is None:
            self._cert_detail_win = CertChainDetailWindow(self._config, parent=None)
        self._cert_detail_win.show_chain(chain, title, status, cn)
