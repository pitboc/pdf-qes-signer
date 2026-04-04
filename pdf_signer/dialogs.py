# SPDX-License-Identifier: GPL-3.0-or-later
"""
Qt dialogs for PDF QES Signer.

Provides:
  - TokenInfoDialog       – displays token contents; lets user select a key label
  - Pkcs11ConfigDialog    – configure PKCS#11 library path and key label
  - AppearanceConfigDialog – standalone dialog for signature appearance settings
  - ProfileSelectDialog   – choose and activate a profile
  - NewProfileDialog      – create a new profile (copy of current)
  - RenameProfileDialog   – rename any profile
  - DeleteProfileDialog   – delete a profile with special-case handling
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Optional

import re

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QMessageBox,
    QPushButton, QRadioButton, QSizePolicy, QSlider, QSpinBox, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget, QCheckBox, QComboBox,
    QAbstractItemView, QGridLayout,
)

from .config import AppConfig, PDF_STANDARD_FONTS
from .appearance import SigAppearance
from .pdf_view import DPI_SCALE
from .i18n import t


# ── Token data helpers ────────────────────────────────────────────────────────

# Mapping von EC-Kurven-OIDs (Dotted-String) zu lesbaren Bezeichnungen.
# Wird genutzt, um den Schlüsseltyp eines ECC-Schlüssels im Token-Baum
# anzuzeigen, anstatt der rohen OID-Zeichenkette.
_EC_CURVES: dict[str, str] = {
    "1.2.840.10045.3.1.7":        "P-256 (256 Bit)",
    "1.3.132.0.34":               "P-384 (384 Bit)",
    "1.3.132.0.35":               "P-521 (521 Bit)",
    "1.3.36.3.3.2.8.1.1.7":      "brainpoolP256r1 (256 Bit)",
    "1.3.36.3.3.2.8.1.1.11":     "brainpoolP384r1 (384 Bit)",
    "1.3.36.3.3.2.8.1.1.13":     "brainpoolP512r1 (512 Bit)",
}

# Mapping von X.509-Zertifikat-OIDs zu lesbaren deutschen Bezeichnungen.
# Wird beim Formatieren von Subject- und Issuer-Distinguished-Names genutzt,
# damit der Benutzer "Nachname=Mustermann" statt "2.5.4.4=Mustermann" sieht.
_CERT_OID_NAMES: dict[str, str] = {
    "2.5.4.3":               "CN",
    "2.5.4.4":               "Nachname",
    "2.5.4.42":              "Vorname",
    "2.5.4.12":              "Titel",
    "2.5.4.5":               "Zert-Nr",
    "2.5.4.6":               "Land",
    "2.5.4.7":               "Ort",
    "2.5.4.8":               "Bundesland",
    "2.5.4.10":              "Organisation",
    "2.5.4.11":              "Abteilung",
    "2.5.4.97":              "Org-Kennung",
    "1.2.840.113549.1.9.1":  "E-Mail",
}


def _decode_der_oid(der: bytes) -> str:
    """Decode a DER-encoded OID (tag 0x06) to dotted-string notation."""
    # Mindestlänge prüfen und sicherstellen, dass das Tag 0x06 (OID) vorliegt
    if len(der) < 2 or der[0] != 0x06:
        return ""
    # OID-Inhalt hinter Tag (0x06) und Längen-Byte extrahieren
    oid_bytes = der[2:2 + der[1]]
    # Erstes Byte kodiert die ersten beiden Komponenten: x.y → x*40 + y
    components = [oid_bytes[0] // 40, oid_bytes[0] % 40]
    # Restliche Bytes dekodieren (Base-128-Kodierung, MSB=1 bedeutet Folgebyte)
    i, value = 1, 0
    while i < len(oid_bytes):
        b = oid_bytes[i]; i += 1
        value = (value << 7) | (b & 0x7F)
        # MSB=0 signalisiert das letzte Byte einer Komponente
        if not (b & 0x80):
            components.append(value)
            value = 0
    return ".".join(str(c) for c in components)


def _read_key_info(obj, p11) -> dict:
    """Extract displayable attributes from a PKCS#11 key object."""
    info: dict = {}
    # Label des Schlüssels auslesen – wird als Anzeigename im Baum genutzt
    try:
        info["label"] = obj[p11.Attribute.LABEL]
    except Exception:
        info["label"] = "(unknown)"
    # CKA_ID als Hex-String – verbindet Schlüssel mit zugehörigem Zertifikat
    try:
        info["id"] = bytes(obj[p11.Attribute.ID]).hex()
    except Exception:
        pass
    # Schlüsseltyp ermitteln (RSA oder EC/ECC)
    try:
        from pkcs11 import KeyType
        kt = obj[p11.Attribute.KEY_TYPE]
        info["key_type"] = {KeyType.RSA: "RSA", KeyType.EC: "EC (ECC)"}.get(kt, str(kt))
    except Exception:
        pass
    # RSA: key size from modulus bits
    try:
        info["key_size"] = f"{obj[p11.Attribute.MODULUS_BITS]} Bit"
    except Exception:
        pass
    # EC: curve name from EC_PARAMS OID
    # Nur wenn RSA-Größe nicht ermittelt werden konnte (ECC hat kein MODULUS_BITS)
    if "key_size" not in info:
        try:
            # EC_PARAMS enthält die Kurvendefinition als DER-kodierte OID
            oid = _decode_der_oid(bytes(obj[p11.Attribute.EC_PARAMS]))
            info["key_size"] = _EC_CURVES.get(oid, oid) if oid else None
            if not info["key_size"]:
                del info["key_size"]
        except Exception:
            pass
    return info


def _read_cert_info(obj, p11) -> dict:
    """Extract displayable attributes from a PKCS#11 certificate object."""
    info: dict = {}
    # Label des Zertifikats – oft identisch mit dem Schlüssel-Label
    try:
        info["label"] = obj[p11.Attribute.LABEL]
    except Exception:
        info["label"] = "(no label)"
    # CKA_ID als Hex-String – verknüpft Zertifikat mit privatem Schlüssel
    try:
        info["id"] = bytes(obj[p11.Attribute.ID]).hex()
    except Exception:
        pass
    try:
        import warnings
        from cryptography import x509 as cx509
        # Rohe DER-Daten des Zertifikats vom Token lesen und parsen
        cert_data = bytes(obj[p11.Attribute.VALUE])
        with warnings.catch_warnings():
            # Veraltete API-Warnungen unterdrücken (z.B. bei alten Zertifikaten)
            warnings.simplefilter("ignore")
            cert = cx509.load_der_x509_certificate(cert_data)

        def fmt_dn(name) -> str:
            """Formatiert einen Distinguished Name als lesbare Zeichenkette."""
            parts = []
            for attr in name:
                # OID in lesbares Kürzel umwandeln, Fallback auf Dotted-String
                lbl = _CERT_OID_NAMES.get(attr.oid.dotted_string, attr.oid.dotted_string)
                parts.append(f"{lbl}={attr.value}")
            return ", ".join(parts)

        # Subject (Zertifikatsinhaber) und Issuer (Aussteller) formatieren
        info["subject"]    = fmt_dn(cert.subject)
        info["issuer"]     = fmt_dn(cert.issuer)
        # Seriennummer in Großbuchstaben-Hex für bessere Lesbarkeit
        info["serial"]     = f"{cert.serial_number:X}"
        info["valid_from"] = cert.not_valid_before_utc.strftime("%d.%m.%Y")
        info["valid_to"]   = cert.not_valid_after_utc.strftime("%d.%m.%Y")
        # Individual name components for display-name composition
        # Einzelne Namensbestandteile separat extrahieren, damit später
        # der Anzeigename (Titel Vorname Nachname) zusammengesetzt werden kann
        for attr in cert.subject:
            dotted = attr.oid.dotted_string
            if dotted == "2.5.4.12":   # Title
                info["name_titel"] = attr.value
            elif dotted == "2.5.4.42": # GivenName
                info["name_vorname"] = attr.value
            elif dotted == "2.5.4.4":  # Surname
                info["name_nachname"] = attr.value
        # Subject Alternative Name (SAN) auslesen – enthält oft E-Mail-Adressen
        try:
            san = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
            info["san_emails"] = san.value.get_values_for_type(cx509.RFC822Name)
        except cx509.ExtensionNotFound:
            # Viele Zertifikate haben keine SAN-Erweiterung – kein Fehler
            info["san_emails"] = []
    except Exception:
        info["san_emails"] = []
    return info


# ── Token info dialog ─────────────────────────────────────────────────────────

class TokenInfoDialog(QDialog):
    """Display all token objects in a unified tree grouped by CKA_CLASS.

    all_items – list of dicts, each with an "obj_class" key
                ("PRIVATE_KEY", "PRIVATE_KEY_DERIVED", "PUBLIC_KEY",
                "CERTIFICATE") plus the attributes from _read_key_info()
                or _read_cert_info().

    Section headers separate each class.  Only private-key items can be
    transferred to the key-label field via "Key-Label übernehmen".
    """

    # Reihenfolge der Objektklassen im Baum: Private Keys zuerst (wichtigste
    # für den Benutzer), dann Zertifikate, dann öffentliche Schlüssel
    _CLASS_ORDER  = ["PRIVATE_KEY", "CERTIFICATE", "PUBLIC_KEY"]
    # i18n-Schlüssel für die Abschnittsüberschriften im Baum
    _CLASS_LABELS = {
        "PRIVATE_KEY": "dlg_token_class_private_key",
        "CERTIFICATE": "dlg_token_class_certificate",
        "PUBLIC_KEY":  "dlg_token_class_public_key",
    }

    # Signal: wird ausgelöst wenn der Benutzer einen Schlüssel/Zertifikat
    # auswählt und "Übernehmen" klickt. Übergibt (key_id_hex, cert_cn).
    key_selected = pyqtSignal(str, str)  # (key_id_hex, cert_cn)

    def __init__(self, parent, token, all_items: list[dict]) -> None:
        super().__init__(parent)
        # token: PKCS#11-Token-Objekt (für Metadaten wie Label, Hersteller)
        self.token     = token
        # all_items: Liste aller gefundenen Objekte als Dicts (von _read_key_info
        # und _read_cert_info erzeugt, jeweils mit "obj_class"-Schlüssel)
        self.all_items = all_items
        self.setWindowTitle(t("dlg_token_info_title"))
        self.resize(680, 520)
        self._build_ui()
        self._select_first_object()

    def _build_ui(self) -> None:
        lay = QVBoxLayout(self)

        # ── Token meta info ───────────────────────────────────────────────
        # Obere Gruppe mit Token-Metadaten (Name, Hersteller, Modell, Seriennummer)
        info_grp = QGroupBox()
        info_form = QFormLayout(info_grp)
        info_form.setHorizontalSpacing(16)
        info_form.setContentsMargins(8, 4, 8, 4)

        def _token_str(attr: str) -> str:
            """Liest ein Token-Attribut und gibt es als bereinigten String zurück."""
            try:
                v = getattr(self.token, attr)
                if isinstance(v, (bytes, bytearray)):
                    # Bytes-Felder (z.B. manufacturer_id) als ASCII dekodieren
                    return v.decode("ascii", errors="replace").strip()
                return str(v).strip()
            except Exception:
                return ""

        info_form.addRow("Name:",       QLabel(_token_str("label")))
        info_form.addRow("Hersteller:", QLabel(_token_str("manufacturer_id")))
        # Modell und Seriennummer nur anzeigen wenn vorhanden (walrus operator)
        if v := _token_str("model"):
            info_form.addRow("Modell:", QLabel(v))
        if v := _token_str("serial"):
            info_form.addRow("Seriennr.:", QLabel(v))
        lay.addWidget(info_grp)

        # ── Unified object tree ───────────────────────────────────────────
        # Baumwidget mit allen Token-Objekten, gruppiert nach Objektklasse
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setColumnCount(2)
        self.tree.header().setStretchLastSection(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        # Auswahl-Änderung: Schaltfläche "Übernehmen" aktivieren/deaktivieren
        self.tree.itemSelectionChanged.connect(self._on_selection_changed)
        # Doppelklick auf ein Objekt-Element löst direkt "Übernehmen" aus
        self.tree.itemDoubleClicked.connect(self._on_double_click)

        # all_items nach Objektklasse gruppieren (dict: Klasse → Liste von Dicts)
        grouped: dict[str, list[dict]] = {}
        for item in self.all_items:
            grouped.setdefault(item.get("obj_class", ""), []).append(item)

        # Hintergrundfarbe für Abschnittsüberschriften aus dem System-Palette holen
        alt_brush = self.palette().alternateBase()

        for cls in self._CLASS_ORDER:
            # Objektklassen überspringen, für die keine Objekte vorhanden sind
            if cls not in grouped:
                continue

            # Section header – not selectable, bold, shaded background
            # Abschnitts-Header: fett, grauer Hintergrund, nicht auswählbar
            hdr = QTreeWidgetItem([t(self._CLASS_LABELS[cls]), ""])
            hdr.setFlags(Qt.ItemFlag.ItemIsEnabled)
            font = hdr.font(0); font.setBold(True); hdr.setFont(0, font)
            hdr.setBackground(0, alt_brush); hdr.setBackground(1, alt_brush)
            self.tree.addTopLevelItem(hdr)

            for item_data in grouped[cls]:
                # Haupteintrag für das Token-Objekt (auswählbar)
                obj = QTreeWidgetItem(hdr, [item_data["label"], ""])
                # Objektklasse im UserRole speichern, damit _selected_item() den
                # Typ ermitteln kann ohne erneut in all_items zu suchen
                obj.setData(0, Qt.ItemDataRole.UserRole, cls)

                # Attribute children (non-selectable)
                # Attribute je nach Objekttyp unterschiedlich anzeigen
                if cls in ("PRIVATE_KEY", "PUBLIC_KEY"):
                    attrs = (("id", "ID"), ("key_type", "Schlüsseltyp"),
                             ("key_size", "Schlüssellänge"))
                elif cls == "CERTIFICATE":
                    attrs = (("id", "ID"), ("subject", "Inhaber"),
                             ("issuer", "Aussteller"), ("serial", "Seriennummer"),
                             ("valid_from", "Gültig ab"), ("valid_to", "Gültig bis"))
                else:
                    attrs = ()

                # Attribut-Kindknoten anlegen (nur sichtbar, nicht auswählbar)
                for attr, lbl in attrs:
                    if attr in item_data:
                        child = QTreeWidgetItem(obj, [lbl, item_data[attr]])
                        child.setFlags(Qt.ItemFlag.ItemIsEnabled)
                # SAN-E-Mail-Adressen als eigene Kindknoten anzeigen
                for email in item_data.get("san_emails", []):
                    child = QTreeWidgetItem(obj, ["E-Mail (SAN)", email])
                    child.setFlags(Qt.ItemFlag.ItemIsEnabled)

        # Alle Abschnitte aufklappen damit der Benutzer sofort alle Objekte sieht
        self.tree.expandAll()
        self.tree.resizeColumnToContents(0)
        lay.addWidget(self.tree)

        # ── Buttons ───────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        # "Key-Label übernehmen": überträgt die CKA_ID des gewählten Objekts
        # in das Konfigurationsfeld und schließt den Dialog
        self.btn_use = QPushButton(t("dlg_token_use_key"))
        self.btn_use.setEnabled(False)  # erst nach Auswahl eines Objekts aktiv
        self.btn_use.clicked.connect(self._use_selected)
        b_close = QPushButton(t("dlg_token_close"))
        b_close.clicked.connect(self.accept)
        btn_row.addWidget(self.btn_use)
        btn_row.addStretch()
        btn_row.addWidget(b_close)
        lay.addLayout(btn_row)

    def _select_first_object(self) -> None:
        """Select the first selectable object item in the tree."""
        for i in range(self.tree.topLevelItemCount()):
            header = self.tree.topLevelItem(i)
            if header.childCount() > 0:
                self.tree.setCurrentItem(header.child(0))
                return

    def _selected_item(self):
        """Return the selected object item (any class), or None for section headers.

        If an attribute child is selected, navigate up to the parent object item
        so the user can click any row within an object to activate "Übernehmen".
        """
        items = self.tree.selectedItems()
        if not items:
            return None
        item = items[0]
        parent = item.parent()
        if parent is None:
            # Section header – not a selectable object
            return None
        if parent.parent() is not None:
            # Attribute child → use the parent object item instead
            item = parent
        return item if item.data(0, Qt.ItemDataRole.UserRole) is not None else None

    def _on_selection_changed(self) -> None:
        # "Übernehmen"-Schaltfläche nur aktivieren wenn ein Objekt-Element
        # (kein Header, kein Attribut-Kind) ausgewählt ist
        self.btn_use.setEnabled(self._selected_item() is not None)

    def _on_double_click(self, item, _col) -> None:
        # Doppelklick auf Objekt-Element löst direkt die Übernahme aus;
        # Klick auf Header oder Attribut-Kinder wird ignoriert (kein UserRole)
        if item.data(0, Qt.ItemDataRole.UserRole) is not None:
            self._use_selected()

    def _use_selected(self) -> None:
        item = self._selected_item()
        if item:
            key_id_hex = ""
            composed_name = ""
            cls = item.data(0, Qt.ItemDataRole.UserRole)
            # Get the ID from the matching entry in all_items
            # CKA_ID des ausgewählten Objekts aus all_items heraussuchen
            for entry in self.all_items:
                if entry.get("obj_class") == cls and entry.get("label") == item.text(0):
                    key_id_hex = entry.get("id", "")
                    break
            # Compose display name from the certificate with the same ID
            # Das zu diesem Schlüssel gehörende Zertifikat suchen (gleiche CKA_ID)
            # und daraus den Anzeigenamen (Titel Vorname Nachname) zusammensetzen
            for entry in self.all_items:
                if entry.get("obj_class") == "CERTIFICATE" and entry.get("id") == key_id_hex:
                    parts = []
                    if titel := entry.get("name_titel"):
                        parts.append(titel)
                    if vorname := entry.get("name_vorname"):
                        parts.append(vorname)
                    if nachname := entry.get("name_nachname"):
                        parts.append(nachname)
                    composed_name = " ".join(parts)
                    break
            # Signal mit CKA_ID und zusammengesetztem Namen senden;
            # der Slot im aufrufenden Dialog füllt damit die Eingabefelder
            self.key_selected.emit(key_id_hex, composed_name)
        self.accept()


# ── PFX certificate info dialog ───────────────────────────────────────────────

def _pfx_check_encrypted(pfx_path: str) -> bool:
    """Return True if the PFX file at *pfx_path* requires a non-empty passphrase.

    Attempts to load the file with password=None and password=b"" in sequence.
    Returns True only when both attempts fail, indicating a real passphrase is
    required.  IOErrors (file not found, permission denied) propagate to the
    caller.
    """
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        load_pkcs12 as _load_pfx,
    )
    with open(pfx_path, "rb") as fh:
        data = fh.read()
    for pw in (None, b""):
        try:
            _load_pfx(data, pw)
            return False
        except Exception:
            pass
    return True


def _pfx_load_cert_info(pfx_path: str, passphrase: bytes | None = None) -> dict:
    """Load PFX and return a dict with all displayable object details.

    Top-level keys:
      ``cn``          – Common Name of the signing certificate (for appearance)
      ``key_type``    – e.g. "RSA" or "EC (ECC)" (empty if no key)
      ``key_size``    – e.g. "2048 Bit" or curve name (empty if unknown)
      ``subject``     – formatted DN of signing certificate
      ``issuer``      – formatted DN of signing certificate issuer
      ``valid_from``  – validity start (formatted date string)
      ``valid_to``    – validity end (formatted date string)
      ``serial``      – serial number as uppercase hex
      ``self_signed`` – True when subject == issuer
      ``chain``       – list of dicts, one per additional certificate, each with
                        keys: ``cn``, ``subject``, ``issuer``, ``valid_from``,
                        ``valid_to``, ``serial``, ``self_signed``

    Raises on load failure (wrong passphrase, corrupt file, …).
    """
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        load_pkcs12 as _load_pfx,
    )
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec

    with open(pfx_path, "rb") as fh:
        data = fh.read()

    pkcs12 = None
    for pw in ([passphrase] if passphrase is not None else [None, b""]):
        try:
            pkcs12 = _load_pfx(data, pw)
            break
        except Exception:
            pass
    if pkcs12 is None:
        _load_pfx(data, passphrase)  # re-raise with original passphrase

    def fmt_dn(name) -> str:
        parts = []
        for attr in name:
            lbl = _CERT_OID_NAMES.get(attr.oid.dotted_string, attr.oid.dotted_string)
            parts.append(f"{lbl}={attr.value}")
        return ", ".join(parts)

    def cert_dict(cert) -> dict:
        """Extract display fields from a cryptography x509.Certificate."""
        attrs = cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)
        return {
            "cn":          attrs[0].value if attrs else "",
            "subject":     fmt_dn(cert.subject),
            "issuer":      fmt_dn(cert.issuer),
            "valid_from":  cert.not_valid_before_utc.strftime("%d.%m.%Y"),
            "valid_to":    cert.not_valid_after_utc.strftime("%d.%m.%Y"),
            "serial":      f"{cert.serial_number:X}",
            "self_signed": cert.subject == cert.issuer,
        }

    info: dict = {
        "cn": "", "key_type": "", "key_size": "",
        "subject": "", "issuer": "", "valid_from": "", "valid_to": "",
        "serial": "", "self_signed": False, "chain": [],
    }

    # Schlüsseltyp und -größe aus dem privaten Schlüssel lesen.
    # Der Schlüssel ist nur kurz im Speicher – kein Verweis wird gespeichert.
    if pkcs12.key is not None:
        k = pkcs12.key
        if isinstance(k, _rsa.RSAPrivateKey):
            info["key_type"] = "RSA"
            info["key_size"] = f"{k.key_size} Bit"
        elif isinstance(k, _ec.EllipticCurvePrivateKey):
            info["key_type"] = "EC (ECC)"
            info["key_size"] = k.curve.name
        else:
            info["key_type"] = type(k).__name__

    if pkcs12.cert:
        info.update(cert_dict(pkcs12.cert.certificate))

    for extra in (pkcs12.additional_certs or []):
        info["chain"].append(cert_dict(extra.certificate))

    return info


def _pfx_load_with_prompt(parent, pfx_path: str) -> tuple[dict, bytes | None] | None:
    """Try to load PFX cert info, prompting for a password if necessary.

    Returns ``(info_dict, passphrase)`` on success, or ``None`` if the user
    cancelled the password dialog.  The passphrase is the resolved bytes value
    (``None`` or ``b""`` for unprotected files, encoded bytes for protected ones)
    so the caller can forward it to further operations like ``PfxInfoDialog``.

    The private key is decrypted only briefly to parse the certificate; no
    reference to the key object is retained after this function returns.
    The passphrase itself is not stored anywhere by this function.
    """
    from PyQt6.QtWidgets import QInputDialog, QLineEdit

    # First attempt: no password (covers unprotected and empty-password files)
    try:
        info = _pfx_load_cert_info(pfx_path)
        return info, None
    except Exception:
        pass

    # File requires a real passphrase – ask the user once
    pw_str, ok = QInputDialog.getText(
        parent,
        t("cfg_pfx_password_title"),
        t("cfg_pfx_password_prompt"),
        QLineEdit.EchoMode.Password,
    )
    if not ok:
        return None  # user cancelled

    passphrase = pw_str.encode() if pw_str else b""
    try:
        info = _pfx_load_cert_info(pfx_path, passphrase)
        return info, passphrase
    except Exception as exc:
        QMessageBox.critical(
            parent,
            t("dlg_pfx_load_error_title"),
            t("dlg_pfx_load_error", error=str(exc)),
        )
        return None


class PfxInfoDialog(QDialog):
    """Display all objects from a PFX/PKCS#12 file in a grouped tree.

    Three sections mirror the PKCS#11 TokenInfoDialog layout:
      - Private Key   – key type and size
      - Signaturzertifikat – subject, issuer, validity, serial
      - Zertifikatskette   – one entry per additional (CA) certificate

    The "CN übernehmen" button emits ``cn_selected(str)`` with the Common Name
    of the signing certificate so the caller can populate the cert_cn field.
    """

    cn_selected = pyqtSignal(str)

    def __init__(self, parent, pfx_path: str = "",
                 passphrase: bytes | None = None,
                 info: dict | None = None) -> None:
        """Show PFX object tree.

        Pass a pre-loaded *info* dict (from ``_pfx_load_cert_info``) to avoid
        reading and decrypting the file a second time.  If *info* is None the
        file is loaded from *pfx_path* using *passphrase*.
        """
        super().__init__(parent)
        self.setWindowTitle(t("dlg_pfx_info_title"))
        self.resize(680, 480)
        self._cn = ""
        if info is None:
            try:
                info = _pfx_load_cert_info(pfx_path, passphrase)
            except Exception as exc:
                traceback.print_exc()
                QMessageBox.critical(parent, t("dlg_pfx_load_error_title"),
                                     t("dlg_pfx_load_error", error=str(exc)))
                self._build_error_ui(str(exc))
                return
        self._cn = info.get("cn", "")
        self._build_ui(info)

    def _build_error_ui(self, msg: str) -> None:
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(msg))
        btn = QPushButton(t("dlg_token_close"))
        btn.clicked.connect(self.accept)
        lay.addWidget(btn)

    @staticmethod
    def _add_section(tree, title: str, alt_brush) -> "QTreeWidgetItem":
        """Add a bold, shaded, non-selectable section header to *tree*."""
        from PyQt6.QtWidgets import QTreeWidgetItem
        hdr = QTreeWidgetItem([title, ""])
        hdr.setFlags(Qt.ItemFlag.ItemIsEnabled)
        font = hdr.font(0); font.setBold(True); hdr.setFont(0, font)
        hdr.setBackground(0, alt_brush); hdr.setBackground(1, alt_brush)
        tree.addTopLevelItem(hdr)
        return hdr

    @staticmethod
    def _add_object(parent_item, label: str, attrs: list[tuple[str, str]]):
        """Add an object item with attribute children under *parent_item*."""
        from PyQt6.QtWidgets import QTreeWidgetItem
        obj = QTreeWidgetItem(parent_item, [label, ""])
        for attr_lbl, attr_val in attrs:
            if attr_val:
                child = QTreeWidgetItem(obj, [attr_lbl, attr_val])
                child.setFlags(Qt.ItemFlag.ItemIsEnabled)
        return obj

    def _build_ui(self, info: dict) -> None:
        lay = QVBoxLayout(self)

        tree = QTreeWidget()
        tree.setHeaderHidden(True)
        tree.setColumnCount(2)
        tree.header().setStretchLastSection(True)
        tree.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        alt_brush = self.palette().alternateBase()

        # ── Privater Schlüssel ────────────────────────────────────────────
        if info.get("key_type"):
            hdr = self._add_section(tree, t("dlg_pfx_private_key"), alt_brush)
            self._add_object(hdr, info["key_type"], [
                ("Schlüsseltyp",   info["key_type"]),
                ("Schlüssellänge", info.get("key_size", "")),
            ])

        # ── Signaturzertifikat ────────────────────────────────────────────
        if info.get("subject"):
            hdr = self._add_section(tree, t("dlg_pfx_signing_cert"), alt_brush)
            issuer = (f"{info['issuer']}  {t('dlg_pfx_self_signed')}"
                      if info["self_signed"] else info["issuer"])
            self._add_object(hdr, info["cn"] or info["subject"], [
                ("Inhaber",        info["subject"]),
                ("Aussteller",     issuer),
                ("Gültig ab",      info["valid_from"]),
                ("Gültig bis",     info["valid_to"]),
                ("Seriennummer",   info["serial"]),
            ])

        # ── Zertifikatskette ──────────────────────────────────────────────
        if info["chain"]:
            hdr = self._add_section(
                tree, t("dlg_pfx_chain_header", n=len(info["chain"])), alt_brush)
            for c in info["chain"]:
                issuer = (f"{c['issuer']}  {t('dlg_pfx_self_signed')}"
                          if c["self_signed"] else c["issuer"])
                self._add_object(hdr, c["cn"] or c["subject"], [
                    ("Inhaber",      c["subject"]),
                    ("Aussteller",   issuer),
                    ("Gültig ab",    c["valid_from"]),
                    ("Gültig bis",   c["valid_to"]),
                    ("Seriennummer", c["serial"]),
                ])

        tree.expandAll()
        tree.resizeColumnToContents(0)
        lay.addWidget(tree)

        # ── Buttons ───────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        if self._cn:
            btn_use = QPushButton(t("dlg_pfx_use_cn"))
            btn_use.clicked.connect(self._use_cn)
            btn_row.addWidget(btn_use)
        btn_row.addStretch()
        btn_close = QPushButton(t("dlg_token_close"))
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)
        lay.addLayout(btn_row)

    def _use_cn(self) -> None:
        self.cn_selected.emit(self._cn)
        self.accept()


# ── PKCS#11 configuration dialog ──────────────────────────────────────────────

class Pkcs11ConfigDialog(QDialog):
    """Configure the signing method (PKCS#11 token or PFX file) and TSA.

    Tab 1 – Signing method:
      A QComboBox selects the signing source (currently PFX/PKCS#12 or
      PKCS#11 hardware token; designed to be extensible for future sources).
      The relevant form rows are shown or hidden based on the selection.
      The shared cert_cn field is read-only in both modes; it is filled from
      the token dialog (PKCS#11) or from the certificate inside the PFX file.

    Tab 2 – TSA: unchanged.

    PIN entry is intentionally absent here – the PIN / passphrase is entered
    in the main window's Token/PIN panel so that it is available immediately
    before signing.
    """

    def __init__(self, parent, config: AppConfig) -> None:
        super().__init__(parent)
        self.config = config
        self.setWindowTitle(t("cfg_title"))
        self.setMinimumWidth(520)
        # Cache für geladene PFX-Metadaten; wird bei Dateiauswahl gefüllt und
        # bei Pfadänderung geleert. Nur Metadaten – kein Passwort, kein Schlüssel.
        self._pfx_info: dict | None = None
        self._build_ui()
        self._load_values()

    def _build_ui(self) -> None:
        lay  = QVBoxLayout(self)
        tabs = QTabWidget()

        # ── Tab 1: Signatur-Methode ────────────────────────────────────────
        sig_tab  = QWidget()
        stab_lay = QVBoxLayout(sig_tab)

        # Modus-Auswahl: QComboBox (erweiterbar für künftige Signaturquellen)
        mode_row = QHBoxLayout()
        self._mode_combo = QComboBox()
        self._mode_combo.addItem(t("cfg_mode_pfx"),    "pfx")
        self._mode_combo.addItem(t("cfg_mode_pkcs11"), "pkcs11")
        mode_row.addWidget(QLabel(t("cfg_mode_label")))
        mode_row.addWidget(self._mode_combo, 1)
        stab_lay.addLayout(mode_row)

        # Gemeinsames Formular; einzelne Zeilen werden je nach Modus ein-/ausgeblendet
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        # ── PKCS#11-spezifische Felder ─────────────────────────────────────
        lib_row = QHBoxLayout()
        self.lib_edit = QLineEdit()
        self.lib_edit.setPlaceholderText(
            "C:\\Windows\\System32\\P11TCOSSigGx64.dll"
            if sys.platform == "win32"
            else "/usr/lib/.../opensc-pkcs11.so"
        )
        bb = QPushButton(t("cfg_lib_browse"))
        bb.setFixedWidth(36)
        bb.clicked.connect(self._browse_lib)
        lib_row.addWidget(self.lib_edit)
        lib_row.addWidget(bb)
        self._lib_lbl   = QLabel(t("cfg_lib_label"))
        self._lib_widget = QWidget()
        self._lib_widget.setLayout(lib_row)
        form.addRow(self._lib_lbl, self._lib_widget)

        self.key_id_edit = QLineEdit()
        self.key_id_edit.setPlaceholderText(t("cfg_key_id_placeholder"))
        self._key_id_lbl  = QLabel(t("cfg_key_id_label"))
        self._key_id_hint = QLabel(t("cfg_key_id_hint"))
        self._key_id_hint.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow(self._key_id_lbl, self.key_id_edit)
        form.addRow("", self._key_id_hint)

        self.pin_edit = QLineEdit()
        self.pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_edit.setPlaceholderText(t("cfg_pin_placeholder"))
        self._pin_lbl  = QLabel(t("cfg_pin_label"))
        self._pin_hint = QLabel(t("cfg_pin_hint"))
        self._pin_hint.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow(self._pin_lbl, self.pin_edit)
        form.addRow("", self._pin_hint)

        # ── PFX-spezifische Felder ─────────────────────────────────────────
        pfx_row = QHBoxLayout()
        self.pfx_edit = QLineEdit()
        self.pfx_edit.setPlaceholderText(t("cfg_pfx_path_label"))
        self.pfx_edit.textChanged.connect(self._on_pfx_path_changed)
        pfx_bb = QPushButton(t("cfg_lib_browse"))
        pfx_bb.setFixedWidth(36)
        pfx_bb.clicked.connect(self._browse_pfx)
        pfx_row.addWidget(self.pfx_edit)
        pfx_row.addWidget(pfx_bb)
        self._pfx_lbl    = QLabel(t("cfg_pfx_path_label"))
        self._pfx_widget = QWidget()
        self._pfx_widget.setLayout(pfx_row)
        self._pfx_hint = QLabel("")
        self._pfx_hint.setStyleSheet("color: gray; font-size: 10px;")
        form.addRow(self._pfx_lbl, self._pfx_widget)
        form.addRow("", self._pfx_hint)

        # ── Gemeinsames Feld: CN ───────────────────────────────────────────
        # Zeigt in beiden Modi den CN aus dem Zertifikat (read-only)
        self.cert_cn_edit = QLineEdit()
        self.cert_cn_edit.setReadOnly(True)
        self.cert_cn_edit.setStyleSheet("color: gray;")
        self._cert_cn_lbl = QLabel(t("cfg_cert_cn_label"))
        form.addRow(self._cert_cn_lbl, self.cert_cn_edit)

        stab_lay.addLayout(form)

        # ── PKCS#11-Aktionen ───────────────────────────────────────────────
        self._pkcs11_test_widget = QWidget()
        test_row = QHBoxLayout(self._pkcs11_test_widget)
        test_row.setContentsMargins(0, 0, 0, 0)
        test_no_pin = QPushButton(t("cfg_test_btn_no_pin"))
        test_no_pin.clicked.connect(lambda: self._test_token(with_pin=False))
        test_with_pin = QPushButton(t("cfg_test_btn_with_pin"))
        test_with_pin.clicked.connect(lambda: self._test_token(with_pin=True))
        test_row.addWidget(test_no_pin)
        test_row.addWidget(test_with_pin)
        stab_lay.addWidget(self._pkcs11_test_widget)

        # ── PFX-Aktionen ───────────────────────────────────────────────────
        self._pfx_action_widget = QWidget()
        pfx_action_row = QHBoxLayout(self._pfx_action_widget)
        pfx_action_row.setContentsMargins(0, 0, 0, 0)
        self._pfx_show_cert_btn = QPushButton(t("cfg_pfx_show_cert_btn"))
        self._pfx_show_cert_btn.clicked.connect(self._show_pfx_cert)
        pfx_action_row.addWidget(self._pfx_show_cert_btn)
        pfx_action_row.addStretch()
        stab_lay.addWidget(self._pfx_action_widget)

        # Status-Label (beide Modi)
        self.status_lbl = QLabel("")
        self.status_lbl.setWordWrap(True)
        stab_lay.addWidget(self.status_lbl)
        stab_lay.addStretch()

        tabs.addTab(sig_tab, t("cfg_tab_pkcs11"))

        # ── Tab 2: TSA ────────────────────────────────────────────────────
        tsa_tab  = QWidget()
        tsa_form = QFormLayout(tsa_tab)
        tsa_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        self.tsa_url_edit = QLineEdit()
        self.tsa_url_edit.setPlaceholderText("http://tsa.baltstamp.lt")
        tsa_hint = QLabel(t("cfg_tsa_hint"))
        tsa_hint.setStyleSheet("color: gray; font-size: 10px;")
        tsa_hint.setWordWrap(True)
        tsa_form.addRow(t("cfg_tsa_url"), self.tsa_url_edit)
        tsa_form.addRow("", tsa_hint)

        # OCSP/PAdES-LTA-Checkbox
        self.ocsp_lta_chk = QCheckBox(t("cfg_ocsp_lta_label"))
        self._ocsp_hint_lbl = QLabel()
        self._ocsp_hint_lbl.setWordWrap(True)
        self._ocsp_hint_lbl.setStyleSheet("color: gray; font-size: 10px;")
        tsa_form.addRow("", self.ocsp_lta_chk)
        tsa_form.addRow("", self._ocsp_hint_lbl)

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

        # Modus-Wechsel verbinden (nach Widget-Erstellung)
        self._mode_combo.currentIndexChanged.connect(self._on_mode_changed)

    def _on_mode_changed(self, _index: int = -1) -> None:
        """Show/hide form rows based on selected signing mode."""
        pkcs11 = (self._mode_combo.currentData() == "pkcs11")
        # PKCS#11-spezifische Widgets
        for w in (self._lib_lbl, self._lib_widget,
                  self._key_id_lbl, self.key_id_edit, self._key_id_hint,
                  self._pin_lbl, self.pin_edit, self._pin_hint,
                  self._pkcs11_test_widget):
            w.setVisible(pkcs11)
        # PFX-spezifische Widgets
        for w in (self._pfx_lbl, self._pfx_widget, self._pfx_hint,
                  self._pfx_action_widget):
            w.setVisible(not pkcs11)
        self.status_lbl.setText("")
        self._update_ocsp_state()

    def _load_values(self) -> None:
        mode = self.config.get("pkcs11", "signer_mode")
        # Combobox: Index 0 = pfx, Index 1 = pkcs11
        idx = 1 if mode == "pkcs11" else 0
        self._mode_combo.blockSignals(True)
        self._mode_combo.setCurrentIndex(idx)
        self._mode_combo.blockSignals(False)
        self.lib_edit.setText(self.config.get("pkcs11", "lib_path"))
        self.key_id_edit.setText(self.config.get("pkcs11", "key_id"))
        self.cert_cn_edit.setText(self.config.get("pkcs11", "cert_cn"))
        # pfx_edit setzen ohne _on_pfx_path_changed auszulösen (kein Cache-Reset)
        self.pfx_edit.blockSignals(True)
        self.pfx_edit.setText(self.config.get("pkcs11", "pfx_path"))
        self.pfx_edit.blockSignals(False)
        self.tsa_url_edit.setText(self.config.get("tsa", "url"))
        self.ocsp_lta_chk.setChecked(self.config.getbool("tsa", "embed_validation_info"))
        self._on_mode_changed()
        self._update_pfx_hint()
        # Infos für bereits gespeicherten Pfad vorladen (ohne Passwort-Prompt)
        pfx_path = self.pfx_edit.text().strip()
        if pfx_path and mode == "pfx":
            try:
                self._pfx_info = _pfx_load_cert_info(pfx_path)
            except Exception:
                pass  # Passwortgeschützt – Cache bleibt leer bis User öffnet
        self._update_ocsp_state()

    def _browse_lib(self) -> None:
        start = self.config.get("paths", "last_lib_dir")
        if sys.platform == "win32":
            lib_filter = "DLL (*.dll);;Shared Libraries (*.so *.so.*);;All Files (*)"
        else:
            lib_filter = t("dlg_lib_filter")
        path, _ = QFileDialog.getOpenFileName(
            self, t("dlg_browse_lib"), start, lib_filter)
        if path:
            self.lib_edit.setText(path)
            self.config.set("paths", "last_lib_dir", str(Path(path).parent))

    def _browse_pfx(self) -> None:
        """Open file dialog to select a PFX/PKCS#12 file.

        After selection, certificate metadata is read immediately.  If the
        file is password-protected a password dialog is shown once; only the
        CN is stored in the config – the passphrase and the private key object
        are discarded as soon as the metadata has been extracted.
        """
        start = self.config.get("paths", "last_open_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("cfg_pfx_browse_title"), start, t("cfg_pfx_filter"))
        if not path:
            return
        self.pfx_edit.setText(path)
        self.config.set("paths", "last_open_dir", str(Path(path).parent))
        # Metadaten lesen – bei passwortgeschützter Datei erscheint ein Popup.
        # Passwort und privater Schlüssel werden nach dem Lesen verworfen.
        result = _pfx_load_with_prompt(self, path)
        if result is not None:
            info, _ = result   # passphrase wird hier verworfen
            self._pfx_info = info  # Metadaten cachen für "Zertifikat anzeigen"
            if info.get("cn"):
                self.cert_cn_edit.setText(info["cn"])
            self._update_ocsp_state()

    def _on_pfx_path_changed(self, _text: str) -> None:
        """Clear cached info and update hint when the PFX path field changes."""
        self._pfx_info = None
        self._update_pfx_hint()
        self._update_ocsp_state()

    def _update_pfx_hint(self) -> None:
        """Show whether the current PFX file is password-protected."""
        path = self.pfx_edit.text().strip()
        if not path or not Path(path).exists():
            self._pfx_hint.setText("")
            return
        try:
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
        """Enable/disable the OCSP checkbox based on cert type and signer mode.

        OCSP requires a CA-issued certificate with an AIA/OCSP extension.
        Self-signed certificates (detectable for PFX) cannot use OCSP.
        PKCS#11 hardware tokens always carry CA-issued certificates.
        """
        mode = self._mode_combo.currentData() or "pfx"
        if mode == "pfx":
            self_signed = bool(
                self._pfx_info and self._pfx_info.get("self_signed", False))
            if self_signed:
                self.ocsp_lta_chk.setEnabled(False)
                self.ocsp_lta_chk.setChecked(False)
                self._ocsp_hint_lbl.setText(t("cfg_ocsp_self_signed_hint"))
                self._ocsp_hint_lbl.setStyleSheet(
                    "color: #c07000; font-size: 10px;")
            else:
                self.ocsp_lta_chk.setEnabled(True)
                self._ocsp_hint_lbl.setText(t("cfg_ocsp_lta_hint"))
                self._ocsp_hint_lbl.setStyleSheet("color: gray; font-size: 10px;")
        else:
            # PKCS#11: immer CA-ausgestellt → immer verfügbar
            self.ocsp_lta_chk.setEnabled(True)
            self._ocsp_hint_lbl.setText(t("cfg_ocsp_lta_hint"))
            self._ocsp_hint_lbl.setStyleSheet("color: gray; font-size: 10px;")

    def _show_pfx_cert(self) -> None:
        """Open PfxInfoDialog using cached metadata (no second password prompt).

        If the cache is empty (e.g. dialog re-opened without re-selecting the
        file) the file is loaded again, prompting for a password if needed.
        """
        path = self.pfx_edit.text().strip()
        if not path:
            self.status_lbl.setText(t("cfg_pfx_no_file"))
            return
        if self._pfx_info is None:
            result = _pfx_load_with_prompt(self, path)
            if result is None:
                return
            info, _ = result
            self._pfx_info = info
        dlg = PfxInfoDialog(self, info=self._pfx_info)
        dlg.cn_selected.connect(self.cert_cn_edit.setText)
        dlg.exec()

    def _save_and_close(self) -> None:
        mode = self._mode_combo.currentData() or "pfx"
        self.config.set("pkcs11", "signer_mode", mode)
        self.config.set("pkcs11", "lib_path", self.lib_edit.text().strip())
        self.config.set("pkcs11", "key_id",   self.key_id_edit.text().strip())
        self.config.set("pkcs11", "cert_cn",  self.cert_cn_edit.text().strip())
        self.config.set("pkcs11", "pfx_path", self.pfx_edit.text().strip())
        self.config.set("tsa", "url", self.tsa_url_edit.text().strip())
        self.config.setbool("tsa", "embed_validation_info",
                            self.ocsp_lta_chk.isChecked())
        self.config.save()
        self.accept()

    def _test_token(self, with_pin: bool = False) -> None:
        lib_path = self.lib_edit.text().strip()
        # Sofortige UI-Rückmeldung vor dem blockierenden Token-Zugriff
        self.status_lbl.setText(t("status_token_reading"))
        QApplication.processEvents()
        try:
            import pkcs11 as p11
            lib   = p11.lib(lib_path)
            # Ersten Slot mit vorhandenem Token ermitteln
            slots = lib.get_slots(token_present=True)
            if not slots:
                raise RuntimeError("No token found.")
            token = slots[0].get_token()

            # all_items: Sammelliste aller Token-Objekte als Dicts.
            # Jedes Dict enthält mindestens "obj_class" und "label".
            all_items: list[dict] = []

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
                # Session mit PIN öffnen: dadurch werden auch private Schlüssel
                # sichtbar (auf TCOS-Karten ohne PIN sind sie nicht sichtbar)
                with token.open(rw=True, user_pin=pin) as session:
                    # Private Schlüssel lesen (nur nach Authentifizierung sichtbar)
                    for k in session.get_objects(
                            {p11.Attribute.CLASS: p11.ObjectClass.PRIVATE_KEY}):
                        item = _read_key_info(k, p11)
                        item["obj_class"] = "PRIVATE_KEY"
                        all_items.append(item)
                    # Zertifikate lesen
                    for c in session.get_objects(
                            {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}):
                        item = _read_cert_info(c, p11)
                        item["obj_class"] = "CERTIFICATE"
                        all_items.append(item)
                    # Öffentliche Schlüssel lesen
                    for k in session.get_objects(
                            {p11.Attribute.CLASS: p11.ObjectClass.PUBLIC_KEY}):
                        item = _read_key_info(k, p11)
                        item["obj_class"] = "PUBLIC_KEY"
                        all_items.append(item)
            else:
                # Open without PIN.  Most tokens expose private key metadata
                # without authentication (the key itself never leaves the
                # hardware).  TCOS cards hide private key objects completely
                # without PIN; in that case we offer derivation from the
                # public key labels as a fallback.
                # Öffentliche Session: private Schlüssel können leer sein (TCOS-Karten)
                with token.open() as session:
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

            # Zusammenfassung der gefundenen Objekte für das Status-Label
            n_priv  = sum(1 for i in all_items if i["obj_class"] == "PRIVATE_KEY")
            n_certs = sum(1 for i in all_items if i["obj_class"] == "CERTIFICATE")
            status = t("status_token_ok",
                       label=token.label.strip(), keys=n_priv, certs=n_certs)
            self.status_lbl.setText(status)

            # Token-Info-Dialog anzeigen; wenn der Benutzer einen Schlüssel
            # auswählt, werden key_id_edit und cert_cn_edit automatisch gefüllt
            dlg = TokenInfoDialog(self, token, all_items)
            dlg.key_selected.connect(
                lambda kid, cn: (self.key_id_edit.setText(kid),
                                 self.cert_cn_edit.setText(cn)))
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

    # Vordefinierte Datumsformate mit Beispielen für die Auswahlbox.
    # Das erste Element des Tupels ist das Python-strftime-Format,
    # das zweite ist ein Beispiel-String für die Anzeige im Dropdown.
    DATE_FORMATS: list[tuple[str, str]] = [
        ("%d.%m.%Y %H:%M",    "31.12.2025 14:30"),
        ("%d.%m.%Y",          "31.12.2025"),
        ("%Y-%m-%d %H:%M:%S", "2025-12-31 14:30:00"),
        ("%Y-%m-%d",          "2025-12-31"),
        ("%d/%m/%Y %H:%M",    "31/12/2025 14:30"),
        ("%B %d, %Y",         "December 31, 2025"),
    ]
    # Sentinel-Wert für den "Benutzerdefiniert…"-Eintrag in der Datumsformat-Combobox
    CUSTOM_FMT = "__custom__"

    def __init__(self, parent, config: AppConfig,
                 appearance: SigAppearance,
                 selected_fdef=None) -> None:
        super().__init__(parent)
        self.config        = config
        self.appearance    = appearance
        # selected_fdef: das aktuell ausgewählte Signaturfeld (für die Vorschaugröße);
        # None → keine feldgrößenabhängige Vorschau möglich
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
        # Vollbreite-Vorschau unterhalb der Tabs – zeigt die Signatur so,
        # wie sie im Unterschriftsfeld des PDFs erscheinen wird
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
        # "Speichern" schreibt Konfiguration und schließt Dialog
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

        # Zeile: Pfad-Eingabe (read-only) + "…"-Button + "Löschen"-Button
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
        # Steuerung des Layouts: Bild links/rechts, Rahmen, Bild-Text-Verhältnis
        lay_grp = QGroupBox(t("appdlg_tab_layout"))
        lg = QFormLayout(lay_grp)
        lg.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        # Combobox: Bild links ("img_left") oder rechts ("img_right")
        self.layout_combo = QComboBox()
        self.layout_combo.addItem(t("app_layout_img_left"),  "img_left")
        self.layout_combo.addItem(t("app_layout_img_right"), "img_right")
        # Bei Layout-Änderung: Beschriftungen des Sliders aktualisieren und
        # Vorschau neu rendern
        self.layout_combo.currentIndexChanged.connect(self._on_layout_changed_dlg)
        lg.addRow(t("app_layout_label"), self.layout_combo)

        # Checkbox: dünner Rahmen um das Signaturfeld
        self.chk_border = QCheckBox(t("appdlg_border"))
        self.chk_border.toggled.connect(self._update_preview)
        lg.addRow("", self.chk_border)

        # Image / text ratio slider
        # Slider steuert den Anteil des Bildes an der Gesamtbreite (10–70 %)
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
        # Checkbox aktiviert die Namensanzeige; Combobox wählt Quelle
        # (aus Zertifikat-CN oder benutzerdefinierter Text)
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
        # Ort der Signatur (z.B. "Berlin") – frei eingebbarer Text
        self.chk_location = QCheckBox(t("app_location_label"))
        self.location_edit = QLineEdit()
        gl.addWidget(self.chk_location, row, 0)
        gl.addWidget(self.location_edit, row, 1)
        row += 1

        # Reason
        # Signaturgrund (z.B. "Genehmigung") – frei eingebbarer Text
        self.chk_reason = QCheckBox(t("app_reason_label"))
        self.reason_edit = QLineEdit()
        gl.addWidget(self.chk_reason, row, 0)
        gl.addWidget(self.reason_edit, row, 1)
        row += 1

        # Date
        # Datum der Signatur – pyhanko fügt automatisch den Zeitstempel
        # über den %(ts)s-Platzhalter ein; das Format ist frei wählbar
        self.chk_date = QCheckBox(t("app_date_label"))
        date_col = QVBoxLayout()
        self.date_fmt_combo = QComboBox()
        for fmt, example in self.DATE_FORMATS:
            self.date_fmt_combo.addItem(f"{fmt}  →  {example}", fmt)
        self.date_fmt_combo.addItem("Custom…", self.CUSTOM_FMT)
        # Bei "Custom…" wird das Freitext-Feld eingeblendet
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
        # Schriftgröße in Punkten für den Text im Signaturfeld
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
        # Alle Checkboxen und Eingabefelder lösen bei Änderung eine Vorschau-
        # Aktualisierung aus; Checkboxen steuern zusätzlich die Aktivierung
        # der zugehörigen Eingabefelder
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
        # Freitext-Eingabe nur aktiv wenn Name aktiviert UND Modus "custom"
        self.name_custom_edit.setEnabled(
            name_on and self.name_mode_combo.currentData() == "custom")
        # Eingabefelder nur aktiv wenn die zugehörige Checkbox aktiviert ist
        self.location_edit.setEnabled(self.chk_location.isChecked())
        self.reason_edit.setEnabled(self.chk_reason.isChecked())
        self.date_fmt_combo.setEnabled(self.chk_date.isChecked())
        self.date_fmt_custom.setEnabled(self.chk_date.isChecked())
        self._update_preview()

    def _on_layout_changed_dlg(self) -> None:
        # Bei Layout-Änderung (Bild links/rechts) Slider-Beschriftungen aktualisieren
        self._update_ratio_labels()
        self._update_preview()

    def _on_date_fmt_changed(self) -> None:
        # Freitext-Eingabe ein-/ausblenden je nach Auswahl in der Combobox
        is_custom = self.date_fmt_combo.currentData() == self.CUSTOM_FMT
        self.date_fmt_custom.setVisible(is_custom)
        self._update_preview()

    def _on_ratio_changed(self, value: int) -> None:
        self._update_ratio_labels(value)
        self._update_preview()

    def _update_ratio_labels(self, value: int = None) -> None:
        # Beschriftungen links/rechts des Sliders aktualisieren.
        # Wenn Bild links: linkes Label zeigt Bildanteil, rechtes Textanteil.
        # Wenn Bild rechts: linkes Label zeigt Textanteil, rechtes Bildanteil.
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
        # Bild-Dateidialog; zuletzt genutztes Verzeichnis aus Konfig als Startpunkt
        start = self.config.get("paths", "last_img_dir")
        path, _ = QFileDialog.getOpenFileName(
            self, t("appdlg_browse_img"), start, t("appdlg_img_filter"))
        if path:
            self.img_path_edit.setText(path)
            self.config.set("paths", "last_img_dir", str(Path(path).parent))
            self._update_preview()

    def _clear_image(self) -> None:
        # Bildpfad löschen → Vorschau zeigt nur Text
        self.img_path_edit.clear()
        self._update_preview()

    def _update_preview(self) -> None:
        """Render preview using the currently selected signature field size."""
        # Aktuelle UI-Werte temporär in AppConfig schreiben (ohne auf Disk zu speichern)
        # damit SigAppearance.render_preview() die aktuellen Einstellungen liest
        self._apply_to_config(save=False)
        fdef = self.selected_fdef
        # Ohne ausgewähltes Feld: Hinweistext statt Vorschau anzeigen
        if fdef is None:
            self.full_preview.clear()
            self.full_preview.setText(t("ap_preview_hint"))
            self.full_preview.setStyleSheet(
                "background: #f0f0f0; border: 1px solid #ccc; color: gray;")
            return

        # Skalierung: Signaturfeld in den verfügbaren Vorschaubereich einpassen
        fw      = abs(fdef.x2 - fdef.x1)
        fh      = abs(fdef.y2 - fdef.y1)
        avail_w = max(10, self.full_preview.width()  - 4)
        avail_h = max(10, self.full_preview.height() - 4)
        scale   = min(avail_w / max(fw, 1), avail_h / max(fh, 1))
        pw      = max(10, int(fw * scale))
        ph      = max(10, int(fh * scale))

        # Vorschau-Pixmap vom SigAppearance-Renderer erzeugen lassen
        px = self.appearance.render_preview(
            pw, ph, pixels_per_point=DPI_SCALE * scale)

        # Vorschau-Pixmap auf grauen Canvas zentriert zeichnen
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
        # Vorschau bei Dialoggrößenänderung neu berechnen,
        # damit sie immer den verfügbaren Platz optimal ausfüllt
        super().resizeEvent(ev)
        self._update_preview()

    # ── Load / save ───────────────────────────────────────────────────────

    def _date_fmt_value(self) -> str:
        # Aktuell ausgewähltes Datumsformat zurückgeben:
        # Bei "Custom…" aus dem Freitext-Feld lesen, sonst aus der Combobox
        if self.date_fmt_combo.currentData() == self.CUSTOM_FMT:
            return self.date_fmt_custom.text().strip() or "%d.%m.%Y %H:%M"
        return self.date_fmt_combo.currentData() or "%d.%m.%Y %H:%M"

    def _load_values(self) -> None:
        # Alle Widgets aus der AppConfig befüllen (beim Dialog-Öffnen)
        self.img_path_edit.setText(self.config.get("appearance", "image_path"))

        idx = self.layout_combo.findData(self.config.get("appearance", "layout"))
        self.layout_combo.setCurrentIndex(max(0, idx))
        self.chk_border.setChecked(self.config.getbool("appearance", "show_border"))

        # Verhältnis-Slider: ungültige Werte auf gültigen Bereich clampen
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
        # Datumsformat: gespeichertes Format in der Combobox suchen;
        # falls nicht vorhanden → "Custom…" wählen und Freitext-Feld befüllen
        saved_fmt = self.config.get("appearance", "date_format") or "%d.%m.%Y %H:%M"
        fmt_idx   = self.date_fmt_combo.findData(saved_fmt)
        if fmt_idx >= 0:
            self.date_fmt_combo.setCurrentIndex(fmt_idx)
        else:
            custom_idx = self.date_fmt_combo.findData(self.CUSTOM_FMT)
            self.date_fmt_combo.setCurrentIndex(custom_idx)
            self.date_fmt_custom.setText(saved_fmt)
            self.date_fmt_custom.setVisible(True)

        # Schriftgröße: ungültige Werte abfangen
        try:
            fs = int(self.config.get("appearance", "font_size") or "8")
        except (ValueError, TypeError):
            fs = 8
        self.font_size_spin.setValue(max(5, min(24, fs)))

        # Checkbox-abhängige Felder aktivieren/deaktivieren
        self._on_checks_changed()

    def _apply_to_config(self, save: bool = True) -> None:
        # Alle aktuellen Widget-Werte in die AppConfig schreiben.
        # save=False: nur In-Memory (für Vorschau-Aktualisierung ohne Disk-Zugriff)
        # save=True: zusätzlich auf Disk persistieren
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
        # Alle Werte dauerhaft speichern und Dialog schließen
        self._apply_to_config(save=True)
        self.accept()


# ── Profile management dialogs ────────────────────────────────────────────────

_PROFILE_NAME_RE = re.compile(r'^[A-Za-z0-9äöüÄÖÜß _\-]+$')


def _validate_profile_name(name: str) -> str | None:
    """Return None if *name* is valid, else an i18n error key."""
    if not name:
        return "dlg_profile_empty_name"
    if not _PROFILE_NAME_RE.match(name):
        return "dlg_profile_invalid_name"
    return None


class ProfileManagerDialog(QDialog):
    """Combined profile management dialog: New, Rename, Delete, Close.

    Double-clicking a profile entry activates it and closes the dialog.
    After the dialog closes, check ``changes_made`` and ``switch_to``.
    """

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self.changes_made = False
        self.switch_to: str | None = None
        self.setWindowTitle(t("dlg_profile_mgr_title"))
        self.resize(340, 280)
        self._build_ui()

    def _build_ui(self) -> None:
        lay = QVBoxLayout(self)
        self._list = QListWidget()
        self._refresh_list()
        self._list.itemDoubleClicked.connect(self._on_item_double_clicked)
        lay.addWidget(self._list)

        btn_row = QHBoxLayout()
        self._btn_new    = QPushButton(t("dlg_profile_new_short"))
        self._btn_rename = QPushButton(t("dlg_profile_rename_btn"))
        self._btn_delete = QPushButton(t("dlg_profile_delete_btn"))
        btn_close        = QPushButton(t("dlg_token_close"))
        self._btn_new.clicked.connect(self._on_new)
        self._btn_rename.clicked.connect(self._on_rename)
        self._btn_delete.clicked.connect(self._on_delete)
        btn_close.clicked.connect(self.accept)
        btn_row.addStretch()
        btn_row.addWidget(self._btn_new)
        btn_row.addWidget(self._btn_rename)
        btn_row.addWidget(self._btn_delete)
        btn_row.addSpacing(12)
        btn_row.addWidget(btn_close)
        btn_row.addStretch()
        lay.addLayout(btn_row)

    def _refresh_list(self) -> None:
        self._list.clear()
        active = self.config.active_profile
        for name in self.config.list_profiles():
            label = f"{name}  {t('dlg_profile_active')}" if name == active else name
            self._list.addItem(label)
        if self._list.count() > 0:
            self._list.setCurrentRow(0)

    def _current_name(self) -> str | None:
        row = self._list.currentRow()
        if row < 0:
            return None
        profiles = self.config.list_profiles()
        return profiles[row] if row < len(profiles) else None

    def _on_item_double_clicked(self, _item) -> None:
        name = self._current_name()
        if name is None:
            return
        if name != self.config.active_profile:
            self.config.switch_profile(name)
            self.config.save()
            self.changes_made = True
            self.switch_to = name
        self.accept()

    def _on_new(self) -> None:
        from PyQt6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(
            self, t("dlg_profile_new_title"), t("dlg_profile_new_label"))
        if not ok:
            return
        name = name.strip()
        err = _validate_profile_name(name)
        if err:
            QMessageBox.warning(self, t("dlg_profile_new_title"), t(err))
            return
        if name in self.config.list_profiles():
            answer = QMessageBox.question(
                self, t("dlg_profile_exists_title"),
                t("dlg_profile_exists_msg", name=name))
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.config.new_profile_from_current(name)
        self.config.save()
        self.changes_made = True
        self.switch_to = name
        self._refresh_list()

    def _on_rename(self) -> None:
        from PyQt6.QtWidgets import QInputDialog
        old = self._current_name()
        if old is None:
            return
        new, ok = QInputDialog.getText(
            self, t("dlg_profile_rename_title"),
            t("dlg_profile_rename_label"), text=old)
        if not ok:
            return
        new = new.strip()
        if new == old:
            return
        err = _validate_profile_name(new)
        if err:
            QMessageBox.warning(self, t("dlg_profile_rename_title"), t(err))
            return
        if new in self.config.list_profiles():
            QMessageBox.warning(self, t("dlg_profile_rename_title"),
                                t("dlg_profile_name_exists"))
            return
        self.config.rename_profile(old, new)
        self.config.save()
        self.changes_made = True
        if self.config.active_profile == new:
            self.switch_to = new
        self._refresh_list()

    def _on_delete(self) -> None:
        name = self._current_name()
        if name is None:
            return
        profiles = self.config.list_profiles()

        # Last profile – offer reset instead
        if len(profiles) == 1:
            msg = QMessageBox(self)
            msg.setWindowTitle(t("dlg_profile_last_title"))
            msg.setText(t("dlg_profile_last_msg"))
            btn_reset = msg.addButton(t("dlg_profile_reset_btn"),
                                      QMessageBox.ButtonRole.AcceptRole)
            msg.addButton(t("cfg_cancel_btn"), QMessageBox.ButtonRole.RejectRole)
            msg.exec()
            if msg.clickedButton() is btn_reset:
                self.config.reset_profile(name)
                self.config.save()
                self.changes_made = True
                self.switch_to = name
                self._refresh_list()
            return

        # Active profile
        if name == self.config.active_profile:
            remaining = [p for p in profiles if p != name]
            next_profile = remaining[0]
            answer = QMessageBox.question(
                self, t("dlg_profile_delete_title"),
                t("dlg_profile_delete_active_msg", name=name, next=next_profile))
            if answer != QMessageBox.StandardButton.Yes:
                return
            self.config.delete_profile(name)
            self.config.switch_profile(next_profile)
            self.config.save()
            self.switch_to = next_profile
        else:
            answer = QMessageBox.question(
                self, t("dlg_profile_delete_title"),
                t("dlg_profile_delete_confirm_msg", name=name))
            if answer != QMessageBox.StandardButton.Yes:
                return
            self.config.delete_profile(name)
            self.config.save()

        self.changes_made = True
        self._refresh_list()


class ProfileSelectDialog(QDialog):
    """List all profiles; clicking an entry activates it immediately."""

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self.selected_profile: str | None = None
        self.setWindowTitle(t("dlg_profile_select_title"))
        self.resize(320, 260)
        self._build_ui()

    def _build_ui(self) -> None:
        lay = QVBoxLayout(self)
        self._list = QListWidget()
        active = self.config.active_profile
        for name in self.config.list_profiles():
            label = f"{name}  {t('dlg_profile_active')}" if name == active else name
            self._list.addItem(label)
            if name == active:
                self._list.setCurrentRow(self._list.count() - 1)
        # Single click on a non-active profile activates and closes
        self._list.itemClicked.connect(self._on_item_clicked)
        lay.addWidget(self._list)

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton(t("cfg_cancel_btn"))
        btn_cancel.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(btn_cancel)
        btn_row.addStretch()
        lay.addLayout(btn_row)

    def _current_name(self) -> str | None:
        row = self._list.currentRow()
        if row < 0:
            return None
        profiles = self.config.list_profiles()
        return profiles[row] if row < len(profiles) else None

    def _on_item_clicked(self, _item) -> None:
        name = self._current_name()
        if name is None:
            return
        if name != self.config.active_profile:
            self.selected_profile = name
        self.accept()


class NewProfileDialog(QDialog):
    """Enter a name for a new profile (copy of current settings)."""

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self.profile_name: str | None = None
        self.setWindowTitle(t("dlg_profile_new_title"))
        self.resize(340, 120)
        self._build_ui()

    def _build_ui(self) -> None:
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self._name_edit = QLineEdit()
        self._name_edit.returnPressed.connect(self._accept)
        form.addRow(t("dlg_profile_new_label"), self._name_edit)
        lay.addLayout(form)

        btn_row = QHBoxLayout()
        self._btn_create = QPushButton(t("dlg_profile_new_btn"))
        self._btn_create.clicked.connect(self._accept)
        btn_cancel = QPushButton(t("cfg_cancel_btn"))
        btn_cancel.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(self._btn_create)
        btn_row.addStretch()
        lay.addLayout(btn_row)

    def _accept(self) -> None:
        name = self._name_edit.text().strip()
        err = _validate_profile_name(name)
        if err:
            QMessageBox.warning(self, t("dlg_profile_new_title"), t(err))
            return
        if name in self.config.list_profiles():
            answer = QMessageBox.question(
                self, t("dlg_profile_exists_title"),
                t("dlg_profile_exists_msg", name=name))
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.profile_name = name
        self.accept()


class RenameProfileDialog(QDialog):
    """Select a profile from a list and give it a new name."""

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self.old_name: str | None = None
        self.new_name: str | None = None
        self.setWindowTitle(t("dlg_profile_rename_title"))
        self.resize(340, 300)
        self._build_ui()

    def _build_ui(self) -> None:
        lay = QVBoxLayout(self)
        self._list = QListWidget()
        active = self.config.active_profile
        for name in self.config.list_profiles():
            label = f"{name}  {t('dlg_profile_active')}" if name == active else name
            self._list.addItem(label)
            if name == active:
                self._list.setCurrentRow(self._list.count() - 1)
        self._list.itemSelectionChanged.connect(self._on_selection)
        lay.addWidget(self._list)

        form = QFormLayout()
        self._name_edit = QLineEdit()
        self._name_edit.returnPressed.connect(self._accept)
        form.addRow(t("dlg_profile_rename_label"), self._name_edit)
        lay.addLayout(form)

        btn_row = QHBoxLayout()
        self._btn_rename = QPushButton(t("dlg_profile_rename_btn"))
        self._btn_rename.clicked.connect(self._accept)
        btn_cancel = QPushButton(t("cfg_cancel_btn"))
        btn_cancel.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(self._btn_rename)
        btn_row.addStretch()
        lay.addLayout(btn_row)
        self._on_selection()

    def _current_name(self) -> str | None:
        row = self._list.currentRow()
        if row < 0:
            return None
        profiles = self.config.list_profiles()
        return profiles[row] if row < len(profiles) else None

    def _on_selection(self) -> None:
        self._name_edit.setText(self._current_name() or "")

    def _accept(self) -> None:
        old = self._current_name()
        if old is None:
            return
        new = self._name_edit.text().strip()
        err = _validate_profile_name(new)
        if err:
            QMessageBox.warning(self, t("dlg_profile_rename_title"), t(err))
            return
        if new == old:
            self.reject()
            return
        if new in self.config.list_profiles():
            QMessageBox.warning(self, t("dlg_profile_rename_title"),
                                t("dlg_profile_name_exists"))
            return
        self.old_name = old
        self.new_name = new
        self.accept()


class DeleteProfileDialog(QDialog):
    """Select a profile to delete; dialog stays open for further deletions.

    After closing, check ``changes_made`` and ``switch_to`` in the caller.
    The dialog performs deletions and profile switches directly on *config*.
    """

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self.changes_made = False   # True if at least one deletion/reset occurred
        self.switch_to: str | None = None  # last switch target (for UI refresh)
        self.setWindowTitle(t("dlg_profile_delete_title"))
        self.resize(320, 260)
        self._build_ui()

    def _build_ui(self) -> None:
        lay = QVBoxLayout(self)
        self._list = QListWidget()
        self._refresh_list()
        lay.addWidget(self._list)

        btn_row = QHBoxLayout()
        self._btn_delete = QPushButton(t("dlg_profile_delete_btn"))
        self._btn_delete.clicked.connect(self._on_delete)
        btn_cancel = QPushButton(t("cfg_cancel_btn"))
        btn_cancel.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(self._btn_delete)
        btn_row.addStretch()
        lay.addLayout(btn_row)

    def _refresh_list(self) -> None:
        """Rebuild the list from current profile state."""
        self._list.clear()
        active = self.config.active_profile
        for name in self.config.list_profiles():
            label = f"{name}  {t('dlg_profile_active')}" if name == active else name
            self._list.addItem(label)
        if self._list.count() > 0:
            self._list.setCurrentRow(0)

    def _current_name(self) -> str | None:
        row = self._list.currentRow()
        if row < 0:
            return None
        profiles = self.config.list_profiles()
        return profiles[row] if row < len(profiles) else None

    def _on_delete(self) -> None:
        name = self._current_name()
        if name is None:
            return
        profiles = self.config.list_profiles()

        # Last profile – offer reset instead
        if len(profiles) == 1:
            msg = QMessageBox(self)
            msg.setWindowTitle(t("dlg_profile_last_title"))
            msg.setText(t("dlg_profile_last_msg"))
            btn_reset = msg.addButton(t("dlg_profile_reset_btn"),
                                      QMessageBox.ButtonRole.AcceptRole)
            msg.addButton(t("cfg_cancel_btn"), QMessageBox.ButtonRole.RejectRole)
            msg.exec()
            if msg.clickedButton() is btn_reset:
                self.config.reset_profile(name)
                self.config.save()
                self.changes_made = True
                self.switch_to = name
                self._refresh_list()
            return

        # Active profile – warn and confirm
        if name == self.config.active_profile:
            remaining = [p for p in profiles if p != name]
            next_profile = remaining[0]
            answer = QMessageBox.question(
                self, t("dlg_profile_delete_title"),
                t("dlg_profile_delete_active_msg", name=name, next=next_profile))
            if answer != QMessageBox.StandardButton.Yes:
                return
            self.config.delete_profile(name)
            self.config.switch_profile(next_profile)
            self.config.save()
            self.switch_to = next_profile
        else:
            answer = QMessageBox.question(
                self, t("dlg_profile_delete_title"),
                t("dlg_profile_delete_confirm_msg", name=name))
            if answer != QMessageBox.StandardButton.Yes:
                return
            self.config.delete_profile(name)
            self.config.save()

        self.changes_made = True
        self._refresh_list()


class DocMDPDialog(QDialog):
    """Ask the user which docMDP restriction to apply to the first signature.

    The selected value is one of ``"none"``, ``"p2"``, or ``"p1"`` and can be
    read from ``self.docmdp`` after the dialog is accepted.  The caller is
    responsible for persisting the value back to the profile config.
    """

    def __init__(self, initial: str = "none", parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(t("dlg_docmdp_title"))
        self.docmdp = initial

        lay = QVBoxLayout(self)

        lbl = QLabel(t("dlg_docmdp_info"))
        lbl.setWordWrap(True)
        lay.addWidget(lbl)

        self._rb_none = QRadioButton(t("dlg_docmdp_none"))
        self._rb_p2   = QRadioButton(t("dlg_docmdp_p2"))
        self._rb_p1   = QRadioButton(t("dlg_docmdp_p1"))

        for rb, val in ((self._rb_none, "none"),
                        (self._rb_p2,   "p2"),
                        (self._rb_p1,   "p1")):
            lay.addWidget(rb)
            if val == initial:
                rb.setChecked(True)

        if not any(rb.isChecked()
                   for rb in (self._rb_none, self._rb_p2, self._rb_p1)):
            self._rb_none.setChecked(True)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setText(t("btn_ok"))
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText(t("btn_cancel"))
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def _on_accept(self) -> None:
        if self._rb_p2.isChecked():
            self.docmdp = "p2"
        elif self._rb_p1.isChecked():
            self.docmdp = "p1"
        else:
            self.docmdp = "none"
        self.accept()


class CertChainDetailWindow(QWidget):
    """Inspector window showing the certificate chain for one signature or TSA token.

    Acts as a singleton inspector: calling ``show_chain`` replaces the current
    content so the user can switch between chains without opening new windows.
    Geometry (position + size) is persisted in the global ``AppConfig`` under
    the ``[cert_detail_window]`` section.
    """

    # Colour constants reused from validation_dialog
    _GREEN = "#1a7a1a"
    _RED   = "#9a0000"
    _GREY  = "#666666"

    def __init__(self, config, parent=None) -> None:
        from PyQt6.QtCore import Qt
        super().__init__(parent, Qt.WindowType.Dialog)
        self._config = config
        self._setup_ui()
        self._restore_geometry()

    # ── UI ────────────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        from PyQt6.QtWidgets import QPushButton
        from PyQt6.QtCore import Qt
        lay = QVBoxLayout(self)
        lay.setSpacing(4)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(2)
        self._tree.header().hide()
        self._tree.setAlternatingRowColors(True)
        self._tree.setSelectionMode(QTreeWidget.SelectionMode.NoSelection)
        self._tree.header().setStretchLastSection(True)
        lay.addWidget(self._tree)

        bot = QHBoxLayout()
        self._overall_lbl = QLabel()
        self._overall_lbl.setContentsMargins(2, 2, 2, 2)
        bot.addWidget(self._overall_lbl)
        bot.addStretch()
        close_btn = QPushButton(t("cert_win_close"))
        close_btn.clicked.connect(self.close)
        bot.addWidget(close_btn)
        lay.addLayout(bot)

    # ── Public API ────────────────────────────────────────────────────────

    def show_chain(self, chain: list, title: str,
                   overall_status, cn: str) -> None:
        """Replace displayed chain and update the window title."""
        from .validation_result import ValidationStatus, CertSource
        self.setWindowTitle(title)
        self._tree.clear()

        chain_len = len(chain)
        for cert in chain:
            self._add_cert_item(cert, chain_len)

        self._tree.resizeColumnToContents(0)
        self._tree.expandAll()

        # Overall status line
        label, color = self._status_label_color(overall_status, chain)
        txt = f"{t('cert_win_label_overall')}:  {label}"
        self._overall_lbl.setText(txt)
        self._overall_lbl.setStyleSheet(
            f"font-weight: bold; color: {color};" if color else "")

        if not self.isVisible():
            self.show()
        self.raise_()

    # ── Helpers ───────────────────────────────────────────────────────────

    def _add_cert_item(self, cert, chain_len: int = 0) -> None:
        from .validation_result import CertSource, ValidationStatus
        from PyQt6.QtGui import QFont

        is_self_signed = cert.is_root and chain_len == 1
        if is_self_signed:
            role = t("cert_win_role_self_signed")
        else:
            role = self._cert_role(cert)
        cn   = self._cn_from_subject(cert.subject)

        top = QTreeWidgetItem(self._tree)
        top.setFlags(top.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        top.setText(0, cn)
        top.setText(1, role)
        f = QFont()
        f.setBold(True)
        top.setFont(0, f)

        if cert.source == CertSource.NOT_FOUND:
            top.setForeground(0, QColor(self._RED))
            top.setForeground(1, QColor(self._RED))

        issuer_display = (t("cert_win_self_signed_issuer")
                          if is_self_signed
                          else self._cn_from_subject(cert.issuer))
        self._add_sub(top, t("cert_win_label_issuer"), issuer_display)
        self._add_sub(top, t("cert_win_label_valid"),
                      self._fmt_validity(cert))
        self._add_sub(top, t("cert_win_label_source"),
                      self._source_text(cert.source))
        if cert.ocsp is not None:
            self._add_sub(top, t("cert_win_label_ocsp"),
                          self._ocsp_text(cert.ocsp))

    def _add_sub(self, parent: QTreeWidgetItem,
                 label: str, value: str) -> QTreeWidgetItem:
        sub = QTreeWidgetItem(parent)
        sub.setFlags(sub.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        sub.setText(0, label)
        sub.setForeground(0, QColor(self._GREY))
        sub.setText(1, value)
        return sub

    @staticmethod
    def _cert_role(cert) -> str:
        from .validation_result import CertSource
        if cert.source == CertSource.NOT_FOUND:
            return "?"
        if cert.is_root:
            return t("cert_win_role_root")
        if cert.is_ca:
            return t("cert_win_role_intermediate")
        return t("cert_win_role_ee")

    @staticmethod
    def _cn_from_subject(subject: str) -> str:
        sep = ";" if ";" in subject else ","
        for part in subject.split(sep):
            part = part.strip()
            colon = part.find(":")
            if colon > 0:
                key = part[:colon].strip()
                if key in ("Common Name", "CN"):
                    return part[colon + 1:].strip()
        return subject.split(sep)[0].strip() if subject else "?"

    @staticmethod
    def _fmt_validity(cert) -> str:
        from datetime import datetime
        vf, vu = cert.valid_from, cert.valid_until
        if vf == datetime.min or vu == datetime.max:
            return "–"
        return f"{vf.strftime('%d.%m.%Y')} – {vu.strftime('%d.%m.%Y')}"

    @staticmethod
    def _source_text(source) -> str:
        from .validation_result import CertSource
        return {
            CertSource.EMBEDDED:   t("cert_win_source_embedded"),
            CertSource.CERTIFI:    t("cert_win_source_certifi"),
            CertSource.SYSTEM:     t("cert_win_source_system"),
            CertSource.DOWNLOADED: t("cert_win_source_downloaded"),
            CertSource.NOT_FOUND:  t("cert_win_source_not_found"),
            CertSource.EU_TSL:     t("cert_win_source_eu_tsl"),
        }.get(source, t("cert_win_source_unknown"))

    @staticmethod
    def _ocsp_text(ocsp) -> str:
        status_map = {
            "good":    t("cert_win_ocsp_good"),
            "revoked": t("cert_win_ocsp_revoked"),
            "unknown": t("cert_win_ocsp_unknown"),
        }
        label = status_map.get(ocsp.cert_status, t("cert_win_ocsp_not_checked"))
        if ocsp.produced_at:
            label += f"  ({ocsp.produced_at.strftime('%d.%m.%Y')})"
        return label

    @staticmethod
    def _status_label_color(status, chain) -> tuple[str, str]:
        from .validation_result import ValidationStatus, CertSource
        if status == ValidationStatus.VALID:
            return t("val_chain_valid"), "#1a7a1a"
        if status == ValidationStatus.INVALID:
            # Determine reason
            if any(c.source == CertSource.NOT_FOUND for c in chain):
                return t("val_chain_incomplete"), "#9a0000"
            ee = chain[0] if chain else None
            if ee and ee.ocsp and ee.ocsp.cert_status == "revoked":
                return t("val_chain_revoked"), "#9a0000"
            return t("val_chain_expired"), "#9a0000"
        if status == ValidationStatus.UNKNOWN:
            if len(chain) == 1 and chain[0].is_root:
                return t("val_chain_self_signed"), "#8a6000"
            root = chain[-1] if chain else None
            if root and root.source == CertSource.CERTIFI:
                return t("val_chain_unknown_revoc"), "#8a6000"
            return t("val_chain_unknown_root"), "#8a6000"
        return t("val_chain_not_checked"), ""

    # ── Geometry persistence ──────────────────────────────────────────────

    def _restore_geometry(self) -> None:
        try:
            x = int(self._config.get("cert_detail_window", "x"))
            y = int(self._config.get("cert_detail_window", "y"))
            w = int(self._config.get("cert_detail_window", "width"))
            h = int(self._config.get("cert_detail_window", "height"))
            self.resize(max(300, w), max(200, h))
            if x >= 0 and y >= 0:
                self.move(x, y)
        except Exception:
            self.resize(520, 420)

    def closeEvent(self, event) -> None:
        try:
            geo = self.geometry()
            self._config.set("cert_detail_window", "x",      str(geo.x()))
            self._config.set("cert_detail_window", "y",      str(geo.y()))
            self._config.set("cert_detail_window", "width",  str(geo.width()))
            self._config.set("cert_detail_window", "height", str(geo.height()))
            self._config.save()
        except Exception:
            pass
        super().closeEvent(event)
