# SPDX-License-Identifier: GPL-3.0-or-later
"""QES trust store: on-demand TSL loading backed by EU LOTL.

## Architektur

Die Klasse :class:`QesTrustStore` definiert ein abstraktes Interface.
:class:`XmlCacheTrustStore` ist die erste Implementierung und speichert die
TSL-XML-Dateien lokal.  Zukünftige Backends (NSS, Windows-CAPI) können ohne
Änderungen am aufrufenden Code eingesteckt werden.

## Vertrauen entsteht in zwei Schritten

1. **AIA** (Authority Information Access, Erweiterung im Zertifikat selbst)
   liefert die Kette: Signing-Cert → Intermediate → Root.  AIA ist eine
   Selbstauskunft – ein Angreifer kann beliebige URLs eintragen.

2. **LOTL** (EU List of Trusted Lists, `ec.europa.eu`) bestätigt, dass ein
   Root oder eine Intermediate-CA offiziell als Qualified Trust Service
   Provider anerkannt ist.  Die LOTL wird über HTTPS geladen; der TLS-Anker
   ist certifi (Mozilla-Bundle).

Erst die Kombination macht es sicher: AIA findet den Weg, LOTL bestätigt das
Ziel.  Ein AIA-Root ohne LOTL-Eintrag wird niemals als ``extra_trust_root``
akzeptiert.

## Lokaler Cache

::

    ~/.config/pdf-signer/tsl_cache/
        lotl_urls.json      ← [{country, url}], ~43 Einträge, ~3 KB
        tsl_DE.xml          ← DE-TSL, erst nach erstem DE-Dokument vorhanden
        tsl_AT.xml          ← AT-TSL, erst nach erstem AT-Dokument
        ...

Der Cache wird *nie* automatisch beim Programmstart befüllt.  Jede
Netzwerkaktivität passiert on-demand und nur mit expliziter Zustimmung
(``auto_fetch=True`` oder Nutzer-Dialog).

Die Gültigkeit einer TSL-Datei wird über das ``NextUpdate``-Element im XML
geprüft.  Nach Ablauf wird die TSL beim nächsten Zugriff neu geladen.

## Fingerprint-Abgleich

Für jedes AIA-Root-Zertifikat prüft :meth:`XmlCacheTrustStore.is_trusted`
den SHA-256-Fingerprint gegen *alle* gecachten TSL-XMLs.  Trifft es zu, ist
das Zertifikat LOTL-bestätigt und darf als ``extra_trust_root`` verwendet
werden.  Andernfalls bleibt es in ``other_certs`` (nur Kettenaufbau, kein
Vertrauen).

## Bekannte Einschränkung: keine XMLDSig-Prüfung

LOTL und nationale TSLs sind nach ETSI TS 119 612 mit einer
**XML Digital Signature (XMLDSig)** signiert – ein Format, das grundlegend
anders aufgebaut ist als die CMS/PKCS#7-Signaturen in PDFs.  Die Prüfung
erfordert XML-Kanonisierung (C14N) und XMLDSig-Envelope-Parsing; beides
deckt der vorhandene Stack (pyhanko + asn1crypto) nicht ab.  Eine
vollständige Implementierung würde ``xmlsec`` + ``lxml`` (native C-Bibliothek
``libxmlsec1``) erfordern.

Beim **Download** ist die Integrität durch TLS gesichert (Anker: certifi).
Im **Disk-Cache** besteht ohne XMLDSig-Prüfung kein kryptografischer Schutz
gegen nachträgliche Manipulation der TSL-Dateien.  Da dafür Schreibzugriff
auf ``~/.config/pdf-signer/tsl_cache/`` nötig wäre, ist das Risiko in der
Praxis gering.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

from .config import CONFIG_DIR

_log = logging.getLogger(__name__)

LOTL_URL  = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
_TSL_NS   = "http://uri.etsi.org/02231/v2#"
_CACHE_DIR = CONFIG_DIR / "tsl_cache"


# ── Abstract interface ────────────────────────────────────────────────────────

class QesTrustStore(ABC):
    """Interface für QES-Zertifikatsvertrauen.

    Trennschicht zwischen ValidationWorker und konkreter Speicherung.
    Implementierungen: :class:`XmlCacheTrustStore` (aktuell),
    NssTrustStore / WindowsStoreTrustStore (geplant).
    """

    @abstractmethod
    def is_trusted(self, der: bytes) -> bool:
        """True wenn das DER-Zertifikat in einer gecachten nationalen TSL steht."""

    @abstractmethod
    def has_lotl_urls(self) -> bool:
        """True wenn die LOTL-URL-Liste lokal vorhanden ist (auch wenn abgelaufen)."""

    @abstractmethod
    def lotl_urls_valid(self) -> bool:
        """True wenn die LOTL-URL-Liste vorhanden *und* noch nicht abgelaufen ist."""

    @abstractmethod
    def fetch_lotl_urls(self, timeout: int = 10) -> bool:
        """LOTL herunterladen und nationale TSL-URLs speichern.  True bei Erfolg."""

    @abstractmethod
    def tsl_is_cached(self, country: str) -> bool:
        """True wenn eine gültige TSL-XML für das Länderkürzel vorhanden ist."""

    @abstractmethod
    def fetch_tsl(self, country: str, timeout: int = 10) -> bool:
        """Nationale TSL herunterladen und cachen.  True bei Erfolg."""

    @abstractmethod
    def country_hint(self, cert_der: bytes) -> Optional[str]:
        """ISO-Länderkürzel aus dem Issuer-DN des Zertifikats extrahieren."""

    @abstractmethod
    def cached_countries(self) -> list[str]:
        """Liste der Länderkürzel mit lokal gecachten TSLs."""

    @abstractmethod
    def cache_info(self) -> dict:
        """Status-Informationen über den lokalen Cache.

        Returns a dict with:
        - ``has_lotl_urls`` (bool)
        - ``lotl_urls_valid`` (bool)
        - ``lotl_next_update`` (datetime or None)
        - ``lotl_url_count`` (int)
        - ``lotl_urls_size_kb`` (float)
        - ``tsls`` (list of dicts, one per cached TSL file):
            - ``country`` (str)
            - ``next_update`` (datetime or None)
            - ``valid`` (bool)
            - ``size_kb`` (float)
        """

    @abstractmethod
    def clear_cache(self, keep_urls: bool = False) -> None:
        """Lokalen Cache leeren.

        Args:
            keep_urls: Wenn True, wird ``lotl_urls.json`` behalten;
                       nur die TSL-XML-Dateien werden gelöscht.
        """


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tag(local: str) -> str:
    return f"{{{_TSL_NS}}}{local}"


def _fetch_url(url: str, timeout: int) -> Optional[str]:
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        _log.debug("LOTL: fetch failed (%s): %s", url, exc)
        return None


# ── XmlCacheTrustStore ────────────────────────────────────────────────────────

class XmlCacheTrustStore(QesTrustStore):
    """TSL-XML-basierter Trust Store mit lokalem Disk-Cache.

    Speichert nur die TSL-Quelldokumente (XML), keine einzelnen Zertifikate.
    Fingerprint-Abgleich erfolgt zur Laufzeit durch Parsen der gecachten XMLs.
    """

    def __init__(self) -> None:
        self._cache_dir       = _CACHE_DIR
        self._urls_file       = self._cache_dir / "lotl_urls.json"
        self._urls: list[dict] = []          # [{country, url}, ...]
        self._lotl_next_update: Optional[datetime] = None
        self._fp_cache: dict[bytes, bool] = {}  # fingerprint → trusted (in-process)
        self._load_urls()

    # ── LOTL URL list ─────────────────────────────────────────────────────

    def _load_urls(self) -> None:
        if not self._urls_file.exists():
            return
        try:
            raw = json.loads(self._urls_file.read_text(encoding="utf-8"))
        except Exception:
            return
        # Support both old list format [{country,url},...] and new dict format
        # {"next_update": "...", "urls": [{country,url},...]}
        if isinstance(raw, list):
            self._urls = raw
            self._lotl_next_update = None
        elif isinstance(raw, dict):
            self._urls = raw.get("urls", [])
            nu_str = raw.get("next_update")
            if nu_str:
                try:
                    self._lotl_next_update = datetime.fromisoformat(
                        nu_str.replace("Z", "+00:00"))
                except Exception:
                    self._lotl_next_update = None

    def has_lotl_urls(self) -> bool:
        return len(self._urls) > 0

    def lotl_urls_valid(self) -> bool:
        if not self._urls:
            return False
        if self._lotl_next_update is not None:
            return self._lotl_next_update > datetime.now(timezone.utc)
        # Fallback: accept if file is younger than 30 days
        if self._urls_file.exists():
            age = datetime.now(timezone.utc) - datetime.fromtimestamp(
                self._urls_file.stat().st_mtime, tz=timezone.utc)
            return age < timedelta(days=30)
        return False

    def fetch_lotl_urls(self, timeout: int = 10) -> bool:
        text = _fetch_url(LOTL_URL, timeout)
        if not text:
            return False
        try:
            root = ET.fromstring(text)
        except Exception as exc:
            _log.debug("LOTL: XML parse error: %s", exc)
            return False

        urls: list[dict] = []
        for ptr in root.iter(_tag("OtherTSLPointer")):
            loc       = ptr.find(_tag("TSLLocation"))
            territory = ptr.find(f".//{_tag('SchemeTerritory')}")
            if loc is None or not loc.text:
                continue
            url = loc.text.strip()
            if not url.startswith("http"):
                continue
            country = (territory.text.strip()
                       if territory is not None and territory.text else "")
            urls.append({"country": country, "url": url})

        if not urls:
            return False

        # Extract <NextUpdate><dateTime> from LOTL SchemeInformation
        next_update: Optional[datetime] = None
        try:
            nu_elem = root.find(
                f".//{_tag('SchemeInformation')}/{_tag('NextUpdate')}/{_tag('dateTime')}")
            if nu_elem is None:
                # Some LOTL versions place NextUpdate directly under root
                nu_elem = root.find(
                    f".//{_tag('NextUpdate')}/{_tag('dateTime')}")
            if nu_elem is not None and nu_elem.text:
                next_update = datetime.fromisoformat(
                    nu_elem.text.strip().replace("Z", "+00:00"))
                _log.info("LOTL: next update: %s", next_update.isoformat())
        except Exception as exc:
            _log.debug("LOTL: could not parse NextUpdate: %s", exc)

        self._urls = urls
        self._lotl_next_update = next_update
        data = {
            "next_update": next_update.isoformat() if next_update else None,
            "urls": urls,
        }
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            self._urls_file.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8")
        except Exception as exc:
            _log.debug("LOTL: could not save URL list: %s", exc)

        _log.info("LOTL: cached %d national TSL URLs", len(urls))
        return True

    # ── National TSL loading ──────────────────────────────────────────────

    def _tsl_path(self, country: str) -> Path:
        return self._cache_dir / f"tsl_{country.upper()}.xml"

    def _tsl_next_update(self, path: Path) -> Optional[datetime]:
        """Return NextUpdate datetime from a cached TSL XML, or None."""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            root = ET.fromstring(text)
            nu = root.find(f".//{_tag('NextUpdate')}/{_tag('dateTime')}")
            if nu is not None and nu.text:
                return datetime.fromisoformat(
                    nu.text.strip().replace("Z", "+00:00"))
        except Exception:
            pass
        return None

    def tsl_is_cached(self, country: str) -> bool:
        path = self._tsl_path(country)
        if not path.exists():
            return False
        nu = self._tsl_next_update(path)
        if nu is not None:
            return nu > datetime.now(timezone.utc)
        # Fallback: accept if file is younger than 7 days
        age = datetime.now(timezone.utc) - datetime.fromtimestamp(
            path.stat().st_mtime, tz=timezone.utc)
        return age < timedelta(days=7)

    def _url_for_country(self, country: str) -> Optional[str]:
        cc = country.upper()
        for entry in self._urls:
            if entry.get("country", "").upper() == cc:
                url = entry.get("url", "")
                if url.lower().endswith(".xml") or url.lower().endswith(".xtsl"):
                    return url
        return None

    def fetch_tsl(self, country: str, timeout: int = 10) -> bool:
        url = self._url_for_country(country)
        if not url:
            _log.debug("LOTL: no XML URL for country %s", country)
            return False

        text = _fetch_url(url, timeout)
        if not text:
            return False

        # Sanity check: must contain a TrustServiceProviderList
        try:
            root = ET.fromstring(text)
            if root.find(_tag("TrustServiceProviderList")) is None:
                _log.debug("LOTL: TSL for %s has no TrustServiceProviderList", country)
                return False
        except Exception as exc:
            _log.debug("LOTL: TSL XML parse error for %s: %s", country, exc)
            return False

        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            self._tsl_path(country).write_text(text, encoding="utf-8")
        except Exception as exc:
            _log.debug("LOTL: could not save TSL for %s: %s", country, exc)

        # Invalidate in-process fingerprint cache – new TSL may change results
        self._fp_cache.clear()
        _log.info("LOTL: cached TSL for %s", country)
        return True

    # ── Fingerprint lookup ────────────────────────────────────────────────

    def is_trusted(self, der: bytes) -> bool:
        fp = hashlib.sha256(der).digest()
        if fp in self._fp_cache:
            return self._fp_cache[fp]
        result = self._search_cached_tsls(fp)
        self._fp_cache[fp] = result
        return result

    def _search_cached_tsls(self, fingerprint: bytes) -> bool:
        """Suche in allen gecachten TSL-XMLs nach dem SHA-256-Fingerprint."""
        for path in sorted(self._cache_dir.glob("tsl_*.xml")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                root = ET.fromstring(text)
                tsp_list = root.find(_tag("TrustServiceProviderList"))
                if tsp_list is None:
                    continue
                for elem in tsp_list.iter(_tag("X509Certificate")):
                    if not elem.text:
                        continue
                    try:
                        der = base64.b64decode(elem.text.strip())
                        if hashlib.sha256(der).digest() == fingerprint:
                            return True
                    except Exception:
                        pass
            except Exception:
                pass
        return False

    # ── Country hint ──────────────────────────────────────────────────────

    def country_hint(self, cert_der: bytes) -> Optional[str]:
        """ISO-Länderkürzel aus dem Subject-DN des Zertifikats."""
        try:
            from asn1crypto import x509 as asn1_x509
            cert = asn1_x509.Certificate.load(cert_der)
            for rdn_seq in cert.subject.chosen:
                for attr in rdn_seq:
                    if attr["type"].native in ("country_name", "2.5.4.6"):
                        val = attr["value"].native
                        if isinstance(val, str) and len(val) == 2:
                            return val.upper()
        except Exception:
            pass
        return None

    def cached_countries(self) -> list[str]:
        return sorted(p.stem[4:] for p in self._cache_dir.glob("tsl_*.xml"))

    def cache_info(self) -> dict:
        tsls = []
        for path in sorted(self._cache_dir.glob("tsl_*.xml")):
            country = path.stem[4:]
            next_update = self._tsl_next_update(path)
            valid = self.tsl_is_cached(country)
            size_kb = path.stat().st_size / 1024
            tsls.append({
                "country":     country,
                "next_update": next_update,
                "valid":       valid,
                "size_kb":     size_kb,
            })
        has_urls = self._urls_file.exists()
        url_count = len(self._urls)
        urls_size_kb = (self._urls_file.stat().st_size / 1024
                        if has_urls else 0.0)
        return {
            "has_lotl_urls":     has_urls,
            "lotl_urls_valid":   self.lotl_urls_valid(),
            "lotl_next_update":  self._lotl_next_update,
            "lotl_url_count":    url_count,
            "lotl_urls_size_kb": urls_size_kb,
            "tsls":              tsls,
        }

    def clear_cache(self, keep_urls: bool = False) -> None:
        for path in self._cache_dir.glob("tsl_*.xml"):
            try:
                path.unlink()
            except Exception:
                pass
        if not keep_urls and self._urls_file.exists():
            try:
                self._urls_file.unlink()
            except Exception:
                pass
            self._urls = []
        self._fp_cache.clear()
