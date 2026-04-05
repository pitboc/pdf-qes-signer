# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests für den TSL-Nachladeweg in der Signaturvalidierung.

## Testaufbau

| Test                          | Netzwerk | Beschreibung                                        |
|-------------------------------|----------|-----------------------------------------------------|
| test_tsl_confirmed_via_mock   | nein     | Fake-TSL mit Fake-Cert → EU_TSL-Klassifizierung     |
| test_tsl_fetched_real_network | ja       | Echter FI-TSL-Download über LOTL → Cache wächst     |
| test_no_tsl_fetch_no_country  | nein*    | Kein C= im Subject → kein TSL-Ladeversuch           |

(*) kein TSL-Download, aber LOTL-URL-Liste kann nachgeladen werden.

## Strategie

``test_tsl_confirmed_via_mock``:
  Einziger Test, der zwingend einen Mock braucht: Das Fake-Zertifikat aus PDF 09
  steht nie in einer echten nationalen TSL.  Die Fake-TSL-XML enthält den
  Fingerabdruck des eingebetteten CMS-Zertifikats, damit ``is_trusted()`` True
  zurückgibt und die EU_TSL-Klassifizierung ausgelöst wird.

``test_tsl_fetched_real_network``:
  Kein Mock.  Die Validierung läuft mit dem echten Cache-Verzeichnis und echtem
  Netzwerkzugriff.  Nach dem Test muss die FI-TSL im Cache vorhanden sein.
  Der Fake-Cert steht nicht in der echten FI-TSL → chain_status bleibt UNKNOWN.
  Das ist korrekt und zeigt, dass LOTL-Bestätigung nicht fälschlicherweise
  für Fake-Certs ausgelöst wird.

``test_no_tsl_fetch_no_country``:
  Kein Mock auf ``_fetch_url``.  PDF 10 enthält keine C=-Attribute; country_hint()
  gibt None zurück und der TSL-Ladeweg wird nie betreten.  Die Anzahl der
  gecachten TSL-Dateien darf nach dem Test nicht gestiegen sein.
"""

from __future__ import annotations

import base64
import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtCore import QCoreApplication
_qt_app = QCoreApplication.instance() or QCoreApplication(sys.argv)

import pytest

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "tools"))

from pdf_signer.validation_extractor import extract
from pdf_signer.validation_worker import ValidationWorker
from pdf_signer.validation_result import CertSource, ValidationStatus

import create_test_pdfs as gen


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _run_validation(pdf_bytes: bytes, auto_fetch: bool = False,
                    cache_dir: Path | None = None) -> object:
    """Phase 1 + Phase 2 synchron ausführen.

    Wenn ``cache_dir`` angegeben, wird ``_CACHE_DIR`` auf dieses Verzeichnis
    umgeleitet (kein Schreiben in den echten Cache).  Ohne ``cache_dir`` wird
    der echte Cache unter ``~/.config/pdf-signer/`` verwendet.
    """
    doc = extract(pdf_bytes)
    worker = ValidationWorker(doc, pdf_bytes, auto_fetch=auto_fetch)
    if cache_dir is not None:
        with patch("pdf_signer.lotl_trust._CACHE_DIR", cache_dir):
            worker.run()
    else:
        worker.run()
    return doc


def _first_sig(doc):
    for rev in doc.revisions:
        if rev.signed_by and rev.signed_by.sig_type == "signature":
            return rev.signed_by
    pytest.fail("Keine Signatur im Dokument gefunden")


def _extract_cms_certs_der(pdf_bytes: bytes) -> list[bytes]:
    """Alle im CMS eingebetteten Zertifikate als DER-Bytes extrahieren."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    result = []
    reader = PdfFileReader(io.BytesIO(pdf_bytes), strict=False)
    for sig_obj in reader.embedded_regular_signatures:
        try:
            for c in sig_obj.signed_data["certificates"]:
                try:
                    result.append(c.chosen.dump())
                except Exception:
                    pass
        except Exception:
            pass
    return result


def _make_fake_tsl_xml(cert_ders: list[bytes]) -> str:
    """Minimale TSL-XML mit den angegebenen Zertifikaten."""
    ns = "http://uri.etsi.org/02231/v2#"
    cert_elems = "\n          ".join(
        f"<X509Certificate>{base64.b64encode(der).decode()}</X509Certificate>"
        for der in cert_ders
    )
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<TrustServiceStatusList xmlns="{ns}">\n'
        f'  <SchemeInformation>\n'
        f'    <NextUpdate><dateTime>2030-01-01T00:00:00Z</dateTime></NextUpdate>\n'
        f'  </SchemeInformation>\n'
        f'  <TrustServiceProviderList>\n'
        f'    <TrustServiceProvider><TSPServices><TSPService>\n'
        f'      <ServiceInformation><ServiceDigitalIdentity><DigitalId>\n'
        f'          {cert_elems}\n'
        f'      </DigitalId></ServiceDigitalIdentity></ServiceInformation>\n'
        f'    </TSPService></TSPServices></TrustServiceProvider>\n'
        f'  </TrustServiceProviderList>\n'
        f'</TrustServiceStatusList>'
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def pdf_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("tsl_loading_pdfs")
    gen.gen_09_tsl_trigger_cms(out)
    gen.gen_10_no_country_hint(out)
    return out


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_tsl_confirmed_via_mock(pdf_dir, tmp_path):
    """Fake-TSL mit Fake-Cert → EU_TSL-Klassifizierung (Mock notwendig).

    Das Fake-Zertifikat aus PDF 09 steht nicht in einer echten TSL.  Die
    Fake-TSL-XML enthält seine Fingerabdrücke; nur so kann EU_TSL-Status
    erreicht werden.  Dieser Test prüft, dass der Bestätigungsweg technisch
    funktioniert, sobald ein Fingerabdruck in einer TSL gefunden wird.
    """
    pdf_bytes = (pdf_dir / "09_tsl_trigger_cms.pdf").read_bytes()
    tsl_url = "http://test.local/at_tsl.xml"

    # Fake-Cache mit FI-URL-Eintrag
    cache_dir = tmp_path / "tsl_cache"
    cache_dir.mkdir()
    (cache_dir / "lotl_urls.json").write_text(json.dumps({
        "next_update": "2030-01-01T00:00:00+00:00",
        "urls": [{"country": "FI", "url": tsl_url}],
    }), encoding="utf-8")

    cms_ders = _extract_cms_certs_der(pdf_bytes)
    assert cms_ders, "Keine CMS-Certs im Test-PDF gefunden"
    fake_tsl = _make_fake_tsl_xml(cms_ders)

    def fake_fetch(url: str, timeout: int):
        return fake_tsl if tsl_url in url else None

    with patch("pdf_signer.lotl_trust._fetch_url", side_effect=fake_fetch):
        doc = _run_validation(pdf_bytes, auto_fetch=True, cache_dir=cache_dir)

    sig = _first_sig(doc)
    sources = {c.source for c in sig.cert_chain}
    assert CertSource.EU_TSL in sources, (
        f"Erwartet EU_TSL-Quelle nach TSL-Bestätigung, "
        f"tatsächliche Quellen: {sources}"
    )


def test_tsl_fetched_real_network(pdf_dir):
    """Echter FI-TSL-Download: nach der Validierung ist tsl_FI.xml im Cache.

    Kein Mock – echter Netzwerkzugriff auf die EU LOTL und die österreichische
    TSL.  Das Fake-Zertifikat steht nicht in der echten FI-TSL, daher bleibt
    chain_status UNKNOWN.  Das ist korrekt: der Test prüft nur, dass der
    Ladevorgang ausgelöst wurde, nicht die Bestätigung des Fake-Certs.
    """
    from pdf_signer.lotl_trust import XmlCacheTrustStore
    pdf_bytes = (pdf_dir / "09_tsl_trigger_cms.pdf").read_bytes()

    doc = _run_validation(pdf_bytes, auto_fetch=True)

    store = XmlCacheTrustStore()
    assert store.tsl_is_cached("FI"), (
        "FI-TSL wurde nicht in den Cache geladen. "
        "Netzwerkzugriff verfügbar? FI in der LOTL-URL-Liste?"
    )
    # Fake-Cert nicht in echter TSL → UNKNOWN ist das korrekte Ergebnis
    sig = _first_sig(doc)
    assert sig.chain_status != ValidationStatus.VALID, (
        "Fake-Cert darf nach echter TSL-Prüfung nicht als VALID gelten"
    )


def test_no_tsl_fetch_no_country(pdf_dir):
    """PDF 10 (kein C= im Subject): kein TSL-Ladeversuch, Cache bleibt unverändert.

    Kein Mock auf _fetch_url.  country_hint() gibt für alle Certs None zurück;
    der TSL-Ladeweg wird nie betreten.  Die Anzahl gecachter TSL-Dateien darf
    nach der Validierung nicht gestiegen sein.
    """
    from pdf_signer.lotl_trust import XmlCacheTrustStore
    pdf_bytes = (pdf_dir / "10_no_country_hint.pdf").read_bytes()

    countries_before = set(XmlCacheTrustStore().cached_countries())

    _run_validation(pdf_bytes, auto_fetch=True)

    countries_after = set(XmlCacheTrustStore().cached_countries())
    new_countries = countries_after - countries_before
    assert not new_countries, (
        f"Unerwartete neue TSL-Einträge obwohl kein C= im Subject: {new_countries}"
    )
