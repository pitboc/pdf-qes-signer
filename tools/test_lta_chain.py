#!/usr/bin/env python3
"""
LTA-Kettentest für PKCS#11-Karte.

Testet die für PAdES-LTA nötige Zertifikatskette ohne ein PDF zu signieren:
  1. Signing-Zertifikat vom Token lesen (kein Login nötig)
  2. AIA caIssuers-Kette bis zum Root-CA herunterladen
  3. ValidationContext aufbauen (certifi + AIA-Roots)
  4. OCSP-Erreichbarkeit prüfen (pyhanko_certvalidator)

Voraussetzungen (im Projekt-venv bereits enthalten):
    source .venv/bin/activate

Verwendung:
    python tools/test_lta_chain.py --module /pfad/zur/libpkcs11tcos_SigG_PCSC.so
    python tools/test_lta_chain.py --module /pfad/zur/lib.so --key-id ecb3...
"""

import argparse
import sys

DEFAULT_MODULE = "./libpkcs11tcos_SigG_PCSC.so"

# ── Farben für Konsole ────────────────────────────────────────────────────────
OK   = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"
INFO = "\033[34m·\033[0m"


def step(label: str) -> None:
    print(f"\n{INFO} {label} …")


def ok(msg: str) -> None:
    print(f"  {OK} {msg}")


def fail(msg: str) -> None:
    print(f"  {FAIL} {msg}")


def show_cert_summary(der: bytes, prefix: str = "    ") -> None:
    """Print one-line subject/issuer/validity summary."""
    try:
        from asn1crypto import x509 as asn1_x509
        cert = asn1_x509.Certificate.load(der)
        subj = cert.subject.human_friendly
        issr = cert.issuer.human_friendly
        nb   = cert['tbs_certificate']['validity']['not_before'].native.strftime("%d.%m.%Y")
        na   = cert['tbs_certificate']['validity']['not_after'].native.strftime("%d.%m.%Y")
        self_signed = cert.subject == cert.issuer
        typ = "Root-CA" if self_signed else "Intermediate/End-Entity"
        print(f"{prefix}Betreff : {subj}")
        print(f"{prefix}Ausstell: {issr}")
        print(f"{prefix}Gültigkeit: {nb} – {na}  [{typ}]")
    except Exception as e:
        print(f"{prefix}(Zertifikat nicht lesbar: {e})")


# ── Schritt 1: Signing-Zertifikat vom Token lesen ────────────────────────────

def read_signing_cert(module_path: str, key_id_hex: str | None) -> bytes:
    step("Signing-Zertifikat vom Token lesen (kein Login nötig)")
    try:
        import pkcs11 as p11
    except ImportError:
        fail("python-pkcs11 nicht installiert")
        sys.exit(1)

    lib = p11.lib(module_path)
    slots = lib.get_slots(token_present=True)
    if not slots:
        fail("Kein Token gefunden")
        sys.exit(1)

    token = slots[0].get_token()
    ok(f"Token: {token.label!r}  Modell: {token.model!r}")

    target_id = bytes.fromhex(key_id_hex) if key_id_hex else None

    with token.open() as session:
        certs = list(session.get_objects(
            {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}))
        ok(f"Zertifikate (ohne Login): {len(certs)}")

        signing_cert_der: bytes | None = None
        for c in certs:
            try:
                c_der = bytes(c[p11.Attribute.VALUE])
            except Exception:
                continue
            try:
                c_id = bytes(c[p11.Attribute.ID])
            except Exception:
                c_id = b""
            label = ""
            try:
                label = c[p11.Attribute.LABEL]
            except Exception:
                pass

            if target_id is None or c_id == target_id:
                signing_cert_der = c_der
                ok(f"Verwende Zertifikat: {label!r}  CKA_ID={c_id.hex()}")
                show_cert_summary(c_der)
                break

        if signing_cert_der is None:
            fail("Kein passendes Signing-Zertifikat gefunden")
            sys.exit(1)

    return signing_cert_der


# ── Schritt 2: AIA-Kette herunterladen ───────────────────────────────────────

def fetch_aia_chain(signing_cert_der: bytes) -> tuple[list[bytes], list]:
    step("AIA caIssuers-Kette herunterladen")

    import urllib.request
    from asn1crypto import x509 as asn1_x509

    other_certs: list[bytes] = []
    extra_roots: list        = []
    visited: set[str]        = set()
    current_der = signing_cert_der

    for depth in range(6):
        try:
            # asn1crypto statt cryptography.x509: tolerant gegenüber
            # NULL-Parametern im AlgorithmIdentifier (TeleSec-Java-Artefakt)
            cert = asn1_x509.Certificate.load(current_der)
            url: str | None = None
            for ext in cert['tbs_certificate']['extensions']:
                if ext['extn_id'].native == 'authority_information_access':
                    for desc in ext['extn_value'].parsed:
                        if desc['access_method'].native == 'ca_issuers':
                            url = desc['access_location'].chosen.native
                            break
                    break
            if not url:
                ok(f"Ebene {depth}: kein weiterer caIssuers-Link → Kettenende")
                break
            if url in visited:
                ok(f"Ebene {depth}: URL bereits besucht → Schleife vermieden")
                break
            visited.add(url)
            print(f"  {INFO} Lade: {url}")
            with urllib.request.urlopen(url, timeout=15) as resp:
                issuer_der = resp.read()
            issuer = asn1_x509.Certificate.load(issuer_der)
            other_certs.append(issuer_der)
            self_signed = issuer.subject == issuer.issuer
            typ = "Root-CA (selbstsigniert)" if self_signed else "Intermediate-CA"
            ok(f"Ebene {depth+1}: {issuer.subject.human_friendly}  [{typ}]")
            if self_signed:
                extra_roots.append(issuer)
                ok("Root-CA als extra_trust_root vorgemerkt")
                break
            current_der = issuer_der
        except Exception as e:
            fail(f"Ebene {depth}: Fehler – {e}")
            break

    ok(f"Kette: {len(other_certs)} Zertifikat(e) heruntergeladen, "
       f"{len(extra_roots)} Root-CA(s) gefunden")
    return other_certs, extra_roots


# ── Schritt 3: certifi-Roots laden ───────────────────────────────────────────

def load_certifi_roots() -> list:
    step("certifi Mozilla-CA-Bundle laden")
    try:
        import certifi
        from asn1crypto import pem as asn1_pem, x509 as asn1_x509
        roots: list = []
        with open(certifi.where(), "rb") as fh:
            data = fh.read()
        for _type, _headers, der in asn1_pem.unarmor(data, multiple=True):
            try:
                roots.append(asn1_x509.Certificate.load(der))
            except Exception:
                pass
        ok(f"{len(roots)} Root-CAs aus certifi geladen")
        return roots
    except Exception as e:
        fail(f"certifi nicht verfügbar: {e}")
        return []


# ── Schritt 4: ValidationContext + Pfadvalidierung (löst OCSP aus) ────────────

def validate_chain(signing_cert_der: bytes,
                   other_certs: list[bytes],
                   extra_roots: list,
                   certifi_roots: list) -> bool:
    step("ValidationContext aufbauen und Zertifikatspfad validieren (OCSP)")

    try:
        from pyhanko_certvalidator import ValidationContext, CertificateValidator
        from asn1crypto import x509 as asn1_x509
    except ImportError as e:
        fail(f"pyhanko-certvalidator nicht verfügbar: {e}")
        return False

    # ValidationContext.other_certs erwartet asn1crypto.x509.Certificate-Objekte,
    # keine rohen DER-Bytes
    other_as_asn1: list[asn1_x509.Certificate] = []
    for der in other_certs:
        try:
            other_as_asn1.append(asn1_x509.Certificate.load(der))
        except Exception:
            pass

    all_other   = other_as_asn1
    all_roots   = certifi_roots + extra_roots

    ok(f"other_certs: {len(all_other)} Zertifikat(e)")
    ok(f"extra_trust_roots: {len(all_roots)} Root-CA(s)")
    ok(f"allow_fetching=True  (OCSP-Abruf über Netz aktiviert)")

    try:
        vc = ValidationContext(
            other_certs=all_other,
            extra_trust_roots=all_roots or None,
            allow_fetching=True,
        )
        import asyncio
        end_cert = asn1_x509.Certificate.load(signing_cert_der)
        validator = CertificateValidator(end_cert, validation_context=vc)
        print(f"  {INFO} Validiere Kette … (kann einige Sekunden dauern)")
        # pyhanko_certvalidator >= 0.26 hat nur noch async API.
        # QES-Zertifikate haben Key Usage "non_repudiation" (Bit 1), nicht
        # "digital_signature" (Bit 0) – letzteres ist für TLS/Auth-Zertifikate.
        path = asyncio.run(validator.async_validate_usage({"non_repudiation"}))
        ok(f"Kette valide! Pfad: {' → '.join(c.subject.human_friendly for c in path)}")
        return True
    except Exception as e:
        fail(f"Pfadvalidierung fehlgeschlagen: {e}")
        # Hilfreiche Diagnose
        err = str(e).lower()
        if "ocsp" in err or "revocation" in err:
            print(f"     Hinweis: OCSP-Abfrage fehlgeschlagen – "
                  f"Netzwerk erreichbar? URL: http://pks.telesec.de/ocspr")
        elif "path" in err or "trust" in err or "certificate could not be validated" in err:
            print(f"     Hinweis: Kein Vertrauensanker gefunden – "
                  f"Root-CA nicht in certifi und nicht via AIA heruntergeladen?")
        return False


# ── Schritt 5: OCSP-URL direkt pingen ────────────────────────────────────────

def ping_ocsp(signing_cert_der: bytes) -> None:
    step("OCSP-Responder direkt pingen")
    try:
        from asn1crypto import x509 as asn1_x509
        cert = asn1_x509.Certificate.load(signing_cert_der)
        ocsp_url: str | None = None
        for ext in cert['tbs_certificate']['extensions']:
            if ext['extn_id'].native == 'authority_information_access':
                for desc in ext['extn_value'].parsed:
                    if desc['access_method'].native == 'ocsp':
                        ocsp_url = desc['access_location'].chosen.native
                        break
                break
        if not ocsp_url:
            fail("Kein OCSP-URL im Zertifikat gefunden")
            return
        ok(f"OCSP-URL: {ocsp_url}")

        import urllib.request
        req = urllib.request.Request(ocsp_url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                # Ein GET ohne Body ergibt normalerweise HTTP 400 oder 200 –
                # beides beweist dass der Server erreichbar ist
                ok(f"Server antwortet: HTTP {resp.status}")
        except Exception as e:
            code = getattr(getattr(e, "code", None), "__class__", type(e)).__name__
            http_code = getattr(e, "code", None)
            if http_code and 400 <= http_code < 500:
                ok(f"Server erreichbar (HTTP {http_code} – erwartet für leere OCSP-Anfrage)")
            else:
                fail(f"Verbindungsfehler: {e}")
    except Exception as e:
        fail(f"OCSP-Ping fehlgeschlagen: {e}")


# ── Hauptprogramm ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Testet die LTA-Zertifikatskette für eine PKCS#11-Karte."
    )
    parser.add_argument(
        "--module", default=DEFAULT_MODULE,
        help=f"Pfad zur PKCS#11-Bibliothek (Standard: {DEFAULT_MODULE})",
    )
    parser.add_argument(
        "--key-id", default=None,
        help="CKA_ID des Signing-Schlüssels als Hex (Standard: erstes Zertifikat)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("LTA-Kettentest")
    print("=" * 60)

    signing_cert_der         = read_signing_cert(args.module, args.key_id)
    other_certs, extra_roots = fetch_aia_chain(signing_cert_der)
    certifi_roots            = load_certifi_roots()
    ping_ocsp(signing_cert_der)
    success = validate_chain(signing_cert_der, other_certs, extra_roots, certifi_roots)

    print("\n" + "=" * 60)
    if success:
        print(f"{OK}  Alle Schritte erfolgreich – LTA sollte funktionieren.")
    else:
        print(f"{FAIL}  Mindestens ein Schritt fehlgeschlagen – "
              f"siehe Hinweise oben.")
    print("=" * 60)


if __name__ == "__main__":
    main()
