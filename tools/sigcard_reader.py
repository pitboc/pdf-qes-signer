#!/usr/bin/env python3
"""
Signaturkarte Leseskript
Zeigt den Inhalt einer Signaturkarte via PKCS#11 an.

Listet alle Slots und alle Objekte auf – sowohl ohne Login (öffentliche Objekte)
als auch nach PIN-Eingabe (geschützte Objekte). So wird sichtbar, welche
Zertifikate und Schlüssel die Karte enthält und welche CA-Hierarchie hinterlegt ist.

Voraussetzungen (im Projekt-venv bereits enthalten):
    source .venv/bin/activate

Verwendung:
    python tools/sigcard_reader.py --module /pfad/zur/libpkcs11.so
    python tools/sigcard_reader.py --module /pfad/zur/libpkcs11.so --no-pin
    python tools/sigcard_reader.py --module /pfad/zur/libpkcs11.so --slot 1
"""

import argparse
import getpass
import sys

DEFAULT_MODULE = "./libpkcs11tcos_SigG_PCSC.so"

OID_NAMES = {
    "2.5.4.3":  "CN",
    "2.5.4.4":  "Nachname",
    "2.5.4.42": "Vorname",
    "2.5.4.12": "Titel",
    "2.5.4.5":  "Zert-Nr",
    "2.5.4.6":  "Land",
    "2.5.4.7":  "Ort",
    "2.5.4.8":  "Bundesland",
    "2.5.4.10": "Organisation",
    "2.5.4.11": "Abteilung",
    "2.5.4.97": "Org-Kennung",
    "1.2.840.113549.1.9.1": "E-Mail",
}


def decode_cert(cert_der: bytes) -> None:
    """Print human-readable certificate details including AIA/OCSP URLs."""
    try:
        from asn1crypto import x509 as asn1_x509
        cert = asn1_x509.Certificate.load(cert_der)
    except Exception as e:
        print(f"    (Zertifikat konnte nicht dekodiert werden: {e})")
        return

    tbs  = cert['tbs_certificate']
    self_signed = cert.subject == cert.issuer

    # DN-Felder mit lesbaren Namen ausgeben
    def format_dn(name) -> str:
        parts = []
        for attr in name.chosen:
            for atv in attr:
                oid = atv['type'].dotted
                val = atv['value'].native
                label = OID_NAMES.get(oid, oid)
                parts.append(f"{label}={val}")
        return ", ".join(parts)

    print(f"    Inhaber      : {format_dn(tbs['subject'])}")
    print(f"    Aussteller   : {format_dn(tbs['issuer'])}")
    print(f"    Seriennummer : {tbs['serial_number'].native:X}")
    nb = tbs['validity']['not_before'].native.strftime('%d.%m.%Y')
    na = tbs['validity']['not_after'].native.strftime('%d.%m.%Y')
    print(f"    Gültig ab    : {nb}")
    print(f"    Gültig bis   : {na}")

    # Typ bestimmen
    is_ca = False
    for ext in tbs['extensions']:
        if ext['extn_id'].native == 'basic_constraints':
            is_ca = ext['extn_value'].parsed['ca'].native
            break
    if self_signed:
        print(f"    Typ          : Root-CA (selbstsigniert)")
    elif is_ca:
        print(f"    Typ          : Zwischen-CA (CA-Zertifikat)")
    else:
        print(f"    Typ          : End-Entity (Benutzerzertifikat)")

    # SAN (E-Mail)
    for ext in tbs['extensions']:
        if ext['extn_id'].native == 'subject_alt_name':
            emails = [v.chosen.native for v in ext['extn_value'].parsed
                      if v.name == 'rfc822_name']
            if emails:
                print(f"    E-Mail (SAN) : {', '.join(emails)}")
            break

    # AIA: caIssuers und OCSP
    for ext in tbs['extensions']:
        if ext['extn_id'].native == 'authority_information_access':
            for desc in ext['extn_value'].parsed:
                method = desc['access_method'].native
                url    = desc['access_location'].chosen.native
                if method == 'ca_issuers':
                    print(f"    AIA caIssuers: {url}")
                elif method == 'ocsp':
                    print(f"    AIA OCSP     : {url}")
            break

    # BasicConstraints
    for ext in tbs['extensions']:
        if ext['extn_id'].native == 'basic_constraints':
            bc = ext['extn_value'].parsed
            print(f"    BasicConstr. : CA={bc['ca'].native}, "
                  f"pathLen={bc['path_len_constraint'].native}")
            break


def list_slot(session, slot_index: int, logged_in: bool) -> None:
    """Print all objects in a session."""
    from pkcs11 import Attribute, ObjectClass

    try:
        objects = list(session.get_objects())
    except Exception as e:
        print(f"  Fehler beim Lesen der Objekte: {e}")
        return

    login_state = "nach Login" if logged_in else "ohne Login"
    print(f"  Objekte in Slot {slot_index} ({login_state}): {len(objects)}\n")

    if not objects:
        print("  (Keine Objekte sichtbar)")
        return

    for i, obj in enumerate(objects, start=1):
        print(f"  --- Objekt {i} ---")

        # Klasse
        obj_class = None
        try:
            obj_class = obj[Attribute.CLASS]
            class_names = {
                ObjectClass.CERTIFICATE: "Zertifikat",
                ObjectClass.PUBLIC_KEY:  "Öffentlicher Schlüssel",
                ObjectClass.PRIVATE_KEY: "Privater Schlüssel",
                ObjectClass.SECRET_KEY:  "Geheimer Schlüssel",
                ObjectClass.DATA:        "Daten",
            }
            print(f"  Klasse       : {class_names.get(obj_class, str(obj_class))}")
        except Exception:
            pass

        # Label
        try:
            print(f"  Label        : {obj[Attribute.LABEL]!r}")
        except Exception:
            print(f"  Label        : (nicht lesbar)")

        # CKA_ID
        try:
            obj_id = bytes(obj[Attribute.ID])
            print(f"  CKA_ID       : {obj_id.hex() if obj_id else '(leer)'}")
        except Exception:
            print(f"  CKA_ID       : (kein Attribut)")

        # Schlüsseltyp und -größe
        try:
            from pkcs11 import KeyType
            key_type = obj[Attribute.KEY_TYPE]
            key_names = {KeyType.RSA: "RSA", KeyType.EC: "EC (ECC)"}
            print(f"  Schlüsseltyp : {key_names.get(key_type, str(key_type))}")
        except Exception:
            pass
        try:
            print(f"  Schlüsselbits: {obj[Attribute.MODULUS_BITS]}")
        except Exception:
            pass

        # Zertifikats-Details
        if obj_class == ObjectClass.CERTIFICATE:
            try:
                cert_der = bytes(obj[Attribute.VALUE])
                decode_cert(cert_der)
            except Exception as e:
                print(f"    (Wert nicht lesbar: {e})")

        print()


def run(module_path: str, pin: str | None, only_slot: int | None) -> None:
    try:
        import pkcs11
    except ImportError:
        print("FEHLER: Bibliothek 'python-pkcs11' nicht gefunden.")
        sys.exit(1)

    print(f"Lade PKCS#11-Modul: {module_path}\n")
    try:
        lib = pkcs11.lib(module_path)
    except Exception as e:
        print(f"FEHLER: Modul konnte nicht geladen werden: {e}")
        sys.exit(1)

    # Alle Slots (auch leere) auflisten
    try:
        all_slots = lib.get_slots(token_present=False)
        slots_with_token = lib.get_slots(token_present=True)
    except Exception as e:
        print(f"FEHLER beim Lesen der Slots: {e}")
        sys.exit(1)

    print(f"Slots gesamt   : {len(all_slots)}")
    print(f"Slots mit Token: {len(slots_with_token)}\n")

    if not slots_with_token:
        print("Kein Token / keine Karte gefunden.")
        sys.exit(1)

    for slot in slots_with_token:
        slot_index = slot.slot_id
        if only_slot is not None and slot_index != only_slot:
            continue

        try:
            token = slot.get_token()
        except Exception as e:
            print(f"Slot {slot_index}: Fehler beim Token-Lesen: {e}")
            continue

        print("=" * 65)
        print(f"Slot-Nr.      : {slot_index}")
        print(f"Token-Label   : {token.label!r}")
        print(f"Hersteller    : {token.manufacturer_id!r}")
        print(f"Modell        : {token.model!r}")
        print(f"Seriennummer  : {token.serial!r}")
        print("=" * 65)

        # ── Pass 1: Ohne Login (öffentliche Objekte) ─────────────────────────
        try:
            with token.open() as session:
                list_slot(session, slot_index, logged_in=False)
        except Exception as e:
            print(f"  Sitzung ohne Login fehlgeschlagen: {e}\n")

        # ── Pass 2: Mit PIN (alle Objekte, inkl. geschützte) ─────────────────
        if pin is not None:
            print(f"  Öffne Sitzung mit PIN …")
            try:
                with token.open(user_pin=pin) as session:
                    list_slot(session, slot_index, logged_in=True)
            except Exception as e:
                print(f"  Sitzung mit PIN fehlgeschlagen: {e}\n")
        else:
            print("  (Kein PIN angegeben – geschützte Objekte werden nicht angezeigt)\n")

        print()


def main():
    parser = argparse.ArgumentParser(
        description="Listet alle Slots und Objekte einer PKCS#11-Signaturkarte auf."
    )
    parser.add_argument(
        "--module", default=DEFAULT_MODULE,
        help=f"Pfad zur PKCS#11-Bibliothek (Standard: {DEFAULT_MODULE})",
    )
    parser.add_argument(
        "--no-pin", action="store_true",
        help="Keine PIN-Abfrage; nur öffentliche Objekte anzeigen",
    )
    parser.add_argument(
        "--slot", type=int, default=None,
        help="Nur diesen Slot anzeigen (Standard: alle)",
    )
    args = parser.parse_args()

    pin: str | None = None
    if not args.no_pin:
        try:
            pin = getpass.getpass("PIN (leer lassen für --no-pin-Verhalten): ").strip() or None
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

    run(args.module, pin=pin, only_slot=args.slot)


if __name__ == "__main__":
    main()
