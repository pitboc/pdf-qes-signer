#!/usr/bin/env python3
"""
Signaturkarte Leseskript
Zeigt den Inhalt einer Signaturkarte via PKCS#11 an.

Voraussetzungen:
    python3 -m venv venv
    source venv/bin/activate
    pip install python-pkcs11 cryptography

Verwendung:
    python sigcard_reader.py [--module PFAD_ZUR_BIBLIOTHEK]
"""

import argparse
import getpass
import sys

# Standardpfad zur PKCS#11-Bibliothek (anpassen falls nötig)
DEFAULT_MODULE = "./libpkcs11tcos_SigG_PCSC.so"


def list_objects(module_path: str, pin: str | None = None) -> None:
    try:
        import pkcs11
        from pkcs11 import Attribute, ObjectClass
    except ImportError:
        print("FEHLER: Bibliothek 'python-pkcs11' nicht gefunden.")
        print("Bitte in einem venv installieren:")
        print("  python3 -m venv venv")
        print("  source venv/bin/activate")
        print("  pip install python-pkcs11 cryptography")
        sys.exit(1)

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("FEHLER: Bibliothek 'cryptography' nicht gefunden.")
        print("  pip install cryptography")
        sys.exit(1)

    print(f"Lade PKCS#11-Modul: {module_path}\n")

    try:
        lib = pkcs11.lib(module_path)
    except Exception as e:
        print(f"FEHLER: Modul konnte nicht geladen werden: {e}")
        sys.exit(1)

    # Token-Info
    try:
        slots = lib.get_slots(token_present=True)
        if not slots:
            print("Kein Token / keine Karte gefunden.")
            sys.exit(1)
    except Exception as e:
        print(f"FEHLER beim Suchen nach Slots: {e}")
        sys.exit(1)

    for slot in slots:
        try:
            token = slot.get_token()
        except Exception as e:
            print(f"  Slot-Fehler: {e}")
            continue

        print("=" * 60)
        print(f"Token-Label   : {token.label!r}")
        print(f"Hersteller    : {token.manufacturer_id!r}")
        print(f"Modell        : {token.model!r}")
        print(f"Seriennummer  : {token.serial!r}")
        print("=" * 60)

        try:
            if pin:
                print(f"  Öffne Sitzung mit PIN …")
                session = token.open(rw=True, user_pin=pin)
            else:
                print(f"  Öffne Sitzung ohne PIN …")
                session = token.open()
        except Exception as e:
            print(f"FEHLER beim Öffnen der Sitzung: {e}")
            continue

        with session:
            objects = list(session.get_objects())

            if not objects:
                print("  Keine Objekte auf der Karte gefunden.")
                continue

            print(f"  Gefundene Objekte: {len(objects)}\n")

            for i, obj in enumerate(objects, start=1):
                print(f"  --- Objekt {i} ---")

                # Klasse
                try:
                    obj_class = obj[Attribute.CLASS]
                    class_names = {
                        ObjectClass.CERTIFICATE: "Zertifikat",
                        ObjectClass.PUBLIC_KEY:  "Öffentlicher Schlüssel",
                        ObjectClass.PRIVATE_KEY: "Privater Schlüssel",
                        ObjectClass.SECRET_KEY:  "Geheimer Schlüssel",
                        ObjectClass.DATA:        "Daten",
                    }
                    print(f"  Klasse        : {class_names.get(obj_class, str(obj_class))}")
                except Exception:
                    pass

                # Label
                try:
                    print(f"  Label         : {obj[Attribute.LABEL]!r}")
                except Exception:
                    pass

                # ID
                try:
                    obj_id = obj[Attribute.ID]
                    print(f"  ID            : {obj_id.hex()}")
                except Exception:
                    pass

                # Algorithmus / Key-Typ
                try:
                    from pkcs11 import Attribute as A, KeyType
                    key_type = obj[A.KEY_TYPE]
                    key_names = {
                        KeyType.RSA: "RSA",
                        KeyType.EC:  "EC (ECC)",
                    }
                    print(f"  Schlüsseltyp  : {key_names.get(key_type, str(key_type))}")
                except Exception:
                    pass

                # EC Point (öffentlicher ECC-Schlüssel)
                try:
                    from pkcs11 import Attribute as A
                    ec_point = bytes(obj[A.EC_POINT])
                    print(f"  EC_POINT      : {ec_point.hex()}")
                    ec_params = bytes(obj[A.EC_PARAMS])
                    print(f"  EC_PARAMS     : {ec_params.hex()}")
                except Exception:
                    pass

                # Key-Größe
                try:
                    bits = obj[Attribute.MODULUS_BITS]
                    print(f"  Schlüssellänge: {bits} Bit")
                except Exception:
                    pass

                # Zertifikat-Details (nur für Zertifikat-Objekte)
                if obj_class == ObjectClass.CERTIFICATE:
                    try:
                        import warnings
                        cert_data = bytes(obj[Attribute.VALUE])
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore")
                            cert = x509.load_der_x509_certificate(cert_data, default_backend())

                        # OID → lesbare Feldnamen
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

                        def format_dn(name):
                            parts = []
                            for attr in name:
                                label = OID_NAMES.get(attr.oid.dotted_string, attr.oid.dotted_string)
                                parts.append(f"{label}={attr.value}")
                            return ", ".join(parts)

                        print(f"  Inhaber       : {format_dn(cert.subject)}")
                        print(f"  Aussteller    : {format_dn(cert.issuer)}")
                        print(f"  Seriennummer  : {cert.serial_number:X}")
                        print(f"  Gültig ab     : {cert.not_valid_before_utc.strftime('%d.%m.%Y')}")
                        print(f"  Gültig bis    : {cert.not_valid_after_utc.strftime('%d.%m.%Y')}")

                        # SANs (E-Mail etc.)
                        try:
                            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                            emails = san.value.get_values_for_type(x509.RFC822Name)
                            if emails:
                                print(f"  E-Mail (SAN)  : {', '.join(emails)}")
                        except x509.ExtensionNotFound:
                            pass
                    except Exception as e:
                        print(f"  (Zertifikat konnte nicht dekodiert werden: {e})")

                print()

        print()


def main():
    parser = argparse.ArgumentParser(
        description="Listet Objekte auf einer PKCS#11-Signaturkarte auf."
    )
    parser.add_argument(
        "--module",
        default=DEFAULT_MODULE,
        help=f"Pfad zur PKCS#11-Bibliothek (Standard: {DEFAULT_MODULE})",
    )
    args = parser.parse_args()

    try:
        pin = getpass.getpass("PIN (leer lassen für Abfrage ohne PIN): ")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    list_objects(args.module, pin=pin or None)


if __name__ == "__main__":
    main()
