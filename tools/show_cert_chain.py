"""
Zeigt Signaturen, eingebettete Zertifikate, DSS-Inhalt und Archiv-Timestamps
eines signierten PDFs.

PAdES-LTA speichert die Zertifikatskette, OCSP-Responses und den
Archiv-Timestamp im DSS-Dictionary des PDFs, nicht im CMS-Container der
Signatur.  Dieses Tool zeigt beides.

Verwendung:
    python tools/show_cert_chain.py dokument.pdf
"""

import sys
from pyhanko.pdf_utils.reader import PdfFileReader


def _cert_summary(c) -> str:
    nb = c['tbs_certificate']['validity']['not_before'].native
    na = c['tbs_certificate']['validity']['not_after'].native
    return (f"{c.subject.human_friendly}\n"
            f"      Aussteller : {c.issuer.human_friendly}\n"
            f"      Gültig     : {nb.strftime('%d.%m.%Y')} – "
            f"{na.strftime('%d.%m.%Y')}")


def show_cert_chain(pdf_path: str) -> None:
    with open(pdf_path, "rb") as fh:
        reader = PdfFileReader(fh)

        # ── Signaturen ─────────────────────────────────────────────────────────
        sigs = reader.embedded_signatures
        if not sigs:
            print("Keine Signaturen gefunden.")
            return

        for i, sig in enumerate(sigs):
            print(f"\n{'='*60}")
            print(f"Signatur {i+1}: {sig.field_name}")
            print(f"{'='*60}")

            sd = sig.signed_data

            # CMS-Zertifikate (direkt im Signatur-Container)
            cms_certs = list(sd['certificates'])
            print(f"\nCMS-Zertifikate ({len(cms_certs)}):")
            if cms_certs:
                for cert in cms_certs:
                    c = cert.chosen
                    print(f"  · {_cert_summary(c)}")
            else:
                print("  (keine)")

        # ── DSS-Dictionary (PAdES-LTA-Inhalt) ─────────────────────────────────
        print(f"\n{'='*60}")
        print("DSS-Dictionary (PAdES-LTA-Validierungsdaten)")
        print(f"{'='*60}")

        root = reader.root
        dss = root.get('/DSS')
        if dss is None:
            print("\n  Kein DSS-Dictionary vorhanden.")
            print("  → Dokument enthält keine LTA-Validierungsdaten.")
        else:
            dss = dss.get_object()

            # DSS-Zertifikate
            dss_certs_ref = dss.get('/Certs')
            if dss_certs_ref is not None:
                dss_cert_list = dss_certs_ref.get_object()
                print(f"\nDSS-Zertifikate ({len(dss_cert_list)}):")
                for ref in dss_cert_list:
                    try:
                        from asn1crypto import x509 as asn1_x509
                        der = ref.get_object().data
                        c = asn1_x509.Certificate.load(der)
                        print(f"  · {_cert_summary(c)}")
                    except Exception as e:
                        print(f"  · (nicht lesbar: {e})")
            else:
                print("\nDSS-Zertifikate: keine")

            # OCSP-Responses
            dss_ocsps_ref = dss.get('/OCSPs')
            if dss_ocsps_ref is not None:
                dss_ocsp_list = dss_ocsps_ref.get_object()
                print(f"\nOCSP-Responses ({len(dss_ocsp_list)}):")
                for ref in dss_ocsp_list:
                    try:
                        from asn1crypto import ocsp as asn1_ocsp
                        der = ref.get_object().data
                        resp = asn1_ocsp.OCSPResponse.load(der)
                        basic = resp['response_bytes']['response'].parsed
                        produced = basic['tbs_response_data']['produced_at'].native
                        responses = basic['tbs_response_data']['responses']
                        for r in responses:
                            status = r['cert_status'].name
                            print(f"  · Status: {status}  "
                                  f"Ausgestellt: {produced.strftime('%d.%m.%Y %H:%M:%S %Z')}")
                    except Exception as e:
                        print(f"  · (nicht lesbar: {e})")
            else:
                print("\nOCSP-Responses: keine")

            # CRLs
            dss_crls_ref = dss.get('/CRLs')
            if dss_crls_ref is not None:
                dss_crl_list = dss_crls_ref.get_object()
                print(f"\nCRLs ({len(dss_crl_list)}): vorhanden")
            else:
                print("\nCRLs: keine")

        # ── Dokument-Timestamps (Archiv-Timestamps für LTA) ────────────────────
        print(f"\n{'='*60}")
        print("Dokument-Timestamps (Archiv-Timestamps)")
        print(f"{'='*60}")

        doc_ts = reader.embedded_timestamp_signatures
        if not doc_ts:
            print("\n  Keine Archiv-Timestamps gefunden.")
            print("  → Dokument ist PAdES-T (Signatur+Zeitstempel), aber kein LTA.")
        else:
            for j, ts in enumerate(doc_ts):
                try:
                    gen_time = ts.self_reported_timestamp
                    tsa_name = (ts.signer_cert.subject.human_friendly
                                if ts.signer_cert else "(unbekannt)")
                    # Policy aus TSTInfo via ParsableOctetString.parsed
                    try:
                        from asn1crypto import tsp as asn1_tsp
                        raw = ts.signed_data['encap_content_info']['content'].contents
                        tst_info = asn1_tsp.TSTInfo.load(raw)
                        policy = tst_info['policy'].dotted
                    except Exception:
                        policy = "(nicht lesbar)"
                    print(f"\n  Archiv-Timestamp {j+1}:")
                    print(f"    Zeitpunkt : {gen_time.strftime('%d.%m.%Y %H:%M:%S %Z')}")
                    print(f"    Policy    : {policy}")
                    print(f"    TSA-Cert  : {tsa_name}")
                except Exception as e:
                    print(f"\n  Archiv-Timestamp {j+1}: (Details nicht lesbar: {e})")

        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Verwendung: python tools/show_cert_chain.py dokument.pdf")
    else:
        show_cert_chain(sys.argv[1])
