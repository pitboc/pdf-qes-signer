# SPDX-License-Identifier: GPL-3.0-or-later
"""Data model for PDF signature validation results.

## Revision hierarchy

A PDF with multiple signatures uses incremental updates.  Each new revision
appends bytes to the file and covers *all* previous bytes with its signature.
The containment order is therefore:

    Rev 3 (outermost – covers everything)
      └── Rev 2 (covers Rev 1)
            └── Rev 1 (innermost – original document)

``DocumentValidation.revisions`` is ordered oldest-first (1 … n).  The UI
displays them newest-first so the visual nesting matches the cryptographic
containment.

## Two-phase population

Objects are first created with ``status = ValidationStatus.NOT_CHECKED`` so
the UI tree can be built immediately from embedded data (Phase 1 – offline,
instant).  A background worker then fills in revocation details and updates
status fields (Phase 2 – optional network access).

## Status granularity

``SignatureInfo`` carries three separate status fields so the UI can show
exactly *why* a signature is yellow/red:

- ``crypto_status``     – byte integrity (hash + signature math)
- ``chain_status``      – trust anchor reachable, dates valid
- ``revocation_status`` – OCSP / CRL result
- ``status``            – overall (worst of the three)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Literal, Optional


class ValidationStatus(Enum):
    """Validity assessment of a signature, certificate, or revocation object."""
    VALID       = "valid"        # intact, trusted, not revoked
    UNKNOWN     = "unknown"      # crypto OK but revocation status unavailable
    INVALID     = "invalid"      # broken, revoked, expired, or untrusted
    NOT_CHECKED = "not_checked"  # analysis not yet run (Phase 1 placeholder)


class CertSource(Enum):
    """Origin of a certificate or revocation object."""
    EMBEDDED   = "embedded"    # stored inside the PDF (CMS container or DSS)
    SYSTEM     = "system"      # found in the OS / certifi trust store
    EU_TSL     = "eu_tsl"      # found in an EU national Trust Service List (LOTL)
    DOWNLOADED = "downloaded"  # fetched from the network at runtime
    NOT_FOUND  = "not_found"   # required but not available


@dataclass
class OCSPInfo:
    """One OCSP response, embedded in the PDF or fetched online."""
    produced_at: datetime
    cert_status: str          # ASN.1 value: "good" | "revoked" | "unknown"
    source: CertSource
    status: ValidationStatus  # validity of this OCSP response itself


@dataclass
class CRLInfo:
    """Presence of a CRL entry (detailed parsing deferred)."""
    source: CertSource
    status: ValidationStatus


@dataclass
class CertInfo:
    """One X.509 certificate in a validation chain."""
    subject: str
    issuer: str
    valid_from: datetime
    valid_until: datetime
    source: CertSource
    status: ValidationStatus
    is_root: bool = False
    is_ca: bool = False        # True if Basic Constraints cA=TRUE (or self-signed root)
    subject_hashable: Optional[bytes] = None  # asn1crypto Name.hashable – for reliable lookup
    ocsp: Optional[OCSPInfo] = None
    crl: Optional[CRLInfo] = None


@dataclass
class TimestampInfo:
    """RFC-3161 timestamp token (embedded in a signature or as LTA document timestamp)."""
    time: datetime
    tsa_subject: str      # subject CN of the TSA signing certificate
    policy_oid: str
    source: CertSource    # where the TSA certificate came from
    status: ValidationStatus
    cert_chain: list[CertInfo] = field(default_factory=list)


@dataclass
class SignatureInfo:
    """One digital signature or document timestamp (LTA) contained in the PDF."""

    field_name: str
    sig_type: Literal["signature", "doc_timestamp"]

    # Human-readable signer identity from the signing certificate subject.
    signer_subject: str

    # Self-reported signing time from the CMS SignedData; prefer
    # ``timestamp.time`` when present (TSA-authoritative).
    signing_time: Optional[datetime]

    # Embedded RFC-3161 timestamp token (None for bare signatures without TSA).
    timestamp: Optional[TimestampInfo] = None

    # Full certificate chain, index 0 = end-entity, last = root (or highest found).
    cert_chain: list[CertInfo] = field(default_factory=list)

    # Granular status – allows the UI to show exactly what failed.
    crypto_status: ValidationStatus = ValidationStatus.NOT_CHECKED
    chain_status: ValidationStatus = ValidationStatus.NOT_CHECKED
    revocation_status: ValidationStatus = ValidationStatus.NOT_CHECKED

    # Overall status = worst of the three above.
    status: ValidationStatus = ValidationStatus.NOT_CHECKED


@dataclass
class RevisionInfo:
    """One PDF revision (base document or incremental update)."""

    revision_number: int    # 1-based; 1 = original document
    total_revisions: int    # total revision count in this document
    description: str        # short label, e.g. "Signatur: Max Mustermann"

    # Authoritative time: from the embedded timestamp when present,
    # otherwise from the self-reported signing time, otherwise None.
    date: Optional[datetime]

    signed_by: Optional[SignatureInfo] = None
    status: ValidationStatus = ValidationStatus.NOT_CHECKED


@dataclass
class DocumentValidation:
    """Complete validation result for one PDF document.

    ``revisions`` is ordered oldest-first (revision 1 … n).  The UI renders
    them newest-first to express the cryptographic containment visually.
    """

    revisions: list[RevisionInfo] = field(default_factory=list)
    overall_status: ValidationStatus = ValidationStatus.NOT_CHECKED
    has_dss: bool = False   # DSS dictionary present in the PDF
    is_lta: bool = False    # at least one archival (LTA) timestamp present
