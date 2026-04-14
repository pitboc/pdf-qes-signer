# Changelog

All notable changes to PDF QES Signer are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased] – 0.3.4.dev1

### Fixed
- Key generation dialog: openssl command text field now sizes itself to its
  content (no vertical scrollbar); entire form wrapped in a scroll area so
  all widgets remain reachable on small screens

---

## [0.3.4.dev0] – 2026-04-14

### Added
- Multilingual interface: French, Spanish, Italian, Dutch, Polish, Portuguese
  (in addition to existing German and English)
- Installer: `--installversion vX.Y.Z` flag to install or downgrade to a
  specific release without API lookup
- Installer: downgrade warning with confirmation prompt when target version
  is older than the installed version
- Installer: installed version is now read from the venv (`importlib.metadata`)
  instead of `install.conf`, eliminating a second source of truth

### Fixed
- Crash when checking signatures: stale references to removed menu actions
  (`_act_sign`, `_act_check_sigs`) caused `AttributeError`
- "Restart" after update only closed the app without relaunching it
- Certificate viewer labels (key type, key size) were not translated
- Dates in certificate viewer and settings always used the system locale
  instead of the app language
- Settings → General tab renamed to "Language" in all 8 locales
- Certificate detail window: issuer fingerprint and LOTL annotation now shown
  even when the chain is untrusted (expired cert, unknown root) — Phase 2
  now annotates the signer chain in the untrusted branch too
- Certificate detail window: LOTL anchor shown in amber (not green) when
  issuer signature not yet verified; invalid issuer signature shown in red

---

## [0.3.3] – 2026-04-11

### Added
- Built-in key generation: create self-signed PKCS#12 certificates directly
  from Settings, including openssl command preview and interactive terminal
  execution
- Signature verification: Phase 1 issuer signature check with EU LOTL trust
  chain; embedded root CA via AIA on signing
- Settings dialog redesigned (Firefox-style, tabbed layout)
- Update channels: stable (default) and develop; warning shown when switching
  to develop
- In-app update notification dialog with changelog on startup and manual check
- Installer: stable/develop channel selection, remembered across upgrades
- Installer: Windows ARM64 support (Python + VC++ runtime)
- Config schema versioning with downgrade warning

### Fixed
- Installer: pip upgrade now runs correctly and logs output
- Installer: encoding issues and error log saving on failure
- Installer: uses `python.exe` (not `pythonw.exe`) for pip operations
- Installer: writes selected update channel to `settings.ini`
- TSA chain status, fingerprint verification, BaltStamp TSA URL default
- Version-compare fallback for pre-release (`devN`) version strings

---

## [0.3.2] – 2026-04-07

### Added
- Self-contained Windows installer with graphical wizard (PowerShell embedded
  in `.bat`, no admin rights required)
- Automatic update: download and install new releases from Codeberg directly
  from within the app
- Windows ARM64 support
- Detects conda/system Python environments and aborts with helpful message

### Fixed
- Missing VC++ Redistributable detected on Windows with install instructions
- Package installation progress output on Windows

---

## [0.3.1] – 2026-04-05

### Added
- Signature validation dialog with trust chain visualization (EU LOTL/TSL)
- Certificate chain visualization with self-signed and DSS-pool support
- LOTL NextUpdate tracking and TSL cache management dialog
- Post-signature modification warnings and historical revision view
- docMDP restriction detection (P=1 lock after first signature)
- Security hardening: certificate chain pinning, fingerprint verification

### Fixed
- Include embedded CMS certificates in LOTL trust check
- Consistent button labels across all dialogs
- Certificate detail window stays above validation dialog
- Linearisation hint xref sections excluded from revision list
- Post-signature revisions preserved correctly when re-signing

---

## [0.3.0] – 2026-03-15

### Added
- PAdES-LTA: OCSP revocation embedding and archival timestamp support
- PFX/P12 file-based signing as alternative to PKCS#11 hardware token
- Profile management: multiple named signing configurations
- Continuous scroll view for multi-page PDFs with lazy rendering
- Zoom controls: fit-width/height, Ctrl+scroll, rubber-band zoom (Ctrl+drag)
- Middle-drag panning in both single-page and continuous mode
- SVG toolbar icons
- Rotated PDF support; in-memory workflow; field classification (free /
  locked / signed)

---

## [0.2.3] – 2026-03-13

### Fixed
- Delete button greyed out correctly; field selection after draw; save button
  label; token dialog improvements

---

## [0.2.2] – 2026-03-09

### Added
- Editable page number field; auto-scroll to selected signature field
- Continuous scroll view (early version)

---

## [0.2.1] – 2026-03-08

### Added
- `key_id`-based signing; improved token dialog; certificate name display

---

## [0.1.0] – 2026-03-05

### Added
- Initial public release: modular rewrite
- PKCS#11 hardware token signing
- Signature field placement (draw, resize, delete)
- RFC 3161 timestamp authority (TSA) support
- Windows support (config paths, setup script, launcher)
- Appearance panel (image, name, date customisation)
