# Changelog

All notable changes to PDF QES Signer are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Fixed
- **Windows installer: `install.log` could fail to write** ("part of the
  path could not be found") when an error occurred before the install
  directory existed on disk (e.g. during the Python check in Step 1, which
  runs before `New-Item` creates the directory in Step 3). `Save-Log` now
  creates the directory first.
- **Windows installer: Python detection could crash with "Access denied"**
  if the registry (`HKCU`/`HKLM\SOFTWARE\Python\PythonCore`) pointed at a
  Microsoft Store Python stub. Stage 3 (registry) now filters `WindowsApps`
  paths like Stages 1 and 2 already did, and `Test-PythonVersion` no longer
  lets a failed process launch crash the whole installer.
- **Linux installer: `pip` could be missing after venv creation** on minimal
  distros (e.g. Debian/Ubuntu images without `python3-pip`), causing
  `.venv/bin/pip: file or directory not found` even though `python3-venv`
  was installed and `python3 -m venv` reported success. The installer now
  bootstraps `pip` via `ensurepip` if it's missing after venv creation, and
  prints a clear `python3-pip` install hint if that also fails.
- **Locked (already-signable) signature fields didn't show the live
  appearance preview** when selected — only the orange highlight border was
  drawn. The preview pixmap is now rendered for locked fields too, matching
  the behaviour of freely-editable fields.
- **Form-field edits could be lost or shown stale after scrolling/paging**,
  because `ContinuousView` destroys and recreates the per-page widget when a
  page leaves the render band (lazy rendering, zoom rebuild, single-page
  page-flip) without first committing an open text/combobox overlay. The
  overlay is now flushed before any such teardown.
- **Text/combobox form fields could render twice, slightly misaligned**,
  after switching pages and back. The app draws these values itself
  (matched to the field's own font) in addition to fitz's own rasterised
  widget appearance, which only exists once the field has been committed at
  least once; a fresh page render then baked both into the pixmap. The
  affected widgets are now hidden (PDF `NoView` flag) while the base pixmap
  is rendered, then restored.
- **Checkbox/radio-button toggles didn't visually update** until navigating
  away and back to the page. Their state lives only in fitz's rasterised
  appearance stream (unlike text/combobox, they have no custom paintEvent
  drawing), and normal field-list refreshes only repaint the existing
  pixmap. The affected page is now explicitly re-rendered right after such
  an edit is committed.

---

## [1.0.3] – 2026-07-04

### Added
- **Help menu: "User Manual" and "Electronic Signatures Explained" entries**
  open the bundled `user-manual.pdf` / `signatur-stufen.pdf` (or
  `signature-levels.pdf` when the UI language isn't German) in the OS's
  default PDF viewer (`QDesktopServices.openUrl`). All three PDFs now ship
  inside the installed wheel (`pdf_signer/docs/`) alongside their
  canonical, git-tracked copies in the repo's `docs/` directory.
- **English translation of the eIDAS signature-levels explainer**
  (`docs/signature-levels.md` / `.pdf`), sibling of the existing German
  `signatur-stufen.md` / `.pdf`.

### Fixed
- **Default TSA switched from BalTstamp to ACCV:** `http://tsa.baltstamp.lt`
  stopped responding. The default/placeholder RFC-3161 timestamp server is
  now `http://tss.accv.es:8318/tsa`.
- **Crash handler could swallow the original traceback on `RecursionError`:**
  A `RecursionError` reaching `sys.excepthook` left the interpreter's call
  stack at the recursion limit, so the handler's own bookkeeping (log file
  write, traceback formatting, Qt dialog) immediately tripped the same limit
  again. Python then discarded the original traceback and only printed
  "Error in sys.excepthook" to the console. The handler now temporarily
  raises the recursion limit so it can actually log and display the original
  exception.

---

## [1.0.2] – 2026-05-03

### Changed
- **Single-page mode is now handled inside `ContinuousView`:** Previously the
  application maintained two separate rendering code paths (single-page and
  continuous).  Single-page mode is now a layout mode of `ContinuousView`
  (`_single_page_mode` flag): the container is sized to exactly one page, all
  other slots are moved off-screen, and the scroll bar covers only the current
  page.  Page Down / Page Up and scrolling past the page edge automatically
  flip to the next or previous page.  This eliminates duplicated code and
  ensures that bugs fixed in one mode apply to both.

### Fixed
- **Form field value not displayed after leaving the field:** Text and combobox
  form field values were only visible inside the active overlay widget (QLineEdit
  / QPlainTextEdit).  After clicking away the field appeared empty.  The value
  stored in `FormFieldDef.value` is now drawn directly in `paintEvent` whenever
  no overlay is active for that field.
- **Form field font matches PDF specification:** The font family and style
  (bold / italic) specified in the field's `/DA` string are now applied both
  to the static value rendering and to the active edit overlay.  A shared
  `make_form_field_qfont()` helper in `config.py` maps all 14 Base-14 PDF font
  aliases to Qt font families, reusing the existing `_HELV_QT` / `_TIRO_QT` /
  `_COUR_QT` fallback lists.
- **Scroll-to-field jumped to page bottom in single-page mode:** `scroll_to_field`
  used the continuous-mode y-offset as `page_top`, which added a large offset
  and caused the scrollbar to clamp at its maximum.  In single-page mode the
  active page slot is always at y = 0, so `page_top` is now 0 in that mode.
- **Active text overlay lost focus when switching to continuous mode:**
  `set_single_page_mode(False)` triggered `_update_visible()` while the
  scrollbar still held the old single-page value, so the active page was
  considered out of range and unrendered, destroying the focused overlay.
  The target scroll position is now set before `_update_visible()` runs.

---

## [1.0.1] – 2026-04-21

### Fixed
- **Form field text edits now correctly mark the document as modified:** Typing
  in a PDF text-form-field overlay no longer leaves the Save button grayed out.
  A pending overlay is also flushed automatically before any save action, so
  edits are never silently discarded.
- **Text annotations survive Save / Save As for continued editing:** After
  saving, text annotation overlays remain visible and editable.  Subsequent
  saves correctly pick up any further changes instead of writing a byte-identical
  copy.  The pre-annotation base bytes are preserved so annotations are never
  embedded twice.
- **Shared last-used directory for Open and Save dialogs:** The Open-PDF,
  Save As, and Sign-Save dialogs now share a single last-used directory.
  Changing the directory in any of these dialogs updates the default for all
  of them.

---

## [1.0.0] – 2026-04-20

### Added
- **Keyboard shortcuts:** `t` toggles text-annotation mode, `s` opens the
  sign dialog, `c` opens the signature-validation dialog — all active when no
  text input has focus.
- **Tab / Shift+Tab navigation in form fields:** Pressing Tab moves focus to
  the next editable text field in the PDF form (top-to-bottom, left-to-right,
  wrapping); Shift+Tab moves backwards.  Checkboxes, radio buttons, and
  drop-down lists are excluded from the tab order.
- **Tab / Shift+Tab navigation between text annotations:** In text-annotation
  mode, Tab cycles through existing text overlays sorted by position.
- **Tab / Shift+Tab navigation between signature fields:** When the signature
  field list has focus, Tab / Shift+Tab selects the next / previous signable
  field.

---

## [0.3.10] – 2026-04-20

### Added
- **Interactive PDF form field editing:** Text fields, checkboxes, and radio
  buttons in existing PDF forms can now be filled in directly in the viewer.
  Changes are serialised back into the document on save or sign.
- **Flatten form fields on sign:** When signing, all filled form fields are
  flattened into the page content so the values are permanently embedded in
  the signed PDF.
- **Classic Save / Save As:** The toolbar and File menu now provide a standard
  Save (Ctrl+S) action that writes directly to the opened file, and a
  Save As (Ctrl+Shift+S) action that opens a file dialog and switches the
  working context to the new file.  Both actions are greyed out when no
  document is loaded; Save is additionally greyed out when there are no
  unsaved changes.

### Fixed
- **Radio button selection (Firefox/PDF.js):** The `/V` entry on radio button
  parent fields is now written as a PDF name object (`/OnState`) instead of a
  plain string, fixing incorrect display in Firefox and PDF.js viewers.
- **Radio button structure (LibreOffice PDFs):** Radio button groups exported
  by LibreOffice use a non-standard flat structure; the app now normalises
  them into the standard parent/kids hierarchy before editing.
- **Crash log rotation:** The crash log (`~/.local/share/pdf-signer/crash.log`)
  now rotates daily and shows a user-facing error dialog for unhandled
  exceptions in addition to writing to the log file.
- **Text mode reset on file open:** Opening a new PDF while text-annotation
  mode was active could crash with a `RuntimeError` on the deleted overlay
  widget; text mode is now cleanly exited before the new document is loaded.

---

## [0.3.9] – 2026-04-18

### Added
- **Drag-to-move signature fields:** Each free signature field now shows a red
  10×10 px drag handle in its top-left corner (same style as text annotation
  overlays).  Grabbing the handle moves the field in real time; the updated
  PDF coordinates are written back on mouse release.  Works in both single-page
  and continuous-view modes, and also exits text-annotation mode if active.
- **Cursor feedback on handles:** Hovering over a drag handle changes the
  cursor to the move cursor (⤢) for both signature fields and text annotation
  overlays.
- **Crash log:** Unhandled Python exceptions and C-level faults (SIGSEGV,
  SIGABRT) are now written to `~/.local/share/pdf-signer/crash.log` with a
  timestamp.  Uses `sys.excepthook` for Python tracebacks and `faulthandler`
  for low-level crashes.
- **Unsaved-changes warning on open:** Opening a new PDF while the current
  document has unsaved changes now shows a confirmation dialog ("Verwerfen" /
  "Discard") instead of silently discarding them.  Translated into all 8
  supported languages.

---

## [0.3.8] – 2026-04-18

### Added
- **Early certificate validation before signing:** When no certificate source
  is configured (no PFX/P12 file in PKCS#12 mode, or no PKCS#11 library path
  set), a warning dialog now appears immediately when the user clicks Sign –
  before any file-save or DocMDP dialog.  The dialog offers a direct shortcut
  to the Token/Signature settings page.

### Fixed
- **Text annotation overlay position and character spacing:** The Qt overlay
  anchor and the fitz TextWriter baseline are now aligned via empirically
  calibrated offset constants (0.2 mm X, 0.04 mm/pt Y).  Qt font kerning is
  disabled in the overlay to match fitz TextWriter, which renders without
  kern-pair adjustments (fixes visible gap in letter pairs such as "Te").
  Single-line annotations without character spacing now use one `tw.append()`
  call instead of per-character calls to avoid positioning artefacts.

---

## [0.3.7] – 2026-04-18

### Added
- **12 PDF Base-14 font variants** for text annotations: Bold, Italic/Oblique,
  and Bold-Italic/Bold-Oblique for Helvetica, Times, and Courier.  The
  toolbar font dropdown now lists all 12 variants; the correct style is
  preserved across save/reload via a custom `/QESFontName` PDF key.

### Changed
- **Text annotations are now selectable in the signed PDF.**  Previously the
  annotation text was rasterised to a ~216 dpi image and burned into the page
  as a picture.  Text is now written as native PDF text operators via
  `fitz.TextWriter`, so it remains searchable and copy-pasteable.  Character
  spacing is preserved through explicit per-character x-positioning (no `Tc`
  operator needed).  Fonts are embedded as Type0/CID subsets, so rendering is
  viewer-independent.

### Fixed
- Text annotations placed on rotated pages (`/Rotate 90`, `180`, `270`) now
  appear upright and at the correct position after signing.  Previously the
  text was rendered in the wrong orientation on all non-zero rotations.

## [0.3.6] – 2026-04-17

### Fixed
- Signature field appearance preview now matches the signed PDF at any zoom
  level. The horizontal text indent (`x`) and vertical baseline (`y`) were
  previously computed with fixed pixel offsets that only matched pyhanko's
  output at the preview-panel DPI (96/72 ≈ 1.333 px/pt). At higher zoom
  levels the text appeared noticeably shifted compared to the final signature.
  Both values are now proportional to `pixels_per_point`:
  - `x` uses 14 PDF points (4 pt outer margin + 10 pt inner text-box margin,
    matching pyhanko's `inner_content_layout` + `DEFAULT_TEXT_BOX_MARGIN`).
  - `y` uses the full em size instead of the font's `ascent`, matching
    pyhanko's first-baseline calculation (`field_h/2 + (n/2 − 1) × font_size`).

---

## [0.3.5] – 2026-04-16

### Added
- **Text annotations**: place free-text labels on PDF pages before signing.
  Click the text tool in the toolbar, click anywhere on the page, and type.
  Supports three fonts (Helvetica, Times, Courier), adjustable font size and
  colour, and optional character spacing. Annotations are saved as PDF
  FreeText objects (recoverable on re-open) and burned into the page content
  when signing, so they appear in every viewer without annotation support.

### Fixed
- Text annotation preview now uses the same URW/Nimbus fonts that
  PyMuPDF/fitz uses internally for PDF Base-14 fonts (Nimbus Sans, Nimbus
  Roman, Nimbus Mono PS), giving a pixel-accurate on-screen preview on Linux.
  On Windows the standard fallbacks (Arial, Times New Roman, Courier New) are
  used automatically.
- Text annotation baseline positioning corrected in both the interactive
  overlay and the burned-in PDF: the baseline now lands precisely at the
  clicked position. Previously the overlay used the full em-square height
  as offset instead of the true typographic ascent, and the signed PDF used
  approximate magic constants instead of fitz's actual internal baseline
  formula (`rect_top_pdf − 0.8 × font_size`).

---

## [0.3.4] – 2026-04-14

### Fixed
- Key generation dialog: openssl command text field now sizes itself to its
  content (no vertical scrollbar); entire form wrapped in a scroll area so
  all widgets remain reachable on small screens
- Selecting a signature field from the list now also adjusts the horizontal
  scroll position so the field is visible (single-page and continuous mode)
- Signature fields can no longer be drawn partially outside the page;
  coordinates are clamped to the page boundary using unrotated (mediabox)
  dimensions, which correctly handles all page rotations (0°/90°/180°/270°)
- Windows installer: downgrade is now detected before the first dialog;
  title and heading show "Downgrade Warning" (orange), action button says
  "Downgrade", and Enter/Escape default to Cancel
- Windows installer: update channel is now read from `settings.ini`
  instead of the Windows Registry; Registry write after install removed –
  `settings.ini` is the single source of truth for both app and installer
- Windows installer: main form action button always labelled "Install"
  (was dynamically changed to "Update" for existing installations)
- Windows installer: `settings.ini` is now written without BOM
  (`UTF8NoBOM`); previously the BOM caused a startup crash
  (`MissingSectionHeaderError`) when running on Windows
- Windows installer: `--installversion` flag now correctly skips its own
  argument (was: `shift` shifted `%0` as well; fixed with `shift /1`)
- App startup: INI files with BOM are now read correctly on all platforms
  (`utf-8-sig` codec strips the BOM automatically)

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
