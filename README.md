# PDF QES Signer

A GUI tool for visually placing signature fields in PDF documents and applying
**qualified electronic signatures (QES)** via PKCS#11 / smartcard.

> **Repository:**
> Primary: [codeberg.org/pitbo/pdf-qes-signer](https://codeberg.org/pitbo/pdf-qes-signer)
> Mirror: [github.com/pitboc/pdf-qes-signer](https://github.com/pitboc/pdf-qes-signer) *(read-only)*
>
> **Issues and contributions:** Please use the Codeberg repository.
> The GitHub repository is a read-only mirror and does not accept issues or pull requests.

## Background and motivation

Qualified electronic signatures (QES) in Germany require a signature card issued
by an accredited trust service provider. Deutsche Telekom Security GmbH issues
TCOS-based QES cards (model **TCOS 3.0 SigG**) under the Telesec brand.

On Linux, these cards are **not properly supported by OpenSC** – the standard
open-source PKCS#11 middleware. The proprietary PKCS#11 library provided by
Deutsche Telekom (`libpkcs11tcos_SigG_PCSC.so`) is required instead.

At the time this project was started, **no free signing software for Linux**
was available that worked reliably with these cards and allowed visually placing
signature fields in a PDF. PDF QES Signer was created to fill this gap.

### Tested hardware

| Property          | Value                          |
|-------------------|--------------------------------|
| Token manufacturer | DEUTSCHE TELEKOM SECURITY GMBH |
| Token model       | TCOS 3.0 SigG                  |
| Hardware version  | 4.32                           |
| Firmware version  | 3.0                            |
| PKCS#11 library   | `libpkcs11tcos_SigG_PCSC.so`   |

The library is distributed by Deutsche Telekom together with the card and is
**not** included in this repository.  You can verify your card is recognized
with:

```bash
pkcs11-tool --module ./libpkcs11tcos_SigG_PCSC.so --list-slots
```

## Features

- Open PDF files and navigate multi-page documents
- Draw signature fields by left-click and drag on the PDF canvas
- Click an existing field to select it; right-click to delete it
- Selected field is highlighted with a bold border and shows the visual appearance preview
- Configure visual appearance: optional PNG image (with transparency),
  signer name, location, reason, and date
- Apply a QES signature via any PKCS#11-compatible smartcard or USB token —
  specifically tested and developed for **Telesec TCOS 3.0 SigG** cards
- PIN-pad support: leave the PIN field empty to use the hardware PIN pad;
  the PKCS#11 session is kept open so the PIN is requested only once
- Chain multiple signatures: after signing, the signed PDF is reloaded
  automatically so further fields can be signed in sequence
- Existing unsigned fields in already-signed PDFs are shown as locked (orange)
  and protected from modification to preserve the existing signature hash
- Bilingual UI: German and English (switchable at runtime)
- Persistent configuration in `~/.config/pdf-signer/pdf_signer.ini`

## Requirements

- Python ≥ 3.9
- [pymupdf](https://pymupdf.readthedocs.io/) (`fitz` / `pymupdf`)
- [Pillow](https://pillow.readthedocs.io/)
- [PyQt6](https://pypi.org/project/PyQt6/)
- [pyhanko](https://pyhanko.readthedocs.io/) + pyhanko-certvalidator
- [python-pkcs11](https://python-pkcs11.readthedocs.io/)
- [cryptography](https://cryptography.io/)

### Windows: additional prerequisites

- **Python 3.9+** – install from [python.org](https://www.python.org/downloads/);
  check *"Add python.exe to PATH"* during installation
- **Microsoft Visual C++ Redistributable 2015–2022 (x64)** – required by PyMuPDF;
  download from Microsoft:
  [vc_redist.x64.exe](https://aka.ms/vs/17/release/vc_redist.x64.exe)

## Installation

> **Note:** The current development version (master branch) contains the latest
> features and fixes and is generally preferred over the tagged releases.

### Option A – Download archive (recommended for end users)

**Linux / macOS** – download and extract the `.tar.gz` archive:

```bash
wget https://codeberg.org/pitbo/pdf-qes-signer/archive/master.tar.gz
tar xf master.tar.gz
cd pdf-qes-signer
./setup_pdf_signer.sh
```

**Windows** – download the `.zip` archive:

1. Download [master.zip](https://codeberg.org/pitbo/pdf-qes-signer/archive/master.zip)
2. Extract the archive (right-click → *Extract All…*)
3. Open the extracted folder and double-click `setup_pdf_signer.bat`

### Option B – Clone with Git

```bash
# Primary (Codeberg)
git clone https://codeberg.org/pitbo/pdf-qes-signer.git

# Mirror (GitHub)
git clone https://github.com/pitboc/pdf-qes-signer.git

cd pdf-qes-signer
```

**Linux / macOS:**
```bash
./setup_pdf_signer.sh
```

**Windows:**
```cmd
setup_pdf_signer.bat
```

The setup script creates a `.venv/` virtual environment, installs all
dependencies, and generates a launcher script.

## Usage

**Linux / macOS:**
```bash
./start_signer.sh [PDF_FILE]
```

**Windows:**
```cmd
start_signer.bat [PDF_FILE]
```

Or manually:

```bash
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate.bat       # Windows
python -m pdf_signer [PDF_FILE]
```

### Workflow

1. **Open** a PDF via *File → Open PDF* or the toolbar button.
2. **Draw** one or more signature fields by left-click + drag on the page.
3. **Configure** the visual appearance in the right panel (Text / Image tabs).
4. **Configure** the PKCS#11 token via *Settings → Configure PKCS#11 / Token*:
   - Enter the path to your PKCS#11 library.
     - Telesec TCOS card: `/path/to/libpkcs11tcos_SigG_PCSC.so`
     - Other cards: e.g. `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`
   - Click *Test Token* to read key and certificate labels.
   - Select the correct key label.
5. **Enter your PIN** in the Token / PIN panel (or leave empty for PIN-pad).
6. **Select** the target signature field in the list (or "invisible" for a
   non-visual signature) – either by clicking the field in the PDF view or
   by selecting it in the field list on the right.
7. **Sign** via *Sign → Sign document (QES)* or the toolbar button and
   choose the output file location.

### Save fields without signing

Use *File → Save with fields (copy)* to embed the signature field annotations
into a PDF copy without applying a signature. This is useful for preparing
documents that others will sign later.

## Configuration

The application stores its settings in `~/.config/pdf-signer/pdf_signer.ini`.
See [`pdf_signer.ini.example`](pdf_signer.ini.example) for all available options
with default values.

## Project structure

```
pdf_signer/
├── __init__.py        # package marker, version
├── __main__.py        # enables python -m pdf_signer
├── main.py            # entry point: argument parsing, QApplication
├── config.py          # AppConfig (INI persistence), PDF_STANDARD_FONTS
├── appearance.py      # SigAppearance, Qt and Pillow renderers
├── signer.py          # SaveFieldsWorker, SignWorker, PKCS#11 logic
├── pdf_view.py        # PDFViewWidget, SignatureFieldDef
├── dialogs.py         # Pkcs11ConfigDialog, AppearanceConfigDialog, TokenInfoDialog
├── main_window.py     # PDFSignerApp main window
└── i18n/
    ├── __init__.py    # I18n class, t() function
    ├── de.py          # German translations
    └── en.py          # English translations
```

## API documentation

The source modules contain detailed docstrings explaining both the public API
and key architectural decisions (field categories, incremental write strategy,
image-padding trick, coordinate systems). To browse them as HTML:

```bash
source .venv/bin/activate
pip install pdoc          # once, as a development tool
pdoc pdf_signer           # opens browser – no files written to disk
```

## License

GNU General Public License v3.0 or later – see [LICENSE](LICENSE).
