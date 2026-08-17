#!/usr/bin/env bash
# PDF QES Signer – Linux Installer
#
# Downloads and installs pdf-qes-signer from Codeberg into a Python venv.
# Does not require root – everything goes into ~/.local/share/pdf-signer/.
#
# Usage:  bash setup_pdf_signer.sh [--installversion vX.Y.Z]
#
# Options:
#   --installversion vX.Y.Z   Install a specific version (e.g. v0.3.3).
#                             Use this to downgrade or pin a release.

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
INSTALL_DIR="$HOME/.local/share/pdf-signer"
VENV_DIR="$INSTALL_DIR/.venv"
CONFIG_DIR="$HOME/.config/pdf-signer"
CONFIG_FILE="$CONFIG_DIR/install.conf"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/pdf-signer.desktop"
BIN_DIR="$HOME/.local/bin"
SYMLINK="$BIN_DIR/pdf-signer"
STARTER="$INSTALL_DIR/pdf-signer.sh"
UNINSTALLER="$INSTALL_DIR/uninstall.sh"
# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
bold()  { printf '\033[1m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
yellow(){ printf '\033[33m%s\033[0m' "$*"; }
red()   { printf '\033[31m%s\033[0m' "$*"; }

ok()   { echo "  $(green "✓") $*"; }
warn() { echo "  $(yellow "!") $*"; }
fail() { echo "  $(red   "✗") $*"; }

die() { fail "$*"; exit 1; }

header() {
    echo
    echo "$(bold "=== $* ===")"
    echo
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
INSTALL_VERSION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --installversion)
            INSTALL_VERSION="${2:-}"
            [[ -z "$INSTALL_VERSION" ]] && die "--installversion requires a version argument (e.g. v0.3.3)"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Detect update vs. fresh install
# ---------------------------------------------------------------------------
IS_UPGRADE=false
if [[ -f "$CONFIG_FILE" && -x "$VENV_DIR/bin/python" ]]; then
    IS_UPGRADE=true
fi

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
clear
echo
echo "$(bold "PDF QES Signer – Linux Installer")"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
if $IS_UPGRADE; then
    echo "An existing installation was detected – this will update pdf-signer."
else
    echo "This installer will set up PDF QES Signer in:"
    echo "  $INSTALL_DIR"
fi
echo

# ---------------------------------------------------------------------------
# GPL notice + confirmation
# ---------------------------------------------------------------------------
echo "$(bold "License")"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat <<'EOF'

PDF QES Signer is free software, distributed under the terms of the
GNU General Public License, version 3 or later (GPL-3.0-or-later).

You may use, copy, modify and distribute this software under the
conditions of the GPL. The full license text is available at:

  https://www.gnu.org/licenses/gpl-3.0.html

EOF
read -rp "Press Enter to accept the license and continue, or Ctrl+C to abort ... "
echo

# ---------------------------------------------------------------------------
# Release channel
# ---------------------------------------------------------------------------
CHANNEL="stable"
if $IS_UPGRADE; then
    CHANNEL=$(grep '^channel=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "stable")
fi

if [[ -n "$INSTALL_VERSION" ]]; then
    # Specific version requested – skip channel selection, keep existing channel
    ok "Installing specific version: $INSTALL_VERSION (channel: $CHANNEL)"
    echo
else
    header "Update channel"

    echo "  Which update channel do you want to use?"
    echo
    if [[ "$CHANNEL" == "develop" ]]; then
        echo "    1) stable   – official releases  (recommended)"
        echo "    2) develop  – pre-releases and test builds  [current]"
        echo
        read -rp "  Your choice [1/2, default: 2 (develop)]: " _ch
        case "${_ch}" in
            1) CHANNEL="stable" ;;
            *) :                 ;;
        esac
    else
        echo "    1) stable   – official releases  (recommended)"
        echo "    2) develop  – pre-releases and test builds"
        echo
        read -rp "  Your choice [1/2, default: 1 (stable)]: " _ch
        case "${_ch}" in
            2) CHANNEL="develop" ;;
            *) :                  ;;
        esac
    fi

    if [[ "$CHANNEL" == "develop" ]]; then
        ok "Channel: develop (pre-releases)"
    else
        ok "Channel: stable (recommended)"
    fi
    echo
fi

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------
header "Checking prerequisites"

# Python
PYTHON=""
for cmd in python3.13 python3.12 python3.11 python3; do
    if command -v "$cmd" &>/dev/null; then
        major=$("$cmd" -c 'import sys; print(sys.version_info.major)')
        minor=$("$cmd" -c 'import sys; print(sys.version_info.minor)')
        if [[ "$major" -ge 3 && "$minor" -ge 11 ]]; then
            PYTHON="$cmd"
            ok "Python $major.$minor found ($cmd)"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    fail "Python 3.11 or newer not found."
    echo
    echo "  Please install Python using your package manager:"
    echo
    echo "    Debian / Ubuntu:   sudo apt install python3 python3-venv"
    echo "    Fedora / RHEL:     sudo dnf install python3"
    echo "    Arch Linux:        sudo pacman -S python"
    echo "    openSUSE:          sudo zypper install python3"
    echo
    die "Aborting. Re-run this installer after installing Python."
fi

# python3-venv (separate package on Debian/Ubuntu)
if ! "$PYTHON" -c "import venv" &>/dev/null; then
    fail "Python module 'venv' not found."
    echo
    echo "  Please install it using your package manager:"
    echo
    echo "    Debian / Ubuntu:   sudo apt install python3-venv"
    echo "    Fedora / RHEL:     (included with python3)"
    echo "    Arch Linux:        (included with python)"
    echo "    openSUSE:          sudo zypper install python3-venv"
    echo
    die "Aborting. Re-run this installer after installing python3-venv."
fi

# Downloader
if command -v curl &>/dev/null; then
    DOWNLOADER="curl"
    ok "curl found"
elif command -v wget &>/dev/null; then
    DOWNLOADER="wget"
    ok "wget found"
else
    die "Neither curl nor wget found. Please install one of them."
fi

# ---------------------------------------------------------------------------
# Fetch release info / build URL
# ---------------------------------------------------------------------------
header "Fetching release information"

if [[ -n "$INSTALL_VERSION" ]]; then
    # Specific version: build URL directly, no API call needed
    TAG="$INSTALL_VERSION"
    VERSION="${TAG#v}"
    WHL_URL="https://codeberg.org/pitbo/pdf-qes-signer/releases/download/${TAG}/pdf_qes_signer-${VERSION}-py3-none-any.whl"
    ok "Target version: $VERSION"
    ok "Package: $(basename "$WHL_URL")"
else
    echo "  Contacting Codeberg API ..."

    if [[ "$CHANNEL" == "develop" ]]; then
        API_URL="https://codeberg.org/api/v1/repos/pitbo/pdf-qes-signer/releases?limit=5"
    else
        API_URL="https://codeberg.org/api/v1/repos/pitbo/pdf-qes-signer/releases/latest"
    fi

    if [[ "$DOWNLOADER" == "curl" ]]; then
        release_json=$(curl -fsSL "$API_URL") || die "Failed to contact Codeberg API."
    else
        release_json=$(wget -qO- "$API_URL") || die "Failed to contact Codeberg API."
    fi

    VERSION=$(echo "$release_json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
if isinstance(data, list):
    if not data: raise SystemExit('No releases found.')
    data = data[0]
print(data['tag_name'])
")
    WHL_URL=$(echo "$release_json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
if isinstance(data, list):
    if not data: raise SystemExit('No releases found.')
    data = data[0]
assets = data.get('assets', [])
whl = next((a['browser_download_url'] for a in assets if a['name'].endswith('.whl')), None)
if not whl:
    raise SystemExit('No .whl asset found in latest release.')
print(whl)
")

    ok "Latest release: $VERSION"
    ok "Package: $(basename "$WHL_URL")"
fi

if $IS_UPGRADE; then
    installed_version=$(
        "$VENV_DIR/bin/python" -c \
        "import importlib.metadata; print(importlib.metadata.version('pdf-qes-signer'))" \
        2>/dev/null || echo "")
    [[ -n "$installed_version" ]] && ok "Installed version:  $installed_version"
    ok "Target version:     $VERSION"
    echo
    if [[ "$installed_version" == "$VERSION" ]]; then
        warn "Version $VERSION is already installed."
        read -rp "  Reinstall anyway? [y/N] " answer
        [[ "${answer,,}" == "y" ]] || { echo "  Aborted."; exit 0; }
    else
        higher=$(printf '%s\n' "$installed_version" "$VERSION" | sort -V | tail -1)
        if [[ "$higher" == "$installed_version" ]]; then
            warn "Downgrade detected: $installed_version → $VERSION"
            read -rp "  Continue with downgrade? [y/N] " answer
            [[ "${answer,,}" == "y" ]] || { echo "  Aborted."; exit 0; }
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
header "Installing"

echo "  Creating directories ..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DESKTOP_DIR" "$BIN_DIR"
ok "Directories ready"

# venv
if $IS_UPGRADE; then
    echo "  Updating existing venv ..."
else
    echo "  Creating Python virtual environment ..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

# Some distros (e.g. minimal Debian/Ubuntu installs) create a venv without
# pip even though python3-venv is present, because pip itself lives in the
# separate python3-pip package. Bootstrap it via ensurepip if missing.
if [[ ! -x "$VENV_DIR/bin/pip" ]]; then
    echo "  pip missing in venv, bootstrapping via ensurepip ..."
    if ! "$VENV_DIR/bin/python" -m ensurepip --upgrade --default-pip &>/dev/null; then
        fail "Could not install pip into the virtual environment."
        echo
        echo "  Please install pip for your Python interpreter and re-run this installer:"
        echo
        echo "    Debian / Ubuntu:   sudo apt install python3-pip"
        echo "    Fedora / RHEL:     sudo dnf install python3-pip"
        echo "    Arch Linux:        sudo pacman -S python-pip"
        echo "    openSUSE:          sudo zypper install python3-pip"
        echo
        die "Aborting. Re-run this installer after installing pip."
    fi
fi
ok "venv ready"

# pip install
echo "  Installing pdf-qes-signer $VERSION ..."
if [[ -n "$INSTALL_VERSION" ]]; then
    "$VENV_DIR/bin/pip" install --quiet --force-reinstall "$WHL_URL" \
        || die "pip install failed."
else
    "$VENV_DIR/bin/pip" install --quiet --upgrade "$WHL_URL" \
        || die "pip install failed."
fi
ok "pdf-qes-signer $VERSION installed"

# Detect Python version inside venv (for icon path)
VENV_PY_VER=$("$VENV_DIR/bin/python" -c \
    "import sys; print(f'python{sys.version_info.major}.{sys.version_info.minor}')")
ICON_PATH="$VENV_DIR/lib/$VENV_PY_VER/site-packages/pdf_signer/icons/app.png"

# Starter script
echo "  Writing starter script ..."
cat > "$STARTER" <<STARTER_SCRIPT
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python" -m pdf_signer "\$@"
STARTER_SCRIPT
chmod +x "$STARTER"
ok "Starter script: $STARTER"

# Symlink
echo "  Creating symlink in $BIN_DIR ..."
ln -sf "$STARTER" "$SYMLINK"
ok "Symlink: $SYMLINK → pdf-signer"

# Ensure ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    if ! grep -qF '.local/bin' "$HOME/.bashrc" 2>/dev/null; then
        {
            echo ''
            echo '# Added by pdf-signer installer'
            echo 'export PATH="$HOME/.local/bin:$PATH"'
        } >> "$HOME/.bashrc"
        warn "$BIN_DIR added to PATH in ~/.bashrc"
        warn "Restart your shell or run: source ~/.bashrc"
    fi
fi

# .desktop file
echo "  Writing desktop entry ..."
cat > "$DESKTOP_FILE" <<DESKTOP
[Desktop Entry]
Name=PDF QES Signer
Comment=Place signature fields in PDFs and apply qualified electronic signatures
Exec=$STARTER %f
Icon=$ICON_PATH
Type=Application
MimeType=application/pdf;
Categories=Office;
StartupNotify=true
DESKTOP
ok "Desktop entry: $DESKTOP_FILE"

if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi

# Uninstaller
echo "  Writing uninstaller ..."
cat > "$UNINSTALLER" <<UNINSTALL_SCRIPT
#!/usr/bin/env bash
# PDF QES Signer – Uninstaller
set -euo pipefail

echo "Removing PDF QES Signer ..."

rm -rf  "$INSTALL_DIR"
rm -f   "$DESKTOP_FILE"
rm -f   "$SYMLINK"
rm -rf  "$CONFIG_DIR"

if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi

echo "Done. PDF QES Signer has been removed."
echo "Note: Python and system packages were not removed."
UNINSTALL_SCRIPT
chmod +x "$UNINSTALLER"
ok "Uninstaller: $UNINSTALLER"

# install.conf
cat > "$CONFIG_FILE" <<CONF
# PDF QES Signer – installation metadata
install_dir=$INSTALL_DIR
installed_at=$(date -Iseconds)
channel=$CHANNEL
CONF
ok "Config saved: $CONFIG_FILE"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  $(green "$(bold "Installation complete!")") PDF QES Signer $VERSION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "  Start from terminal:   pdf-signer [file.pdf]"
echo "  Start from launcher:   search for 'PDF QES Signer'"
echo "  Open PDF with:         right-click → Open With → PDF QES Signer"
echo
echo "  To uninstall:          $UNINSTALLER"
echo
