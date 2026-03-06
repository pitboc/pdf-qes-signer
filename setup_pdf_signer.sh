#!/usr/bin/env bash
# =============================================================
#  PDF QES Signer – Setup Script
#  Creates a Python venv and installs all dependencies.
# =============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON="${PYTHON:-python3}"

# ── Colour helpers ─────────────────────────────────────────────────────────
GREEN="\e[32m"; YELLOW="\e[33m"; RED="\e[31m"; RESET="\e[0m"
info()  { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
error() { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║       PDF QES Signer – Setup         ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# ── Check Python ───────────────────────────────────────────────────────────
command -v "$PYTHON" &>/dev/null \
    || error "python3 not found. Please install: sudo apt install python3"

PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
info "Python $PY_VER found: $($PYTHON -c 'import sys; print(sys.executable)')"

"$PYTHON" -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" \
    || error "Python 3.9 or newer required (found: $PY_VER)."

# ── Create venv ────────────────────────────────────────────────────────────
if [ -d "$VENV_DIR" ]; then
    warn "Existing venv found: $VENV_DIR"
    read -rp "      Recreate? [y/N] " ans
    if [[ "$ans" =~ ^[yYjJ]$ ]]; then
        rm -rf "$VENV_DIR"
        info "Old venv removed."
    else
        info "Using existing venv."
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    info "Creating venv in: $VENV_DIR"
    "$PYTHON" -m venv "$VENV_DIR"
fi

# ── Upgrade pip ────────────────────────────────────────────────────────────
PIP="$VENV_DIR/bin/pip"
info "Upgrading pip…"
"$PIP" install --upgrade pip --quiet

# ── Install dependencies ───────────────────────────────────────────────────
PACKAGES=(
    "pymupdf"
    "Pillow"
    "pyhanko"
    "pyhanko-certvalidator"
    "python-pkcs11"
    "PyQt6"
    "cryptography"
)

echo ""
echo "  Installing packages:"
for pkg in "${PACKAGES[@]}"; do
    echo -n "    • $pkg … "
    if "$PIP" install "$pkg" --quiet 2>/dev/null; then
        echo -e "${GREEN}OK${RESET}"
    else
        echo -e "${YELLOW}WARNING (optional)${RESET}"
        warn "$pkg could not be installed – QES functionality may be limited."
    fi
done

# ── Install the package itself (registers metadata for importlib.metadata) ──
echo -n "    • setuptools … "
"$PIP" install --upgrade setuptools wheel --quiet 2>/dev/null \
    && echo -e "${GREEN}OK${RESET}" || echo -e "${YELLOW}WARNING${RESET}"
echo -n "    • pdf-qes-signer (package) … "
if "$PIP" install -e "$SCRIPT_DIR" --quiet 2>/dev/null; then
    echo -e "${GREEN}OK${RESET}"
else
    echo -e "${YELLOW}WARNING${RESET}"
    warn "Package install failed – version will show as 0.0.0+dev."
fi

# ── Create launcher script ─────────────────────────────────────────────────
LAUNCHER="$SCRIPT_DIR/start_signer.sh"
cat > "$LAUNCHER" <<'EOF'
#!/usr/bin/env bash
# Start PDF QES Signer inside the venv
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.venv/bin/activate"
exec python -m pdf_signer "$@"
EOF
chmod +x "$LAUNCHER"
info "Launcher created: $LAUNCHER"

# ── Desktop entry (optional) ───────────────────────────────────────────────
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/pdf-qes-signer.desktop"
mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=PDF QES Signer
Comment=Place signature fields and apply QES signatures to PDF documents
Exec=$LAUNCHER
Icon=application-pdf
Terminal=false
Categories=Office;
EOF
info "Desktop entry created: $DESKTOP_FILE"

# ── Done ───────────────────────────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║  Setup complete! ✓                   ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
echo "  Start with:"
echo -e "    ${GREEN}./start_signer.sh${RESET}"
echo ""
echo "  Or manually:"
echo -e "    ${GREEN}source .venv/bin/activate && python -m pdf_signer${RESET}"
echo ""
