#!/usr/bin/env bash
# Start PDF QES Signer inside the venv
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.venv/bin/activate"
exec python -m pdf_signer "$@"
