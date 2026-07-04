#!/usr/bin/env bash
# Builds docs/user-manual.pdf from docs/user-manual.md
# via pandoc + lualatex using docs/latex/user_manual_template.tex.
set -euo pipefail
cd "$(dirname "$0")/.."

pandoc docs/user-manual.md \
  --from=markdown+raw_tex \
  --pdf-engine=lualatex \
  --template=docs/latex/user_manual_template.tex \
  --toc --toc-depth=2 \
  -V lang=en \
  -o docs/user-manual.pdf

mkdir -p pdf_signer/docs
cp docs/user-manual.pdf pdf_signer/docs/user-manual.pdf

echo "PDF built: docs/user-manual.pdf"
echo "Copied for packaging: pdf_signer/docs/user-manual.pdf"
