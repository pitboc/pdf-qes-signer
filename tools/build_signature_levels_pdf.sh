#!/usr/bin/env bash
# Builds docs/signature-levels.pdf from docs/signature-levels.md
# via pandoc + lualatex using docs/latex/signature_levels_template.tex.
# English sibling of build_signatur_stufen_pdf.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

pandoc docs/signature-levels.md \
  --from=markdown+raw_tex \
  --pdf-engine=lualatex \
  --template=docs/latex/signature_levels_template.tex \
  --toc --toc-depth=2 \
  -V lang=en \
  -o docs/signature-levels.pdf

mkdir -p pdf_signer/docs
cp docs/signature-levels.pdf pdf_signer/docs/signature-levels.pdf

echo "PDF built: docs/signature-levels.pdf"
echo "Copied for packaging: pdf_signer/docs/signature-levels.pdf"
