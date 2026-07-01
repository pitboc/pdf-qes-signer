#!/usr/bin/env bash
# Erzeugt docs/signatur-stufen.pdf aus docs/signatur-stufen.md
# via pandoc + lualatex und der projektlokalen Vorlage docs/latex/qes_template.tex.
set -euo pipefail
cd "$(dirname "$0")/.."

pandoc docs/signatur-stufen.md \
  --from=markdown+raw_tex \
  --pdf-engine=lualatex \
  --template=docs/latex/qes_template.tex \
  --toc --toc-depth=2 \
  -V lang=de \
  -o docs/signatur-stufen.pdf

echo "PDF erstellt: docs/signatur-stufen.pdf"
