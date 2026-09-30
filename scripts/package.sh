#!/usr/bin/env bash
# Build a clean, distributable archive of SentinelX.
#
# A plain `zip -r SentinelX.zip SentinelX/` is NOT git-aware -- .gitignore
# does nothing for it, so __pycache__/, .pytest_cache/, and *.pyc files
# sneak into the archive. This script cleans compiled artifacts first and
# then explicitly excludes them (and other non-shippable paths) from the
# zip, so the two guardrails don't rely on each other.
#
# Usage: ./scripts/package.sh [output-name.zip]

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

OUT="${1:-SentinelX.zip}"

echo "Cleaning compiled/cache artifacts..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete
rm -rf reports/

echo "Building ${OUT}..."
rm -f "${OUT}"
zip -qr "${OUT}" . \
  -x "*.git*" \
  -x "*__pycache__*" \
  -x "*.pytest_cache*" \
  -x "*.pyc" \
  -x "reports/*" \
  -x "*.venv*" \
  -x "${OUT}"

echo "Done: ${OUT}"
