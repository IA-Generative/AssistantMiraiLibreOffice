#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--config <path>] [--output <path>]

Build + install + restart LibreOffice.
Extra options are passed to 02-build-oxt.sh.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

echo "Build + install + restart LibreOffice..."
"$ROOT_DIR/scripts/02-build-oxt.sh" --install --restart "$@"
