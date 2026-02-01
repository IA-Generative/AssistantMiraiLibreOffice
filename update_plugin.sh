#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Build + install + relance de LibreOffice..."
"$SCRIPT_DIR/build.sh" --install --restart
