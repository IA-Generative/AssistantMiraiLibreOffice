#!/usr/bin/env bash
# Build OXT, install extension, and open LibreOffice with a test document.
#
# Usage:
#   scripts/dev-launch.sh [--doc <path>] [--no-build] [--config <path>]
#
# Options:
#   --doc <path>     Document to open (default: tests/fixtures/sample.odt)
#   --no-build       Skip OXT build (use existing dist/mirai.oxt)
#   --config <path>  Config file passed to 02-build-oxt.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOFFICE="/Applications/LibreOffice.app/Contents/MacOS/soffice"
UNOPKG="/Applications/LibreOffice.app/Contents/MacOS/unopkg"
OXT_PATH="$ROOT_DIR/dist/mirai.oxt"
TEST_DOC="$ROOT_DIR/tests/fixtures/sample.odt"
DO_BUILD=true
BUILD_EXTRA_ARGS=()

log()  { printf '▶ %s\n' "$*"; }
ok()   { printf '✓ %s\n' "$*"; }
err()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ── Parse arguments ───────────────────────────────────────────────────────────
while [ "$#" -gt 0 ]; do
  case "$1" in
    --doc)
      TEST_DOC="${2:-}"; [ -n "$TEST_DOC" ] || err "Missing value for --doc"; shift 2 ;;
    --no-build)
      DO_BUILD=false; shift ;;
    --config)
      BUILD_EXTRA_ARGS+=(--config "${2:-}"); shift 2 ;;
    -h|--help)
      sed -n '2,10p' "$0"; exit 0 ;;
    *)
      err "Unknown option: $1" ;;
  esac
done

# ── Sanity checks ─────────────────────────────────────────────────────────────
[ -x "$SOFFICE" ] || err "LibreOffice not found at $SOFFICE"
[ -x "$UNOPKG"  ] || err "unopkg not found at $UNOPKG"

# ── 1. Quit LibreOffice if running ───────────────────────────────────────────
if pgrep -x soffice >/dev/null 2>&1; then
  log "Closing LibreOffice..."
  osascript -e 'tell application "LibreOffice" to quit' 2>/dev/null || true
  # Wait until process is gone (max 10 s)
  for i in $(seq 1 10); do
    pgrep -x soffice >/dev/null 2>&1 || break
    sleep 1
  done
fi

# ── 2. Build OXT ─────────────────────────────────────────────────────────────
if [ "$DO_BUILD" = true ]; then
  log "Building OXT..."
  "$ROOT_DIR/scripts/02-build-oxt.sh" "${BUILD_EXTRA_ARGS[@]+"${BUILD_EXTRA_ARGS[@]}"}"
  ok "OXT built: $OXT_PATH"
else
  [ -f "$OXT_PATH" ] || err "OXT not found: $OXT_PATH (run without --no-build first)"
  log "Skipping build, using: $OXT_PATH"
fi

# ── 3. Install extension ──────────────────────────────────────────────────────
log "Installing extension..."
"$UNOPKG" add --replace "$OXT_PATH" 2>/dev/null || {
  "$UNOPKG" remove "fr.gouv.interieur.mirai" 2>/dev/null || true
  printf "yes\n" | "$UNOPKG" add "$OXT_PATH"
}
ok "Extension installed"

# ── 4. Create test document if needed ────────────────────────────────────────
if [ ! -f "$TEST_DOC" ]; then
  log "Creating test document: $TEST_DOC"
  python3 "$ROOT_DIR/scripts/_make_sample_odt.py" "$TEST_DOC"
  ok "Test document created"
fi

# ── 5. Launch LibreOffice with the document ───────────────────────────────────
log "Opening: $TEST_DOC"
open -a LibreOffice "$TEST_DOC"
ok "LibreOffice launched"
