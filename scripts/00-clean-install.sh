#!/usr/bin/env bash
# Reset the LibreOffice plugin to a clean-install state.
#
# What this does:
#   1. Quit LibreOffice (if running)
#   2. Reset config.json  → keep only bootstrap_url / config_path
#   3. Delete LibreOffice log files  (unopkg.log, GraphicsRenderTests.log)
#   4. Purge extension temp cache    (extensions/tmp/)
#   5. Uninstall the Mirai extension (optional, --uninstall flag)
#
# Usage:
#   scripts/00-clean-install.sh [--uninstall] [--config <profile.json>]
#   scripts/00-clean-install.sh [--uninstall] [--bootstrap-url <url>] [--config-path <path>]

set -euo pipefail

SOFFICE="/Applications/LibreOffice.app/Contents/MacOS/soffice"
UNOPKG="/Applications/LibreOffice.app/Contents/MacOS/unopkg"
LO_USER_DIR="$HOME/Library/Application Support/LibreOffice/4/user"
CONFIG_FILE="$LO_USER_DIR/config/config.json"

BOOTSTRAP_URL=""
CONFIG_PATH=""
CONFIG_PROFILE=""
DO_UNINSTALL=false

log()  { printf '▶ %s\n' "$*"; }
ok()   { printf '✓ %s\n' "$*"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --uninstall)          DO_UNINSTALL=true; shift ;;
    --config)             CONFIG_PROFILE="${2:-}"; shift 2 ;;
    --bootstrap-url)      BOOTSTRAP_URL="${2:-}"; shift 2 ;;
    --config-path)        CONFIG_PATH="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '2,12p' "$0"; exit 0 ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2; exit 1 ;;
  esac
done

# If --config was given, use it as the initial config file directly
if [ -n "$CONFIG_PROFILE" ]; then
  if [ ! -f "$CONFIG_PROFILE" ]; then
    printf 'ERROR: config profile not found: %s\n' "$CONFIG_PROFILE" >&2; exit 1
  fi
elif [ -z "$BOOTSTRAP_URL" ]; then
  # Default fallback
  BOOTSTRAP_URL="http://localhost:3001"
  CONFIG_PATH="/config/libreoffice/config.json?profile=dev"
fi

# ── 1. Quit LibreOffice ───────────────────────────────────────────────────────
if pgrep -x soffice >/dev/null 2>&1; then
  log "Closing LibreOffice..."
  osascript -e 'tell application "LibreOffice" to quit' 2>/dev/null || true
  for i in $(seq 1 10); do
    pgrep -x soffice >/dev/null 2>&1 || break
    sleep 1
  done
  ok "LibreOffice closed"
fi

# ── 2. Reset config.json ──────────────────────────────────────────────────────
log "Resetting config.json..."
mkdir -p "$(dirname "$CONFIG_FILE")"
if [ -n "$CONFIG_PROFILE" ]; then
  cp "$CONFIG_PROFILE" "$CONFIG_FILE"
  ok "config.json reset from profile → $CONFIG_PROFILE"
else
  python3 - "$CONFIG_FILE" "$BOOTSTRAP_URL" "$CONFIG_PATH" <<'PY'
import json, sys
path, bootstrap_url, config_path = sys.argv[1], sys.argv[2], sys.argv[3]
data = {
    "configVersion": 1,
    "enabled": True,
    "bootstrap_url": bootstrap_url,
    "config_path": config_path,
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=4, ensure_ascii=False)
    f.write("\n")
PY
  ok "config.json reset → $CONFIG_FILE"
fi

# ── 3. Delete log files ───────────────────────────────────────────────────────
log "Deleting log files..."
rm -f "$LO_USER_DIR/unopkg.log"
rm -f "$LO_USER_DIR/GraphicsRenderTests.log"
ok "Log files deleted"

# ── 4. Purge extension temp cache ─────────────────────────────────────────────
log "Purging extension temp cache..."
rm -rf "$LO_USER_DIR/extensions/tmp/"
ok "Extension temp cache purged"

# ── 5. Uninstall extension (optional) ────────────────────────────────────────
if [ "$DO_UNINSTALL" = true ]; then
  if [ -x "$UNOPKG" ]; then
    log "Uninstalling Mirai extension..."
    "$UNOPKG" remove "fr.gouv.interieur.mirai" 2>/dev/null && ok "Extension uninstalled" || ok "Extension was not installed"
  else
    printf 'WARN: unopkg not found at %s — skipping uninstall\n' "$UNOPKG" >&2
  fi
fi

printf '\n✓ Clean install ready. Run scripts/dev-launch.sh to reinstall.\n'
