#!/usr/bin/env bash
# Build LibreOffice OXT package for mirai

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXTENSION_NAME="mirai"

INSTALL_AFTER_BUILD=false
RESTART_LIBREOFFICE=false
OUTPUT_PATH="$ROOT_DIR/dist/${EXTENSION_NAME}.oxt"
CONFIG_PATH=""

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --install                 Install extension after build (unopkg)
  --restart                 Restart LibreOffice after install
  --config <path>           Config file to embed as config.default.json
  --output <path>           Output OXT file path (default: ./dist/mirai.oxt)
  -h, --help                Show this help
USAGE
}

log() { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "Command not found: $1"
    exit 1
  }
}

resolve_config_path() {
  if [ -n "$CONFIG_PATH" ]; then
    [ -f "$CONFIG_PATH" ] || { err "Config file not found: $CONFIG_PATH"; exit 1; }
    printf '%s' "$CONFIG_PATH"
    return
  fi

  local prod="$ROOT_DIR/config/config.default.json"
  local example="$ROOT_DIR/config/config.default.example.json"

  if [ -f "$prod" ]; then
    printf '%s' "$prod"
  elif [ -f "$example" ]; then
    warn "config/config.default.json missing, using config.default.example.json"
    printf '%s' "$example"
  else
    err "No config.default found (config/config.default.json or config/config.default.example.json)"
    exit 1
  fi
}

find_unopkg() {
  local os_name="$1"
  local unopkg_bin
  unopkg_bin="$(command -v unopkg || true)"
  if [ -n "$unopkg_bin" ]; then
    printf '%s' "$unopkg_bin"
    return
  fi

  if [ "$os_name" = "Darwin" ] && [ -x "/Applications/LibreOffice.app/Contents/MacOS/unopkg" ]; then
    printf '%s' "/Applications/LibreOffice.app/Contents/MacOS/unopkg"
    return
  fi

  if [ "$os_name" = "Linux" ]; then
    for candidate in /usr/lib/libreoffice/program/unopkg /usr/bin/unopkg /snap/bin/unopkg; do
      [ -x "$candidate" ] && { printf '%s' "$candidate"; return; }
    done
  fi

  for candidate in \
    "/c/Program Files/LibreOffice/program/unopkg.com" \
    "/c/Program Files/LibreOffice/program/unopkg.exe" \
    "/c/Program Files (x86)/LibreOffice/program/unopkg.com" \
    "/c/Program Files (x86)/LibreOffice/program/unopkg.exe"; do
    [ -x "$candidate" ] && { printf '%s' "$candidate"; return; }
  done

  printf ''
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install)
      INSTALL_AFTER_BUILD=true
      shift
      ;;
    --restart)
      RESTART_LIBREOFFICE=true
      shift
      ;;
    --config)
      CONFIG_PATH="${2:-}"
      [ -n "$CONFIG_PATH" ] || { err "Missing value for --config"; exit 1; }
      shift 2
      ;;
    --output)
      OUTPUT_PATH="${2:-}"
      [ -n "$OUTPUT_PATH" ] || { err "Missing value for --output"; exit 1; }
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

require_cmd zip

[ -d "$ROOT_DIR/oxt" ] || { err "Missing directory: oxt"; exit 1; }
[ -d "$ROOT_DIR/src" ] || { err "Missing directory: src"; exit 1; }
[ -f "$ROOT_DIR/main.py" ] || { err "Missing file: main.py"; exit 1; }

CONFIG_IN_USE="$(resolve_config_path)"

mkdir -p "$(dirname "$OUTPUT_PATH")"
if [ -f "$OUTPUT_PATH" ]; then
  log "Removing previous package: $OUTPUT_PATH"
  rm -f "$OUTPUT_PATH"
fi

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

cp -R "$ROOT_DIR/oxt/." "$STAGE_DIR/"
cp "$ROOT_DIR/main.py" "$STAGE_DIR/main.py"
cp -R "$ROOT_DIR/src" "$STAGE_DIR/src"
cp "$CONFIG_IN_USE" "$STAGE_DIR/config.default.json"
# Calc functions reference for formula generation
mkdir -p "$STAGE_DIR/config"
if [ -f "$ROOT_DIR/config/calc-functions.json" ]; then
  cp "$ROOT_DIR/config/calc-functions.json" "$STAGE_DIR/config/calc-functions.json"
fi
# Device Management metadata and config template
if [ -f "$ROOT_DIR/dm-manifest.json" ]; then
  cp "$ROOT_DIR/dm-manifest.json" "$STAGE_DIR/dm-manifest.json"
fi
if [ -f "$ROOT_DIR/dm-config.json" ]; then
  cp "$ROOT_DIR/dm-config.json" "$STAGE_DIR/dm-config.json"
fi
# Documentation (README + notice utilisateur) for device-management auto-description
mkdir -p "$STAGE_DIR/docs"
[ -f "$ROOT_DIR/README.md" ] && cp "$ROOT_DIR/README.md" "$STAGE_DIR/docs/README.md"
[ -f "$ROOT_DIR/docs/notice-utilisateur.md" ] && cp "$ROOT_DIR/docs/notice-utilisateur.md" "$STAGE_DIR/docs/notice-utilisateur.md"

find "$STAGE_DIR" -name ".DS_Store" -delete
find "$STAGE_DIR" -name "*.pyc" -delete
find "$STAGE_DIR" -name "__pycache__" -type d -prune -exec rm -rf {} +

log "Creating package: $OUTPUT_PATH"
(
  cd "$STAGE_DIR"
  zip -r "$OUTPUT_PATH" . \
    -x "*.git*" -x "*.DS_Store" -x "*.pyc" -x "*__pycache__*"
) >/dev/null

log "OK: Package created: $OUTPUT_PATH"

if [ "$INSTALL_AFTER_BUILD" != true ]; then
  exit 0
fi

OS_NAME="$(uname -s)"
if [ "$OS_NAME" = "Darwin" ]; then
  osascript -e 'tell application "LibreOffice" to quit' >/dev/null 2>&1 || true
elif [ "$OS_NAME" = "Linux" ]; then
  pkill -f soffice.bin >/dev/null 2>&1 || true
  pkill -f soffice >/dev/null 2>&1 || true
else
  taskkill //IM soffice.bin //F >/dev/null 2>&1 || true
  taskkill //IM soffice.exe //F >/dev/null 2>&1 || true
fi

UNOPKG_BIN="$(find_unopkg "$OS_NAME")"
[ -n "$UNOPKG_BIN" ] || { err "unopkg not found"; exit 1; }

log "Installing extension via unopkg..."
"$UNOPKG_BIN" add --replace "$OUTPUT_PATH" >/dev/null 2>&1 || {
  warn "--replace not supported, fallback to remove + add"
  "$UNOPKG_BIN" remove "fr.gouv.interieur.mirai" >/dev/null 2>&1 || true
  printf "yes\n" | "$UNOPKG_BIN" add "$OUTPUT_PATH"
}

log "OK: Extension installed"
if [ "$RESTART_LIBREOFFICE" = true ] && [ "$OS_NAME" = "Darwin" ]; then
  log "Restarting LibreOffice..."
  open -a "LibreOffice"
fi
