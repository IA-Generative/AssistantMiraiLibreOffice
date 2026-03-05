#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILES_DIR="$ROOT_DIR/config/profiles"
TARGET_FILE="$ROOT_DIR/config/config.default.json"

PROFILE_NAME=""
OUTPUT_PATH=""
INSTALL_AFTER_BUILD=false
RESTART_AFTER_INSTALL=false
APPLY_PROFILE=false

usage() {
  cat <<USAGE
Usage: $(basename "$0") --profile <name|path> [options]

Build an OXT package using a selected profile config.

Options:
  --profile <name|path>     Profile name (docker|kubernetes|dgx|local-llm) or JSON file path
  --output <path>           Output OXT file path (default: dist/mirai.<profile>.oxt)
  --apply-profile           Also copy profile to config/config.default.json
  --install                 Install extension after build
  --restart                 Restart LibreOffice after install
  -h, --help                Show this help
USAGE
}

resolve_profile_path() {
  local raw="$1"
  if [ -f "$raw" ]; then
    printf '%s' "$raw"
    return
  fi
  if [ -f "$ROOT_DIR/$raw" ]; then
    printf '%s' "$ROOT_DIR/$raw"
    return
  fi
  if [ -f "$PROFILES_DIR/config.default.${raw}.json" ]; then
    printf '%s' "$PROFILES_DIR/config.default.${raw}.json"
    return
  fi
  return 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      PROFILE_NAME="${2:-}"
      [ -n "$PROFILE_NAME" ] || { echo "Missing value for --profile" >&2; exit 1; }
      shift 2
      ;;
    --output)
      OUTPUT_PATH="${2:-}"
      [ -n "$OUTPUT_PATH" ] || { echo "Missing value for --output" >&2; exit 1; }
      shift 2
      ;;
    --apply-profile)
      APPLY_PROFILE=true
      shift
      ;;
    --install)
      INSTALL_AFTER_BUILD=true
      shift
      ;;
    --restart)
      RESTART_AFTER_INSTALL=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

[ -n "$PROFILE_NAME" ] || {
  echo "Missing --profile" >&2
  usage
  exit 1
}

PROFILE_PATH="$(resolve_profile_path "$PROFILE_NAME" || true)"
[ -n "$PROFILE_PATH" ] || {
  echo "Profile not found: $PROFILE_NAME" >&2
  exit 1
}

PROFILE_LABEL="$PROFILE_NAME"
if [ -f "$PROFILE_NAME" ] || [ -f "$ROOT_DIR/$PROFILE_NAME" ]; then
  PROFILE_LABEL="$(basename "$PROFILE_PATH")"
  PROFILE_LABEL="${PROFILE_LABEL#config.default.}"
  PROFILE_LABEL="${PROFILE_LABEL%.json}"
fi

if [ -z "$OUTPUT_PATH" ]; then
  OUTPUT_PATH="$ROOT_DIR/dist/mirai.${PROFILE_LABEL}.oxt"
else
  case "$OUTPUT_PATH" in
    /*) ;;
    *) OUTPUT_PATH="$ROOT_DIR/$OUTPUT_PATH" ;;
  esac
fi

if [ "$APPLY_PROFILE" = true ]; then
  mkdir -p "$(dirname "$TARGET_FILE")"
  cp "$PROFILE_PATH" "$TARGET_FILE"
  echo "Applied profile: $PROFILE_PATH -> $TARGET_FILE"
fi

CMD=("$ROOT_DIR/scripts/02-build-oxt.sh" "--config" "$PROFILE_PATH" "--output" "$OUTPUT_PATH")
if [ "$INSTALL_AFTER_BUILD" = true ]; then
  CMD+=("--install")
fi
if [ "$RESTART_AFTER_INSTALL" = true ]; then
  CMD+=("--restart")
fi

"${CMD[@]}"
echo "Release package built with profile '$PROFILE_LABEL': $OUTPUT_PATH"
