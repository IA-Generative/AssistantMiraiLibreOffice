#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILES_DIR="$ROOT_DIR/config/profiles"
TARGET_FILE="$ROOT_DIR/config/config.default.json"

PROFILE_NAME=""
PRINT_RESULT=false
LIST_ONLY=false

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Apply a predefined profile to config/config.default.json.

Options:
  --profile <name|path>     Profile name (docker|kubernetes|dgx|local-llm) or JSON file path
  --list                    List available profile names
  --print                   Print resulting config file
  -h, --help                Show this help
USAGE
}

list_profiles() {
  [ -d "$PROFILES_DIR" ] || return 0
  for p in "$PROFILES_DIR"/config.default.*.json; do
    [ -f "$p" ] || continue
    b="$(basename "$p")"
    b="${b#config.default.}"
    b="${b%.json}"
    printf '%s\n' "$b"
  done
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
    --list)
      LIST_ONLY=true
      shift
      ;;
    --print)
      PRINT_RESULT=true
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

if [ "$LIST_ONLY" = true ]; then
  list_profiles
  exit 0
fi

[ -n "$PROFILE_NAME" ] || {
  echo "Missing --profile. Use --list to see available profiles." >&2
  exit 1
}

PROFILE_PATH="$(resolve_profile_path "$PROFILE_NAME" || true)"
[ -n "$PROFILE_PATH" ] || {
  echo "Profile not found: $PROFILE_NAME" >&2
  echo "Available profiles:" >&2
  list_profiles >&2
  exit 1
}

mkdir -p "$(dirname "$TARGET_FILE")"
cp "$PROFILE_PATH" "$TARGET_FILE"
echo "Applied profile: $PROFILE_PATH -> $TARGET_FILE"

if [ "$PRINT_RESULT" = true ]; then
  cat "$TARGET_FILE"
fi
