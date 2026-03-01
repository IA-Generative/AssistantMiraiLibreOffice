#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  cat <<USAGE
Usage:
  scripts/04-repack-oxt.sh --src <oxt_file_or_unpacked_dir> [--config <config.default.json>] [--out <output.oxt>]

Examples:
  scripts/04-repack-oxt.sh --src ./dist/mirai.oxt --config ./config/config.default.json --out ./dist/mirai.oxt
  scripts/04-repack-oxt.sh --src ./dist/mirai.oxt --out ./dist/mirai.oxt

Notes:
  - If --config is omitted, defaults are searched in:
      1) ./config/config.default.json
      2) ./config/config.default.example.json
  - Embedded target filename is always: config.default.json
USAGE
}

SRC=""
CONFIG=""
OUT="$ROOT_DIR/dist/mirai.repacked.oxt"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --src)
      SRC="${2:-}"
      shift 2
      ;;
    --config)
      CONFIG="${2:-}"
      shift 2
      ;;
    --out)
      OUT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

[ -n "$SRC" ] || { echo "Missing --src" >&2; usage; exit 1; }

if [ -z "$CONFIG" ] && [ -f "$ROOT_DIR/config/config.default.json" ]; then
  CONFIG="$ROOT_DIR/config/config.default.json"
elif [ -z "$CONFIG" ] && [ -f "$ROOT_DIR/config/config.default.example.json" ]; then
  CONFIG="$ROOT_DIR/config/config.default.example.json"
fi

if [ -n "$CONFIG" ] && [ ! -f "$CONFIG" ]; then
  echo "Config file not found: $CONFIG" >&2
  exit 1
fi

command -v zip >/dev/null 2>&1 || { echo "zip command not found" >&2; exit 1; }
command -v unzip >/dev/null 2>&1 || { echo "unzip command not found" >&2; exit 1; }

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
WORK_DIR="$TMP_DIR/work"
mkdir -p "$WORK_DIR"

case "$SRC" in
  /*) SRC_PATH="$SRC" ;;
  *) SRC_PATH="$ROOT_DIR/$SRC" ;;
esac

if [ -d "$SRC_PATH" ]; then
  cp -R "$SRC_PATH"/. "$WORK_DIR"/
elif [ -f "$SRC_PATH" ]; then
  unzip -q "$SRC_PATH" -d "$WORK_DIR"
else
  echo "Invalid --src: $SRC" >&2
  exit 1
fi

if [ -n "$CONFIG" ]; then
  cp "$CONFIG" "$WORK_DIR/config.default.json"
fi

if [ ! -f "$WORK_DIR/META-INF/manifest.xml" ]; then
  echo "Warning: META-INF/manifest.xml missing in source content" >&2
fi
if [ ! -f "$WORK_DIR/description.xml" ]; then
  echo "Warning: description.xml missing in source content" >&2
fi

case "$OUT" in
  /*) OUT_PATH="$OUT" ;;
  *) OUT_PATH="$ROOT_DIR/$OUT" ;;
esac

mkdir -p "$(dirname "$OUT_PATH")"
rm -f "$OUT_PATH"

(
  cd "$WORK_DIR"
  find . -name ".DS_Store" -delete
  find . -name "*.pyc" -delete
  find . -name "__pycache__" -type d -prune -exec rm -rf {} +
  zip -q -r "$OUT_PATH" . -x "*.pyc" -x "*__pycache__*"
)

echo "OXT repackaged: $OUT_PATH"
if [ -n "$CONFIG" ]; then
  echo "Embedded defaults from: $CONFIG -> config.default.json"
else
  echo "No config.default.json embedded (file not provided)."
fi
