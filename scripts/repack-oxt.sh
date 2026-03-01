#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/repack-oxt.sh --src <oxt_file_or_unpacked_dir> [--config <config.default.json>] [--out <output.oxt>]

Examples:
  scripts/repack-oxt.sh --src ./build/mirai.oxt --config ./config.default.json --out ./dist/mirai.oxt
  scripts/repack-oxt.sh --src ./unpacked-oxt --config ./config.default.json

Notes:
  - If --config is omitted and ./config.default.json exists, it is embedded automatically.
  - The config is embedded as: config.default.json at the root of the OXT archive.
EOF
}

SRC=""
CONFIG=""
OUT="mirai.repacked.oxt"

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

if [ -z "$SRC" ]; then
  echo "Missing --src" >&2
  usage
  exit 1
fi

if [ -z "$CONFIG" ] && [ -f "config.default.json" ]; then
  CONFIG="config.default.json"
fi

if [ -n "$CONFIG" ] && [ ! -f "$CONFIG" ]; then
  echo "Config file not found: $CONFIG" >&2
  exit 1
fi

if ! command -v zip >/dev/null 2>&1; then
  echo "zip command not found" >&2
  exit 1
fi
if ! command -v unzip >/dev/null 2>&1; then
  echo "unzip command not found" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
WORK_DIR="$TMP_DIR/work"
mkdir -p "$WORK_DIR"

if [ -d "$SRC" ]; then
  cp -R "$SRC"/. "$WORK_DIR"/
elif [ -f "$SRC" ]; then
  unzip -q "$SRC" -d "$WORK_DIR"
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

mkdir -p "$(dirname "$OUT")"
OUT_ABS="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
rm -f "$OUT_ABS"

(
  cd "$WORK_DIR"
  find . -name ".DS_Store" -delete
  zip -q -r "$OUT_ABS" .
)

echo "OXT repackaged: $OUT_ABS"
if [ -n "$CONFIG" ]; then
  echo "Embedded defaults from: $CONFIG -> config.default.json"
else
  echo "No config.default.json embedded (file not provided)."
fi
