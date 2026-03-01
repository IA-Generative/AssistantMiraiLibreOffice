#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[1/4] Shell syntax checks"
bash -n   "$ROOT_DIR/scripts/02-build-oxt.sh"   "$ROOT_DIR/scripts/05-update-plugin.sh"   "$ROOT_DIR/scripts/01-init-default-config.sh"   "$ROOT_DIR/scripts/04-repack-oxt.sh"

echo "[2/4] Python syntax checks"
python -m py_compile   "$ROOT_DIR/main.py"   "$ROOT_DIR/src/mirai/entrypoint.py"   "$ROOT_DIR/src/mirai/menu_actions/shared.py"   "$ROOT_DIR/src/mirai/menu_actions/writer.py"   "$ROOT_DIR/src/mirai/menu_actions/calc.py"

echo "[3/4] Build package"
"$ROOT_DIR/scripts/02-build-oxt.sh"

echo "[4/4] Verify archive content"
unzip -l "$ROOT_DIR/dist/mirai.oxt" | rg "config\.default\.json|src/mirai/entrypoint\.py|main\.py|META-INF/manifest\.xml" >/dev/null

echo "OK: local checks passed"
