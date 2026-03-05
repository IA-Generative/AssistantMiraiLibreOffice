#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[1/5] Shell syntax checks"
bash -n \
  "$ROOT_DIR/scripts/02-build-oxt.sh" \
  "$ROOT_DIR/scripts/05-update-plugin.sh" \
  "$ROOT_DIR/scripts/01-init-default-config.sh" \
  "$ROOT_DIR/scripts/04-repack-oxt.sh" \
  "$ROOT_DIR/scripts/06-use-config-profile.sh" \
  "$ROOT_DIR/scripts/07-package-release.sh"

echo "[2/5] Python syntax checks"
python -m py_compile \
  "$ROOT_DIR/main.py" \
  "$ROOT_DIR/src/mirai/entrypoint.py" \
  "$ROOT_DIR/src/mirai/menu_actions/shared.py" \
  "$ROOT_DIR/src/mirai/menu_actions/writer.py" \
  "$ROOT_DIR/src/mirai/menu_actions/calc.py"

python -m py_compile "$ROOT_DIR/src/mirai/security_flow.py"
python -m json.tool "$ROOT_DIR/config/profiles/config.default.docker.json" >/dev/null
python -m json.tool "$ROOT_DIR/config/profiles/config.default.kubernetes.json" >/dev/null
python -m json.tool "$ROOT_DIR/config/profiles/config.default.dgx.json" >/dev/null
python -m json.tool "$ROOT_DIR/config/profiles/config.default.local-llm.json" >/dev/null

echo "[3/5] Unit tests"
pytest -q "$ROOT_DIR/tests/unit"

echo "[4/5] Build package"
"$ROOT_DIR/scripts/02-build-oxt.sh"

echo "[5/5] Verify archive content"
unzip -l "$ROOT_DIR/dist/mirai.oxt" | rg "config\.default\.json|src/mirai/entrypoint\.py|main\.py|META-INF/manifest\.xml" >/dev/null

echo "OK: local checks passed"
