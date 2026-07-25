#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[1/6] Shell syntax checks"
bash -n \
  "$ROOT_DIR/scripts/02-build-oxt.sh" \
  "$ROOT_DIR/scripts/05-update-plugin.sh" \
  "$ROOT_DIR/scripts/01-init-default-config.sh" \
  "$ROOT_DIR/scripts/04-repack-oxt.sh" \
  "$ROOT_DIR/scripts/06-use-config-profile.sh" \
  "$ROOT_DIR/scripts/07-package-release.sh"

echo "[2/6] Python syntax checks"
# TOUS les modules, y compris core/ et ui/ : ils étaient absents de cette liste,
# si bien qu'une erreur de syntaxe dans le moteur ou l'IHM passait le contrôle.
find "$ROOT_DIR/src" "$ROOT_DIR/main.py" -name '*.py' -print0 | xargs -0 python -m py_compile

for profile in docker kubernetes local-llm dev; do
  f="$ROOT_DIR/config/profiles/config.default.$profile.json"
  [ -f "$f" ] && python -m json.tool "$f" >/dev/null
done
# Les profils portant une URL réelle sont gitignorés : on valide leur exemple.
for f in "$ROOT_DIR"/config/profiles/*.example.json; do
  [ -f "$f" ] && python -m json.tool "$f" >/dev/null
done

echo "[3/6] Lint (ruff)"
# Dégradation gracieuse : un poste sans ruff ne doit jamais être bloqué.
if python -m ruff --version >/dev/null 2>&1; then
  # Bloquant sur les erreurs franches (bugs, imports, style).
  python -m ruff check "$ROOT_DIR/src/mirai/core" "$ROOT_DIR/src/mirai/ui" \
    --ignore C901
  # La complexité est un budget en cours de résorption : on la MESURE et on
  # l'affiche, sans bloquer, pour que le chiffre reste sous les yeux.
  complex_count=$(python -m ruff check "$ROOT_DIR/src/mirai/core" "$ROOT_DIR/src/mirai/ui" \
    --select C901 --output-format concise 2>/dev/null | grep -c C901 || true)
  echo "    complexité > 10 : $complex_count fonction(s) — budget cible : 0"
else
  echo "    ruff absent — lint ignoré (installez-le avec : python3 -m pip install ruff)"
fi

echo "[4/6] Unit + integration tests"
pytest -q "$ROOT_DIR/tests/unit" "$ROOT_DIR/tests/integration"

echo "[5/6] Build package"
"$ROOT_DIR/scripts/02-build-oxt.sh"

echo "[6/6] Verify archive content"
unzip -l "$ROOT_DIR/dist/mirai.oxt" | rg "config\.default\.json|src/mirai/entrypoint\.py|main\.py|META-INF/manifest\.xml" >/dev/null

echo "OK: local checks passed"
