# CLAUDE.md — MIrAI LibreOffice Extension

## Project

Extension LibreOffice (OXT) intégrant un assistant IA dans Writer et Calc. Se connecte à un backend OpenAI-compatible via Device Management.

## Quick commands

```bash
# Build
./scripts/02-build-oxt.sh

# Dev cycle (build + install + launch LO)
./scripts/dev-launch.sh
./scripts/dev-launch.sh --config config/profiles/config.default.integration.json

# Clean install (purge cache + uninstall)
./scripts/00-clean-install.sh --uninstall

# Deploy release (canary rollout)
./scripts/deploy-release.sh \
  --bootstrap-url https://bootstrap.fake-domain.name \
  --strategy canary --profile int

# Deploy release (immediate)
./scripts/deploy-release.sh \
  --bootstrap-url https://bootstrap.fake-domain.name \
  --strategy immediate --profile prod

# Check campaign progress
curl -s -H "X-Admin-Token: $DM_ADMIN_TOKEN" \
  https://bootstrap.fake-domain.name/api/campaigns/{id}/progress | python3 -m json.tool

# Simulate 100 devices
python3 tests/simulation/deploy_simulator.py \
  --devices 100 --bootstrap-url https://bootstrap.fake-domain.name --profile int

# Tests
python3 -m pytest tests/unit/ -v

# K8s deploy (device-management Scaleway)
cd ../device-management && ./scripts/k8s/deploy.sh scaleway
```

## Architecture

- `src/mirai/entrypoint.py` — Main extension code (MainJob)
- `src/mirai/menu_actions/writer.py` — Writer actions (extend, edit, resize, summarize, simplify)
- `src/mirai/menu_actions/calc.py` — Calc actions (transform, formula, analyze)
- `oxt/Addons.xcu` — Menu definition (Writer + Calc)
- `config/profiles/` — Bootstrap config profiles (dev, docker, integration, kubernetes, production)

## Key constraints

- **Threading**: NEVER call `processEventsToIdle` from a background thread — crashes LibreOffice
- **No pip**: Only `urllib.request` — no external Python packages in the plugin
- **UNO API**: All UI via `com.sun.star.awt.*` dialogs
- **Config profiles**: `dev`, `int`, `prod` (not `integration` — device-management rejects it)

## Device Management (sibling repo)

Located at `../device-management/`. Key files:
- `app/main.py` — Config endpoint, update directives, enrollment
- `app/admin/` — Admin UI (campaigns, artifacts, cohorts, devices)
- `deploy/k8s/overlays/scaleway/` — Scaleway Kapsule deployment
- K8s DNS resolver: `10.32.0.10` (for relay-assistant nginx)
