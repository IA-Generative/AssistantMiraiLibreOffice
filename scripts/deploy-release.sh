#!/usr/bin/env bash
# Deploy a new MIrAI LibreOffice release via device-management.
#
# Usage:
#   scripts/deploy-release.sh --bootstrap-url <url> [options]
#
# Options:
#   --bootstrap-url <url>    Bootstrap server URL (required)
#   --version <ver>          Version string (default: from oxt/description.xml)
#   --profile <p>            Config profile: dev|int|prod (default: int)
#   --strategy <s>           Rollout strategy: immediate|canary (default: canary)
#   --admin-token <tok>      Admin API token (default: $DM_ADMIN_TOKEN env var)
#   --cohort-id <id>         Target cohort ID (default: none = all devices)
#   --config <path>          Config file for OXT build (optional)
#   --dry-run                Build and show plan without deploying
#   -h, --help               Show this help

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OXT_PATH="$ROOT_DIR/dist/mirai.oxt"

# Defaults
BOOTSTRAP_URL=""
VERSION=""
PROFILE="int"
STRATEGY="canary"
ADMIN_TOKEN="${DM_ADMIN_TOKEN:-}"
COHORT_ID=""
BUILD_CONFIG=""
DRY_RUN=false

log()  { printf '▶ %s\n' "$*"; }
ok()   { printf '✓ %s\n' "$*"; }
err()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,15p' "$0"
  exit 0
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bootstrap-url) BOOTSTRAP_URL="${2:-}"; shift 2 ;;
    --version)       VERSION="${2:-}"; shift 2 ;;
    --profile)       PROFILE="${2:-}"; shift 2 ;;
    --strategy)      STRATEGY="${2:-}"; shift 2 ;;
    --admin-token)   ADMIN_TOKEN="${2:-}"; shift 2 ;;
    --cohort-id)     COHORT_ID="${2:-}"; shift 2 ;;
    --config)        BUILD_CONFIG="${2:-}"; shift 2 ;;
    --dry-run)       DRY_RUN=true; shift ;;
    -h|--help)       usage ;;
    *)               err "Unknown option: $1" ;;
  esac
done

[ -n "$BOOTSTRAP_URL" ] || err "Missing --bootstrap-url"
[ -n "$ADMIN_TOKEN" ]   || err "Missing --admin-token or DM_ADMIN_TOKEN env var"

# ── 1. Extract version from description.xml if not provided ──────────────
if [ -z "$VERSION" ]; then
  VERSION=$(grep -oP '(?<=<version value=")[^"]+' "$ROOT_DIR/oxt/description.xml" 2>/dev/null || echo "")
  [ -n "$VERSION" ] || err "Could not extract version from oxt/description.xml. Use --version."
fi
log "Version: $VERSION"

# ── 2. Build OXT ─────────────────────────────────────────────────────────
log "Building OXT..."
BUILD_ARGS=()
if [ -n "$BUILD_CONFIG" ]; then
  BUILD_ARGS+=(--config "$BUILD_CONFIG")
fi
"$ROOT_DIR/scripts/02-build-oxt.sh" "${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}"
ok "OXT built: $OXT_PATH"

# ── 3. Compute checksum ──────────────────────────────────────────────────
CHECKSUM="sha256:$(shasum -a 256 "$OXT_PATH" | awk '{print $1}')"
FILE_SIZE=$(stat -f%z "$OXT_PATH" 2>/dev/null || stat --printf=%s "$OXT_PATH")
log "Checksum: $CHECKSUM"
log "Size: $((FILE_SIZE / 1024)) KB"

# ── 4. Rollout config ────────────────────────────────────────────────────
if [ "$STRATEGY" = "canary" ]; then
  ROLLOUT_CONFIG='{"strategy":"percentage","stages":[{"percent":5,"duration_hours":24,"label":"canary"},{"percent":25,"duration_hours":48,"label":"early_adopters"},{"percent":100,"duration_hours":0,"label":"general_availability"}],"auto_advance":true,"rollback_on_failure_rate":0.1}'
else
  ROLLOUT_CONFIG='{"strategy":"immediate","stages":[{"percent":100,"duration_hours":0,"label":"immediate"}],"auto_advance":true,"rollback_on_failure_rate":0.1}'
fi

# ── 5. Show plan ─────────────────────────────────────────────────────────
printf '\n'
printf '┌─────────────────────────────────────────┐\n'
printf '│  MIrAI Release Deployment Plan          │\n'
printf '├─────────────────────────────────────────┤\n'
printf '│  Version:    %-26s │\n' "$VERSION"
printf '│  Strategy:   %-26s │\n' "$STRATEGY"
printf '│  Profile:    %-26s │\n' "$PROFILE"
printf '│  Bootstrap:  %-26s │\n' "$BOOTSTRAP_URL"
printf '│  Checksum:   %-26s │\n' "${CHECKSUM:0:20}..."
if [ -n "$COHORT_ID" ]; then
  printf '│  Cohort:     %-26s │\n' "$COHORT_ID"
fi
printf '└─────────────────────────────────────────┘\n'
printf '\n'

if [ "$DRY_RUN" = true ]; then
  log "Dry run — stopping here."
  exit 0
fi

# ── 6. Upload artifact ───────────────────────────────────────────────────
log "Uploading artifact..."
UPLOAD_RESPONSE=$(curl -s -X POST \
  "${BOOTSTRAP_URL}/api/artifacts" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -F "device_type=libreoffice" \
  -F "version=${VERSION}" \
  -F "binary=@${OXT_PATH}" \
  -F "changelog_url=https://github.com/IA-Generative/AssistantMiraiLibreOffice/releases/tag/v${VERSION}" \
  2>&1)

ARTIFACT_ID=$(echo "$UPLOAD_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('artifact_id',''))" 2>/dev/null || echo "")
if [ -z "$ARTIFACT_ID" ]; then
  printf 'Upload response: %s\n' "$UPLOAD_RESPONSE" >&2
  err "Failed to upload artifact"
fi
ok "Artifact uploaded: ID=$ARTIFACT_ID"

# ── 7. Create campaign ───────────────────────────────────────────────────
log "Creating campaign..."
CAMPAIGN_BODY=$(python3 -c "
import json
body = {
    'name': 'Release v${VERSION}',
    'description': 'Automated release of MIrAI v${VERSION} (${STRATEGY})',
    'type': 'plugin_update',
    'artifact_id': ${ARTIFACT_ID},
    'urgency': 'normal',
    'status': 'draft',
    'rollout_config': json.loads('${ROLLOUT_CONFIG}'),
}
cohort = '${COHORT_ID}'
if cohort:
    body['target_cohort_id'] = int(cohort)
print(json.dumps(body))
")

CAMPAIGN_RESPONSE=$(curl -s -X POST \
  "${BOOTSTRAP_URL}/api/campaigns" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -d "$CAMPAIGN_BODY" \
  2>&1)

CAMPAIGN_ID=$(echo "$CAMPAIGN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('campaign_id',''))" 2>/dev/null || echo "")
if [ -z "$CAMPAIGN_ID" ]; then
  printf 'Campaign response: %s\n' "$CAMPAIGN_RESPONSE" >&2
  err "Failed to create campaign"
fi
ok "Campaign created: ID=$CAMPAIGN_ID"

# ── 8. Start rollout ─────────────────────────────────────────────────────
log "Starting rollout..."
START_RESPONSE=$(curl -s -X PATCH \
  "${BOOTSTRAP_URL}/api/campaigns/${CAMPAIGN_ID}/start" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  2>&1)

START_OK=$(echo "$START_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null || echo "")
if [ "$START_OK" != "True" ]; then
  printf 'Start response: %s\n' "$START_RESPONSE" >&2
  err "Failed to start campaign"
fi
ok "Rollout started"

# ── 9. Show tracking info ────────────────────────────────────────────────
printf '\n'
printf '✓ Deployment initiated successfully!\n'
printf '\n'
printf '  Track progress:\n'
printf '    curl -s -H "X-Admin-Token: $DM_ADMIN_TOKEN" \\\n'
printf '      %s/api/campaigns/%s/progress | python3 -m json.tool\n' "$BOOTSTRAP_URL" "$CAMPAIGN_ID"
printf '\n'
printf '  Pause rollout:\n'
printf '    curl -s -X PATCH -H "X-Admin-Token: $DM_ADMIN_TOKEN" \\\n'
printf '      %s/api/campaigns/%s/pause\n' "$BOOTSTRAP_URL" "$CAMPAIGN_ID"
printf '\n'
printf '  Abort and rollback:\n'
printf '    curl -s -X PATCH -H "X-Admin-Token: $DM_ADMIN_TOKEN" \\\n'
printf '      %s/api/campaigns/%s/abort\n' "$BOOTSTRAP_URL" "$CAMPAIGN_ID"
printf '\n'
