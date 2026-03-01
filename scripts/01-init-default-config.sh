#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/config/config.default.json"
EXAMPLE_FILE="$ROOT_DIR/config/config.default.example.json"
INTERACTIVE=false
COPY_FROM_EXAMPLE=true

# Track explicit CLI intent (supports empty-string values)
HAS_KEYCLOAK_ISSUER_URL=false
HAS_KEYCLOAK_REALM=false
HAS_KEYCLOAK_CLIENT_ID=false
HAS_KEYCLOAK_REDIRECT_URI=false
HAS_KEYCLOAK_ALLOWED_REDIRECT_URI=false
HAS_PROXY_URL=false
HAS_BOOTSTRAP_URL=false
HAS_DEVICE_NAME=false
HAS_CONFIG_PATH=false

KEYCLOAK_ISSUER_URL="${KEYCLOAK_ISSUER_URL:-}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-}"
KEYCLOAK_REDIRECT_URI="${KEYCLOAK_REDIRECT_URI:-}"
KEYCLOAK_ALLOWED_REDIRECT_URI="${KEYCLOAK_ALLOWED_REDIRECT_URI:-}"
PROXY_URL="${PROXY_URL:-}"
BOOTSTRAP_URL="${BOOTSTRAP_URL:-}"
DEVICE_NAME="${DEVICE_NAME:-}"
CONFIG_PATH_VALUE="${CONFIG_PATH:-}"

usage() {
  cat <<USAGE
Usage: scripts/01-init-default-config.sh [options]

Initialize/update key defaults in config/config.default.json for:
  keycloakIssuerUrl
  keycloakRealm
  keycloakClientId
  keycloak_redirect_uri
  keycloak_allowed_redirect_uri
  proxy_url
  bootstrap_url
  device_name
  config_path

Options:
  --file <path>                          Target JSON file (default: config/config.default.json)
  --interactive                          Prompt for missing values
  --no-copy-example                      Do not auto-create file from config.default.example.json
  --keycloak-issuer-url <value>
  --keycloak-realm <value>               Use "" to force empty value
  --keycloak-client-id <value>
  --keycloak-redirect-uri <value>
  --keycloak-allowed-redirect-uri <value>
  --proxy-url <value>
  --bootstrap-url <value>
  --device-name <value>
  --config-path <value>
  -h, --help                             Show this help

Environment fallback variables (used when CLI option not provided):
  KEYCLOAK_ISSUER_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID,
  KEYCLOAK_REDIRECT_URI, KEYCLOAK_ALLOWED_REDIRECT_URI,
  PROXY_URL, BOOTSTRAP_URL, DEVICE_NAME, CONFIG_PATH
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --file)
      CONFIG_FILE="${2:-}"
      shift 2
      ;;
    --interactive)
      INTERACTIVE=true
      shift
      ;;
    --no-copy-example)
      COPY_FROM_EXAMPLE=false
      shift
      ;;
    --keycloak-issuer-url)
      HAS_KEYCLOAK_ISSUER_URL=true
      KEYCLOAK_ISSUER_URL="${2-}"
      shift 2
      ;;
    --keycloak-realm)
      HAS_KEYCLOAK_REALM=true
      KEYCLOAK_REALM="${2-}"
      shift 2
      ;;
    --keycloak-client-id)
      HAS_KEYCLOAK_CLIENT_ID=true
      KEYCLOAK_CLIENT_ID="${2-}"
      shift 2
      ;;
    --keycloak-redirect-uri)
      HAS_KEYCLOAK_REDIRECT_URI=true
      KEYCLOAK_REDIRECT_URI="${2-}"
      shift 2
      ;;
    --keycloak-allowed-redirect-uri)
      HAS_KEYCLOAK_ALLOWED_REDIRECT_URI=true
      KEYCLOAK_ALLOWED_REDIRECT_URI="${2-}"
      shift 2
      ;;
    --proxy-url)
      HAS_PROXY_URL=true
      PROXY_URL="${2-}"
      shift 2
      ;;
    --bootstrap-url)
      HAS_BOOTSTRAP_URL=true
      BOOTSTRAP_URL="${2-}"
      shift 2
      ;;
    --device-name)
      HAS_DEVICE_NAME=true
      DEVICE_NAME="${2-}"
      shift 2
      ;;
    --config-path)
      HAS_CONFIG_PATH=true
      CONFIG_PATH_VALUE="${2-}"
      shift 2
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

# Apply env fallback (non-empty) when CLI option was not provided
if [ "$HAS_KEYCLOAK_ISSUER_URL" = false ] && [ -n "$KEYCLOAK_ISSUER_URL" ]; then HAS_KEYCLOAK_ISSUER_URL=true; fi
if [ "$HAS_KEYCLOAK_REALM" = false ] && [ -n "$KEYCLOAK_REALM" ]; then HAS_KEYCLOAK_REALM=true; fi
if [ "$HAS_KEYCLOAK_CLIENT_ID" = false ] && [ -n "$KEYCLOAK_CLIENT_ID" ]; then HAS_KEYCLOAK_CLIENT_ID=true; fi
if [ "$HAS_KEYCLOAK_REDIRECT_URI" = false ] && [ -n "$KEYCLOAK_REDIRECT_URI" ]; then HAS_KEYCLOAK_REDIRECT_URI=true; fi
if [ "$HAS_KEYCLOAK_ALLOWED_REDIRECT_URI" = false ] && [ -n "$KEYCLOAK_ALLOWED_REDIRECT_URI" ]; then HAS_KEYCLOAK_ALLOWED_REDIRECT_URI=true; fi
if [ "$HAS_PROXY_URL" = false ] && [ -n "$PROXY_URL" ]; then HAS_PROXY_URL=true; fi
if [ "$HAS_BOOTSTRAP_URL" = false ] && [ -n "$BOOTSTRAP_URL" ]; then HAS_BOOTSTRAP_URL=true; fi
if [ "$HAS_DEVICE_NAME" = false ] && [ -n "$DEVICE_NAME" ]; then HAS_DEVICE_NAME=true; fi
if [ "$HAS_CONFIG_PATH" = false ] && [ -n "$CONFIG_PATH_VALUE" ]; then HAS_CONFIG_PATH=true; fi

case "$CONFIG_FILE" in
  /*) ;;
  *) CONFIG_FILE="$ROOT_DIR/$CONFIG_FILE" ;;
esac

if [ ! -f "$CONFIG_FILE" ]; then
  if [ "$COPY_FROM_EXAMPLE" = true ] && [ -f "$EXAMPLE_FILE" ]; then
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cp "$EXAMPLE_FILE" "$CONFIG_FILE"
    echo "Created $CONFIG_FILE from example"
  else
    echo "Config file not found: $CONFIG_FILE" >&2
    exit 1
  fi
fi

export DM_CONFIG_FILE="$CONFIG_FILE"
export DM_INTERACTIVE="$INTERACTIVE"

export DM_HAS_KEYCLOAK_ISSUER_URL="$HAS_KEYCLOAK_ISSUER_URL"
export DM_HAS_KEYCLOAK_REALM="$HAS_KEYCLOAK_REALM"
export DM_HAS_KEYCLOAK_CLIENT_ID="$HAS_KEYCLOAK_CLIENT_ID"
export DM_HAS_KEYCLOAK_REDIRECT_URI="$HAS_KEYCLOAK_REDIRECT_URI"
export DM_HAS_KEYCLOAK_ALLOWED_REDIRECT_URI="$HAS_KEYCLOAK_ALLOWED_REDIRECT_URI"
export DM_HAS_PROXY_URL="$HAS_PROXY_URL"
export DM_HAS_BOOTSTRAP_URL="$HAS_BOOTSTRAP_URL"
export DM_HAS_DEVICE_NAME="$HAS_DEVICE_NAME"
export DM_HAS_CONFIG_PATH="$HAS_CONFIG_PATH"

export DM_KEYCLOAK_ISSUER_URL="$KEYCLOAK_ISSUER_URL"
export DM_KEYCLOAK_REALM="$KEYCLOAK_REALM"
export DM_KEYCLOAK_CLIENT_ID="$KEYCLOAK_CLIENT_ID"
export DM_KEYCLOAK_REDIRECT_URI="$KEYCLOAK_REDIRECT_URI"
export DM_KEYCLOAK_ALLOWED_REDIRECT_URI="$KEYCLOAK_ALLOWED_REDIRECT_URI"
export DM_PROXY_URL="$PROXY_URL"
export DM_BOOTSTRAP_URL="$BOOTSTRAP_URL"
export DM_DEVICE_NAME="$DEVICE_NAME"
export DM_CONFIG_PATH="$CONFIG_PATH_VALUE"

python3 - <<'PY'
import json
import os

path = os.environ['DM_CONFIG_FILE']
interactive = os.environ.get('DM_INTERACTIVE', 'false').lower() == 'true'

mapping = [
    ('keycloakIssuerUrl', 'DM_KEYCLOAK_ISSUER_URL', 'DM_HAS_KEYCLOAK_ISSUER_URL', 'keycloakIssuerUrl'),
    ('keycloakRealm', 'DM_KEYCLOAK_REALM', 'DM_HAS_KEYCLOAK_REALM', 'keycloakRealm'),
    ('keycloakClientId', 'DM_KEYCLOAK_CLIENT_ID', 'DM_HAS_KEYCLOAK_CLIENT_ID', 'keycloakClientId'),
    ('keycloak_redirect_uri', 'DM_KEYCLOAK_REDIRECT_URI', 'DM_HAS_KEYCLOAK_REDIRECT_URI', 'keycloak_redirect_uri'),
    ('keycloak_allowed_redirect_uri', 'DM_KEYCLOAK_ALLOWED_REDIRECT_URI', 'DM_HAS_KEYCLOAK_ALLOWED_REDIRECT_URI', 'keycloak_allowed_redirect_uri'),
    ('proxy_url', 'DM_PROXY_URL', 'DM_HAS_PROXY_URL', 'proxy_url'),
    ('bootstrap_url', 'DM_BOOTSTRAP_URL', 'DM_HAS_BOOTSTRAP_URL', 'bootstrap_url'),
    ('device_name', 'DM_DEVICE_NAME', 'DM_HAS_DEVICE_NAME', 'device_name'),
    ('config_path', 'DM_CONFIG_PATH', 'DM_HAS_CONFIG_PATH', 'config_path'),
]

with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)

changed = []

for json_key, env_value, env_has, label in mapping:
    is_explicit = os.environ.get(env_has, 'false').lower() == 'true'
    provided = os.environ.get(env_value, '')
    current = data.get(json_key, '')
    new_value = current

    if is_explicit:
        new_value = provided
    elif interactive:
        typed = input(f"{label} [{current}]: ")
        if typed != '':
            new_value = typed

    if new_value != current:
        data[json_key] = new_value
        changed.append((json_key, current, new_value))

with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=4, ensure_ascii=False)
    f.write('\n')

print(f"Updated file: {path}")
if changed:
    print("Changed keys:")
    for k, old, new in changed:
        print(f"  - {k}: {old!r} -> {new!r}")
else:
    print("No changes applied (provide options/env or use --interactive).")
PY
