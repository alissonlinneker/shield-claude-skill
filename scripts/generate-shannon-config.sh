#!/usr/bin/env bash
set -euo pipefail

# Generates a Shannon YAML configuration file for the target application.
#
# Usage:
#   generate-shannon-config.sh --app-type <type> --url <url> [--auth-config <path>]
#
# Arguments:
#   --app-type    Application type: web-app | api-only | spa-with-api
#   --url         Target application URL
#   --auth-config (Optional) Path to JSON file with authentication configuration
#
# Templates are loaded from configs/shannon-templates/ in the skill directory.
# Outputs the path to the generated config file on stdout.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
TEMPLATES_DIR="$SKILL_DIR/configs/shannon-templates"
OUTPUT_DIR="${SHANNON_CONFIG_OUTPUT_DIR:-/tmp/shield-shannon-configs}"

APP_TYPE=""
URL=""
AUTH_CONFIG=""

# --- Argument parsing ---

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app-type)
            APP_TYPE="$2"
            shift 2
            ;;
        --url)
            URL="$2"
            shift 2
            ;;
        --auth-config)
            AUTH_CONFIG="$2"
            shift 2
            ;;
        *)
            echo "Error: Unknown argument: $1" >&2
            echo "Usage: generate-shannon-config.sh --app-type <type> --url <url> [--auth-config <path>]" >&2
            exit 1
            ;;
    esac
done

# --- Validation ---

if [[ -z "$APP_TYPE" ]]; then
    echo "Error: --app-type is required (web-app|api-only|spa-with-api)" >&2
    exit 1
fi

if [[ -z "$URL" ]]; then
    echo "Error: --url is required" >&2
    exit 1
fi

case "$APP_TYPE" in
    web-app|api-only|spa-with-api) ;;
    *)
        echo "Error: Invalid app type '$APP_TYPE'. Must be: web-app, api-only, spa-with-api" >&2
        exit 1
        ;;
esac

if [[ -n "$AUTH_CONFIG" ]] && [[ ! -f "$AUTH_CONFIG" ]]; then
    echo "Error: Auth config file not found: $AUTH_CONFIG" >&2
    exit 1
fi

# --- Prepare output directory ---

mkdir -p "$OUTPUT_DIR"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
CONFIG_FILE="$OUTPUT_DIR/shannon-${APP_TYPE}-${TIMESTAMP}.yaml"

# --- Extract URL components ---

# Remove protocol prefix for host extraction
URL_HOST="$(echo "$URL" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|:.*||')"
URL_PORT="$(echo "$URL" | grep -o ':[0-9]*' | tail -1 | tr -d ':' || true)"

# --- Check for template file ---

TEMPLATE_FILE="$TEMPLATES_DIR/${APP_TYPE}.yaml"

if [[ -f "$TEMPLATE_FILE" ]]; then
    # Use existing template as base, substituting placeholders
    sed \
        -e "s|{{URL}}|${URL}|g" \
        -e "s|{{HOST}}|${URL_HOST}|g" \
        -e "s|{{PORT}}|${URL_PORT:-443}|g" \
        -e "s|{{TIMESTAMP}}|${TIMESTAMP}|g" \
        "$TEMPLATE_FILE" > "$CONFIG_FILE"
else
    # Generate config from scratch based on app type
    echo "Warning: Template not found at $TEMPLATE_FILE, generating default config." >&2

    cat > "$CONFIG_FILE" <<YAML
# Shannon configuration
# Type: ${APP_TYPE}
# Target: ${URL}
# Generated: ${TIMESTAMP}

target:
  url: "${URL}"
  host: "${URL_HOST}"
  port: ${URL_PORT:-443}

scan:
  type: "${APP_TYPE}"
YAML

    case "$APP_TYPE" in
        web-app)
            cat >> "$CONFIG_FILE" <<'YAML'
  modules:
    - spider
    - active-scan
    - passive-scan
    - authentication-test
    - session-management
    - input-validation
    - xss-detection
    - sqli-detection
    - csrf-detection
    - header-analysis
  spider:
    max_depth: 5
    max_pages: 500
    respect_robots: false
  active_scan:
    strength: "medium"
    threshold: "medium"
YAML
            ;;
        api-only)
            cat >> "$CONFIG_FILE" <<'YAML'
  modules:
    - api-discovery
    - active-scan
    - passive-scan
    - authentication-test
    - input-validation
    - sqli-detection
    - idor-detection
    - rate-limit-check
    - header-analysis
  api:
    discovery_mode: "brute"
    common_paths: true
    openapi_scan: true
  active_scan:
    strength: "medium"
    threshold: "medium"
YAML
            ;;
        spa-with-api)
            cat >> "$CONFIG_FILE" <<'YAML'
  modules:
    - spider
    - ajax-spider
    - api-discovery
    - active-scan
    - passive-scan
    - authentication-test
    - session-management
    - input-validation
    - xss-detection
    - sqli-detection
    - cors-check
    - header-analysis
  spider:
    max_depth: 5
    max_pages: 500
    respect_robots: false
  ajax_spider:
    enabled: true
    max_duration: 300
    browser: "chrome-headless"
  active_scan:
    strength: "medium"
    threshold: "medium"
YAML
            ;;
    esac

    # Add reporting section
    cat >> "$CONFIG_FILE" <<'YAML'

reporting:
  format: "json"
  include_evidence: true
  include_request_response: true
  risk_threshold: "low"
YAML
fi

# --- Append authentication configuration if provided ---

if [[ -n "$AUTH_CONFIG" ]]; then
    echo "" >> "$CONFIG_FILE"
    echo "authentication:" >> "$CONFIG_FILE"

    # Parse auth config JSON and convert to YAML
    # Supports: type (basic|bearer|form|cookie), and type-specific fields
    auth_type="$(grep -o '"type"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"

    if [[ -n "$auth_type" ]]; then
        echo "  type: \"${auth_type}\"" >> "$CONFIG_FILE"

        case "$auth_type" in
            basic)
                username="$(grep -o '"username"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
                password="$(grep -o '"password"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
                echo "  username: \"${username}\"" >> "$CONFIG_FILE"
                echo "  password: \"${password}\"" >> "$CONFIG_FILE"
                ;;
            bearer)
                token="$(grep -o '"token"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
                echo "  token: \"${token}\"" >> "$CONFIG_FILE"
                ;;
            form)
                login_url="$(grep -o '"login_url"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
                username_field="$(grep -o '"username_field"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
                password_field="$(grep -o '"password_field"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
                username="$(grep -o '"username"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
                password="$(grep -o '"password"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
                echo "  login_url: \"${login_url}\"" >> "$CONFIG_FILE"
                echo "  username_field: \"${username_field:-username}\"" >> "$CONFIG_FILE"
                echo "  password_field: \"${password_field:-password}\"" >> "$CONFIG_FILE"
                echo "  username: \"${username}\"" >> "$CONFIG_FILE"
                echo "  password: \"${password}\"" >> "$CONFIG_FILE"
                ;;
            cookie)
                cookie_name="$(grep -o '"cookie_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
                cookie_value="$(grep -o '"cookie_value"[[:space:]]*:[[:space:]]*"[^"]*"' "$AUTH_CONFIG" | sed 's/.*: *"\([^"]*\)".*/\1/' || true)"
                echo "  cookie_name: \"${cookie_name}\"" >> "$CONFIG_FILE"
                echo "  cookie_value: \"${cookie_value}\"" >> "$CONFIG_FILE"
                ;;
            *)
                echo "  # Unknown auth type: ${auth_type}" >> "$CONFIG_FILE"
                ;;
        esac
    fi
fi

# --- Output config path ---

echo "$CONFIG_FILE"
