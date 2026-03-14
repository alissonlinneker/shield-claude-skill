#!/usr/bin/env bash
set -euo pipefail

# Checks availability of security tools required by Shield.
# Outputs JSON to stdout with tool status, versions, and install hints.

# --- Helpers ---

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    printf '%s' "$str"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

get_version() {
    local cmd="$1"
    shift
    "$cmd" "$@" 2>/dev/null | head -1 || echo "unknown"
}

# --- Tool Checks ---

check_docker() {
    if check_command docker; then
        local ver
        ver="$(docker --version 2>/dev/null | sed 's/Docker version \([^,]*\).*/\1/' || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"https://docs.docker.com/get-docker/"}'
    fi
}

check_shannon() {
    local shannon_bin=""

    # Priority: SHANNON_PATH env > ./shannon > ~/shannon
    if [[ -n "${SHANNON_PATH:-}" ]] && [[ -x "${SHANNON_PATH}/shannon" ]]; then
        shannon_bin="${SHANNON_PATH}/shannon"
    elif [[ -x "./shannon" ]]; then
        shannon_bin="./shannon"
    elif [[ -x "${HOME}/shannon/shannon" ]]; then
        shannon_bin="${HOME}/shannon/shannon"
    elif check_command shannon; then
        shannon_bin="$(command -v shannon)"
    fi

    if [[ -n "$shannon_bin" ]]; then
        local real_path
        real_path="$(cd "$(dirname "$shannon_bin")" && pwd)/$(basename "$shannon_bin")"
        printf '{"available":true,"path":"%s"}' "$(json_escape "$real_path")"
    else
        printf '{"available":false,"install":"git clone the Shannon repository and set SHANNON_PATH"}'
    fi
}

check_semgrep() {
    if check_command semgrep; then
        local ver
        ver="$(semgrep --version 2>/dev/null || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"pip install semgrep"}'
    fi
}

check_gitleaks() {
    if check_command gitleaks; then
        local ver
        ver="$(gitleaks version 2>/dev/null || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"brew install gitleaks  OR  go install github.com/gitleaks/gitleaks/v8@latest"}'
    fi
}

check_npm_audit() {
    if check_command npm; then
        printf '{"available":true}'
    else
        printf '{"available":false,"install":"Install Node.js: https://nodejs.org/"}'
    fi
}

check_pip_audit() {
    if check_command pip-audit; then
        local ver
        ver="$(pip-audit --version 2>/dev/null | head -1 || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"pip install pip-audit"}'
    fi
}

check_composer_audit() {
    if check_command composer; then
        # composer audit was added in Composer 2.4
        local ver
        ver="$(composer --version 2>/dev/null | sed 's/Composer version \([^ ]*\).*/\1/' || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"https://getcomposer.org/download/"}'
    fi
}

check_govulncheck() {
    if check_command govulncheck; then
        printf '{"available":true}'
    else
        printf '{"available":false,"install":"go install golang.org/x/vuln/cmd/govulncheck@latest"}'
    fi
}

check_bundle_audit() {
    if check_command bundle-audit; then
        local ver
        ver="$(bundle-audit version 2>/dev/null || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"gem install bundler-audit"}'
    fi
}

check_cargo_audit() {
    if check_command cargo-audit; then
        local ver
        ver="$(cargo audit --version 2>/dev/null || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"cargo install cargo-audit"}'
    fi
}

check_cargo_outdated() {
    if check_command cargo-outdated; then
        printf '{"available":true}'
    else
        printf '{"available":false,"install":"cargo install cargo-outdated"}'
    fi
}

check_trivy() {
    if check_command trivy; then
        local ver
        ver="$(trivy --version 2>/dev/null | head -1 || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"brew install trivy  OR  https://trivy.dev/latest/getting-started/installation/"}'
    fi
}

check_dotnet() {
    if check_command dotnet; then
        local ver
        ver="$(dotnet --version 2>/dev/null || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"https://dotnet.microsoft.com/download"}'
    fi
}

check_maven() {
    if check_command mvn; then
        local ver
        ver="$(mvn --version 2>/dev/null | head -1 || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"https://maven.apache.org/install.html"}'
    fi
}

check_gradle() {
    if check_command gradle; then
        local ver
        ver="$(gradle --version 2>/dev/null | grep Gradle | head -1 || echo "unknown")"
        printf '{"available":true,"version":"%s"}' "$(json_escape "$ver")"
    else
        printf '{"available":false,"install":"https://gradle.org/install/"}'
    fi
}

# --- Main ---

printf '{\n'
printf '  "docker": %s,\n' "$(check_docker)"
printf '  "shannon": %s,\n' "$(check_shannon)"
printf '  "semgrep": %s,\n' "$(check_semgrep)"
printf '  "gitleaks": %s,\n' "$(check_gitleaks)"
printf '  "npm_audit": %s,\n' "$(check_npm_audit)"
printf '  "pip_audit": %s,\n' "$(check_pip_audit)"
printf '  "composer_audit": %s,\n' "$(check_composer_audit)"
printf '  "govulncheck": %s,\n' "$(check_govulncheck)"
printf '  "bundle_audit": %s,\n' "$(check_bundle_audit)"
printf '  "cargo_audit": %s,\n' "$(check_cargo_audit)"
printf '  "cargo_outdated": %s,\n' "$(check_cargo_outdated)"
printf '  "trivy": %s,\n' "$(check_trivy)"
printf '  "dotnet": %s,\n' "$(check_dotnet)"
printf '  "maven": %s,\n' "$(check_maven)"
printf '  "gradle": %s\n' "$(check_gradle)"
printf '}\n'
