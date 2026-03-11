#!/usr/bin/env bash
set -euo pipefail

# Runs package/dependency audit for the detected package manager.
# Outputs normalized JSON vulnerability findings to stdout.
#
# Usage: run-sca.sh <project-path> <package-manager>
#
# Supported package managers: npm, yarn, pnpm, pip, composer

PROJECT_PATH="${1:-}"
PACKAGE_MANAGER="${2:-}"

if [[ -z "$PROJECT_PATH" ]]; then
    echo "Error: project path is required as first argument" >&2
    exit 1
fi

if [[ ! -d "$PROJECT_PATH" ]]; then
    echo "Error: project directory not found: $PROJECT_PATH" >&2
    exit 1
fi

if [[ -z "$PACKAGE_MANAGER" ]]; then
    echo "Error: package manager is required as second argument (npm|yarn|pnpm|pip|composer)" >&2
    exit 1
fi

PROJECT_PATH="$(cd "$PROJECT_PATH" && pwd)"

# --- Helpers ---

has_jq() {
    command -v jq >/dev/null 2>&1
}

# Output empty result when the tool produces non-JSON or no output
empty_result() {
    local tool="$1"
    local pm="$2"
    local reason="${3:-no output}"
    printf '{"tool":"%s","package_manager":"%s","findings":[],"summary":{"total":0},"note":"%s"}\n' "$tool" "$pm" "$reason"
}

is_valid_json() {
    if [[ -z "$1" ]]; then
        return 1
    fi
    echo "$1" | jq empty 2>/dev/null
}

# --- Audit functions ---

run_npm_audit() {
    echo "Running npm audit in: $PROJECT_PATH" >&2

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && npm audit --json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "npm-audit" "npm" "npm audit produced no JSON output"
        return
    fi

    # Check if npm audit returned an error (e.g., missing lockfile)
    if has_jq && echo "$raw_output" | jq -e '.error' >/dev/null 2>&1; then
        local err_summary
        err_summary="$(echo "$raw_output" | jq -r '.error.summary // "unknown error"')"
        echo "Warning: npm audit error: $err_summary" >&2
        empty_result "npm-audit" "npm" "$err_summary"
        return
    fi

    if has_jq; then
        echo "$raw_output" | jq '
        {
            "tool": "npm-audit",
            "package_manager": "npm",
            "findings": (
                if .vulnerabilities then
                    [.vulnerabilities | to_entries[] | {
                        "severity": (
                            if .value.severity == "critical" then "CRITICAL"
                            elif .value.severity == "high" then "HIGH"
                            elif .value.severity == "moderate" then "MEDIUM"
                            elif .value.severity == "low" then "LOW"
                            else "MEDIUM"
                            end
                        ),
                        "title": ("Vulnerable dependency: " + .key),
                        "description": (.value.via[0] | if type == "object" then .title // "" else . end),
                        "package": .key,
                        "installed_version": (.value.range // "unknown"),
                        "vulnerable_range": (.value.range // "unknown"),
                        "recommendation": (.value.fixAvailable | if type == "object" then "Update to " + .name + "@" + .version else "Check for updates" end),
                        "cwe": null,
                        "owasp": "A06:2021",
                        "source_tool": "npm-audit",
                        "file": "package.json",
                        "line": null
                    }]
                elif .advisories then
                    [.advisories | to_entries[] | .value | {
                        "severity": (
                            if .severity == "critical" then "CRITICAL"
                            elif .severity == "high" then "HIGH"
                            elif .severity == "moderate" then "MEDIUM"
                            elif .severity == "low" then "LOW"
                            else "MEDIUM"
                            end
                        ),
                        "title": .title,
                        "description": .overview,
                        "package": .module_name,
                        "installed_version": (.findings[0].version // "unknown"),
                        "vulnerable_range": .vulnerable_versions,
                        "recommendation": .recommendation,
                        "cwe": (.cwe // null),
                        "owasp": "A06:2021",
                        "source_tool": "npm-audit",
                        "file": "package.json",
                        "line": null
                    }]
                else
                    []
                end
            ),
            "summary": {
                "total": (
                    if .metadata.vulnerabilities then
                        (.metadata.vulnerabilities.total // 0)
                    else 0 end
                )
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_yarn_audit() {
    echo "Running yarn audit in: $PROJECT_PATH" >&2

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && yarn audit --json 2>/dev/null)" || true

    if [[ -z "$raw_output" ]]; then
        empty_result "yarn-audit" "yarn" "yarn audit produced no output"
        return
    fi

    if has_jq; then
        # yarn audit outputs NDJSON (one JSON object per line)
        echo "$raw_output" | jq -s '
        {
            "tool": "yarn-audit",
            "package_manager": "yarn",
            "findings": [
                .[] | select(.type == "auditAdvisory") | .data.advisory | {
                    "severity": (
                        if .severity == "critical" then "CRITICAL"
                        elif .severity == "high" then "HIGH"
                        elif .severity == "moderate" then "MEDIUM"
                        elif .severity == "low" then "LOW"
                        else "MEDIUM"
                        end
                    ),
                    "title": .title,
                    "description": .overview,
                    "package": .module_name,
                    "installed_version": (.findings[0].version // "unknown"),
                    "vulnerable_range": .vulnerable_versions,
                    "recommendation": .recommendation,
                    "cwe": (.cwe // null),
                    "owasp": "A06:2021",
                    "source_tool": "yarn-audit",
                    "file": "package.json",
                    "line": null
                }
            ],
            "summary": {
                "total": ([.[] | select(.type == "auditAdvisory")] | length)
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_pnpm_audit() {
    echo "Running pnpm audit in: $PROJECT_PATH" >&2

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && pnpm audit --json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "pnpm-audit" "pnpm" "pnpm audit produced no JSON output"
        return
    fi

    if has_jq; then
        # pnpm audit JSON format is similar to npm
        echo "$raw_output" | jq '
        {
            "tool": "pnpm-audit",
            "package_manager": "pnpm",
            "findings": (
                if .advisories then
                    [.advisories | to_entries[] | .value | {
                        "severity": (
                            if .severity == "critical" then "CRITICAL"
                            elif .severity == "high" then "HIGH"
                            elif .severity == "moderate" then "MEDIUM"
                            elif .severity == "low" then "LOW"
                            else "MEDIUM"
                            end
                        ),
                        "title": .title,
                        "description": .overview,
                        "package": .module_name,
                        "installed_version": (.findings[0].version // "unknown"),
                        "vulnerable_range": .vulnerable_versions,
                        "recommendation": .recommendation,
                        "cwe": (.cwe // null),
                        "owasp": "A06:2021",
                        "source_tool": "pnpm-audit",
                        "file": "package.json",
                        "line": null
                    }]
                else
                    []
                end
            ),
            "summary": {
                "total": (if .advisories then (.advisories | length) else 0 end)
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_pip_audit() {
    echo "Running pip-audit in: $PROJECT_PATH" >&2

    if ! command -v pip-audit >/dev/null 2>&1; then
        echo "Error: pip-audit is not installed. Install with: pip install pip-audit" >&2
        printf '{"tool":"pip-audit","package_manager":"pip","findings":[],"summary":{"total":0},"error":"pip-audit not installed"}\n'
        return
    fi

    local raw_output
    local req_file=""

    # Detect requirements file
    for candidate in "$PROJECT_PATH/requirements.txt" "$PROJECT_PATH/requirements/base.txt" "$PROJECT_PATH/requirements/production.txt"; do
        if [[ -f "$candidate" ]]; then
            req_file="$candidate"
            break
        fi
    done

    if [[ -n "$req_file" ]]; then
        raw_output="$(pip-audit -r "$req_file" --format json --output - 2>/dev/null)" || true
    else
        raw_output="$(cd "$PROJECT_PATH" && pip-audit --format json --output - 2>/dev/null)" || true
    fi

    if ! is_valid_json "$raw_output"; then
        empty_result "pip-audit" "pip" "pip-audit produced no JSON output"
        return
    fi

    if has_jq; then
        echo "$raw_output" | jq '
        {
            "tool": "pip-audit",
            "package_manager": "pip",
            "findings": [
                .dependencies // [] | .[] | select(.vulns | length > 0) |
                . as $dep |
                .vulns[] | {
                    "severity": "HIGH",
                    "title": ("Vulnerable dependency: " + $dep.name + " " + ($dep.version // "")),
                    "description": (.description // .id),
                    "package": $dep.name,
                    "installed_version": ($dep.version // "unknown"),
                    "vulnerable_range": "see advisory",
                    "recommendation": (
                        if .fix_versions and (.fix_versions | length > 0)
                        then "Update to " + .fix_versions[0]
                        else "No fix available"
                        end
                    ),
                    "cwe": null,
                    "owasp": "A06:2021",
                    "source_tool": "pip-audit",
                    "file": "requirements.txt",
                    "line": null,
                    "advisory_id": .id,
                    "advisory_url": (.aliases[0] // null)
                }
            ],
            "summary": {
                "total": ([.dependencies // [] | .[] | select(.vulns | length > 0) | .vulns[]] | length)
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_composer_audit() {
    echo "Running composer audit in: $PROJECT_PATH" >&2

    if ! command -v composer >/dev/null 2>&1; then
        echo "Error: composer is not installed." >&2
        printf '{"tool":"composer-audit","package_manager":"composer","findings":[],"summary":{"total":0},"error":"composer not installed"}\n'
        return
    fi

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && composer audit --format json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "composer-audit" "composer" "no packages to audit or composer.lock missing"
        return
    fi

    if has_jq; then
        echo "$raw_output" | jq '
        {
            "tool": "composer-audit",
            "package_manager": "composer",
            "findings": [
                .advisories // {} | to_entries[] |
                . as $pkg |
                .value[] | {
                    "severity": (
                        if .severity == "critical" then "CRITICAL"
                        elif .severity == "high" then "HIGH"
                        elif .severity == "medium" then "MEDIUM"
                        elif .severity == "low" then "LOW"
                        else "MEDIUM"
                        end
                    ),
                    "title": .title,
                    "description": (.title // ""),
                    "package": $pkg.key,
                    "installed_version": "see composer.lock",
                    "vulnerable_range": .affectedVersions,
                    "recommendation": ("See advisory: " + (.link // "")),
                    "cwe": (.cve // null),
                    "owasp": "A06:2021",
                    "source_tool": "composer-audit",
                    "file": "composer.json",
                    "line": null,
                    "advisory_id": (.advisoryId // null)
                }
            ],
            "summary": {
                "total": ([.advisories // {} | to_entries[] | .value[]] | length)
            }
        }'
    else
        echo "$raw_output"
    fi
}

# --- Main ---

case "$PACKAGE_MANAGER" in
    npm)
        run_npm_audit
        ;;
    yarn)
        run_yarn_audit
        ;;
    pnpm)
        run_pnpm_audit
        ;;
    pip|pipenv|poetry)
        run_pip_audit
        ;;
    composer)
        run_composer_audit
        ;;
    *)
        echo "Warning: Unsupported package manager: $PACKAGE_MANAGER" >&2
        echo "Supported: npm, yarn, pnpm, pip, composer" >&2
        printf '{"tool":"sca","package_manager":"%s","findings":[],"summary":{"total":0},"error":"unsupported package manager"}\n' "$PACKAGE_MANAGER"
        ;;
esac
