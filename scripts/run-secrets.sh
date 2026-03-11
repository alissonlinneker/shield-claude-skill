#!/usr/bin/env bash
set -euo pipefail

# Runs gitleaks on a repository to detect hardcoded secrets.
# Outputs normalized JSON findings to stdout.
#
# Usage: run-secrets.sh <project-path>

PROJECT_PATH="${1:-}"

if [[ -z "$PROJECT_PATH" ]]; then
    echo "Error: project path is required as first argument" >&2
    exit 1
fi

if [[ ! -d "$PROJECT_PATH" ]]; then
    echo "Error: project directory not found: $PROJECT_PATH" >&2
    exit 1
fi

PROJECT_PATH="$(cd "$PROJECT_PATH" && pwd)"

# --- Verify gitleaks is available ---

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "Error: gitleaks is not installed." >&2
    echo "Install with: brew install gitleaks  OR  go install github.com/gitleaks/gitleaks/v8@latest" >&2
    exit 1
fi

# --- Run gitleaks ---

TEMP_OUTPUT="$(mktemp /tmp/shield-secrets-XXXXXX.json)"
trap 'rm -f "$TEMP_OUTPUT"' EXIT

echo "Running gitleaks on: $PROJECT_PATH" >&2

# gitleaks returns exit code 1 when secrets are found, which is expected
gitleaks detect \
    --source "$PROJECT_PATH" \
    --report-format json \
    --report-path "$TEMP_OUTPUT" \
    --no-banner \
    2>/dev/null || true

# --- Check if output was generated ---

if [[ ! -s "$TEMP_OUTPUT" ]]; then
    # No findings — output empty result
    printf '{"tool":"gitleaks","findings":[],"summary":{"total":0}}\n'
    exit 0
fi

# --- Normalize output ---

if command -v jq >/dev/null 2>&1; then
    jq '
    {
        "tool": "gitleaks",
        "findings": [
            .[] | {
                "severity": (
                    # Map secret types to severity levels
                    if (.RuleID // "" | test("private.key|private_key|rsa|ssh"; "i")) then "CRITICAL"
                    elif (.RuleID // "" | test("aws|gcp|azure|cloud"; "i")) then "CRITICAL"
                    elif (.RuleID // "" | test("database|db.password|connection.string"; "i")) then "CRITICAL"
                    elif (.RuleID // "" | test("api.key|api_key|apikey|secret.key|token"; "i")) then "HIGH"
                    elif (.RuleID // "" | test("password|passwd|pwd"; "i")) then "HIGH"
                    else "MEDIUM"
                    end
                ),
                "title": ("Hardcoded secret: " + (.RuleID // "unknown")),
                "description": (.Description // ("Secret detected by rule: " + (.RuleID // "unknown"))),
                "file": (.File // "unknown"),
                "line": (.StartLine // null),
                "end_line": (.EndLine // null),
                "column": (.StartColumn // null),
                "code_snippet": (
                    # Redact the actual secret value — show only context
                    if .Match then
                        (.Match | if length > 40 then .[:20] + "****REDACTED****" + .[-10:] else "****REDACTED****" end)
                    else null
                    end
                ),
                "rule_id": (.RuleID // "unknown"),
                "entropy": (.Entropy // null),
                "commit": (.Commit // null),
                "author": (.Author // null),
                "date": (.Date // null),
                "cwe": "CWE-798",
                "owasp": "A02:2021",
                "source_tool": "gitleaks",
                "tags": ["secrets", "hardcoded-credentials"]
            }
        ],
        "summary": {
            "total": length,
            "by_rule": (group_by(.RuleID) | map({(.[0].RuleID // "unknown"): length}) | add // {})
        }
    }' "$TEMP_OUTPUT"
else
    # Fallback: output raw gitleaks JSON
    echo "Warning: jq not found. Outputting raw gitleaks JSON." >&2
    cat "$TEMP_OUTPUT"
fi
