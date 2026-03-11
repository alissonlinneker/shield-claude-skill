#!/usr/bin/env bash
set -euo pipefail

# Runs Semgrep SAST analysis on a project with language-appropriate rules.
# Outputs normalized JSON findings to stdout.
#
# Usage: run-sast.sh <project-path> <language>

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
RULES_DIR="$SKILL_DIR/configs/semgrep-rules"

PROJECT_PATH="${1:-}"
LANGUAGE="${2:-}"

if [[ -z "$PROJECT_PATH" ]]; then
    echo "Error: project path is required as first argument" >&2
    exit 1
fi

if [[ ! -d "$PROJECT_PATH" ]]; then
    echo "Error: project directory not found: $PROJECT_PATH" >&2
    exit 1
fi

if [[ -z "$LANGUAGE" ]]; then
    echo "Error: language is required as second argument" >&2
    exit 1
fi

PROJECT_PATH="$(cd "$PROJECT_PATH" && pwd)"

# --- Verify semgrep is available ---

if ! command -v semgrep >/dev/null 2>&1; then
    echo "Error: semgrep is not installed. Install with: pip install semgrep" >&2
    exit 1
fi

# --- Build rule arguments ---

SEMGREP_ARGS=()
RULE_FILE=""

# Check for language-specific custom rules
for candidate in "$RULES_DIR/${LANGUAGE}.yaml" "$RULES_DIR/${LANGUAGE}.yml"; do
    if [[ -f "$candidate" ]]; then
        RULE_FILE="$candidate"
        break
    fi
done

if [[ -n "$RULE_FILE" ]]; then
    echo "Using custom rules: $RULE_FILE" >&2
    SEMGREP_ARGS+=(--config "$RULE_FILE")

    # Also check for a common rules file
    for common in "$RULES_DIR/common.yaml" "$RULES_DIR/common.yml"; do
        if [[ -f "$common" ]]; then
            SEMGREP_ARGS+=(--config "$common")
            echo "Including common rules: $common" >&2
            break
        fi
    done
else
    echo "No custom rules for '$LANGUAGE', using semgrep auto config." >&2
    SEMGREP_ARGS+=(--config auto)
fi

# --- Run semgrep ---

TEMP_OUTPUT="$(mktemp /tmp/shield-sast-XXXXXX.json)"
trap 'rm -f "$TEMP_OUTPUT"' EXIT

echo "Running Semgrep on: $PROJECT_PATH" >&2
echo "Language: $LANGUAGE" >&2

semgrep \
    "${SEMGREP_ARGS[@]}" \
    --json \
    --quiet \
    --exclude='node_modules' \
    --exclude='vendor' \
    --exclude='.venv' \
    --exclude='venv' \
    --exclude='dist' \
    --exclude='build' \
    --exclude='.next' \
    --exclude='target' \
    --exclude='__pycache__' \
    "$PROJECT_PATH" \
    > "$TEMP_OUTPUT" 2>/dev/null || true

# --- Normalize output to common finding format ---

# Use inline processing to normalize semgrep JSON output
# If jq is available, use it for proper JSON processing
if command -v jq >/dev/null 2>&1; then
    jq --arg tool "semgrep" --arg lang "$LANGUAGE" '
    {
        "tool": "semgrep",
        "language": $lang,
        "findings": (
            if .results then
                [.results[] | {
                    "severity": (
                        if .extra.severity == "ERROR" then "HIGH"
                        elif .extra.severity == "WARNING" then "MEDIUM"
                        elif .extra.severity == "INFO" then "LOW"
                        else (.extra.severity // "MEDIUM")
                        end
                    ),
                    "title": (.check_id // "unknown-check"),
                    "description": (.extra.message // ""),
                    "file": .path,
                    "line": .start.line,
                    "end_line": .end.line,
                    "column": .start.col,
                    "code_snippet": (.extra.lines // ""),
                    "rule_id": (.check_id // ""),
                    "cwe": (
                        if .extra.metadata.cwe then
                            (if (.extra.metadata.cwe | type) == "array" then
                                .extra.metadata.cwe[0]
                            else
                                .extra.metadata.cwe
                            end)
                        else null
                        end
                    ),
                    "owasp": (
                        if .extra.metadata.owasp then
                            (if (.extra.metadata.owasp | type) == "array" then
                                .extra.metadata.owasp[0]
                            else
                                .extra.metadata.owasp
                            end)
                        else null
                        end
                    ),
                    "confidence": (.extra.metadata.confidence // "MEDIUM"),
                    "source_tool": "semgrep"
                }]
            else
                []
            end
        ),
        "summary": {
            "total": (if .results then (.results | length) else 0 end),
            "errors": (if .errors then (.errors | length) else 0 end)
        }
    }' "$TEMP_OUTPUT"
else
    # Fallback: output raw semgrep JSON if jq is not available
    echo "Warning: jq not found. Outputting raw semgrep JSON." >&2
    cat "$TEMP_OUTPUT"
fi
