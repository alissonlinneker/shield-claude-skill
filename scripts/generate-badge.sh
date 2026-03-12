#!/usr/bin/env bash
set -euo pipefail

# Generates a shields.io-compatible badge JSON from a Shield scan result.
# The badge file can be committed to the repo and referenced via shields.io
# dynamic badge endpoint for real-time score display in README files.
#
# Usage:
#   generate-badge.sh <consolidated.json>          # from file
#   cat consolidated.json | generate-badge.sh      # from stdin
#
# Outputs: shield-badge.json (shields.io endpoint schema)

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required. Install with: brew install jq" >&2
    exit 1
fi

# Read input
INPUT_DATA=""
if [[ $# -gt 0 ]] && [[ -f "$1" ]]; then
    INPUT_DATA="$(cat "$1")"
elif [[ ! -t 0 ]]; then
    INPUT_DATA="$(cat)"
else
    echo "Error: pass a consolidated JSON file or pipe to stdin." >&2
    exit 1
fi

if ! echo "$INPUT_DATA" | jq empty 2>/dev/null; then
    echo "Error: invalid JSON input" >&2
    exit 1
fi

# Calculate score if input has findings, or read score directly
SCORE_DATA=""
if echo "$INPUT_DATA" | jq -e '.score' >/dev/null 2>&1; then
    # Input is already a score output
    SCORE_DATA="$INPUT_DATA"
else
    # Input is consolidated findings — calculate score
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "$SCRIPT_DIR/calculate-score.sh" ]]; then
        SCORE_DATA="$(echo "$INPUT_DATA" | bash "$SCRIPT_DIR/calculate-score.sh")"
    else
        echo "Error: cannot find calculate-score.sh to compute score" >&2
        exit 1
    fi
fi

# Extract score and risk level
SCORE="$(echo "$SCORE_DATA" | jq -r '.score')"
RISK="$(echo "$SCORE_DATA" | jq -r '.risk_level')"
TOTAL="$(echo "$SCORE_DATA" | jq -r '.total_findings')"

# Map risk level to color
COLOR="lightgrey"
case "$RISK" in
    LOW)      COLOR="brightgreen" ;;
    MEDIUM)   COLOR="yellow" ;;
    HIGH)     COLOR="orange" ;;
    CRITICAL) COLOR="red" ;;
esac

# Generate shields.io endpoint badge JSON
# See: https://shields.io/badges/endpoint-badge
jq -n \
    --argjson schema 1 \
    --arg label "Shield Score" \
    --arg message "${SCORE}/100" \
    --arg color "$COLOR" \
    --arg risk "$RISK" \
    --argjson score "$SCORE" \
    --argjson findings "$TOTAL" \
    '{
        "schemaVersion": $schema,
        "label": $label,
        "message": $message,
        "color": $color,
        "metadata": {
            "score": $score,
            "risk_level": $risk,
            "total_findings": $findings,
            "scan_date": (now | strftime("%Y-%m-%d"))
        }
    }'
