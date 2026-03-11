#!/usr/bin/env bash
set -euo pipefail

# Calculates a security risk score from consolidated findings.
#
# Formula: 100 - (CRITICAL*15 + HIGH*8 + MEDIUM*3 + LOW*1), minimum 0
#
# Usage:
#   calculate-score.sh <consolidated.json>   # from file
#   cat consolidated.json | calculate-score.sh   # from stdin
#
# Outputs JSON with score, risk level, and breakdown to stdout.

# --- Determine input source ---

INPUT_FILE=""

if [[ $# -gt 0 ]] && [[ -f "$1" ]]; then
    INPUT_FILE="$1"
fi

# --- Verify jq is available ---

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required. Install with: brew install jq" >&2
    exit 1
fi

# --- Read input ---

if [[ -n "$INPUT_FILE" ]]; then
    INPUT_DATA="$(cat "$INPUT_FILE")"
else
    # Read from stdin
    if [[ -t 0 ]]; then
        echo "Error: no input provided. Pass a file argument or pipe JSON to stdin." >&2
        echo "Usage: calculate-score.sh <consolidated.json>" >&2
        echo "   or: cat consolidated.json | calculate-score.sh" >&2
        exit 1
    fi
    INPUT_DATA="$(cat)"
fi

# --- Validate JSON ---

if ! echo "$INPUT_DATA" | jq empty 2>/dev/null; then
    echo "Error: invalid JSON input" >&2
    exit 1
fi

# --- Calculate score ---

echo "$INPUT_DATA" | jq '
    # Weight constants
    def weights: { "critical": 15, "high": 8, "medium": 3, "low": 1 };

    # Count findings by severity
    (
        if .findings then
            {
                "critical": ([.findings[] | select(.severity == "CRITICAL")] | length),
                "high": ([.findings[] | select(.severity == "HIGH")] | length),
                "medium": ([.findings[] | select(.severity == "MEDIUM")] | length),
                "low": ([.findings[] | select(.severity == "LOW")] | length)
            }
        elif .summary.by_severity then
            .summary.by_severity
        else
            { "critical": 0, "high": 0, "medium": 0, "low": 0 }
        end
    ) as $counts |

    # Calculate deductions
    ($counts.critical * weights.critical) as $crit_ded |
    ($counts.high * weights.high) as $high_ded |
    ($counts.medium * weights.medium) as $med_ded |
    ($counts.low * weights.low) as $low_ded |
    ($crit_ded + $high_ded + $med_ded + $low_ded) as $total_ded |

    # Calculate score (minimum 0)
    ([0, (100 - $total_ded)] | max) as $score |

    # Determine risk level
    (
        if $score >= 90 then "LOW"
        elif $score >= 70 then "MEDIUM"
        elif $score >= 40 then "HIGH"
        else "CRITICAL"
        end
    ) as $risk_level |

    # Output
    {
        "score": $score,
        "max_score": 100,
        "risk_level": $risk_level,
        "breakdown": {
            "critical": {
                "count": $counts.critical,
                "weight": weights.critical,
                "deduction": $crit_ded
            },
            "high": {
                "count": $counts.high,
                "weight": weights.high,
                "deduction": $high_ded
            },
            "medium": {
                "count": $counts.medium,
                "weight": weights.medium,
                "deduction": $med_ded
            },
            "low": {
                "count": $counts.low,
                "weight": weights.low,
                "deduction": $low_ded
            }
        },
        "total_deduction": $total_ded,
        "total_findings": ($counts.critical + $counts.high + $counts.medium + $counts.low)
    }
'
