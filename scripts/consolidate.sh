#!/usr/bin/env bash
set -euo pipefail

# Merges multiple tool output JSON files into a single consolidated report.
# Deduplicates findings, assigns SHIELD-XXX IDs, sorts by severity,
# and calculates summary counts.
#
# Usage: consolidate.sh <file1.json> [file2.json] [file3.json] ...
#
# Outputs consolidated JSON to stdout.

if [[ $# -eq 0 ]]; then
    echo "Error: at least one tool output file is required" >&2
    echo "Usage: consolidate.sh <file1.json> [file2.json] ..." >&2
    exit 1
fi

# --- Verify jq is available ---

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required for consolidation. Install with: brew install jq" >&2
    exit 1
fi

# --- Validate input files ---

INPUT_FILES=()
TOOLS_USED=()

for file in "$@"; do
    if [[ ! -f "$file" ]]; then
        echo "Warning: file not found, skipping: $file" >&2
        continue
    fi

    # Validate JSON
    if ! jq empty "$file" 2>/dev/null; then
        echo "Warning: invalid JSON, skipping: $file" >&2
        continue
    fi

    INPUT_FILES+=("$file")

    # Extract tool name
    tool_name="$(jq -r '.tool // "unknown"' "$file" 2>/dev/null || echo "unknown")"
    TOOLS_USED+=("$tool_name")
done

if [[ ${#INPUT_FILES[@]} -eq 0 ]]; then
    echo "Error: no valid input files provided" >&2
    exit 1
fi

# --- Merge all findings ---

# Collect all findings into a single array, then deduplicate and sort
MERGED="$(jq -s '
    # Collect all findings from all files, normalize cwe to string
    [.[] | .findings // [] | .[] |
        .cwe = (if (.cwe | type) == "array" then (.cwe[0] // null) else .cwe end)
    ] |

    # Deduplicate: same file + line + source_tool + title = duplicate
    group_by([(.file // ""), (.line // 0 | tostring), (.source_tool // ""), (.title // "")]) |
    map(.[0]) |

    # Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
    sort_by(
        if .severity == "CRITICAL" then 0
        elif .severity == "HIGH" then 1
        elif .severity == "MEDIUM" then 2
        elif .severity == "LOW" then 3
        else 4
        end
    )
' "${INPUT_FILES[@]}")"

# --- Assign SHIELD IDs and build final output ---

SCAN_DATE="$(date +%Y-%m-%d)"
SCAN_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Build tools arrays as JSON
TOOLS_USED_JSON="$(printf '%s\n' "${TOOLS_USED[@]}" | jq -R . | jq -s 'unique')"

echo "$MERGED" | jq \
    --arg scan_date "$SCAN_DATE" \
    --arg scan_time "$SCAN_TIME" \
    --argjson tools_used "$TOOLS_USED_JSON" \
    '
    # Assign sequential SHIELD-XXX IDs
    . as $findings |
    {
        "findings": [
            $findings | to_entries[] | .value + {
                "id": ("SHIELD-" + ((.key + 1) | tostring | if length < 3 then ("000" + .)[-3:] else . end))
            }
        ],
        "metadata": {
            "scan_date": $scan_date,
            "scan_timestamp": $scan_time,
            "tools_used": $tools_used,
            "tools_skipped": [],
            "total_files_scanned": (
                [$findings[].file // null | select(. != null)] | unique | length
            )
        },
        "summary": {
            "total": ($findings | length),
            "by_severity": {
                "critical": ([$findings[] | select(.severity == "CRITICAL")] | length),
                "high": ([$findings[] | select(.severity == "HIGH")] | length),
                "medium": ([$findings[] | select(.severity == "MEDIUM")] | length),
                "low": ([$findings[] | select(.severity == "LOW")] | length)
            },
            "by_tool": (
                [$findings[] | .source_tool // "unknown"] |
                group_by(.) |
                map({(.[0]): length}) |
                add // {}
            ),
            "by_cwe": (
                [$findings[] | .cwe // null | select(. != null) |
                    if type == "array" then .[] else . end] |
                group_by(.) |
                map({(.[0]): length}) |
                add // {}
            )
        }
    }
'
