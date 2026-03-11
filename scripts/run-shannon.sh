#!/usr/bin/env bash
set -euo pipefail

# Orchestrates Shannon execution: starts a scan, polls for completion,
# and outputs the final report path.
#
# Usage:
#   run-shannon.sh --shannon-path <path> --url <url> --repo <name> \
#                  [--config <path>] [--output-dir <path>]
#
# Outputs progress updates to stderr. Prints the report file path to stdout.

SHANNON_PATH=""
URL=""
REPO_NAME=""
CONFIG_PATH=""
OUTPUT_DIR=""
POLL_INTERVAL="${SHANNON_POLL_INTERVAL:-30}"

# --- Argument parsing ---

while [[ $# -gt 0 ]]; do
    case "$1" in
        --shannon-path)
            SHANNON_PATH="$2"
            shift 2
            ;;
        --url)
            URL="$2"
            shift 2
            ;;
        --repo)
            REPO_NAME="$2"
            shift 2
            ;;
        --config)
            CONFIG_PATH="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            echo "Error: Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# --- Validation ---

if [[ -z "$SHANNON_PATH" ]]; then
    echo "Error: --shannon-path is required" >&2
    exit 1
fi

if [[ -z "$URL" ]]; then
    echo "Error: --url is required" >&2
    exit 1
fi

if [[ -z "$REPO_NAME" ]]; then
    echo "Error: --repo is required" >&2
    exit 1
fi

SHANNON_PATH="$(cd "$SHANNON_PATH" && pwd)"
SHANNON_BIN="$SHANNON_PATH/shannon"

if [[ ! -x "$SHANNON_BIN" ]]; then
    echo "Error: Shannon binary not found or not executable: $SHANNON_BIN" >&2
    exit 1
fi

if [[ -n "$CONFIG_PATH" ]] && [[ ! -f "$CONFIG_PATH" ]]; then
    echo "Error: Config file not found: $CONFIG_PATH" >&2
    exit 1
fi

# Default output directory
if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="/tmp/shield-reports/$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUTPUT_DIR"

# --- Start Shannon ---

echo "[Shannon] Starting scan..." >&2
echo "[Shannon]   URL:  $URL" >&2
echo "[Shannon]   Repo: $REPO_NAME" >&2
if [[ -n "$CONFIG_PATH" ]]; then
    echo "[Shannon]   Config: $CONFIG_PATH" >&2
fi

cmd_args=("$SHANNON_BIN" "start" "URL=$URL" "REPO=$REPO_NAME")
if [[ -n "$CONFIG_PATH" ]]; then
    cmd_args+=("CONFIG=$CONFIG_PATH")
fi

start_output="$("${cmd_args[@]}" 2>&1)" || {
    echo "Error: Shannon failed to start:" >&2
    echo "$start_output" >&2
    exit 1
}

echo "[Shannon] Start output:" >&2
echo "$start_output" >&2

# --- Extract workflow ID ---

# Try common patterns Shannon might use for workflow IDs
workflow_id=""

# Pattern: "ID: <value>" or "id: <value>"
workflow_id="$(echo "$start_output" | grep -oiE '(workflow[_ ]?)?id[=: ]+[a-zA-Z0-9_-]+' | head -1 | sed 's/.*[=: ]//' || true)"

# Fallback: Look for a UUID pattern
if [[ -z "$workflow_id" ]]; then
    workflow_id="$(echo "$start_output" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1 || true)"
fi

# Fallback: Look for any standalone alphanumeric ID (at least 8 chars)
if [[ -z "$workflow_id" ]]; then
    workflow_id="$(echo "$start_output" | grep -oE '\b[a-zA-Z0-9]{8,}\b' | tail -1 || true)"
fi

if [[ -z "$workflow_id" ]]; then
    echo "Error: Could not extract workflow ID from Shannon output." >&2
    echo "Raw output: $start_output" >&2
    exit 1
fi

echo "[Shannon] Workflow ID: $workflow_id" >&2

# --- Poll for completion ---

max_polls=240  # 240 * 30s = 2 hours max
poll_count=0

while true; do
    poll_count=$((poll_count + 1))

    if [[ $poll_count -gt $max_polls ]]; then
        echo "Error: Shannon scan timed out after $((max_polls * POLL_INTERVAL / 60)) minutes." >&2
        exit 1
    fi

    query_output="$($SHANNON_BIN query ID="$workflow_id" 2>&1)" || true

    # Check for completion indicators
    if echo "$query_output" | grep -qiE '(complete|finished|done|success)'; then
        echo "[Shannon] Scan completed!" >&2
        break
    fi

    if echo "$query_output" | grep -qiE '(failed|error|aborted)'; then
        echo "Error: Shannon scan failed:" >&2
        echo "$query_output" >&2
        exit 1
    fi

    # Extract and display progress if available
    progress="$(echo "$query_output" | grep -oiE '[0-9]+%' | tail -1 || true)"
    status="$(echo "$query_output" | grep -oiE 'status[=: ]+[a-zA-Z_-]+' | head -1 | sed 's/.*[=: ]//' || true)"

    if [[ -n "$progress" ]]; then
        echo "[Shannon] Progress: $progress ${status:+(${status})}" >&2
    elif [[ -n "$status" ]]; then
        echo "[Shannon] Status: $status (poll #$poll_count)" >&2
    else
        echo "[Shannon] Waiting... (poll #$poll_count)" >&2
    fi

    sleep "$POLL_INTERVAL"
done

# --- Collect report ---

echo "[Shannon] Collecting report..." >&2

# Look for report in common Shannon output locations
REPORT_FILE=""
AUDIT_LOGS_DIR="$SHANNON_PATH/audit-logs"

for candidate_dir in "$AUDIT_LOGS_DIR" "$SHANNON_PATH/reports" "$SHANNON_PATH/output"; do
    if [[ -d "$candidate_dir" ]]; then
        # Find the most recently modified JSON report file
        latest="$(find "$candidate_dir" -maxdepth 2 -name '*.json' -newer "$OUTPUT_DIR" -type f 2>/dev/null | head -1 || true)"
        if [[ -z "$latest" ]]; then
            # Fallback: find any JSON file containing the workflow ID or repo name
            latest="$(find "$candidate_dir" -maxdepth 2 -name '*.json' -type f -print0 2>/dev/null | xargs -0 grep -l "$REPO_NAME" 2>/dev/null | head -1 || true)"
        fi
        if [[ -z "$latest" ]]; then
            # Fallback: most recently modified JSON in the directory
            latest="$(find "$candidate_dir" -maxdepth 2 -name '*.json' -type f -print 2>/dev/null | while read -r f; do echo "$(stat -f '%m' "$f" 2>/dev/null || stat -c '%Y' "$f" 2>/dev/null || echo 0) $f"; done | sort -rn | head -1 | awk '{print $2}' || true)"
        fi
        if [[ -n "$latest" ]]; then
            REPORT_FILE="$latest"
            break
        fi
    fi
done

if [[ -z "$REPORT_FILE" ]]; then
    echo "Warning: Could not locate Shannon report file in expected directories." >&2
    echo "Check Shannon's audit-logs/ directory manually." >&2

    # Try to extract report path from the query output
    REPORT_FILE="$(echo "$query_output" | grep -oE '/[^ ]*\.json' | head -1 || true)"
    if [[ -z "$REPORT_FILE" ]] || [[ ! -f "$REPORT_FILE" ]]; then
        echo "Error: No report file found." >&2
        exit 1
    fi
fi

# Copy report to output directory
DEST_REPORT="$OUTPUT_DIR/shannon-report-$(date +%Y%m%d-%H%M%S).json"
cp "$REPORT_FILE" "$DEST_REPORT"

echo "[Shannon] Report saved to: $DEST_REPORT" >&2

# Output the report path to stdout
echo "$DEST_REPORT"
