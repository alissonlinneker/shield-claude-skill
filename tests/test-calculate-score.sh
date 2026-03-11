#!/usr/bin/env bash
set -uo pipefail

# Tests for scripts/calculate-score.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALCULATE_SCORE="$SCRIPT_DIR/../scripts/calculate-score.sh"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

source "$SCRIPT_DIR/test-helpers.sh"

echo "  Testing: calculate-score.sh"

# Ensure the script exists and is executable
if [[ ! -f "$CALCULATE_SCORE" ]]; then
    echo "  ERROR: calculate-score.sh not found at $CALCULATE_SCORE"
    exit 1
fi
chmod +x "$CALCULATE_SCORE"

# Check jq dependency (calculate-score.sh requires it)
if ! command -v jq >/dev/null 2>&1; then
    echo "  SKIP: jq is not installed (required by calculate-score.sh)"
    echo ""
    echo "========================================="
    echo "  Total: 0  |  Passed: 0  |  Failed: 0"
    echo "  SKIPPED (jq not available)"
    echo "========================================="
    exit 0
fi

# ============================================================
# Helper: Create consolidated JSON with specific finding counts
# ============================================================
make_findings_json() {
    local critical="${1:-0}"
    local high="${2:-0}"
    local medium="${3:-0}"
    local low="${4:-0}"

    local findings="["
    local id=1
    local first=true
    local i

    i=0; while [[ $i -lt $critical ]]; do
        [[ "$first" == "true" ]] && first=false || findings+=","
        findings+=$(printf '{"id":"SHIELD-%03d","severity":"CRITICAL","title":"Critical %d","source_tool":"test","file":"c%d.js","line":%d,"status":"confirmed"}' "$id" "$id" "$id" "$id")
        id=$((id + 1)); i=$((i + 1))
    done
    i=0; while [[ $i -lt $high ]]; do
        [[ "$first" == "true" ]] && first=false || findings+=","
        findings+=$(printf '{"id":"SHIELD-%03d","severity":"HIGH","title":"High %d","source_tool":"test","file":"h%d.js","line":%d,"status":"confirmed"}' "$id" "$id" "$id" "$id")
        id=$((id + 1)); i=$((i + 1))
    done
    i=0; while [[ $i -lt $medium ]]; do
        [[ "$first" == "true" ]] && first=false || findings+=","
        findings+=$(printf '{"id":"SHIELD-%03d","severity":"MEDIUM","title":"Medium %d","source_tool":"test","file":"m%d.js","line":%d,"status":"confirmed"}' "$id" "$id" "$id" "$id")
        id=$((id + 1)); i=$((i + 1))
    done
    i=0; while [[ $i -lt $low ]]; do
        [[ "$first" == "true" ]] && first=false || findings+=","
        findings+=$(printf '{"id":"SHIELD-%03d","severity":"LOW","title":"Low %d","source_tool":"test","file":"l%d.js","line":%d,"status":"confirmed"}' "$id" "$id" "$id" "$id")
        id=$((id + 1)); i=$((i + 1))
    done

    findings+="]"
    local total=$((critical + high + medium + low))

    printf '{"findings":%s,"summary":{"total":%d,"by_severity":{"critical":%d,"high":%d,"medium":%d,"low":%d}}}' \
        "$findings" "$total" "$critical" "$high" "$medium" "$low"
}

# ============================================================
# Test: Perfect score (no findings) = 100
# ============================================================
test_perfect_score() {
    setup_test_dir
    local input
    input="$(make_findings_json 0 0 0 0)"
    echo "$input" > "$TEST_TEMP_DIR/perfect.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/perfect.json")"

    assert_valid_json "$output" "perfect: output is valid JSON"
    assert_json_value "$output" "score" "100" "perfect: score is 100"
    assert_json_value "$output" "risk_level" "LOW" "perfect: risk level is LOW"
    assert_json_value "$output" "total_findings" "0" "perfect: total findings is 0"

    teardown_test_dir
}

# ============================================================
# Test: 1 CRITICAL = 100 - 15 = 85
# ============================================================
test_one_critical() {
    setup_test_dir
    local input
    input="$(make_findings_json 1 0 0 0)"
    echo "$input" > "$TEST_TEMP_DIR/one-crit.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/one-crit.json")"

    assert_valid_json "$output" "one_critical: output is valid JSON"
    assert_json_value "$output" "score" "85" "one_critical: score is 85"
    assert_json_value "$output" "risk_level" "MEDIUM" "one_critical: risk level is MEDIUM"
    assert_json_value "$output" "breakdown.critical.count" "1" "one_critical: critical count is 1"
    assert_json_value "$output" "breakdown.critical.deduction" "15" "one_critical: critical deduction is 15"

    teardown_test_dir
}

# ============================================================
# Test: Mixed severities
# ============================================================
test_mixed_severities() {
    setup_test_dir
    # 2 CRITICAL (-30) + 2 HIGH (-16) + 1 MEDIUM (-3) + 1 LOW (-1) = -50
    # Score = 100 - 50 = 50
    local input
    input="$(make_findings_json 2 2 1 1)"
    echo "$input" > "$TEST_TEMP_DIR/mixed.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/mixed.json")"

    assert_valid_json "$output" "mixed: output is valid JSON"
    assert_json_value "$output" "score" "50" "mixed: score is 50 (2C+2H+1M+1L)"
    assert_json_value "$output" "risk_level" "HIGH" "mixed: risk level is HIGH"
    assert_json_value "$output" "total_deduction" "50" "mixed: total deduction is 50"
    assert_json_value "$output" "total_findings" "6" "mixed: total findings is 6"

    teardown_test_dir
}

# ============================================================
# Test: Minimum score is 0 (many findings)
# ============================================================
test_minimum_score() {
    setup_test_dir
    # 10 CRITICAL = -150, should clamp to 0
    local input
    input="$(make_findings_json 10 0 0 0)"
    echo "$input" > "$TEST_TEMP_DIR/many.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/many.json")"

    assert_valid_json "$output" "minimum: output is valid JSON"
    assert_json_value "$output" "score" "0" "minimum: score is clamped to 0"
    assert_json_value "$output" "risk_level" "CRITICAL" "minimum: risk level is CRITICAL"

    teardown_test_dir
}

# ============================================================
# Test: Risk threshold - LOW (90-100)
# ============================================================
test_risk_level_low() {
    setup_test_dir
    # 1 MEDIUM (-3) + 1 LOW (-1) = -4, score = 96
    local input
    input="$(make_findings_json 0 0 1 1)"
    echo "$input" > "$TEST_TEMP_DIR/low-risk.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/low-risk.json")"

    assert_json_value "$output" "score" "96" "low_risk: score is 96"
    assert_json_value "$output" "risk_level" "LOW" "low_risk: risk level is LOW"

    teardown_test_dir
}

# ============================================================
# Test: Risk threshold - MEDIUM (70-89)
# ============================================================
test_risk_level_medium() {
    setup_test_dir
    # 1 HIGH (-8) + 1 MEDIUM (-3) = -11, score = 89
    local input
    input="$(make_findings_json 0 1 1 0)"
    echo "$input" > "$TEST_TEMP_DIR/med-risk.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/med-risk.json")"

    assert_json_value "$output" "score" "89" "medium_risk: score is 89"
    assert_json_value "$output" "risk_level" "MEDIUM" "medium_risk: risk level is MEDIUM"

    teardown_test_dir
}

# ============================================================
# Test: Risk threshold - exactly 90 is LOW
# ============================================================
test_risk_level_boundary_90() {
    setup_test_dir
    # 10 LOW = -10, score = 90
    local input
    input="$(make_findings_json 0 0 0 10)"
    echo "$input" > "$TEST_TEMP_DIR/boundary90.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/boundary90.json")"

    assert_json_value "$output" "score" "90" "boundary_90: score is 90"
    assert_json_value "$output" "risk_level" "LOW" "boundary_90: 90 is still LOW risk"

    teardown_test_dir
}

# ============================================================
# Test: Risk threshold - exactly 70 is MEDIUM
# ============================================================
test_risk_level_boundary_70() {
    setup_test_dir
    # 2 CRITICAL (-30) = score 70
    local input
    input="$(make_findings_json 2 0 0 0)"
    echo "$input" > "$TEST_TEMP_DIR/boundary70.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/boundary70.json")"

    assert_json_value "$output" "score" "70" "boundary_70: score is 70"
    assert_json_value "$output" "risk_level" "MEDIUM" "boundary_70: 70 is MEDIUM risk"

    teardown_test_dir
}

# ============================================================
# Test: Risk threshold - exactly 40 is HIGH
# ============================================================
test_risk_level_boundary_40() {
    setup_test_dir
    # 4 CRITICAL (-60) = score 40
    local input
    input="$(make_findings_json 4 0 0 0)"
    echo "$input" > "$TEST_TEMP_DIR/boundary40.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/boundary40.json")"

    assert_json_value "$output" "score" "40" "boundary_40: score is 40"
    assert_json_value "$output" "risk_level" "HIGH" "boundary_40: 40 is HIGH risk"

    teardown_test_dir
}

# ============================================================
# Test: Risk threshold - 39 is CRITICAL
# ============================================================
test_risk_level_critical() {
    setup_test_dir
    # 4 CRITICAL (-60) + 1 LOW (-1) = -61, score = 39
    local input
    input="$(make_findings_json 4 0 0 1)"
    echo "$input" > "$TEST_TEMP_DIR/crit-risk.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/crit-risk.json")"

    assert_json_value "$output" "score" "39" "critical_risk: score is 39"
    assert_json_value "$output" "risk_level" "CRITICAL" "critical_risk: 39 is CRITICAL risk"

    teardown_test_dir
}

# ============================================================
# Test: JSON output format has all expected keys
# ============================================================
test_output_format() {
    setup_test_dir
    local input
    input="$(make_findings_json 1 1 1 1)"
    echo "$input" > "$TEST_TEMP_DIR/format.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/format.json")"

    assert_json_key "$output" "score" "format: has score key"
    assert_json_key "$output" "max_score" "format: has max_score key"
    assert_json_key "$output" "risk_level" "format: has risk_level key"
    assert_json_key "$output" "breakdown" "format: has breakdown key"
    assert_json_key "$output" "total_deduction" "format: has total_deduction key"
    assert_json_key "$output" "total_findings" "format: has total_findings key"
    assert_json_value "$output" "max_score" "100" "format: max_score is 100"

    teardown_test_dir
}

# ============================================================
# Test: Breakdown values are correct
# ============================================================
test_breakdown_values() {
    setup_test_dir
    # 1C=15, 2H=16, 3M=9, 4L=4 -> total_ded=44, score=56
    local input
    input="$(make_findings_json 1 2 3 4)"
    echo "$input" > "$TEST_TEMP_DIR/breakdown.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/breakdown.json")"

    assert_json_value "$output" "breakdown.critical.count" "1" "breakdown: critical count"
    assert_json_value "$output" "breakdown.critical.weight" "15" "breakdown: critical weight"
    assert_json_value "$output" "breakdown.critical.deduction" "15" "breakdown: critical deduction"

    assert_json_value "$output" "breakdown.high.count" "2" "breakdown: high count"
    assert_json_value "$output" "breakdown.high.weight" "8" "breakdown: high weight"
    assert_json_value "$output" "breakdown.high.deduction" "16" "breakdown: high deduction"

    assert_json_value "$output" "breakdown.medium.count" "3" "breakdown: medium count"
    assert_json_value "$output" "breakdown.medium.weight" "3" "breakdown: medium weight"
    assert_json_value "$output" "breakdown.medium.deduction" "9" "breakdown: medium deduction"

    assert_json_value "$output" "breakdown.low.count" "4" "breakdown: low count"
    assert_json_value "$output" "breakdown.low.weight" "1" "breakdown: low weight"
    assert_json_value "$output" "breakdown.low.deduction" "4" "breakdown: low deduction"

    assert_json_value "$output" "total_deduction" "44" "breakdown: total deduction is 44"
    assert_json_value "$output" "score" "56" "breakdown: score is 56"
    assert_json_value "$output" "total_findings" "10" "breakdown: total findings is 10"

    teardown_test_dir
}

# ============================================================
# Test: stdin input mode (pipe)
# ============================================================
test_stdin_input() {
    local input
    input="$(make_findings_json 0 1 0 0)"

    local output
    output="$(echo "$input" | bash "$CALCULATE_SCORE")"

    assert_valid_json "$output" "stdin: output is valid JSON"
    assert_json_value "$output" "score" "92" "stdin: score is 92 (1 HIGH)"

    teardown_test_dir
}

# ============================================================
# Test: With fixture consolidated-output.json
# ============================================================
test_with_fixture() {
    local fixture_file="$FIXTURES_DIR/consolidated-output.json"
    if [[ ! -f "$fixture_file" ]]; then
        _fail "fixture: consolidated-output.json not found"
        return
    fi

    local output
    output="$(bash "$CALCULATE_SCORE" "$fixture_file")"

    # From fixture: 2 CRITICAL (-30) + 2 HIGH (-16) + 1 MEDIUM (-3) + 1 LOW (-1) = -50
    # Score = 100 - 50 = 50
    assert_valid_json "$output" "fixture: output is valid JSON"
    assert_json_value "$output" "score" "50" "fixture: score is 50"
    assert_json_value "$output" "risk_level" "HIGH" "fixture: risk level is HIGH"
    assert_json_value "$output" "total_findings" "6" "fixture: total findings is 6"
}

# ============================================================
# Test: Invalid JSON input
# ============================================================
test_invalid_json() {
    setup_test_dir
    echo "this is not json" > "$TEST_TEMP_DIR/bad.json"

    local exit_code=0
    bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/bad.json" 2>/dev/null || exit_code=$?
    assert_equals "1" "$exit_code" "invalid_json: exits with code 1 for bad JSON"

    teardown_test_dir
}

# ============================================================
# Test: Non-file argument falls through to stdin, invalid stdin fails
# ============================================================
test_invalid_stdin() {
    local exit_code=0
    echo "NOT JSON AT ALL {{{" | bash "$CALCULATE_SCORE" 2>/dev/null || exit_code=$?
    assert_equals "1" "$exit_code" "invalid_stdin: exits with code 1 for invalid JSON on stdin"
}

# ============================================================
# Test: Only HIGH findings
# ============================================================
test_only_high() {
    setup_test_dir
    # 3 HIGH = -24, score = 76
    local input
    input="$(make_findings_json 0 3 0 0)"
    echo "$input" > "$TEST_TEMP_DIR/high-only.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/high-only.json")"

    assert_json_value "$output" "score" "76" "only_high: score is 76"
    assert_json_value "$output" "risk_level" "MEDIUM" "only_high: risk level is MEDIUM"

    teardown_test_dir
}

# ============================================================
# Test: Only LOW findings
# ============================================================
test_only_low() {
    setup_test_dir
    # 5 LOW = -5, score = 95
    local input
    input="$(make_findings_json 0 0 0 5)"
    echo "$input" > "$TEST_TEMP_DIR/low-only.json"

    local output
    output="$(bash "$CALCULATE_SCORE" "$TEST_TEMP_DIR/low-only.json")"

    assert_json_value "$output" "score" "95" "only_low: score is 95"
    assert_json_value "$output" "risk_level" "LOW" "only_low: risk level is LOW"

    teardown_test_dir
}

# --- Run all tests ---

test_perfect_score
test_one_critical
test_mixed_severities
test_minimum_score
test_risk_level_low
test_risk_level_medium
test_risk_level_boundary_90
test_risk_level_boundary_70
test_risk_level_boundary_40
test_risk_level_critical
test_output_format
test_breakdown_values
test_stdin_input
test_with_fixture
test_invalid_json
test_invalid_stdin
test_only_high
test_only_low

print_summary
