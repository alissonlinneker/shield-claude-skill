#!/usr/bin/env bash
set -uo pipefail

# Tests for scripts/consolidate.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSOLIDATE="$SCRIPT_DIR/../scripts/consolidate.sh"

source "$SCRIPT_DIR/test-helpers.sh"

echo "  Testing: consolidate.sh"

# Ensure the script exists and is executable
if [[ ! -f "$CONSOLIDATE" ]]; then
    echo "  ERROR: consolidate.sh not found at $CONSOLIDATE"
    exit 1
fi
chmod +x "$CONSOLIDATE"

# Check jq dependency (consolidate.sh requires it)
if ! command -v jq >/dev/null 2>&1; then
    echo "  SKIP: jq is not installed (required by consolidate.sh)"
    echo ""
    echo "========================================="
    echo "  Total: 0  |  Passed: 0  |  Failed: 0"
    echo "  SKIPPED (jq not available)"
    echo "========================================="
    exit 0
fi

# ============================================================
# Helper: Create a tool output JSON file in the expected format
# ============================================================
create_tool_output() {
    local file="$1"
    local tool="$2"
    local findings_json="$3"

    cat > "$file" <<EOF
{
  "tool": "$tool",
  "findings": $findings_json
}
EOF
}

# ============================================================
# Test: Consolidation with all three tool outputs
# ============================================================
test_full_consolidation() {
    setup_test_dir

    # Create mock semgrep output
    create_tool_output "$TEST_TEMP_DIR/semgrep.json" "semgrep" '[
        {
            "id": "SG-001",
            "severity": "CRITICAL",
            "title": "SQL Injection in UserRepository",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
            "source_tool": "semgrep",
            "file": "src/db/users.js",
            "line": 23,
            "evidence": "db.query(user_input)",
            "status": "confirmed"
        },
        {
            "id": "SG-002",
            "severity": "MEDIUM",
            "title": "Cross-site scripting vulnerability",
            "cwe": "CWE-79",
            "owasp": "A03:2021",
            "source_tool": "semgrep",
            "file": "src/views/profile.js",
            "line": 15,
            "evidence": "innerHTML = input",
            "status": "confirmed"
        }
    ]'

    # Create mock gitleaks output
    create_tool_output "$TEST_TEMP_DIR/gitleaks.json" "gitleaks" '[
        {
            "severity": "CRITICAL",
            "title": "AWS Access Key",
            "cwe": "CWE-798",
            "owasp": "A07:2021",
            "source_tool": "gitleaks",
            "file": "src/config/aws.js",
            "line": 5,
            "evidence": "aws_access_key_id = AKIA...",
            "status": "confirmed"
        }
    ]'

    # Create mock npm-audit output
    create_tool_output "$TEST_TEMP_DIR/npm-audit.json" "npm-audit" '[
        {
            "severity": "HIGH",
            "title": "Prototype Pollution in lodash",
            "cwe": "CWE-1321",
            "owasp": "A06:2021",
            "source_tool": "npm-audit",
            "file": "package.json",
            "line": 0,
            "evidence": "lodash < 4.17.21",
            "status": "confirmed"
        }
    ]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/semgrep.json" "$TEST_TEMP_DIR/gitleaks.json" "$TEST_TEMP_DIR/npm-audit.json" 2>/dev/null)"

    assert_valid_json "$output" "full: output is valid JSON"
    assert_json_key "$output" "findings" "full: has findings key"
    assert_json_key "$output" "summary" "full: has summary key"
    assert_json_key "$output" "metadata" "full: has metadata key"

    # Check total count
    assert_json_value "$output" "summary.total" "4" "full: total findings is 4"

    # Check severity counts
    assert_json_value "$output" "summary.by_severity.critical" "2" "full: 2 critical findings"
    assert_json_value "$output" "summary.by_severity.high" "1" "full: 1 high finding"
    assert_json_value "$output" "summary.by_severity.medium" "1" "full: 1 medium finding"

    teardown_test_dir
}

# ============================================================
# Test: Severity sorting (CRITICAL first)
# ============================================================
test_severity_sorting() {
    setup_test_dir

    # Create findings with mixed severities (LOW first intentionally)
    create_tool_output "$TEST_TEMP_DIR/mixed.json" "test-tool" '[
        {
            "severity": "LOW",
            "title": "Low finding",
            "source_tool": "test",
            "file": "a.js",
            "line": 1,
            "status": "confirmed"
        },
        {
            "severity": "CRITICAL",
            "title": "Critical finding",
            "source_tool": "test",
            "file": "b.js",
            "line": 2,
            "status": "confirmed"
        },
        {
            "severity": "HIGH",
            "title": "High finding",
            "source_tool": "test",
            "file": "c.js",
            "line": 3,
            "status": "confirmed"
        },
        {
            "severity": "MEDIUM",
            "title": "Medium finding",
            "source_tool": "test",
            "file": "d.js",
            "line": 4,
            "status": "confirmed"
        }
    ]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/mixed.json" 2>/dev/null)"

    # First finding should be CRITICAL
    assert_json_value "$output" "findings.0.severity" "CRITICAL" "sorting: first finding is CRITICAL"

    # Second should be HIGH
    assert_json_value "$output" "findings.1.severity" "HIGH" "sorting: second finding is HIGH"

    # Third should be MEDIUM
    assert_json_value "$output" "findings.2.severity" "MEDIUM" "sorting: third finding is MEDIUM"

    # Fourth should be LOW
    assert_json_value "$output" "findings.3.severity" "LOW" "sorting: fourth finding is LOW"

    teardown_test_dir
}

# ============================================================
# Test: SHIELD-XXX ID assignment is sequential
# ============================================================
test_sequential_ids() {
    setup_test_dir

    create_tool_output "$TEST_TEMP_DIR/multi.json" "test-tool" '[
        {
            "severity": "HIGH",
            "title": "First finding",
            "source_tool": "test",
            "file": "a.js",
            "line": 1,
            "status": "confirmed"
        },
        {
            "severity": "HIGH",
            "title": "Second finding",
            "source_tool": "test",
            "file": "b.js",
            "line": 2,
            "status": "confirmed"
        },
        {
            "severity": "MEDIUM",
            "title": "Third finding",
            "source_tool": "test",
            "file": "c.js",
            "line": 3,
            "status": "confirmed"
        }
    ]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/multi.json" 2>/dev/null)"

    assert_json_value "$output" "findings.0.id" "SHIELD-001" "ids: first finding is SHIELD-001"
    assert_json_value "$output" "findings.1.id" "SHIELD-002" "ids: second finding is SHIELD-002"
    assert_json_value "$output" "findings.2.id" "SHIELD-003" "ids: third finding is SHIELD-003"

    teardown_test_dir
}

# ============================================================
# Test: Deduplication (same file + line + tool + title = merge)
# ============================================================
test_deduplication() {
    setup_test_dir

    # Two files with the same finding (same file, line, tool, title)
    create_tool_output "$TEST_TEMP_DIR/dup1.json" "semgrep" '[
        {
            "severity": "HIGH",
            "title": "SQL Injection",
            "source_tool": "semgrep",
            "file": "src/db.js",
            "line": 10,
            "status": "confirmed"
        }
    ]'

    create_tool_output "$TEST_TEMP_DIR/dup2.json" "semgrep" '[
        {
            "severity": "HIGH",
            "title": "SQL Injection",
            "source_tool": "semgrep",
            "file": "src/db.js",
            "line": 10,
            "status": "confirmed"
        }
    ]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/dup1.json" "$TEST_TEMP_DIR/dup2.json" 2>/dev/null)"

    assert_json_value "$output" "summary.total" "1" "dedup: duplicate finding consolidated to 1"

    teardown_test_dir
}

# ============================================================
# Test: No dedup for same file+line but different tool
# ============================================================
test_no_false_dedup() {
    setup_test_dir

    create_tool_output "$TEST_TEMP_DIR/tool1.json" "semgrep" '[
        {
            "severity": "HIGH",
            "title": "SQL Injection",
            "source_tool": "semgrep",
            "file": "src/db.js",
            "line": 10,
            "status": "confirmed"
        }
    ]'

    create_tool_output "$TEST_TEMP_DIR/tool2.json" "shannon" '[
        {
            "severity": "HIGH",
            "title": "SQL Injection",
            "source_tool": "shannon",
            "file": "src/db.js",
            "line": 10,
            "status": "confirmed"
        }
    ]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/tool1.json" "$TEST_TEMP_DIR/tool2.json" 2>/dev/null)"

    assert_json_value "$output" "summary.total" "2" "no_false_dedup: different tools keep separate findings"

    teardown_test_dir
}

# ============================================================
# Test: Single tool output
# ============================================================
test_single_tool() {
    setup_test_dir

    create_tool_output "$TEST_TEMP_DIR/single.json" "gitleaks" '[
        {
            "severity": "CRITICAL",
            "title": "Hardcoded API Key",
            "source_tool": "gitleaks",
            "file": ".env",
            "line": 3,
            "status": "confirmed"
        }
    ]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/single.json" 2>/dev/null)"

    assert_valid_json "$output" "single_tool: output is valid JSON"
    assert_json_value "$output" "summary.total" "1" "single_tool: total is 1"
    assert_json_value "$output" "summary.by_severity.critical" "1" "single_tool: 1 critical"
    assert_json_value "$output" "findings.0.id" "SHIELD-001" "single_tool: first ID is SHIELD-001"

    teardown_test_dir
}

# ============================================================
# Test: Empty findings
# ============================================================
test_empty_findings() {
    setup_test_dir

    create_tool_output "$TEST_TEMP_DIR/empty.json" "semgrep" '[]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/empty.json" 2>/dev/null)"

    assert_valid_json "$output" "empty: output is valid JSON"
    assert_json_value "$output" "summary.total" "0" "empty: total is 0"
    assert_json_value "$output" "summary.by_severity.critical" "0" "empty: 0 critical"
    assert_json_value "$output" "summary.by_severity.high" "0" "empty: 0 high"
    assert_json_value "$output" "summary.by_severity.medium" "0" "empty: 0 medium"
    assert_json_value "$output" "summary.by_severity.low" "0" "empty: 0 low"

    teardown_test_dir
}

# ============================================================
# Test: No arguments exits with error
# ============================================================
test_no_args() {
    local exit_code=0
    bash "$CONSOLIDATE" 2>/dev/null || exit_code=$?
    assert_equals "1" "$exit_code" "no_args: exits with code 1 when no files given"
}

# ============================================================
# Test: Invalid JSON file is skipped with warning
# ============================================================
test_invalid_json_skipped() {
    setup_test_dir

    echo "this is not json" > "$TEST_TEMP_DIR/bad.json"
    create_tool_output "$TEST_TEMP_DIR/good.json" "semgrep" '[
        {
            "severity": "LOW",
            "title": "Minor issue",
            "source_tool": "semgrep",
            "file": "x.js",
            "line": 1,
            "status": "confirmed"
        }
    ]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/bad.json" "$TEST_TEMP_DIR/good.json" 2>/dev/null)"

    assert_valid_json "$output" "invalid_json: output is still valid JSON"
    assert_json_value "$output" "summary.total" "1" "invalid_json: valid file findings preserved"

    teardown_test_dir
}

# ============================================================
# Test: Metadata contains scan_date
# ============================================================
test_metadata_scan_date() {
    setup_test_dir

    create_tool_output "$TEST_TEMP_DIR/meta.json" "test" '[
        {
            "severity": "LOW",
            "title": "Test",
            "source_tool": "test",
            "file": "a.js",
            "line": 1,
            "status": "confirmed"
        }
    ]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/meta.json" 2>/dev/null)"

    assert_json_key "$output" "metadata.scan_date" "metadata: has scan_date"
    assert_json_key "$output" "metadata.tools_used" "metadata: has tools_used"

    teardown_test_dir
}

# ============================================================
# Test: tools_used reflects input tools
# ============================================================
test_tools_used_list() {
    setup_test_dir

    create_tool_output "$TEST_TEMP_DIR/sg.json" "semgrep" '[
        {"severity":"LOW","title":"A","source_tool":"semgrep","file":"a.js","line":1,"status":"confirmed"}
    ]'
    create_tool_output "$TEST_TEMP_DIR/gl.json" "gitleaks" '[
        {"severity":"LOW","title":"B","source_tool":"gitleaks","file":"b.js","line":1,"status":"confirmed"}
    ]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/sg.json" "$TEST_TEMP_DIR/gl.json" 2>/dev/null)"

    assert_json_array_contains "$output" "metadata.tools_used" "semgrep" "tools_used: includes semgrep"
    assert_json_array_contains "$output" "metadata.tools_used" "gitleaks" "tools_used: includes gitleaks"

    teardown_test_dir
}

# ============================================================
# Test: by_tool summary counts
# ============================================================
test_by_tool_summary() {
    setup_test_dir

    create_tool_output "$TEST_TEMP_DIR/all.json" "mixed" '[
        {"severity":"CRITICAL","title":"A","source_tool":"semgrep","file":"a.js","line":1,"status":"confirmed"},
        {"severity":"HIGH","title":"B","source_tool":"semgrep","file":"b.js","line":2,"status":"confirmed"},
        {"severity":"LOW","title":"C","source_tool":"gitleaks","file":"c.js","line":3,"status":"confirmed"}
    ]'

    local output
    output="$(bash "$CONSOLIDATE" "$TEST_TEMP_DIR/all.json" 2>/dev/null)"

    assert_json_value "$output" "summary.by_tool.semgrep" "2" "by_tool: semgrep has 2 findings"
    assert_json_value "$output" "summary.by_tool.gitleaks" "1" "by_tool: gitleaks has 1 finding"

    teardown_test_dir
}

# --- Run all tests ---

test_full_consolidation
test_severity_sorting
test_sequential_ids
test_deduplication
test_no_false_dedup
test_single_tool
test_empty_findings
test_no_args
test_invalid_json_skipped
test_metadata_scan_date
test_tools_used_list
test_by_tool_summary

print_summary
