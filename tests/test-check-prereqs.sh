#!/usr/bin/env bash
set -uo pipefail

# Tests for scripts/check-prereqs.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK_PREREQS="$SCRIPT_DIR/../scripts/check-prereqs.sh"

source "$SCRIPT_DIR/test-helpers.sh"

echo "  Testing: check-prereqs.sh"

# Ensure the script exists and is executable
if [[ ! -f "$CHECK_PREREQS" ]]; then
    echo "  ERROR: check-prereqs.sh not found at $CHECK_PREREQS"
    exit 1
fi
chmod +x "$CHECK_PREREQS"

# ============================================================
# Test: Output is valid JSON
# ============================================================
test_valid_json_output() {
    local output
    output="$(bash "$CHECK_PREREQS")"

    assert_valid_json "$output" "prereqs: output is valid JSON"
}

# ============================================================
# Test: All expected top-level keys present
# ============================================================
test_expected_keys() {
    local output
    output="$(bash "$CHECK_PREREQS")"

    assert_json_key "$output" "docker" "prereqs: has 'docker' key"
    assert_json_key "$output" "shannon" "prereqs: has 'shannon' key"
    assert_json_key "$output" "semgrep" "prereqs: has 'semgrep' key"
    assert_json_key "$output" "gitleaks" "prereqs: has 'gitleaks' key"
    assert_json_key "$output" "npm_audit" "prereqs: has 'npm_audit' key"
    assert_json_key "$output" "pip_audit" "prereqs: has 'pip_audit' key"
    assert_json_key "$output" "composer_audit" "prereqs: has 'composer_audit' key"
}

# ============================================================
# Test: Each tool entry has 'available' boolean key
# ============================================================
test_available_key_present() {
    local output
    output="$(bash "$CHECK_PREREQS")"

    local tools=("docker" "shannon" "semgrep" "gitleaks" "npm_audit" "pip_audit" "composer_audit")
    for tool in "${tools[@]}"; do
        assert_json_key "$output" "${tool}.available" "prereqs: ${tool} has 'available' key"
    done
}

# ============================================================
# Test: Available tools have version or path info
# ============================================================
test_available_tools_have_version() {
    local output
    output="$(bash "$CHECK_PREREQS")"

    # Docker: if available, should have version
    if command -v docker >/dev/null 2>&1; then
        assert_json_value "$output" "docker.available" "true" "prereqs: docker shows as available"
        assert_json_key "$output" "docker.version" "prereqs: docker has version when available"
    else
        assert_json_value "$output" "docker.available" "false" "prereqs: docker shows as unavailable"
    fi

    # npm (via npm_audit): if available, should show available
    if command -v npm >/dev/null 2>&1; then
        assert_json_value "$output" "npm_audit.available" "true" "prereqs: npm_audit shows as available"
    else
        assert_json_value "$output" "npm_audit.available" "false" "prereqs: npm_audit shows as unavailable"
    fi

    # semgrep
    if command -v semgrep >/dev/null 2>&1; then
        assert_json_value "$output" "semgrep.available" "true" "prereqs: semgrep shows as available"
        assert_json_key "$output" "semgrep.version" "prereqs: semgrep has version when available"
    else
        assert_json_value "$output" "semgrep.available" "false" "prereqs: semgrep shows as unavailable"
    fi

    # gitleaks
    if command -v gitleaks >/dev/null 2>&1; then
        assert_json_value "$output" "gitleaks.available" "true" "prereqs: gitleaks shows as available"
        assert_json_key "$output" "gitleaks.version" "prereqs: gitleaks has version when available"
    else
        assert_json_value "$output" "gitleaks.available" "false" "prereqs: gitleaks shows as unavailable"
    fi
}

# ============================================================
# Test: Unavailable tools have install instructions
# ============================================================
test_missing_tools_have_install_hint() {
    local output
    output="$(bash "$CHECK_PREREQS")"

    # Shannon is likely not installed in most environments
    local shannon_available
    shannon_available="$(python3 -c "
import json, sys
data = json.loads(sys.argv[1])
print(str(data.get('shannon', {}).get('available', False)).lower())
" "$output" 2>/dev/null)" || true

    if [[ "$shannon_available" == "false" ]]; then
        assert_json_key "$output" "shannon.install" "prereqs: shannon has install hint when unavailable"
    fi

    # pip-audit is also commonly missing
    if ! command -v pip-audit >/dev/null 2>&1; then
        assert_json_key "$output" "pip_audit.install" "prereqs: pip_audit has install hint when unavailable"
    fi

    # composer is commonly missing on non-PHP systems
    if ! command -v composer >/dev/null 2>&1; then
        assert_json_key "$output" "composer_audit.install" "prereqs: composer_audit has install hint when unavailable"
    fi
}

# ============================================================
# Test: Script exits successfully
# ============================================================
test_exit_code() {
    local exit_code=0
    bash "$CHECK_PREREQS" >/dev/null 2>&1 || exit_code=$?
    assert_equals "0" "$exit_code" "prereqs: exits with code 0"
}

# ============================================================
# Test: Output does not contain raw error messages
# ============================================================
test_no_stderr_in_stdout() {
    local output
    output="$(bash "$CHECK_PREREQS" 2>/dev/null)"

    # Should not contain common error patterns in stdout
    assert_not_contains "$output" "command not found" "prereqs: no 'command not found' in stdout"
    assert_not_contains "$output" "Error:" "prereqs: no 'Error:' in stdout"
    assert_not_contains "$output" "Permission denied" "prereqs: no 'Permission denied' in stdout"
}

# ============================================================
# Test: Docker version format (when available)
# ============================================================
test_docker_version_format() {
    if ! command -v docker >/dev/null 2>&1; then
        _pass "prereqs: docker version format (skipped: docker not installed)"
        return
    fi

    local output
    output="$(bash "$CHECK_PREREQS")"

    local version
    version="$(python3 -c "
import json, sys
data = json.loads(sys.argv[1])
print(data.get('docker', {}).get('version', ''))
" "$output" 2>/dev/null)" || true

    # Docker version should contain at least a number
    if [[ "$version" =~ [0-9] ]]; then
        _pass "prereqs: docker version contains a version number"
    else
        _fail "prereqs: docker version contains a version number" "got: '$version'"
    fi
}

# ============================================================
# Test: Shannon path field (when available)
# ============================================================
test_shannon_path_field() {
    local output
    output="$(bash "$CHECK_PREREQS")"

    local shannon_available
    shannon_available="$(python3 -c "
import json, sys
data = json.loads(sys.argv[1])
print(str(data.get('shannon', {}).get('available', False)).lower())
" "$output" 2>/dev/null)" || true

    if [[ "$shannon_available" == "true" ]]; then
        assert_json_key "$output" "shannon.path" "prereqs: shannon has path when available"
    else
        _pass "prereqs: shannon path field (skipped: shannon not available)"
    fi
}

# ============================================================
# Test: Re-running produces consistent output
# ============================================================
test_idempotent_output() {
    local output1 output2
    output1="$(bash "$CHECK_PREREQS" 2>/dev/null)"
    output2="$(bash "$CHECK_PREREQS" 2>/dev/null)"

    assert_equals "$output1" "$output2" "prereqs: output is consistent across runs"
}

# --- Run all tests ---

test_valid_json_output
test_expected_keys
test_available_key_present
test_available_tools_have_version
test_missing_tools_have_install_hint
test_exit_code
test_no_stderr_in_stdout
test_docker_version_format
test_shannon_path_field
test_idempotent_output

print_summary
