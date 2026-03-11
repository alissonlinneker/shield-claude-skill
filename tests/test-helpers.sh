#!/usr/bin/env bash
# Shared test helper functions for Shield test suite.
# Source this file from each test script.

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# --- Counters ---
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# --- Test Directory Management ---

TEST_TEMP_DIR=""

setup_test_dir() {
    TEST_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shield-test-XXXXXX")"
    export TEST_TEMP_DIR
}

teardown_test_dir() {
    if [[ -n "$TEST_TEMP_DIR" ]] && [[ -d "$TEST_TEMP_DIR" ]]; then
        rm -rf "$TEST_TEMP_DIR"
    fi
    TEST_TEMP_DIR=""
}

# --- Assertion Functions ---

_pass() {
    local name="$1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    printf "${GREEN}  PASS${NC} %s\n" "$name"
}

_fail() {
    local name="$1"
    local detail="${2:-}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    printf "${RED}  FAIL${NC} %s\n" "$name"
    if [[ -n "$detail" ]]; then
        printf "       %s\n" "$detail"
    fi
}

assert_equals() {
    local expected="$1"
    local actual="$2"
    local name="${3:-assert_equals}"

    if [[ "$expected" == "$actual" ]]; then
        _pass "$name"
    else
        _fail "$name" "expected: '$expected', got: '$actual'"
    fi
}

assert_not_equals() {
    local not_expected="$1"
    local actual="$2"
    local name="${3:-assert_not_equals}"

    if [[ "$not_expected" != "$actual" ]]; then
        _pass "$name"
    else
        _fail "$name" "expected NOT '$not_expected', but got it"
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local name="${3:-assert_contains}"

    if [[ "$haystack" == *"$needle"* ]]; then
        _pass "$name"
    else
        _fail "$name" "'$needle' not found in output"
    fi
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local name="${3:-assert_not_contains}"

    if [[ "$haystack" != *"$needle"* ]]; then
        _pass "$name"
    else
        _fail "$name" "'$needle' was found in output but should not be"
    fi
}

assert_json_key() {
    local json="$1"
    local key="$2"
    local name="${3:-assert_json_key}"

    # Use python for robust JSON parsing if available, fallback to grep
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "
import json, sys
data = json.loads(sys.argv[1])
keys = sys.argv[2].split('.')
obj = data
for k in keys:
    if isinstance(obj, dict) and k in obj:
        obj = obj[k]
    else:
        sys.exit(1)
" "$json" "$key" 2>/dev/null; then
            _pass "$name"
        else
            _fail "$name" "key '$key' not found in JSON"
        fi
    else
        # Fallback: simple grep-based check (less robust)
        if echo "$json" | grep -q "\"$key\""; then
            _pass "$name"
        else
            _fail "$name" "key '$key' not found in JSON (grep fallback)"
        fi
    fi
}

assert_json_value() {
    local json="$1"
    local key="$2"
    local expected="$3"
    local name="${4:-assert_json_value}"

    if command -v python3 >/dev/null 2>&1; then
        local actual
        actual="$(python3 -c "
import json, sys
data = json.loads(sys.argv[1])
keys = sys.argv[2].split('.')
obj = data
for k in keys:
    if isinstance(obj, dict) and k in obj:
        obj = obj[k]
    elif isinstance(obj, list):
        obj = obj[int(k)]
    else:
        print('__KEY_NOT_FOUND__')
        sys.exit(0)
val = obj
if isinstance(val, bool):
    print(str(val).lower())
elif val is None:
    print('null')
else:
    print(val)
" "$json" "$key" 2>/dev/null)" || true

        if [[ "$actual" == "__KEY_NOT_FOUND__" ]]; then
            _fail "$name" "key '$key' not found in JSON"
        elif [[ "$actual" == "$expected" ]]; then
            _pass "$name"
        else
            _fail "$name" "key '$key': expected '$expected', got '$actual'"
        fi
    else
        _fail "$name" "python3 not available for JSON parsing"
    fi
}

assert_json_array_contains() {
    local json="$1"
    local key="$2"
    local value="$3"
    local name="${4:-assert_json_array_contains}"

    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "
import json, sys
data = json.loads(sys.argv[1])
keys = sys.argv[2].split('.')
obj = data
for k in keys:
    if isinstance(obj, dict) and k in obj:
        obj = obj[k]
    else:
        sys.exit(1)
if not isinstance(obj, list):
    sys.exit(1)
if sys.argv[3] not in obj:
    sys.exit(1)
" "$json" "$key" "$value" 2>/dev/null; then
            _pass "$name"
        else
            _fail "$name" "'$value' not found in array '$key'"
        fi
    else
        _fail "$name" "python3 not available for JSON parsing"
    fi
}

assert_json_array_length() {
    local json="$1"
    local key="$2"
    local expected_len="$3"
    local name="${4:-assert_json_array_length}"

    if command -v python3 >/dev/null 2>&1; then
        local actual_len
        actual_len="$(python3 -c "
import json, sys
data = json.loads(sys.argv[1])
keys = sys.argv[2].split('.')
obj = data
for k in keys:
    if isinstance(obj, dict) and k in obj:
        obj = obj[k]
    else:
        print(-1)
        sys.exit(0)
print(len(obj) if isinstance(obj, list) else -1)
" "$json" "$key" 2>/dev/null)" || true

        if [[ "$actual_len" == "$expected_len" ]]; then
            _pass "$name"
        else
            _fail "$name" "array '$key': expected length $expected_len, got $actual_len"
        fi
    else
        _fail "$name" "python3 not available for JSON parsing"
    fi
}

assert_exit_code() {
    local expected="$1"
    local actual="$?"
    local name="${2:-assert_exit_code}"

    # If the caller captured the exit code, it must pass it explicitly.
    # This function checks the argument against expected.
    if [[ "$expected" == "$actual" ]]; then
        _pass "$name"
    else
        _fail "$name" "expected exit code $expected, got $actual"
    fi
}

assert_exit_code_of() {
    local expected="$1"
    local name="$2"
    shift 2
    local actual=0
    "$@" >/dev/null 2>&1 || actual=$?

    if [[ "$expected" == "$actual" ]]; then
        _pass "$name"
    else
        _fail "$name" "expected exit code $expected, got $actual"
    fi
}

assert_file_exists() {
    local path="$1"
    local name="${2:-assert_file_exists}"

    if [[ -f "$path" ]]; then
        _pass "$name"
    else
        _fail "$name" "file not found: $path"
    fi
}

assert_file_not_exists() {
    local path="$1"
    local name="${2:-assert_file_not_exists}"

    if [[ ! -f "$path" ]]; then
        _pass "$name"
    else
        _fail "$name" "file should not exist: $path"
    fi
}

assert_dir_exists() {
    local path="$1"
    local name="${2:-assert_dir_exists}"

    if [[ -d "$path" ]]; then
        _pass "$name"
    else
        _fail "$name" "directory not found: $path"
    fi
}

assert_valid_json() {
    local json="$1"
    local name="${2:-assert_valid_json}"

    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "import json, sys; json.loads(sys.argv[1])" "$json" 2>/dev/null; then
            _pass "$name"
        else
            _fail "$name" "invalid JSON"
        fi
    else
        _fail "$name" "python3 not available for JSON validation"
    fi
}

# --- Summary ---

print_summary() {
    echo ""
    echo "========================================="
    printf "  Total: %d  |  " "$TESTS_TOTAL"
    printf "${GREEN}Passed: %d${NC}  |  " "$TESTS_PASSED"
    printf "${RED}Failed: %d${NC}\n" "$TESTS_FAILED"
    echo "========================================="

    if [[ "$TESTS_FAILED" -gt 0 ]]; then
        return 1
    fi
    return 0
}
