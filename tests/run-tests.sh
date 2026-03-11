#!/usr/bin/env bash
set -uo pipefail

# Test runner for Shield security skill test suite.
# Finds and executes all test-*.sh files, tracking pass/fail counts.
#
# Usage:
#   ./run-tests.sh                    # Run all tests
#   ./run-tests.sh test-detect-stack.sh test-check-prereqs.sh  # Run specific tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

# --- Counters ---
SUITES_PASSED=0
SUITES_FAILED=0
SUITES_TOTAL=0

# --- Collect test files ---
declare -a test_files=()

if [[ $# -gt 0 ]]; then
    # Run specific test files passed as arguments
    for arg in "$@"; do
        if [[ "$arg" == /* ]]; then
            test_files+=("$arg")
        elif [[ -f "$SCRIPT_DIR/$arg" ]]; then
            test_files+=("$SCRIPT_DIR/$arg")
        else
            printf "${RED}Warning:${NC} Test file not found: %s\n" "$arg"
        fi
    done
else
    # Find all test-*.sh files (excluding test-helpers.sh)
    while IFS= read -r -d '' file; do
        test_files+=("$file")
    done < <(find "$SCRIPT_DIR" -maxdepth 1 -name 'test-*.sh' -not -name 'test-helpers.sh' -print0 | sort -z)
fi

if [[ ${#test_files[@]} -eq 0 ]]; then
    printf "${RED}No test files found.${NC}\n"
    exit 1
fi

# --- Header ---
echo ""
printf "${BOLD}Shield Security Skill — Test Suite${NC}\n"
printf "Running %d test file(s)...\n" "${#test_files[@]}"
echo "========================================="

# --- Run each test file ---
for test_file in "${test_files[@]}"; do
    test_name="$(basename "$test_file")"
    SUITES_TOTAL=$((SUITES_TOTAL + 1))

    echo ""
    printf "${BOLD}[%s]${NC}\n" "$test_name"

    # Make sure the test file is executable
    if [[ ! -x "$test_file" ]]; then
        chmod +x "$test_file"
    fi

    # Run the test in a subshell to isolate failures
    if bash "$test_file"; then
        SUITES_PASSED=$((SUITES_PASSED + 1))
    else
        SUITES_FAILED=$((SUITES_FAILED + 1))
        printf "${RED}  ^^^ Suite failed: %s${NC}\n" "$test_name"
    fi
done

# --- Summary ---
echo ""
echo "========================================="
printf "${BOLD}Test Suite Summary${NC}\n"
echo "========================================="
printf "  Suites run:    %d\n" "$SUITES_TOTAL"
printf "  ${GREEN}Suites passed: %d${NC}\n" "$SUITES_PASSED"
printf "  ${RED}Suites failed: %d${NC}\n" "$SUITES_FAILED"
echo "========================================="

if [[ "$SUITES_FAILED" -gt 0 ]]; then
    printf "\n${RED}${BOLD}RESULT: FAIL${NC}\n\n"
    exit 1
else
    printf "\n${GREEN}${BOLD}RESULT: PASS${NC}\n\n"
    exit 0
fi
