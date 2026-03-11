#!/usr/bin/env bash
set -euo pipefail

# Checks for outdated dependencies in a project.
# Complementary to vulnerability audit — finds packages with newer versions
# available, even if the current version has no known vulnerabilities.
#
# When an SCA findings file is provided (--sca-file), cross-references outdated
# packages with known vulnerabilities. Packages that are both outdated AND have
# known CVEs get severity "SECURITY" instead of MAJOR/MINOR/PATCH.
#
# Usage: run-outdated.sh <project-path> <package-manager> [--sca-file <path>]
#
# Supported package managers: npm, yarn, pnpm, pip, composer

PROJECT_PATH="${1:-}"
PACKAGE_MANAGER="${2:-}"
SCA_FILE=""

# Parse optional --sca-file argument
shift 2 2>/dev/null || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sca-file)
            SCA_FILE="${2:-}"
            shift 2
            ;;
        *) shift ;;
    esac
done

if [[ -z "$PROJECT_PATH" ]]; then
    echo "Error: project path is required as first argument" >&2
    exit 1
fi

if [[ ! -d "$PROJECT_PATH" ]]; then
    echo "Error: project directory not found: $PROJECT_PATH" >&2
    exit 1
fi

if [[ -z "$PACKAGE_MANAGER" ]]; then
    echo "Error: package manager is required as second argument (npm|yarn|pnpm|pip|composer)" >&2
    exit 1
fi

PROJECT_PATH="$(cd "$PROJECT_PATH" && pwd)"

# --- Helpers ---

has_jq() {
    command -v jq >/dev/null 2>&1
}

# Output empty result when the tool produces non-JSON or no output
empty_result() {
    local tool="$1"
    local pm="$2"
    local reason="${3:-no output}"
    printf '{"tool":"%s","package_manager":"%s","outdated":[],"summary":{"total":0,"security":0,"major":0,"minor":0,"patch":0},"note":"%s"}\n' "$tool" "$pm" "$reason"
}

is_valid_json() {
    if [[ -z "$1" ]]; then
        return 1
    fi
    echo "$1" | jq empty 2>/dev/null
}

# Classify severity with optional security cross-reference.
# If the package has known vulnerabilities (from SCA data), returns "SECURITY".
# Otherwise returns MAJOR, MINOR, PATCH, or UNKNOWN based on version distance.
classify_with_security() {
    local pkg_name="$1"
    local current="$2"
    local latest="$3"

    if is_vulnerable_package "$pkg_name"; then
        echo "SECURITY"
        return
    fi

    classify_severity "$current" "$latest"
}

# Compare two semver components to classify the update severity.
# Returns: MAJOR, MINOR, PATCH, or UNKNOWN
classify_severity() {
    local current="$1"
    local latest="$2"

    # Strip leading 'v' if present
    current="${current#v}"
    latest="${latest#v}"

    # Extract major.minor.patch using parameter expansion (bash 3.2 compatible)
    local cur_major cur_minor cur_patch
    local lat_major lat_minor lat_patch

    cur_major="${current%%.*}"
    local cur_rest="${current#*.}"
    cur_minor="${cur_rest%%.*}"
    cur_patch="${cur_rest#*.}"
    cur_patch="${cur_patch%%[^0-9]*}"

    lat_major="${latest%%.*}"
    local lat_rest="${latest#*.}"
    lat_minor="${lat_rest%%.*}"
    lat_patch="${lat_rest#*.}"
    lat_patch="${lat_patch%%[^0-9]*}"

    # Default to 0 if empty
    cur_major="${cur_major:-0}"
    cur_minor="${cur_minor:-0}"
    cur_patch="${cur_patch:-0}"
    lat_major="${lat_major:-0}"
    lat_minor="${lat_minor:-0}"
    lat_patch="${lat_patch:-0}"

    if [[ "$lat_major" != "$cur_major" ]]; then
        echo "MAJOR"
    elif [[ "$lat_minor" != "$cur_minor" ]]; then
        echo "MINOR"
    elif [[ "$lat_patch" != "$cur_patch" ]]; then
        echo "PATCH"
    else
        echo "UNKNOWN"
    fi
}

# Build a human-readable "behind" description
describe_behind() {
    local current="$1"
    local latest="$2"

    current="${current#v}"
    latest="${latest#v}"

    local cur_major cur_minor cur_patch
    local lat_major lat_minor lat_patch

    cur_major="${current%%.*}"
    local cur_rest="${current#*.}"
    cur_minor="${cur_rest%%.*}"
    cur_patch="${cur_rest#*.}"
    cur_patch="${cur_patch%%[^0-9]*}"

    lat_major="${latest%%.*}"
    local lat_rest="${latest#*.}"
    lat_minor="${lat_rest%%.*}"
    lat_patch="${lat_rest#*.}"
    lat_patch="${lat_patch%%[^0-9]*}"

    cur_major="${cur_major:-0}"
    cur_minor="${cur_minor:-0}"
    cur_patch="${cur_patch:-0}"
    lat_major="${lat_major:-0}"
    lat_minor="${lat_minor:-0}"
    lat_patch="${lat_patch:-0}"

    local parts=""
    local major_diff=$((lat_major - cur_major))
    local minor_diff=$((lat_minor - cur_minor))
    local patch_diff=$((lat_patch - cur_patch))

    if [[ $major_diff -gt 0 ]]; then
        parts="${major_diff} major"
    fi
    if [[ $minor_diff -gt 0 ]]; then
        if [[ -n "$parts" ]]; then
            parts="${parts}, ${minor_diff} minor"
        else
            parts="${minor_diff} minor"
        fi
    fi
    if [[ $patch_diff -gt 0 ]]; then
        if [[ -n "$parts" ]]; then
            parts="${parts}, ${patch_diff} patch"
        else
            parts="${patch_diff} patch"
        fi
    fi

    if [[ -z "$parts" ]]; then
        parts="version differs"
    fi

    echo "$parts"
}

# Build a list of vulnerable package names from SCA findings for cross-referencing
build_vulnerable_packages() {
    if [[ -z "$SCA_FILE" ]] || [[ ! -f "$SCA_FILE" ]]; then
        return
    fi
    if ! has_jq; then
        return
    fi
    # Extract unique package names from SCA findings
    jq -r '.findings[]? | .package // empty' "$SCA_FILE" 2>/dev/null | sort -u
}

# Check if a package name appears in the vulnerable packages list
is_vulnerable_package() {
    local pkg="$1"
    if [[ -z "$VULNERABLE_PACKAGES" ]]; then
        return 1
    fi
    echo "$VULNERABLE_PACKAGES" | grep -qx "$pkg" 2>/dev/null
}

# Load vulnerable packages list once at startup
VULNERABLE_PACKAGES=""
if [[ -n "$SCA_FILE" ]] && [[ -f "$SCA_FILE" ]]; then
    VULNERABLE_PACKAGES="$(build_vulnerable_packages)"
    if [[ -n "$VULNERABLE_PACKAGES" ]]; then
        local_count="$(echo "$VULNERABLE_PACKAGES" | wc -l | tr -d ' ')"
        echo "Cross-referencing with $local_count vulnerable packages from SCA data" >&2
    fi
fi

# --- Outdated check functions ---

run_npm_outdated() {
    echo "Running npm outdated in: $PROJECT_PATH" >&2

    local raw_output
    # npm outdated returns exit code 1 when outdated packages exist — this is normal
    raw_output="$(cd "$PROJECT_PATH" && npm outdated --json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "outdated-check" "npm" "npm outdated produced no JSON output"
        return
    fi

    # Check if npm returned an error object
    if has_jq && echo "$raw_output" | jq -e '.error' >/dev/null 2>&1; then
        local err_summary
        err_summary="$(echo "$raw_output" | jq -r '.error.summary // "unknown error"')"
        echo "Warning: npm outdated error: $err_summary" >&2
        empty_result "outdated-check" "npm" "$err_summary"
        return
    fi

    # Check for empty object
    if has_jq; then
        local count
        count="$(echo "$raw_output" | jq 'length')"
        if [[ "$count" == "0" ]]; then
            empty_result "outdated-check" "npm" "all packages up to date"
            return
        fi
    fi

    if has_jq; then
        # Process each package through shell to use classify_severity
        local outdated_json="[]"
        local total=0
        local security_count=0
        local major_count=0
        local minor_count=0
        local patch_count=0

        local packages
        packages="$(echo "$raw_output" | jq -r 'to_entries[] | @base64')"

        for entry in $packages; do
            local pkg_name current wanted latest
            pkg_name="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.key')"
            current="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.value.current // "unknown"')"
            wanted="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.value.wanted // "unknown"')"
            latest="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.value.latest // "unknown"')"

            local severity="UNKNOWN"
            local behind="unknown"

            if [[ "$current" != "unknown" && "$latest" != "unknown" ]]; then
                severity="$(classify_with_security "$pkg_name" "$current" "$latest")"
                behind="$(describe_behind "$current" "$latest")"
            fi

            total=$((total + 1))
            case "$severity" in
                SECURITY) security_count=$((security_count + 1)) ;;
                MAJOR) major_count=$((major_count + 1)) ;;
                MINOR) minor_count=$((minor_count + 1)) ;;
                PATCH) patch_count=$((patch_count + 1)) ;;
            esac

            outdated_json="$(echo "$outdated_json" | jq \
                --arg pkg "$pkg_name" \
                --arg cur "$current" \
                --arg wan "$wanted" \
                --arg lat "$latest" \
                --arg sev "$severity" \
                --arg beh "$behind" \
                '. + [{"package": $pkg, "current": $cur, "wanted": $wan, "latest": $lat, "severity": $sev, "behind": $beh}]'
            )"
        done

        jq -n \
            --argjson outdated "$outdated_json" \
            --argjson total "$total" \
            --argjson security "$security_count" \
            --argjson major "$major_count" \
            --argjson minor "$minor_count" \
            --argjson patch "$patch_count" \
            '{
                "tool": "outdated-check",
                "package_manager": "npm",
                "outdated": $outdated,
                "summary": {
                    "total": $total,
                    "security": $security,
                    "major": $major,
                    "minor": $minor,
                    "patch": $patch
                }
            }'
    else
        echo "$raw_output"
    fi
}

run_yarn_outdated() {
    echo "Running yarn outdated in: $PROJECT_PATH" >&2

    local raw_output
    # yarn outdated returns exit code 1 when outdated packages exist
    raw_output="$(cd "$PROJECT_PATH" && yarn outdated --json 2>/dev/null)" || true

    if [[ -z "$raw_output" ]]; then
        empty_result "outdated-check" "yarn" "yarn outdated produced no output"
        return
    fi

    if has_jq; then
        # yarn outdated --json outputs NDJSON. The data table line has type "table"
        # with head: ["Package","Current","Wanted","Latest","Package Type","URL"]
        local table_line
        table_line="$(echo "$raw_output" | jq -s '[.[] | select(.type == "table")] | .[0] // empty' 2>/dev/null)" || true

        if [[ -z "$table_line" ]]; then
            empty_result "outdated-check" "yarn" "yarn outdated returned no table data"
            return
        fi

        local outdated_json="[]"
        local total=0
        local security_count=0
        local major_count=0
        local minor_count=0
        local patch_count=0

        local rows
        rows="$(echo "$table_line" | jq -r '.data.body[] | @base64')"

        for row in $rows; do
            local pkg_name current wanted latest
            pkg_name="$(echo "$row" | base64 -d 2>/dev/null | jq -r '.[0]')"
            current="$(echo "$row" | base64 -d 2>/dev/null | jq -r '.[1]')"
            wanted="$(echo "$row" | base64 -d 2>/dev/null | jq -r '.[2]')"
            latest="$(echo "$row" | base64 -d 2>/dev/null | jq -r '.[3]')"

            local severity="UNKNOWN"
            local behind="unknown"

            if [[ "$current" != "unknown" && "$latest" != "unknown" ]]; then
                severity="$(classify_with_security "$pkg_name" "$current" "$latest")"
                behind="$(describe_behind "$current" "$latest")"
            fi

            total=$((total + 1))
            case "$severity" in
                SECURITY) security_count=$((security_count + 1)) ;;
                MAJOR) major_count=$((major_count + 1)) ;;
                MINOR) minor_count=$((minor_count + 1)) ;;
                PATCH) patch_count=$((patch_count + 1)) ;;
            esac

            outdated_json="$(echo "$outdated_json" | jq \
                --arg pkg "$pkg_name" \
                --arg cur "$current" \
                --arg wan "$wanted" \
                --arg lat "$latest" \
                --arg sev "$severity" \
                --arg beh "$behind" \
                '. + [{"package": $pkg, "current": $cur, "wanted": $wan, "latest": $lat, "severity": $sev, "behind": $beh}]'
            )"
        done

        jq -n \
            --argjson outdated "$outdated_json" \
            --argjson total "$total" \
            --argjson security "$security_count" \
            --argjson major "$major_count" \
            --argjson minor "$minor_count" \
            --argjson patch "$patch_count" \
            '{
                "tool": "outdated-check",
                "package_manager": "yarn",
                "outdated": $outdated,
                "summary": {
                    "total": $total,
                    "security": $security,
                    "major": $major,
                    "minor": $minor,
                    "patch": $patch
                }
            }'
    else
        echo "$raw_output"
    fi
}

run_pnpm_outdated() {
    echo "Running pnpm outdated in: $PROJECT_PATH" >&2

    local raw_output
    # Try --format json first, then --json as fallback
    raw_output="$(cd "$PROJECT_PATH" && pnpm outdated --format json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        raw_output="$(cd "$PROJECT_PATH" && pnpm outdated --json 2>/dev/null)" || true
    fi

    if ! is_valid_json "$raw_output"; then
        empty_result "outdated-check" "pnpm" "pnpm outdated produced no JSON output"
        return
    fi

    if has_jq; then
        # pnpm outdated --format json returns an object keyed by package name:
        # { "pkg": { "current": "1.0.0", "latest": "2.0.0", "wanted": "1.2.0", "isDeprecated": false, "dependencyType": "..." } }
        local outdated_json="[]"
        local total=0
        local security_count=0
        local major_count=0
        local minor_count=0
        local patch_count=0

        local packages
        packages="$(echo "$raw_output" | jq -r 'to_entries[] | @base64')"

        for entry in $packages; do
            local pkg_name current wanted latest
            pkg_name="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.key')"
            current="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.value.current // "unknown"')"
            wanted="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.value.wanted // "unknown"')"
            latest="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.value.latest // "unknown"')"

            local severity="UNKNOWN"
            local behind="unknown"

            if [[ "$current" != "unknown" && "$latest" != "unknown" ]]; then
                severity="$(classify_with_security "$pkg_name" "$current" "$latest")"
                behind="$(describe_behind "$current" "$latest")"
            fi

            total=$((total + 1))
            case "$severity" in
                SECURITY) security_count=$((security_count + 1)) ;;
                MAJOR) major_count=$((major_count + 1)) ;;
                MINOR) minor_count=$((minor_count + 1)) ;;
                PATCH) patch_count=$((patch_count + 1)) ;;
            esac

            outdated_json="$(echo "$outdated_json" | jq \
                --arg pkg "$pkg_name" \
                --arg cur "$current" \
                --arg wan "$wanted" \
                --arg lat "$latest" \
                --arg sev "$severity" \
                --arg beh "$behind" \
                '. + [{"package": $pkg, "current": $cur, "wanted": $wan, "latest": $lat, "severity": $sev, "behind": $beh}]'
            )"
        done

        jq -n \
            --argjson outdated "$outdated_json" \
            --argjson total "$total" \
            --argjson security "$security_count" \
            --argjson major "$major_count" \
            --argjson minor "$minor_count" \
            --argjson patch "$patch_count" \
            '{
                "tool": "outdated-check",
                "package_manager": "pnpm",
                "outdated": $outdated,
                "summary": {
                    "total": $total,
                    "security": $security,
                    "major": $major,
                    "minor": $minor,
                    "patch": $patch
                }
            }'
    else
        echo "$raw_output"
    fi
}

run_pip_outdated() {
    echo "Running pip list --outdated in: $PROJECT_PATH" >&2

    if ! command -v pip >/dev/null 2>&1 && ! command -v pip3 >/dev/null 2>&1; then
        echo "Error: pip is not installed." >&2
        printf '{"tool":"outdated-check","package_manager":"pip","outdated":[],"summary":{"total":0,"major":0,"minor":0,"patch":0},"error":"pip not installed"}\n'
        return
    fi

    local pip_cmd="pip"
    if ! command -v pip >/dev/null 2>&1; then
        pip_cmd="pip3"
    fi

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && $pip_cmd list --outdated --format json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "outdated-check" "pip" "pip list --outdated produced no JSON output"
        return
    fi

    if has_jq; then
        # Check for empty array
        local count
        count="$(echo "$raw_output" | jq 'length')"
        if [[ "$count" == "0" ]]; then
            empty_result "outdated-check" "pip" "all packages up to date"
            return
        fi

        # pip list --outdated --format json returns:
        # [{"name": "pkg", "version": "1.0.0", "latest_version": "2.0.0", "latest_filetype": "wheel"}]
        local outdated_json="[]"
        local total=0
        local security_count=0
        local major_count=0
        local minor_count=0
        local patch_count=0

        local packages
        packages="$(echo "$raw_output" | jq -r '.[] | @base64')"

        for entry in $packages; do
            local pkg_name current latest
            pkg_name="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.name')"
            current="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.version // "unknown"')"
            latest="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.latest_version // "unknown"')"

            local severity="UNKNOWN"
            local behind="unknown"

            if [[ "$current" != "unknown" && "$latest" != "unknown" ]]; then
                severity="$(classify_with_security "$pkg_name" "$current" "$latest")"
                behind="$(describe_behind "$current" "$latest")"
            fi

            total=$((total + 1))
            case "$severity" in
                SECURITY) security_count=$((security_count + 1)) ;;
                MAJOR) major_count=$((major_count + 1)) ;;
                MINOR) minor_count=$((minor_count + 1)) ;;
                PATCH) patch_count=$((patch_count + 1)) ;;
            esac

            outdated_json="$(echo "$outdated_json" | jq \
                --arg pkg "$pkg_name" \
                --arg cur "$current" \
                --arg wan "$current" \
                --arg lat "$latest" \
                --arg sev "$severity" \
                --arg beh "$behind" \
                '. + [{"package": $pkg, "current": $cur, "wanted": $wan, "latest": $lat, "severity": $sev, "behind": $beh}]'
            )"
        done

        jq -n \
            --argjson outdated "$outdated_json" \
            --argjson total "$total" \
            --argjson security "$security_count" \
            --argjson major "$major_count" \
            --argjson minor "$minor_count" \
            --argjson patch "$patch_count" \
            '{
                "tool": "outdated-check",
                "package_manager": "pip",
                "outdated": $outdated,
                "summary": {
                    "total": $total,
                    "security": $security,
                    "major": $major,
                    "minor": $minor,
                    "patch": $patch
                }
            }'
    else
        echo "$raw_output"
    fi
}

run_composer_outdated() {
    echo "Running composer outdated in: $PROJECT_PATH" >&2

    if ! command -v composer >/dev/null 2>&1; then
        echo "Error: composer is not installed." >&2
        printf '{"tool":"outdated-check","package_manager":"composer","outdated":[],"summary":{"total":0,"major":0,"minor":0,"patch":0},"error":"composer not installed"}\n'
        return
    fi

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && composer outdated --format json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "outdated-check" "composer" "composer outdated produced no JSON output"
        return
    fi

    # Check for error responses
    if has_jq && echo "$raw_output" | jq -e '.error' >/dev/null 2>&1; then
        local err_msg
        err_msg="$(echo "$raw_output" | jq -r '.error // "unknown error"')"
        echo "Warning: composer outdated error: $err_msg" >&2
        empty_result "outdated-check" "composer" "$err_msg"
        return
    fi

    if has_jq; then
        # composer outdated --format json returns:
        # {"installed": [{"name": "pkg", "version": "1.0.0", "latest": "2.0.0", "latest-status": "semver-safe-update"|"update-possible"}]}
        local installed
        installed="$(echo "$raw_output" | jq '.installed // []')"

        local count
        count="$(echo "$installed" | jq 'length')"
        if [[ "$count" == "0" ]]; then
            empty_result "outdated-check" "composer" "all packages up to date"
            return
        fi

        local outdated_json="[]"
        local total=0
        local security_count=0
        local major_count=0
        local minor_count=0
        local patch_count=0

        local packages
        packages="$(echo "$installed" | jq -r '.[] | @base64')"

        for entry in $packages; do
            local pkg_name current latest latest_status
            pkg_name="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.name')"
            current="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.version // "unknown"')"
            latest="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '.latest // "unknown"')"
            latest_status="$(echo "$entry" | base64 -d 2>/dev/null | jq -r '."latest-status" // "unknown"')"

            # Strip leading 'v' for version comparison
            local current_clean="${current#v}"
            local latest_clean="${latest#v}"

            local severity="UNKNOWN"
            local behind="unknown"

            if [[ "$latest_status" == "update-possible" ]]; then
                # update-possible means a major version update (potentially breaking)
                severity="MAJOR"
            elif [[ "$latest_status" == "semver-safe-update" ]]; then
                # semver-safe means minor or patch — classify by comparing versions
                if [[ "$current_clean" != "unknown" && "$latest_clean" != "unknown" ]]; then
                    severity="$(classify_severity "$current_clean" "$latest_clean")"
                else
                    severity="MINOR"
                fi
            else
                if [[ "$current_clean" != "unknown" && "$latest_clean" != "unknown" ]]; then
                    severity="$(classify_severity "$current_clean" "$latest_clean")"
                fi
            fi

            if [[ "$current_clean" != "unknown" && "$latest_clean" != "unknown" ]]; then
                behind="$(describe_behind "$current_clean" "$latest_clean")"
            fi

            total=$((total + 1))
            case "$severity" in
                SECURITY) security_count=$((security_count + 1)) ;;
                MAJOR) major_count=$((major_count + 1)) ;;
                MINOR) minor_count=$((minor_count + 1)) ;;
                PATCH) patch_count=$((patch_count + 1)) ;;
            esac

            outdated_json="$(echo "$outdated_json" | jq \
                --arg pkg "$pkg_name" \
                --arg cur "$current" \
                --arg wan "$current" \
                --arg lat "$latest" \
                --arg sev "$severity" \
                --arg beh "$behind" \
                '. + [{"package": $pkg, "current": $cur, "wanted": $wan, "latest": $lat, "severity": $sev, "behind": $beh}]'
            )"
        done

        jq -n \
            --argjson outdated "$outdated_json" \
            --argjson total "$total" \
            --argjson security "$security_count" \
            --argjson major "$major_count" \
            --argjson minor "$minor_count" \
            --argjson patch "$patch_count" \
            '{
                "tool": "outdated-check",
                "package_manager": "composer",
                "outdated": $outdated,
                "summary": {
                    "total": $total,
                    "security": $security,
                    "major": $major,
                    "minor": $minor,
                    "patch": $patch
                }
            }'
    else
        echo "$raw_output"
    fi
}

# --- Main ---

case "$PACKAGE_MANAGER" in
    npm)
        run_npm_outdated
        ;;
    yarn)
        run_yarn_outdated
        ;;
    pnpm)
        run_pnpm_outdated
        ;;
    pip|pipenv|poetry)
        run_pip_outdated
        ;;
    composer)
        run_composer_outdated
        ;;
    *)
        echo "Error: Unsupported package manager: $PACKAGE_MANAGER" >&2
        echo "Supported: npm, yarn, pnpm, pip, composer" >&2
        printf '{"tool":"outdated-check","package_manager":"%s","outdated":[],"summary":{"total":0,"major":0,"minor":0,"patch":0},"error":"unsupported package manager"}\n' "$PACKAGE_MANAGER"
        exit 1
        ;;
esac
