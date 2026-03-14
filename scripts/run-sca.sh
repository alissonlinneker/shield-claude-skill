#!/usr/bin/env bash
set -euo pipefail

# Runs package/dependency audit for the detected package manager.
# Outputs normalized JSON vulnerability findings to stdout.
#
# Usage: run-sca.sh <project-path> <package-manager>
#
# Supported package managers: npm, yarn, pnpm, pip, composer, bundler, cargo, go, maven, gradle, dotnet

PROJECT_PATH="${1:-}"
PACKAGE_MANAGER="${2:-}"

if [[ -z "$PROJECT_PATH" ]]; then
    echo "Error: project path is required as first argument" >&2
    exit 1
fi

if [[ ! -d "$PROJECT_PATH" ]]; then
    echo "Error: project directory not found: $PROJECT_PATH" >&2
    exit 1
fi

if [[ -z "$PACKAGE_MANAGER" ]]; then
    echo "Error: package manager is required as second argument (npm|yarn|pnpm|pip|composer|bundler|cargo|go|maven|gradle|dotnet)" >&2
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
    printf '{"tool":"%s","package_manager":"%s","findings":[],"summary":{"total":0},"note":"%s"}\n' "$tool" "$pm" "$reason"
}

is_valid_json() {
    if [[ -z "$1" ]]; then
        return 1
    fi
    echo "$1" | jq empty 2>/dev/null
}

# --- Audit functions ---

run_npm_audit() {
    echo "Running npm audit in: $PROJECT_PATH" >&2

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && npm audit --json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "npm-audit" "npm" "npm audit produced no JSON output"
        return
    fi

    # Check if npm audit returned an error (e.g., missing lockfile)
    if has_jq && echo "$raw_output" | jq -e '.error' >/dev/null 2>&1; then
        local err_summary
        err_summary="$(echo "$raw_output" | jq -r '.error.summary // "unknown error"')"
        echo "Warning: npm audit error: $err_summary" >&2
        empty_result "npm-audit" "npm" "$err_summary"
        return
    fi

    if has_jq; then
        echo "$raw_output" | jq '
        {
            "tool": "npm-audit",
            "package_manager": "npm",
            "findings": (
                if .vulnerabilities then
                    [.vulnerabilities | to_entries[] | {
                        "severity": (
                            if .value.severity == "critical" then "CRITICAL"
                            elif .value.severity == "high" then "HIGH"
                            elif .value.severity == "moderate" then "MEDIUM"
                            elif .value.severity == "low" then "LOW"
                            else "MEDIUM"
                            end
                        ),
                        "title": ("Vulnerable dependency: " + .key),
                        "description": (.value.via[0] | if type == "object" then .title // "" else . end),
                        "package": .key,
                        "installed_version": (.value.range // "unknown"),
                        "vulnerable_range": (.value.range // "unknown"),
                        "recommendation": (.value.fixAvailable | if type == "object" then "Update to " + .name + "@" + .version else "Check for updates" end),
                        "cwe": null,
                        "owasp": "A06:2021",
                        "source_tool": "npm-audit",
                        "file": "package.json",
                        "line": null
                    }]
                elif .advisories then
                    [.advisories | to_entries[] | .value | {
                        "severity": (
                            if .severity == "critical" then "CRITICAL"
                            elif .severity == "high" then "HIGH"
                            elif .severity == "moderate" then "MEDIUM"
                            elif .severity == "low" then "LOW"
                            else "MEDIUM"
                            end
                        ),
                        "title": .title,
                        "description": .overview,
                        "package": .module_name,
                        "installed_version": (.findings[0].version // "unknown"),
                        "vulnerable_range": .vulnerable_versions,
                        "recommendation": .recommendation,
                        "cwe": (.cwe // null),
                        "owasp": "A06:2021",
                        "source_tool": "npm-audit",
                        "file": "package.json",
                        "line": null
                    }]
                else
                    []
                end
            ),
            "summary": {
                "total": (
                    if .metadata.vulnerabilities then
                        (.metadata.vulnerabilities.total // 0)
                    else 0 end
                )
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_yarn_audit() {
    echo "Running yarn audit in: $PROJECT_PATH" >&2

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && yarn audit --json 2>/dev/null)" || true

    if [[ -z "$raw_output" ]]; then
        empty_result "yarn-audit" "yarn" "yarn audit produced no output"
        return
    fi

    if has_jq; then
        # yarn audit outputs NDJSON (one JSON object per line)
        echo "$raw_output" | jq -s '
        {
            "tool": "yarn-audit",
            "package_manager": "yarn",
            "findings": [
                .[] | select(.type == "auditAdvisory") | .data.advisory | {
                    "severity": (
                        if .severity == "critical" then "CRITICAL"
                        elif .severity == "high" then "HIGH"
                        elif .severity == "moderate" then "MEDIUM"
                        elif .severity == "low" then "LOW"
                        else "MEDIUM"
                        end
                    ),
                    "title": .title,
                    "description": .overview,
                    "package": .module_name,
                    "installed_version": (.findings[0].version // "unknown"),
                    "vulnerable_range": .vulnerable_versions,
                    "recommendation": .recommendation,
                    "cwe": (.cwe // null),
                    "owasp": "A06:2021",
                    "source_tool": "yarn-audit",
                    "file": "package.json",
                    "line": null
                }
            ],
            "summary": {
                "total": ([.[] | select(.type == "auditAdvisory")] | length)
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_pnpm_audit() {
    echo "Running pnpm audit in: $PROJECT_PATH" >&2

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && pnpm audit --json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "pnpm-audit" "pnpm" "pnpm audit produced no JSON output"
        return
    fi

    if has_jq; then
        # pnpm audit JSON format is similar to npm
        echo "$raw_output" | jq '
        {
            "tool": "pnpm-audit",
            "package_manager": "pnpm",
            "findings": (
                if .advisories then
                    [.advisories | to_entries[] | .value | {
                        "severity": (
                            if .severity == "critical" then "CRITICAL"
                            elif .severity == "high" then "HIGH"
                            elif .severity == "moderate" then "MEDIUM"
                            elif .severity == "low" then "LOW"
                            else "MEDIUM"
                            end
                        ),
                        "title": .title,
                        "description": .overview,
                        "package": .module_name,
                        "installed_version": (.findings[0].version // "unknown"),
                        "vulnerable_range": .vulnerable_versions,
                        "recommendation": .recommendation,
                        "cwe": (.cwe // null),
                        "owasp": "A06:2021",
                        "source_tool": "pnpm-audit",
                        "file": "package.json",
                        "line": null
                    }]
                else
                    []
                end
            ),
            "summary": {
                "total": (if .advisories then (.advisories | length) else 0 end)
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_pip_audit() {
    echo "Running pip-audit in: $PROJECT_PATH" >&2

    if ! command -v pip-audit >/dev/null 2>&1; then
        echo "Error: pip-audit is not installed. Install with: pip install pip-audit" >&2
        printf '{"tool":"pip-audit","package_manager":"pip","findings":[],"summary":{"total":0},"error":"pip-audit not installed"}\n'
        return
    fi

    local raw_output
    local req_file=""

    # Detect requirements file
    for candidate in "$PROJECT_PATH/requirements.txt" "$PROJECT_PATH/requirements/base.txt" "$PROJECT_PATH/requirements/production.txt"; do
        if [[ -f "$candidate" ]]; then
            req_file="$candidate"
            break
        fi
    done

    if [[ -n "$req_file" ]]; then
        raw_output="$(pip-audit -r "$req_file" --format json --output - 2>/dev/null)" || true
    else
        raw_output="$(cd "$PROJECT_PATH" && pip-audit --format json --output - 2>/dev/null)" || true
    fi

    if ! is_valid_json "$raw_output"; then
        empty_result "pip-audit" "pip" "pip-audit produced no JSON output"
        return
    fi

    if has_jq; then
        echo "$raw_output" | jq '
        {
            "tool": "pip-audit",
            "package_manager": "pip",
            "findings": [
                .dependencies // [] | .[] | select(.vulns | length > 0) |
                . as $dep |
                .vulns[] | {
                    "severity": "HIGH",
                    "title": ("Vulnerable dependency: " + $dep.name + " " + ($dep.version // "")),
                    "description": (.description // .id),
                    "package": $dep.name,
                    "installed_version": ($dep.version // "unknown"),
                    "vulnerable_range": "see advisory",
                    "recommendation": (
                        if .fix_versions and (.fix_versions | length > 0)
                        then "Update to " + .fix_versions[0]
                        else "No fix available"
                        end
                    ),
                    "cwe": null,
                    "owasp": "A06:2021",
                    "source_tool": "pip-audit",
                    "file": "requirements.txt",
                    "line": null,
                    "advisory_id": .id,
                    "advisory_url": (.aliases[0] // null)
                }
            ],
            "summary": {
                "total": ([.dependencies // [] | .[] | select(.vulns | length > 0) | .vulns[]] | length)
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_composer_audit() {
    echo "Running composer audit in: $PROJECT_PATH" >&2

    if ! command -v composer >/dev/null 2>&1; then
        echo "Error: composer is not installed." >&2
        printf '{"tool":"composer-audit","package_manager":"composer","findings":[],"summary":{"total":0},"error":"composer not installed"}\n'
        return
    fi

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && composer audit --format json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "composer-audit" "composer" "no packages to audit or composer.lock missing"
        return
    fi

    if has_jq; then
        echo "$raw_output" | jq '
        {
            "tool": "composer-audit",
            "package_manager": "composer",
            "findings": [
                .advisories // {} | to_entries[] |
                . as $pkg |
                .value[] | {
                    "severity": (
                        if .severity == "critical" then "CRITICAL"
                        elif .severity == "high" then "HIGH"
                        elif .severity == "medium" then "MEDIUM"
                        elif .severity == "low" then "LOW"
                        else "MEDIUM"
                        end
                    ),
                    "title": .title,
                    "description": (.title // ""),
                    "package": $pkg.key,
                    "installed_version": "see composer.lock",
                    "vulnerable_range": .affectedVersions,
                    "recommendation": ("See advisory: " + (.link // "")),
                    "cwe": (.cve // null),
                    "owasp": "A06:2021",
                    "source_tool": "composer-audit",
                    "file": "composer.json",
                    "line": null,
                    "advisory_id": (.advisoryId // null)
                }
            ],
            "summary": {
                "total": ([.advisories // {} | to_entries[] | .value[]] | length)
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_go_audit() {
    echo "Running govulncheck in: $PROJECT_PATH" >&2

    if ! command -v govulncheck >/dev/null 2>&1; then
        echo "Error: govulncheck is not installed. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest" >&2
        printf '{"tool":"govulncheck","package_manager":"go","findings":[],"summary":{"total":0},"error":"govulncheck not installed"}\n'
        return
    fi

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && govulncheck -json ./... 2>/dev/null)" || true

    if [[ -z "$raw_output" ]]; then
        empty_result "govulncheck" "go" "govulncheck produced no output"
        return
    fi

    if has_jq; then
        # govulncheck outputs a stream of JSON objects (one per line), not an array.
        # Each object has exactly one key: config, progress, osv, or finding.
        # We first collect all osv entries into a lookup, then extract findings.
        echo "$raw_output" | jq -s '
        # Build a map of OSV ID -> OSV data for severity/summary lookup
        (
            [.[] | select(.osv != null) | .osv] |
            reduce .[] as $o ({}; . + {($o.id): $o})
        ) as $osv_map |
        # Extract finding objects
        [.[] | select(.finding != null) | .finding] |
        # Deduplicate by OSV ID (multiple findings can reference the same vuln)
        group_by(.osv) |
        [
            .[] | .[0] as $f |
            ($osv_map[$f.osv] // {}) as $osv_data |
            {
                "severity": (
                    # Derive from CVSS score in osv database_specific or severity field
                    if $osv_data.database_specific.severity then
                        (if $osv_data.database_specific.severity == "CRITICAL" then "CRITICAL"
                         elif $osv_data.database_specific.severity == "HIGH" then "HIGH"
                         elif $osv_data.database_specific.severity == "MODERATE" then "MEDIUM"
                         elif $osv_data.database_specific.severity == "LOW" then "LOW"
                         else "HIGH" end)
                    elif ($osv_data.severity // [] | length > 0) then
                        (
                            ($osv_data.severity[0].score // 0) as $score |
                            if $score >= 9.0 then "CRITICAL"
                            elif $score >= 7.0 then "HIGH"
                            elif $score >= 4.0 then "MEDIUM"
                            else "LOW" end
                        )
                    else "HIGH"
                    end
                ),
                "title": ($osv_data.summary // ("Vulnerability " + $f.osv)),
                "description": ($osv_data.details // ""),
                "package": ($f.trace[0].module // "unknown"),
                "installed_version": ($f.trace[0].version // "unknown"),
                "vulnerable_range": "see advisory",
                "recommendation": "Update to patched version",
                "cwe": null,
                "owasp": "A06:2021",
                "source_tool": "govulncheck",
                "file": (
                    if ($f.trace | length > 0) and ($f.trace[-1].position // null) != null
                    then ($f.trace[-1].position.filename // null)
                    else null end
                ),
                "line": (
                    if ($f.trace | length > 0) and ($f.trace[-1].position // null) != null
                    then ($f.trace[-1].position.line // null)
                    else null end
                ),
                "advisory_id": $f.osv
            }
        ] |
        {
            "tool": "govulncheck",
            "package_manager": "go",
            "findings": .,
            "summary": {
                "total": length
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_bundle_audit() {
    echo "Running bundle-audit in: $PROJECT_PATH" >&2

    if ! command -v bundle-audit >/dev/null 2>&1; then
        echo "Error: bundle-audit is not installed. Install with: gem install bundler-audit" >&2
        printf '{"tool":"bundle-audit","package_manager":"bundler","findings":[],"summary":{"total":0},"error":"bundle-audit not installed"}\n'
        return
    fi

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && bundle-audit check --format json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "bundle-audit" "bundler" "bundle-audit produced no JSON output"
        return
    fi

    if has_jq; then
        echo "$raw_output" | jq '
        {
            "tool": "bundle-audit",
            "package_manager": "bundler",
            "findings": [
                (.results // [])[] | {
                    "severity": (
                        if .advisory.criticality == "critical" then "CRITICAL"
                        elif .advisory.criticality == "high" then "HIGH"
                        elif .advisory.criticality == "medium" then "MEDIUM"
                        elif .advisory.criticality == "low" then "LOW"
                        elif .advisory.criticality == "none" then "LOW"
                        else "MEDIUM"
                        end
                    ),
                    "title": (.advisory.title // "Unknown advisory"),
                    "description": (.advisory.description // .advisory.title // ""),
                    "package": (.gem.name // "unknown"),
                    "installed_version": (.gem.version // "unknown"),
                    "vulnerable_range": "see advisory",
                    "recommendation": "Update to patched version",
                    "cwe": (
                        if .advisory.cve then ("CVE-" + .advisory.cve)
                        else null end
                    ),
                    "owasp": "A06:2021",
                    "source_tool": "bundle-audit",
                    "file": "Gemfile.lock",
                    "line": null,
                    "advisory_id": (.advisory.id // null)
                }
            ],
            "summary": {
                "total": ((.results // []) | length)
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_cargo_audit() {
    echo "Running cargo audit in: $PROJECT_PATH" >&2

    if ! command -v cargo-audit >/dev/null 2>&1; then
        echo "Error: cargo-audit is not installed. Install with: cargo install cargo-audit" >&2
        printf '{"tool":"cargo-audit","package_manager":"cargo","findings":[],"summary":{"total":0},"error":"cargo-audit not installed"}\n'
        return
    fi

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && cargo audit --json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "cargo-audit" "cargo" "cargo audit produced no JSON output"
        return
    fi

    if has_jq; then
        echo "$raw_output" | jq '
        {
            "tool": "cargo-audit",
            "package_manager": "cargo",
            "findings": [
                (.vulnerabilities.list // [])[] | {
                    "severity": (
                        if .advisory.cvss then
                            # Extract CVSS score from the CVSS vector string
                            # The score is typically embedded; parse numeric value if present
                            (
                                (.advisory.cvss | split("/") |
                                    if length > 0 then
                                        # Try to extract base score from CVSS string
                                        .[0] | gsub("[^0-9.]"; "") |
                                        if . != "" then tonumber else 0 end
                                    else 0 end
                                ) as $score |
                                if $score >= 9.0 then "CRITICAL"
                                elif $score >= 7.0 then "HIGH"
                                elif $score >= 4.0 then "MEDIUM"
                                elif $score > 0 then "LOW"
                                else "HIGH"
                                end
                            )
                        else "HIGH"
                        end
                    ),
                    "title": (.advisory.title // "Unknown advisory"),
                    "description": (.advisory.description // .advisory.title // ""),
                    "package": (.package.name // "unknown"),
                    "installed_version": (.package.version // "unknown"),
                    "vulnerable_range": (
                        if .versions.patched and (.versions.patched | length > 0)
                        then "patched in: " + (.versions.patched | join(", "))
                        else "see advisory"
                        end
                    ),
                    "recommendation": (
                        if .versions.patched and (.versions.patched | length > 0)
                        then "Update to " + .versions.patched[0]
                        else "No fix available"
                        end
                    ),
                    "cwe": (
                        [(.advisory.aliases // [])[] | select(startswith("CVE-"))] |
                        if length > 0 then .[0] else null end
                    ),
                    "owasp": "A06:2021",
                    "source_tool": "cargo-audit",
                    "file": "Cargo.lock",
                    "line": null,
                    "advisory_id": (.advisory.id // null)
                }
            ],
            "summary": {
                "total": ((.vulnerabilities.list // []) | length)
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_maven_audit() {
    echo "Running Maven dependency-check in: $PROJECT_PATH" >&2

    if ! command -v mvn >/dev/null 2>&1; then
        echo "Error: mvn is not installed." >&2
        printf '{"tool":"maven-audit","package_manager":"maven","findings":[],"summary":{"total":0},"error":"mvn not installed"}\n'
        return
    fi

    if [[ ! -f "$PROJECT_PATH/pom.xml" ]]; then
        echo "Warning: pom.xml not found in $PROJECT_PATH" >&2
        empty_result "maven-audit" "maven" "pom.xml not found"
        return
    fi

    local raw_output=""
    local report_file="$PROJECT_PATH/target/dependency-check-report.json"

    # Try OWASP dependency-check plugin first
    if (cd "$PROJECT_PATH" && mvn org.owasp:dependency-check-maven:check -Dformat=JSON -DprettyPrint=true >&2 2>&1); then
        if [[ -f "$report_file" ]]; then
            raw_output="$(cat "$report_file" 2>/dev/null)" || true
        fi
    fi

    if ! is_valid_json "$raw_output"; then
        # Fallback: run dependency:tree for limited analysis
        echo "OWASP dependency-check not available, falling back to dependency:tree" >&2
        local tree_output
        tree_output="$(cd "$PROJECT_PATH" && mvn dependency:tree 2>/dev/null)" || true

        if [[ -n "$tree_output" ]]; then
            printf '{"tool":"maven-audit","package_manager":"maven","findings":[],"summary":{"total":0},"note":"limited analysis via dependency:tree — install OWASP dependency-check-maven plugin for full vulnerability scanning"}\n'
        else
            empty_result "maven-audit" "maven" "mvn dependency:tree produced no output"
        fi
        return
    fi

    if has_jq; then
        echo "$raw_output" | jq '
        {
            "tool": "maven-audit",
            "package_manager": "maven",
            "findings": [
                .dependencies // [] | .[] | select(.vulnerabilities != null and (.vulnerabilities | length > 0)) |
                . as $dep |
                .vulnerabilities[] | {
                    "severity": (
                        if .severity == "CRITICAL" or .severity == "critical" then "CRITICAL"
                        elif .severity == "HIGH" or .severity == "high" then "HIGH"
                        elif .severity == "MEDIUM" or .severity == "medium" then "MEDIUM"
                        elif .severity == "LOW" or .severity == "low" then "LOW"
                        else "MEDIUM"
                        end
                    ),
                    "title": ("Vulnerable dependency: " + ($dep.fileName // $dep.filePath // "unknown")),
                    "description": (.description // .name // ""),
                    "package": ($dep.fileName // "unknown"),
                    "installed_version": ($dep.version // "unknown"),
                    "vulnerable_range": "see advisory",
                    "recommendation": "Update to a non-vulnerable version",
                    "cwe": (if .cwes and (.cwes | length > 0) then .cwes[0] | tostring else null end),
                    "owasp": "A06:2021",
                    "source_tool": "maven-audit",
                    "file": "pom.xml",
                    "line": null,
                    "advisory_id": (.name // null),
                    "advisory_url": (if .references and (.references | length > 0) then .references[0] else null end)
                }
            ],
            "summary": {
                "total": ([.dependencies // [] | .[] | select(.vulnerabilities != null and (.vulnerabilities | length > 0)) | .vulnerabilities[]] | length)
            }
        }'
    else
        echo "$raw_output"
    fi
}

run_gradle_audit() {
    echo "Running Gradle dependency-check in: $PROJECT_PATH" >&2

    if ! command -v gradle >/dev/null 2>&1; then
        echo "Error: gradle is not installed." >&2
        printf '{"tool":"gradle-audit","package_manager":"gradle","findings":[],"summary":{"total":0},"error":"gradle not installed"}\n'
        return
    fi

    if [[ ! -f "$PROJECT_PATH/build.gradle" ]] && [[ ! -f "$PROJECT_PATH/build.gradle.kts" ]]; then
        echo "Warning: build.gradle not found in $PROJECT_PATH" >&2
        empty_result "gradle-audit" "gradle" "build.gradle not found"
        return
    fi

    local report_file="$PROJECT_PATH/build/reports/dependency-check-report.json"

    # Try OWASP dependency-check plugin
    if (cd "$PROJECT_PATH" && gradle dependencyCheckAnalyze --info >&2 2>&1); then
        if [[ -f "$report_file" ]]; then
            local raw_output
            raw_output="$(cat "$report_file" 2>/dev/null)" || true

            if is_valid_json "$raw_output" && has_jq; then
                echo "$raw_output" | jq '
                {
                    "tool": "gradle-audit",
                    "package_manager": "gradle",
                    "findings": [
                        .dependencies // [] | .[] | select(.vulnerabilities != null and (.vulnerabilities | length > 0)) |
                        . as $dep |
                        .vulnerabilities[] | {
                            "severity": (
                                if .severity == "CRITICAL" or .severity == "critical" then "CRITICAL"
                                elif .severity == "HIGH" or .severity == "high" then "HIGH"
                                elif .severity == "MEDIUM" or .severity == "medium" then "MEDIUM"
                                elif .severity == "LOW" or .severity == "low" then "LOW"
                                else "MEDIUM"
                                end
                            ),
                            "title": ("Vulnerable dependency: " + ($dep.fileName // $dep.filePath // "unknown")),
                            "description": (.description // .name // ""),
                            "package": ($dep.fileName // "unknown"),
                            "installed_version": ($dep.version // "unknown"),
                            "vulnerable_range": "see advisory",
                            "recommendation": "Update to a non-vulnerable version",
                            "cwe": (if .cwes and (.cwes | length > 0) then .cwes[0] | tostring else null end),
                            "owasp": "A06:2021",
                            "source_tool": "gradle-audit",
                            "file": "build.gradle",
                            "line": null,
                            "advisory_id": (.name // null),
                            "advisory_url": (if .references and (.references | length > 0) then .references[0] else null end)
                        }
                    ],
                    "summary": {
                        "total": ([.dependencies // [] | .[] | select(.vulnerabilities != null and (.vulnerabilities | length > 0)) | .vulnerabilities[]] | length)
                    }
                }'
                return
            elif [[ -n "${raw_output:-}" ]]; then
                echo "$raw_output"
                return
            fi
        fi
    fi

    # Fallback: no dependency-check plugin configured
    echo "OWASP dependency-check plugin not available for Gradle" >&2
    printf '{"tool":"gradle-audit","package_manager":"gradle","findings":[],"summary":{"total":0},"note":"OWASP dependency-check plugin not configured — add the plugin to build.gradle for vulnerability scanning"}\n'
}

run_dotnet_audit() {
    echo "Running dotnet list package --vulnerable in: $PROJECT_PATH" >&2

    if ! command -v dotnet >/dev/null 2>&1; then
        echo "Error: dotnet is not installed." >&2
        printf '{"tool":"dotnet-audit","package_manager":"dotnet","findings":[],"summary":{"total":0},"error":"dotnet not installed"}\n'
        return
    fi

    local raw_output
    raw_output="$(cd "$PROJECT_PATH" && dotnet list package --vulnerable --include-transitive --format json 2>/dev/null)" || true

    if ! is_valid_json "$raw_output"; then
        empty_result "dotnet-audit" "dotnet" "dotnet list package --vulnerable produced no JSON output"
        return
    fi

    if has_jq; then
        echo "$raw_output" | jq '
        {
            "tool": "dotnet-audit",
            "package_manager": "dotnet",
            "findings": [
                .projects // [] | .[] |
                .frameworks // [] | .[] |
                (
                    (.topLevelPackages // []) + (.transitivePackages // [])
                ) | .[] |
                select(.vulnerabilities != null and (.vulnerabilities | length > 0)) |
                . as $pkg |
                .vulnerabilities[] | {
                    "severity": (
                        if .severity == "Critical" or .severity == "critical" or .severity == "CRITICAL" then "CRITICAL"
                        elif .severity == "High" or .severity == "high" or .severity == "HIGH" then "HIGH"
                        elif .severity == "Medium" or .severity == "medium" or .severity == "MEDIUM" then "MEDIUM"
                        elif .severity == "Low" or .severity == "low" or .severity == "LOW" then "LOW"
                        else "MEDIUM"
                        end
                    ),
                    "title": ("Vulnerable dependency: " + ($pkg.id // "unknown")),
                    "description": ("Vulnerability found in " + ($pkg.id // "unknown") + " " + ($pkg.resolvedVersion // "")),
                    "package": ($pkg.id // "unknown"),
                    "installed_version": ($pkg.resolvedVersion // "unknown"),
                    "vulnerable_range": "see advisory",
                    "recommendation": "Update to a non-vulnerable version",
                    "cwe": null,
                    "owasp": "A06:2021",
                    "source_tool": "dotnet-audit",
                    "file": "*.csproj",
                    "line": null,
                    "advisory_url": (.advisoryurl // null)
                }
            ],
            "summary": {
                "total": ([
                    .projects // [] | .[] |
                    .frameworks // [] | .[] |
                    (
                        (.topLevelPackages // []) + (.transitivePackages // [])
                    ) | .[] |
                    select(.vulnerabilities != null and (.vulnerabilities | length > 0)) |
                    .vulnerabilities[]
                ] | length)
            }
        }'
    else
        echo "$raw_output"
    fi
}

# --- Main ---

case "$PACKAGE_MANAGER" in
    npm)
        run_npm_audit
        ;;
    yarn)
        run_yarn_audit
        ;;
    pnpm)
        run_pnpm_audit
        ;;
    pip|pipenv|poetry)
        run_pip_audit
        ;;
    composer)
        run_composer_audit
        ;;
    bundler)
        run_bundle_audit
        ;;
    cargo)
        run_cargo_audit
        ;;
    go)
        run_go_audit
        ;;
    maven)
        run_maven_audit
        ;;
    gradle)
        run_gradle_audit
        ;;
    dotnet)
        run_dotnet_audit
        ;;
    bun)
        echo "Note: Bun does not have a native audit command." >&2
        echo "Consider using npm audit or running 'bun pm ls' for dependency listing." >&2
        printf '{"tool":"sca","package_manager":"bun","findings":[],"summary":{"total":0},"note":"bun has no native audit command — use npm audit as fallback or run bun pm ls for dependency listing"}\n'
        ;;
    *)
        echo "Warning: Unsupported package manager: $PACKAGE_MANAGER" >&2
        echo "Supported: npm, yarn, pnpm, pip, composer, bundler, cargo, go, maven, gradle, dotnet, bun" >&2
        printf '{"tool":"sca","package_manager":"%s","findings":[],"summary":{"total":0},"error":"unsupported package manager"}\n' "$PACKAGE_MANAGER"
        ;;
esac
