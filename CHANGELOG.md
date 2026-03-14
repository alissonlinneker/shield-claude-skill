# Changelog

All notable changes to Shield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-14

### Added

- **Go ecosystem support** — govulncheck for vulnerability audit, `go list -m -u` for outdated check, 10 custom Semgrep rules
- **Ruby ecosystem support** — bundle-audit for vulnerability audit, `bundle outdated` for freshness check, 10 custom Semgrep rules
- **Rust ecosystem support** — cargo-audit for vulnerability audit, cargo-outdated for freshness check, 8 custom Semgrep rules
- **Java ecosystem support** — Maven and Gradle via OWASP dependency-check for audit, versions plugin for outdated, 10 custom Semgrep rules
- **C#/.NET ecosystem support** — `dotnet list package --vulnerable` for audit, `--outdated` for freshness check
- **Bun package manager support** — graceful fallback with guidance (no native audit/outdated commands)
- **Polyglot project detection** — `detect-stack.sh` now outputs `all_package_managers` JSON array alongside the primary `package_manager` field
- **Extended tool checks** — `check-prereqs.sh` now validates 15 tools (was 7): added govulncheck, bundle-audit, cargo-audit, cargo-outdated, trivy, dotnet, maven, gradle
- **Extended installer** — `install.sh` now installs govulncheck, bundle-audit, cargo-audit, cargo-outdated and checks for dotnet, maven, gradle
- **72 Semgrep rules** across 7 languages (was 62 across 6): added `java.yaml` with 10 rules

### Fixed

- `run-outdated.sh` wildcard fallback missing `security` key in summary JSON
- `install.sh` banner showed `/shield full` instead of `/shield:shield full`
- README "Planned" labels replaced with actual tool names for all implemented ecosystems
- README Dependency Freshness table expanded from 5 to 11 ecosystems
- README prerequisites table updated with all new tools

## [0.2.0] - 2026-03-14

### Added

- **Security Auditor skill** (`/shield:audit`) — intelligence layer that complements tool-based scanning
  - Attack chain analysis for each SHIELD-XXX finding with exploitability rating
  - False positive detection and confirmation with reasoning
  - Logic vulnerability analysis (IDOR, race conditions, business logic flaws)
  - IaC security review (Dockerfile, Kubernetes, Terraform, GitHub Actions, nginx)
  - Architecture threat modeling (trust boundaries, attack surface mapping)
  - Adjusted risk score combining tool output + manual analysis
  - Works without any tools installed — pure reasoning
- **OWASP Top 10 reference** (`references/owasp-top10.md`) — compact reference with CWEs and code patterns
- **IaC security checklist** (`references/iac-checklist.md`) — Docker, k8s, Terraform, GitHub Actions, nginx
- **Cryptography guidance** (`references/crypto-guidance.md`) — passwords, AES, JWT, TLS, key management

## [0.1.1] - 2026-03-12

### Added

- **Security badge generator** (`scripts/generate-badge.sh`) — creates shields.io-compatible JSON badge from scan results
- **Self-scan report** (`docs/self-scan-report.md`) — Shield scanning its own codebase (100/100)
- **Shield logo** (`docs/logo.svg`) — minimalist `/shield` wordmark
- **Badge documentation** in README — how to add Shield Score badge to any project

### Fixed

- Plugin installation: `author` field in `plugin.json` changed from string to object format
- Marketplace name changed from `shield` to `shield-security` to avoid install confusion
- All invocation commands updated to use `/shield:shield` namespace for plugin installations
- Correct plugin registration instructions (`/plugin marketplace add` + `/plugin install`)

## [0.1.0] - 2026-03-11

### Added

- **Stack detection** for 9 ecosystems: JavaScript, TypeScript, Python, PHP, Go, Ruby, Rust, Java, C#
- **Vulnerability audit** via npm/yarn/pnpm audit, pip-audit, and composer audit with severity normalization
- **Static analysis** via Semgrep with 34 custom security rules (12 JS/TS, 11 Python, 11 PHP)
- **Secrets scanning** via gitleaks with severity classification and secret redaction
- **Shannon pentest orchestration** with automatic config generation for web-app, API-only, and SPA+API targets
- **Dependency freshness check** with SECURITY/MAJOR/MINOR/PATCH classification and SCA cross-referencing
- **Consolidation engine** that merges, deduplicates, and assigns SHIELD-XXX IDs to findings across all tools
- **Risk scoring** with weighted formula (CRITICAL x15, HIGH x8, MEDIUM x3, LOW x1) and 4-tier risk levels
- **Compliance mapping** to OWASP Top 10 2021, SOC 2, PCI-DSS, and HIPAA controls
- **SARIF 2.1.0 template** for GitHub Security tab integration
- **Report and issue templates** for structured markdown output
- **Shannon config templates** for 3 application types (web-app, api-only, spa-with-api)
- **Plugin structure** with `.claude-plugin/plugin.json` and marketplace manifest
- **Graceful degradation** — runs whatever tools are installed, skips the rest
- **install.sh** with cross-platform support (macOS/Linux), installs jq, Semgrep, gitleaks, Trivy, and Shannon
- **189 unit tests** across 4 test suites (detect-stack, check-prereqs, consolidate, calculate-score)
- 6 modes: full, quick, fix, verify, score, outdated

[0.3.0]: https://github.com/alissonlinneker/shield-claude-skill/releases/tag/v0.3.0
[0.2.0]: https://github.com/alissonlinneker/shield-claude-skill/releases/tag/v0.2.0
[0.1.1]: https://github.com/alissonlinneker/shield-claude-skill/releases/tag/v0.1.1
[0.1.0]: https://github.com/alissonlinneker/shield-claude-skill/releases/tag/v0.1.0
