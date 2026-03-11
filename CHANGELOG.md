# Changelog

All notable changes to Shield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/alissonlinneker/shield-claude-skill/releases/tag/v0.1.0
