<h1 align="center">Shield</h1>

<p align="center">
  <strong>Security orchestration for code editor CLIs.</strong><br>
  Autonomous pentests. Static analysis. Secrets scanning. Dependency audits. One command.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://github.com/alissonlinneker/shield-claude-skill/releases"><img src="https://img.shields.io/badge/version-0.1.0-green.svg" alt="Version 0.1.0"></a>
  <a href="docs/self-scan-report.md"><img src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Falissonlinneker%2Fshield-claude-skill%2Fmain%2Fshield-badge.json&query=%24.message&label=Shield%20Score&color=brightgreen" alt="Shield Score"></a>
  <a href="https://github.com/alissonlinneker/shield-claude-skill/stargazers"><img src="https://img.shields.io/github/stars/alissonlinneker/shield-claude-skill?style=social" alt="GitHub Stars"></a>
</p>

<p align="center"><em>One command. Full security posture. Actionable fixes.</em></p>

---

## What Shield Does

Shield detects your tech stack, runs every applicable security scanner in parallel, consolidates findings into a single report, calculates a risk score, proposes code fixes, and optionally files GitHub issues -- all without leaving your editor.

```
                                +-------------------+
                                | Shannon Pentest   |  Proof-by-exploitation, real PoCs
                                +-------------------+
                                | Semgrep SAST      |  34 custom rules + community rulesets
Your Code --> detect-stack.sh --| gitleaks Secrets   |  Full git history scan
                                | Dependency Audit   |  npm / pip / composer audit
                                | Freshness Check    |  Outdated dependency detection
                                +-------------------+
                                         |
                                   consolidate.sh
                                         |
                                  calculate-score.sh
                                         |
                        +----------------+----------------+
                        |                |                |
                  Risk Scorecard    Fix Proposals    GitHub Issues
                   (0-100)         (ready diffs)    (per finding)
```

## Quick Start

```bash
# 1. Clone and install security tools
git clone https://github.com/alissonlinneker/shield-claude-skill.git
cd shield-claude-skill && ./install.sh

# 2. Register the marketplace in Claude Code (run inside Claude Code)
/plugin marketplace add /path/to/shield-claude-skill

# 3. Install the plugin
/plugin install shield@shield-security

# 4. Open any project and run
/shield:shield
```

Or for quick testing without marketplace registration:

```bash
claude --plugin-dir /path/to/shield-claude-skill
# Then inside Claude Code:
/shield:shield
```

## Features

| Category | Capability | Details |
|----------|-----------|---------|
| **Pentest** | Autonomous penetration testing | Full attack-surface analysis via Shannon -- proof-by-exploitation with real PoC payloads |
| **SAST** | Static application security testing | Semgrep with 34 custom rules (12 JS/TS, 11 Python, 11 PHP) plus community rulesets |
| **Secrets** | Secrets scanning | gitleaks detection across entire git history -- keys, tokens, passwords |
| **SCA** | Dependency vulnerability audit | npm/yarn/pnpm audit, pip-audit, composer audit -- auto-detected by lock file |
| **Freshness** | Dependency outdated check | Detects packages behind on MAJOR, MINOR, and PATCH versions |
| **Scoring** | Security scorecard | Weighted 0-100 risk score with severity breakdown |
| **Remediation** | Fix proposals | Generates before/after diffs you can apply directly |
| **Baselines** | Scan comparison | Tracks improvements and regressions between scans |
| **Issues** | GitHub issue creation | Files issues with severity labels, CWE references, and compliance mappings |
| **SARIF** | Standard output format | SARIF export for GitHub Security tab integration |
| **Compliance** | Compliance mapping | Maps findings to SOC 2, PCI-DSS, and HIPAA controls |
| **Zero-config** | Stack detection | Automatically identifies languages, frameworks, package managers, Docker presence |
| **Resilience** | Graceful degradation | Runs whichever tools are installed, skips the rest, notes gaps in report |

## Real Output Examples

### Example 1 -- Quick Scan on a Node.js Project

```
Stack detected: JavaScript, TypeScript, Next.js, React (pnpm)

Security Score: 0/100 — CRITICAL RISK
[                              ] 0/100

| Severity | Count |
|----------|-------|
| CRITICAL |     1 |
| HIGH     |    20 |
| MEDIUM   |     5 |
| LOW      |     3 |

Top findings:
  [CRITICAL] SHIELD-001: fast-xml-parser regex injection bypass (CWE-185)
             Package: fast-xml-parser | Fix: Update to 4.4.1+
  [HIGH]     SHIELD-002: brace-expansion ReDoS (CWE-1333)
             Package: brace-expansion | Fix: Update to 2.0.1+
  [HIGH]     SHIELD-003: tar hardlink path traversal (CWE-22)
             Package: tar | Fix: Update to 6.2.1+
  [HIGH]     SHIELD-004: micromatch ReDoS via recursive patterns (CWE-1333)
             Package: micromatch | Fix: Update to 4.0.8+

Outdated dependencies: 47 packages behind latest
  MAJOR: 12 packages (breaking changes, potential security risk)
  MINOR: 18 packages (may include security fixes)
  PATCH: 17 packages (bug fixes, security patches)
```

### Example 2 -- Clean Scan on a PHP Project

```
Stack detected: PHP, Laravel, Composer, Docker

Security Score: 100/100 — LOW RISK
[##############################] 100/100

| Severity | Count |
|----------|-------|
| CRITICAL |     0 |
| HIGH     |     0 |
| MEDIUM   |     0 |
| LOW      |     0 |

No vulnerabilities found across all scanners.
All dependencies are up to date.
```

### Example 3 -- Consolidated JSON Output

```json
{
  "findings": [
    {
      "id": "SHIELD-001",
      "severity": "CRITICAL",
      "title": "SQL Injection in UserRepository",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "source_tool": "semgrep",
      "file": "src/repositories/user.ts",
      "line": 45,
      "evidence": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
      "recommendation": "Use parameterized queries",
      "status": "new"
    }
  ],
  "metadata": {
    "scan_date": "2026-03-11",
    "scan_timestamp": "2026-03-11T14:30:00Z",
    "tools_used": ["semgrep", "gitleaks", "npm-audit"],
    "tools_skipped": ["shannon"],
    "total_files_scanned": 142
  },
  "summary": {
    "total": 29,
    "by_severity": { "critical": 1, "high": 20, "medium": 5, "low": 3 },
    "by_tool": { "semgrep": 8, "gitleaks": 0, "npm-audit": 21 },
    "by_cwe": { "CWE-89": 1, "CWE-1333": 5, "CWE-22": 3 }
  }
}
```

### Example 4 -- Security Scorecard Breakdown

```json
{
  "score": 45,
  "max_score": 100,
  "risk_level": "HIGH",
  "breakdown": {
    "critical": { "count": 1, "weight": 15, "deduction": 15 },
    "high":     { "count": 3, "weight": 8,  "deduction": 24 },
    "medium":   { "count": 4, "weight": 3,  "deduction": 12 },
    "low":      { "count": 4, "weight": 1,  "deduction": 4 }
  },
  "total_deduction": 55,
  "total_findings": 12
}
```

## Modes

| Mode | Command | Description |
|------|---------|-------------|
| **Full** | `/shield:shield full` | Complete assessment -- Shannon pentest + SAST + secrets + SCA + freshness + scorecard |
| **Quick** | `/shield:shield quick` | Fast scan -- SAST + secrets + dependency audit + freshness (no pentest) |
| **Fix** | `/shield:shield fix` | Auto-remediation -- analyzes findings and generates ready-to-apply diffs |
| **Verify** | `/shield:shield verify` | Re-scan after fixes -- confirms issues are resolved, compares against baseline |
| **Score** | `/shield:shield score` | Scorecard only -- calculates risk score from last scan or fresh data |
| **Outdated** | `/shield:shield outdated` | Dependency freshness check -- lists all outdated packages by severity tier |

## Prerequisites

| Tool | Required | Purpose | Install |
|------|----------|---------|---------|
| [Semgrep](https://semgrep.dev/) | Recommended | Static analysis (SAST) | `brew install semgrep` or `pip install semgrep` |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Recommended | Secrets scanning | `brew install gitleaks` |
| [jq](https://jqlang.github.io/jq/) | Required | JSON processing for consolidation | `brew install jq` |
| [Trivy](https://trivy.dev/) | Optional | Container and IaC scanning (v0.2.0) | `brew install trivy` |
| [Shannon](https://github.com/KeygraphHQ/shannon) | Optional | Autonomous penetration testing | `git clone` + Docker |
| [Docker](https://www.docker.com/) | Optional | Required for Shannon pentest | `brew install --cask docker` |
| npm / yarn / pnpm | Auto-detected | Node.js dependency audit + freshness | Bundled with Node.js |
| [pip-audit](https://pypi.org/project/pip-audit/) | Auto-detected | Python dependency audit | `pip install pip-audit` |
| [Composer](https://getcomposer.org/) | Auto-detected | PHP dependency audit + freshness | `brew install composer` |

> **Graceful degradation:** Shield runs whatever tools are installed. Missing a tool? Shield skips that scanner and notes it in the report. Install more tools later for deeper coverage.

## Installation

### Automated (Recommended)

```bash
git clone https://github.com/alissonlinneker/shield-claude-skill.git
cd shield-claude-skill
chmod +x install.sh
./install.sh
```

The install script detects your OS, installs available tools via the appropriate package manager (Homebrew on macOS, apt/pip on Linux), and validates the setup.

### Manual

Install individual tools as needed:

```bash
# macOS (Homebrew)
brew install semgrep gitleaks trivy jq

# Linux (pip + apt)
pip install semgrep pip-audit
apt install gitleaks jq   # or download from GitHub releases
apt install trivy          # or add Aqua Security repo

# Shannon (optional -- requires Docker)
git clone https://github.com/KeygraphHQ/shannon.git ~/shannon
```

### Plugin Registration (Claude Code)

From inside Claude Code, register the marketplace and install:

```bash
# Option A: From local clone
/plugin marketplace add /path/to/shield-claude-skill
/plugin install shield@shield-security

# Option B: From GitHub
/plugin marketplace add alissonlinneker/shield-claude-skill
/plugin install shield@shield-security

# Verify installation
/plugin list
```

For development and testing, load directly without installing:

```bash
claude --plugin-dir /path/to/shield-claude-skill
```

After installation, the skill is available as `/shield:shield` in any project. Run `/reload-plugins` if you update the plugin files.

## Usage Examples

### Full Security Assessment

```
/shield:shield full
```

Runs all available scanners including Shannon pentest (requires Docker and a target URL), generates a scorecard, and produces a comprehensive markdown report with fix proposals.

### Quick Scan

```
/shield:shield quick
```

Runs SAST, secrets scanning, dependency audit, and freshness check. Skips penetration testing for speed. Best for development workflow integration.

### Auto-Remediation

```
/shield:shield fix
```

Analyzes existing findings and generates before/after diffs for each vulnerability. You approve which fixes to apply, one by one or by severity tier.

### Verify Fixes

```
/shield:shield verify
```

Re-runs all scanners and compares against the previous baseline. Shows new issues, resolved issues, persistent issues, and score delta.

### Scorecard Only

```
/shield:shield score
```

Calculates the security risk score (0-100) from available scan data. Fast way to check posture without running a full scan.

### Dependency Freshness

```
/shield:shield outdated
```

Checks all installed packages against their latest published versions. Reports MAJOR, MINOR, and PATCH version gaps.

> **Note:** When installed as a standalone skill (not via plugin), use `/shield` instead of `/shield:shield`. The `:shield` namespace is only needed for plugin installations.

## Configuration

Shield works with **zero configuration** -- it automatically detects your tech stack by scanning for lock files, config files, and source code patterns. No YAML pipelines or config files needed.

For advanced customization:

| What | Where | Details |
|------|-------|---------|
| Custom SAST rules | `configs/semgrep-rules/*.yaml` | Add Semgrep YAML rule files per language |
| Shannon templates | `configs/shannon-templates/*.yaml` | Pentest configuration for different app architectures |
| Report template | `templates/report.md` | Customize the markdown report structure |
| Issue template | `templates/issue.md` | Customize GitHub issue format |
| SARIF template | `templates/sarif.json` | Customize SARIF export structure |

### Included Shannon Templates

| Template | Use Case |
|----------|----------|
| `web-app.yaml` | Traditional server-rendered web applications |
| `spa-with-api.yaml` | Single-page applications with REST/GraphQL backends |
| `api-only.yaml` | Headless API services |

## Security Scorecard

Shield calculates a **risk score from 0 to 100** using a weighted penalty system across all findings from every scanner.

### Scoring Formula

```
Score = max(0, 100 - Penalties)

Penalties:
  CRITICAL findings  x 15 points each
  HIGH     findings  x  8 points each
  MEDIUM   findings  x  3 points each
  LOW      findings  x  1 point each
```

### Risk Levels

| Score Range | Risk Level | Action |
|-------------|------------|--------|
| 90-100 | **LOW RISK** | Minimal issues -- maintain current posture |
| 70-89 | **MEDIUM RISK** | Minor issues -- action recommended |
| 40-69 | **HIGH RISK** | Significant vulnerabilities -- remediation needed |
| 0-39 | **CRITICAL RISK** | Severe exposure -- immediate action required |

### Worked Examples

**Project A** -- 1 CRITICAL, 5 HIGH, 2 MEDIUM findings:
```
100 - (1x15 + 5x8 + 2x3) = 100 - (15 + 40 + 6) = 100 - 61 = 39/100 --> CRITICAL RISK
```

**Project B** -- 0 CRITICAL, 2 HIGH, 4 MEDIUM, 3 LOW findings:
```
100 - (0 + 2x8 + 4x3 + 3x1) = 100 - (16 + 12 + 3) = 100 - 31 = 69/100 --> HIGH RISK
```

**Project C** -- 0 CRITICAL, 0 HIGH, 1 MEDIUM, 2 LOW findings:
```
100 - (0 + 0 + 1x3 + 2x1) = 100 - 5 = 95/100 --> LOW RISK
```

## Dependency Freshness

Beyond vulnerability scanning, Shield checks whether your dependencies are up to date. Outdated packages are a leading vector for security incidents -- patches you never installed cannot protect you.

### Version Gap Tiers

| Tier | Meaning | Risk |
|------|---------|------|
| **MAJOR** version behind | Breaking changes between your version and latest | High -- may include security architecture changes |
| **MINOR** version behind | New features and potential security enhancements missed | Medium -- often includes security hardening |
| **PATCH** version behind | Bug fixes and security patches not applied | Varies -- frequently contains CVE fixes |

### How It Works

Shield uses native package manager commands for accurate, lockfile-aware checks:

| Ecosystem | Command | Output |
|-----------|---------|--------|
| npm | `npm outdated --json` | Current vs. wanted vs. latest for each package |
| yarn | `yarn outdated --json` | NDJSON table with current, wanted, latest |
| pnpm | `pnpm outdated --format json` | Same structure, workspace-aware |
| pip | `pip list --outdated --format json` | Installed vs. latest version |
| Composer | `composer outdated --format json` | Direct and transitive dependency status |

Freshness data is included in the consolidated report and factored into remediation recommendations.

## Compliance Mapping

Every finding is mapped to relevant compliance framework controls:

| Framework | Coverage | Control References |
|-----------|----------|-------------------|
| **SOC 2** | Trust Services Criteria | CC6.1 (Logical Access), CC6.3 (Role-Based Access), CC6.7 (Data-in-Transit), CC6.8 (Input Controls), CC7.1 (System Monitoring) |
| **PCI-DSS** | Requirements 6, 7, 11 | 6.5.x (Secure Development), 6.6 (Application Firewall), 7.1 (Access Control), 11.3 (Penetration Testing) |
| **HIPAA** | Technical Safeguards | 164.312(a) Access Controls, 164.312(e) Transmission Security |

### OWASP Top 10 Cross-Reference

| OWASP 2021 | SOC 2 | PCI-DSS | Example CWEs |
|------------|-------|---------|--------------|
| A01 Broken Access Control | CC6.1, CC6.3 | 6.5.8, 7.1 | CWE-22, CWE-284, CWE-285, CWE-639 |
| A02 Cryptographic Failures | CC6.1, CC6.7 | 3.4, 4.1, 6.5.3 | CWE-259, CWE-327, CWE-328 |
| A03 Injection | CC6.1 | 6.5.1 | CWE-20, CWE-74, CWE-79, CWE-89 |
| A04 Insecure Design | CC3.2, CC5.2 | 6.3 | CWE-209, CWE-256, CWE-501 |
| A05 Security Misconfiguration | CC6.1, CC7.1 | 2.2, 6.5.10 | CWE-16, CWE-611 |
| A06 Vulnerable Components | CC6.1 | 6.3.2 | CWE-1035 |
| A07 Auth Failures | CC6.1, CC6.2 | 6.5.10, 8.1 | CWE-287, CWE-384 |
| A08 Data Integrity Failures | CC7.2 | 6.5.8 | CWE-345, CWE-502 |
| A09 Logging Failures | CC7.2, CC7.3 | 10.1 | CWE-117, CWE-223, CWE-778 |
| A10 SSRF | CC6.1 | 6.5.9 | CWE-918 |

## Supported Ecosystems

| Ecosystem | Stack Detection | Vulnerability Audit | Outdated Check | SAST Rules |
|-----------|:-:|:-:|:-:|:-:|
| **Node.js** (npm/yarn/pnpm) | Yes | npm/yarn/pnpm audit | npm/yarn/pnpm outdated | 12 rules |
| **Python** (pip/pipenv/poetry) | Yes | pip-audit | pip list --outdated | 11 rules |
| **PHP** (Composer) | Yes | composer audit | composer outdated | 11 rules |
| **Go** | Yes | Planned | Planned | Planned |
| **Ruby** | Yes | Planned | Planned | Planned |
| **Rust** | Yes | Planned | Planned | Planned |
| **Java** (Maven/Gradle) | Yes | Planned | Planned | Planned |
| **C#** (.NET) | Yes | Planned | Planned | Planned |

Stack detection works for all ecosystems listed above. Vulnerability auditing, freshness checks, and custom SAST rules are active for Node.js, Python, and PHP, with more languages on the roadmap.

## Architecture

Shield is built as a collection of focused shell scripts, each responsible for one task. Scripts communicate via JSON on stdout, with logs on stderr.

```
scripts/
  check-prereqs.sh         # Validates installed tools
  detect-stack.sh           # Identifies languages, frameworks, package managers
  run-sast.sh               # Runs Semgrep with language-specific rule configs
  run-secrets.sh            # Runs gitleaks across git history
  run-sca.sh                # Runs package manager audit (npm/pip/composer)
  run-outdated.sh           # Checks for outdated dependencies with security cross-ref
  run-shannon.sh            # Orchestrates Shannon pentest workflow
  generate-shannon-config.sh # Generates Shannon YAML from detected stack
  setup-shannon.sh          # Initial Shannon installation helper
  consolidate.sh            # Merges + deduplicates findings, assigns SHIELD IDs
  calculate-score.sh        # Computes weighted risk score from findings

configs/
  semgrep-rules/            # Custom Semgrep YAML rules (JS, Python, PHP)
  shannon-templates/        # Pentest configs (web-app, SPA, API-only)

templates/
  report.md                 # Markdown report template with Handlebars placeholders
  issue.md                  # GitHub issue template
  sarif.json                # SARIF output template
```

### Design Principles

- **Each script does one thing.** JSON in, JSON out. No hidden state.
- **Graceful degradation.** Missing tools are skipped, not fatal. The report notes what was unavailable.
- **Zero config by default.** Stack detection makes configuration optional for most projects.
- **Deterministic IDs.** Findings get stable `SHIELD-XXX` identifiers for tracking across scans.

## Shannon Integration

Shield wraps the [Shannon autonomous pentester](https://github.com/KeygraphHQ/shannon) to deliver proof-by-exploitation security testing.

### What Shannon Provides

- **Real attack simulation** -- not signature matching, actual exploitation attempts
- **Proof-of-concept payloads** -- concrete `curl` commands and request bodies that demonstrate each vulnerability
- **Attack surface mapping** -- discovers endpoints, parameters, and authentication flows automatically
- **Workflow-based execution** -- runs multi-step attack chains, not just single-request probes

### What Shield Adds on Top

- **Stack-aware configuration** -- `generate-shannon-config.sh` produces Shannon YAML tuned to your detected framework (Express, Django, Laravel, etc.)
- **Finding normalization** -- Shannon results are merged with SAST/SCA/secrets findings into unified `SHIELD-XXX` format
- **Risk scoring** -- Shannon findings are weighted alongside other tools in the 0-100 scorecard
- **Fix proposals** -- Shield generates code diffs to remediate issues Shannon discovered
- **GitHub issues** -- One-click issue creation with PoC details, severity labels, and CWE tags

### Requirements

- Docker (running)
- Shannon cloned locally (`git clone https://github.com/KeygraphHQ/shannon.git`)
- Target application accessible via URL

### Included Templates

| Template | Target Architecture |
|----------|-------------------|
| `web-app.yaml` | Server-rendered apps (Express, Django, Laravel, Rails) |
| `spa-with-api.yaml` | SPAs with REST/GraphQL backends (React+Express, Vue+FastAPI) |
| `api-only.yaml` | Headless APIs and microservices |

## Security Badge

After scanning your project with Shield, you can add a security score badge to your README. This shows visitors that your project is actively monitored for vulnerabilities.

### Generate the Badge

After running `/shield:shield`, generate the badge file:

```bash
# From your project root (after a scan):
bash /path/to/shield-claude-skill/scripts/generate-badge.sh /tmp/consolidated.json > shield-badge.json
```

Or ask Shield to generate it as part of the scan — it will create `shield-badge.json` in your project root.

### Add to Your README

Commit `shield-badge.json` to your repo, then add this to your README:

```markdown
![Shield Score](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FYOUR_USER%2FYOUR_REPO%2Fmain%2Fshield-badge.json&query=%24.message&label=Shield%20Score&style=flat)
```

Replace `YOUR_USER` and `YOUR_REPO` with your GitHub username and repository name.

### Badge Examples

| Score | Badge |
|-------|-------|
| 100/100 | ![Shield Score](https://img.shields.io/badge/Shield_Score-100%2F100-brightgreen) |
| 85/100 | ![Shield Score](https://img.shields.io/badge/Shield_Score-85%2F100-yellow) |
| 55/100 | ![Shield Score](https://img.shields.io/badge/Shield_Score-55%2F100-orange) |
| 20/100 | ![Shield Score](https://img.shields.io/badge/Shield_Score-20%2F100-red) |

### Keep It Updated

Re-run `/shield:shield` periodically and regenerate the badge to keep your score current. The badge reads from the JSON file in your repo, so it updates automatically when you push a new `shield-badge.json`.

## Contributing

Contributions are welcome. Please follow this workflow:

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Write your changes with tests
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`)
5. Push to your fork and open a Pull Request
6. Ensure tests pass

### Development

```bash
# Run the test suite
npm test

# Lint shell scripts (requires shellcheck)
npm run lint

# Install all security tool dependencies
npm run install-deps
```

### Adding SAST Rules

Custom Semgrep rules live in `configs/semgrep-rules/`. Each file targets one language:

```
configs/semgrep-rules/
  javascript.yaml   # 12 rules: injection, XSS, prototype pollution, etc.
  python.yaml       # 11 rules: SQLi, command injection, SSTI, etc.
  php.yaml          # 11 rules: SQLi, file inclusion, deserialization, etc.
```

Follow [Semgrep's rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax/) and include `cwe`, `owasp`, and `severity` metadata in each rule.

### Reporting Security Issues

If you discover a security vulnerability in Shield itself, please report it responsibly. Do **not** open a public issue. Instead, use [GitHub's Security Advisory feature](https://github.com/alissonlinneker/shield-claude-skill/security/advisories/new) to report it privately.

## License

[MIT](LICENSE) -- Copyright (c) 2026 ALASTecnology

## Acknowledgments

- **[Shannon](https://github.com/KeygraphHQ/shannon)** by KeygraphHQ -- Autonomous penetration testing engine
- **[Semgrep](https://semgrep.dev/)** by Semgrep, Inc. -- Static analysis and pattern matching
- **[gitleaks](https://github.com/gitleaks/gitleaks)** by Zaqueri Adams -- Secrets detection across git history
- **[Trivy](https://trivy.dev/)** by Aqua Security -- Vulnerability scanning for containers and IaC
