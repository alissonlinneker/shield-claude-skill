# Shield MVP Design — v0.1.0

## Overview

Security skill for code editor CLIs that orchestrates Shannon (autonomous pentester) with
complementary security tools (Semgrep, gitleaks, package audits), consolidates findings,
proposes code fixes, and integrates with GitHub issue tracking.

## Core Decisions

| Decision | Choice |
|----------|--------|
| Primary tool | Shannon (autonomous pentest via Docker) |
| Complementary tools | Semgrep (SAST), gitleaks (secrets), npm/pip/composer audit (SCA) |
| Fallback | Graceful degradation — runs whatever tools are available |
| Fix proposals | User chooses: individual approval, batch, or report-only |
| GitHub issues | Ask before creating |
| Persistence | `reports/security-YYYY-MM-DD.md` in repository |
| License | MIT (Shannon called externally, no AGPL contamination) |
| Distribution | Standalone skill (SKILL.md) + marketplace publishing |

## Unique Differentiators

1. **Proof-by-exploitation** — Shannon proves vulnerabilities with working PoC exploits
2. **Auto-remediation proposals** — Contextual diffs for every finding
3. **Multi-tool orchestration** — Single command runs Shannon + 3 complementary tools
4. **Security scorecard** — 0-100 risk score with badge for README
5. **Baseline diffing** — Compare scans over time (new/fixed/persistent)
6. **Compliance mapping** — Findings mapped to SOC2, HIPAA, PCI-DSS controls
7. **SARIF output** — GitHub Security tab integration
8. **Fix verification loop** — Re-scan after fixes to confirm resolution
9. **Zero-config start** — Auto-detects stack, generates Shannon config
10. **Pre-commit hook** — Quick scan on staged files before commit

## Architecture

```
shield-claude-skill/
├── SKILL.md
├── README.md
├── LICENSE
├── package.json
├── install.sh
├── scripts/
│   ├── check-prereqs.sh
│   ├── detect-stack.sh
│   ├── setup-shannon.sh
│   ├── generate-shannon-config.sh
│   ├── run-shannon.sh
│   ├── run-sast.sh
│   ├── run-sca.sh
│   ├── run-secrets.sh
│   ├── consolidate.sh
│   └── calculate-score.sh
├── configs/
│   ├── semgrep-rules/
│   │   ├── javascript.yaml
│   │   ├── python.yaml
│   │   └── php.yaml
│   └── shannon-templates/
│       ├── web-app.yaml
│       ├── api-only.yaml
│       └── spa-with-api.yaml
├── templates/
│   ├── report.md
│   ├── issue.md
│   └── sarif.json
├── tests/
│   ├── test-detect-stack.sh
│   ├── test-check-prereqs.sh
│   ├── test-consolidate.sh
│   └── test-calculate-score.sh
└── docs/
    ├── installation.md
    ├── usage.md
    └── configuration.md
```

## Execution Flow

1. User invokes `/shield` with optional URL and mode flags
2. `check-prereqs.sh` — verifies Docker, Shannon, tools
3. `detect-stack.sh` — identifies language/framework/package manager
4. If Shannon available: `run-shannon.sh` starts pentest
5. In parallel: `run-sast.sh`, `run-sca.sh`, `run-secrets.sh`
6. Monitor Shannon progress via `./shannon query`
7. `consolidate.sh` — merge all outputs into normalized JSON
8. `calculate-score.sh` — compute security risk score
9. Agent enriches: CWE/OWASP mapping, fix proposals, compliance mapping
10. Save `reports/security-YYYY-MM-DD.md`
11. Present summary with scorecard
12. Offer: apply fixes? create issues? generate SARIF?
