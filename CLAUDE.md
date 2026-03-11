# Shield Development Guide

## Project Overview

Security orchestrator skill that wraps Shannon (autonomous pentester) with complementary
security tools. Distributed as a standalone SKILL.md for code editor CLIs.

## Architecture

- `SKILL.md` — Skill entry point (markdown with YAML frontmatter)
- `scripts/` — Shell scripts for each security tool integration
- `configs/` — Semgrep rules and Shannon templates
- `templates/` — Report, issue, and SARIF output templates
- `tests/` — Bash-based unit tests

## Development Rules

- All code, comments, and documentation in English
- Shell scripts: `#!/usr/bin/env bash` with `set -euo pipefail`
- All scripts must pass `shellcheck --severity=error`
- Scripts output JSON to stdout, logs/errors to stderr
- Tests must be self-contained (no external tool dependencies)

## Testing

```bash
bash tests/run-tests.sh           # Run all tests
bash tests/test-detect-stack.sh   # Run single suite
npm test                          # Via package.json
```

## Key Conventions

- Finding IDs: `SHIELD-XXX` (sequential)
- Severity levels: CRITICAL, HIGH, MEDIUM, LOW
- Score formula: `100 - (CRITICAL*15 + HIGH*8 + MEDIUM*3 + LOW*1)`, min 0
- Shannon is called via CLI (`./shannon start`), never imported as a module
