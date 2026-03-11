---
name: shield
description: "Orchestrates security scanning and autonomous penetration testing. Runs Shannon pentester with Semgrep SAST, gitleaks secrets scanning, and dependency audits. Consolidates findings, proposes code fixes with diffs, calculates risk scores, and creates GitHub issues. Invoke with /shield."
---

# Shield — Security Orchestrator

## When to Invoke

- User requests security scan, vulnerability audit, or penetration test
- User says "check for secrets", "find security issues", "scan dependencies"
- Before production deployments
- After adding new dependencies or authentication flows
- User invokes `/shield`

## Modes

| Mode | Trigger | What Runs |
|------|---------|-----------|
| **full** | `/shield full` or `/shield URL=https://app.com` | Shannon pentest + all complementary tools |
| **quick** | `/shield` or `/shield quick` | Semgrep + gitleaks + package audit only |
| **fix** | `/shield fix` | Re-analyze existing report and propose fixes |
| **verify** | `/shield verify` | Re-scan to confirm fixes resolved findings |
| **score** | `/shield score` | Calculate and display security scorecard only |
| **outdated** | `/shield outdated` | Check for outdated dependencies (major/minor/patch behind) |

## Execution Protocol

### Step 1 — Prerequisites Check

Run `scripts/check-prereqs.sh` from the skill directory. This checks for:
- Docker availability (required for Shannon)
- Shannon installation (cloned repo with `./shannon` CLI)
- Semgrep (`semgrep` binary)
- gitleaks (`gitleaks` binary)
- Package audit tools (`npm audit`, `pip-audit`, `composer audit`)

Report which tools are available and which are missing with installation instructions.
If no tools are available at all, stop and provide installation guidance.
If at least one tool is available, proceed with what's available.

### Step 2 — Stack Detection

Run `scripts/detect-stack.sh` in the target project directory. Outputs JSON:
```json
{
  "languages": ["javascript", "typescript"],
  "frameworks": ["express", "react"],
  "package_manager": "npm",
  "has_dockerfile": true,
  "has_docker_compose": true,
  "entry_points": ["src/index.ts", "src/app.ts"]
}
```

### Step 3 — Shannon Pentest (Full Mode Only)

**Prerequisites:** Docker running, Shannon cloned, target app accessible at URL.

1. Run `scripts/generate-shannon-config.sh` with detected stack info to produce a Shannon YAML config
2. Copy/symlink the target repo into Shannon's `./repos/` directory
3. Run `scripts/run-shannon.sh` with URL and repo name
4. Monitor progress by polling `./shannon query ID=<workflow-id>` every 30 seconds
5. When complete, collect the report from Shannon's `audit-logs/` directory

### Step 4 — Complementary Scanning (Parallel)

Run all available tools in parallel:

**SAST (Semgrep):**
```bash
scripts/run-sast.sh <project-path> <language>
```
Uses language-specific rules from `configs/semgrep-rules/`.

**Secrets (gitleaks):**
```bash
scripts/run-secrets.sh <project-path>
```
Scans entire repository for hardcoded secrets, API keys, tokens.

**SCA (Package Audit):**
```bash
scripts/run-sca.sh <project-path> <package-manager>
```
Runs the appropriate audit command for the detected package manager.

**Dependency Freshness (all modes):**
```bash
scripts/run-outdated.sh <project-path> <package-manager>
```
Checks for outdated dependencies. Reports packages that are MAJOR, MINOR, or PATCH versions behind. Runs alongside the vulnerability audit for a complete dependency health picture.

### Step 5 — Consolidation

Run `scripts/consolidate.sh` to merge all tool outputs into a single normalized JSON:
```json
{
  "findings": [
    {
      "id": "SHIELD-001",
      "severity": "CRITICAL",
      "title": "SQL Injection in UserRepository",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "source_tool": "shannon",
      "file": "src/repositories/user.ts",
      "line": 45,
      "evidence": "...",
      "poc": "curl -X POST ...",
      "status": "exploited"
    }
  ],
  "metadata": {
    "scan_date": "2026-03-11",
    "mode": "full",
    "tools_used": ["shannon", "semgrep", "gitleaks", "npm-audit"],
    "tools_skipped": []
  }
}
```

### Step 6 — Risk Score Calculation

Run `scripts/calculate-score.sh` on the consolidated JSON.

Scoring formula (100 = perfect, 0 = critical risk):
- Start at 100
- Each CRITICAL finding: -15 points
- Each HIGH finding: -8 points
- Each MEDIUM finding: -3 points
- Each LOW finding: -1 point
- Minimum score: 0

Display as: `Security Score: 72/100 [██████████░░░░] MEDIUM RISK`

Thresholds:
- 90-100: LOW RISK (green)
- 70-89: MEDIUM RISK (yellow)
- 40-69: HIGH RISK (orange)
- 0-39: CRITICAL RISK (red)

### Step 7 — Report Enrichment

For EACH finding in the consolidated JSON, you MUST:

1. **Classify** — Map to CWE ID and OWASP Top 10 2021 category
2. **Explain impact** — Describe what an attacker could achieve, specific to this codebase
3. **Propose fix** — Generate a before/after diff showing the exact code change needed
4. **Compliance mapping** — Note which compliance frameworks this affects:
   - SOC 2: Trust Service Criteria reference
   - PCI-DSS: Requirement number
   - HIPAA: Safeguard reference (if healthcare data involved)

### Step 8 — Report Generation

Generate the report using `templates/report.md` structure.
Save to `reports/security-YYYY-MM-DD.md` in the project root.

If a previous report exists, perform **baseline diff**:
- NEW: findings not in previous report
- FIXED: findings in previous report but not current
- PERSISTENT: findings in both reports

### Step 9 — User Interaction

Present a summary table to the user with finding counts by severity and the security score.

Then ask: **"How would you like to proceed?"**

Options to offer:
1. **Review findings** — Walk through each finding with explanation and proposed fix
2. **Apply fixes** — Three sub-options:
   a. One by one (approve each individually)
   b. By severity (e.g., "Apply all CRITICAL fixes?")
   c. Report only (no fixes applied)
3. **Create GitHub issues** — One issue per finding using `templates/issue.md`
4. **Generate SARIF** — Output in SARIF format for GitHub Security tab
5. **Export compliance report** — Generate compliance-focused report

### Step 10 — Fix Verification (Optional)

After fixes are applied, offer to re-run the scan to verify the fixes resolved the findings.
Compare before/after scores and show improvement.

## Important Constraints

- NEVER run Shannon against targets you don't own or have authorization to test
- ALWAYS ask before creating GitHub issues (they notify the team)
- ALWAYS ask before applying code changes
- If Shannon is running, do NOT interrupt it — let the workflow complete
- Respect rate limits — Shannon uses significant API resources
- Reports may contain sensitive exploit details — warn about committing to public repos

## Report Template Location

Use the template at `templates/report.md` for generating security reports.
Use the template at `templates/issue.md` for generating GitHub issues.

## Installation Check

If the user hasn't installed Shield's dependencies yet, point them to `install.sh`:
```bash
# From the shield-claude-skill directory:
./install.sh
```

## Compliance Mapping Reference

| OWASP 2021 | SOC 2 | PCI-DSS | CWE Examples |
|------------|-------|---------|--------------|
| A01 Broken Access Control | CC6.1, CC6.3 | 6.5.8, 7.1 | 22, 284, 285, 639 |
| A02 Cryptographic Failures | CC6.1, CC6.7 | 3.4, 4.1, 6.5.3 | 259, 327, 328 |
| A03 Injection | CC6.1 | 6.5.1 | 20, 74, 79, 89 |
| A04 Insecure Design | CC3.2, CC5.2 | 6.3 | 209, 256, 501 |
| A05 Security Misconfiguration | CC6.1, CC7.1 | 2.2, 6.5.10 | 16, 611 |
| A06 Vulnerable Components | CC6.1 | 6.3.2 | 1035 |
| A07 Auth Failures | CC6.1, CC6.2 | 6.5.10, 8.1 | 287, 384 |
| A08 Data Integrity Failures | CC7.2 | 6.5.8 | 345, 502 |
| A09 Logging Failures | CC7.2, CC7.3 | 10.1 | 117, 223, 778 |
| A10 SSRF | CC6.1 | 6.5.9 | 918 |
