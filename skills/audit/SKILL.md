---
name: audit
description: >
  Intelligence-driven security analysis — the reasoning layer that complements Shield's
  tool-based scanning. Use this skill when the user says "analyze these findings",
  "explain this vulnerability", "is this exploitable", "false positive?", "fix this security
  issue", "threat model this", "audit my Dockerfile/Terraform/k8s/GitHub Actions",
  "harden this config", "review my auth code", "is this JWT safe", "check for secrets",
  or pastes Shield's consolidated.json for deeper analysis. Also trigger on any security
  question after `/shield:shield` has run. Works without any tools installed — pure
  Claude intelligence. Part of the Shield plugin (github.com/alissonlinneker/shield-claude-skill).
---

# Security Auditor — Intelligence Layer for Shield

Shield runs the tools. This skill provides the brain.

**When Shield output is available:** enriches every `SHIELD-XXX` finding with attack chains,
exploitability assessment, fix code, and false-positive analysis.

**Without Shield output:** performs full static security analysis on any code, IaC, or config
using OWASP Top 10 reasoning, logic vulnerability detection, and the reference files below.

## Reference files — load as needed

- `references/owasp-top10.md` — load when analyzing application code (injection, auth, XSS, etc.)
- `references/iac-checklist.md` — load when reviewing Dockerfile, k8s YAML, Terraform, GitHub Actions, nginx
- `references/crypto-guidance.md` — load when crypto issues arise (passwords, JWT, TLS, random, AES)

Only load the reference file relevant to the current analysis. All three together = ~9KB context.

---

## Input modes

| Mode | Trigger | What to do |
|------|---------|-----------|
| **Shield companion** | User pastes `consolidated.json` or runs `/shield:audit` after a scan | Enrich each SHIELD-XXX finding |
| **Code audit** | User pastes source code or uploads a file | Full OWASP analysis, 6 layers |
| **IaC audit** | Dockerfile, k8s, Terraform, CI YAML | Load `iac-checklist.md`, produce hardened version |
| **Focused question** | "Is this JWT safe?" / "Can this be injected?" | Direct answer, no full report |
| **Threat model** | Architecture description, API spec, data flow | Assets, trust boundaries, attack vectors |

---

## Shield companion mode (primary use case)

When the user provides Shield's `consolidated.json`, process each finding:

```
## Enhanced Analysis: SHIELD-001
Tool: semgrep | Severity: CRITICAL | CWE: CWE-89

Confirmed? YES / LIKELY / FALSE POSITIVE
[Reasoning from code context]

Exploitability: Trivial / Easy / Moderate / Hard / Theoretical
[Why: "Endpoint is public, no auth required, input reaches sink in 2 hops"]

Attack chain:
1. Attacker sends: GET /users?id=1 OR 1=1--
2. Input reaches db.query() at user.ts:45 without sanitization
3. Result: full users table returned — credentials, emails, PII

Fix (complete, runnable):
[corrected code with inline comments explaining each security change]

OWASP: A03:2021 Injection | Compliance: PCI-DSS 6.5.1, SOC 2 CC6.1
```

After all findings, add:

```
## Findings Shield missed (logic/architecture)
[Vulnerabilities tools cannot detect: business logic flaws, IDOR, race conditions]

## False positive analysis
[Shield findings that appear to be false positives, with reasoning]

## Combined risk score
Shield score: XX/100
Manual analysis delta: [+/-] because [reason]
Adjusted score: YY/100
```

---

## Full audit — 6 layers

When given code to audit without Shield output:

### Layer 1 — Attack surface mapping
Entry points, trust boundaries, sensitive assets, external dependencies, auth perimeter.

### Layer 2 — OWASP Top 10 analysis
Load `references/owasp-top10.md`. For each finding:

```
[SEVERITY] [CWE-XXX] Title
Location: file:line | Confidence: HIGH/MEDIUM/LOW

Attack chain:
1. [specific input] → [specific function] → [missing control] → [impact]

Evidence:
  [exact vulnerable code]

Fix:
  [corrected code + one-line explanation]
```

Severity: CRITICAL (RCE, auth bypass) | HIGH (SQLi, XSS, SSRF) | MEDIUM (CSRF, weak crypto) | LOW (headers, info disclosure) | INFO (best practice)

### Layer 3 — Logic vulnerabilities (tools miss these)

- **Broken business logic:** rate limit bypass, negative prices, TOCTOU, state machine skips
- **Auth/authz:** JWT alg:none/kid injection/weak secret, IDOR, OAuth state missing, session fixation
- **Crypto misuse:** ECB mode, reused IVs, timing attacks (`==` vs `hmac.compare_digest`), `Math.random()` for tokens
- **Race conditions:** check-then-act, double-spend, insufficient locking

### Layer 4 — IaC & infrastructure
Load `references/iac-checklist.md` when Dockerfile, k8s, Terraform, or CI/CD files are present.

### Layer 5 — Secrets & credentials
API keys, private keys, DB connection strings, base64-encoded secrets, credentials in comments or URLs.
For each: identify service, assess if real vs placeholder, recommend rotation + secrets manager migration.

### Layer 6 — Dependencies (pattern-based, no live CVE lookup)
Known vulnerable package patterns, typosquatting risk, unpinned versions.
Note: for live CVE data → run `/shield:shield quick` (SCA scanner).

---

## Output format

```markdown
# Security Audit Report
Component: [name] | Date: [today] | Scope: [what was reviewed]
Summary: X critical, Y high, Z medium, W low

Risk Score: XX/100

## Attack Surface
[Layer 1 output]

## Findings
[One block per finding, format above]

## What's secure ✓
[2–4 specific things done well — always include]

## Priority fix order
1. [Fix today — why]
2. [Next sprint — why]
3. [Nice to have — why]

## Shield integration note
[If Shield ran: "N findings confirmed, M appear to be false positives"]
[If Shield not installed: "Run /shield:shield for dependency CVEs and git history secrets scan"]
```

---

## Fix code standards

Every fix must be: **runnable** (not pseudocode), **idiomatic** (language best practices), **explained** (one comment per change), **non-breaking** (preserves functionality).

```python
# BEFORE (vulnerable):
query = f"SELECT * FROM users WHERE email = '{email}'"

# AFTER — parameterized query separates code from data.
# DB driver handles escaping; user input never reaches the SQL parser.
query = "SELECT * FROM users WHERE email = %s"
cursor.execute(query, (email,))
```

---

## Scope honesty — always be explicit

- "This covers the auth module only. Payment processing was not reviewed."
- "Cannot confirm SSRF without seeing `validateUrl()` — not provided."
- "SHIELD-042 appears to be a false positive: `escape()` at line 18 sanitizes before the sink at line 34."
- "For live CVE data, this analysis cannot substitute for Shield's SCA scanner."

**Never fabricate CVE IDs.** Describe the vulnerability pattern without asserting a specific CVE number if uncertain.
