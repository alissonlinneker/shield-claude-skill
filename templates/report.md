# Security Assessment Report — {{PROJECT_NAME}}

**Date:** {{SCAN_DATE}}
**Mode:** {{SCAN_MODE}}
**Stack:** {{DETECTED_STACK}}
**Tools Used:** {{TOOLS_USED}}
**Tools Unavailable:** {{TOOLS_SKIPPED}}

---

## Security Scorecard

**Score: {{SCORE}}/100 — {{RISK_LEVEL}}**

{{SCORE_BAR}}

| Severity | Count | Points Deducted |
|----------|-------|-----------------|
| CRITICAL | {{CRITICAL_COUNT}} | -{{CRITICAL_DEDUCTION}} |
| HIGH | {{HIGH_COUNT}} | -{{HIGH_DEDUCTION}} |
| MEDIUM | {{MEDIUM_COUNT}} | -{{MEDIUM_DEDUCTION}} |
| LOW | {{LOW_COUNT}} | -{{LOW_DEDUCTION}} |

{{#if BASELINE_DIFF}}
## Changes Since Last Scan ({{PREVIOUS_DATE}})

| Status | Count |
|--------|-------|
| New | {{NEW_COUNT}} |
| Fixed | {{FIXED_COUNT}} |
| Persistent | {{PERSISTENT_COUNT}} |

**Score Change:** {{SCORE_DELTA}}
{{/if}}

---

## Findings

{{#each FINDINGS}}
### [{{SEVERITY}}] {{TITLE}}

- **ID:** {{ID}}
- **File:** {{FILE}}:{{LINE}}
- **CWE:** {{CWE}}
- **OWASP:** {{OWASP}}
- **Tool:** {{SOURCE_TOOL}}
- **Status:** {{STATUS}}
{{#if BASELINE_STATUS}}- **Baseline:** {{BASELINE_STATUS}}{{/if}}

#### Description

{{DESCRIPTION}}

#### Impact

{{IMPACT}}

{{#if POC}}
#### Proof of Concept

```
{{POC}}
```
{{/if}}

#### Proposed Fix

```diff
{{FIX_DIFF}}
```

#### Compliance Impact

{{COMPLIANCE_MAPPING}}

---
{{/each}}

## Recommendations

{{RECOMMENDATIONS}}

## Appendix: Tool Versions

{{TOOL_VERSIONS}}
