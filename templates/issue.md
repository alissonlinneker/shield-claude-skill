## [{{SEVERITY}}] {{TITLE}}

**Shield Finding ID:** {{ID}}
**CWE:** {{CWE}}
**OWASP:** {{OWASP}}

### Location

`{{FILE}}:{{LINE}}`

### Description

{{DESCRIPTION}}

### Impact

{{IMPACT}}

{{#if POC}}
### Proof of Concept

```
{{POC}}
```
{{/if}}

### Proposed Fix

```diff
{{FIX_DIFF}}
```

### References

- [CWE-{{CWE_ID}}](https://cwe.mitre.org/data/definitions/{{CWE_ID}}.html)
- [OWASP {{OWASP}}](https://owasp.org/Top10/{{OWASP_LINK}}/)

### Compliance

{{COMPLIANCE_MAPPING}}

---
*Detected by Shield Security Scanner*
