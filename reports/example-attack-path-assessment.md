# AD CS Attack-Path Assessment

Synthetic defensive analysis only. No live-domain enumeration or certificate abuse is performed.

## Executive Summary

The sample relationship set demonstrates how certificate-template configuration and enrollment scope can combine into identity-risk paths. The highest-priority synthetic path originates from `UserAuthentication`, where authentication capability, broad enrollment, requester-controlled subject data, missing issuance approval, exportable private keys, and privileged-boundary context are all present.

## Representative Finding

### ADCS-PATH synthetic critical path

- Template: `UserAuthentication`
- Principal: `Domain Users`
- Relationship: `enrollable_by`
- Target boundary: Privileged Identity Boundary
- ATT&CK: T1649, T1078
- Risk drivers: authentication-capable EKU; broad enrollment principal; requester-controlled subject data; no independent issuance approval; exportable private key; privileged identity boundary

**Impact:** the combination weakens identity assurance and increases the chance that certificate issuance could create a material privilege path if equivalent conditions existed in a real environment.

**Remediation:** restrict enrollment, remove unnecessary requester-controlled identity fields and authentication EKUs, disable exportable keys where not required, and add issuance approval for sensitive workflows.

**Validation:** reassess the remediated configuration and confirm that the original path no longer meets critical/high-risk conditions. Closure should also include an accountable owner, change reference, post-change review, and passing validation result.

## Governance Notes

Risk acceptance is tracked separately from technical exposure. An exception requires an owner, approver, rationale, review reference, and expiry date. Expired or incomplete exceptions do not qualify as valid governance evidence.
