# Assessment Methodology

## Review Scope

The methodology evaluates synthetic AD CS configuration through three control families:

1. **Certificate template trust controls** — enrollment scope, authentication EKUs, subject-name handling, issuance approval, key exportability, validity, and ownership.
2. **Certification authority controls** — enrollment transport and audit configuration.
3. **Governance controls** — ownership, reviewability, and evidence-driven remediation.

## Risk Classification

| Severity | Interpretation |
|---|---|
| Critical | Configuration can materially weaken an identity trust boundary and warrants immediate review. |
| High | Significant identity or issuance-control weakness requiring prioritized remediation. |
| Medium | Material hardening or detection gap with lower immediate exploitability. |
| Low | Governance or hygiene weakness that should be corrected through normal control improvement. |

Confidence represents how directly the supplied configuration supports the finding. It is intentionally independent of severity.

## Analysis Sequence

1. Validate input structure and identify the reviewed templates/CAs.
2. Determine whether templates can issue certificates suitable for authentication.
3. Review enrollment principals for broad or unintended access.
4. Review requester-controlled identity fields and issuance approval controls.
5. Review key-protection and certificate-lifetime settings.
6. Review CA web-enrollment transport and audit configuration.
7. Produce findings with impact, remediation, validation, and defensive ATT&CK context.
8. Re-run after configuration changes to demonstrate risk reduction.

## ATT&CK Context

The project uses ATT&CK references to describe the defensive significance of certificate-backed identity and account-trust weaknesses. Relevant mappings include T1649, T1556, T1078, and T1098. The repository deliberately excludes procedures for abusing those techniques.

## Evidence Expectations

A remediation should not be treated as closed solely because a configuration change was requested. Closure evidence should demonstrate the effective template or CA state and, where feasible, show that a benign issuance or audit validation behaves as intended.
