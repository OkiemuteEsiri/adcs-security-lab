# AD CS Control Validation Matrix

This matrix separates a detected configuration condition from the evidence required to close it. It is intended for defensive validation and portfolio demonstration using synthetic data only.

| Control area | Risk condition | Security impact | Minimum remediation evidence | Revalidation condition | Defensive context |
|---|---|---|---|---|---|
| Enrollment scope | Authentication-capable template is enrollable by an unnecessarily broad principal set | Expands the population able to request identity-bearing certificates | Approved enrollment groups and revised template permissions | Reassessment shows broad principals removed and intended principals retained | Identity access governance; T1649 context |
| Subject / SAN control | Requester can supply identity-sensitive subject data where it is not required | Can weaken the binding between approved identity and certificate content | Template setting change plus approved design rationale | Reassessment confirms requester-controlled identity fields are disabled where unnecessary | Certificate abuse threat modeling; T1649 context |
| Issuance approval | High-impact template lacks manager approval or authorized signatures | Reduces independent control before certificate issuance | Enabled issuance approval/signature requirement and owner confirmation | Synthetic reassessment confirms the approval control is active | Preventive control strengthening |
| Authentication EKUs | Template exposes authentication capability beyond its intended business purpose | Increases identity risk if other template controls are weak | EKU review, approved intended use, and template change where required | Reassessment confirms only required EKUs remain | T1649 / T1078 defensive context |
| Private-key protection | Exportable private keys are enabled without a documented need | Increases risk of credential portability and misuse | Non-exportable-key policy or formally governed exception | Reassessment confirms setting changed or exception remains valid and time-bounded | Credential protection |
| Certificate lifetime | Authentication certificate lifetime exceeds the approved baseline | Extends exposure window after issuance | Reduced validity period and documented baseline | Reassessment confirms lifetime is within policy | Credential lifecycle governance |
| CA web enrollment | Web enrollment is available without HTTPS-only enforcement | Weakens transport protection around enrollment workflows | HTTPS-only configuration and approved certificate/TLS configuration | Reassessment confirms insecure access is not permitted | Secure management plane |
| CA auditing | Security-relevant CA auditing is disabled or insufficient | Reduces investigation and detection evidence | Required audit policy enabled and logging ownership documented | Reassessment confirms audit settings and synthetic evidence requirements | Detection and investigation readiness |
| Ownership | Template or CA control lacks an accountable owner | Delays remediation and weakens exception governance | Named accountable owner and review cadence | Reassessment confirms ownership metadata is populated | Security governance |
| Privileged path context | A risky template relationship crosses a privileged identity boundary | Raises priority because the potential security consequence is higher | Exposure-reducing template/relationship change and owner-approved validation evidence | Path correlation no longer produces the same privileged-risk condition | Attack-path prioritization; ATT&CK context only |

## Evidence maturity

Use the following evidence levels when discussing remediation quality:

1. **Administrative evidence** — ticket, owner acknowledgement, or planned change only. This does not establish technical closure.
2. **Implementation evidence** — configuration change is documented, but independent validation is incomplete.
3. **Technical validation** — the relevant control is reassessed after change and the original condition no longer reproduces.
4. **Sustained validation** — the control remains effective over an agreed review period or repeated assessment cycle.

## Closure principles

A finding should not be marked technically validated because a change ticket is closed. Minimum defensible closure requires an accountable owner, a traceable change, post-change assessment, and a passing validation result.

Risk acceptance is also not remediation. An exception may make continued exposure governed and visible, but the technical condition remains present until the control state changes and revalidation passes.

## ATT&CK interpretation

ATT&CK references in this repository are used to communicate potential adversary-relevant context and to support defensive threat modeling. They do not prove exploitability, successful certificate abuse, account compromise, or attribution.
