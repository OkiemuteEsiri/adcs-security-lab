# Active Directory Certificate Services Security Lab

A defensive, recruiter-facing security-engineering project for assessing risky Active Directory Certificate Services (AD CS) configurations, correlating certificate templates to identity relationships, prioritizing attack paths, and validating remediation evidence in a fully synthetic environment.

> **Safety scope:** synthetic configuration data only. This repository performs no LDAP/RPC enumeration, certificate requests, credential use, exploitation, production targeting, or confidential-data processing.

## Problem Statement

AD CS can create high-impact identity paths when certificate templates, enrollment rights, issuance controls, or CA settings are overly permissive. Configuration findings are useful, but mature security engineering also needs to answer: which identities can reach the risky template, which paths cross privileged boundaries, how should those paths be prioritized, and what evidence is required before remediation is considered closed?

This project addresses that lifecycle with an offline Python assessment engine, relationship correlation, explainable path scoring, governance validation, analyst reporting, unit tests, and CI quality gates.

## Architecture

```text
Synthetic AD CS inventory        Synthetic relationships
          |                               |
          +---------------+---------------+
                          v
                 Configuration assessor
                          |
                          v
                 Attack-path correlator
                          |
        +-----------------+-----------------+
        |                 |                 |
        v                 v                 v
   Risk scoring      ATT&CK context    Portfolio metrics
        |                 |                 |
        +-----------------+-----------------+
                          v
                  Markdown reporting
                          |
                          v
             Remediation evidence gate
```

## Repository Structure

```text
.
├── src/
│   ├── assessor.py              # template/CA control engine
│   ├── attack_paths.py          # relationship correlation + scoring
│   ├── remediation.py           # closure and exception validation
│   └── reporting.py             # analyst-facing Markdown output
├── tests/
│   ├── test_assessor.py
│   └── test_attack_paths.py
├── data/
│   ├── synthetic_adcs_inventory.json
│   └── synthetic_relationships.json
├── docs/
│   ├── architecture.md
│   ├── methodology.md
│   ├── remediation-validation.md
│   └── attack-path-governance.md
├── reports/
│   ├── example-assessment.md
│   └── example-attack-path-assessment.md
└── .github/workflows/tests.yml
```

## Capabilities

### Configuration assessment

The baseline assessor evaluates synthetic template and CA conditions including:

- requester-controlled subject/SAN with authentication EKUs;
- broad enrollment rights;
- missing manager approval or authorized signatures;
- long-lived authentication certificates;
- exportable private keys;
- missing ownership metadata;
- web enrollment without HTTPS-only enforcement;
- disabled CA auditing.

### Attack-path correlation

`src/attack_paths.py` correlates certificate templates with explicit identity relationships and evaluates security context including:

- authentication-capable EKUs;
- broad enrollment principals;
- requester-controlled subject data;
- missing independent issuance approval;
- exportable private keys;
- privileged identity boundaries.

Each path receives a deterministic SHA-256-derived ID, a bounded `0–100` risk score, severity, rationale, and defensive ATT&CK context. Results are sorted deterministically to support regression testing and repeatable reporting.

### Remediation and governance

`src/remediation.py` keeps technical exposure separate from governance acceptance. A remediation cannot be marked validated without:

- accountable owner;
- change reference;
- implemented control change;
- post-change security review;
- passing validation result.

Incomplete evidence returns `needs_evidence`; an explicit failed validation returns `invalid_closure`.

Risk exceptions require an owner, approver, rationale, review reference, and expiry date. An expired exception is not treated as active and never reduces the technical risk score merely because risk was accepted.

## Risk Model

The attack-path score is intentionally explainable rather than probabilistic. Risk increases when a relationship combines identity-sensitive properties such as broad enrollment, authentication capability, requester-controlled identity data, weak issuance governance, exportable keys, and privileged-boundary context. Scores are capped at 100.

The score is a prioritization mechanism, not proof that exploitation is possible or has occurred.

## MITRE ATT&CK Context

Relevant defensive mappings include:

- **T1649 — Steal or Forge Authentication Certificates**
- **T1078 — Valid Accounts**
- **T1556 — Modify Authentication Process**
- **T1098 — Account Manipulation**

ATT&CK mappings are used for threat modeling, architecture review, detection planning, and risk communication only.

## Usage

Run the baseline configuration assessor:

```bash
python -m src.assessor data/synthetic_adcs_inventory.json
```

Run all tests:

```bash
python -m unittest discover -s tests -v
```

The path-correlation module is intentionally library-first so it can be consumed by reporting, future CLI automation, or a controlled data-ingestion layer without coupling assessment logic to external directory access.

## Methodology

1. Validate the synthetic inventory and relationship assumptions.
2. Assess template and CA configuration controls.
3. Correlate template enrollment relationships.
4. Score path context using explicit security factors.
5. Prioritize findings deterministically.
6. Map relevant defensive ATT&CK techniques.
7. Produce analyst-facing output.
8. Apply remediation changes to the synthetic configuration.
9. Reassess and require complete closure evidence.
10. Track any accepted exception independently with ownership and expiry.

See `docs/attack-path-governance.md` for the extended methodology and trust boundaries.

## Testing and CI/CD

GitHub Actions uses least-privilege `contents: read` permissions. The workflow:

- compiles Python source and tests;
- runs the complete `unittest` suite;
- executes a synthetic attack-path smoke check;
- validates deterministic ATT&CK/report content.

The new test module covers critical-path prioritization, deterministic IDs, score bounds, ATT&CK context, metrics, reporting, successful closure, failed closure, incomplete evidence, active exceptions, and expired exceptions.

## Design Decisions

- **Offline by design:** no domain, CA, LDAP, RPC, HTTP enrollment, or credential interaction.
- **Deterministic IDs:** stable findings make regression analysis and remediation tracking easier.
- **Explainable scoring:** every risk increase has an explicit rationale.
- **Governance separation:** risk acceptance does not magically reduce technical exposure.
- **Fail-closed closure:** remediation requires evidence and a passing validation result.
- **Synthetic evidence:** all identities, templates, groups, references, and relationships are fictional.

## Example Security Outcome

The synthetic `UserAuthentication` template produces the highest-priority path because it combines authentication capability, broad enrollment, requester-controlled identity fields, no independent issuance approval, exportable keys, and a privileged-boundary relationship. The recommended response is to reduce enrollment scope, remove unnecessary requester-controlled identity fields, strengthen issuance controls, and validate the resulting configuration before closure.

## Skills Demonstrated

- Active Directory / identity security
- PKI and AD CS security review
- attack-path analysis
- security architecture and trust-boundary reasoning
- Python security automation
- contextual risk prioritization
- deterministic security engineering
- remediation validation
- exception governance
- MITRE ATT&CK mapping
- technical reporting
- unit testing
- CI/CD quality gates

## Limitations

This project does not query a live directory or certification authority and does not model every AD CS attack-path class, ACL combination, trust relationship, issuance-policy nuance, or enterprise PKI topology. It does not demonstrate exploitation capability and should not be interpreted as evidence of production experience with a specific environment.

A production implementation would require authoritative inventory collection, schema/version controls, ACL normalization, ownership integration, exception-system integration, organization-specific baselines, monitoring telemetry, and change-management controls.

## Roadmap

- template-to-principal graph visualization;
- CA hierarchy and issuance-policy analysis;
- richer ACL relationship modeling;
- SARIF/JSON export;
- owner-level risk aggregation;
- exception expiry dashboards;
- remediation evidence bundles;
- defensive Windows event-log validation guidance;
- policy-as-code baselines for approved template profiles.

## Ethical Use

Use only with systems you own or are explicitly authorized to assess. The implementation is intentionally defensive and designed for security engineering, architecture review, remediation validation, and portfolio demonstration.
