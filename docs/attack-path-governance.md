# Attack-Path and Governance Methodology

## Objective

This extension models how risky AD CS template properties combine with enrollment relationships to create identity-risk paths. It is intentionally offline: relationships are synthetic and no LDAP, RPC, HTTP enrollment, certificate request, credential use, or domain interaction occurs.

## Processing Model

1. Load synthetic certificate-template and CA inventory.
2. Load explicit template-to-principal relationships.
3. Correlate each relationship to the referenced template.
4. Evaluate authentication EKUs, requester-controlled subject data, enrollment breadth, issuance approval, exportable-key settings, and privileged-boundary context.
5. Produce deterministic path identifiers and bounded risk scores.
6. Sort paths by risk and render analyst-ready reporting.
7. Validate remediation evidence separately from technical exposure.

## Risk Scoring

The path model uses additive, explainable factors and caps scores at 100. Authentication capability, broad enrollment, requester-controlled identity fields, missing approval, exportable keys, and privileged-boundary context increase risk. A score is a prioritization aid, not proof of exploitability or compromise.

## ATT&CK Context

- T1649 — Steal or Forge Authentication Certificates
- T1078 — Valid Accounts

Mappings communicate likely security impact and defensive coverage. They do not claim that exploitation occurred.

## Governance Model

Technical exposure and risk acceptance are deliberately separate. An approved exception does not reduce technical risk merely because it was accepted. Exceptions require an owner, approver, rationale, expiry date, and review reference. Expired or incomplete exceptions must be revisited.

## Remediation Evidence

A finding is considered validated only when evidence includes:

- accountable owner;
- change reference;
- confirmation that the control changed;
- post-change security review;
- passing validation result.

Failed validation produces `invalid_closure`; incomplete evidence produces `needs_evidence`.

## Trust Boundaries

This repository trusts only local synthetic JSON committed with the project. It does not trust external network responses, production directory exports, certificates, secrets, or user-supplied executable content.

## Limitations

The model does not implement every AD CS escalation class, does not infer complex ACL chains, and does not validate real enterprise PKI. Production use would require schema versioning, authoritative directory/PKI data collection, exception integration, stronger policy baselines, and organization-specific ownership metadata.
