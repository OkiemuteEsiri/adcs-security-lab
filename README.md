# Active Directory Certificate Services Security Lab

A defensive security-engineering project for identifying risky Active Directory Certificate Services (AD CS) configurations, translating certificate-template and CA posture into prioritized findings, and validating remediation in a synthetic lab environment.

> **Scope:** synthetic configuration data only. This repository contains no credential theft, certificate abuse automation, exploit payloads, production targeting, or confidential data.

## Problem Statement

AD CS can create high-impact identity attack paths when certificate templates, enrollment rights, issuance controls, or certification-authority settings are overly permissive. Security teams need a repeatable way to review these configurations before they become viable privilege-escalation paths.

This project implements a lightweight Python assessment engine that evaluates synthetic AD CS inventory for risky template and CA conditions, assigns severity and confidence, explains the security impact, and provides remediation and validation steps.

## Architecture

```text
Synthetic AD CS inventory
        |
        v
JSON loader
        |
        v
Template + CA control engine
        |
        +--> severity / confidence
        +--> ATT&CK defensive context
        +--> remediation guidance
        |
        v
Console / Markdown-ready findings
```

## Repository Structure

```text
.
├── src/
│   └── assessor.py
├── tests/
│   └── test_assessor.py
├── data/
│   └── synthetic_adcs_inventory.json
├── docs/
│   ├── architecture.md
│   ├── methodology.md
│   └── remediation-validation.md
├── reports/
│   └── example-assessment.md
└── .github/workflows/tests.yml
```

## Controls Implemented

The assessment engine currently checks for:

- enrollee-supplied subject/SAN combined with client-authentication EKUs
- broad enrollment rights on sensitive templates
- missing manager approval or authorized-signature requirements
- templates usable for authentication with weak issuance controls
- long template validity periods
- exportable private-key settings
- vulnerable CA web-enrollment exposure indicators
- weak CA auditing configuration
- unprotected enrollment endpoints
- missing template ownership metadata

The checks intentionally model defensive review concepts associated with well-known AD CS attack-path classes without implementing exploitation.

## Risk Model

Each finding contains:

- control ID
- severity: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`
- confidence: `HIGH`, `MEDIUM`, or `LOW`
- affected object
- impact statement
- remediation
- validation step
- relevant defensive ATT&CK context

Critical and high findings are designed to represent configurations that could materially weaken identity assurance or privilege boundaries.

## Usage

```bash
python -m src.assessor data/synthetic_adcs_inventory.json
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Example Finding

```json
{
  "control_id": "ADCS-001",
  "severity": "CRITICAL",
  "object": "UserAuthentication",
  "message": "Template permits requester-controlled subject data and client authentication with broad enrollment rights",
  "remediation": "Restrict subject-name supply and narrow enrollment principals to explicitly approved groups."
}
```

## MITRE ATT&CK Context

Relevant defensive mappings include:

- **T1649 — Steal or Forge Authentication Certificates**
- **T1556 — Modify Authentication Process**
- **T1078 — Valid Accounts**
- **T1098 — Account Manipulation**

ATT&CK references are used for defensive architecture, detection, and risk communication only.

## Remediation Workflow

1. Validate whether the flagged template or CA setting is actually enabled and published.
2. Identify principals with enrollment or administrative rights.
3. Remove requester-controlled subject/SAN settings where not explicitly required.
4. Restrict enrollment to approved groups.
5. Add manager approval or authorized-signature controls for sensitive certificate issuance.
6. Disable unnecessary authentication EKUs.
7. Harden enrollment endpoints and CA auditing.
8. Re-run the assessment against the remediated synthetic configuration.
9. Record evidence showing the finding no longer evaluates as critical/high.

## CI/CD

GitHub Actions runs the Python unit-test suite for pushes and pull requests. The workflow provides a simple regression gate for the control engine while keeping the project dependency-light.

## Skills Demonstrated

- Active Directory identity security
- PKI / AD CS security review
- attack-path risk analysis
- Python security automation
- configuration assessment
- remediation validation
- MITRE ATT&CK mapping
- security reporting
- unit testing
- DevSecOps quality gates

## Limitations

This project analyzes synthetic JSON configuration rather than querying a live domain, certification authority, LDAP directory, or Windows host. It does not claim exploitation capability, production validation, or complete coverage of every AD CS misconfiguration class.

## Roadmap

- add template-to-principal relationship graphing
- add certificate-authority hierarchy analysis
- add policy-exception expiry tracking
- add SARIF export
- add risk aggregation by business owner
- add remediation evidence bundles
- add defensive event-log validation guidance

## Ethical Use

Use only for systems you own or are explicitly authorized to assess. The project is intentionally defensive and designed for security engineering, architecture review, and portfolio demonstration.