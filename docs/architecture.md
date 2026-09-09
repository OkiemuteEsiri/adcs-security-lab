# Architecture

## Objective

The lab models a defensive review pipeline for Active Directory Certificate Services configuration. It converts synthetic certificate-template and certification-authority configuration into explainable findings that security engineering and identity teams can prioritize and validate.

## Components

1. **Inventory layer** — JSON input representing templates and certification authorities.
2. **Control engine** — deterministic checks in `src/assessor.py`.
3. **Risk layer** — normalized severity and confidence values.
4. **Context layer** — defensive MITRE ATT&CK references for risk communication.
5. **Validation layer** — tests and documented remediation verification steps.

## Data Flow

```text
JSON inventory
   |
   v
load_inventory()
   |
   v
assess_inventory()
   |-- template controls
   |-- CA controls
   v
Finding objects
   |
   +--> summarize()
   +--> JSON output
   +--> remediation / validation workflow
```

## Design Decisions

- Standard library only, minimizing dependency and supply-chain overhead.
- Deterministic control logic supports repeatable tests and transparent review.
- No live LDAP, RPC, SMB, certificate enrollment, or domain discovery is performed.
- Findings separate severity from confidence so impact and evidential certainty are not conflated.
- ATT&CK mappings provide defensive context only and do not drive exploit automation.

## Security Boundary

The engine accepts configuration artifacts as data. It does not authenticate to domains, enumerate certificate services, request certificates, manipulate templates, or interact with production identity infrastructure.
