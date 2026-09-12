# Recruiter / Engineering Review Guide

This guide provides a short, evidence-based path for reviewing the AD CS Security Lab without needing to read the entire repository.

## Five-minute review path

1. Read the problem statement and architecture in `README.md`.
2. Review `src/assessor.py` for deterministic template and CA control evaluation.
3. Review `src/attack_paths.py` for identity relationship correlation, bounded risk scoring, and ATT&CK context.
4. Review `src/remediation.py` for closure evidence and exception-governance checks.
5. Open `reports/example-attack-path-assessment.md` to see analyst-facing output.
6. Review `.github/workflows/tests.yml` to confirm compile, unit-test, and synthetic smoke-test quality gates.

## Capability-to-evidence map

| Capability | Repository evidence | What it demonstrates |
|---|---|---|
| AD CS configuration review | `src/assessor.py` | Rule-based evaluation of risky template and CA properties |
| Identity-path analysis | `src/attack_paths.py` | Correlation of certificate-template exposure with identity relationships |
| Explainable prioritization | `src/attack_paths.py`, `docs/methodology.md` | Bounded deterministic scoring with explicit rationale |
| Remediation governance | `src/remediation.py`, `docs/remediation-validation.md` | Evidence-based closure and exception validation |
| Analyst reporting | `src/reporting.py`, `reports/` | Translation of technical findings into reviewable security output |
| Architecture reasoning | `docs/architecture.md`, `docs/attack-path-governance.md` | Trust boundaries, assumptions, governance, and limitations |
| Quality engineering | `tests/`, `.github/workflows/tests.yml` | Regression tests and CI validation on synthetic data |

## Questions this project can support in an interview

- How should risky certificate templates be prioritized when several controls fail at once?
- Why is broad enrollment alone insufficient to describe a complete identity attack path?
- How should privileged identity relationships affect prioritization without overstating exploitability?
- What evidence should be required before an AD CS remediation is considered technically validated?
- How should accepted risk be represented without altering the underlying technical exposure?
- Why should ATT&CK mappings be treated as defensive context rather than evidence that compromise occurred?

## Security boundaries

The project intentionally does **not** perform:

- live LDAP, RPC, SMB, HTTP enrollment, or CA discovery;
- certificate requests or authentication attempts;
- credential use, password attacks, or ticket abuse;
- exploitation of AD CS misconfigurations;
- production targeting or use of employer/client data.

All identities, templates, groups, relationships, change references, and assessment evidence are synthetic.

## CI interpretation

A workflow badge or historical successful run is not proof that every commit is green. Recruiters or reviewers should verify the GitHub Actions result for the exact commit being evaluated. The workflow itself is deliberately small and inspectable: source compilation, unit tests, and a synthetic attack-path smoke validation.

## Portfolio positioning

This repository is best evaluated as an **identity security / PKI security-engineering project**. Its value is the full defensive lifecycle: configuration assessment, relationship context, explainable prioritization, reporting, remediation evidence, revalidation, and governance—rather than offensive AD CS exploitation.
