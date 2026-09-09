from __future__ import annotations

import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable


AUTH_EKUS = {
    "Client Authentication",
    "Smart Card Logon",
    "PKINIT Client Authentication",
    "Any Purpose",
}

BROAD_PRINCIPALS = {
    "Domain Users",
    "Authenticated Users",
    "Everyone",
}


@dataclass(frozen=True)
class Finding:
    control_id: str
    severity: str
    confidence: str
    object: str
    message: str
    impact: str
    remediation: str
    validation: str
    attack: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["attack"] = list(self.attack)
        return data


def _template_findings(template: dict[str, Any]) -> Iterable[Finding]:
    name = template.get("name", "<unnamed-template>")
    ekus = set(template.get("ekus", []))
    enrollment = set(template.get("enrollment_principals", []))
    auth_enabled = bool(ekus & AUTH_EKUS)
    broad_enrollment = bool(enrollment & BROAD_PRINCIPALS)
    subject_supply = bool(template.get("enrollee_supplies_subject", False))
    manager_approval = bool(template.get("manager_approval", False))
    signatures = int(template.get("authorized_signatures", 0) or 0)

    if auth_enabled and subject_supply and broad_enrollment:
        yield Finding(
            "ADCS-001",
            "CRITICAL",
            "HIGH",
            name,
            "Template permits requester-controlled subject data and authentication EKUs with broad enrollment rights",
            "A broadly enrollable authentication certificate could undermine identity assurance and create a high-impact privilege path.",
            "Disable requester-controlled subject/SAN settings unless explicitly required and restrict enrollment to approved groups.",
            "Reassess the template and confirm requester-controlled identity fields are disabled or enrollment is tightly scoped.",
            ("T1649", "T1078"),
        )

    if auth_enabled and broad_enrollment and not manager_approval and signatures == 0:
        yield Finding(
            "ADCS-002",
            "HIGH",
            "HIGH",
            name,
            "Authentication-capable template is broadly enrollable without issuance approval controls",
            "Weak issuance governance can allow certificates to be obtained without an independent approval boundary.",
            "Restrict enrollment and require manager approval or authorized signatures for sensitive issuance workflows.",
            "Confirm sensitive templates require an approval control and no broad principal retains enrollment permission.",
            ("T1649", "T1078"),
        )

    validity_days = int(template.get("validity_days", 0) or 0)
    if auth_enabled and validity_days > 365:
        yield Finding(
            "ADCS-003",
            "MEDIUM",
            "HIGH",
            name,
            f"Authentication certificate validity is {validity_days} days",
            "Long-lived authentication certificates increase the duration of credential exposure and complicate recovery.",
            "Reduce validity to a documented business-appropriate period and pair renewal with lifecycle monitoring.",
            "Issue a test certificate under the remediated policy and verify the validity period meets the approved baseline.",
            ("T1649",),
        )

    if bool(template.get("exportable_private_key", False)) and auth_enabled:
        yield Finding(
            "ADCS-004",
            "HIGH",
            "HIGH",
            name,
            "Authentication template allows private keys to be exportable",
            "Exportable authentication keys increase the risk of credential replication outside the intended endpoint boundary.",
            "Disable private-key export unless a documented exception requires it and enforce protected key storage.",
            "Verify newly issued authentication certificates use non-exportable key settings.",
            ("T1649", "T1556"),
        )

    if not template.get("owner"):
        yield Finding(
            "ADCS-005",
            "LOW",
            "HIGH",
            name,
            "Template has no recorded security owner",
            "Unowned PKI objects are more likely to retain obsolete permissions or risky issuance settings.",
            "Assign an accountable owner and define a periodic recertification interval.",
            "Confirm ownership metadata and review cadence are recorded.",
            tuple(),
        )


def _ca_findings(ca: dict[str, Any]) -> Iterable[Finding]:
    name = ca.get("name", "<unnamed-ca>")

    if bool(ca.get("web_enrollment_enabled", False)) and not bool(ca.get("https_only", False)):
        yield Finding(
            "ADCS-101",
            "HIGH",
            "HIGH",
            name,
            "CA web enrollment is enabled without HTTPS-only enforcement",
            "Unprotected enrollment transport weakens confidentiality and integrity around certificate request workflows.",
            "Require HTTPS for enrollment endpoints and disable legacy HTTP access where operationally feasible.",
            "Validate the enrollment endpoint rejects or redirects unprotected HTTP and presents the approved certificate chain.",
            ("T1649",),
        )

    if not bool(ca.get("auditing_enabled", False)):
        yield Finding(
            "ADCS-102",
            "MEDIUM",
            "HIGH",
            name,
            "Certification authority auditing is disabled",
            "Missing CA audit telemetry reduces the ability to investigate suspicious issuance and administrative changes.",
            "Enable CA auditing and forward relevant events to the approved security monitoring platform.",
            "Perform a benign synthetic issuance workflow and verify expected CA audit events are recorded.",
            ("T1078", "T1098"),
        )


def assess_inventory(inventory: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for template in inventory.get("templates", []):
        findings.extend(_template_findings(template))
    for ca in inventory.get("certificate_authorities", []):
        findings.extend(_ca_findings(ca))
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda item: (order[item.severity], item.control_id, item.object))
    return findings


def load_inventory(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def summarize(findings: list[Finding]) -> dict[str, int]:
    totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        totals[finding.severity] += 1
    return totals


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("Usage: python -m src.assessor <inventory.json>", file=sys.stderr)
        return 2

    inventory = load_inventory(args[0])
    findings = assess_inventory(inventory)
    output = {
        "summary": summarize(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    print(json.dumps(output, indent=2))
    return 1 if any(f.severity in {"CRITICAL", "HIGH"} for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
