from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable


@dataclass(frozen=True)
class Relationship:
    source: str
    relation: str
    target: str
    privileged_target: bool = False


@dataclass(frozen=True)
class AttackPath:
    path_id: str
    template: str
    principal: str
    target: str
    relation: str
    risk_score: int
    severity: str
    rationale: tuple[str, ...]
    attack: tuple[str, ...]


def _severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def _stable_id(*parts: str) -> str:
    raw = "|".join(parts).encode("utf-8")
    return "ADCS-PATH-" + sha256(raw).hexdigest()[:12].upper()


def build_attack_paths(inventory: dict[str, Any], relationships: Iterable[Relationship]) -> list[AttackPath]:
    templates = {item["name"]: item for item in inventory.get("templates", []) if item.get("name")}
    paths: list[AttackPath] = []

    for edge in relationships:
        template = templates.get(edge.source)
        if not template:
            continue

        principals = set(template.get("enrollment_principals", []))
        if edge.target not in principals and edge.relation == "enrollable_by":
            continue

        ekus = set(template.get("ekus", []))
        auth_capable = bool(ekus & {"Client Authentication", "Smart Card Logon", "PKINIT Client Authentication", "Any Purpose"})
        broad = edge.target in {"Domain Users", "Authenticated Users", "Everyone"}
        subject_supply = bool(template.get("enrollee_supplies_subject", False))
        approval = bool(template.get("manager_approval", False)) or int(template.get("authorized_signatures", 0) or 0) > 0
        exportable = bool(template.get("exportable_private_key", False))

        score = 10
        rationale: list[str] = []
        if auth_capable:
            score += 20
            rationale.append("authentication-capable EKU")
        if broad:
            score += 20
            rationale.append("broad enrollment principal")
        if subject_supply:
            score += 25
            rationale.append("requester-controlled subject data")
        if not approval:
            score += 10
            rationale.append("no independent issuance approval")
        if exportable:
            score += 10
            rationale.append("exportable private key")
        if edge.privileged_target:
            score += 20
            rationale.append("privileged identity boundary")
        score = min(score, 100)

        paths.append(
            AttackPath(
                path_id=_stable_id(edge.source, edge.relation, edge.target),
                template=edge.source,
                principal=edge.target,
                target="Privileged Identity Boundary" if edge.privileged_target else "Enterprise Identity Boundary",
                relation=edge.relation,
                risk_score=score,
                severity=_severity(score),
                rationale=tuple(rationale),
                attack=("T1649", "T1078") if auth_capable else ("T1649",),
            )
        )

    return sorted(paths, key=lambda p: (-p.risk_score, p.template, p.principal))


def summarize_paths(paths: Iterable[AttackPath]) -> dict[str, int]:
    result = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": 0}
    for path in paths:
        result[path.severity] += 1
        result["TOTAL"] += 1
    return result
