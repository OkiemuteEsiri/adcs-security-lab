from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ClosureResult:
    finding_id: str
    status: str
    missing: tuple[str, ...]


REQUIRED_FIELDS = (
    "owner",
    "change_reference",
    "control_changed",
    "post_change_review",
    "validation_passed",
)


def validate_closure(finding_id: str, evidence: dict[str, Any]) -> ClosureResult:
    missing: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in evidence:
            missing.append(field)

    for field in ("owner", "change_reference"):
        if field in evidence and (not isinstance(evidence[field], str) or not evidence[field].strip()):
            missing.append(field)

    for field in ("control_changed", "post_change_review", "validation_passed"):
        if field in evidence and evidence[field] is not True:
            missing.append(field)

    missing = sorted(set(missing))
    if missing:
        status = "invalid_closure" if evidence.get("validation_passed") is False else "needs_evidence"
        return ClosureResult(finding_id, status, tuple(missing))
    return ClosureResult(finding_id, "validated", tuple())


def validate_exception(exception: dict[str, Any], as_of: str) -> tuple[str, tuple[str, ...]]:
    required = ("exception_id", "owner", "approver", "rationale", "expires_on", "review_reference")
    missing = tuple(field for field in required if not str(exception.get(field, "")).strip())
    if missing:
        return "invalid", missing
    if exception["expires_on"] < as_of:
        return "expired", tuple()
    return "active", tuple()
