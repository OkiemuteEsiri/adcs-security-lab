from __future__ import annotations

from typing import Iterable
from src.attack_paths import AttackPath, summarize_paths


def render_attack_path_report(paths: Iterable[AttackPath]) -> str:
    paths = list(paths)
    summary = summarize_paths(paths)
    lines = [
        "# AD CS Attack-Path Assessment",
        "",
        "Synthetic defensive analysis only. No live-domain enumeration or certificate abuse is performed.",
        "",
        "## Executive Summary",
        "",
        f"- Total paths: {summary['TOTAL']}",
        f"- Critical: {summary['CRITICAL']}",
        f"- High: {summary['HIGH']}",
        f"- Medium: {summary['MEDIUM']}",
        f"- Low: {summary['LOW']}",
        "",
        "## Prioritized Paths",
        "",
    ]
    for path in paths:
        lines.extend([
            f"### {path.path_id} — {path.severity} ({path.risk_score}/100)",
            "",
            f"- Template: `{path.template}`",
            f"- Principal: `{path.principal}`",
            f"- Relationship: `{path.relation}`",
            f"- Target boundary: {path.target}",
            f"- ATT&CK: {', '.join(path.attack)}",
            f"- Rationale: {', '.join(path.rationale) if path.rationale else 'baseline relationship only'}",
            "",
            "**Remediation:** restrict enrollment, remove unnecessary authentication EKUs or requester-controlled identity fields, add issuance approval where appropriate, and review privileged trust relationships.",
            "",
            "**Validation:** reassess the remediated synthetic configuration and confirm the original path no longer meets its prior risk conditions.",
            "",
        ])
    return "\n".join(lines)
