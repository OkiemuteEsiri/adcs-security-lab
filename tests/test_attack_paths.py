import json
import unittest
from pathlib import Path

from src.attack_paths import Relationship, build_attack_paths, summarize_paths
from src.remediation import validate_closure, validate_exception
from src.reporting import render_attack_path_report


class AttackPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = json.loads(Path("data/synthetic_adcs_inventory.json").read_text(encoding="utf-8"))
        raw = json.loads(Path("data/synthetic_relationships.json").read_text(encoding="utf-8"))
        cls.relationships = [Relationship(**item) for item in raw]

    def test_prioritizes_risky_user_authentication_template(self):
        paths = build_attack_paths(self.inventory, self.relationships)
        self.assertEqual(paths[0].template, "UserAuthentication")
        self.assertEqual(paths[0].severity, "CRITICAL")
        self.assertGreaterEqual(paths[0].risk_score, 80)

    def test_ids_are_deterministic(self):
        first = build_attack_paths(self.inventory, self.relationships)
        second = build_attack_paths(self.inventory, self.relationships)
        self.assertEqual([p.path_id for p in first], [p.path_id for p in second])

    def test_scores_are_bounded(self):
        for path in build_attack_paths(self.inventory, self.relationships):
            self.assertGreaterEqual(path.risk_score, 0)
            self.assertLessEqual(path.risk_score, 100)

    def test_attack_mapping_present(self):
        paths = build_attack_paths(self.inventory, self.relationships)
        self.assertIn("T1649", paths[0].attack)

    def test_summary_totals_match(self):
        paths = build_attack_paths(self.inventory, self.relationships)
        summary = summarize_paths(paths)
        self.assertEqual(summary["TOTAL"], len(paths))

    def test_report_contains_remediation_and_attack(self):
        report = render_attack_path_report(build_attack_paths(self.inventory, self.relationships))
        self.assertIn("Remediation", report)
        self.assertIn("T1649", report)

    def test_complete_closure_validates(self):
        result = validate_closure("ADCS-PATH-TEST", {
            "owner": "Identity Engineering",
            "change_reference": "CHG-SYN-1001",
            "control_changed": True,
            "post_change_review": True,
            "validation_passed": True,
        })
        self.assertEqual(result.status, "validated")

    def test_failed_validation_is_invalid_closure(self):
        result = validate_closure("ADCS-PATH-TEST", {
            "owner": "Identity Engineering",
            "change_reference": "CHG-SYN-1002",
            "control_changed": True,
            "post_change_review": True,
            "validation_passed": False,
        })
        self.assertEqual(result.status, "invalid_closure")

    def test_missing_closure_evidence_is_reported(self):
        result = validate_closure("ADCS-PATH-TEST", {"owner": "Identity Engineering"})
        self.assertEqual(result.status, "needs_evidence")
        self.assertIn("change_reference", result.missing)

    def test_exception_state(self):
        active, missing = validate_exception({
            "exception_id": "EX-SYN-01",
            "owner": "Identity Engineering",
            "approver": "Security Architecture",
            "rationale": "Temporary compatibility requirement",
            "expires_on": "2027-01-31",
            "review_reference": "RISK-SYN-01",
        }, "2026-09-12")
        self.assertEqual(active, "active")
        self.assertEqual(missing, tuple())

    def test_expired_exception_is_not_active(self):
        status, _ = validate_exception({
            "exception_id": "EX-SYN-02",
            "owner": "Identity Engineering",
            "approver": "Security Architecture",
            "rationale": "Legacy dependency",
            "expires_on": "2025-01-01",
            "review_reference": "RISK-SYN-02",
        }, "2026-09-12")
        self.assertEqual(status, "expired")


if __name__ == "__main__":
    unittest.main()
