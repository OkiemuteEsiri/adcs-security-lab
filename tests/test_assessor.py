import unittest

from src.assessor import assess_inventory, summarize


class AssessInventoryTests(unittest.TestCase):
    def test_critical_subject_supply_and_broad_enrollment(self):
        inventory = {
            "templates": [
                {
                    "name": "RiskyTemplate",
                    "ekus": ["Client Authentication"],
                    "enrollment_principals": ["Domain Users"],
                    "enrollee_supplies_subject": True,
                    "manager_approval": False,
                    "authorized_signatures": 0,
                    "validity_days": 90,
                    "exportable_private_key": False,
                    "owner": "Identity"
                }
            ]
        }
        findings = assess_inventory(inventory)
        self.assertTrue(any(f.control_id == "ADCS-001" and f.severity == "CRITICAL" for f in findings))

    def test_hardened_template_has_no_high_or_critical_findings(self):
        inventory = {
            "templates": [
                {
                    "name": "Hardened",
                    "ekus": ["Client Authentication"],
                    "enrollment_principals": ["Approved PKI Users"],
                    "enrollee_supplies_subject": False,
                    "manager_approval": True,
                    "authorized_signatures": 1,
                    "validity_days": 180,
                    "exportable_private_key": False,
                    "owner": "Identity"
                }
            ]
        }
        findings = assess_inventory(inventory)
        self.assertFalse(any(f.severity in {"CRITICAL", "HIGH"} for f in findings))

    def test_long_validity_is_medium(self):
        inventory = {
            "templates": [
                {
                    "name": "LongLived",
                    "ekus": ["Client Authentication"],
                    "enrollment_principals": ["Approved PKI Users"],
                    "validity_days": 730,
                    "owner": "Identity"
                }
            ]
        }
        findings = assess_inventory(inventory)
        self.assertTrue(any(f.control_id == "ADCS-003" and f.severity == "MEDIUM" for f in findings))

    def test_ca_transport_and_auditing_controls(self):
        inventory = {
            "certificate_authorities": [
                {
                    "name": "LAB-CA",
                    "web_enrollment_enabled": True,
                    "https_only": False,
                    "auditing_enabled": False
                }
            ]
        }
        control_ids = {f.control_id for f in assess_inventory(inventory)}
        self.assertEqual({"ADCS-101", "ADCS-102"}, control_ids)

    def test_summary_counts_severity(self):
        inventory = {
            "templates": [
                {
                    "name": "RiskyTemplate",
                    "ekus": ["Client Authentication"],
                    "enrollment_principals": ["Domain Users"],
                    "enrollee_supplies_subject": True,
                    "manager_approval": False,
                    "authorized_signatures": 0,
                    "validity_days": 730,
                    "exportable_private_key": True,
                    "owner": "Identity"
                }
            ]
        }
        totals = summarize(assess_inventory(inventory))
        self.assertGreaterEqual(totals["CRITICAL"], 1)
        self.assertGreaterEqual(totals["HIGH"], 1)
        self.assertGreaterEqual(totals["MEDIUM"], 1)


if __name__ == "__main__":
    unittest.main()
