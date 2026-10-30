from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from org_governance_attestor import expired_exception_findings, findings_for_repository


class OrganizationAttestorTests(unittest.TestCase):
    def healthy(self):
        return {
            "name": "pilot", "default_branch": "main", "caller": {
                "present": True, "central": True, "workflow_state": "active"},
            "required_checks": ["pr-qa / Pull Request Quality Assurance"],
            "pull_request_rule": True, "promotion_branches": {"development": True, "staging": True},
            "declares_production": True, "release_workflow_candidate": True,
        }

    def test_healthy_configuration_has_no_drift(self):
        self.assertEqual(findings_for_repository(self.healthy()), [])

    def test_missing_caller_and_required_check_are_distinct(self):
        record = self.healthy()
        record["caller"] = {"present": False}
        record["required_checks"] = []
        codes = {item["code"] for item in findings_for_repository(record)}
        self.assertEqual(codes, {"MISSING_CALLER", "UNENFORCED_CHECK"})

    def test_disabled_caller_and_unprotected_promotion_are_detected(self):
        record = self.healthy()
        record["caller"]["workflow_state"] = "disabled_manually"
        record["promotion_branches"]["staging"] = False
        codes = {item["code"] for item in findings_for_repository(record)}
        self.assertEqual(codes, {"DISABLED_CALLER", "UNPROTECTED_PROMOTION_BRANCH"})

    def test_noncentral_caller_missing_pr_rule_and_release_route_are_distinct(self):
        record = self.healthy()
        record["caller"]["central"] = False
        record["pull_request_rule"] = False
        record["release_workflow_candidate"] = False
        codes = {item["code"] for item in findings_for_repository(record)}
        self.assertEqual(codes, {"NONCENTRAL_CALLER", "MISSING_PR_RULE", "MISSING_RELEASE_CONTROL_EVIDENCE"})

    def test_central_repository_self_caller_is_valid(self):
        record = self.healthy()
        record["name"] = ".github"
        record["caller"]["central"] = False
        self.assertEqual(findings_for_repository(record), [])

    def test_failed_query_is_unknown_not_compliant(self):
        self.assertEqual([f["code"] for f in findings_for_repository({"name": "pilot", "query_error": "403"})],
                         ["EVIDENCE_UNAVAILABLE"])

    def test_unknown_workflow_state_is_not_called_disabled(self):
        record = self.healthy()
        record["caller"]["workflow_state"] = "unknown"
        self.assertEqual([f["code"] for f in findings_for_repository(record)],
                         ["CALLER_STATE_UNVERIFIED"])

    def test_expired_exception_is_reported_without_claiming_active_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy" / "exceptions"
            path.mkdir(parents=True)
            (path / "expired.json").write_text(json.dumps({"repository": "Synergie-ITCI/pilot",
                "expires_at": "2026-01-01T00:00:00Z"}))
            (path / "future.json").write_text(json.dumps({"repository": "Synergie-ITCI/pilot",
                "expires_at": "2027-01-01T00:00:00Z"}))
            findings = expired_exception_findings(Path(tmp), datetime(2026, 10, 30, tzinfo=timezone.utc))
            self.assertEqual([(f["code"], f["detail"]) for f in findings],
                             [("EXPIRED_EXCEPTION_RECORD", "expired.json")])


if __name__ == "__main__":
    unittest.main()
