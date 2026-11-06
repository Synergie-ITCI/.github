"""Safety contract for the production-only OpenTofu plan verifier."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("hosting_authorize", Path(__file__).with_name("authorize.py"))
authorize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authorize)


class PlanSafetyTest(unittest.TestCase):
    def verify(self, changes, phase):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            plan.write_text(json.dumps({"resource_changes": changes}))
            authorize.check_plan(plan, phase)

    @staticmethod
    def change(address, kind="aws_s3_bucket", actions=None, after=None):
        return {
            "address": address,
            "mode": "managed",
            "type": kind,
            "change": {"actions": actions or ["create"], "after": after or {}},
        }

    def test_phase_one_accepts_isolated_addition(self):
        self.verify([self.change("aws_s3_bucket.production", after={"bucket": "fieldzilla-production"})], "phase1")

    def test_phase_one_rejects_existing_resource_mutation(self):
        with self.assertRaises(SystemExit):
            self.verify([self.change("aws_db_instance.staging", "aws_db_instance", ["update"])], "phase1")

    def test_phase_one_rejects_shared_listener_addition(self):
        with self.assertRaises(SystemExit):
            self.verify([self.change("aws_lb_listener_rule.hosting_health", "aws_lb_listener_rule")], "phase1")

    def test_phase_one_rejects_staging_reference_in_new_resource(self):
        with self.assertRaises(SystemExit):
            self.verify([self.change("aws_iam_role.production", "aws_iam_role", after={"name": "staging-role"})], "phase1")

    def test_phase_two_accepts_only_three_shared_additions(self):
        self.verify([
            self.change("aws_lb_listener_certificate.production", "aws_lb_listener_certificate"),
            self.change("aws_lb_listener_rule.hosting_health", "aws_lb_listener_rule"),
            self.change("aws_lb_listener_rule.application_pending", "aws_lb_listener_rule"),
        ], "phase2")

    def test_phase_two_rejects_other_addition(self):
        with self.assertRaises(SystemExit):
            self.verify([
                self.change("aws_lb_listener_certificate.production", "aws_lb_listener_certificate"),
                self.change("aws_lb_listener_rule.hosting_health", "aws_lb_listener_rule"),
                self.change("aws_lb_listener_rule.application_pending", "aws_lb_listener_rule"),
                self.change("aws_db_instance.unreviewed", "aws_db_instance"),
            ], "phase2")


if __name__ == "__main__":
    unittest.main()
