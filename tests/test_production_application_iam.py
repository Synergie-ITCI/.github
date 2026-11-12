import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/fieldzilla-production"))
from application_iam import deployment_policy
from test_production_application_plan import manifest


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.inputs = {
            "scope": "production",
            "application": manifest(),
            "container_instance_arn": "arn:aws:ecs:ap-south-1:918870682888:container-instance/fieldzilla-production/"
            + "d" * 32,
            "snapshot_id": "fieldzilla-production-pre-release-20261110",
        }

    def test_no_unbounded_resource_secret_read_or_routing_write(self):
        policy = deployment_policy(self.inputs)
        for statement in policy["Statement"]:
            self.assertEqual(statement["Effect"], "Allow")
            self.assertNotIn("*", statement["Resource"])
            for action in statement["Action"]:
                self.assertNotIn("*", action)
                self.assertFalse(action.startswith(("secretsmanager:", "kms:")))
                if action.startswith("iam:"):
                    self.assertEqual(action, "iam:PassRole")
                if action.startswith("elasticloadbalancing:"):
                    self.assertEqual(
                        action, "elasticloadbalancing:DescribeTargetHealth"
                    )

    def test_task_listing_and_passrole_are_resource_scoped(self):
        statements = deployment_policy(self.inputs)["Statement"]
        listing = next(s for s in statements if "ecs:ListTasks" in s["Action"])
        self.assertEqual(listing["Resource"], [self.inputs["container_instance_arn"]])
        self.assertEqual(
            listing["Condition"]["ArnEquals"]["ecs:cluster"],
            "arn:aws:ecs:ap-south-1:918870682888:cluster/fieldzilla-production",
        )
        delegation = next(s for s in statements if "iam:PassRole" in s["Action"])
        self.assertEqual(len(delegation["Resource"]), 4)
        self.assertEqual(
            delegation["Condition"]["StringEquals"]["iam:PassedToService"],
            "ecs-tasks.amazonaws.com",
        )

    def test_wrong_environment_host_or_snapshot_cannot_render(self):
        for key, value in (
            ("scope", "staging"),
            (
                "container_instance_arn",
                self.inputs["container_instance_arn"].replace("production", "staging"),
            ),
            ("snapshot_id", "shared-unreviewed-snapshot"),
        ):
            inputs = copy.deepcopy(self.inputs)
            inputs[key] = value
            with self.assertRaises(ValueError):
                deployment_policy(inputs)

    def test_recovery_scaling_does_not_require_changing_task_definition(self):
        rows = {row["Sid"]: row for row in deployment_policy(self.inputs)["Statement"]}
        self.assertIn("ArnLikeIfExists", rows["UpdateOnlyTargetServices"]["Condition"])
        self.assertEqual(rows["RegisterOnlyTargetFamilies"]["Condition"]["StringEqualsIfExists"]["ecs:privileged"], "false")
        self.assertNotIn("BoolIfExists", rows["RegisterOnlyTargetFamilies"]["Condition"])
        self.assertIn("ArnLike", rows["CreateOnlyTargetServices"]["Condition"])
        self.assertEqual(len(rows["RunOnlyMigrationFamily"]["Resource"]), 1)
        self.assertIn("-migration:", rows["RunOnlyMigrationFamily"]["Resource"][0])


if __name__ == "__main__":
    unittest.main()
