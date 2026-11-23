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
        self.assertEqual(len(rows["RunOnlyAttestationAndMigrationFamilies"]["Resource"]), 2)
        self.assertTrue(any("-migration:" in resource for resource in rows["RunOnlyAttestationAndMigrationFamilies"]["Resource"]))
        self.assertTrue(any("-api:" in resource for resource in rows["RunOnlyAttestationAndMigrationFamilies"]["Resource"]))

    def test_production_worker_control_is_exactly_scoped(self):
        rows = {row["Sid"]: row for row in deployment_policy(self.inputs)["Statement"]}
        worker = "arn:aws:ecs:ap-south-1:918870682888:service/fieldzilla-production/fieldzilla-production-worker"
        self.assertIn(worker, rows["ReadExactServices"]["Resource"])
        self.assertIn(worker, rows["UpdateOnlyTargetServices"]["Resource"])
        self.assertNotIn(worker, rows["CreateOnlyTargetServices"]["Resource"])


if __name__ == "__main__":
    unittest.main()


class WorkerRolloutPolicyTests(unittest.TestCase):
    def setUp(self):
        application = manifest()
        self.base = {
            "scope": "production",
            "application": application,
            "container_instance_arn": "arn:aws:ecs:ap-south-1:918870682888:container-instance/fieldzilla-production/"
            + "d" * 32,
            "snapshot_id": "fieldzilla-production-pre-release-20261110",
        }
        self.rollout = copy.deepcopy(self.base)
        self.rollout["worker_target_digest"] = application["api_digest"]
        self.family = "arn:aws:ecs:ap-south-1:918870682888:task-definition/fieldzilla-production-worker:*"

    @staticmethod
    def statement(policy, sid):
        return next((s for s in policy["Statement"] if s["Sid"] == sid), None)

    def test_without_a_worker_rollout_the_worker_family_is_not_granted(self):
        policy = deployment_policy(self.base)
        for sid in ("RegisterOnlyTargetFamilies", "TagOnlyDuringRegistration"):
            self.assertNotIn(self.family, self.statement(policy, sid)["Resource"])
        self.assertIsNone(self.statement(policy, "ReadPriorWorkerDefinition"))
        update = self.statement(policy, "UpdateOnlyTargetServices")
        self.assertNotIn(self.family, update["Condition"]["ArnLikeIfExists"]["ecs:task-definition"])

    def test_a_worker_rollout_adds_exactly_the_worker_family_and_a_read_only_describe(self):
        before = deployment_policy(self.base)
        after = deployment_policy(self.rollout)
        for sid in ("RegisterOnlyTargetFamilies", "TagOnlyDuringRegistration"):
            self.assertEqual(
                self.statement(after, sid)["Resource"],
                self.statement(before, sid)["Resource"] + [self.family],
            )
        register = self.statement(after, "RegisterOnlyTargetFamilies")
        self.assertEqual(register["Condition"]["StringEquals"]["aws:RequestTag/environment"], "production")
        update = self.statement(after, "UpdateOnlyTargetServices")
        self.assertIn(self.family, update["Condition"]["ArnLikeIfExists"]["ecs:task-definition"])
        # The worker service was already updatable (stop and restore); nothing else is added.
        self.assertEqual(update["Resource"], self.statement(before, "UpdateOnlyTargetServices")["Resource"])
        describe = self.statement(after, "ReadPriorWorkerDefinition")
        self.assertEqual(describe["Action"], ["ecs:DescribeTaskDefinition"])
        self.assertEqual(describe["Resource"], ["*"])
        # No other statement gained an unbounded resource, secret read, or routing write.
        added = {s["Sid"] for s in after["Statement"]} - {s["Sid"] for s in before["Statement"]}
        self.assertEqual(added, {"ReadPriorWorkerDefinition"})
        for statement in after["Statement"]:
            if statement["Sid"] != "ReadPriorWorkerDefinition":
                self.assertNotIn("*", statement["Resource"])
