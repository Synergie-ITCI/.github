import copy
import importlib.util
import unittest
from pathlib import Path

source = (
    Path(__file__).resolve().parents[1]
    / "scripts/fieldzilla-production/application_plan.py"
)
spec = importlib.util.spec_from_file_location("production_application_plan", source)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
render = module.render


def manifest():
    prefix = "arn:aws:iam::918870682888:role/FieldzillaProduction"
    return {
        "source_sha": "a" * 40,
        "api_digest": "sha256:" + "b" * 64,
        "admin-web_digest": "sha256:" + "c" * 64,
        **{
            key: prefix + suffix
            for key, suffix in [
                ("api_execution_role", "ApiExecution"),
                ("migration_execution_role", "MigrationExecution"),
                ("admin_execution_role", "AdminExecution"),
                ("api_task_role", "ApiTask"),
            ]
        },
        "runtime_secret": (
            "arn:aws:secretsmanager:ap-south-1:918870682888:"
            "secret:/synergie/fieldzilla/production/runtime-Ab1234"
        ),
        "migration_secret": (
            "arn:aws:secretsmanager:ap-south-1:918870682888:"
            "secret:/synergie/fieldzilla/production/migration-Cd5678"
        ),
        **{
            kind + "_target_group": (
                "arn:aws:elasticloadbalancing:ap-south-1:918870682888:targetgroup/pmp-production-"
            )
            + name
            + "/0123456789abcdef"
            for kind, name in [("api", "api"), ("admin-web", "admin")]
        },
    }


class PlanTests(unittest.TestCase):
    def test_zero_services_and_no_cutover(self):
        plan = render(manifest())
        self.assertTrue(
            all(service["desiredCount"] == 0 for service in plan["service_preparation"])
        )
        self.assertNotIn("listener", plan)
        for service in plan["service_preparation"]:
            self.assertEqual(
                service["deploymentConfiguration"]["deploymentCircuitBreaker"],
                {"enable": True, "rollback": False},
            )
        self.assertEqual(len(plan["task_definitions"]), 3)
        self.assertNotIn("taskRoleArn", plan["task_definitions"][2])
        for task in plan["task_definitions"]:
            self.assertIn("@sha256:", task["containerDefinitions"][0]["image"])
        migration = plan["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(
            migration["command"],
            ["python", "scripts/production_historical_migrate.py"],
        )

    def test_migration_bootstrap_context_without_api_credential_access(self):
        inputs = manifest()
        tasks = {task["family"]: task for task in render(inputs)["task_definitions"]}
        migration = tasks["fieldzilla-production-migration"]["containerDefinitions"][0]
        api = tasks["fieldzilla-production-api"]["containerDefinitions"][0]
        migration_refs = {
            item["name"]: item["valueFrom"] for item in migration["secrets"]
        }
        api_refs = {item["name"]: item["valueFrom"] for item in api["secrets"]}
        self.assertEqual(
            set(migration_refs), {"APP_DATABASE_URL", "APP_DATABASE_CONTEXT_SECRET"}
        )
        self.assertEqual(
            migration_refs["APP_DATABASE_CONTEXT_SECRET"],
            inputs["migration_secret"] + ":APP_DATABASE_CONTEXT_SECRET::",
        )
        self.assertEqual(
            api_refs["APP_DATABASE_CONTEXT_SECRET"],
            inputs["runtime_secret"] + ":APP_DATABASE_CONTEXT_SECRET::",
        )
        self.assertEqual(
            api_refs["APP_FIELD_ENCRYPTION_LEGACY_KEYS"],
            inputs["runtime_secret"] + ":APP_FIELD_ENCRYPTION_LEGACY_KEYS::",
        )
        self.assertTrue(
            all(
                value.startswith(inputs["migration_secret"] + ":")
                for value in migration_refs.values()
            )
        )

    def test_reject_wrong_environment_account_region_or_mutable_image(self):
        good = manifest()
        mutations = [
            (
                "api_target_group",
                good["api_target_group"].replace("production", "staging"),
            ),
            ("runtime_secret", good["runtime_secret"].replace("production", "staging")),
            (
                "api_execution_role",
                good["api_execution_role"].replace("918870682888", "111111111111"),
            ),
            (
                "migration_secret",
                good["migration_secret"].replace("ap-south-1", "us-east-1"),
            ),
            ("api_digest", "latest"),
            ("source_sha", "main"),
        ]
        for key, value in mutations:
            bad = copy.deepcopy(good)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                render(bad)

    def test_migration_cannot_reuse_runtime_identity_or_credentials(self):
        for key, source in [
            ("migration_execution_role", "api_execution_role"),
            ("migration_secret", "runtime_secret"),
        ]:
            bad = manifest()
            bad[key] = bad[source]
            with self.assertRaises(ValueError):
                render(bad)


if __name__ == "__main__":
    unittest.main()


class RehearsalPlanTests(unittest.TestCase):
    def test_rehearsal_has_its_own_tasks_roles_secrets_targets_and_logs(self):
        inputs = manifest()
        for key in (
            "api_execution_role",
            "migration_execution_role",
            "admin_execution_role",
            "api_task_role",
        ):
            inputs[key] = inputs[key].replace("Production", "ProductionRehearsal")
        for key in ("runtime_secret", "migration_secret"):
            inputs[key] = inputs[key].replace("/production/", "/production-rehearsal/")
        for key in ("api_target_group", "admin-web_target_group"):
            inputs[key] = inputs[key].replace(
                "pmp-production-", "pmp-production-rehearsal-"
            )
        plan = render(inputs, scope="production-rehearsal")
        self.assertEqual(
            plan["task_definitions"][2]["containerDefinitions"][0]["command"],
            ["alembic", "upgrade", "fieldzilla_pr119@head"],
        )
        for definition in plan["task_definitions"]:
            self.assertTrue(
                definition["family"].startswith("fieldzilla-production-rehearsal-")
            )
            container = definition["containerDefinitions"][0]
            self.assertIn(
                "/production-rehearsal/",
                container["logConfiguration"]["options"]["awslogs-group"],
            )
            for secret in container.get("secrets", []):
                self.assertIn("/production-rehearsal/", secret["valueFrom"])
                self.assertNotEqual(secret["name"], "APP_FIELD_ENCRYPTION_LEGACY_KEYS")
            self.assertNotIn(
                "https://fieldzilla.synergieinsights.in",
                str(container.get("environment", [])),
            )
            # The same immutable candidate images are intentionally reused.
            self.assertIn("/synergie/fieldzilla/production/", container["image"])
        self.assertTrue(
            all(
                s["cluster"] == "fieldzilla-production-rehearsal"
                for s in plan["service_preparation"]
            )
        )

    def test_rehearsal_never_accepts_production_or_staging_refs(self):
        with self.assertRaises(ValueError):
            render(manifest(), scope="production-rehearsal")
        with self.assertRaises(ValueError):
            render(manifest(), scope="staging")
