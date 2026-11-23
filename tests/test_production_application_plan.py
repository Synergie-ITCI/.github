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


class TrustedProxyTests(unittest.TestCase):
    NAME = "APP_TRUSTED_PROXY_COUNT"

    @staticmethod
    def env(plan, family_suffix):
        definition = next(row for row in plan["task_definitions"] if row["family"].endswith(family_suffix))
        return {row["name"]: row["value"] for row in definition["containerDefinitions"][0].get("environment", [])}

    def test_only_the_production_api_task_trusts_exactly_one_proxy_hop(self):
        plan = render(manifest())
        self.assertEqual(self.env(plan, "-api")[self.NAME], "1")
        self.assertNotIn(self.NAME, self.env(plan, "-admin-web"))
        self.assertNotIn(self.NAME, self.env(plan, "-migration"))

    def test_the_isolated_rehearsal_is_not_behind_the_production_alb_and_trusts_no_proxy(self):
        inputs = manifest()
        for key in ("api_execution_role", "migration_execution_role", "admin_execution_role", "api_task_role"):
            inputs[key] = inputs[key].replace("Production", "ProductionRehearsal")
        for key in ("runtime_secret", "migration_secret"):
            inputs[key] = inputs[key].replace("/production/", "/production-rehearsal/")
        for key in ("api_target_group", "admin-web_target_group"):
            inputs[key] = inputs[key].replace("pmp-production-", "pmp-production-rehearsal-")
        plan = render(inputs, scope="production-rehearsal")
        self.assertNotIn(self.NAME, self.env(plan, "-api"))

    def test_the_rest_of_the_api_configuration_is_unchanged(self):
        env = self.env(render(manifest()), "-api")
        self.assertEqual(
            set(env) - {self.NAME},
            {"APP_ENVIRONMENT", "APP_OBJECT_STORAGE_BACKEND", "APP_OBJECT_STORAGE_REGION",
             "APP_ADMIN_WEB_BASE_URL", "APP_CORS_ORIGINS"},
        )


class PlanTests(unittest.TestCase):
    def test_pr853_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR853_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr844_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR844_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr841_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR841_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr835_uses_only_reviewed_password_reset_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR835_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "upgrade", "20261121_0078"])

    def test_pr814_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR814_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr816_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR816_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr819_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR819_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr811_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR811_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr808_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR808_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr806_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR806_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr804_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR804_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr802_sql_free_task_cannot_run_a_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR802_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "current"])

    def test_pr798_uses_reviewed_mother_bridge_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR798_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "upgrade", "20261117_0077"])

    def test_pr787_uses_reviewed_operational_role_migration(self):
        inputs = manifest()
        inputs["source_sha"] = module.PR787_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "upgrade", "20261116_0075"])

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
