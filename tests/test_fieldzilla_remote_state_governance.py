from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/fieldzilla-staging-opentofu-apply.yml"
AUTHORIZER = ROOT / "actions/opentofu-plan-authorizer/opentofu_plan_authorization.py"


def load_authorizer():
    spec = importlib.util.spec_from_file_location("fieldzilla_authorizer", AUTHORIZER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FieldZillaRemoteStateGovernanceTests(unittest.TestCase):
    def test_workflow_uses_locked_remote_state_not_ephemeral_backend(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn('backend "s3"', workflow)
        self.assertIn("STATE_BUCKET: synergie-fieldzilla-opentofu-state-918870682888-ap-south-1", workflow)
        self.assertIn("STATE_LOCK_TABLE: synergie-fieldzilla-opentofu-locks", workflow)
        self.assertIn("put-bucket-versioning", workflow)
        self.assertIn("put-bucket-encryption", workflow)
        self.assertIn("put-public-access-block", workflow)
        self.assertIn("aws dynamodb create-table", workflow)
        self.assertIn('"bootstrap","plan","import","post-import-plan","drift","apply"', workflow)
        self.assertIn("tofu -chdir=infra/aws init -input=false -lockfile=readonly", workflow)
        self.assertNotIn("-backend=false", workflow)
        self.assertNotIn("devops-audit", workflow)

    def test_workflow_gates_import_before_state_mutation_and_backs_up_state(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("Backup current remote state object", workflow)
        self.assertIn("Backup imported remote state object", workflow)
        self.assertIn("fieldzilla-staging-state-evidence", workflow)
        self.assertIn("s3://${STATE_BUCKET}/backups/${GITHUB_RUN_ID}", workflow)
        self.assertIn("import-map-json is required for import mode", workflow)
        verify_index = workflow.index("name: Verify approved import map")
        import_index = workflow.index("name: Controlled import into locked remote state")
        self.assertLess(verify_index, import_index)
        self.assertIn('"import-map.json"', workflow)
        self.assertIn('"tofu", "-chdir=infra/aws", "import", "-input=false", "-lock=true"', workflow)

    def test_workflow_preserves_exact_artifact_and_oidc_release_binding(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("CENTRAL_WORKFLOW_REF: Synergie-ITCI/.github/.github/workflows/fieldzilla-staging-opentofu-apply.yml@refs/tags/pr-qa-v1-rc122", workflow)
        self.assertIn("Verify OIDC token claims", workflow)
        self.assertIn("verify-source-artifact", workflow)
        self.assertIn("mark-used", workflow)
        self.assertIn("tofu -chdir=infra/aws apply -input=false -lock=true", workflow)

    def test_plan_safety_rejects_destructive_dns_or_production_changes(self) -> None:
        module = load_authorizer()
        base = {
            "variables": {
                "enable_production": {"value": False},
                "route53_zone_id": {"value": ""},
                "container_instance_type": {"value": "t4g.small"},
                "monthly_budget_usd": {"value": "100"},
            },
            "resource_changes": [],
        }
        cases = [
            {"address": "aws_s3_bucket.evidence", "type": "aws_s3_bucket", "change": {"actions": ["delete"]}},
            {"address": "aws_route53_record.cert", "type": "aws_route53_record", "change": {"actions": ["create"]}},
            {"address": "aws_ecs_service.production", "type": "aws_ecs_service", "change": {"actions": ["create"]}},
        ]

        for change in cases:
            with self.subTest(change=change["address"]):
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "plan.json"
                    doc = dict(base)
                    doc["resource_changes"] = [change]
                    path.write_text(json.dumps(doc), encoding="utf-8")
                    with self.assertRaises(SystemExit):
                        module.verify_plan_safety(type("Args", (), {"plan_json_path": path, "plan_kind": "normal"})())

    def test_post_import_plan_must_be_clean(self) -> None:
        module = load_authorizer()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.json"
            path.write_text(
                json.dumps(
                    {
                        "variables": {
                            "enable_production": {"value": False},
                            "route53_zone_id": {"value": ""},
                            "container_instance_type": {"value": "t4g.small"},
                            "monthly_budget_usd": {"value": "100"},
                        },
                        "resource_changes": [
                            {
                                "address": "aws_vpc.app",
                                "type": "aws_vpc",
                                "change": {"actions": ["update"], "after": {}},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                module.verify_plan_safety(
                    type("Args", (), {"plan_json_path": path, "plan_kind": "post-import"})()
                )

    def test_import_map_requires_fieldzilla_ownership_and_allowed_type(self) -> None:
        module = load_authorizer()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "import-map.json"
            payload = {
                "repository": "Synergie-ITCI/programme-management-platform",
                "environment": "synergie-app-staging",
                "imports": [
                    {
                        "address": "aws_s3_bucket_lifecycle_configuration.evidence",
                        "id": "fz-evidence-example",
                        "evidence": {
                            "Application": "fieldzilla",
                            "Repository": "Synergie-ITCI/programme-management-platform",
                        },
                    }
                ],
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            expected = module.sha256_file(path)
            module.verify_import_map(
                type(
                    "Args",
                    (),
                    {"import_map_path": path, "expected_import_map_sha256": expected},
                )()
            )

            payload["imports"][0]["evidence"]["Application"] = "other"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(SystemExit):
                module.verify_import_map(
                    type(
                        "Args",
                        (),
                        {"import_map_path": path, "expected_import_map_sha256": module.sha256_file(path)},
                    )()
                )


if __name__ == "__main__":
    unittest.main()
