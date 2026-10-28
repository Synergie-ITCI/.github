"""Bind the scoped RoadSense build role and workflow to one approved pair."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATABASE = "5f26e3081b65b095389eeaeeb1871e27c001928138a71e1363a976a402731512"
POLICY = "003023b6060daeb99534baafc82616867b7dd5df3ba0c91af97034a8a4522e25"
INVENTORY = "3e3e61385f632a2a88a99cf146855e2f5f095eb72130345e1e7f624afe80f49e"
VERSION = "llxUjX.WIAcZoPCnuCoBuZ3OsAJnXiwk"


class ScopedBuildTests(unittest.TestCase):
    def test_build_reads_only_the_approved_database_version(self):
        policy = json.loads((ROOT / "iam/roadsense-build-policy.json").read_text())
        read = next(item for item in policy["Statement"] if item["Action"] == "s3:GetObjectVersion")
        self.assertEqual(read["Resource"].rsplit("/", 2)[-2:], [DATABASE, "road_safety_pilot.sqlite"])
        self.assertEqual(read["Condition"]["StringEquals"]["s3:VersionId"], VERSION)

    def test_build_checks_policy_inventory_and_database_before_image(self):
        workflow = (ROOT / ".github/workflows/roadsense-build-release.yml").read_text()
        for value in (DATABASE, POLICY, INVENTORY, VERSION,
                      "2026-10-27-scoped-publication-owner-approved-candidate-v1"):
            self.assertIn(value, workflow)
        self.assertIn("'231'", workflow)
        self.assertIn("'11'", workflow)
        self.assertLess(workflow.index("Validate publication policy before artifact access"),
                        workflow.index("Build exact image with bundled held database"))

    def test_build_oidc_trust_pins_immutable_v10_workflow(self):
        trust = json.loads((ROOT / "iam/roadsense-build-trust.json").read_text())
        self.assertEqual(
            trust["Statement"][0]["Condition"]["StringEquals"][
                "token.actions.githubusercontent.com:job_workflow_ref"],
            "Synergie-ITCI/.github/.github/workflows/roadsense-build-release.yml"
            "@refs/tags/roadsense-gate-d-v10",
        )


if __name__ == "__main__":
    unittest.main()
