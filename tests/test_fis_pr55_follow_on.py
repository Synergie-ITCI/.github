"""Keep the FIS follow-on release authorization bound to one reviewed PR."""

import json
from pathlib import Path
import tempfile
from unittest import TestCase, mock

from test_pr_qa_regressions import load_engine_module


ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
ENTRY = next(row for row in POLICY["governance"]["critical_infrastructure_paths"]
             if row.get("repository") == "Synergie-ITCI/fis.synergielms.com"
             and row.get("pr_number") == 55)


class FisPr55FollowOnTests(TestCase):
    def test_authorization_is_exact_and_preserves_all_controls(self):
        self.assertEqual(ENTRY["expected_base_sha"],
                         "b1f86b0ac589fa2bd339d3368f32d63adb914a81")
        self.assertEqual(ENTRY["expected_head_sha"],
                         "ab9c90812c79b665bbd654733f82988c660f06a0")
        self.assertEqual(set(ENTRY["paths"]), set(ENTRY["file_sha256"]))
        self.assertEqual(len(ENTRY["paths"]), 11)
        self.assertEqual(ENTRY["file_sha256"][".github/workflows/pr-qa.yml"],
                         "6ed34120ade41f7918712787b3d5e8fd2cbf628059122e3ad3455340b647f8d5")
        self.assertEqual(ENTRY["required_reviewers"], ["SaurabhVermaIN"])
        self.assertIn("fresh-backup-and-rollback", ENTRY["required_controls"])
        self.assertIn("exact-head-and-file-sha256", ENTRY["required_controls"])

    def test_engine_rejects_unreviewed_head_base_path_and_bytes(self):
        engine = load_engine_module()
        path = "deploy/ssm-fis-gate-d-production.sh"
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "deploy").mkdir()
            (repo / path).write_text("unreviewed")
            event = {"repository": {"full_name": ENTRY["repository"]},
                     "pull_request": {"number": 55,
                                      "head": {"sha": ENTRY["expected_head_sha"]},
                                      "base": {"sha": ENTRY["expected_base_sha"]}}}
            context = engine.PRContext(
                repo=repo, config={},
                policy={"governance": {"critical_infrastructure_paths": [ENTRY]}},
                changed_files=[path], event=event)
            with mock.patch.object(engine, "run_git", return_value=ENTRY["expected_head_sha"]):
                self.assertIsNone(engine.governed_critical_infrastructure_authorization(context, path))
                event["pull_request"]["head"]["sha"] = "a" * 40
                self.assertIsNone(engine.governed_critical_infrastructure_authorization(context, path))
                event["pull_request"]["head"]["sha"] = ENTRY["expected_head_sha"]
                event["pull_request"]["base"]["sha"] = "b" * 40
                self.assertIsNone(engine.governed_critical_infrastructure_authorization(context, path))
                event["pull_request"]["base"]["sha"] = ENTRY["expected_base_sha"]
                self.assertIsNone(engine.governed_critical_infrastructure_authorization(
                    context, "deploy/unreviewed.sh"))
