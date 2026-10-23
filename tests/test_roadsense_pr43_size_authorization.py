"""The main promotion reuses the same reviewed patch with independent PR QA."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
import pr_qa as qa
from adapters.base import PRContext


class RoadSensePr43SizeAuthorizationTests(unittest.TestCase):
    def test_main_promotion_selects_same_authorization(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        authorizations = policy["one_time_baseline_alignments"]
        source = next(item for item in authorizations if item.get("pr_number") == 41
                      and item.get("repository") == "Synergie-ITCI/roadsense-production-dashboard")
        ctx = PRContext(repo=ROOT, config={}, policy=policy, changed_files=[],
                        head_ref="promotion/bengaluru-coverage-recovery-main", base_ref="main",
                        event={"repository": {"full_name": source["repository"]},
                               "pull_request": {"number": 43}})
        self.assertEqual(qa.baseline_policy(ctx), source)
        self.assertIn({"head_ref": ctx.head_ref, "base_ref": ctx.base_ref}, source["promotion_scope"]["branches"])
        self.assertEqual(source["relaxations"], ["diff_size"])
        ctx.head_ref = "promotion/unreviewed"
        self.assertNotEqual(qa.baseline_policy(ctx), source)
