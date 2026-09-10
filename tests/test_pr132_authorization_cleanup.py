"""Regression proof that the temporary PR132 authorization remains isolated."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "pr-qa" / "pr_qa.py"


def load_engine():
    spec = importlib.util.spec_from_file_location("pr132_cleanup_engine", ENGINE)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.path.insert(0, str(ENGINE.parent))
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Pr132AuthorizationIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = load_engine()
        self.policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        self.config = copy.deepcopy(self.policy["defaults"])
        self.git_context = {
            "head_sha": "1f2e18a3b58a5520b3981e86445d2b4023018223",
            "base_sha": "0c3185b2ec1846e193e71b2a3b54d2bea6d11e56",
        }

    def context(self, repository: str, number: int = 132):
        return self.engine.PRContext(
            repo=ROOT,
            config=copy.deepcopy(self.config),
            policy=copy.deepcopy(self.policy),
            changed_files=[f"file-{index}.py" for index in range(201)],
            additions=5001,
            head_ref="release/mobile-household-sync-alignment-20260909",
            base_ref="development",
            event={
                "repository": {"full_name": repository},
                "pull_request": {
                    "number": number,
                    "body": "one-time-baseline-pr132-fb31d4ab-3d6e-423d-b2f0-8e0a28ecbda8",
                    "labels": [],
                },
            },
        )

    def test_current_policy_contains_only_the_fresh_exact_authorization(self) -> None:
        authorization = self.policy["one_time_baseline_alignment"]
        self.assertEqual(authorization["repository"], "Synergie-ITCI/programme-management-platform")
        self.assertEqual(authorization["repository_id"], 1315697868)
        self.assertEqual(authorization["pr_number"], 132)
        self.assertEqual(authorization["expected_head_sha"], "1f2e18a3b58a5520b3981e86445d2b4023018223")
        self.assertEqual(authorization["allowed_effective_additions"], 25492)
        self.assertEqual(authorization["allowed_changed_files"], 182)
        self.assertEqual(authorization["relaxations"], ["diff_size", "exact_gitleaks_fingerprint_allowlist"])
        serialized = json.dumps(self.policy, sort_keys=True)
        self.assertNotIn("fb31d4ab-3d6e-423d-b2f0-8e0a28ecbda8", serialized)
        self.assertNotIn("dcc05ff1-e09c-4a90-85a8-f3a538991444", serialized)
        self.assertEqual(serialized.count("one-time-baseline-pr132-"), 1)

    def test_obsolete_pr132_marker_request_fails_closed(self) -> None:
        ctx = self.context("Synergie-ITCI/programme-management-platform")
        with mock.patch.dict(
            os.environ,
            {
                "PR_QA_BASELINE_ALIGNMENT": "true",
                "GITHUB_REPOSITORY": "Synergie-ITCI/programme-management-platform",
            },
            clear=False,
        ):
            result = self.engine.gate_baseline_alignment(ctx, self.git_context)[0]
        self.assertEqual(result.status, "FAIL")
        self.assertIn("failed closed", result.message)
        self.assertFalse(self.engine.baseline_active(ctx))

    def test_unmatched_consumers_retain_default_limits_and_no_relaxation(self) -> None:
        self.assertEqual(self.policy["minimum_thresholds"]["max_additions"], 5000)
        self.assertEqual(self.policy["minimum_thresholds"]["max_changed_files"], 200)
        self.assertEqual(self.policy["defaults"]["thresholds"]["max_additions"], 5000)
        self.assertEqual(self.policy["defaults"]["thresholds"]["max_changed_files"], 200)

        for repository in (
            "Synergie-ITCI/programme-management-platform",
            "Synergie-ITCI/.github",
            "Synergie-ITCI/unmatched-consumer",
            "outside/unmatched-consumer",
        ):
            with self.subTest(repository=repository):
                ctx = self.context(repository, number=999)
                with mock.patch.dict(
                    os.environ,
                    {"GITHUB_REPOSITORY": repository},
                    clear=False,
                ):
                    result = self.engine.gate_baseline_alignment(
                        ctx, self.git_context
                    )[0]
                    findings = self.engine.risk_threshold_findings(ctx)
                self.assertEqual(result.status, "PASS")
                self.assertFalse(self.engine.baseline_active(ctx))
                self.assertTrue(
                    any("max_additions=5000" in finding for finding in findings)
                )
                self.assertTrue(
                    any("max_changed_files=200" in finding for finding in findings)
                )


if __name__ == "__main__":
    unittest.main()
