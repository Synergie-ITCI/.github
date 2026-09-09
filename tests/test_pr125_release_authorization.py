"""Exercise the exact temporary release policy without making it time-dependent."""

import copy
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from unittest import mock

from tests import test_baseline_live_binding as existing


class ExactPr125AuthorizationTests(existing.BaselineLiveBindingTests):
    def setUp(self):
        super().setUp()
        self.central_policy = json.loads(
            (existing.ROOT / "policy/pr-qa-policy.json").read_text()
        )
        authorization = self.central_policy.get("one_time_baseline_alignment")
        if authorization is None:
            # Cleanup removes the runtime policy, while this regression retains
            # the exact immutable rc101 artifact as historical test evidence.
            archived = subprocess.check_output(
                ["git", "show", "pr-qa-v1-rc101:policy/pr-qa-policy.json"],
                cwd=existing.ROOT,
                text=True,
            )
            authorization = json.loads(archived)["one_time_baseline_alignment"]
        self.policy = copy.deepcopy(authorization)
        self.sha = self.policy["expected_head_sha"]
        self.base = self.policy["expected_base_sha"]
        self.repository = self.policy["repository"]
        self.now = datetime.fromisoformat(self.policy["issued_at"]) + timedelta(
            minutes=1
        )
        frozen = mock.patch.object(existing.binding, "datetime", wraps=datetime).start()
        frozen.now.return_value = self.now
        self.ctx.head_ref = self.policy["head_ref"]
        self.ctx.base_ref = self.policy["base_ref"]
        self.ctx.pr_body = self.policy["required_pr_body_marker"]
        self.ctx.event["repository"]["full_name"] = self.repository
        self.gc = {"head_sha": self.sha, "base_sha": self.base}
        self.git.return_value.stdout = self.sha + "\n"
        self.live["body"] = self.ctx.pr_body
        self.live["head"].update(sha=self.sha, ref=self.ctx.head_ref)
        self.live["base"].update(sha=self.base, ref=self.ctx.base_ref)
        for side in ("head", "base"):
            self.live[side]["repo"]["full_name"] = self.repository
        os.environ["GITHUB_REPOSITORY"] = self.repository

    def engine(self):
        spec = importlib.util.spec_from_file_location(
            "pr125_policy_engine", existing.ROOT / "pr-qa/pr_qa.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def test_exact_policy_has_only_approved_coordinates_and_relaxation(self):
        self.assertEqual(self.repository, "Synergie-ITCI/programme-management-platform")
        self.assertEqual(self.policy["pr_number"], 125)
        self.assertEqual(self.sha, "17d32f62e4686acdcd6e613b8b99b23c0b1a4ac3")
        self.assertEqual(self.base, "c502dc88bd3f9288cf3cb6a2684523a7b89f78fa")
        self.assertEqual(self.ctx.head_ref, "chore/mobile-prettier-baseline-20260909")
        self.assertEqual(
            self.ctx.base_ref, "integration/mobile-household-sync-contract-20260909"
        )
        self.assertEqual(self.policy["relaxations"], ["diff_size"])
        self.assertEqual(self.policy["allowed_changed_files"], 107)
        self.assertEqual(self.policy["allowed_effective_additions"], 10857)
        self.assertFalse(
            any("secret" in field or "allowlist" in field for field in self.policy)
        )

    def test_unmatched_and_omitted_consumers_keep_both_default_limits(self):
        engine = self.engine()
        for repository in (
            self.repository,
            "Synergie-ITCI/.github",
            "Synergie-ITCI/jkcementypsscholarship",
            "Synergie-ITCI/telemedicine-backend",
            "Synergie-ITCI/saksham-backend",
            "external/example",
        ):
            with self.subTest(repository=repository):
                ctx = existing.PRContext(
                    repo=existing.ROOT,
                    config=copy.deepcopy(self.central_policy["defaults"]),
                    policy={
                        **self.central_policy,
                        "one_time_baseline_alignment": self.policy,
                    },
                    changed_files=[f"file-{i}.py" for i in range(201)],
                    additions=5001,
                    head_ref="feature/example",
                    base_ref="development",
                    event={
                        "repository": {"full_name": repository},
                        "pull_request": {"number": 999},
                    },
                )
                with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": repository}):
                    self.assertEqual(
                        engine.gate_baseline_alignment(ctx, self.gc)[0].status, "PASS"
                    )
                    self.assertFalse(engine.baseline_active(ctx))
                    findings = engine.risk_threshold_findings(ctx)
                    self.assertTrue(
                        any("max_additions=5000" in item for item in findings)
                    )
                    self.assertTrue(
                        any("max_changed_files=200" in item for item in findings)
                    )
                    ctx.event["pull_request"]["labels"] = [
                        {"name": "one-time-baseline-alignment"}
                    ]
                    self.assertEqual(
                        engine.gate_baseline_alignment(ctx, self.gc)[0].status, "FAIL"
                    )
                    self.assertFalse(engine.baseline_active(ctx))
        self.http.assert_not_called()

    def test_exact_live_candidate_relaxes_only_additions(self):
        engine = self.engine()
        self.ctx.policy = {
            **self.central_policy,
            "one_time_baseline_alignment": self.policy,
        }
        self.ctx.additions = 10857
        self.ctx.changed_files = [f"file-{i}.py" for i in range(107)]
        result = engine.gate_baseline_alignment(self.ctx, self.gc)
        self.assertEqual(result[0].status, "PASS", result[0].details)
        self.assertEqual(engine.baseline_relaxations(self.ctx), {"diff_size"})
        self.assertEqual(engine.risk_threshold_findings(self.ctx), [])
        self.assertFalse(engine.baseline_allows(self.ctx, "changed_file_count"))
