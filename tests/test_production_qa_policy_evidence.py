"""Artifact, execution-identity and activation boundaries; no cloud execution."""

import copy
import hashlib
import io
import json
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/fieldzilla-production"))
from qa_policy_evidence import (
    DETECTOR,
    QUALITY,
    read_final_report,
    verify_pr808_detector_log_recovery,
    verify_pr841_detector_log_recovery,
    verify_pr857_detector_log_recovery,
    verify_qa_policy_evidence,
)


class PR808DetectorRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "promotion_pr": 808,
            "application": {"source_sha": "5d92dd585eda25391297bfd9d408c585f556a4d6"},
            "base_sha": "bd9b3bd3d6b0fa4d7e27448e09a674de3c601aa0",
        }
        self.proof = {
            "run_id": 44451575467,
            "policy_sha": "ea802c2a5e2b7965850db7c19a69bfe12b897f18",
        }
        self.run = {"run_attempt": 2}
        self.detector = {
            "id": 135404339322,
            "head_sha": self.manifest["application"]["source_sha"],
            "started_at": "2026-11-19T07:16:47Z",
            "steps": [
                {"name": name, "conclusion": "success"}
                for name in (
                    "Resolve approved central PR QA release",
                    "Checkout immutable central PR QA framework",
                    "Detect technologies",
                )
            ],
        }
        self.selector = {
            "state": "closed",
            "merge_commit_sha": "a3b0380d9eeb3a5e56d3d24e947ee375c4d3c7bb",
            "head": {"sha": "c862601ff13a6c438854dfaafb7c49eb2a385dd7"},
            "base": {"sha": "6a940de7c493be4aa257bbe2f97977ba021622d4"},
            "merged_at": "2026-11-19T07:13:03Z",
        }
        self.current_main = self.selector["merge_commit_sha"]
        self.ancestry_status = "identical"

    def api(self, path):
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": self.current_main}}
        if "/compare/" in path:
            self.assertEqual(
                path.rsplit("/", 1)[-1],
                f"a3b0380d9eeb3a5e56d3d24e947ee375c4d3c7bb...{self.current_main}",
            )
            return {"status": self.ancestry_status}
        if path.endswith("/pulls/809"):
            return self.selector
        raise AssertionError(path)

    def verify(self, *, now=None):
        from datetime import UTC, datetime

        verify_pr808_detector_log_recovery(
            self.manifest, self.proof, "pr-qa-v1-rc368", self.run,
            self.detector, self.api,
            now=now or datetime(2026, 11, 19, 8, tzinfo=UTC),
        )

    def test_exact_incident_can_use_successful_post_merge_detector(self):
        self.verify()

    def test_later_protected_caller_merge_is_allowed_only_with_selector_ancestry(self):
        self.current_main = "b" * 40
        self.ancestry_status = "ahead"
        self.verify()
        self.ancestry_status = "diverged"
        with self.assertRaisesRegex(ValueError, "not in main ancestry"):
            self.verify()

    def test_other_identity_or_unverified_detector_is_rejected(self):
        for target, key, bad in (
            (self.manifest, "promotion_pr", 807),
            (self.proof, "run_id", 1),
            (self.run, "run_attempt", 1),
            (self.detector, "id", 1),
            (self.detector, "started_at", "2026-11-19T07:12:00Z"),
            (self.selector, "merge_commit_sha", "f" * 40),
        ):
            original = target[key]
            target[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()
            target[key] = original
        self.detector["steps"][0]["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            self.verify()

    def test_recovery_expires_with_review_record(self):
        from datetime import datetime

        with self.assertRaises(ValueError):
            self.verify(now=datetime.fromisoformat("2026-11-20T06:30:11Z"))


class PR841DetectorRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "promotion_pr": 841,
            "application": {"source_sha": "42730e5659959ba708fcfea4d37c80edde71fc9f"},
            "base_sha": "8646fe3583dfdd4985ec6e13fbb5c01fa7bdfb4d",
        }
        self.proof = {"run_id": 44936685431}
        self.run = {"run_attempt": 3}
        self.detector = {
            "head_sha": self.manifest["application"]["source_sha"],
            "started_at": "2026-11-21T20:00:00Z",
            "steps": [
                {"name": name, "conclusion": "success"}
                for name in (
                    "Resolve approved central PR QA release",
                    "Checkout immutable central PR QA framework",
                    "Detect technologies",
                )
            ],
        }
        self.current_main = "f" * 40
        self.ancestry = "ahead"
        self.selector = {
            "state": "closed",
            "merge_commit_sha": "daace8f2312cd77046147aff57911d48de3dd14f",
            "head": {"sha": "9bc40fc589a6c142cf6ff33cf24f6b3b4620eb52"},
            "base": {"sha": "e9e8690e0d212c576c4b34cabaa7abbeb11a9986"},
            "merged_at": "2026-11-21T19:10:17Z",
        }

    def api(self, path):
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": self.current_main}}
        if "/compare/" in path:
            return {"status": self.ancestry}
        if path.endswith("/pulls/842"):
            return self.selector
        raise AssertionError(path)

    def verify(self, *, now=None):
        from datetime import UTC, datetime

        verify_pr841_detector_log_recovery(
            self.manifest, self.proof, "pr-qa-v1-rc393", self.run,
            self.detector, self.api,
            now=now or datetime(2026, 11, 21, 20, tzinfo=UTC),
        )

    def test_only_exact_successful_post_merge_detector_can_recover(self):
        self.verify()
        for target, key, bad in (
            (self.manifest, "promotion_pr", 840),
            (self.proof, "run_id", 1),
            (self.run, "run_attempt", 2),
            (self.detector, "head_sha", "f" * 40),
            (self.detector, "started_at", "2026-11-21T19:00:00Z"),
            (self.selector, "merge_commit_sha", "f" * 40),
        ):
            original = target[key]
            target[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()
            target[key] = original
        self.detector["steps"][0]["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            self.verify()

    def test_ancestry_and_expiry_fail_closed(self):
        from datetime import datetime

        self.ancestry = "diverged"
        with self.assertRaises(ValueError):
            self.verify()
        self.ancestry = "ahead"
        with self.assertRaises(ValueError):
            self.verify(now=datetime.fromisoformat("2026-11-22T17:29:39Z"))


class PR857DetectorRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "promotion_pr": 857,
            "application": {"source_sha": "e1c5f8ecdc4e5e791580cf0b5a81daf19f79a8f9"},
            "base_sha": "601fd19e8fef1a93e3881cca0d0b28423d4d360b",
            "central_tag": "pr-qa-v1-rc401",
            "central_sha": "c" * 40,
        }
        self.proof = {
            "run_id": 45217055941,
            "policy_sha": "c" * 40,
        }
        self.run = {"run_attempt": 4}
        self.detector = {
            "id": 1,
            "head_sha": self.manifest["application"]["source_sha"],
            "started_at": "2026-11-24T03:20:06Z",
            "steps": [
                {"name": name, "conclusion": "success"}
                for name in (
                    "Resolve approved central PR QA release",
                    "Checkout immutable central PR QA framework",
                    "Detect technologies",
                )
            ],
        }
        self.selector = {
            "state": "closed",
            "merge_commit_sha": "f262f4d9203543e27f73278bda2adbc4927fcb46",
            "head": {"sha": "594d4dfa07ee96069f39b193683c59bfa9cdfc05"},
            "base": {"sha": "292dc96beb4a82a73e904267b5ed3d4a1a2a37b0"},
            "merged_at": "2026-11-24T03:19:07Z",
        }
        self.ancestry = "ahead"

    def api(self, path):
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": "f262f4d9203543e27f73278bda2adbc4927fcb46"}}
        if "/compare/" in path:
            return {"status": self.ancestry}
        if path.endswith("/pulls/859"):
            return self.selector
        raise AssertionError(path)

    def verify(self, *, now=None):
        from datetime import UTC, datetime

        verify_pr857_detector_log_recovery(
            self.manifest, self.proof, "pr-qa-v1-rc401", self.run,
            self.detector, self.api,
            now=now or datetime(2026, 11, 24, 3, tzinfo=UTC),
        )

    def test_exact_successful_post_merge_detector_can_recover(self):
        self.verify()
        for target, key, bad in (
            (self.manifest, "promotion_pr", 856),
            (self.proof, "run_id", 1),
            (self.proof, "policy_sha", "f" * 40),
            (self.run, "run_attempt", 3),
            (self.manifest, "central_tag", "pr-qa-v1-rc400"),
            (self.detector, "head_sha", "f" * 40),
            (self.detector, "started_at", "2026-11-24T03:18:00Z"),
            (self.selector, "merge_commit_sha", "f" * 40),
        ):
            original = target[key]
            target[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()
            target[key] = original
        self.detector["steps"][0]["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            self.verify()

    def test_ancestry_and_expiry_fail_closed(self):
        from datetime import datetime

        self.ancestry = "diverged"
        with self.assertRaises(ValueError):
            self.verify()
        self.ancestry = "ahead"
        with self.assertRaises(ValueError):
            self.verify(now=datetime.fromisoformat("2026-11-24T15:30:00Z"))


class QAPolicyTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "scope": "production",
            "promotion_pr": 712,
            "application": {"source_sha": "a" * 40},
            "base_sha": "b" * 40,
            "central_tag": "pr-qa-v1-rc232",
            "central_sha": "c" * 40,
            "qa_evidence": {
                "policy_release": "pr-qa-v1-rc233",
                "policy_sha": "d" * 40,
                "run_id": 11,
                "artifact_id": 22,
                "archive_sha256": "",
            },
        }
        self.checks = {
            QUALITY: {
                "head_sha": "a" * 40,
                "status": "completed",
                "conclusion": "success",
                "app": {"slug": "github-actions"},
                "details_url": "https://github.com/Synergie-ITCI/programme-management-platform/actions/runs/11/job/33",
            }
        }
        self.run = {
            "id": 11,
            "run_attempt": 1,
            "head_sha": "a" * 40,
            "status": "completed",
            "conclusion": "success",
            "event": "pull_request",
            "path": ".github/workflows/pr-qa.yml",
            "pull_requests": [
                {"number": 712, "head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}}
            ],
        }
        self.pr = {
            "number": 712,
            "state": "closed",
            "merged_at": "2026-11-10T10:30:00Z",
            "head": {"sha": "a" * 40, "repo": {"full_name": "Synergie-ITCI/programme-management-platform"}},
            "base": {"ref": "main", "sha": "b" * 40},
        }
        self.jobs = [
            {
                "id": identifier,
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-11-10T10:00:00Z",
                "completed_at": "2026-11-10T10:10:00Z",
            }
            for identifier, name in [(33, QUALITY), (34, DETECTOR)]
        ]
        self.logs = (
            b"2026-11-10T09:59:00.000Z Resolved approved release pr-qa-v1-rc233 at "
            + b"d" * 40
            + b"\n"
        )
        self.log_api_failure = False
        self.run_log_api_failure = False
        self.run_log_override = None
        self.run_log_reads = 0
        self.report = {
            "summary": {
                "repository": "Synergie-ITCI/programme-management-platform",
                "overall_result": "PASS",
                "baseline_alignment": {
                    "authorized": True,
                    "source_sha": "a" * 40,
                    "destination_sha": "b" * 40,
                },
            }
        }
        self.artifact = {
            "id": 22,
            "name": "pr-qa-results",
            "expired": False,
            "created_at": "2026-11-10T10:05:00Z",
            "workflow_run": {
                "id": 11,
                "head_sha": "a" * 40,
                "repository_id": 1315697868,
                "head_repository_id": 1315697868,
            },
        }
        self.selected = ("pr-qa-v1-rc233", {"commit": "d" * 40})
        self.resolved = False
        self.rebuild_archive()

    def rebuild_archive(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr("pr-quality-report.json", json.dumps(self.report))
        self.archive = output.getvalue()
        digest = hashlib.sha256(self.archive).hexdigest()
        self.artifact["digest"] = "sha256:" + digest
        self.manifest["qa_evidence"]["archive_sha256"] = digest

    def resolver(self, selection, consumer, **callbacks):
        self.assertEqual(consumer, "Synergie-ITCI/programme-management-platform")
        self.assertEqual(selection, {"version": 1, "fixture": "live-selection"})
        self.assertEqual(set(callbacks), {"lookup", "list_refs"})
        self.resolved = True
        return self.selected

    def api(self, path):
        import base64

        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": "e" * 40}}
        if "/contents/" in path:
            if "framework-releases.json" in path:
                value = {"version": 1, "fixture": "live-selection"}
            else:
                self.assertTrue(path.endswith("?ref=" + "d" * 40))
                value = {"fixture": "activated policy data"}
            return {
                "type": "file",
                "encoding": "base64",
                "content": base64.b64encode(json.dumps(value).encode()).decode(),
            }
        if path.endswith("/actions/runs/11"):
            return self.run
        if path.endswith(f"/pulls/{self.manifest['promotion_pr']}"):
            return self.pr
        if "/jobs?" in path:
            return {"jobs": self.jobs}
        if path.endswith("/jobs/34/logs"):
            if self.log_api_failure:
                raise RuntimeError("per-job log API unavailable")
            return self.logs
        if path.endswith(f"/runs/11/attempts/{self.run['run_attempt']}/logs"):
            self.run_log_reads += 1
            if self.run_log_api_failure:
                raise RuntimeError("run log API unavailable")
            if self.run_log_override is not None:
                return self.run_log_override
            output = io.BytesIO()
            with zipfile.ZipFile(
                output, "w", compression=zipfile.ZIP_DEFLATED
            ) as zipped:
                zipped.writestr(
                    "1_pr-qa _ Detect repository technologies.txt", self.logs
                )
            return output.getvalue()
        if path.endswith("/artifacts/22"):
            return self.artifact
        if path.endswith("/artifacts/22/zip"):
            return self.archive
        raise AssertionError("Unexpected evidence endpoint: " + path)

    def verify(self):
        return verify_qa_policy_evidence(
            self.manifest, checks=self.checks, api=self.api, resolver=self.resolver
        )

    def test_policy_can_advance_without_changing_fixed_executor_or_caller(self):
        before = copy.deepcopy(self.manifest)
        data = self.verify()
        self.assertTrue(self.resolved)
        self.assertEqual(self.manifest, before)
        self.assertEqual(
            set(data),
            {
                "policy/pr-qa-policy.json",
                "policy/audited-migration-authorizations.json",
            },
        )
        self.assertNotEqual(
            self.manifest["central_tag"], self.manifest["qa_evidence"]["policy_release"]
        )

    def test_both_log_endpoints_require_scoped_recovery_before_final_artifact(self):
        from unittest.mock import patch

        self.log_api_failure = True
        self.run_log_api_failure = True
        with patch("qa_policy_evidence.verify_pr808_detector_log_recovery") as recovery:
            self.verify()
            recovery.assert_called_once()
        with self.assertRaises(ValueError):
            self.verify()

    def test_unselected_policy_or_stale_winning_check_is_rejected(self):
        self.selected = ("pr-qa-v1-rc234", {"commit": "f" * 40})
        with self.assertRaises(ValueError):
            self.verify()
        self.selected = ("pr-qa-v1-rc233", {"commit": "d" * 40})
        self.checks[QUALITY]["details_url"] = self.checks[QUALITY][
            "details_url"
        ].replace("runs/11/", "runs/12/")
        with self.assertRaises(ValueError):
            self.verify()

    def test_different_source_base_or_non_pr_run_cannot_prove_qa(self):
        for key, value in (
            ("head_sha", "f" * 40),
            ("event", "workflow_dispatch"),
            ("status", "in_progress"),
            ("path", "other.yml"),
        ):
            with self.subTest(key=key):
                old = self.run[key]
                self.run[key] = value
                try:
                    with self.assertRaises(ValueError):
                        self.verify()
                finally:
                    self.run[key] = old
        self.run["pull_requests"][0]["base"]["sha"] = "f" * 40
        with self.assertRaises(ValueError):
            self.verify()

    def test_merged_pr_can_supply_only_missing_run_pr_association(self):
        self.run["pull_requests"] = []
        self.verify()
        for field, bad in (("state", "open"), ("merged_at", None), ("number", 713)):
            old = self.pr[field]
            self.pr[field] = bad
            with self.assertRaises(ValueError):
                self.verify()
            self.pr[field] = old
        self.pr["base"]["sha"] = "f" * 40
        with self.assertRaises(ValueError):
            self.verify()
        self.pr["base"]["sha"] = "b" * 40
        self.manifest["scope"] = "production-images"
        self.verify()
        self.manifest["scope"] = "production-rehearsal"
        with self.assertRaises(ValueError):
            self.verify()

    def test_metadata_recovery_can_bind_only_an_explicitly_verified_missing_association(self):
        self.manifest["scope"] = "production-images"
        self.run["pull_requests"] = []
        self.pr.update(state="open", merged_at=None)
        with self.assertRaises(ValueError):
            self.verify()
        self.checks["__merge_metadata_recovery__"] = True
        self.verify()
        self.run["pull_requests"] = [{"number": 713, "head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}}]
        with self.assertRaises(ValueError):
            self.verify()

    def test_ordinary_sql_free_image_qa_needs_exact_pass_without_relaxations(self):
        self.manifest["scope"] = "production-images"
        binding = self.report["summary"]["baseline_alignment"]
        binding.update(requested=False, authorized=False, relaxed_checks=[])
        self.rebuild_archive()
        self.verify()
        for field, invalid in (("requested", True), ("relaxed_checks", ["diff_size"])):
            original = binding[field]
            binding[field] = invalid
            self.rebuild_archive()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify()
            binding[field] = original
        self.rebuild_archive()
        self.manifest["scope"] = "production-rehearsal"
        with self.assertRaises(ValueError):
            self.verify()

    def test_exact_pr772_sql_free_rollout_accepts_only_ordinary_pass(self):
        from issued_windows import SQL_FREE_PRODUCTION_BASE, SQL_FREE_PRODUCTION_SOURCE

        source, base = SQL_FREE_PRODUCTION_SOURCE, SQL_FREE_PRODUCTION_BASE
        self.manifest.update(
            promotion_pr=772, base_sha=base,
            review_authorizations={"baseline": "3317b9b7-46c9-4eec-af94-7542758d7f17", "sql": None},
            database={"name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                      "before": ["20260909_0041", "20261109_0073"],
                      "after": ["20260909_0041", "20261113_0074"]},
        )
        self.manifest["application"]["source_sha"] = source
        self.checks[QUALITY]["head_sha"] = source
        self.run["head_sha"] = source
        self.run["pull_requests"] = [{"number": 772, "head": {"sha": source}, "base": {"sha": base}}]
        self.pr.update(number=772)
        self.pr["head"]["sha"] = source
        self.pr["base"]["sha"] = base
        self.artifact["workflow_run"]["head_sha"] = source
        binding = self.report["summary"]["baseline_alignment"]
        binding.update(requested=False, authorized=False, relaxed_checks=[], source_sha=source, destination_sha=base)
        self.rebuild_archive()
        self.verify()
        for key, invalid in (
            ("promotion_pr", 773), ("base_sha", "f" * 40),
            ("database", {"before": ["20260909_0041", "20261109_0073"], "after": ["20260909_0041", "20261109_0073"]}),
        ):
            with self.subTest(key=key):
                original = self.manifest[key]
                self.manifest[key] = invalid
                with self.assertRaises(ValueError):
                    self.verify()
                self.manifest[key] = original
        for field, invalid in (("requested", True), ("relaxed_checks", ["diff_size"])):
            with self.subTest(field=field):
                original = binding[field]
                binding[field] = invalid
                self.rebuild_archive()
                with self.assertRaises(ValueError):
                    self.verify()
                binding[field] = original
        self.report["summary"]["overall_result"] = "FAIL"
        self.rebuild_archive()
        with self.assertRaises(ValueError):
            self.verify()

    def test_exact_pr780_database_current_rollout_accepts_ordinary_qa_only(self):
        from issued_windows import SQL_FREE_UPDATE_BASE, SQL_FREE_UPDATE_REVISIONS, SQL_FREE_UPDATE_SOURCE

        source, base = SQL_FREE_UPDATE_SOURCE, SQL_FREE_UPDATE_BASE
        self.manifest.update(
            operation="rollout", promotion_pr=780, base_sha=base,
            review_authorizations={"baseline": "59fbdeb7-566b-4d6a-bb40-429a7ffce165", "sql": None},
            database={"name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                      "before": SQL_FREE_UPDATE_REVISIONS, "after": SQL_FREE_UPDATE_REVISIONS},
        )
        self.manifest["application"]["source_sha"] = source
        self.checks[QUALITY]["head_sha"] = source
        self.run["head_sha"] = source
        self.run["pull_requests"] = [{"number": 780, "head": {"sha": source}, "base": {"sha": base}}]
        self.pr.update(number=780)
        self.pr["head"]["sha"] = source
        self.pr["base"]["sha"] = base
        self.artifact["workflow_run"]["head_sha"] = source
        binding = self.report["summary"]["baseline_alignment"]
        binding.update(requested=False, authorized=False, relaxed_checks=[], source_sha=source, destination_sha=base)
        self.rebuild_archive()
        self.verify()
        binding["relaxed_checks"] = ["diff_size"]
        self.rebuild_archive()
        with self.assertRaises(ValueError):
            self.verify()

    def test_exact_pr783_database_current_rollout_accepts_ordinary_qa_only(self):
        from issued_windows import SQL_FREE_PR783_BASE, SQL_FREE_PR783_SOURCE, SQL_FREE_UPDATE_REVISIONS

        source, base = SQL_FREE_PR783_SOURCE, SQL_FREE_PR783_BASE
        self.manifest.update(
            operation="rollout", promotion_pr=783, base_sha=base,
            review_authorizations={"baseline": "2d04d97f-b65e-494e-b53b-2f3cc1bba028", "sql": None},
            database={"name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                      "before": SQL_FREE_UPDATE_REVISIONS, "after": SQL_FREE_UPDATE_REVISIONS},
        )
        self.manifest["application"]["source_sha"] = source
        self.checks[QUALITY]["head_sha"] = source
        self.run["head_sha"] = source
        self.run["pull_requests"] = [{"number": 783, "head": {"sha": source}, "base": {"sha": base}}]
        self.pr.update(number=783)
        self.pr["head"]["sha"] = source
        self.pr["base"]["sha"] = base
        self.artifact["workflow_run"]["head_sha"] = source
        binding = self.report["summary"]["baseline_alignment"]
        binding.update(requested=False, authorized=False, relaxed_checks=[], source_sha=source, destination_sha=base)
        self.rebuild_archive()
        self.verify()
        binding["relaxed_checks"] = ["diff_size"]
        self.rebuild_archive()
        with self.assertRaises(ValueError):
            self.verify()

    def test_exact_pr786_migration_accepts_only_ordinary_qa_and_audited_sql(self):
        source = "2b0753f08aaabdacb780d1abd35fc2d5e80bc181"
        base = "576fba59c0d5958cb623351b29201b4d4aef589c"
        self.manifest.update(
            operation="rollout", promotion_pr=786, base_sha=base,
            review_authorizations={"baseline": "1beec030-e3bf-43c4-b2a1-c3299ddb7219",
                                   "sql": "17fc5f90-d712-4dd8-8085-57353395ff0e"},
            database={"name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                      "before": ["20260909_0041", "20261113_0074"],
                      "after": ["20260909_0041", "20261116_0075"]},
        )
        self.manifest["application"]["source_sha"] = source
        self.checks[QUALITY]["head_sha"] = source
        self.run["head_sha"] = source
        self.run["pull_requests"] = [{"number": 786, "head": {"sha": source}, "base": {"sha": base}}]
        self.pr.update(number=786)
        self.pr["head"]["sha"] = source
        self.pr["base"]["sha"] = base
        self.artifact["workflow_run"]["head_sha"] = source
        binding = self.report["summary"]["baseline_alignment"]
        binding.update(requested=False, authorized=False, relaxed_checks=[], source_sha=source, destination_sha=base)
        self.rebuild_archive()
        self.verify()
        for mutation in (
            lambda: self.manifest["review_authorizations"].update(sql=None),
            lambda: self.manifest["database"].update(after=["20260909_0041", "20261113_0074"]),
            lambda: binding.update(relaxed_checks=["diff_size"]),
        ):
            mutation()
            self.rebuild_archive()
            with self.assertRaises(ValueError):
                self.verify()
            self.manifest["review_authorizations"]["sql"] = "17fc5f90-d712-4dd8-8085-57353395ff0e"
            self.manifest["database"]["after"] = ["20260909_0041", "20261116_0075"]
            binding["relaxed_checks"] = []

    def test_exact_pr787_inherited_migration_requires_ordinary_qa_and_its_own_review(self):
        source = "a6e35a7ad36fbc21417a8575bb723a7948a5e8c7"
        base = "739fd2759b949e3228affb69cd090b64613b159a"
        self.manifest.update(
            operation="rollout", promotion_pr=787, base_sha=base,
            review_authorizations={
                "baseline": "ad7b17f5-e21f-4d48-93d8-e81635624b27",
                "sql": "407d605f-815b-4516-b714-5b72bf6c1422",
            },
            database={
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261113_0074"],
                "after": ["20260909_0041", "20261116_0075"],
            },
        )
        self.manifest["application"]["source_sha"] = source
        self.checks[QUALITY]["head_sha"] = source
        self.run["head_sha"] = source
        self.run["pull_requests"] = [{"number": 787, "head": {"sha": source}, "base": {"sha": base}}]
        self.pr.update(number=787)
        self.pr["head"]["sha"] = source
        self.pr["base"]["sha"] = base
        self.artifact["workflow_run"]["head_sha"] = source
        binding = self.report["summary"]["baseline_alignment"]
        binding.update(requested=False, authorized=False, relaxed_checks=[], source_sha=source, destination_sha=base)
        self.rebuild_archive()
        self.verify()
        self.manifest["review_authorizations"]["sql"] = "17fc5f90-d712-4dd8-8085-57353395ff0e"
        with self.assertRaises(ValueError):
            self.verify()

    def test_exact_pr791_role_guard_requires_ordinary_qa_and_its_own_review(self):
        source = "8821f317a4316ec7bca639ac7b6d22e9f903cfd9"
        base = "a1b883710bdd37ce915901dcfa86a837733a7b7b"
        self.manifest.update(
            operation="rollout", promotion_pr=791, base_sha=base,
            review_authorizations={
                "baseline": "b3fcd363-8f1b-460d-a630-167319a2134a",
                "sql": "50e42152-16ec-43c3-8bce-b8df5f4f10cf",
            },
            database={
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261116_0075"],
                "after": ["20260909_0041", "20261117_0076"],
            },
        )
        self.manifest["application"]["source_sha"] = source
        self.checks[QUALITY]["head_sha"] = source
        self.run["head_sha"] = source
        self.run["pull_requests"] = [{"number": 791, "head": {"sha": source}, "base": {"sha": base}}]
        self.pr.update(number=791)
        self.pr["head"]["sha"] = source
        self.pr["base"]["sha"] = base
        self.artifact["workflow_run"]["head_sha"] = source
        binding = self.report["summary"]["baseline_alignment"]
        binding.update(requested=False, authorized=False, relaxed_checks=[], source_sha=source, destination_sha=base)
        self.rebuild_archive()
        self.verify()
        self.manifest["review_authorizations"]["sql"] = "407d605f-815b-4516-b714-5b72bf6c1422"
        with self.assertRaises(ValueError):
            self.verify()

    def test_exact_pr798_mother_bridge_requires_ordinary_qa_and_its_own_review(self):
        source = "ee2b975c9c5a4881d71c6cd46d17af4e2f33aeae"
        base = "4c31546a984e3bda42d52b11a2ce268989991eab"
        self.manifest.update(
            operation="rollout", promotion_pr=798, base_sha=base,
            review_authorizations={
                "baseline": "47ad19da-aa3c-4492-946f-da4b9ffce871",
                "sql": "b0f5dab9-3c63-4273-a8cb-4ca891f7c8ee",
            },
            database={
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261117_0076"],
                "after": ["20260909_0041", "20261117_0077"],
            },
        )
        self.manifest["application"]["source_sha"] = source
        self.checks[QUALITY]["head_sha"] = source
        self.run["head_sha"] = source
        self.run["pull_requests"] = [{"number": 798, "head": {"sha": source}, "base": {"sha": base}}]
        self.pr.update(number=798)
        self.pr["head"]["sha"] = source
        self.pr["base"]["sha"] = base
        self.artifact["workflow_run"]["head_sha"] = source
        binding = self.report["summary"]["baseline_alignment"]
        binding.update(requested=False, authorized=False, relaxed_checks=[], source_sha=source, destination_sha=base)
        self.rebuild_archive()
        self.verify()
        self.manifest["review_authorizations"]["sql"] = "407d605f-815b-4516-b714-5b72bf6c1422"
        with self.assertRaises(ValueError):
            self.verify()

    def test_exact_pr835_password_reset_migration_requires_sql_review(self):
        source = "54069e56d92bfc4546d924c7963e23db4a24e439"
        base = "d63120d3a4664b163e5871aaf40eab6ad361af40"
        self.manifest.update(
            operation="rollout", promotion_pr=835, base_sha=base,
            review_authorizations={
                "baseline": "47ad19da-aa3c-4492-946f-da4b9ffce871",
                "sql": "b0f5dab9-3c63-4273-a8cb-4ca891f7c8ee",
            },
            database={
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261117_0077"],
                "after": ["20260909_0041", "20261121_0078"],
            },
        )
        self.manifest["application"]["source_sha"] = source
        self.checks[QUALITY]["head_sha"] = source
        self.run["head_sha"] = source
        self.run["pull_requests"] = [
            {"number": 835, "head": {"sha": source}, "base": {"sha": base}}
        ]
        self.pr.update(number=835)
        self.pr["head"]["sha"] = source
        self.pr["base"]["sha"] = base
        self.artifact["workflow_run"]["head_sha"] = source
        binding = self.report["summary"]["baseline_alignment"]
        binding.update(
            requested=False, authorized=False, relaxed_checks=[],
            source_sha=source, destination_sha=base,
        )
        self.rebuild_archive()
        self.verify()
        self.manifest["review_authorizations"]["sql"] = None
        with self.assertRaises(ValueError):
            self.verify()

    def test_pr791_migration_command_and_reviewed_bytes(self):
        import base64
        from unittest.mock import patch

        from application_plan import PR791_SOURCE_SHA, render
        from issued_windows import (
            PR791_BASE, PR791_MIGRATION, PR791_SOURCE, PR791_SQL_REVIEW,
            verify_pr791_migration,
        )
        sys.path.insert(0, str(ROOT / "tests"))
        from test_production_application_plan import manifest

        inputs = manifest()
        inputs["source_sha"] = PR791_SOURCE_SHA
        migration = render(inputs)["task_definitions"][2]["containerDefinitions"][0]
        self.assertEqual(migration["command"], ["alembic", "upgrade", "20261117_0076"])

        reviewed_bytes = b"reviewed migration fixture"
        reviewed = {
            "scope": "production", "promotion_pr": 791,
            "application": {"source_sha": PR791_SOURCE}, "base_sha": PR791_BASE,
            "review_authorizations": {"sql": PR791_SQL_REVIEW},
            "database": {
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261116_0075"],
                "after": ["20260909_0041", "20261117_0076"],
            },
        }

        def api(path):
            self.assertEqual(
                path, f"repos/Synergie-ITCI/programme-management-platform/contents/"
                      f"{PR791_MIGRATION}?ref={PR791_SOURCE}",
            )
            return {
                "type": "file", "encoding": "base64",
                "content": base64.b64encode(reviewed_bytes).decode(),
            }

        with patch("issued_windows.PR791_MIGRATION_SHA256", hashlib.sha256(reviewed_bytes).hexdigest()):
            verify_pr791_migration(reviewed, api=api)
            reviewed["database"]["after"] = ["20260909_0041", "20261116_0075"]
            with self.assertRaises(ValueError):
                verify_pr791_migration(reviewed, api=api)
        reviewed["database"]["after"] = ["20260909_0041", "20261117_0076"]
        with self.assertRaises(ValueError):
            verify_pr791_migration(reviewed, api=api)

        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        sql = json.loads((ROOT / "policy/audited-migration-authorizations.json").read_text())
        image_record = next(
            row for row in policy["one_time_baseline_alignments"] if row.get("pr_number") == 791
        )
        sql_record = next(row for row in sql if row.get("pr_number") == 791)
        self.assertEqual(image_record["relaxations"], [])
        self.assertEqual((image_record["allowed_changed_files"], image_record["allowed_effective_additions"]), (13, 306))
        self.assertEqual(sql_record["migration_sha256"], "30bea9f387d9d9e50304a8e8f3dac1db7bb6e7adeda092d896b023c37c3b8681")
        self.assertEqual(sql_record["delete_fingerprints"], [{
            "line": 192,
            "sha256": "dd9408b10f018bfa044a1659986303ebe9f583f36aea6db3de4ffe957cac774c",
        }])

    def test_detector_execution_must_equal_selected_immutable_policy(self):
        for logs in (
            self.logs.replace(b"rc233", b"rc232"),
            self.logs + self.logs,
            b"no immutable release evidence\n",
        ):
            with self.subTest(logs=logs):
                self.logs = logs
                with self.assertRaises(ValueError):
                    self.verify()

    def test_exact_run_archive_can_supply_only_failed_per_job_log_read(self):
        self.log_api_failure = True
        self.verify()
        self.assertEqual(self.run_log_reads, 1)
        self.run["run_attempt"] = 2
        self.verify()
        self.assertEqual(self.run_log_reads, 2)
        self.logs = self.logs.replace(b"rc233", b"rc232")
        with self.assertRaises(ValueError):
            self.verify()

        self.log_api_failure = False
        self.run_log_reads = 0
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.run_log_reads, 0)

    def test_exact_run_attempt_is_required_even_when_job_logs_are_available(self):
        for attempt in (None, 0, True, 11, "2"):
            with self.subTest(attempt=attempt):
                self.run["run_attempt"] = attempt
                with self.assertRaises(ValueError):
                    self.verify()

    def test_run_archive_fallback_rejects_missing_duplicate_and_oversized_log(self):
        self.log_api_failure = True
        name = "1_pr-qa _ Detect repository technologies.txt"
        for entries in (
            {"other.txt": self.logs},
            {name: self.logs + b"x" * (4 * 1024 * 1024)},
        ):
            with self.subTest(entries=list(entries)):
                output = io.BytesIO()
                with zipfile.ZipFile(
                    output, "w", compression=zipfile.ZIP_DEFLATED
                ) as zipped:
                    for path, payload in entries.items():
                        zipped.writestr(path, payload)
                self.run_log_override = output.getvalue()
                with self.assertRaises(ValueError):
                    self.verify()
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as zipped:
            zipped.writestr(name, self.logs)
            import warnings

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                zipped.writestr(name, self.logs)
        self.run_log_override = output.getvalue()
        with self.assertRaises(ValueError):
            self.verify()
        self.run_log_override = b"not a ZIP"
        with self.assertRaises(ValueError):
            self.verify()

    def test_phase1_expired_wrong_origin_and_wrong_attempt_artifacts_are_rejected(self):
        for key, value in (
            ("name", "pr-qa-phase-1-results"),
            ("expired", True),
            ("created_at", "2026-11-10T09:00:00Z"),
            ("digest", "sha256:" + "f" * 64),
        ):
            with self.subTest(key=key):
                old = self.artifact[key]
                self.artifact[key] = value
                try:
                    with self.assertRaises(ValueError):
                        self.verify()
                finally:
                    self.artifact[key] = old
        self.artifact["workflow_run"]["head_repository_id"] = 1
        with self.assertRaises(ValueError):
            self.verify()

    def test_final_report_must_prove_reviewed_base_and_pass(self):
        for key, value in (("destination_sha", "f" * 40), ("authorized", False)):
            with self.subTest(key=key):
                old = self.report["summary"]["baseline_alignment"][key]
                self.report["summary"]["baseline_alignment"][key] = value
                self.rebuild_archive()
                with self.assertRaises(ValueError):
                    self.verify()
                self.report["summary"]["baseline_alignment"][key] = old
        self.report["summary"]["overall_result"] = "FAIL"
        self.rebuild_archive()
        with self.assertRaises(ValueError):
            self.verify()

    def test_archive_tampering_and_unexpected_paths_are_rejected_without_extraction(
        self,
    ):
        with self.assertRaises(ValueError):
            read_final_report(
                self.archive + b"changed",
                self.manifest["qa_evidence"]["archive_sha256"],
            )
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as zipped:
            zipped.writestr("../pr-quality-report.json", "{}")
        data = output.getvalue()
        with self.assertRaises(ValueError):
            read_final_report(data, hashlib.sha256(data).hexdigest())
