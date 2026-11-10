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
    verify_qa_policy_evidence,
)


class QAPolicyTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
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
            "head_sha": "a" * 40,
            "status": "completed",
            "conclusion": "success",
            "event": "pull_request",
            "path": ".github/workflows/pr-qa.yml",
            "pull_requests": [
                {"number": 712, "head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}}
            ],
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
        if "/jobs?" in path:
            return {"jobs": self.jobs}
        if path.endswith("/jobs/34/logs"):
            return self.logs
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
