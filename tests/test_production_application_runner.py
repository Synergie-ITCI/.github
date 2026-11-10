"""Orchestration and entry-point boundaries; not AWS rehearsal evidence."""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/fieldzilla-production"))
sys.path.insert(0, str(ROOT / "pr-qa"))
from application_runner import ContextBoundReceipt, execute_infrastructure, execute_production, validate
from pr_qa import parse_workflow_yaml


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.failure = None
        self.closed = False
        outer = self

        class Receipt:
            def verify(self):
                outer.calls.append("verify")

            def consume(self):
                outer.calls.append("consume")
                if outer.failure == "consume":
                    raise ValueError("approval consumed elsewhere")

        class Engine:
            def __init__(self, manifest, *, aws, authorize, journal):
                outer.calls.append("constructed")

            def __getattr__(self, name):
                def operation(*args, **kwargs):
                    outer.calls.append(name)
                    if outer.failure == name:
                        raise RuntimeError("deterministic failure")
                    if name == "wait_runtime":
                        return {"api": {"digest": "sha256:" + "a" * 64}}
                    if name == "close":
                        outer.closed = True

                return operation

        self.receipt = Receipt()
        self.engine = Engine
        self.manifest = {
            "scope": "production-rehearsal",
            "application": {"source_sha": "b" * 40},
        }

    def execute(self):
        with tempfile.TemporaryDirectory() as folder:
            return execute_infrastructure(
                self.manifest,
                self.receipt,
                Path(folder) / "journal",
                aws=lambda *args: None,
                executor=self.engine,
            )

    def test_complete_infrastructure_sequence_cannot_claim_acceptance(self):
        report = self.execute()
        self.assertEqual(
            self.calls,
            [
                "constructed",
                "preflight",
                "consume",
                "prepare",
                "migrate",
                "start",
                "wait_runtime",
                "record",
                "close",
            ],
        )
        self.assertFalse(report["rehearsal_passed"])
        self.assertIn("APPLICATION_ACCEPTANCE_REQUIRED", report["status"])
        self.assertEqual(report["source_sha"], "b" * 40)
        self.assertTrue(self.closed)

    def test_production_and_staging_never_construct_an_executor(self):
        for scope in ("production", "staging", "production-rehearsal-other"):
            self.manifest["scope"] = scope
            with self.assertRaises(ValueError):
                self.execute()
        self.assertEqual(self.calls, [])

    def test_production_is_separately_bound_and_does_not_claim_cutover(self):
        self.manifest.update(scope="production", operation="rollout")
        with tempfile.TemporaryDirectory() as folder:
            report = execute_production(
                self.manifest, self.receipt, Path(folder) / "journal",
                aws=lambda *args: None, executor=self.engine,
            )
        self.assertEqual(
            self.calls,
            ["constructed", "preflight", "consume", "prepare", "migrate", "start", "wait_runtime", "record", "close"],
        )
        self.assertIs(report["production_live"], False)
        self.assertIn("CUTOVER_AND_ACCEPTANCE_REQUIRED", report["status"])

    def test_failure_does_not_retry_migration_or_silently_recover(self):
        for failure in ("preflight", "consume", "prepare", "migrate", "wait_runtime"):
            with self.subTest(failure=failure):
                self.calls.clear()
                self.closed = False
                self.failure = failure
                with self.assertRaises((RuntimeError, ValueError)):
                    self.execute()
                self.assertTrue(self.closed)
                self.assertEqual(self.calls.count(failure), 1)
                self.assertNotIn("record", self.calls)
                self.assertNotIn("hold_for_recovery", self.calls)
                if failure in {"preflight", "consume"}:
                    self.assertNotIn("prepare", self.calls)
                if failure == "migrate":
                    self.assertNotIn("start", self.calls)


class PolicyAuthorityTests(unittest.TestCase):
    def test_unproven_policy_blocks_receipt_before_any_aws_execution(self):
        manifest = {
            "operation": "rehearsal",
            "expires_at": "2026-11-10T18:00:00Z",
            "application": {},
            "scope": "production-rehearsal",
            "promotion_pr": 712,
            "caller_sha": "a" * 40,
        }
        args = SimpleNamespace(expires_at=manifest["expires_at"], approval_comment_id=1)
        receipt = Mock()
        checks = {"fixture": "current checks"}
        with (
            patch("application_runner.verify_rehearsal_context", return_value=checks),
            patch("application_runner.render"),
            patch("application_runner.ApprovalReceipt", return_value=receipt),
            patch(
                "application_runner.verify_qa_policy_evidence",
                side_effect=ValueError("policy proof rejected"),
            ) as policy,
            patch("application_runner.verify_issued_windows") as windows,
        ):
            with self.assertRaisesRegex(ValueError, "policy proof rejected"):
                validate(
                    b"{}",
                    manifest,
                    args,
                    api=Mock(),
                    environment={"GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"},
                    central_sha="b" * 40,
                )
            self.assertEqual(policy.call_count, 1)
            windows.assert_not_called()
            receipt.verify.assert_not_called()
            receipt.consume.assert_not_called()


class WorkflowTests(unittest.TestCase):
    def test_reusable_only_main_identity_before_credentials_and_no_application_checkout(
        self,
    ):
        source = (
            ROOT / ".github/workflows/fieldzilla-production-application.yml"
        ).read_text()
        workflow = parse_workflow_yaml(source)
        # The central loader supports optional PyYAML (YAML 1.1, where `on`
        # is True) and its dependency-free fallback. GitHub accepts this key.
        triggers = workflow.get("on", workflow.get(True))
        self.assertEqual(set(triggers), {"workflow_call"})
        self.assertEqual(
            workflow["concurrency"],
            {
                "group": "fieldzilla-production-hosting",
                "cancel-in-progress": False,
            },
        )
        jobs = workflow["jobs"]
        self.assertEqual(set(jobs), {"isolated-infrastructure"})
        job = jobs["isolated-infrastructure"]
        self.assertEqual(job["environment"], "synergie-app-production")
        steps = job["steps"]
        identity = steps[0]["run"]
        for value in (
            "refs/heads/main",
            "workflow_dispatch",
            "job_workflow_ref",
            "job_workflow_sha",
        ):
            self.assertIn(value, identity)
        verify = next(
            i for i, step in enumerate(steps) if "unused owner" in step.get("name", "")
        )
        credentials = next(
            i
            for i, step in enumerate(steps)
            if step.get("uses", "").startswith("aws-actions/")
        )
        self.assertLess(verify, credentials)
        role = steps[credentials]["with"]["role-to-assume"]
        self.assertIn("SynergieFieldzillaProductionRehearsalApplicationDeploy", role)
        self.assertIn("SynergieFieldzillaProductionApplicationDeploy", role)
        self.assertIn("inputs.execution-kind == 'production'", role)
        checkouts = [
            step
            for step in steps
            if step.get("uses", "").startswith("actions/checkout@")
        ]
        self.assertEqual(len(checkouts), 1)
        self.assertEqual(checkouts[0]["with"]["repository"], "Synergie-ITCI/.github")
        self.assertIs(checkouts[0]["with"]["persist-credentials"], False)
        self.assertNotIn("secrets: inherit", source)


class ContextBindingTests(unittest.TestCase):
    def test_ref_drift_prevents_verification_and_consumption(self):
        calls = []

        class Receipt:
            def verify(self):
                calls.append("receipt verified")

            def consume(self):
                calls.append("receipt consumed")

        changed = False

        def context():
            calls.append("context verified")
            if changed:
                raise ValueError("source or current checks changed")

        bound = ContextBoundReceipt(Receipt(), context)
        bound.verify()
        bound.consume()
        self.assertEqual(
            calls,
            [
                "context verified",
                "receipt verified",
                "context verified",
                "receipt consumed",
            ],
        )
        changed = True
        calls.clear()
        for operation in (bound.verify, bound.consume):
            with self.assertRaises(ValueError):
                operation()
        self.assertEqual(calls, ["context verified", "context verified"])


if __name__ == "__main__":
    unittest.main()
