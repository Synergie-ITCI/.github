"""Exercise the staging mobile exception's dependency and per-SHA bundle gates."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
import mobile_bundle_evidence as bundles
import staging_mobile_audit_exception as exception

FINDING = {
    "package": "braces",
    "id": "GHSA-aaaa-bbbb-cccc",
    "severity": "high",
    "range": "<2",
}
SECOND = {
    "package": "shell-quote",
    "id": "GHSA-dddd-eeee-ffff",
    "severity": "critical",
    "range": "<3",
}


class StagingMobileAuditExceptionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.head = "a" * 40
        self.repo = Path(temporary.name) / "repo"
        self.central = self.repo / ".pr-qa-framework"
        self.mobile = self.repo / "apps/mobile"
        self.mobile.mkdir(parents=True)
        exceptions = self.central / "policy/exceptions"
        exceptions.mkdir(parents=True)
        script = "npm audit --audit-level=high"
        (self.mobile / "package.json").write_text(
            json.dumps({"scripts": {"audit:ci": script}})
        )
        (self.mobile / "package-lock.json").write_text("lock")
        self.evidence = exceptions / "evidence.md"
        self.evidence.write_text("approved dependency evidence")
        self.manifest = {
            "repository": exception.REPOSITORY,
            "environment": "staging",
            "workflow": "staging-deploy.yml",
            "exception_id": "test-staging-tooling",
            "approver": "Approver",
            "approved_at": "2026-10-09T00:00:00Z",
            "reason": "Reviewed dependency evidence",
            "residual_risk": "Build tools remain vulnerable",
            "remediation_owner": "Mobile Platform Lead",
            "expires_at": "2099-01-01T00:00:00Z",
            "evidence_file": self.evidence.name,
            "evidence_sha256": exception.digest(self.evidence),
            "dependency_sha256": {
                name: exception.digest(self.repo / name)
                for name in exception.DEPENDENCIES
            },
            "audit_script_sha256": exception.script_digest(script),
            "baseline_tags": ["baseline"],
            "baseline_releases": [],
            "advisories": [FINDING.copy(), SECOND.copy()],
        }
        self.manifest_file = exceptions / exception.MANIFEST
        self.audit = {"findings": [FINDING.copy(), SECOND.copy()]}
        self.tracked = {"paths": ""}
        self.release_state = {"tags": {"baseline"}, "releases": set()}

        def command(*args: str, cwd: Path | None = None, **kwargs: object) -> str:
            if args[:3] == ("npm", "audit", "--json"):
                return json.dumps(
                    {
                        "vulnerabilities": {
                            item["package"]: {
                                "via": [
                                    {
                                        "url": "https://github.com/advisories/"
                                        + item["id"],
                                        "severity": item["severity"],
                                        "range": item["range"],
                                    }
                                ]
                            }
                            for item in self.audit["findings"]
                        }
                    }
                )
            if args[:3] == ("git", "remote", "get-url") and cwd == self.central:
                return "https://github.com/Synergie-ITCI/.github"
            if args[:2] == ("git", "rev-parse") and cwd == self.central:
                return "c" * 40
            if args[:3] == ("git", "rev-parse", "HEAD") and cwd == self.repo:
                return os.environ["GITHUB_SHA"]
            if args[:2] == ("git", "ls-files") and cwd == self.repo:
                return self.tracked["paths"]
            raise AssertionError((args, cwd, kwargs))

        commands = patch.object(exception, "command", side_effect=command)
        names = patch.object(
            exception,
            "github_names",
            side_effect=lambda endpoint, key: self.release_state[endpoint],
        )
        environment = patch.dict(
            os.environ,
            {
                "GITHUB_REPOSITORY": exception.REPOSITORY,
                "GITHUB_REF": "refs/heads/staging",
                "GITHUB_SHA": self.head,
                "GITHUB_RUN_ID": "12345",
                "FIELDZILLA_RELEASE_ENVIRONMENT": "staging",
                "ACTIVE_CENTRAL_RELEASE": "pr-qa-v1-rc175",
            },
        )
        for mocked in (commands, names, environment):
            mocked.start()
            self.addCleanup(mocked.stop)
        self.save()
        self.bundle(self.head)

    def save(self) -> None:
        self.manifest_file.write_text(json.dumps(self.manifest))

    def bundle(self, head: str, sources: list[str] | None = None) -> None:
        directory = self.repo / "staging-mobile-bundle-evidence"
        directory.mkdir(exist_ok=True)
        modules = sources or ["../node_modules/safe-package/index.js", "src/App.tsx"]
        for platform in bundles.PLATFORMS:
            (directory / f"{platform}.bundle").write_text("release bundle")
            (directory / f"{platform}.map").write_text(
                json.dumps({"version": 3, "sources": modules})
            )
        recorded = bundles.collect(self.repo, head, {"braces", "shell-quote"})
        (directory / "bundle-evidence.json").write_text(json.dumps(recorded))

    def test_one_dependency_approval_covers_two_shas_and_reduced_findings(self) -> None:
        first = exception.validate(self.repo, self.central, self.head)
        self.assertEqual(first["staging_sha"], self.head)
        self.assertEqual(first["workflow_run_id"], "12345")
        self.assertEqual(set(first["bundle_check"]), {"android", "ios"})
        next_head = "b" * 40
        os.environ["GITHUB_SHA"] = next_head
        self.bundle(next_head)
        self.audit["findings"] = [FINDING.copy()]
        second = exception.validate(self.repo, self.central, next_head)
        self.assertEqual(second["advisories"], [FINDING])
        self.assertEqual(second["staging_sha"], next_head)

    def test_changed_lockfile_or_audit_script_fails(self) -> None:
        (self.mobile / "package-lock.json").write_text("changed")
        with self.assertRaisesRegex(ValueError, "dependency files changed"):
            exception.validate(self.repo, self.central, self.head)
        (self.mobile / "package-lock.json").write_text("lock")
        (self.mobile / "package.json").write_text(
            json.dumps({"scripts": {"audit:ci": "echo audit"}})
        )
        self.manifest["dependency_sha256"]["apps/mobile/package.json"] = (
            exception.digest(self.mobile / "package.json")
        )
        self.save()
        with self.assertRaisesRegex(ValueError, "audit command changed"):
            exception.validate(self.repo, self.central, self.head)

    def test_new_or_severity_upgraded_advisory_fails(self) -> None:
        for change in ("new", "upgrade"):
            with self.subTest(change=change):
                self.audit["findings"] = [FINDING.copy(), SECOND.copy()]
                if change == "new":
                    self.audit["findings"].append(
                        {
                            "package": "another",
                            "id": "GHSA-gggg-hhhh-iiii",
                            "severity": "high",
                            "range": "<4",
                        }
                    )
                else:
                    self.audit["findings"][0]["severity"] = "critical"
                with self.assertRaisesRegex(ValueError, "advisory"):
                    exception.validate(self.repo, self.central, self.head)

    def test_missing_or_vulnerable_bundle_fails(self) -> None:
        (self.repo / "staging-mobile-bundle-evidence/bundle-evidence.json").unlink()
        with self.assertRaises(FileNotFoundError):
            exception.validate(self.repo, self.central, self.head)
        self.bundle(self.head)
        (self.repo / "staging-mobile-bundle-evidence/ios.map").unlink()
        with self.assertRaisesRegex(ValueError, "source map is missing"):
            exception.validate(self.repo, self.central, self.head)
        self.bundle(self.head, ["../node_modules/braces/index.js"])
        with self.assertRaisesRegex(ValueError, "appears in a release JS bundle"):
            exception.validate(self.repo, self.central, self.head)

    def test_non_fieldzilla_or_production_scope_fails(self) -> None:
        for key, value in (
            ("GITHUB_REPOSITORY", "another/repository"),
            ("FIELDZILLA_RELEASE_ENVIRONMENT", "production"),
        ):
            with (
                self.subTest(key=key),
                patch.dict(os.environ, {key: value}),
                self.assertRaisesRegex(ValueError, "scope"),
            ):
                exception.validate(self.repo, self.central, self.head)

    def test_expiry_release_unavailable_and_missing_evidence_fail(self) -> None:
        self.manifest["expires_at"] = "2000-01-01T00:00:00Z"
        self.save()
        with self.assertRaisesRegex(ValueError, "expired"):
            exception.validate(self.repo, self.central, self.head)
        self.manifest["expires_at"] = "2099-01-01T00:00:00Z"
        self.save()
        with (
            patch.object(
                exception, "github_names", side_effect=ValueError("unavailable")
            ),
            self.assertRaisesRegex(ValueError, "unavailable"),
        ):
            exception.validate(self.repo, self.central, self.head)
        self.evidence.unlink()
        with self.assertRaisesRegex(ValueError, "evidence missing"):
            exception.validate(self.repo, self.central, self.head)

    def test_feature_repo_cannot_supply_its_own_exception(self) -> None:
        local = self.repo / "policy/exceptions"
        local.mkdir(parents=True)
        (local / exception.MANIFEST).write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "central governance checkout"):
            exception.validate(self.repo, local.parent, self.head)
        self.tracked["paths"] = (
            "policy/exceptions/fieldzilla-otp-staging-mobile-audit.json"
        )
        with self.assertRaisesRegex(ValueError, "central ownership"):
            exception.validate(self.repo, self.central, self.head)


if __name__ == "__main__":
    unittest.main()
