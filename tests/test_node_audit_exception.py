from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adapters.base import CommandOutcome, PRContext
from adapters.node import NodeAdapter
from adapters.node_audit_exception import EXCEPTION_FILES, evaluate_mobile_audit_exception


class MobileAuditExceptionTests(unittest.TestCase):
    pr = 476

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.mobile = self.repo / "apps/mobile"
        self.mobile.mkdir(parents=True)
        self.manifest = json.loads(EXCEPTION_FILES[self.pr].read_text())
        for relative in self.manifest["dependency_sha256"]:
            content = '{"scripts":{"audit:ci":"npm audit --audit-level=high"}}' if relative.endswith("package.json") else "test dependency"
            (self.repo / relative).write_text(content)
        self.manifest["dependency_sha256"] = {
            relative: __import__("hashlib").sha256((self.repo / relative).read_bytes()).hexdigest()
            for relative in self.manifest["dependency_sha256"]
        }
        self.ctx = PRContext(
            repo=self.repo, config={}, policy={}, changed_files=["apps/mobile/src/feature.ts"],
            event={"repository": {"full_name": self.manifest["repository"]},
                   "pull_request": {"number": self.pr, "head": {"sha": self.manifest["head_sha"]}}},
        )
        self.original = CommandOutcome("npm run audit:ci", str(self.mobile), 1)

    def evaluate(self, *, audit=None, tags=None, releases=None):
        if audit is None:
            audit = {"vulnerabilities": {
                item["package"]: {"via": [{"url": "https://github.com/advisories/" + item["id"],
                                            "severity": item["severity"], "range": item["range"]}]}
                for item in self.manifest["advisories"]
            }}
        def run(args, cwd=None):
            if args[:3] == ["git", "rev-parse", "HEAD"]:
                return CommandOutcome("git", str(cwd), 0, self.manifest["head_sha"] + "\n")
            if args[:2] == ["gh", "api"]:
                values = tags if "/tags?" in args[2] else releases
                if values is None:
                    values = self.manifest["baseline_tags"] if "/tags?" in args[2] else self.manifest["baseline_releases"]
                key = "name" if "/tags?" in args[2] else "tag_name"
                return CommandOutcome("gh", str(cwd), 0, json.dumps([{key: value} for value in values]))
            return CommandOutcome("npm audit --json", str(cwd), 1, json.dumps(audit))
        canonical_evidence = f"fieldzilla-pr{self.pr}-mobile-evidence.md"
        source_evidence = EXCEPTION_FILES[self.pr].with_name(canonical_evidence).read_bytes()
        with patch.dict("adapters.node_audit_exception.EXCEPTION_FILES", {self.pr: self.repo / "exception.json"}), \
             patch.dict("os.environ", {"GH_TOKEN": "test"}):
            (self.repo / "exception.json").write_text(json.dumps(self.manifest))
            (self.repo / canonical_evidence).write_bytes(source_evidence)
            with patch.object(self.ctx, "run", side_effect=run):
                return evaluate_mobile_audit_exception(self.ctx, self.mobile, self.original)

    def test_exact_match_is_visible_warning(self):
        result = self.evaluate()
        self.assertEqual(result.status, "WARNING")
        self.assertTrue((self.repo / "pr-qa-results/mobile-audit-exception.json").exists())

    def test_other_pr_or_head_fails_closed(self):
        self.ctx.event["pull_request"]["number"] = 477 if self.pr == 476 else 476
        self.assertIsNone(self.evaluate())
        self.ctx.event["pull_request"]["number"] = self.pr
        self.ctx.event["pull_request"]["head"]["sha"] = "0" * 40
        self.assertIsNone(self.evaluate())

    def test_dependency_or_advisory_change_fails_closed(self):
        self.ctx.changed_files.append("apps/mobile/package-lock.json")
        self.assertIsNone(self.evaluate())
        self.ctx.changed_files.pop()
        self.assertIsNone(self.evaluate(audit={"vulnerabilities": {"new": {"via": [{"url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "severity": "high", "range": "*"}]}}}))

    def test_new_tag_or_release_fails_closed(self):
        self.assertIsNone(self.evaluate(tags=self.manifest["baseline_tags"] + ["new-mobile-release"]))
        self.assertIsNone(self.evaluate(releases=["new-mobile-release"]))

    def test_missing_approval_owner_or_expiry_fails_closed(self):
        for field, value in (("approver", ""), ("remediation_owner", ""), ("expires_at", "2020-01-01T00:00:00Z")):
            old = self.manifest[field]
            self.manifest[field] = value
            self.assertIsNone(self.evaluate())
            self.manifest[field] = old

    def test_missing_evidence_or_bad_hash_fails_closed(self):
        old = self.manifest["evidence_sha256"]
        self.manifest["evidence_sha256"] = "0" * 64
        self.assertIsNone(self.evaluate())
        self.manifest["evidence_sha256"] = old
        old = self.manifest["evidence_file"]
        self.manifest["evidence_file"] = "missing-evidence.md"
        self.assertIsNone(self.evaluate())
        self.manifest["evidence_file"] = old

    def test_modified_lockfile_or_audit_script_fails_closed(self):
        self.assertEqual(self.evaluate().status, "WARNING")
        (self.mobile / "package-lock.json").write_text("changed")
        self.assertIsNone(self.evaluate())
        (self.mobile / "package-lock.json").write_text("test dependency")
        (self.mobile / "package.json").write_text('{"scripts":{"audit:ci":"true"}}')
        self.assertIsNone(self.evaluate())

    def test_other_pr_still_has_blocking_dependency_failure(self):
        self.ctx.event["pull_request"]["number"] = 477 if self.pr == 476 else 476
        with patch.object(NodeAdapter, "_ensure_dependencies", return_value=[]), \
             patch.object(self.ctx, "run", return_value=self.original):
            results = NodeAdapter().dependencies(self.ctx, [self.mobile])
        self.assertTrue(any(result.is_blocking_failure() for result in results))


class StagingPromotionAuditExceptionTests(MobileAuditExceptionTests):
    pr = 477


if __name__ == "__main__":
    unittest.main()
