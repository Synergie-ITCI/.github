from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "governance-v2" / "governance_v2.py"
POLICY = json.loads((ROOT / "policy" / "governance-v2-policy.json").read_text(encoding="utf-8"))
TEST_POLICY = {**POLICY, "bootstrap_baselines": {}}
SPEC = importlib.util.spec_from_file_location("governance_v2", MODULE_PATH)
assert SPEC and SPEC.loader
GOV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GOV)


class GovernanceV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="governance-v2-"))
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "governance@example.test")
        self.git("config", "user.name", "Governance Test")
        self.write("README.md", "baseline\n")
        self.commit("chore: baseline")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.repo, text=True, capture_output=True, check=True).stdout.strip()

    def write(self, rel: str, contents: str) -> None:
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def commit(self, message: str) -> None:
        self.git("add", ".")
        self.git("commit", "-q", "-m", message)

    def candidate(self, sha: str) -> dict:
        return GOV.build_candidate(self.repo, "Synergie-ITCI/programme-management-platform", sha, TEST_POLICY, [])

    def feature_record(self, base: str, head: str) -> dict:
        evidence = {
            "schema_version": 1,
            "change_summary": "Test change",
            "testing": {"applicable": True, "details": "unit test"},
            "migration": {"applicable": False, "reason": "none"},
            "privacy": {"applicable": False, "reason": "none"},
            "screenshots": {"applicable": False, "reason": "API-only"},
        }
        return GOV.build_feature_provenance(self.repo, "Synergie-ITCI/programme-management-platform", base, head, self.candidate(head), evidence)

    def test_evidence_accepts_explicit_not_applicable(self) -> None:
        result = GOV.validate_evidence({
            "schema_version": 1,
            "change_summary": "API-only change",
            "testing": {"applicable": True, "details": "pytest"},
            "migration": {"applicable": False, "reason": "schema unchanged"},
            "privacy": {"applicable": False, "reason": "no personal data"},
            "screenshots": {"applicable": False, "reason": "not applicable to API"},
        })
        self.assertEqual(result["status"], "PASS")

    def test_evidence_reports_exact_missing_field(self) -> None:
        result = GOV.validate_evidence({
            "schema_version": 1,
            "change_summary": "Missing screenshot explanation",
            "testing": {"applicable": True, "details": "pytest"},
            "migration": {"applicable": False, "reason": "none"},
            "privacy": {"applicable": False, "reason": "none"},
            "screenshots": {"applicable": False},
        })
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("screenshots.reason", " ".join(result["errors"]))

    def test_evidence_template_inside_html_comment_is_not_accepted(self) -> None:
        body = "<!-- ```synergie-governance-v2-evidence\n{}\n``` -->"
        with self.assertRaises(GOV.GovernanceError):
            GOV.extract_evidence({"body": body})

    def test_promotion_accepts_approved_content_with_different_commit_sha(self) -> None:
        self.write("service.txt", "approved\n")
        self.commit("feat: approved service")
        feature_head = self.git("rev-parse", "HEAD")
        record = self.feature_record(self.base, feature_head)
        self.git("commit", "--allow-empty", "-q", "-m", "promote: staging candidate")
        result = GOV.verify_provenance(self.repo, "Synergie-ITCI/programme-management-platform", self.base, self.git("rev-parse", "HEAD"), [record], TEST_POLICY)
        self.assertEqual(result["status"], "PASS")

    def test_promotion_rejects_unattested_mutation(self) -> None:
        self.write("service.txt", "approved\n")
        self.commit("feat: approved service")
        record = self.feature_record(self.base, self.git("rev-parse", "HEAD"))
        self.write("backdoor.txt", "unattested\n")
        self.commit("fix: hidden mutation")
        result = GOV.verify_provenance(self.repo, "Synergie-ITCI/programme-management-platform", self.base, self.git("rev-parse", "HEAD"), [record], TEST_POLICY)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("backdoor.txt", result["reason"])

    def test_bootstrap_baseline_accepts_only_its_unchanged_blobs(self) -> None:
        self.write("baseline-service.txt", "accepted before V2 activation\n")
        self.commit("feat: accepted baseline")
        baseline = self.git("rev-parse", "HEAD")
        policy = {
            **TEST_POLICY,
            "bootstrap_baselines": {
                "Synergie-ITCI/programme-management-platform": {
                    "commit_sha": baseline,
                    "tree_sha": self.git("rev-parse", "HEAD^{tree}"),
                }
            },
        }
        accepted = GOV.verify_provenance(
            self.repo,
            "Synergie-ITCI/programme-management-platform",
            self.base,
            baseline,
            [],
            policy,
        )
        self.assertEqual(accepted["status"], "PASS")
        self.assertEqual(accepted["bootstrap_covered_paths"], 1)

        self.write("unattested-after-activation.txt", "must be proven\n")
        self.commit("fix: unproven follow-up")
        rejected = GOV.verify_provenance(
            self.repo,
            "Synergie-ITCI/programme-management-platform",
            self.base,
            self.git("rev-parse", "HEAD"),
            [],
            policy,
        )
        self.assertEqual(rejected["status"], "FAIL")
        self.assertIn("unattested-after-activation.txt", rejected["reason"])

    def test_candidate_binding_invalidates_after_staging_mutation(self) -> None:
        self.write("service.txt", "candidate A\n")
        self.commit("feat: candidate a")
        candidate_a = self.candidate(self.git("rev-parse", "HEAD"))
        self.write("service.txt", "candidate B\n")
        self.commit("fix: candidate b")
        result = GOV.verify_candidate(candidate_a, self.candidate(self.git("rev-parse", "HEAD")))
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("candidate_id", result["mismatched_fields"])

    def qa_record(self, candidate: dict, verdict: str = "PASS") -> dict:
        return {
            "schema_version": 1,
            "repository": candidate["repository"],
            "candidate_id": candidate["candidate_id"],
            "staging_sha": candidate["staging_sha"],
            "tree_sha": candidate["tree_sha"],
            "content_digest": candidate["content_digest"],
            "verdict": verdict,
            "reviewer": "SaurabhVermaIN",
            "timestamp": "2026-08-16T12:00:00Z",
            "evidence_reference": "codex://qa/example",
        }

    def test_qa_pass_is_bound_to_exact_candidate_and_reviewer(self) -> None:
        self.write("service.txt", "candidate\n")
        self.commit("feat: candidate")
        candidate = self.candidate(self.git("rev-parse", "HEAD"))
        self.assertEqual(GOV.verify_qa_record(self.qa_record(candidate), candidate, TEST_POLICY, candidate["repository"])["status"], "PASS")
        record = self.qa_record(candidate)
        record["candidate_id"] = "0" * 64
        self.assertEqual(GOV.verify_qa_record(record, candidate, TEST_POLICY, candidate["repository"])["status"], "FAIL")

    def test_fail_qa_never_authorizes_release(self) -> None:
        self.write("service.txt", "candidate\n")
        self.commit("feat: candidate")
        candidate = self.candidate(self.git("rev-parse", "HEAD"))
        result = GOV.verify_qa_record(self.qa_record(candidate, "FAIL"), candidate, TEST_POLICY, candidate["repository"])
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("verdict", " ".join(result["errors"]))

    def test_authorization_cannot_be_reused_or_expired(self) -> None:
        self.write("service.txt", "candidate\n")
        self.commit("feat: candidate")
        candidate = self.candidate(self.git("rev-parse", "HEAD"))
        registry = {"schema_version": 1, "authorizations": [
            {"authorization_id": "exact-a", "repository": candidate["repository"], "pr_number": 42, "boundary": "staging-to-main", "base_sha": self.base, "head_sha": candidate["staging_sha"], "tree_sha": candidate["tree_sha"], "expires_at": "2099-01-01T00:00:00Z"},
            {"authorization_id": "expired-a", "repository": candidate["repository"], "pr_number": 42, "boundary": "staging-to-main", "base_sha": self.base, "head_sha": candidate["staging_sha"], "tree_sha": candidate["tree_sha"], "expires_at": "2000-01-01T00:00:00Z"}
        ]}
        valid = GOV.verify_authorization(registry, "exact-a", candidate["repository"], 42, "staging-to-main", self.base, candidate["staging_sha"], candidate, TEST_POLICY)
        self.assertEqual(valid["status"], "PASS")
        wrong_pr = GOV.verify_authorization(registry, "exact-a", candidate["repository"], 43, "staging-to-main", self.base, candidate["staging_sha"], candidate, TEST_POLICY)
        self.assertEqual(wrong_pr["status"], "FAIL")
        expired = GOV.verify_authorization(registry, "expired-a", candidate["repository"], 42, "staging-to-main", self.base, candidate["staging_sha"], candidate, TEST_POLICY)
        self.assertEqual(expired["status"], "FAIL")

    def test_production_selection_never_starts_deployment_without_authorization(self) -> None:
        self.write("service.txt", "candidate\n")
        self.commit("feat: candidate")
        candidate = self.candidate(self.git("rev-parse", "HEAD"))
        blocked = GOV.production_selection(candidate, "", TEST_POLICY, candidate["repository"])
        allowed = GOV.production_selection(candidate, "SaurabhVermaIN", TEST_POLICY, candidate["repository"])
        self.assertEqual(blocked["status"], "FAIL")
        self.assertEqual(allowed["status"], "PASS")
        self.assertFalse(blocked["deployment_started"])
        self.assertFalse(allowed["deployment_started"])

    def test_current_pr_rejects_stale_event_head(self) -> None:
        self.write("service.txt", "head\n")
        self.commit("feat: head")
        head = self.git("rev-parse", "HEAD")
        result = GOV.validate_current_pr({"number": 12, "head": {"sha": self.base, "ref": "feature/example"}, "base": {"ref": "development"}}, 12, head, "development", "feature/example")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("stale", " ".join(result["errors"]))

    def test_status_registry_has_valid_v2_workflow_producers(self) -> None:
        result = GOV.validate_status_registry(ROOT / "policy" / "status-check-registry.json", ROOT)
        self.assertEqual(result["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
