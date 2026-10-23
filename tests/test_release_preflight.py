import os
import json
import hashlib
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release-preflight"
preflight = SourceFileLoader("release_preflight", str(SCRIPT)).load_module()


class ReleasePreflightTests(unittest.TestCase):
    def test_rc203_disposition_requires_exact_inherited_fixtures_and_reviewed_squash(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc203"]
        source_sha = "e" * 40
        pr_head = "f" * 40
        inherited_text = (ROOT / "tests/test_pr_qa_regressions.py").read_text(encoding="utf-8")
        report = {"results": [{
            "gate": "Secrets", "status": "FAIL", "blocking": True,
            "details": [f'{item["path"]}: {item["label"]}. line_sha256={item["line_sha256"]}'
                        for item in reviewed["synthetic_fixture_findings"]],
        }]}
        pr = {"merged_at": "2026-10-23T08:00:00Z", "merge_commit_sha": source_sha,
              "head": {"sha": pr_head}, "base": {"ref": "main"}}

        def fake_git(args, _root):
            if args[:3] == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN
            elif args == ["show", "pr-qa-v1-rc202:tests/test_pr_qa_regressions.py"]:
                value = inherited_text
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = source_sha
            elif args[:2] == ["rev-list", "--count"]:
                value = "1"
            elif args[:3] == ["rev-list", "--first-parent", "--merges"]:
                value = ""
            elif args in (["rev-parse", f"{pr_head}^{{tree}}"], ["rev-parse", "HEAD^{tree}"]):
                value = "a" * 40
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value + "\n", "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), \
                 patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(pr), "")):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc202"))
                self.assertFalse(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc201"))
                report["results"][0]["details"].append("config.php: API key. line_sha256=" + "b" * 64)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc202"))
                report["results"][0]["details"].pop()
                report["results"].append({"gate": "Repository Hygiene", "status": "FAIL", "blocking": True})
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc202"))
                report["results"].pop()
                path.write_text(json.dumps(report), encoding="utf-8")
                with patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps({**pr, "merged_at": None}), "")):
                    self.assertFalse(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc202"))

    def test_rc202_disposition_is_bound_to_exact_findings_and_merged_tree(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc202"]
        merge = reviewed["approved_merge"]
        source_sha = "e" * 40
        pr_head = "f" * 40
        inherited_text = (ROOT / "tests/test_pr_qa_regressions.py").read_text(encoding="utf-8")
        framework_token = "](?:" + "\\|".join(part + "_path" for part in ("upload", "cache", "log", "storage", "tmp")) + ")["
        literal_details = [
            f"DEVELOPER_DECLARATION: `{value}` introduces a writable/runtime path that has not been classified."
            for value in (framework_token, framework_token, "cache" + "_path", "cache",
                          "Unable to write cache file:", "Cache file written:")
        ]
        report = {"results": [
            {"gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
             "message": "Accidental merge commits detected.", "details": [merge["sha"]]},
            {"gate": "Secrets", "status": "FAIL", "blocking": True,
             "details": [f'{item["path"]}: {item["label"]}. line_sha256={item["line_sha256"]}'
                         for item in reviewed["synthetic_fixture_findings"]]},
            {"gate": "Persistent Data Safety", "status": "FAIL", "blocking": True,
             "details": literal_details},
        ]}
        pr = {"merged_at": "2026-10-23T07:00:00Z", "merge_commit_sha": source_sha,
              "head": {"sha": pr_head}, "base": {"ref": "main"}}

        def fake_git(args, _root):
            if args[:3] == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN
            elif args[:2] == ["show", "pr-qa-v1-rc201:tests/test_pr_qa_regressions.py"]:
                value = inherited_text
            elif args[:3] == ["rev-list", "--parents", "-n"]:
                value = " ".join((merge["sha"], merge["base_sha"], merge["head_sha"]))
            elif args[:2] == ["merge-base", "--is-ancestor"]:
                value = ""
            elif args[:3] == ["rev-list", "--first-parent", "--merges"]:
                value = merge["sha"]
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = source_sha
            elif args in (["rev-parse", f"{pr_head}^{{tree}}"], ["rev-parse", "HEAD^{tree}"]):
                value = "a" * 40
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value + "\n", "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), \
                 patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(pr), "")):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc202_disposition(ROOT, path, "main", "pr-qa-v1-rc201"))
                self.assertFalse(preflight.reviewed_rc202_disposition(ROOT, path, "main", "pr-qa-v1-rc200"))
                report["results"][2]["details"].append("DEVELOPER_DECLARATION: `uploads` is undeclared")
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc202_disposition(ROOT, path, "main", "pr-qa-v1-rc201"))
                report["results"][2]["details"].pop()
                report["results"][1]["details"].append("config.php: API key. line_sha256=" + "b" * 64)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc202_disposition(ROOT, path, "main", "pr-qa-v1-rc201"))
                report["results"][1]["details"].pop()
                path.write_text(json.dumps(report), encoding="utf-8")
                with patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps({**pr, "merged_at": None}), "")):
                    self.assertFalse(preflight.reviewed_rc202_disposition(ROOT, path, "main", "pr-qa-v1-rc201"))

    def test_rc201_disposition_requires_exact_reviewed_findings_and_merge(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc201"]
        merge = reviewed["approved_merge"]
        findings = reviewed["synthetic_fixture_findings"]
        for item in findings:
            self.assertEqual(item["path"], "tests/test_pr_qa_regressions.py")
            lines = (ROOT / item["path"]).read_text(encoding="utf-8").splitlines()
            self.assertTrue(any(hashlib.sha256(line.strip().encode()).hexdigest() == item["line_sha256"] for line in lines))
        report = {"results": [
            {"gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
             "message": "Accidental merge commits detected.", "details": [merge["sha"]]},
            {"gate": "Secrets", "status": "FAIL", "blocking": True,
             "details": [f'{item["path"]}: {item["label"]}. line_sha256={item["line_sha256"]}' for item in findings]},
        ]}
        pr = {"merged_at": "2026-10-23T04:18:28Z", "merge_commit_sha": merge["sha"],
              "head": {"sha": merge["head_sha"]}, "base": {"ref": "main"}}

        def fake_git(args, _root):
            if args[:3] == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN
            elif args[:3] == ["rev-list", "--parents", "-n"]:
                value = " ".join((merge["sha"], merge["base_sha"], merge["head_sha"]))
            elif args[:3] == ["rev-list", "--first-parent", "--merges"]:
                value = merge["sha"]
            elif args[:2] == ["rev-parse", f'{merge["sha"]}^{{tree}}'] or args[:2] == ["rev-parse", f'{merge["head_sha"]}^{{tree}}']:
                value = "a" * 40
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value + "\n", "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), \
                 patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(pr), "")):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc201_disposition(ROOT, path, "main", "pr-qa-v1-rc200"))
                self.assertFalse(preflight.reviewed_rc201_disposition(ROOT, path, "development", "pr-qa-v1-rc200"))
                report["results"][0]["details"] = ["b" * 40]
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc201_disposition(ROOT, path, "main", "pr-qa-v1-rc200"))
                report["results"][0]["details"] = [merge["sha"]]
                report["results"][1]["details"].append("src/config.py: generic credential assignment. line_sha256=" + "c" * 64)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc201_disposition(ROOT, path, "main", "pr-qa-v1-rc200"))
                report["results"][1]["details"].pop()
                path.write_text(json.dumps(report), encoding="utf-8")
                with patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 1, "", "unauthorized")):
                    self.assertFalse(preflight.reviewed_rc201_disposition(ROOT, path, "main", "pr-qa-v1-rc200"))

    def test_technical_preflight_does_not_fabricate_pr_review_evidence(self):
        captured = {}

        def run_engine(command, **kwargs):
            event = Path(command[command.index("--event-path") + 1])
            captured["event"] = __import__("json").loads(event.read_text(encoding="utf-8"))
            captured["command"] = command
            return subprocess.CompletedProcess(command, 0)

        sha = "a" * 40
        with patch.object(preflight, "git", side_effect=[
            subprocess.CompletedProcess([], 0, sha + "\n", ""),
            subprocess.CompletedProcess([], 0, "main\n", ""),
        ]), patch.object(preflight.subprocess, "run", side_effect=run_engine):
            self.assertTrue(preflight.run_pr_qa(ROOT, ROOT, "main", "b" * 40))

        self.assertNotIn("pull_request", captured["event"])
        self.assertEqual(captured["event"]["release_preflight"]["head_sha"], sha)
        self.assertEqual(captured["command"][captured["command"].index("--base-ref") + 1], "main")
        self.assertEqual(captured["command"][captured["command"].index("--head-ref") + 1], "main")

    def test_publisher_bound_preflight_skips_release_enumeration_and_checks_local_tag(self):
        sys.path.insert(0, str(ROOT / "pr-qa"))
        import release_pin
        commit = "a" * 40
        args = ["release-preflight", "--base", "main", "--verified-release", "pr-qa-v1-rc194",
                "--verified-commit", commit]
        local = subprocess.CompletedProcess([], 0, commit + "\n", "")
        with patch.object(sys, "argv", args), patch.object(preflight, "repo_root", return_value=ROOT), \
             patch.object(preflight, "active_release") as enumerate_releases, \
             patch.object(release_pin, "verify_bound_release") as verify_bound, \
             patch.object(preflight, "git", return_value=local), \
             patch.object(preflight, "resolve_origin_base", return_value="b" * 40), \
             patch.object(preflight, "worktree_state", return_value="CLEAN"), \
             patch.object(preflight, "extract_release", return_value=True), \
             patch.object(preflight, "run_pr_qa", return_value=True), \
             patch.object(preflight, "run_consumer_compatibility", return_value=True), \
             patch.object(preflight, "print_report"):
            self.assertEqual(preflight.main(), 0)
            enumerate_releases.assert_not_called()
            verify_bound.assert_called_once()
        stale = subprocess.CompletedProcess([], 0, "c" * 40 + "\n", "")
        with patch.object(sys, "argv", args), patch.object(preflight, "repo_root", return_value=ROOT), \
             patch.object(release_pin, "verify_bound_release"), \
             patch.object(preflight, "git", return_value=stale), \
             patch.object(preflight, "resolve_origin_base", return_value="b" * 40), \
             patch.object(preflight, "worktree_state", return_value="CLEAN"), \
             patch.object(preflight, "run_consumer_compatibility", return_value=True), \
             patch.object(preflight, "print_report"):
            self.assertEqual(preflight.main(), 1)

    def test_central_preflight_uses_live_governed_release(self):
        origin = subprocess.CompletedProcess([], 0, preflight.CENTRAL_ORIGIN + "\n", "")
        active = subprocess.CompletedProcess([], 0, "Resolved active release pr-qa-v1-rc191 at " + "a" * 40 + "\n", "")
        with patch.object(preflight, "git", return_value=origin), patch.object(preflight, "run", return_value=active):
            self.assertEqual(preflight.active_release(ROOT), "pr-qa-v1-rc191")

        failed = subprocess.CompletedProcess([], 1, "", "resolution failed")
        with patch.object(preflight, "git", return_value=origin), patch.object(preflight, "run", return_value=failed):
            self.assertIsNone(preflight.active_release(ROOT))

        malformed = subprocess.CompletedProcess([], 0, "Resolved active release pr-qa-v1-rc191 at wrong\n", "")
        with patch.object(preflight, "git", return_value=origin), patch.object(preflight, "run", return_value=malformed):
            self.assertIsNone(preflight.active_release(ROOT))

    def run_cmd(self, args, cwd, env=None):
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        return subprocess.run(args, cwd=cwd, env=merged_env, text=True, capture_output=True)

    def git(self, repo, *args):
        proc = self.run_cmd(["git", *args], repo)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.strip()

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def make_repo(self):
        temp = tempfile.TemporaryDirectory()
        repo = Path(temp.name)
        self.git(repo, "init", "-b", "feature")
        self.git(repo, "config", "user.email", "tests@example.invalid")
        self.git(repo, "config", "user.name", "Tests")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            'env:\n  PR_QA_FRAMEWORK_RELEASE: "pr-qa-v1-test"\n',
        )
        self.write(
            repo / ".github" / "workflows" / "fieldzilla-staging-opentofu-apply.yml",
            (ROOT / ".github" / "workflows" / "fieldzilla-staging-opentofu-apply.yml").read_text(
                encoding="utf-8"
            ),
        )
        self.write(
            repo / "pr-qa" / "pr_qa.py",
            textwrap.dedent(
                """\
                import os
                import sys

                raise SystemExit(int(os.environ.get("FAKE_PR_QA_EXIT", "0")))
                """
            ),
        )
        (repo / "scripts").mkdir()
        shutil.copy2(SCRIPT, repo / "scripts" / "release-preflight")
        shutil.copy2(ROOT / "scripts" / "consumer-compatibility-preflight", repo / "scripts" / "consumer-compatibility-preflight")
        (repo / "scripts" / "release-preflight").chmod(
            (repo / "scripts" / "release-preflight").stat().st_mode | stat.S_IXUSR
        )
        (repo / "scripts" / "consumer-compatibility-preflight").chmod(
            (repo / "scripts" / "consumer-compatibility-preflight").stat().st_mode | stat.S_IXUSR
        )
        self.write(
            repo / "actions" / "runtime-certifier" / "action.yml",
            (ROOT / "actions" / "runtime-certifier" / "action.yml").read_text(encoding="utf-8"),
        )
        self.write(
            repo / "actions" / "ssm-artifact-promoter" / "action.yml",
            (ROOT / "actions" / "ssm-artifact-promoter" / "action.yml").read_text(encoding="utf-8"),
        )
        self.write(repo / "README.md", "fixture\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-m", "fixture")
        self.git(repo, "tag", "pr-qa-v1-test")
        shutil.copytree(ROOT / "pr-qa", repo / "pr-qa", dirs_exist_ok=True)
        self.git(repo, "add", "pr-qa")
        self.git(repo, "commit", "-m", "candidate framework parser")
        self.git(repo, "update-ref", "refs/remotes/origin/development", "HEAD")
        self.git(repo, "update-ref", "refs/remotes/origin/staging", "HEAD")
        return temp, repo

    def run_preflight(self, repo, *args, env=None):
        return self.run_cmd(["./scripts/release-preflight", *args], repo, env=env)

    def test_ready_when_base_resolves_and_active_release_passes(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ACTIVE_PR_QA_RELEASE: pr-qa-v1-test", proc.stdout)
        self.assertIn("BASE: development", proc.stdout)
        self.assertIn("WORKTREE: CLEAN", proc.stdout)
        self.assertIn("CENTRAL_PR_QA: PASS", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: PASS", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: YES", proc.stdout)
        self.assertIn("DEVELOPER RELEASE READINESS", proc.stdout)
        self.assertNotIn("DEVELOPER_HANDOFF_READY", proc.stdout)

    def test_staging_base_reports_developer_handoff_ready(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, "--base", "staging")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("DEVELOPER STAGING READINESS", proc.stdout)
        self.assertIn("ACTIVE_PR_QA_RELEASE: pr-qa-v1-test", proc.stdout)
        self.assertIn("BASE: staging", proc.stdout)
        self.assertIn("WORKTREE: CLEAN", proc.stdout)
        self.assertIn("CENTRAL_PR_QA: PASS", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: PASS", proc.stdout)
        self.assertIn("DEVELOPER_HANDOFF_READY: YES", proc.stdout)
        self.assertNotIn("READY_FOR_PROMOTION", proc.stdout)

    def test_staging_base_reports_developer_handoff_not_ready_on_failure(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, "--base", "staging", env={"FAKE_PR_QA_EXIT": "9"})

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("DEVELOPER STAGING READINESS", proc.stdout)
        self.assertIn("CENTRAL_PR_QA: FAIL", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: PASS", proc.stdout)
        self.assertIn("DEVELOPER_HANDOFF_READY: NO", proc.stdout)
        self.assertIn("central PR-QA failed", proc.stdout)
        self.assertNotIn("READY_FOR_PROMOTION", proc.stdout)

    def test_unresolved_base_fails_closed(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, "--base", "missing")

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("CENTRAL_PR_QA: FAIL", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: PASS", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: NO", proc.stdout)
        self.assertIn("base 'missing' could not be resolved", proc.stdout)

    def test_pr_qa_failure_blocks_promotion(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, env={"FAKE_PR_QA_EXIT": "9"})

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("CENTRAL_PR_QA: FAIL", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: PASS", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: NO", proc.stdout)
        self.assertIn("central PR-QA failed", proc.stdout)

    def test_dirty_tree_is_reported_and_blocks(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)
        (repo / "dirty.txt").write_text("dirty\n", encoding="utf-8")

        proc = self.run_preflight(repo)

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("WORKTREE: DIRTY", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: FAIL", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: NO", proc.stdout)
        self.assertIn("working tree has uncommitted changes", proc.stdout)


if __name__ == "__main__":
    unittest.main()
