import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release-preflight"


class ReleasePreflightTests(unittest.TestCase):
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
        (repo / "scripts" / "release-preflight").chmod(
            (repo / "scripts" / "release-preflight").stat().st_mode | stat.S_IXUSR
        )
        self.write(repo / "README.md", "fixture\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-m", "fixture")
        self.git(repo, "tag", "pr-qa-v1-test")
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
        self.assertIn("DEVELOPER_HANDOFF_READY: YES", proc.stdout)
        self.assertNotIn("READY_FOR_PROMOTION", proc.stdout)

    def test_staging_base_reports_developer_handoff_not_ready_on_failure(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, "--base", "staging", env={"FAKE_PR_QA_EXIT": "9"})

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("DEVELOPER STAGING READINESS", proc.stdout)
        self.assertIn("CENTRAL_PR_QA: FAIL", proc.stdout)
        self.assertIn("DEVELOPER_HANDOFF_READY: NO", proc.stdout)
        self.assertIn("central PR-QA failed", proc.stdout)
        self.assertNotIn("READY_FOR_PROMOTION", proc.stdout)

    def test_unresolved_base_fails_closed(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, "--base", "missing")

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("CENTRAL_PR_QA: FAIL", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: NO", proc.stdout)
        self.assertIn("base 'missing' could not be resolved", proc.stdout)

    def test_pr_qa_failure_blocks_promotion(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, env={"FAKE_PR_QA_EXIT": "9"})

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("CENTRAL_PR_QA: FAIL", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: NO", proc.stdout)
        self.assertIn("central PR-QA failed", proc.stdout)

    def test_dirty_tree_is_reported_and_blocks(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)
        (repo / "dirty.txt").write_text("dirty\n", encoding="utf-8")

        proc = self.run_preflight(repo)

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("WORKTREE: DIRTY", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: NO", proc.stdout)
        self.assertIn("working tree has uncommitted changes", proc.stdout)


if __name__ == "__main__":
    unittest.main()
