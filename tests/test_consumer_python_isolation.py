"""Regression coverage for central checkouts inside consumer workspaces."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))

from adapters.base import CommandOutcome, PRContext
from adapters.python import PythonAdapter


class ConsumerPythonIsolationTests(unittest.TestCase):
    def test_python_checks_exclude_only_central_checkouts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "pyproject.toml").write_text("[tool.black]\n[tool.ruff]\n")
            (repo / "app.py").write_text("value = 1\n")
            (repo / "tests").mkdir()
            (repo / "tests/test_app.py").write_text("def test_app(): assert True\n")
            for name in (".pr-qa-framework", ".pr-qa-release-resolver"):
                (repo / name).mkdir()
                (repo / name / "pyproject.toml").write_text("[tool.black]\n")
                (repo / name / "bad.py").write_text("invalid =\n")
            adapter = PythonAdapter()
            self.assertEqual(adapter.detect(repo), [repo])
            ctx = PRContext(
                repo=repo,
                config={"runtime": {"install_dependencies": False}},
                policy={},
                changed_files=[],
            )
            calls: list[list[str]] = []

            def run(command: list[str], **_: object) -> CommandOutcome:
                calls.append(command)
                return CommandOutcome(" ".join(command), str(repo), 0)

            ctx.run = run  # type: ignore[method-assign]
            adapter.format(ctx, [repo])
            adapter.lint(ctx, [repo])
            adapter.test(ctx, [repo])
            adapter.build(ctx, [repo])
            joined = [" ".join(command) for command in calls]
            self.assertTrue(
                any("black --check --extend-exclude" in line for line in joined)
            )
            self.assertTrue(
                any(
                    "ruff check" in line and "--extend-exclude" in line
                    for line in joined
                )
            )
            self.assertTrue(
                any(
                    "pytest --ignore=.pr-qa-framework --ignore=.pr-qa-release-resolver"
                    in line
                    for line in joined
                )
            )
            self.assertTrue(
                any("compileall" in line and "-x" in line for line in joined)
            )

    @unittest.skipUnless(shutil.which("ruff"), "Ruff unavailable")
    def test_real_ruff_excludes_checkouts_but_detects_application_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "app.py").write_text("value = 1\n")
            for name in (".pr-qa-framework", ".pr-qa-release-resolver"):
                (repo / name).mkdir()
                (repo / name / "bad.py").write_text("invalid =\n")
            command = [
                "ruff",
                "check",
                ".",
                "--extend-exclude",
                ".pr-qa-framework",
                "--extend-exclude",
                ".pr-qa-release-resolver",
            ]
            self.assertNotEqual(
                subprocess.run(
                    ["ruff", "check", "."], cwd=repo, capture_output=True, check=False
                ).returncode,
                0,
            )
            self.assertEqual(
                subprocess.run(
                    command, cwd=repo, capture_output=True, check=False
                ).returncode,
                0,
            )
            (repo / "app.py").write_text("invalid =\n")
            self.assertNotEqual(
                subprocess.run(
                    command, cwd=repo, capture_output=True, check=False
                ).returncode,
                0,
            )

    @unittest.skipUnless(shutil.which("black"), "Black unavailable")
    def test_real_black_excludes_checkouts_but_detects_application_formatting(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "app.py").write_text("value = 1\n")
            for name in (".pr-qa-framework", ".pr-qa-release-resolver"):
                (repo / name).mkdir()
                (repo / name / "bad.py").write_text("invalid =\n")
            command = [
                "black",
                "--check",
                "--extend-exclude",
                r"/\.pr-qa-(framework|release-resolver)/",
                ".",
            ]
            self.assertNotEqual(
                subprocess.run(
                    ["black", "--check", "."],
                    cwd=repo,
                    capture_output=True,
                    check=False,
                ).returncode,
                0,
            )
            self.assertEqual(
                subprocess.run(
                    command, cwd=repo, capture_output=True, check=False
                ).returncode,
                0,
            )
            (repo / "app.py").write_text("value=1\n")
            self.assertNotEqual(
                subprocess.run(
                    command, cwd=repo, capture_output=True, check=False
                ).returncode,
                0,
            )

    def test_genuine_application_failure_remains_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "pyproject.toml").write_text("[tool.ruff]\n")
            adapter = PythonAdapter()
            ctx = PRContext(
                repo=repo,
                config={"runtime": {"install_dependencies": False}},
                policy={},
                changed_files=[],
            )
            ctx.run = lambda command, **kwargs: CommandOutcome(
                " ".join(command), str(repo), 1
            )  # type: ignore[method-assign]
            self.assertEqual(adapter.lint(ctx, [repo])[0].status, "FAIL")


class PostgresTestConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location(
            "setup_test_postgres", ROOT / "pr-qa" / "setup_test_postgres.py"
        )
        assert spec and spec.loader
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_missing_configuration_is_no_op(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(self.module.configured_database(Path(tmp)))

    def test_test_only_role_and_database_are_passed_to_local_psql(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "pyproject.toml").write_text(
                '[tool.synergie_pr_qa.postgres_test]\nrole = "fixture_user"\ndatabase = "fixture_db"\n'
            )
            self.assertEqual(
                self.module.configured_database(repo), ("fixture_user", "fixture_db")
            )
            with (
                mock.patch.object(
                    sys, "argv", ["setup_test_postgres.py", "--repo", str(repo)]
                ),
                mock.patch.object(
                    self.module.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0),
                ) as run,
            ):
                self.assertEqual(self.module.main(), 0)
            args, kwargs = run.call_args
            self.assertIn("qa_role=fixture_user", args[0])
            self.assertIn("qa_db=fixture_db", args[0])
            self.assertIn("CREATE DATABASE", kwargs["input"])
            self.assertIn("127.0.0.1", args[0])
            self.assertIn("5432", args[0])
            self.assertEqual(kwargs["env"]["PGPASSFILE"], "/dev/null")
            self.assertNotIn("PGHOST", kwargs["env"])
            self.assertNotIn("PGPORT", kwargs["env"])

    def test_invalid_or_privileged_configuration_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for role in ("postgres", "runner", "pg_owner", "bad-role"):
                (repo / "pyproject.toml").write_text(
                    f'[tool.synergie_pr_qa.postgres_test]\nrole = "{role}"\ndatabase = "fixture_db"\n'
                )
                with self.assertRaises(ValueError):
                    self.module.configured_database(repo)
            for database in ("postgres", "template0", "telepathy_test", "bad-name"):
                (repo / "pyproject.toml").write_text(
                    f'[tool.synergie_pr_qa.postgres_test]\nrole = "fixture_user"\ndatabase = "{database}"\n'
                )
                with self.assertRaises(ValueError):
                    self.module.configured_database(repo)

    def test_setup_failure_remains_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "pyproject.toml").write_text(
                '[tool.synergie_pr_qa.postgres_test]\nrole = "fixture_user"\ndatabase = "fixture_db"\n'
            )
            with (
                mock.patch.object(
                    sys, "argv", ["setup_test_postgres.py", "--repo", str(repo)]
                ),
                mock.patch.object(
                    self.module.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 1),
                ),
                self.assertRaises(RuntimeError),
            ):
                self.module.main()

    def test_existing_role_or_database_fails_closed(self) -> None:
        self.assertIn('CREATE ROLE :"qa_role" LOGIN;', self.module.SQL)
        self.assertIn('CREATE DATABASE :"qa_db" OWNER :"qa_role";', self.module.SQL)
        self.assertNotIn("IF NOT EXISTS", self.module.SQL)
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "pyproject.toml").write_text(
                '[tool.synergie_pr_qa.postgres_test]\nrole = "fixture_user"\ndatabase = "fixture_db"\n'
            )
            for existing in ("role", "database"):
                with (
                    mock.patch.object(
                        sys, "argv", ["setup_test_postgres.py", "--repo", str(repo)]
                    ),
                    mock.patch.object(
                        self.module.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess(
                            [], 3, stderr=f"{existing} already exists"
                        ),
                    ),
                    self.assertRaisesRegex(RuntimeError, "Could not prepare isolated"),
                ):
                    self.module.main()

    def test_reserved_checkout_paths_are_rejected_before_central_checkout(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "pr-qa.yml").read_text()
        self.assertEqual(
            workflow.count("Reject consumer-owned central QA checkout paths"), 2
        )
        self.assertEqual(workflow.count("git ls-tree -r --name-only HEAD"), 2)
        self.assertLess(
            workflow.index("Reject consumer-owned central QA checkout paths"),
            workflow.index("Checkout central PR QA release resolver"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "app.py").write_text("value = 1\n")
            reserved = repo / ".pr-qa-release-resolver"
            reserved.mkdir()
            (reserved / "untrusted.py").write_text("value = 2\n")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                check=True,
            )
            files = subprocess.check_output(
                ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "HEAD"],
                text=True,
            ).splitlines()
            self.assertTrue(
                any(path.startswith(".pr-qa-release-resolver/") for path in files)
            )
            guard = (
                "git ls-tree -r --name-only HEAD | "
                "grep -Eq '^\\.pr-qa-(framework|release-resolver)(/|$)'"
            )
            self.assertEqual(
                subprocess.run(["bash", "-c", guard], cwd=repo, check=False).returncode,
                0,
            )
            (reserved / "untrusted.py").unlink()
            subprocess.run(["git", "-C", str(repo), "add", "-u"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-qm",
                    "clean",
                ],
                check=True,
            )
            self.assertNotEqual(
                subprocess.run(["bash", "-c", guard], cwd=repo, check=False).returncode,
                0,
            )
