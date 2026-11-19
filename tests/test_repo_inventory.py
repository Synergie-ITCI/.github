"""File inventory regression tests for technology selection."""

import tempfile
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pr-qa"))

from adapters.base import RepositoryFileInventory, find_files, find_named_files
from pr_qa import detect_technologies, detect_technologies_for_phase
from resolve_node_version import explicit_engine_majors
from resolve_php_version import find_composer_metadata


class RepositoryFileInventoryTests(unittest.TestCase):
    def test_prunes_dependencies_and_preserves_hidden_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for name in [".github/workflows/qa.yml", ".hidden/secret.py", "app.py", "src/app.php", "dist",
                         "node_modules/deep/package.json", "vendor/deep/composer.json", ".terraform/deep/main.tf"]:
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("content")
            (repo / "linked.py").symlink_to(repo / "app.py")
            (repo / "linked-dir").symlink_to(repo / "src", target_is_directory=True)
            inventory = RepositoryFileInventory(repo)
            files = {path.relative_to(repo).as_posix() for path in inventory.files()}
            self.assertEqual(files, {".github/workflows/qa.yml", ".hidden/secret.py", "app.py", "src/app.php", "linked.py"})
            self.assertEqual(find_named_files(repo, {"package.json", "composer.json"}, inventory), [])
            self.assertEqual({path.name for path in find_files(repo, ["*.py"], inventory)}, {"secret.py", "app.py", "linked.py"})
            detected = detect_technologies(repo, inventory)
            self.assertIn("python", detected)
            self.assertIn("php", detected)
            self.assertIn("github_actions", detected)
            self.assertNotIn("node", detected)
            self.assertNotIn("terraform", detected)
            generated = repo / "generated.py"
            generated.write_text("content")
            self.assertNotIn(generated, inventory.files())
            inventory.invalidate()
            self.assertIn(generated, inventory.files())

    def test_same_job_detection_cache_is_bound_to_runner_temp_and_head(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            repo = repo.resolve()
            (repo / "package.json").write_text("{}")
            for command in (["git", "init", "-q"], ["git", "add", "."],
                            ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "initial"]):
                subprocess.run(command, cwd=repo, check=True, capture_output=True)
            cache = root / "runner" / "detection.json"
            env = {"GITHUB_ACTIONS": "true", "RUNNER_TEMP": str(root / "runner")}
            with mock.patch.dict(os.environ, env):
                first = detect_technologies_for_phase(repo, RepositoryFileInventory(repo), str(cache))
                self.assertIn("node", first)
                self.assertTrue(cache.exists(), cache)
                with mock.patch("pr_qa.detect_technologies", side_effect=AssertionError("Repeated detection")):
                    second = detect_technologies_for_phase(repo, RepositoryFileInventory(repo), str(cache))
                self.assertEqual(sorted(first), sorted(second))
                (repo / "pyproject.toml").write_text("[build-system]\n")
                subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
                subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "next"], cwd=repo, check=True, capture_output=True)
                third = detect_technologies_for_phase(repo, RepositoryFileInventory(repo), str(cache))
                self.assertIn("python", third)
                outside = root / "repo-controlled.json"
                self.assertIn("python", detect_technologies_for_phase(repo, RepositoryFileInventory(repo), str(outside)))
                self.assertFalse(outside.exists())

    def test_marker_free_php_legacy_fallback_remains_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            php = repo / "vendor" / "legacy.php"
            php.parent.mkdir()
            php.write_text("<?php")
            self.assertIn("php", detect_technologies(repo))

    def test_version_resolvers_prune_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for rel, content in {
                "app/package.json": '{"engines": {"node": "24"}}',
                "node_modules/deep/package.json": '{"engines": {"node": "30"}}',
                "app/composer.json": '{"require": {"php": "8.4"}}',
                "vendor/deep/composer.json": '{"require": {"php": "8.2"}}',
            }.items():
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            self.assertEqual(explicit_engine_majors(repo), {24})
            self.assertEqual([path.relative_to(repo).as_posix() for path in find_composer_metadata(repo)],
                             ["app/composer.json"])


if __name__ == "__main__":
    unittest.main()
