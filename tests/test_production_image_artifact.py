"""Same-run image artifact origin, traversal, tamper and overwrite boundaries."""

import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/fieldzilla-production"))
from image_artifact import extract_images, validate_origin


class ImageArtifactTests(unittest.TestCase):
    def setUp(self):
        self.source, self.caller, self.run = "a" * 40, "b" * 40, 123
        self.payloads = {
            "api.tar": b"synthetic-api-archive",
            "admin-web.tar": b"synthetic-admin-archive",
        }
        self.build = {
            "source_sha": self.source,
            "caller_sha": self.caller,
            "run_id": self.run,
            "run_attempt": 1,
            "platform": "linux/arm64",
            "images": {},
        }
        for kind in ["api", "admin-web"]:
            data = self.payloads[kind + ".tar"]
            self.build["images"][kind] = {
                "config_digest": "sha256:" + ("c" if kind == "api" else "d") * 64,
                "archive_sha256": hashlib.sha256(data).hexdigest(),
                "archive_bytes": len(data),
            }
        self.metadata = {
            "name": "fieldzilla-production-images-" + self.source,
            "expired": False,
            "size_in_bytes": 512,
            "digest": "sha256:" + "f" * 64,
            "workflow_run": {
                "id": self.run,
                "head_sha": self.caller,
                "head_branch": "main",
                "repository_id": 1315697868,
                "head_repository_id": 1315697868,
            },
        }

    def archive(self, extra=None):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as zipped:
            for name, data in self.payloads.items():
                zipped.writestr(name, data)
            zipped.writestr("images.json", json.dumps(self.build))
            if extra:
                zipped.writestr(*extra)
        return output.getvalue()

    def extract(self, folder, data):
        archive = Path(folder) / "images.zip"
        archive.write_bytes(data)
        return extract_images(
            archive,
            Path(folder) / "verified",
            archive_digest=hashlib.sha256(data).hexdigest(),
            source_sha=self.source,
            caller_sha=self.caller,
            run_id=self.run,
        )

    def test_same_run_exact_source_private_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self.extract(folder, self.archive())
            self.assertEqual(result, self.build)
            self.assertEqual(
                (Path(folder) / "verified/api.tar").read_bytes(),
                self.payloads["api.tar"],
            )
            self.assertEqual(
                (Path(folder) / "verified/api.tar").stat().st_mode & 0o777, 0o600
            )

    def test_origin_rejects_cross_run_fork_branch_expiry_and_digest(self):
        validate_origin(
            self.metadata,
            run_id=self.run,
            caller_sha=self.caller,
            source_sha=self.source,
            archive_digest="f" * 64,
        )
        for target, key, value in [
            (self.metadata, "expired", True),
            (self.metadata, "digest", "sha256:" + "e" * 64),
            (self.metadata["workflow_run"], "id", 124),
            (self.metadata["workflow_run"], "head_branch", "staging"),
            (self.metadata["workflow_run"], "head_sha", self.source),
            (self.metadata["workflow_run"], "head_repository_id", 1),
        ]:
            previous = target[key]
            target[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_origin(
                    self.metadata,
                    run_id=self.run,
                    caller_sha=self.caller,
                    source_sha=self.source,
                    archive_digest="f" * 64,
                )
            target[key] = previous

    def test_traversal_or_extra_script_is_rejected_before_any_extraction(self):
        for name in ["../escape", "execute.py"]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                with self.assertRaises(ValueError):
                    self.extract(folder, self.archive((name, b"synthetic")))
                self.assertFalse((Path(folder) / "verified").exists())

    def test_symlink_is_rejected_before_any_extraction(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as zipped:
            info = zipfile.ZipInfo("api.tar")
            info.external_attr = 0o120777 << 16
            zipped.writestr(info, self.payloads["api.tar"])
            zipped.writestr("admin-web.tar", self.payloads["admin-web.tar"])
            zipped.writestr("images.json", json.dumps(self.build))
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                self.extract(folder, output.getvalue())
            self.assertFalse((Path(folder) / "verified").exists())

    def test_wrong_platform_attempt_or_source_metadata_cannot_be_loaded(self):
        for key, value in [
            ("platform", "linux/amd64"),
            ("run_attempt", 2),
            ("source_sha", "e" * 40),
        ]:
            previous = self.build[key]
            self.build[key] = value
            with self.subTest(key=key), tempfile.TemporaryDirectory() as folder:
                with self.assertRaises(ValueError):
                    self.extract(folder, self.archive())
                self.assertFalse((Path(folder) / "verified").exists())
            self.build[key] = previous

    def test_tampered_image_archive_is_rejected_without_running_any_image(self):
        self.payloads["api.tar"] = b"x" * len(self.payloads["api.tar"])
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(ValueError):
            self.extract(folder, self.archive())

    def test_existing_extraction_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "verified"
            target.mkdir()
            (target / "retained").write_text("retained")
            with self.assertRaises(FileExistsError):
                self.extract(folder, self.archive())
            self.assertEqual((target / "retained").read_text(), "retained")
