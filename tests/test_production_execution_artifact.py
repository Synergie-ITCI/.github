import hashlib
import io
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/fieldzilla-production"))
from execution_artifact import MAX_MANIFEST, NAME, read_manifest_artifact


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.raw = b'{"scope":"production-rehearsal"}\n'
        self.metadata = {
            "id": 123,
            "name": NAME,
            "expired": False,
            "workflow_run": {
                "id": 456,
                "repository_id": 1315697868,
                "head_repository_id": 1315697868,
                "head_branch": "main",
                "head_sha": "a" * 40,
            },
        }

    def archive(self, files):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as zipped:
            for name, data in files:
                zipped.writestr(name, data)
        archive = stream.getvalue()
        self.metadata["digest"] = "sha256:" + hashlib.sha256(archive).hexdigest()
        return archive

    def read(self, archive):
        return read_manifest_artifact(
            metadata=self.metadata,
            archive=archive,
            artifact_id=123,
            run_id=456,
            caller_sha="a" * 40,
            manifest_sha256=hashlib.sha256(self.raw).hexdigest(),
        )

    def test_exact_single_manifest_returned_without_extraction(self):
        raw, payload = self.read(self.archive([("execution-manifest.json", self.raw)]))
        self.assertEqual(raw, self.raw)
        self.assertEqual(payload, {"scope": "production-rehearsal"})

    def test_extra_path_traversal_and_oversized_manifest_rejected(self):
        for files in (
            [("../execution-manifest.json", self.raw)],
            [("execution-manifest.json", self.raw), ("run.sh", b"echo unsafe")],
            [("execution-manifest.json", b"x" * (MAX_MANIFEST + 1))],
        ):
            with (
                self.subTest(files=[name for name, _ in files]),
                self.assertRaises(ValueError),
            ):
                self.read(self.archive(files))

    def test_changed_archive_raw_manifest_or_origin_rejected(self):
        archive = self.archive([("execution-manifest.json", self.raw)])
        with self.assertRaises(ValueError):
            self.read(archive + b"changed")
        with self.assertRaises(ValueError):
            self.read(self.archive([("execution-manifest.json", b"{}")]))
        archive = self.archive([("execution-manifest.json", self.raw)])
        self.metadata["workflow_run"]["head_branch"] = "staging"
        with self.assertRaises(ValueError):
            self.read(archive)

    def test_duplicate_json_properties_cannot_change_meaning_after_approval(self):
        self.raw = b'{"scope":"production-rehearsal","scope":"production"}'
        with self.assertRaises(ValueError):
            self.read(self.archive([("execution-manifest.json", self.raw)]))

    def test_non_object_manifest_is_rejected_even_with_matching_digest(self):
        self.raw = b"[]"
        with self.assertRaises(TypeError):
            self.read(self.archive([("execution-manifest.json", self.raw)]))
