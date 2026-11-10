"""Exact reviewed overlays remain byte-bound and grant no ordinary-consumer access."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'pr-qa'))
import pr_qa as engine
from baseline_authorization import schema_errors


class ReviewedHashOverlayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        self.path = 'deploy/plan.py'
        (self.repo / 'deploy').mkdir()
        (self.repo / self.path).write_text('print("reviewed preparation")\n')
        for args in [('init', '-q'), ('config', 'user.name', 'Synthetic'), ('config', 'user.email', 'synthetic@example.invalid'), ('add', '.'), ('commit', '-qm', 'synthetic reviewed bytes')]:
            subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True)
        self.sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.repo).decode().strip()
        self.digest = hashlib.sha256((self.repo / self.path).read_bytes()).hexdigest()
        self.spec = {'source': 'present', 'candidate': 'reviewed_sha256', 'candidate_sha256': self.digest}
        self.ctx = SimpleNamespace(repo=self.repo)

    def validate(self, spec=None, path=None):
        return engine.validate_baseline_overlay_path(self.ctx, self.sha, self.sha, '', path or self.path, self.spec if spec is None else spec)

    def test_exact_bytes(self):
        self.assertEqual(self.validate(), [])

    def test_dirty_working_tree_is_rejected(self):
        (self.repo / self.path).write_text('print("unreviewed")\n')
        self.assertTrue(self.validate())

    def test_wrong_committed_hash_is_rejected(self):
        self.assertTrue(self.validate({**self.spec, 'candidate_sha256': '0' * 64}))

    def test_missing_hash_is_rejected(self):
        self.assertTrue(self.validate({'candidate': 'reviewed_sha256'}))

    def test_other_selector_cannot_use_hash(self):
        self.assertTrue(self.validate({**self.spec, 'candidate': 'source'}))

    def test_symlink_is_rejected_even_with_matching_target_bytes(self):
        value = (self.repo / self.path).read_text()
        (self.repo / self.path).unlink()
        (self.repo / 'target').write_text(value)
        (self.repo / self.path).symlink_to('../target')
        self.assertTrue(self.validate())

    def test_noncanonical_path_is_rejected(self):
        self.assertTrue(self.validate(path='deploy/../deploy/plan.py'))

    def test_base_selector_requires_authorized_base(self):
        self.assertTrue(self.validate({'candidate': 'base'}))

    def test_retained_prqa_caller_must_match_exact_base(self):
        path = '.github/workflows/pr-qa.yml'
        (self.repo / '.github/workflows').mkdir(parents=True)
        (self.repo / path).write_text('name: exact trusted base caller\n')
        subprocess.run(['git', 'add', '.'], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(['git', 'commit', '-qm', 'trusted base'], cwd=self.repo, check=True, capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.repo).decode().strip()
        self.assertEqual(engine.validate_baseline_overlay_path(self.ctx, self.sha, base, base, path, {'candidate': 'base'}), [])
        (self.repo / path).write_text('name: altered caller\n')
        subprocess.run(['git', 'add', '.'], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(['git', 'commit', '-qm', 'altered caller'], cwd=self.repo, check=True, capture_output=True)
        changed = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.repo).decode().strip()
        self.assertTrue(engine.validate_baseline_overlay_path(self.ctx, self.sha, changed, base, path, {'candidate': 'base'}))

    def test_schema_rejects_malformed_hash(self):
        schema = json.loads((ROOT / 'schemas/one-time-baseline.schema.json').read_text())['properties']['source_overlay']['properties']['paths']['additionalProperties']
        self.assertFalse(schema_errors(self.spec, schema))
        self.assertTrue(schema_errors({**self.spec, 'candidate_sha256': '*'}, schema))


if __name__ == '__main__':
    unittest.main()
