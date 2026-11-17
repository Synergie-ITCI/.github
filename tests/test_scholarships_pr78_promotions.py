"""The PR #78 release controls may cross only the canonical protected branches."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pr-qa'))
import pr_qa
from adapters.base import PRContext


class CurrentRecoveryPromotionTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(pr_qa.SCHOLARSHIPS_CURRENT_RECOVERY_MANIFEST.read_text())
        self.files = self.manifest['files']
        self.development = 'bfbaa1815547ece581c39535aeeb72d39c6966c0'
        self.staging_base = '53e9e714289b76831a8b74a6d094dd9fcfe44853'
        self.main_base = 'e853573a7d426a5b8e3dd2cece7e816d41045d24'
        self.staging_head = 'a' * 40

    def context(self, number, head, base, head_ref, base_ref, files=None):
        return PRContext(
            repo=Path('/unused'), config={}, policy={},
            changed_files=list(self.files if files is None else files),
            head_ref=head_ref, base_ref=base_ref,
            event={'pull_request': {'number': number, 'head': {'sha': head},
                                    'base': {'sha': base}}})

    def verify(self, ctx, digest_override=None, certified_ancestry=True):
        with (patch.object(pr_qa, 'resolve_repository_name', return_value='Synergie-ITCI/scholarships'),
              patch.object(pr_qa, 'run_git', return_value=ctx.event['pull_request']['head']['sha']),
              patch.object(pr_qa, 'git_lines', return_value=list(self.files)),
              patch.object(pr_qa, 'resolve_fresh_origin_development_tip', return_value=self.development),
              patch.object(pr_qa, 'resolve_fresh_origin_staging_tip', return_value=(
                  self.staging_head if ctx.head_ref == 'staging' else self.staging_base)),
              patch.object(pr_qa, 'resolve_fresh_origin_main_tip', return_value=self.main_base),
              patch.object(pr_qa, 'commit_is_ancestor', return_value=certified_ancestry),
              patch.object(pr_qa, 'tree_file_sha256', side_effect=lambda repo, head, rel: (
                  digest_override if digest_override and rel == next(iter(self.files)) else self.files[rel]))):
            return pr_qa.exact_scholarships_current_recovery_promotion(ctx)

    def test_exact_development_to_staging(self):
        ctx = self.context(79, self.development, self.staging_base, 'development', 'staging')
        self.assertTrue(self.verify(ctx))
        self.assertFalse(self.verify(self.context(79, self.development, self.staging_base,
                                                  'feature', 'staging')))
        self.assertFalse(self.verify(self.context(79, self.development, self.staging_base,
                                                  'development', 'staging', list(self.files)[:-1])))
        self.assertFalse(self.verify(ctx, digest_override='0' * 64))

    def test_protected_staging_to_main_requires_certified_ancestry(self):
        ctx = self.context(80, self.staging_head, self.main_base, 'staging', 'main')
        self.assertTrue(self.verify(ctx))
        self.assertFalse(self.verify(ctx, certified_ancestry=False))
        self.assertFalse(self.verify(self.context(80, self.staging_head, self.staging_base,
                                                  'staging', 'main')))
        self.assertFalse(self.verify(self.context(81, self.staging_head, self.main_base,
                                                  'staging', 'main')))


if __name__ == '__main__':
    unittest.main()
