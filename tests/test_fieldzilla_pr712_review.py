"""Prove the proposal stays inert and does not inherit fresh deployment changes."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
import baseline_authorization as binding
import migration_authorization as migration
import pr_qa as engine
from adapters.base import PRContext


class FieldzillaReviewProposalTests(unittest.TestCase):
    def setUp(self):
        self.request = json.loads(
            (ROOT / "operations/fieldzilla-pr712-review/request.json").read_text()
        )
        app = self.request["application"]
        self.context = PRContext(
            repo=ROOT,
            config={},
            policy={},
            changed_files=[],
            head_ref=app["head_ref"],
            base_ref=app["base_ref"],
        )

    def test_proposal_is_not_an_authorization_record(self):
        self.assertEqual(
            self.request["status"], "PREPARATION_ONLY_NOT_AN_AUTHORIZATION"
        )
        self.assertFalse(self.request["issuance"]["issued"])
        self.assertIsNone(self.request["issuance"]["start"])
        self.assertIsNone(self.request["issuance"]["expiry"])
        for value, schema_path in (
            (self.request, binding.SCHEMA_PATH),
            ([self.request], migration.SCHEMA_PATH),
        ):
            self.assertTrue(
                binding.schema_errors(value, json.loads(schema_path.read_text()))
            )

    def test_only_exact_source_blobs_can_be_inherited(self):
        # Assume a future reviewed baseline only to exercise the existing
        # classifier. This mock does not validate or issue such an authorization.
        app = self.request["application"]
        rows = self.request["scope"]["deployment_findings"]
        source = {row["path"]: row["source_blob"] for row in rows if row["source_blob"]}
        candidate = {row["path"]: row["candidate_blob"] for row in rows}
        with mock.patch.object(engine, "baseline_active", return_value=True), \
             mock.patch.object(engine, "baseline_overlay_allowed_paths", return_value=set()), \
             mock.patch.object(engine, "baseline_source_sha", return_value=app["comparison_source_sha"]), \
             mock.patch.object(engine, "baseline_candidate_head_sha", return_value=app["head_sha"]), \
             mock.patch.object(engine, "baseline_commit_exists", return_value=True), \
             mock.patch.object(
                 engine, "baseline_tree_blob_ids",
                 side_effect=lambda _ctx, ref: source if ref == app["comparison_source_sha"] else candidate,
             ):
            for row in rows:
                with self.subTest(path=row["path"]):
                    result = engine.baseline_finding_classification(
                        self.context, row["path"], "deployment_sensitive"
                    )
                    expected = (
                        engine.INHERITED_BASELINE
                        if row["source_blob"] == row["candidate_blob"]
                        else engine.NEW_FINDING
                    )
                    self.assertEqual(result["classification"], expected)
                    self.assertEqual(
                        row["matches_comparison_source"],
                        row["source_blob"] == row["candidate_blob"],
                    )

    def test_proposal_does_not_enable_ordinary_consumers(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(engine.baseline_requested(self.context))
            self.assertFalse(engine.baseline_active(self.context))
        with mock.patch.dict(
            os.environ, {"GITHUB_REPOSITORY": "Synergie-ITCI/.github"}, clear=True
        ), mock.patch.object(migration, "read_live_pr") as lookup:
            reviewed, errors = migration.reviewed_migration_texts(self.context)
            self.assertEqual((reviewed, errors), ({}, []))
            lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
