"""The initial import decision is exact, bounded, and changes no defaults."""
import copy
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "812084ade2727c5702c9ccf8e3e7c771d956d169"


class FieldzillaImportSizeTests(unittest.TestCase):
    def test_only_one_exact_record_changes_and_defaults_are_preserved(self):
        current = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        prior = json.loads(subprocess.check_output(
            ["git", "show", f"{SOURCE}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        proposed = json.loads((ROOT / "operations/fieldzilla-pr712-c92-issuance/proposal.json").read_text())
        rows = current["one_time_baseline_alignments"]
        new = [r for r in rows if r.get("repository_id") == 1315697868 and r.get("pr_number") == 712]
        self.assertEqual(new, [proposed["baseline"]])
        normalized = copy.deepcopy(current)
        i = normalized["one_time_baseline_alignments"].index(new[0])
        normalized["one_time_baseline_alignments"][i] = proposed["previous_baseline"]
        self.assertEqual(normalized, prior)
        self.assertEqual(new[0]["expected_head_sha"], "c92beeb7f493739d9685402925f3104f9716924d")
        self.assertEqual(new[0]["expected_base_sha"], "c8aee71a61059392f17343eac434d2a73dfb3b4c")
        self.assertEqual(new[0]["relaxations"], ["changed_file_count", "diff_size"])
        self.assertEqual(new[0]["allowed_effective_additions"], 148759)
        self.assertEqual(new[0]["allowed_changed_files"], 844)
        self.assertEqual(new[0]["minimum_changed_files"], 844)
        self.assertEqual(new[0]["expires_after"], "2026-11-11T07:04:04Z")
        self.assertEqual(len(new[0]["source_overlay"]["paths"]), 26)

    def test_sql_rebind_preserves_all_reviewed_bytes_and_reviewer(self):
        p = json.loads((ROOT / "operations/fieldzilla-pr712-c92-issuance/proposal.json").read_text())
        current = json.loads((ROOT / "policy/audited-migration-authorizations.json").read_text())
        prior = json.loads(subprocess.check_output(
            ["git", "show", f"{SOURCE}:policy/audited-migration-authorizations.json"], cwd=ROOT,
        ))
        normalized = copy.deepcopy(current)
        normalized[normalized.index(p["sql"])] = p["previous_sql"]
        self.assertEqual(normalized, prior)
        for key in ("migration_path", "migration_sha256", "delete_fingerprints", "approved_reviewer", "expires_at"):
            self.assertEqual(p["sql"][key], p["previous_sql"][key])
        self.assertEqual(p["status"], "PROPOSED_NOT_ISSUED_NOT_ACTIVE")
