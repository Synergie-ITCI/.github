"""The initial import decision is exact, bounded, and changes no defaults."""
import copy
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "1ac84a32901db48888f0d6a82e59195ff3174abf"


class FieldzillaImportSizeTests(unittest.TestCase):
    def test_only_one_exact_record_changes_and_defaults_are_preserved(self):
        current = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        prior = json.loads(subprocess.check_output(
            ["git", "show", f"{SOURCE}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        proposed = json.loads((ROOT / "operations/fieldzilla-pr712-mobile-issuance/proposal.json").read_text())
        rows = current["one_time_baseline_alignments"]
        new = [r for r in rows if r.get("repository_id") == 1315697868 and r.get("pr_number") == 712]
        self.assertEqual(new, [proposed["baseline"]])
        normalized = copy.deepcopy(current)
        i = normalized["one_time_baseline_alignments"].index(new[0])
        normalized["one_time_baseline_alignments"][i] = proposed["previous_baseline"]
        self.assertEqual(normalized, prior)
        self.assertEqual(new[0]["expected_head_sha"], "219ff68c08caeb850b6e21cf745ffa3f8712bcaa")
        self.assertEqual(new[0]["expected_base_sha"], "c8aee71a61059392f17343eac434d2a73dfb3b4c")
        self.assertEqual(new[0]["relaxations"], ["changed_file_count", "diff_size"])
        self.assertEqual(new[0]["allowed_effective_additions"], 148799)
        self.assertEqual(new[0]["allowed_changed_files"], 844)
        self.assertEqual(new[0]["minimum_changed_files"], 844)
        self.assertEqual(new[0]["expires_after"], "2026-11-11T07:04:04Z")
        self.assertEqual(len(new[0]["source_overlay"]["paths"]), 30)

    def test_sql_rebind_preserves_all_reviewed_bytes_and_reviewer(self):
        p = json.loads((ROOT / "operations/fieldzilla-pr712-mobile-issuance/proposal.json").read_text())
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


    def test_mobile_overlay_is_only_four_exact_reviewed_files(self):
        proposal = json.loads((ROOT / "operations/fieldzilla-pr712-mobile-issuance/proposal.json").read_text())
        current = proposal["baseline"]["source_overlay"]
        previous = proposal["previous_baseline"]["source_overlay"]
        expected = {
            "apps/api/tests/architecture/test_mobile_audit_baseline.py",
            "apps/mobile/package.json", "apps/mobile/package-lock.json",
            "apps/mobile/security/mobile-audit-baseline.json",
        }
        self.assertEqual(set(current["paths"]) - set(previous["paths"]), expected)
        self.assertEqual(set(current["allowed_paths"]) - set(previous["allowed_paths"]), expected)
        for path, reviewed in previous["paths"].items():
            self.assertEqual(current["paths"][path], reviewed)
        self.assertEqual(current["approved_application_source_sha"], previous["approved_application_source_sha"])
        self.assertEqual(current["paths"]["apps/mobile/security/mobile-audit-baseline.json"]["candidate_sha256"],
                         "fbb8d12a375224c2d778ad92fda079a0bae1c1db8196ac54750320b73f64a7e8")
        self.assertEqual(current["paths"]["apps/mobile/package-lock.json"]["candidate_sha256"],
                         "9bd53e16a76f2720a31c7d27cbe203f8841e8ab796ec9c5bd2679f9f0904a4a2")
        for path in expected:
            self.assertEqual(current["paths"][path]["candidate"], "reviewed_sha256")
            self.assertRegex(current["paths"][path]["candidate_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(proposal["baseline"]["allowed_effective_additions"] -
                         proposal["previous_baseline"]["allowed_effective_additions"], 40)
