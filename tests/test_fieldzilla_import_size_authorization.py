"""The initial import decision is exact, bounded, and changes no defaults."""
import copy
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "fec8b9a4e7a80cc84ce10e0cdedae10aea85deee"


class FieldzillaImportSizeTests(unittest.TestCase):
    def test_only_one_exact_record_changes_and_defaults_are_preserved(self):
        current = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        prior = json.loads(subprocess.check_output(
            ["git", "show", f"{SOURCE}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        proposed = json.loads((ROOT / "operations/fieldzilla-pr712-caller-base-issuance/proposal.json").read_text())
        rows = current["one_time_baseline_alignments"]
        new = [r for r in rows if r.get("repository_id") == 1315697868 and r.get("pr_number") == 712]
        self.assertEqual(new, [proposed["baseline"]])
        normalized = copy.deepcopy(current)
        i = normalized["one_time_baseline_alignments"].index(new[0])
        normalized["one_time_baseline_alignments"][i] = proposed["previous_baseline"]
        self.assertEqual(normalized, prior)
        self.assertEqual(new[0]["expected_head_sha"], "8c187ba9b90bba5a51b7e774a63d57784d9306f0")
        self.assertEqual(new[0]["expected_base_sha"], "45fc0ce54058125c1dfd4e9bc38de1487232730c")
        self.assertEqual(new[0]["relaxations"], ["changed_file_count", "diff_size"])
        self.assertEqual(new[0]["allowed_effective_additions"], 148823)
        self.assertEqual(new[0]["allowed_changed_files"], 844)
        self.assertEqual(new[0]["minimum_changed_files"], 844)
        self.assertEqual(new[0]["expires_after"], "2026-11-11T07:04:04Z")
        self.assertEqual(len(new[0]["source_overlay"]["paths"]), 32)

    def test_sql_rebind_preserves_all_reviewed_bytes_and_reviewer(self):
        p = json.loads((ROOT / "operations/fieldzilla-pr712-caller-base-issuance/proposal.json").read_text())
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


    def test_format_overlay_changes_only_one_existing_reviewed_hash(self):
        proposal = json.loads((ROOT / "operations/fieldzilla-pr712-format-issuance/proposal.json").read_text())
        current = copy.deepcopy(proposal["baseline"]["source_overlay"])
        previous = proposal["previous_baseline"]["source_overlay"]
        path = "apps/api/tests/architecture/test_mobile_audit_baseline.py"
        self.assertEqual(set(current["paths"]), set(previous["paths"]))
        self.assertNotEqual(current["paths"][path]["candidate_sha256"],
                            previous["paths"][path]["candidate_sha256"])
        current["paths"][path] = previous["paths"][path]
        self.assertEqual(current, previous)
        self.assertEqual(proposal["baseline"]["allowed_effective_additions"] -
                         proposal["previous_baseline"]["allowed_effective_additions"], 24)
        self.assertEqual(proposal["baseline"]["expires_after"],
                         proposal["previous_baseline"]["expires_after"])

    def test_caller_rebind_adds_only_two_exact_base_paths_without_widening_caps(self):
        proposal = json.loads(
            (
                ROOT / "operations/fieldzilla-pr712-caller-base-issuance/proposal.json"
            ).read_text()
        )
        current = copy.deepcopy(proposal["baseline"]["source_overlay"])
        previous = proposal["previous_baseline"]["source_overlay"]
        extras = proposal["new_exact_base_paths"]
        self.assertEqual(
            extras,
            [
                "deploy/production/hosting/prepare_application_manifest.py",
                "deploy/production/hosting/test_prepare_application_manifest.py",
            ],
        )
        for path in extras:
            self.assertEqual(
                current["paths"].pop(path), {"source": "absent", "candidate": "base"}
            )
            current["allowed_paths"].remove(path)
        self.assertEqual(current, previous)
        for key in (
            "allowed_effective_additions",
            "allowed_changed_files",
            "minimum_changed_files",
            "expires_after",
            "relaxations",
        ):
            self.assertEqual(
                proposal["baseline"][key], proposal["previous_baseline"][key]
            )
        self.assertEqual(len(proposal["reviewed_deployment_paths_unchanged"]), 40)
        self.assertFalse(proposal["activation_authorized"])
