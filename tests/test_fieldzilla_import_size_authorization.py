"""The initial import decision is exact, bounded, and changes no defaults."""
import copy
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "9c2e9c85c0103e9c477eda211d305c52355b61a5"
PROPOSAL = ROOT / "operations/fieldzilla-pr712-historical-final-review/proposal.json"


class FieldzillaImportSizeTests(unittest.TestCase):
    def test_historical_review_changes_only_exact_fieldzilla_record(self):
        current = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        prior = json.loads(subprocess.check_output(
            ["git", "show", f"{SOURCE}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        proposed = json.loads(PROPOSAL.read_text())
        rows = current["one_time_baseline_alignments"]
        new = [r for r in rows if r.get("repository_id") == 1315697868 and r.get("pr_number") == 712]
        self.assertEqual(new, [proposed["baseline"]])
        normalized = copy.deepcopy(current)
        normalized["one_time_baseline_alignments"][rows.index(new[0])] = proposed["previous_baseline"]
        self.assertEqual(normalized, prior)
        review = new[0]
        self.assertEqual((review["expected_head_sha"], review["expected_base_sha"]),
                         ("31d5986ed69ba68f453b1b10cfc04cb161f2bd19",
                          "8ae3caaa067b3698713e514e1a834412781a93dc"))
        self.assertEqual((review["allowed_changed_files"], review["minimum_changed_files"],
                          review["allowed_effective_additions"]), (905, 905, 149054))
        self.assertEqual(review["relaxations"], ["changed_file_count", "diff_size"])
        overlay = review["source_overlay"]
        previous = proposed["previous_baseline"]["source_overlay"]
        self.assertEqual(len(overlay["paths"]), 47)
        self.assertEqual(set(overlay["paths"]) - set(previous["paths"]), {
            "apps/api/scripts/production_historical_migrate.py",
            "apps/api/tests/architecture/test_production_historical_migrate.py",
        })
        self.assertEqual(set(overlay["paths"]), set(overlay["allowed_paths"]))
        changed = {path for path in previous["paths"]
                   if overlay["paths"][path] != previous["paths"][path]}
        self.assertEqual(changed, {
            ".gitleaksignore",
            "apps/api/tests/architecture/test_production_application_plan.py",
            "deploy/production/application_plan.py",
        })
        self.assertEqual(overlay["paths"][".gitleaksignore"]["candidate_sha256"],
                         "3f0d4a1d7003c681f8d357f2f4fafdbb0014fa08df71b905adcd1b77a1b0c639")
        self.assertFalse(proposed["activation_authorized"])

    def test_historical_sql_review_preserves_audited_bytes_and_reviewer(self):
        proposed = json.loads(PROPOSAL.read_text())
        current = json.loads((ROOT / "policy/audited-migration-authorizations.json").read_text())
        prior = json.loads(subprocess.check_output(
            ["git", "show", f"{SOURCE}:policy/audited-migration-authorizations.json"], cwd=ROOT,
        ))
        normalized = copy.deepcopy(current)
        normalized[normalized.index(proposed["sql"])] = proposed["previous_sql"]
        self.assertEqual(normalized, prior)
        for key in ("migration_path", "migration_sha256", "delete_fingerprints", "approved_reviewer"):
            self.assertEqual(proposed["sql"][key], proposed["previous_sql"][key])
        self.assertEqual(proposed["sql"]["expected_head_sha"], proposed["application_head_sha"])
        self.assertEqual(proposed["sql"]["expected_base_sha"], proposed["application_base_sha"])
        self.assertEqual(proposed["status"], "PROPOSED_NOT_APPROVED_NOT_ACTIVE")

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

    def test_final_rebind_adds_only_rehearsal_paths_bound_to_exact_base(self):
        proposal = json.loads((ROOT / "operations/fieldzilla-pr712-final-base-issuance/proposal.json").read_text())
        current = copy.deepcopy(proposal["baseline"]["source_overlay"])
        previous = proposal["previous_baseline"]["source_overlay"]
        extras = proposal["new_exact_base_paths"]
        self.assertEqual(len(extras), 13)
        self.assertEqual(extras, sorted(extras))
        self.assertTrue(all(path.startswith("deploy/production/hosting/rehearsal/") for path in extras))
        for path in extras:
            self.assertEqual(current["paths"].pop(path), {"source": "absent", "candidate": "base"})
            current["allowed_paths"].remove(path)
        self.assertEqual(current, previous)
        for key in ("allowed_effective_additions", "allowed_changed_files", "minimum_changed_files", "expires_after", "relaxations"):
            self.assertEqual(proposal["baseline"][key], proposal["previous_baseline"][key])
        self.assertEqual(proposal["sql"]["migration_sha256"], proposal["previous_sql"]["migration_sha256"])
        self.assertEqual(proposal["sql"]["delete_fingerprints"], proposal["previous_sql"]["delete_fingerprints"])
        self.assertFalse(proposal["activation_authorized"])

    def test_expired_review_renewal_preserves_exact_scope(self):
        proposal = json.loads((ROOT / "operations/fieldzilla-pr712-review-renewal/proposal.json").read_text())
        for current, previous, expiry_key in (
            (proposal["baseline"], proposal["previous_baseline"], "expires_after"),
            (proposal["sql"], proposal["previous_sql"], "expires_at"),
        ):
            stable = set(current) - {"issued_at", "authorization_id", expiry_key, "purpose", "required_pr_body_marker"}
            self.assertEqual({key: current[key] for key in stable}, {key: previous[key] for key in stable})
            self.assertEqual(previous[expiry_key], "2026-11-11T07:04:04Z")
            self.assertEqual(current[expiry_key], "2026-11-12T07:04:04Z")
            self.assertNotEqual(current["authorization_id"], previous["authorization_id"])
        self.assertEqual(proposal["status"], "PROPOSED_NOT_APPROVED_NOT_ACTIVE")
        self.assertFalse(proposal["activation_authorized"])

    def test_gitleaks_rebind_changes_only_exact_reviewed_hash_and_head(self):
        proposal = json.loads((ROOT / "operations/fieldzilla-pr712-gitleaks-head-issuance/proposal.json").read_text())
        current = copy.deepcopy(proposal["baseline"])
        previous = copy.deepcopy(proposal["previous_baseline"])
        path = ".gitleaksignore"
        self.assertEqual(proposal["changed_application_paths"], [path])
        self.assertEqual(current["source_overlay"]["paths"][path]["candidate_sha256"],
                         "df13693a489e9d5b778571a8973e89633acc79029f6154ea30f785afa6a98c77")
        self.assertNotEqual(current["source_overlay"]["paths"][path],
                            previous["source_overlay"]["paths"][path])
        current["source_overlay"]["paths"][path] = previous["source_overlay"]["paths"][path]
        for key in ("expected_head_sha", "issued_at", "authorization_id", "required_pr_body_marker", "purpose"):
            current[key] = previous[key]
        self.assertEqual(current, previous)
        current_sql = copy.deepcopy(proposal["sql"])
        previous_sql = proposal["previous_sql"]
        for key in ("expected_head_sha", "issued_at", "authorization_id", "purpose"):
            current_sql[key] = previous_sql[key]
        self.assertEqual(current_sql, previous_sql)
        self.assertFalse(proposal["activation_authorized"])
