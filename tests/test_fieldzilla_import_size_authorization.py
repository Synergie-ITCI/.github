"""The initial import decision is exact, bounded, and changes no defaults."""
import copy
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "9c2e9c85c0103e9c477eda211d305c52355b61a5"
REVIEWED = "c60ca7a7288e09713786aaf2422c06893f5a686d"
FAILED_PHASE_ONE = "02a48b243a111da79b740e254b77124384668458"
PRE_RUFF_REBIND = "c4cf19b96a7672cef86dc2773b242b8982592cef"
PRE_MOBILE_REBIND = "eda726eabd4a207fbd88a64099be49f8a95a9d02"
PRE_AUDIT_TEST_REBIND = "06b87aed06be8552d01338196015f68c5b144b82"
PRE_FINAL_AUDIT_BINDING = "070c81425ac3fded481958e7ca74ed2a00c63fb1"
PROPOSAL = ROOT / "operations/fieldzilla-pr712-historical-final-review/proposal.json"


class FieldzillaImportSizeTests(unittest.TestCase):
    def test_historical_review_changes_only_exact_fieldzilla_record(self):
        current = json.loads(subprocess.check_output(
            ["git", "show", f"{REVIEWED}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
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

    def test_phase_one_accounting_correction_preserves_exact_review(self):
        reviewed = json.loads(subprocess.check_output(
            ["git", "show", f"{REVIEWED}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        current = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_RUFF_REBIND}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        old = next(row for row in reviewed["one_time_baseline_alignments"]
                   if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        new = next(row for row in current["one_time_baseline_alignments"]
                   if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        self.assertEqual((old["minimum_changed_files"], old["allowed_changed_files"]), (905, 905))
        self.assertEqual((new["minimum_changed_files"], new["allowed_changed_files"]), (846, 846))
        self.assertEqual(new["allowed_effective_additions"], 149054)
        source_present = {
            ".github/CODEOWNERS",
            ".github/workflows/architecture-governance.yml",
            ".github/workflows/pr-qa.yml",
            "apps/api/tests/architecture/test_p0a_domain_contracts.py",
        }
        for path in source_present:
            self.assertEqual(old["source_overlay"]["paths"][path]["source"], "present")
            self.assertEqual(new["source_overlay"]["paths"][path]["source"], "present")
        normalized = copy.deepcopy(new)
        normalized["minimum_changed_files"] = 905
        normalized["allowed_changed_files"] = 905
        self.assertEqual(normalized, old)
        current["one_time_baseline_alignments"] = reviewed["one_time_baseline_alignments"]
        self.assertEqual(current, reviewed)

        failed = json.loads(subprocess.check_output(
            ["git", "show", f"{FAILED_PHASE_ONE}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        failed_row = next(row for row in failed["one_time_baseline_alignments"]
                          if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        for path in source_present:
            self.assertEqual(failed_row["source_overlay"]["paths"][path]["source"], "absent")
            failed_row["source_overlay"]["paths"][path]["source"] = "present"
        self.assertEqual(failed_row, new)

    def test_ruff_rebind_changes_only_exact_head_and_three_reviewed_hashes(self):
        previous = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_RUFF_REBIND}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        current = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_MOBILE_REBIND}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        old = next(row for row in previous["one_time_baseline_alignments"]
                   if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        new = next(row for row in current["one_time_baseline_alignments"]
                   if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        self.assertEqual((new["expected_head_sha"], new["expected_base_sha"]),
                         ("56e565b6e4c729ce139e4f88243a03db6674bab3",
                          "8ae3caaa067b3698713e514e1a834412781a93dc"))
        self.assertEqual((new["allowed_changed_files"], new["minimum_changed_files"],
                          new["allowed_effective_additions"]), (846, 846, 149054))
        self.assertEqual(new["source_overlay"]["paths"]["apps/api/scripts/production_historical_migrate.py"]["candidate_sha256"],
                         "a24c1a33733de79de72aa4d1b9edda0edf491ac192f4f7a64d8271f573df079f")
        self.assertEqual(new["source_overlay"]["paths"]["apps/api/tests/architecture/test_production_historical_migrate.py"]["candidate_sha256"],
                         "a622292b9650c8040baef2ba2b71cb2fda8bfa506b50c712555c42c54c4aed6c")
        self.assertEqual(new["source_overlay"]["paths"]["apps/api/tests/architecture/test_production_application_plan.py"]["candidate_sha256"],
                         "a5789126f1a08eb7bd52d15de61b5a4a8645f264d2a92d7d2e8708ef9040682f")
        self.assertEqual(new["expires_after"], old["expires_after"])
        normalized = copy.deepcopy(new)
        for field in ("expected_head_sha", "authorization_id", "required_pr_body_marker", "purpose"):
            normalized[field] = old[field]
        for path in (
            "apps/api/scripts/production_historical_migrate.py",
            "apps/api/tests/architecture/test_production_historical_migrate.py",
            "apps/api/tests/architecture/test_production_application_plan.py",
        ):
            normalized["source_overlay"]["paths"][path] = old["source_overlay"]["paths"][path]
        self.assertEqual(normalized, old)
        current["one_time_baseline_alignments"] = previous["one_time_baseline_alignments"]
        self.assertEqual(current, previous)

    def test_mobile_expiry_rebind_changes_only_head_and_approved_baseline_hash(self):
        previous = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_MOBILE_REBIND}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        current = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_AUDIT_TEST_REBIND}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        old = next(row for row in previous["one_time_baseline_alignments"]
                   if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        new = next(row for row in current["one_time_baseline_alignments"]
                   if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        self.assertEqual((new["expected_head_sha"], new["expected_base_sha"]),
                         ("ebc473f6a169c3dd35dc534fb9e5b5ad7140d484",
                          "8ae3caaa067b3698713e514e1a834412781a93dc"))
        self.assertEqual((new["allowed_changed_files"], new["minimum_changed_files"],
                          new["allowed_effective_additions"]), (846, 846, 149054))
        path = "apps/mobile/security/mobile-audit-baseline.json"
        self.assertEqual(new["source_overlay"]["paths"][path]["candidate_sha256"],
                         "43e47805c5008b5699cd879f2ab5b4290a5721c3904d5422208d18dd63187037")
        self.assertEqual(new["expires_after"], old["expires_after"])
        normalized = copy.deepcopy(new)
        for field in ("expected_head_sha", "authorization_id", "required_pr_body_marker", "purpose"):
            normalized[field] = old[field]
        normalized["source_overlay"]["paths"][path] = old["source_overlay"]["paths"][path]
        self.assertEqual(normalized, old)
        current["one_time_baseline_alignments"] = previous["one_time_baseline_alignments"]
        self.assertEqual(current, previous)

        old_sql = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_MOBILE_REBIND}:policy/audited-migration-authorizations.json"], cwd=ROOT,
        ))
        new_sql = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_AUDIT_TEST_REBIND}:policy/audited-migration-authorizations.json"], cwd=ROOT,
        ))
        old_row = next(row for row in old_sql if row.get("pr_number") == 712)
        new_row = next(row for row in new_sql if row.get("pr_number") == 712)
        self.assertEqual(new_row["expected_head_sha"], "ebc473f6a169c3dd35dc534fb9e5b5ad7140d484")
        normalized_sql = copy.deepcopy(new_row)
        for field in ("expected_head_sha", "authorization_id", "purpose"):
            normalized_sql[field] = old_row[field]
        self.assertEqual(normalized_sql, old_row)
        new_sql[new_sql.index(new_row)] = old_row
        self.assertEqual(new_sql, old_sql)

    def test_audit_test_hash_rebind_changes_only_exact_fieldzilla_review(self):
        previous = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_AUDIT_TEST_REBIND}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        current = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_FINAL_AUDIT_BINDING}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        old = next(row for row in previous["one_time_baseline_alignments"]
                   if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        new = next(row for row in current["one_time_baseline_alignments"]
                   if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        self.assertEqual(new["expected_head_sha"], "89bff181006c7fa06da54839e1b23dbed91a005c")
        self.assertEqual(new["expected_base_sha"], old["expected_base_sha"])
        path = "apps/api/tests/architecture/test_mobile_audit_baseline.py"
        self.assertEqual(new["source_overlay"]["paths"][path]["candidate_sha256"],
                         "cd12274f813f3804e78bda293c25ca7ad0f2ea52b4b1e32f5d333eb1806787f6")
        self.assertEqual(new["expires_after"], old["expires_after"])
        normalized = copy.deepcopy(new)
        for field in ("expected_head_sha", "authorization_id", "required_pr_body_marker", "purpose"):
            normalized[field] = old[field]
        normalized["source_overlay"]["paths"][path] = old["source_overlay"]["paths"][path]
        self.assertEqual(normalized, old)
        current["one_time_baseline_alignments"] = previous["one_time_baseline_alignments"]
        self.assertEqual(current, previous)

        previous_sql = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_AUDIT_TEST_REBIND}:policy/audited-migration-authorizations.json"], cwd=ROOT,
        ))
        current_sql = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_FINAL_AUDIT_BINDING}:policy/audited-migration-authorizations.json"], cwd=ROOT,
        ))
        old_sql = next(row for row in previous_sql if row.get("pr_number") == 712)
        new_sql = next(row for row in current_sql if row.get("pr_number") == 712)
        self.assertEqual(new_sql["expected_head_sha"], new["expected_head_sha"])
        normalized_sql = copy.deepcopy(new_sql)
        for field in ("expected_head_sha", "authorization_id", "purpose"):
            normalized_sql[field] = old_sql[field]
        self.assertEqual(normalized_sql, old_sql)
        current_sql[current_sql.index(new_sql)] = old_sql
        self.assertEqual(current_sql, previous_sql)

    def test_final_audit_expiry_test_binding_changes_only_exact_fieldzilla_review(self):
        previous = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_FINAL_AUDIT_BINDING}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        current = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        old = next(row for row in previous["one_time_baseline_alignments"]
                   if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        new = next(row for row in current["one_time_baseline_alignments"]
                   if row.get("repository_id") == 1315697868 and row.get("pr_number") == 712)
        self.assertEqual((new["expected_head_sha"], new["expected_base_sha"]),
                         ("973bee62d487f4b5c1bd58b269e0a358492fd5bf", old["expected_base_sha"]))
        path = "apps/api/tests/architecture/test_mobile_audit_baseline.py"
        self.assertEqual(new["source_overlay"]["paths"][path]["candidate_sha256"],
                         "2f9a220e41811a0cd648ce22fae80401eee1d8158f24781bfed3b708c752df2f")
        self.assertEqual((new["allowed_changed_files"], new["minimum_changed_files"],
                          new["allowed_effective_additions"], new["expires_after"]),
                         (846, 846, 149054, old["expires_after"]))
        normalized = copy.deepcopy(new)
        for field in ("expected_head_sha", "authorization_id", "required_pr_body_marker", "purpose"):
            normalized[field] = old[field]
        normalized["source_overlay"]["paths"][path] = old["source_overlay"]["paths"][path]
        self.assertEqual(normalized, old)
        current["one_time_baseline_alignments"] = previous["one_time_baseline_alignments"]
        self.assertEqual(current, previous)

        previous_sql = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_FINAL_AUDIT_BINDING}:policy/audited-migration-authorizations.json"], cwd=ROOT,
        ))
        current_sql = json.loads((ROOT / "policy/audited-migration-authorizations.json").read_text())
        old_sql = next(row for row in previous_sql if row.get("pr_number") == 712)
        new_sql = next(row for row in current_sql if row.get("pr_number") == 712)
        self.assertEqual(new_sql["expected_head_sha"], new["expected_head_sha"])
        normalized_sql = copy.deepcopy(new_sql)
        for field in ("expected_head_sha", "authorization_id", "purpose"):
            normalized_sql[field] = old_sql[field]
        self.assertEqual(normalized_sql, old_sql)
        current_sql[current_sql.index(new_sql)] = old_sql
        self.assertEqual(current_sql, previous_sql)

    def test_historical_sql_review_preserves_audited_bytes_and_reviewer(self):
        proposed = json.loads(PROPOSAL.read_text())
        current = json.loads(subprocess.check_output(
            ["git", "show", f"{PRE_RUFF_REBIND}:policy/audited-migration-authorizations.json"], cwd=ROOT,
        ))
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
