"""The initial import decision is exact, bounded, and changes no defaults."""
import copy
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "63af59f396d4e99e1680f5928b3943d165141e14"
PROPOSAL = ROOT / "operations/fieldzilla-pr712-gitleaks-rebind/proposal.json"


class FieldzillaImportSizeTests(unittest.TestCase):
    def test_only_one_exact_record_changes_and_defaults_are_preserved(self):
        current = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        prior = json.loads(subprocess.check_output(
            ["git", "show", f"{SOURCE}:policy/pr-qa-policy.json"], cwd=ROOT,
        ))
        proposed = json.loads(PROPOSAL.read_text())
        rows = current["one_time_baseline_alignments"]
        new = [r for r in rows if r.get("repository_id") == 1315697868 and r.get("pr_number") == 712]
        self.assertEqual(new, [proposed["baseline"]])
        normalized = copy.deepcopy(current)
        i = normalized["one_time_baseline_alignments"].index(new[0])
        normalized["one_time_baseline_alignments"][i] = proposed["previous_baseline"]
        scholarships = [row for row in normalized["one_time_baseline_alignments"]
                        if row.get("repository") == "Synergie-ITCI/scholarships"
                        and row.get("pr_number") == 7]
        self.assertEqual(len(scholarships), 1)
        self.assertEqual(scholarships[0]["expected_head_sha"],
                         "1379352d5ef26cc7e867e52185315083ec63eebe")
        self.assertEqual(scholarships[0]["expires_after"], "2026-11-13T05:01:28Z")
        prior_scholarships = [row for row in prior["one_time_baseline_alignments"]
                              if row.get("repository") == "Synergie-ITCI/scholarships"
                              and row.get("pr_number") == 7]
        self.assertEqual(len(prior_scholarships), 1)
        scholarships[0]["expires_after"] = prior_scholarships[0]["expires_after"]
        self.assertEqual(normalized, prior)
        self.assertEqual(new[0]["expected_head_sha"], "4871f7e5c947cdf84feaae025b38182a0886b5c9")
        self.assertEqual(new[0]["expected_base_sha"], "28cb6e7c8941e4c93365270b0dc1821ed8978b4f")
        self.assertEqual(new[0]["relaxations"], ["changed_file_count", "diff_size"])
        self.assertEqual(new[0]["allowed_effective_additions"], 148858)
        self.assertEqual(new[0]["allowed_changed_files"], 844)
        self.assertEqual(new[0]["minimum_changed_files"], 844)
        self.assertEqual(new[0]["expires_after"], "2026-11-13T05:05:32Z")
        self.assertEqual(len(new[0]["source_overlay"]["paths"]), 45)
        changed = {
            path for path, value in new[0]["source_overlay"]["paths"].items()
            if value != proposed["previous_baseline"]["source_overlay"]["paths"][path]
        }
        self.assertEqual(changed, {"apps/api/tests/architecture/test_mobile_audit_baseline.py", ".gitleaksignore"})
        self.assertEqual(
            new[0]["source_overlay"]["paths"][".gitleaksignore"]["candidate_sha256"],
            "a89dc590daa191a5d34c36f0701628e01695fe4c37ee35c0f0eeebc8fa572b7f",
        )
        self.assertEqual(
            new[0]["source_overlay"]["paths"]["apps/api/tests/architecture/test_mobile_audit_baseline.py"]["candidate_sha256"],
            "3e6445f4c5a9f3a5d44245b15fde7b762caab8bd600be645765f03318fd2ef4f",
        )

    def test_sql_rebind_preserves_all_reviewed_bytes_and_reviewer(self):
        p = json.loads(PROPOSAL.read_text())
        current = json.loads((ROOT / "policy/audited-migration-authorizations.json").read_text())
        prior = json.loads(subprocess.check_output(
            ["git", "show", f"{SOURCE}:policy/audited-migration-authorizations.json"], cwd=ROOT,
        ))
        normalized = copy.deepcopy(current)
        normalized[normalized.index(p["sql"])] = p["previous_sql"]
        self.assertEqual(normalized, prior)
        for key in ("migration_path", "migration_sha256", "delete_fingerprints", "approved_reviewer"):
            self.assertEqual(p["sql"][key], p["previous_sql"][key])
        self.assertEqual(p["status"], "PROPOSED_NOT_APPROVED_NOT_ACTIVE")


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
