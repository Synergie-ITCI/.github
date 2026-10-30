import os
import json
import hashlib
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release-preflight"
preflight = SourceFileLoader("release_preflight", str(SCRIPT)).load_module()


class ReleasePreflightTests(unittest.TestCase):
    def test_rc217_disposition_requires_exact_inherited_evidence(self):
        decisions = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())[
            "release_preflight_dispositions"]
        reviewed = decisions["pr-qa-v1-rc217"]["reviewed_commits"]
        approved = decisions["inherited_synthetic_fixtures"]["synthetic_fixture_findings"][:6]
        candidate = "a" * 40
        workflow = ".github/workflows/roadsense-controlled-release.yml"
        report = {"summary": {"overall_result": "FAIL"}, "results": [
            {"gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
             "message": "Accidental merge commits detected.",
             "details": [candidate, *reversed(reviewed)]},
            {"gate": "Secrets", "status": "FAIL", "blocking": True,
             "details": [f"{item['path']}: {item['label']}. line_sha256={item['line_sha256']}"
                         for item in approved]},
            {"gate": "Deployment Risk", "status": "FAIL", "blocking": True,
             "message": "Deployment workflow is structurally unsafe or missing required controlled-release safeguards.",
             "details": [f"{workflow}: production/live deployment-sensitive workflow does not match the controlled Gate D safe shape."]},
        ]}

        def fake_git(args, _root):
            values = {
                ("remote", "get-url", "origin"): preflight.CENTRAL_ORIGIN + "\n",
                ("rev-parse", "HEAD"): candidate + "\n",
                ("rev-parse", "refs/remotes/origin/main"): candidate + "\n",
                ("rev-list", "--first-parent", "--merges", "pr-qa-v1-rc216..HEAD"):
                    "\n".join([candidate, *reversed(reviewed)]) + "\n",
                ("diff", "--name-only", "HEAD^1..HEAD"):
                    "policy/pr-qa-policy.json\nscripts/release-preflight\ntests/test_release_preflight.py\n",
            }
            if tuple(args) in values:
                return subprocess.CompletedProcess(args, 0, values[tuple(args)], "")
            if args == ["show", "pr-qa-v1-rc216:tests/test_pr_qa_regressions.py"]:
                return subprocess.CompletedProcess(args, 0,
                    (ROOT / "tests/test_pr_qa_regressions.py").read_text(), "")
            if args == ["show", f"roadsense-gate-d-v10:{workflow}"]:
                return subprocess.CompletedProcess(args, 0, (ROOT / workflow).read_text(), "")
            return subprocess.CompletedProcess(args, 1, "", "unexpected git command")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sys.path.insert(0, str(ROOT / "pr-qa"))
            for relative in ("policy/pr-qa-policy.json", "tests/test_pr_qa_regressions.py", workflow):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / relative).read_bytes())
            report_path = root / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), \
                 patch("pr_qa.approved_roadsense_gate_d_release", return_value=True):
                report_path.write_text(json.dumps(report))
                self.assertTrue(preflight.reviewed_rc217_disposition(
                    root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))
                self.assertFalse(preflight.reviewed_rc217_disposition(
                    root, report_path, "development", "pr-qa-v1-rc216", [*reviewed, candidate]))
                self.assertFalse(preflight.reviewed_rc217_disposition(
                    root, report_path, "main", "pr-qa-v1-rc216", reviewed))
                with patch("pr_qa.approved_roadsense_gate_d_release", return_value=False):
                    self.assertFalse(preflight.reviewed_rc217_disposition(
                        root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))
                report["results"][1]["details"][0] = "tests/test_pr_qa_regressions.py: GitHub token. line_sha256=" + "0" * 64
                report_path.write_text(json.dumps(report))
                self.assertFalse(preflight.reviewed_rc217_disposition(
                    root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))
                report["results"][1]["details"][0] = (
                    f"{approved[0]['path']}: {approved[0]['label']}. line_sha256={approved[0]['line_sha256']}")
                report["results"].append({"gate": "Architecture", "status": "FAIL", "blocking": True})
                report_path.write_text(json.dumps(report))
                self.assertFalse(preflight.reviewed_rc217_disposition(
                    root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))
                report["results"].pop()
                report_path.write_text(json.dumps(report))
                for other_release in ("pr-qa-v1-rc215", "pr-qa-v1-rc217"):
                    self.assertFalse(preflight.reviewed_rc217_disposition(
                        root, report_path, "main", other_release, [*reviewed, candidate]))
                with patch.object(preflight, "git", side_effect=lambda args, repo: (
                    subprocess.CompletedProcess(args, 0, "https://github.com/OtherOrg/.github.git\n", "")
                    if args == ["remote", "get-url", "origin"] else fake_git(args, repo))):
                    self.assertFalse(preflight.reviewed_rc217_disposition(
                        root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))
                with patch.object(preflight, "git", side_effect=lambda args, repo: (
                    subprocess.CompletedProcess(args, 0, "\n".join(reversed(reviewed)) + "\n", "")
                    if args == ["rev-list", "--first-parent", "--merges", "pr-qa-v1-rc216..HEAD"]
                    else fake_git(args, repo))):
                    self.assertFalse(preflight.reviewed_rc217_disposition(
                        root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))
                with patch.object(preflight, "git", side_effect=lambda args, repo: (
                    subprocess.CompletedProcess(args, 1, "", "tag unavailable")
                    if args == ["show", f"roadsense-gate-d-v10:{workflow}"]
                    else fake_git(args, repo))):
                    self.assertFalse(preflight.reviewed_rc217_disposition(
                        root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))
                workflow_path = root / workflow
                original_workflow = workflow_path.read_bytes()
                workflow_path.write_bytes(original_workflow + b"\n# changed\n")
                self.assertFalse(preflight.reviewed_rc217_disposition(
                    root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))
                workflow_path.write_bytes(original_workflow)
                report["results"][1]["details"].append("tests/new.py: GitHub token. line_sha256=" + "f" * 64)
                report_path.write_text(json.dumps(report))
                self.assertFalse(preflight.reviewed_rc217_disposition(
                    root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))
                report["results"][1]["details"].pop()
                report["results"].append({"gate": "Tests", "status": "FAIL", "message": "Failed."})
                report_path.write_text(json.dumps(report))
                self.assertFalse(preflight.reviewed_rc217_disposition(
                    root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))
                report["results"].pop()
                report["summary"].pop("overall_result")
                report_path.write_text(json.dumps(report))
                self.assertFalse(preflight.reviewed_rc217_disposition(
                    root, report_path, "main", "pr-qa-v1-rc216", [*reviewed, candidate]))

    def test_generic_protected_merge_disposition_accepts_only_exact_hygiene_noise(self):
        newest, older = (letter * 40 for letter in "ab")
        report = {"results": [{"gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
                               "message": "Accidental merge commits detected.",
                               "details": [newest, older]}]}
        merges = subprocess.CompletedProcess([], 0, f"{newest}\n{older}\n", "")
        with tempfile.TemporaryDirectory() as temp, patch.object(preflight, "git", return_value=merges):
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(report))
            self.assertTrue(preflight.protected_merge_hygiene_disposition(
                ROOT, path, "main", "pr-qa-v1-rc215", [older, newest]))
            self.assertFalse(preflight.protected_merge_hygiene_disposition(
                ROOT, path, "development", "pr-qa-v1-rc215", [older, newest]))
            self.assertFalse(preflight.protected_merge_hygiene_disposition(
                ROOT, path, "main", "pr-qa-v1-rc215", None))
            report["results"][0]["details"] = [newest]
            path.write_text(json.dumps(report))
            self.assertFalse(preflight.protected_merge_hygiene_disposition(
                ROOT, path, "main", "pr-qa-v1-rc215", [older, newest]))
            report["results"][0]["details"] = [newest, older]
            report["results"].append({"gate": "Secrets", "status": "FAIL", "blocking": True})
            path.write_text(json.dumps(report))
            self.assertFalse(preflight.protected_merge_hygiene_disposition(
                ROOT, path, "main", "pr-qa-v1-rc215", [older, newest]))

    def test_compatibility_deferral_requires_bound_release_and_reports_pending(self):
        sha = "a" * 40
        for args in (["release-preflight", "--base", "main", "--compatibility-via-provenance"],
                     ["release-preflight", "--base", "staging", "--verified-release", "pr-qa-v1-rc215",
                      "--verified-commit", sha, "--compatibility-via-provenance"]):
            with self.subTest(args=args), patch.object(sys, "argv", args), self.assertRaises(SystemExit):
                preflight.main()
        output = __import__("io").StringIO()
        with patch("sys.stdout", output):
            preflight.print_report("pr-qa-v1-rc215", "main", "CLEAN", "PASS",
                                   "DEFERRED_TO_EXACT_SOURCE_PROVENANCE", [])
        self.assertIn("READY_FOR_PROMOTION: PENDING_PROVENANCE", output.getvalue())

    def test_rc215_disposition_is_limited_to_reviewed_v9_lineage_and_two_findings(self):
        decision = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())[
            "release_preflight_dispositions"]["pr-qa-v1-rc215"]
        reviewed = decision["reviewed_commits"]
        candidate, correction_head, tree = (letter * 40 for letter in "xyz")
        report = {"results": [
            {"gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
             "message": "Accidental merge commits detected.",
             "details": [candidate, *reversed(reviewed[1:])]},
            {"gate": "Deployment Risk", "status": "FAIL", "blocking": True,
             "message": "Deployment workflow is structurally unsafe or missing required controlled-release safeguards.",
             "details": [f"{path}: production/live deployment-sensitive workflow does not match the controlled Gate D safe shape."
                         for path in decision["workflow_sha256"]]},
        ]}

        def fake_git(args, _root):
            if args == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN + "\n"
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = candidate + "\n"
            elif args == ["rev-list", "--reverse", "--first-parent", "pr-qa-v1-rc214..HEAD"]:
                value = "\n".join([*reviewed, candidate]) + "\n"
            elif args == ["rev-list", "--reverse", "--first-parent", "--merges", "pr-qa-v1-rc214..HEAD"]:
                value = "\n".join([*reviewed[1:], candidate]) + "\n"
            elif args == ["log", "-1", "--format=%B"]:
                value = "Merge pull request #420 from Synergie-ITCI/feature/roadsense-scoped-publication-gate\n"
            elif args == ["rev-parse", "HEAD^2"]:
                value = correction_head + "\n"
            elif args in (["rev-parse", f"{correction_head}^{{tree}}"], ["rev-parse", "HEAD^{tree}"]):
                value = tree + "\n"
            elif args == ["diff", "--name-only", "HEAD^1..HEAD"]:
                value = "policy/pr-qa-policy.json\nscripts/release-preflight\ntests/test_release_preflight.py\n"
            elif len(args) == 2 and args[0] == "show" and args[1].startswith("roadsense-gate-d-v9:"):
                historical = subprocess.run(
                    ["git", "show", args[1]], cwd=ROOT, capture_output=True, text=True, check=True)
                value = historical.stdout
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git command")
            return subprocess.CompletedProcess(args, 0, value, "")

        def fake_run(args, _root):
            number = int(args[-1].rsplit("/", 1)[-1])
            metadata = {"merged_at": "2026-10-27T00:00:00Z",
                        "merge_commit_sha": (candidate if number == 420 else
                                              reviewed[decision["reviewed_prs"].index(number)]),
                        "base": {"ref": "main"},
                        "head": {"sha": correction_head},
                        "title": "Pin rc215 preflight to reviewed RoadSense v9 controls"}
            return subprocess.CompletedProcess(args, 0, json.dumps(metadata), "")

        with tempfile.TemporaryDirectory() as temp:
            fixture_root = Path(temp)
            policy_path = fixture_root / "policy/pr-qa-policy.json"
            policy_path.parent.mkdir(parents=True)
            policy_path.write_bytes((ROOT / "policy/pr-qa-policy.json").read_bytes())
            for workflow_path in decision["workflow_sha256"]:
                historical = subprocess.run(
                    ["git", "show", f"roadsense-gate-d-v9:{workflow_path}"],
                    cwd=ROOT, capture_output=True, check=True)
                destination = fixture_root / workflow_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(historical.stdout)
            path = fixture_root / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), patch.object(preflight, "run", side_effect=fake_run):
                path.write_text(json.dumps(report))
                self.assertTrue(preflight.reviewed_rc215_road_sense_disposition(
                    fixture_root, path, "main", "pr-qa-v1-rc214"))
                report["results"].append({"gate": "Secrets", "status": "FAIL", "blocking": True})
                path.write_text(json.dumps(report))
                self.assertFalse(preflight.reviewed_rc215_road_sense_disposition(
                    fixture_root, path, "main", "pr-qa-v1-rc214"))

    def test_rc211_disposition_accepts_only_reviewed_merge_and_no_other_failure(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc211"]
        candidate, correction_head, tree = (letter * 40 for letter in "xyz")
        merge = reviewed["reviewed_policy_merge"]
        report = {"results": [{
            "gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
            "message": "Accidental merge commits detected.", "details": [candidate, merge],
        }]}

        def fake_git(args, _root):
            if args == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN + "\n"
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = candidate + "\n"
            elif args == ["rev-list", "--reverse", "--first-parent", "--merges", "pr-qa-v1-rc210..HEAD"]:
                value = merge + "\n" + candidate + "\n"
            elif args == ["diff", "--name-only", "pr-qa-v1-rc210..HEAD"]:
                value = "policy/pr-qa-policy.json\nscripts/release-preflight\ntests/test_release_preflight.py\n"
            elif args in (["rev-parse", f"{correction_head}^{{tree}}"], ["rev-parse", "HEAD^{tree}"]):
                value = tree + "\n"
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value, "")

        def fake_run(args, _root):
            number = int(args[-1].rsplit("/", 1)[-1])
            sha = merge if number == 407 else candidate
            head = reviewed["reviewed_policy_head"] if number == 407 else correction_head
            metadata = {"merged_at": "2026-10-25T17:00:00Z", "merge_commit_sha": sha,
                        "head": {"sha": head}, "base": {"ref": "main"}}
            return subprocess.CompletedProcess(args, 0, json.dumps(metadata), "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), patch.object(preflight, "run", side_effect=fake_run):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc211_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc210"))
                self.assertFalse(preflight.reviewed_rc211_lineage_disposition(ROOT, path, "development", "pr-qa-v1-rc210"))
                report["results"][0]["details"].append("q" * 40)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc211_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc210"))
                report["results"][0]["details"].pop()
                report["results"].append({"gate": "Secrets", "status": "FAIL", "blocking": True})
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc211_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc210"))

    def test_rc213_disposition_accepts_only_reviewed_merge_and_no_other_failure(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc213"]
        candidate, correction_head, tree = (letter * 40 for letter in "xyz")
        merge = reviewed["reviewed_policy_merge"]
        report = {"results": [{
            "gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
            "message": "Accidental merge commits detected.", "details": [candidate, merge],
        }]}

        def fake_git(args, _root):
            if args == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN + "\n"
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = candidate + "\n"
            elif args == ["rev-list", "--reverse", "--first-parent", "--merges", "pr-qa-v1-rc212..HEAD"]:
                value = merge + "\n" + candidate + "\n"
            elif args == ["diff", "--name-only", "pr-qa-v1-rc212..HEAD"]:
                value = "policy/pr-qa-policy.json\nscripts/release-preflight\ntests/test_release_preflight.py\n"
            elif args in (["rev-parse", f"{correction_head}^{{tree}}"], ["rev-parse", "HEAD^{tree}"]):
                value = tree + "\n"
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value, "")

        def fake_run(args, _root):
            number = int(args[-1].rsplit("/", 1)[-1])
            sha = merge if number == 411 else candidate
            head = reviewed["reviewed_policy_head"] if number == 411 else correction_head
            metadata = {"merged_at": "2026-10-25T17:00:00Z", "merge_commit_sha": sha,
                        "head": {"sha": head}, "base": {"ref": "main"}}
            return subprocess.CompletedProcess(args, 0, json.dumps(metadata), "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), patch.object(preflight, "run", side_effect=fake_run):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc213_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc212"))
                self.assertFalse(preflight.reviewed_rc213_lineage_disposition(ROOT, path, "development", "pr-qa-v1-rc212"))
                report["results"][0]["details"].append("q" * 40)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc213_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc212"))
                report["results"][0]["details"].pop()
                report["results"].append({"gate": "Secrets", "status": "FAIL", "blocking": True})
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc213_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc212"))
    def test_rc214_disposition_accepts_only_reviewed_merge_and_no_other_failure(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc214"]
        candidate, correction_merge = (letter * 40 for letter in "ab")
        merge = reviewed["reviewed_policy_merge"]
        lineage = [merge, correction_merge]
        report = {"results": [{
            "gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
            "message": "Accidental merge commits detected.", "details": [correction_merge, merge],
        }]}

        def fake_git(args, _root):
            if args == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN + "\n"
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = candidate + "\n"
            elif args == ["rev-list", "--reverse", "--first-parent", "--merges", "pr-qa-v1-rc213..HEAD"]:
                value = "\n".join(lineage) + "\n"
            elif args == ["diff", "--name-only", "pr-qa-v1-rc213..HEAD"]:
                value = "policy/pr-qa-policy.json\nscripts/release-preflight\npr-qa/pr_qa.py\npr-qa/adapters/base.py\ntests/test_release_preflight.py\n"
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value, "")

        def fake_run(args, _root):
            number = int(args[-1].rsplit("/", 1)[-1])
            sha = merge if number == 413 else correction_merge
            head = reviewed["reviewed_policy_head"] if number == 413 else "z" * 40
            metadata = {"merged_at": "2026-10-25T17:00:00Z", "merge_commit_sha": sha,
                        "head": {"sha": head}, "base": {"ref": "main"}}
            return subprocess.CompletedProcess(args, 0, json.dumps(metadata), "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), patch.object(preflight, "run", side_effect=fake_run):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc214_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc213"))
                self.assertFalse(preflight.reviewed_rc214_lineage_disposition(ROOT, path, "development", "pr-qa-v1-rc213"))
                lineage.insert(1, "q" * 40)
                self.assertFalse(preflight.reviewed_rc214_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc213"))
                lineage.pop(1)
                report["results"][0]["details"].append("q" * 40)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc214_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc213"))
                report["results"][0]["details"].pop()
                report["results"].append({"gate": "Secrets", "status": "FAIL", "blocking": True})
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc214_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc213"))


    def test_rc212_disposition_accepts_only_reviewed_merge_and_no_other_failure(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc212"]
        candidate, correction_head, tree = (letter * 40 for letter in "xyz")
        merge = reviewed["reviewed_policy_merge"]
        report = {"results": [{
            "gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
            "message": "Accidental merge commits detected.", "details": [candidate, merge],
        }]}

        def fake_git(args, _root):
            if args == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN + "\n"
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = candidate + "\n"
            elif args == ["rev-list", "--reverse", "--first-parent", "--merges", "pr-qa-v1-rc211..HEAD"]:
                value = merge + "\n" + candidate + "\n"
            elif args == ["diff", "--name-only", "pr-qa-v1-rc211..HEAD"]:
                value = "policy/pr-qa-policy.json\nscripts/release-preflight\ntests/test_release_preflight.py\n"
            elif args in (["rev-parse", f"{correction_head}^{{tree}}"], ["rev-parse", "HEAD^{tree}"]):
                value = tree + "\n"
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value, "")

        def fake_run(args, _root):
            number = int(args[-1].rsplit("/", 1)[-1])
            sha = merge if number == 409 else candidate
            head = reviewed["reviewed_policy_head"] if number == 409 else correction_head
            metadata = {"merged_at": "2026-10-25T17:00:00Z", "merge_commit_sha": sha,
                        "head": {"sha": head}, "base": {"ref": "main"}}
            return subprocess.CompletedProcess(args, 0, json.dumps(metadata), "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), patch.object(preflight, "run", side_effect=fake_run):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc212_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc211"))
                self.assertFalse(preflight.reviewed_rc212_lineage_disposition(ROOT, path, "development", "pr-qa-v1-rc211"))
                report["results"][0]["details"].append("q" * 40)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc212_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc211"))
                report["results"][0]["details"].pop()
                report["results"].append({"gate": "Secrets", "status": "FAIL", "blocking": True})
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc212_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc211"))

    def test_rc210_disposition_accepts_only_reviewed_lineage_and_workflow(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc210"]
        candidate, pr_head, tree = (letter * 40 for letter in "xyz")
        merges = reviewed["reviewed_predecessor_merges"]
        report = {"results": [
            {"gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
             "message": "Accidental merge commits detected.",
             "details": [candidate, *reversed(merges[1:])]},
            {"gate": "Deployment Risk", "status": "FAIL", "blocking": True,
             "message": "Deployment workflow is structurally unsafe or missing required controlled-release safeguards.",
             "details": [".github/workflows/roadsense-controlled-release.yml: production/live deployment-sensitive workflow does not match the controlled Gate D safe shape."]},
        ]}
        workflow = ".github/workflows/roadsense-controlled-release.yml"
        inherited = subprocess.check_output(["git", "show", f"pr-qa-v1-rc209:{workflow}"], cwd=ROOT, text=True)
        # This historical disposition must stop applying when the controlled
        # release workflow changes for Gate D v9.
        historical_workflow = hashlib.sha256((ROOT / workflow).read_bytes()).hexdigest() == reviewed["reviewed_workflow_sha256"]
        pr = {"merged_at": "2026-10-25T15:00:00Z", "merge_commit_sha": candidate,
              "head": {"sha": pr_head}, "base": {"ref": "main"}}

        def fake_git(args, _root):
            if args == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN + "\n"
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = candidate + "\n"
            elif args == ["rev-list", "--reverse", "--first-parent", "--merges", "pr-qa-v1-rc209..HEAD"]:
                value = "\n".join([*merges, candidate]) + "\n"
            elif args == ["show", f"pr-qa-v1-rc209:{workflow}"]:
                value = inherited
            elif args in (["rev-parse", f"{pr_head}^{{tree}}"], ["rev-parse", "HEAD^{tree}"]):
                value = tree + "\n"
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value, "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), \
                 patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(pr), "")):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertEqual(preflight.reviewed_rc210_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc209"), historical_workflow)
                self.assertFalse(preflight.reviewed_rc210_lineage_disposition(ROOT, path, "development", "pr-qa-v1-rc209"))
                self.assertFalse(preflight.reviewed_rc210_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc208"))
                report["results"][0]["details"] = [candidate, *reversed(merges[2:])]
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertEqual(preflight.reviewed_rc210_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc209"), historical_workflow)
                report["results"][0]["details"].append("q" * 40)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc210_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc209"))
                report["results"][0]["details"].pop()
                report["results"][1]["details"].append("unreviewed workflow")
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc210_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc209"))
                report["results"][1]["details"].pop()
                report["results"].append({"gate": "Secrets", "status": "FAIL", "blocking": True})
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc210_lineage_disposition(ROOT, path, "main", "pr-qa-v1-rc209"))

    def test_lineage_accepts_multiple_checked_pr_merges_and_rejects_unreviewed_changes(self):
        release, first, second, first_head, second_head = (letter * 40 for letter in "abcde")
        rules = [{"type": "pull_request"}, {"type": "required_status_checks", "parameters": {
            "required_status_checks": [{"context": "pr-qa / Pull Request Quality Assurance"}]}}]
        checks = lambda head: {"total_count": 2, "check_runs": [
            {"id": number, "name": name, "head_sha": head, "status": "completed",
             "conclusion": "success", "app": {"slug": "github-actions"}}
            for number, name in enumerate(("pr-qa / Pull Request Quality Assurance", "Architecture Governance"), 1)]}
        prs = {first: [{"number": 10, "merged_at": "2026-10-23T01:00:00Z", "merge_commit_sha": first,
                        "base": {"ref": "main"}, "head": {"sha": first_head}}],
               second: [{"number": 11, "merged_at": "2026-10-23T02:00:00Z", "merge_commit_sha": second,
                         "base": {"ref": "main"}, "head": {"sha": second_head}}]}
        parents = {first: f"{first} {release}", second: f"{second} {first}"}
        remote_main = [second]
        first_parent_history = [second, first, release]

        def fake_git(args, _root):
            if args == ["rev-parse", "HEAD"]:
                value = second
            elif args == ["rev-list", "--first-parent", remote_main[0]]:
                value = "\n".join(first_parent_history)
            elif args == ["merge-base", "pr-qa-v1-rc204", second]:
                value = release
            elif args == ["rev-parse", "pr-qa-v1-rc204^{commit}"]:
                value = release
            elif args == ["rev-list", "--reverse", "--first-parent", f"pr-qa-v1-rc204..{second}"]:
                value = f"{first}\n{second}"
            elif args[:3] == ["rev-list", "--parents", "-n"]:
                value = parents[args[-1]]
            elif args[:2] == ["rev-parse", f"{first_head}^{{tree}}"] or args[:2] == ["rev-parse", f"{first}^{{tree}}"]:
                value = "f" * 40
            elif args[:2] == ["rev-parse", f"{second_head}^{{tree}}"] or args[:2] == ["rev-parse", f"{second}^{{tree}}"]:
                value = "e" * 40
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value + "\n", "")

        def fake_api(args, _root):
            path = args[-1]
            if path.endswith("/git/ref/heads/main"):
                value = {"object": {"sha": remote_main[0]}}
            elif path.endswith("/rules/branches/main"):
                value = rules
            elif path.endswith(f"/commits/{first}/pulls"):
                value = prs[first]
            elif path.endswith(f"/commits/{second}/pulls"):
                value = prs[second]
            elif path.endswith(f"/commits/{first_head}/check-runs?per_page=100"):
                value = checks(first_head)
            elif path.endswith(f"/commits/{second_head}/check-runs?per_page=100"):
                value = checks(second_head)
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected API query")
            return subprocess.CompletedProcess(args, 0, json.dumps(value), "")

        with patch.object(preflight, "git", side_effect=fake_git), patch.object(preflight, "run", side_effect=fake_api):
            self.assertEqual(preflight.verify_central_lineage(ROOT, "pr-qa-v1-rc204", second), [first, second])
            remote_main[0] = "f" * 40
            first_parent_history.insert(0, remote_main[0])
            self.assertEqual(preflight.verify_central_lineage(ROOT, "pr-qa-v1-rc204", second), [first, second])
            first_parent_history.remove(second)
            with self.assertRaisesRegex(ValueError, "not on protected main first-parent"):
                preflight.verify_central_lineage(ROOT, "pr-qa-v1-rc204", second)
            first_parent_history.insert(1, second)
            parents[second] = f"{second} {first} {release}"
            with self.assertRaisesRegex(ValueError, "merge parent differs"):
                preflight.verify_central_lineage(ROOT, "pr-qa-v1-rc204", second)
            parents[second] = f"{second} {first}"
            prs[second] = []
            with self.assertRaisesRegex(ValueError, "no unique approved merged PR"):
                preflight.verify_central_lineage(ROOT, "pr-qa-v1-rc204", second)
            prs[second] = [{"number": 11, "merged_at": "2026-10-23T02:00:00Z", "merge_commit_sha": second,
                            "base": {"ref": "main"}, "head": {"sha": second_head}}]
            checks_without_architecture = checks(second_head)
            checks_without_architecture["check_runs"].pop()
            original_checks = checks
            checks = lambda head: checks_without_architecture if head == second_head else original_checks(head)
            with self.assertRaisesRegex(ValueError, "required exact-head checks missing"):
                preflight.verify_central_lineage(ROOT, "pr-qa-v1-rc204", second)
            checks = lambda head: ({"total_count": 3, "check_runs": [
                *original_checks(head)["check_runs"],
                {"id": 3, "name": "Architecture Governance", "head_sha": head,
                 "status": "completed", "conclusion": "failure", "app": {"slug": "github-actions"}},
            ]} if head == second_head else original_checks(head))
            with self.assertRaisesRegex(ValueError, "required exact-head checks missing"):
                preflight.verify_central_lineage(ROOT, "pr-qa-v1-rc204", second)

    def test_inherited_fixture_disposition_accepts_only_exact_prior_fingerprints(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["inherited_synthetic_fixtures"]
        inherited_text = (ROOT / "tests/test_pr_qa_regressions.py").read_text(encoding="utf-8")
        report = {"results": [{
            "gate": "Secrets", "status": "FAIL", "blocking": True,
            "details": [f'{item["path"]}: {item["label"]}. line_sha256={item["line_sha256"]}'
                        for item in reviewed["synthetic_fixture_findings"]],
        }]}
        def fake_git(args, _root):
            if args[:3] == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN
            elif args == ["show", "pr-qa-v1-rc204:tests/test_pr_qa_regressions.py"]:
                value = inherited_text
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value, "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_inherited_fixture_disposition(ROOT, path, "main", "pr-qa-v1-rc204"))
                inherited_text += "\n# changed fixture\n"
                self.assertFalse(preflight.reviewed_inherited_fixture_disposition(ROOT, path, "main", "pr-qa-v1-rc204"))
                inherited_text = (ROOT / "tests/test_pr_qa_regressions.py").read_text(encoding="utf-8")
                self.assertFalse(preflight.reviewed_inherited_fixture_disposition(ROOT, path, "development", "pr-qa-v1-rc204"))
                all_details = report["results"][0]["details"]
                report["results"][0]["details"] = all_details[:6]
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_inherited_fixture_disposition(ROOT, path, "main", "pr-qa-v1-rc204"))
                report["results"][0]["details"] = all_details
                report["results"][0]["details"].extend([report["results"][0]["details"][0]] * 20)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_inherited_fixture_disposition(ROOT, path, "main", "pr-qa-v1-rc204"))
                report["results"][0]["details"].append("config.php: API key. line_sha256=" + "b" * 64)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_inherited_fixture_disposition(ROOT, path, "main", "pr-qa-v1-rc204"))
                report["results"][0]["details"].pop()
                report["results"].append({"gate": "Repository Hygiene", "status": "FAIL", "blocking": True})
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_inherited_fixture_disposition(ROOT, path, "main", "pr-qa-v1-rc204"))
                report["results"].pop()
                report["results"][0]["details"][0] = "tests/test_pr_qa_regressions.py: GitHub token. line_sha256=" + "b" * 64
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_inherited_fixture_disposition(ROOT, path, "main", "pr-qa-v1-rc204"))

    def test_rc204_disposition_accepts_only_exact_inherited_fixtures_after_reviewed_squash(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc204"]
        source_sha = "e" * 40
        pr_head = "f" * 40
        inherited_text = (ROOT / "tests/test_pr_qa_regressions.py").read_text(encoding="utf-8")
        report = {"results": [{
            "gate": "Secrets", "status": "FAIL", "blocking": True,
            "details": [f'{item["path"]}: {item["label"]}. line_sha256={item["line_sha256"]}'
                        for item in reviewed["synthetic_fixture_findings"]],
        }]}
        pr = {"merged_at": "2026-10-23T09:00:00Z", "merge_commit_sha": source_sha,
              "head": {"sha": pr_head}, "base": {"ref": "main"}}

        def fake_git(args, _root):
            if args[:3] == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN
            elif args == ["show", "pr-qa-v1-rc203:tests/test_pr_qa_regressions.py"]:
                value = inherited_text
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = source_sha
            elif args[:2] == ["rev-list", "--count"]:
                value = "1"
            elif args[:3] == ["rev-list", "--first-parent", "--merges"]:
                value = ""
            elif args in (["rev-parse", f"{pr_head}^{{tree}}"], ["rev-parse", "HEAD^{tree}"]):
                value = "a" * 40
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value + "\n", "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), \
                 patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(pr), "")):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc204_disposition(ROOT, path, "main", "pr-qa-v1-rc203"))
                self.assertFalse(preflight.reviewed_rc204_disposition(ROOT, path, "main", "pr-qa-v1-rc202"))
                report["results"][0]["details"].append("config.php: API key. line_sha256=" + "b" * 64)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc204_disposition(ROOT, path, "main", "pr-qa-v1-rc203"))
                report["results"][0]["details"].pop()
                report["results"].append({"gate": "Repository Hygiene", "status": "FAIL", "blocking": True})
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc204_disposition(ROOT, path, "main", "pr-qa-v1-rc203"))
                report["results"].pop()
                path.write_text(json.dumps(report), encoding="utf-8")
                with patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps({**pr, "merged_at": None}), "")):
                    self.assertFalse(preflight.reviewed_rc204_disposition(ROOT, path, "main", "pr-qa-v1-rc203"))

    def test_rc203_disposition_requires_exact_inherited_fixtures_and_reviewed_squash(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc203"]
        source_sha = "e" * 40
        pr_head = "f" * 40
        prior_sha = "d" * 40
        inherited_text = (ROOT / "tests/test_pr_qa_regressions.py").read_text(encoding="utf-8")
        report = {"results": [{
            "gate": "Secrets", "status": "FAIL", "blocking": True,
            "details": [f'{item["path"]}: {item["label"]}. line_sha256={item["line_sha256"]}'
                        for item in reviewed["synthetic_fixture_findings"]],
        }]}
        pr = {"merged_at": "2026-10-23T08:00:00Z", "merge_commit_sha": source_sha,
              "head": {"sha": pr_head}, "base": {"ref": "main"}}
        prior_pr = {"merged_at": "2026-10-23T07:37:47Z", "merge_commit_sha": prior_sha,
                    "base": {"ref": "main"}}

        def fake_api(args, _root):
            value = prior_pr if args[-1].endswith("/385") else pr
            return subprocess.CompletedProcess(args, 0, json.dumps(value), "")

        def fake_git(args, _root):
            if args[:3] == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN
            elif args == ["show", "pr-qa-v1-rc202:tests/test_pr_qa_regressions.py"]:
                value = inherited_text
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = source_sha
            elif args == ["rev-parse", "HEAD^"]:
                value = prior_sha
            elif args[:2] == ["rev-list", "--count"]:
                value = "2"
            elif args[:3] == ["rev-list", "--first-parent", "--merges"]:
                value = ""
            elif args in (["rev-parse", f"{pr_head}^{{tree}}"], ["rev-parse", "HEAD^{tree}"]):
                value = "a" * 40
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value + "\n", "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), \
                 patch.object(preflight, "run", side_effect=fake_api):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc202"))
                self.assertFalse(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc201"))
                report["results"][0]["details"].append("config.php: API key. line_sha256=" + "b" * 64)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc202"))
                report["results"][0]["details"].pop()
                report["results"].append({"gate": "Repository Hygiene", "status": "FAIL", "blocking": True})
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc202"))
                report["results"].pop()
                path.write_text(json.dumps(report), encoding="utf-8")
                with patch.object(preflight, "run", side_effect=lambda args, _root: subprocess.CompletedProcess(args, 0, json.dumps(prior_pr if args[-1].endswith("/385") else {**pr, "merged_at": None}), "")):
                    self.assertFalse(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc202"))
                with patch.object(preflight, "run", side_effect=lambda args, _root: subprocess.CompletedProcess(args, 0, json.dumps({**prior_pr, "merge_commit_sha": "a" * 40} if args[-1].endswith("/385") else pr), "")):
                    self.assertFalse(preflight.reviewed_rc203_disposition(ROOT, path, "main", "pr-qa-v1-rc202"))

    def test_rc202_disposition_is_bound_to_exact_findings_and_merged_tree(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc202"]
        merge = reviewed["approved_merge"]
        source_sha = "e" * 40
        pr_head = "f" * 40
        inherited_text = (ROOT / "tests/test_pr_qa_regressions.py").read_text(encoding="utf-8")
        framework_token = "](?:" + "\\|".join(part + "_path" for part in ("upload", "cache", "log", "storage", "tmp")) + ")["
        literal_details = [
            f"DEVELOPER_DECLARATION: `{value}` introduces a writable/runtime path that has not been classified."
            for value in (framework_token, framework_token, "cache" + "_path", "cache",
                          "Unable to write cache file:", "Cache file written:")
        ]
        report = {"results": [
            {"gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
             "message": "Accidental merge commits detected.", "details": [merge["sha"]]},
            {"gate": "Secrets", "status": "FAIL", "blocking": True,
             "details": [f'{item["path"]}: {item["label"]}. line_sha256={item["line_sha256"]}'
                         for item in reviewed["synthetic_fixture_findings"]]},
            {"gate": "Persistent Data Safety", "status": "FAIL", "blocking": True,
             "details": literal_details},
        ]}
        pr = {"merged_at": "2026-10-23T07:00:00Z", "merge_commit_sha": source_sha,
              "head": {"sha": pr_head}, "base": {"ref": "main"}}

        def fake_git(args, _root):
            if args[:3] == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN
            elif args[:2] == ["show", "pr-qa-v1-rc201:tests/test_pr_qa_regressions.py"]:
                value = inherited_text
            elif args[:3] == ["rev-list", "--parents", "-n"]:
                value = " ".join((merge["sha"], merge["base_sha"], merge["head_sha"]))
            elif args[:2] == ["merge-base", "--is-ancestor"]:
                value = ""
            elif args[:3] == ["rev-list", "--first-parent", "--merges"]:
                value = merge["sha"]
            elif args in (["rev-parse", "HEAD"], ["rev-parse", "refs/remotes/origin/main"]):
                value = source_sha
            elif args in (["rev-parse", f"{pr_head}^{{tree}}"], ["rev-parse", "HEAD^{tree}"]):
                value = "a" * 40
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value + "\n", "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), \
                 patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(pr), "")):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc202_disposition(ROOT, path, "main", "pr-qa-v1-rc201"))
                self.assertFalse(preflight.reviewed_rc202_disposition(ROOT, path, "main", "pr-qa-v1-rc200"))
                report["results"][2]["details"].append("DEVELOPER_DECLARATION: `uploads` is undeclared")
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc202_disposition(ROOT, path, "main", "pr-qa-v1-rc201"))
                report["results"][2]["details"].pop()
                report["results"][1]["details"].append("config.php: API key. line_sha256=" + "b" * 64)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc202_disposition(ROOT, path, "main", "pr-qa-v1-rc201"))
                report["results"][1]["details"].pop()
                path.write_text(json.dumps(report), encoding="utf-8")
                with patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps({**pr, "merged_at": None}), "")):
                    self.assertFalse(preflight.reviewed_rc202_disposition(ROOT, path, "main", "pr-qa-v1-rc201"))

    def test_rc201_disposition_requires_exact_reviewed_findings_and_merge(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text(encoding="utf-8"))
        reviewed = policy["release_preflight_dispositions"]["pr-qa-v1-rc201"]
        merge = reviewed["approved_merge"]
        findings = reviewed["synthetic_fixture_findings"]
        for item in findings:
            self.assertEqual(item["path"], "tests/test_pr_qa_regressions.py")
            lines = (ROOT / item["path"]).read_text(encoding="utf-8").splitlines()
            self.assertTrue(any(hashlib.sha256(line.strip().encode()).hexdigest() == item["line_sha256"] for line in lines))
        report = {"results": [
            {"gate": "Repository Hygiene", "status": "FAIL", "blocking": True,
             "message": "Accidental merge commits detected.", "details": [merge["sha"]]},
            {"gate": "Secrets", "status": "FAIL", "blocking": True,
             "details": [f'{item["path"]}: {item["label"]}. line_sha256={item["line_sha256"]}' for item in findings]},
        ]}
        pr = {"merged_at": "2026-10-23T04:18:28Z", "merge_commit_sha": merge["sha"],
              "head": {"sha": merge["head_sha"]}, "base": {"ref": "main"}}

        def fake_git(args, _root):
            if args[:3] == ["remote", "get-url", "origin"]:
                value = preflight.CENTRAL_ORIGIN
            elif args[:3] == ["rev-list", "--parents", "-n"]:
                value = " ".join((merge["sha"], merge["base_sha"], merge["head_sha"]))
            elif args[:3] == ["rev-list", "--first-parent", "--merges"]:
                value = merge["sha"]
            elif args[:2] == ["rev-parse", f'{merge["sha"]}^{{tree}}'] or args[:2] == ["rev-parse", f'{merge["head_sha"]}^{{tree}}']:
                value = "a" * 40
            else:
                return subprocess.CompletedProcess(args, 1, "", "unexpected git query")
            return subprocess.CompletedProcess(args, 0, value + "\n", "")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            with patch.object(preflight, "git", side_effect=fake_git), \
                 patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(pr), "")):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertTrue(preflight.reviewed_rc201_disposition(ROOT, path, "main", "pr-qa-v1-rc200"))
                self.assertFalse(preflight.reviewed_rc201_disposition(ROOT, path, "development", "pr-qa-v1-rc200"))
                report["results"][0]["details"] = ["b" * 40]
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc201_disposition(ROOT, path, "main", "pr-qa-v1-rc200"))
                report["results"][0]["details"] = [merge["sha"]]
                report["results"][1]["details"].append("src/config.py: generic credential assignment. line_sha256=" + "c" * 64)
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertFalse(preflight.reviewed_rc201_disposition(ROOT, path, "main", "pr-qa-v1-rc200"))
                report["results"][1]["details"].pop()
                path.write_text(json.dumps(report), encoding="utf-8")
                with patch.object(preflight, "run", return_value=subprocess.CompletedProcess([], 1, "", "unauthorized")):
                    self.assertFalse(preflight.reviewed_rc201_disposition(ROOT, path, "main", "pr-qa-v1-rc200"))

    def test_technical_preflight_does_not_fabricate_pr_review_evidence(self):
        captured = {}

        def run_engine(command, **kwargs):
            event = Path(command[command.index("--event-path") + 1])
            captured["event"] = __import__("json").loads(event.read_text(encoding="utf-8"))
            captured["command"] = command
            return subprocess.CompletedProcess(command, 0)

        sha = "a" * 40
        with patch.object(preflight, "git", side_effect=[
            subprocess.CompletedProcess([], 0, sha + "\n", ""),
            subprocess.CompletedProcess([], 0, "main\n", ""),
        ]), patch.object(preflight.subprocess, "run", side_effect=run_engine):
            self.assertTrue(preflight.run_pr_qa(ROOT, ROOT, "main", "b" * 40))

        self.assertNotIn("pull_request", captured["event"])
        self.assertEqual(captured["event"]["release_preflight"]["head_sha"], sha)
        self.assertEqual(captured["command"][captured["command"].index("--base-ref") + 1], "main")
        self.assertEqual(captured["command"][captured["command"].index("--head-ref") + 1], "main")

    def test_publisher_bound_preflight_skips_release_enumeration_and_checks_local_tag(self):
        sys.path.insert(0, str(ROOT / "pr-qa"))
        import release_pin
        commit = "a" * 40
        args = ["release-preflight", "--base", "main", "--verified-release", "pr-qa-v1-rc194",
                "--verified-commit", commit]
        local = subprocess.CompletedProcess([], 0, commit + "\n", "")
        with patch.object(sys, "argv", args), patch.object(preflight, "repo_root", return_value=ROOT), \
             patch.object(preflight, "active_release") as enumerate_releases, \
             patch.object(release_pin, "verify_bound_release") as verify_bound, \
             patch.object(preflight, "git", return_value=local), \
             patch.object(preflight, "resolve_origin_base", return_value="b" * 40), \
             patch.object(preflight, "worktree_state", return_value="CLEAN"), \
             patch.object(preflight, "extract_release", return_value=True), \
             patch.object(preflight, "run_pr_qa", return_value=True), \
             patch.object(preflight, "run_consumer_compatibility", return_value=True), \
             patch.object(preflight, "print_report"):
            self.assertEqual(preflight.main(), 0)
            enumerate_releases.assert_not_called()
            verify_bound.assert_called_once()
        with patch.object(sys, "argv", [*args, "--compatibility-via-provenance"]), \
             patch.object(preflight, "repo_root", return_value=ROOT), \
             patch.object(release_pin, "verify_bound_release"), \
             patch.object(preflight, "git", return_value=local), \
             patch.object(preflight, "resolve_origin_base", return_value="b" * 40), \
             patch.object(preflight, "worktree_state", return_value="CLEAN"), \
             patch.object(preflight, "extract_release", return_value=True), \
             patch.object(preflight, "run_pr_qa", return_value=True), \
             patch.object(preflight, "run_consumer_compatibility") as compatibility, \
             patch.object(preflight, "print_report") as report:
            self.assertEqual(preflight.main(), 0)
            compatibility.assert_not_called()
            self.assertEqual(report.call_args.args[4], "DEFERRED_TO_EXACT_SOURCE_PROVENANCE")
        stale = subprocess.CompletedProcess([], 0, "c" * 40 + "\n", "")
        with patch.object(sys, "argv", args), patch.object(preflight, "repo_root", return_value=ROOT), \
             patch.object(release_pin, "verify_bound_release"), \
             patch.object(preflight, "git", return_value=stale), \
             patch.object(preflight, "resolve_origin_base", return_value="b" * 40), \
             patch.object(preflight, "worktree_state", return_value="CLEAN"), \
             patch.object(preflight, "run_consumer_compatibility", return_value=True), \
             patch.object(preflight, "print_report"):
            self.assertEqual(preflight.main(), 1)

    def test_central_preflight_uses_live_governed_release(self):
        origin = subprocess.CompletedProcess([], 0, preflight.CENTRAL_ORIGIN + "\n", "")
        active = subprocess.CompletedProcess([], 0, "Resolved active release pr-qa-v1-rc191 at " + "a" * 40 + "\n", "")
        with patch.object(preflight, "git", return_value=origin), patch.object(preflight, "run", return_value=active):
            self.assertEqual(preflight.active_release(ROOT), "pr-qa-v1-rc191")

        failed = subprocess.CompletedProcess([], 1, "", "resolution failed")
        with patch.object(preflight, "git", return_value=origin), patch.object(preflight, "run", return_value=failed):
            self.assertIsNone(preflight.active_release(ROOT))

        malformed = subprocess.CompletedProcess([], 0, "Resolved active release pr-qa-v1-rc191 at wrong\n", "")
        with patch.object(preflight, "git", return_value=origin), patch.object(preflight, "run", return_value=malformed):
            self.assertIsNone(preflight.active_release(ROOT))

    def run_cmd(self, args, cwd, env=None):
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        return subprocess.run(args, cwd=cwd, env=merged_env, text=True, capture_output=True)

    def git(self, repo, *args):
        proc = self.run_cmd(["git", *args], repo)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.strip()

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def make_repo(self):
        temp = tempfile.TemporaryDirectory()
        repo = Path(temp.name)
        self.git(repo, "init", "-b", "feature")
        self.git(repo, "config", "user.email", "tests@example.invalid")
        self.git(repo, "config", "user.name", "Tests")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            'env:\n  PR_QA_FRAMEWORK_RELEASE: "pr-qa-v1-test"\n',
        )
        self.write(
            repo / ".github" / "workflows" / "fieldzilla-staging-opentofu-apply.yml",
            (ROOT / ".github" / "workflows" / "fieldzilla-staging-opentofu-apply.yml").read_text(
                encoding="utf-8"
            ),
        )
        self.write(
            repo / "pr-qa" / "pr_qa.py",
            textwrap.dedent(
                """\
                import os
                import sys

                raise SystemExit(int(os.environ.get("FAKE_PR_QA_EXIT", "0")))
                """
            ),
        )
        (repo / "scripts").mkdir()
        shutil.copy2(SCRIPT, repo / "scripts" / "release-preflight")
        shutil.copy2(ROOT / "scripts" / "consumer-compatibility-preflight", repo / "scripts" / "consumer-compatibility-preflight")
        (repo / "scripts" / "release-preflight").chmod(
            (repo / "scripts" / "release-preflight").stat().st_mode | stat.S_IXUSR
        )
        (repo / "scripts" / "consumer-compatibility-preflight").chmod(
            (repo / "scripts" / "consumer-compatibility-preflight").stat().st_mode | stat.S_IXUSR
        )
        self.write(
            repo / "actions" / "runtime-certifier" / "action.yml",
            (ROOT / "actions" / "runtime-certifier" / "action.yml").read_text(encoding="utf-8"),
        )
        self.write(
            repo / "actions" / "ssm-artifact-promoter" / "action.yml",
            (ROOT / "actions" / "ssm-artifact-promoter" / "action.yml").read_text(encoding="utf-8"),
        )
        self.write(repo / "README.md", "fixture\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-m", "fixture")
        self.git(repo, "tag", "pr-qa-v1-test")
        shutil.copytree(ROOT / "pr-qa", repo / "pr-qa", dirs_exist_ok=True)
        self.git(repo, "add", "pr-qa")
        self.git(repo, "commit", "-m", "candidate framework parser")
        self.git(repo, "update-ref", "refs/remotes/origin/development", "HEAD")
        self.git(repo, "update-ref", "refs/remotes/origin/staging", "HEAD")
        return temp, repo

    def run_preflight(self, repo, *args, env=None):
        return self.run_cmd(["./scripts/release-preflight", *args], repo, env=env)

    def test_ready_when_base_resolves_and_active_release_passes(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ACTIVE_PR_QA_RELEASE: pr-qa-v1-test", proc.stdout)
        self.assertIn("BASE: development", proc.stdout)
        self.assertIn("WORKTREE: CLEAN", proc.stdout)
        self.assertIn("CENTRAL_PR_QA: PASS", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: PASS", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: YES", proc.stdout)
        self.assertIn("DEVELOPER RELEASE READINESS", proc.stdout)
        self.assertNotIn("DEVELOPER_HANDOFF_READY", proc.stdout)

    def test_staging_base_reports_developer_handoff_ready(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, "--base", "staging")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("DEVELOPER STAGING READINESS", proc.stdout)
        self.assertIn("ACTIVE_PR_QA_RELEASE: pr-qa-v1-test", proc.stdout)
        self.assertIn("BASE: staging", proc.stdout)
        self.assertIn("WORKTREE: CLEAN", proc.stdout)
        self.assertIn("CENTRAL_PR_QA: PASS", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: PASS", proc.stdout)
        self.assertIn("DEVELOPER_HANDOFF_READY: YES", proc.stdout)
        self.assertNotIn("READY_FOR_PROMOTION", proc.stdout)

    def test_staging_base_reports_developer_handoff_not_ready_on_failure(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, "--base", "staging", env={"FAKE_PR_QA_EXIT": "9"})

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("DEVELOPER STAGING READINESS", proc.stdout)
        self.assertIn("CENTRAL_PR_QA: FAIL", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: PASS", proc.stdout)
        self.assertIn("DEVELOPER_HANDOFF_READY: NO", proc.stdout)
        self.assertIn("central PR-QA failed", proc.stdout)
        self.assertNotIn("READY_FOR_PROMOTION", proc.stdout)

    def test_unresolved_base_fails_closed(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, "--base", "missing")

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("CENTRAL_PR_QA: FAIL", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: PASS", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: NO", proc.stdout)
        self.assertIn("base 'missing' could not be resolved", proc.stdout)

    def test_pr_qa_failure_blocks_promotion(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)

        proc = self.run_preflight(repo, env={"FAKE_PR_QA_EXIT": "9"})

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("CENTRAL_PR_QA: FAIL", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: PASS", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: NO", proc.stdout)
        self.assertIn("central PR-QA failed", proc.stdout)

    def test_dirty_tree_is_reported_and_blocks(self):
        temp, repo = self.make_repo()
        self.addCleanup(temp.cleanup)
        (repo / "dirty.txt").write_text("dirty\n", encoding="utf-8")

        proc = self.run_preflight(repo)

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("WORKTREE: DIRTY", proc.stdout)
        self.assertIn("CONSUMER_COMPATIBILITY: FAIL", proc.stdout)
        self.assertIn("READY_FOR_PROMOTION: NO", proc.stdout)
        self.assertIn("working tree has uncommitted changes", proc.stdout)


if __name__ == "__main__":
    unittest.main()
