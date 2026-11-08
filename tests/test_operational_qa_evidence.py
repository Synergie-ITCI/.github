"""Adversarial tests use isolated fixtures; never query Actions or live services."""

import contextlib
import copy
import datetime as dt
import importlib.util
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "operational_evidence",
    Path(__file__).resolve().parents[1] / "tools/operational_qa_evidence.py",
)
qa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa)
POLICY = qa.POLICY_PATH.read_bytes()
NOW = dt.datetime(2026, 11, 8, 10, tzinfo=dt.UTC)
WORKFLOW = b"uses: Synergie-ITCI/.github/actions/operational-qa-evidence@" + b"f" * 40


def fixture(php=False):
    contract = {
        "schema": 1,
        "enabled": True,
        "repository": "Synergie-ITCI/saksham"
        if php
        else "Synergie-ITCI/programme-management-platform",
        "repository_id": 42 if php else 1315697868,
        "source_sha": "a" * 40,
        "branch": "main" if php else "staging",
        "issuer_workflow_path": ".github/workflows/operations.yml"
        if php
        else ".github/workflows/staging-deploy.yml",
        "issuer_workflow_sha256": qa.digest(WORKFLOW),
        "verifier_commit": "f" * 40,
        "producer_job": "PHP QA" if php else "QA and Build Validation",
        "required_jobs": ["PHP QA" if php else "QA and Build Validation"],
        "source_checks": {"PHPUnit": "tests", "PHP lint": "lint"}
        if php
        else {"Backend Tests": "tests", "Backend Ruff": "lint", "Admin build": "build"},
        "fresh_checks": ["composer audit", "approval", "live checks"]
        if php
        else [
            "pip-audit",
            "npm audit when applicable",
            "approval",
            "runtime",
            "drain-lock",
        ],
        "approval_and_live_checks_required": True,
        "central_release": {"tag": "pr-qa-v1-rc225", "commit": "b" * 40},
        "inputs_digest": qa.digest(
            b"composer.lock + PHP image"
            if php
            else b"lockfiles + pip freeze + runner image"
        ),
        "required_check_contract_sha256": "e" * 64,
        "operations": {
            "observe": "counts-only-observe",
            "pause": "locked-worker-pause",
        },
    }
    record = qa.record_for(contract, POLICY, 19, 1, NOW - dt.timedelta(minutes=10))
    server = {
        "repository": {
            "id": contract["repository_id"],
            "full_name": contract["repository"],
        },
        "branch": {"protected": True, "commit": {"sha": contract["source_sha"]}},
        "run": {
            "id": 19,
            "run_attempt": 1,
            "head_sha": contract["source_sha"],
            "repository": {"id": contract["repository_id"]},
            "head_repository": {"id": contract["repository_id"]},
            "status": "completed",
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_branch": contract["branch"],
            "path": contract["issuer_workflow_path"],
            "created_at": (NOW - dt.timedelta(minutes=20)).isoformat(),
            "updated_at": NOW.isoformat(),
        },
        "workflow_bytes": WORKFLOW,
        "release_commit": "b" * 40,
        "selected_release": {"release": "pr-qa-v1-rc225", "commit": "b" * 40},
        "required_check_contract_sha256": "e" * 64,
        "jobs": [
            {
                "name": contract["producer_job"],
                "conclusion": "success",
                "steps": [
                    {"name": name, "conclusion": "success"}
                    for name in contract["source_checks"]
                ],
            }
        ],
    }
    return contract, record, server


def package(record, server, extra=None):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("qa-evidence.json", json.dumps(record))
        if extra:
            archive.writestr(extra, "unexpected")
    blob = target.getvalue()
    server["artifact"] = {
        "name": "operational-source-qa",
        "expired": False,
        "digest": "sha256:" + qa.digest(blob),
        "size_in_bytes": len(blob),
        "workflow_run": {
            "id": 19,
            "repository_id": server["repository"]["id"],
            "head_repository_id": server["repository"]["id"],
            "head_sha": "a" * 40,
        },
    }
    return blob


class EvidenceTests(unittest.TestCase):
    def test_valid_different_repository_shapes(self):
        for php in (False, True):
            c, r, s = fixture(php)
            decision = qa.verify(c, POLICY, "observe", s, package(r, s), NOW)
            self.assertTrue(decision["reuse_source_checks"])
            self.assertFalse(decision["authorizes_operation"])
            self.assertEqual(decision["fresh_checks"], c["fresh_checks"])

    def test_every_bound_record_field_rejects_changes(self):
        c, record, server = fixture()
        for field in qa.FIELDS - {"issued_at"}:
            with self.subTest(field=field):
                r, s = copy.deepcopy(record), copy.deepcopy(server)
                r[field] = "tampered"
                with self.assertRaises((qa.Rejected, TypeError)):
                    qa.verify(c, POLICY, "observe", s, package(r, s), NOW)

    def test_changed_inputs_checks_and_policy(self):
        for field, value in [
            ("inputs_digest", "f" * 64),
            ("required_jobs", ["Another check"]),
            ("source_checks", {"New check": "tests"}),
            ("central_release", {"tag": "pr-qa-v1-rc226", "commit": "c" * 40}),
        ]:
            c, r, s = fixture()
            blob = package(r, s)
            c[field] = value
            with self.subTest(field=field), self.assertRaises(qa.Rejected):
                qa.verify(c, POLICY, "observe", s, blob, NOW)
        c, r, s = fixture()
        with self.assertRaises(qa.Rejected):
            qa.verify(c, POLICY + b"\n", "observe", s, package(r, s), NOW)

    def test_server_origin_and_outcomes(self):
        variants = [
            lambda s: s["run"].update(conclusion="failure"),
            lambda s: s["run"].update(event="pull_request_target"),
            lambda s: s["run"].update(run_attempt=2),
            lambda s: s["run"].update(head_sha="c" * 40),
            lambda s: s["run"].update(path=".github/workflows/forged.yml"),
            lambda s: s["run"]["head_repository"].update(id=999),
            lambda s: s["branch"].update(protected=False),
            lambda s: s["branch"]["commit"].update(sha="d" * 40),
            lambda s: s.update(workflow_bytes=b"changed issuer code"),
            lambda s: s.update(release_commit="d" * 40),
            lambda s: s.update(
                selected_release={"release": "pr-qa-v1-rc226", "commit": "d" * 40}
            ),
            lambda s: s["artifact"].update(expired=True),
            lambda s: s["artifact"]["workflow_run"].update(id=20),
            lambda s: s["jobs"][0]["steps"][0].update(conclusion="skipped"),
            lambda s: s.update(jobs=[]),
            lambda s: s["jobs"].append(copy.deepcopy(s["jobs"][0])),
        ]
        for index, mutate in enumerate(variants):
            c, r, s = fixture()
            blob = package(r, s)
            mutate(s)
            with self.subTest(index=index), self.assertRaises(qa.Rejected):
                qa.verify(c, POLICY, "observe", s, blob, NOW)

    def test_expired_future_and_outside_run(self):
        for issued in (
            NOW - dt.timedelta(hours=7),
            NOW + dt.timedelta(seconds=1),
            NOW - dt.timedelta(minutes=25),
        ):
            c, r, s = fixture()
            r["issued_at"] = issued.isoformat()
            with self.subTest(issued=issued), self.assertRaises(qa.Rejected):
                qa.verify(c, POLICY, "observe", s, package(r, s), NOW)

    def test_pause_has_shorter_age(self):
        c, r, s = fixture()
        r["issued_at"] = (NOW - dt.timedelta(hours=2)).isoformat()
        s["run"]["created_at"] = (NOW - dt.timedelta(hours=3)).isoformat()
        blob = package(r, s)
        self.assertTrue(
            qa.verify(c, POLICY, "observe", s, blob, NOW)["reuse_source_checks"]
        )
        with self.assertRaises(qa.Rejected):
            qa.verify(c, POLICY, "pause", s, blob, NOW)

    def test_tampered_incomplete_and_extra_archive_members(self):
        c, r, s = fixture()
        blob = package(r, s)
        with self.assertRaises(qa.Rejected):
            qa.verify(c, POLICY, "observe", s, blob[:-1] + b"X", NOW)
        del r["inputs_digest"]
        with self.assertRaises(qa.Rejected):
            qa.verify(c, POLICY, "observe", s, package(r, s), NOW)
        c, r, s = fixture()
        with self.assertRaises(qa.Rejected):
            qa.verify(c, POLICY, "observe", s, package(r, s, "../unexpected"), NOW)

    def test_no_opt_in_resume_or_live_security_substitution(self):
        for change in (
            lambda c: c.update(enabled=False),
            lambda c: c.update(approval_and_live_checks_required=False),
            lambda c: c["source_checks"].update({"Security": "security"}),
        ):
            c, r, s = fixture()
            change(c)
            with self.assertRaises(qa.Rejected):
                qa.verify(c, POLICY, "observe", s, package(r, s), NOW)
        c, r, s = fixture()
        with self.assertRaisesRegex(qa.Rejected, "operation_not_eligible"):
            qa.verify(c, POLICY, "resume", s, package(r, s), NOW)

    def test_duplicate_json(self):
        with self.assertRaises(qa.Rejected):
            qa.strict_json('{"schema":1,"schema":1}')

    def test_strict_numeric_identity_and_changed_required_rule(self):
        for key, value in [("schema", True), ("run_id", 19.0), ("run_attempt", True)]:
            c, r, s = fixture()
            r[key] = value
            with self.subTest(key=key), self.assertRaises(qa.Rejected):
                qa.verify(c, POLICY, "observe", s, package(r, s), NOW)
        c, r, s = fixture()
        blob = package(r, s)
        s["required_check_contract_sha256"] = "d" * 64
        with self.assertRaisesRegex(qa.Rejected, "required_check_policy_changed"):
            qa.verify(c, POLICY, "observe", s, blob, NOW)
        with self.assertRaisesRegex(qa.Rejected, "required_check_policy_unavailable"):
            qa.required_check_hash([])

    def test_cli_unavailable_and_missing_evidence_fall_back(self):
        c, _, _ = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(c))
            env = {
                "GITHUB_REPOSITORY": c["repository"],
                "GITHUB_SHA": c["source_sha"],
                "GITHUB_REF": "refs/heads/" + c["branch"],
                "EVIDENCE_VERIFIER_REF": c["verifier_commit"],
            }
            for artifact_id in ("", "91"):
                output = io.StringIO()
                argv = [
                    "evidence",
                    "verify",
                    "--contract",
                    str(path),
                    "--operation",
                    "observe",
                    "--artifact-id",
                    artifact_id,
                ]
                with (
                    patch.dict(qa.os.environ, env, clear=True),
                    patch("sys.argv", argv),
                    patch.object(
                        qa, "fetch_server", side_effect=OSError("unavailable")
                    ),
                    contextlib.redirect_stdout(output),
                ):
                    qa.main()
                decision = json.loads(output.getvalue())
                self.assertFalse(decision["reuse_source_checks"])
                self.assertFalse(decision["authorizes_operation"])

    def test_fresh_approval_and_runtime_contract_cannot_disappear(self):
        c, _, _ = fixture()
        c["fresh_checks"] = []
        with self.assertRaisesRegex(qa.Rejected, "fresh_gate_contract_missing"):
            qa.validate_contract(c, qa.strict_json(POLICY), "observe")


if __name__ == "__main__":
    unittest.main()
