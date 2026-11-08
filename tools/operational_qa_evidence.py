"""Opt-in source-check evidence, never operation authorization.

Uses the authenticated Actions artifact/run/digest boundary already used by
roadsense_gate_d.read_artifact_json, generalized without its release authority.
Missing or unverifiable evidence means FULL_QA, including API outages. No AWS.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
import re
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy/operational-qa-evidence.json"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = {
    "schema",
    "repository",
    "repository_id",
    "source_sha",
    "issuer_revision",
    "issuer_workflow_path",
    "issuer_workflow_sha256",
    "central_release",
    "policy_sha256",
    "inputs_digest",
    "source_checks",
    "required_jobs",
    "run_id",
    "run_attempt",
    "issued_at",
    "verifier_commit",
    "required_check_contract_sha256",
}


class Rejected(ValueError):
    """Evidence cannot substitute for source checks."""


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique)


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value)
    require(parsed.tzinfo is not None, "timestamp_without_timezone")
    return parsed


def validate_contract(contract, policy, operation):
    require(contract.get("enabled") is True, "not_opted_in")
    kind = contract.get("operations", {}).get(operation)
    require(kind in policy["max_age_seconds"], "operation_not_eligible")
    require(
        type(contract.get("schema")) is int and contract["schema"] == 1,
        "contract_schema",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", contract["repository"]),
        "repository_invalid",
    )
    require(
        re.fullmatch(
            r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml",
            contract["issuer_workflow_path"],
        ),
        "workflow_path_invalid",
    )
    require(HEX40.fullmatch(contract["source_sha"]) is not None, "source_sha_invalid")
    require(
        HEX64.fullmatch(contract["issuer_workflow_sha256"]) is not None,
        "issuer_hash_invalid",
    )
    require(
        HEX64.fullmatch(contract["inputs_digest"]) is not None, "inputs_digest_invalid"
    )
    require(
        HEX40.fullmatch(contract["verifier_commit"]) is not None, "verifier_pin_invalid"
    )
    require(
        HEX64.fullmatch(contract["required_check_contract_sha256"]) is not None,
        "required_check_contract_invalid",
    )
    require(
        type(contract["repository_id"]) is int and contract["repository_id"] > 0,
        "repository_id_invalid",
    )
    require(
        contract["source_checks"] and contract["required_jobs"], "empty_check_contract"
    )
    require(
        set(contract["source_checks"].values()) <= set(policy["reusable_categories"]),
        "non_source_check_requested",
    )
    require(
        contract.get("fresh_checks")
        and contract.get("approval_and_live_checks_required") is True,
        "fresh_gate_contract_missing",
    )
    release = contract["central_release"]
    require(
        set(release) == {"tag", "commit"} and HEX40.fullmatch(release["commit"]),
        "central_pin_invalid",
    )
    require(re.fullmatch(r"pr-qa-v1-rc[0-9]+", release["tag"]), "central_tag_invalid")
    return policy["max_age_seconds"][kind]


def record_for(contract, policy_bytes, run_id, attempt, now):
    """Issuer runs only after all original source steps; upload is caller-owned."""
    return {
        "schema": 1,
        **{
            k: contract[k]
            for k in (
                "repository",
                "repository_id",
                "source_sha",
                "issuer_workflow_path",
                "issuer_workflow_sha256",
                "central_release",
                "inputs_digest",
                "source_checks",
                "required_jobs",
                "verifier_commit",
                "required_check_contract_sha256",
            )
        },
        "issuer_revision": contract["source_sha"],
        "policy_sha256": digest(policy_bytes),
        "run_id": run_id,
        "run_attempt": attempt,
        "issued_at": now.isoformat(),
    }


def verify(contract, policy_bytes, operation, server, blob, now):
    policy = strict_json(policy_bytes)
    age = validate_contract(contract, policy, operation)
    artifact, run = server["artifact"], server["run"]
    require(
        server["repository"]["id"] == contract["repository_id"], "repository_identity"
    )
    require(
        server["repository"]["full_name"] == contract["repository"], "repository_name"
    )
    require(
        server["branch"]["protected"] is True
        and server["branch"]["commit"]["sha"] == contract["source_sha"],
        "protected_tip_changed",
    )
    require(
        run["status"] == "completed" and run["conclusion"] == "success",
        "issuer_not_successful",
    )
    require(run["event"] in {"push", "workflow_dispatch"}, "untrusted_event")
    require(
        run["repository"]["id"] == contract["repository_id"]
        and run["head_repository"]["id"] == contract["repository_id"],
        "issuer_repository",
    )
    require(
        run["head_sha"] == contract["source_sha"]
        and run["head_branch"] == contract["branch"],
        "issuer_commit_or_branch",
    )
    require(run["path"] == contract["issuer_workflow_path"], "issuer_workflow")
    require(
        digest(server["workflow_bytes"]) == contract["issuer_workflow_sha256"],
        "issuer_revision_changed",
    )
    require(
        contract["verifier_commit"].encode() in server["workflow_bytes"],
        "issuer_verifier_pin",
    )
    require(
        server["release_commit"] == contract["central_release"]["commit"],
        "central_release_moved",
    )
    require(
        server["selected_release"]
        == {
            "release": contract["central_release"]["tag"],
            "commit": contract["central_release"]["commit"],
        },
        "central_selection_changed",
    )
    require(
        server["required_check_contract_sha256"]
        == contract["required_check_contract_sha256"],
        "required_check_policy_changed",
    )
    require(
        artifact["name"] == policy["artifact_name"] and artifact["expired"] is False,
        "artifact_unavailable",
    )
    require(
        type(artifact["size_in_bytes"]) is int
        and 0 < artifact["size_in_bytes"] <= policy["max_zip_bytes"]
        and len(blob) == artifact["size_in_bytes"],
        "artifact_size",
    )
    origin = artifact["workflow_run"]
    require(
        origin["id"] == run["id"]
        and origin["repository_id"] == contract["repository_id"]
        and origin["head_sha"] == contract["source_sha"]
        and origin["head_repository_id"] == contract["repository_id"],
        "artifact_origin",
    )
    require(artifact.get("digest") == "sha256:" + digest(blob), "artifact_tampered")
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        require(archive.namelist() == ["qa-evidence.json"], "artifact_members")
        info = archive.getinfo("qa-evidence.json")
        require(
            info.file_size <= policy["max_record_bytes"] and not info.is_dir(),
            "record_size",
        )
        evidence = strict_json(archive.read(info))
    require(
        set(evidence) == FIELDS
        and type(evidence["schema"]) is int
        and evidence["schema"] == 1,
        "record_schema",
    )
    require(
        all(
            type(evidence[k]) is int and evidence[k] > 0
            for k in ("repository_id", "run_id", "run_attempt")
        ),
        "record_identity_types",
    )
    expected = record_for(contract, policy_bytes, run["id"], run["run_attempt"], now)
    for key in FIELDS - {"issued_at"}:
        require(evidence[key] == expected[key], "record_mismatch:" + key)
    issued = timestamp(evidence["issued_at"])
    require(
        dt.timedelta(0) <= now - issued <= dt.timedelta(seconds=age),
        "evidence_expired_or_future",
    )
    require(
        timestamp(run["created_at"]) <= issued <= timestamp(run["updated_at"]),
        "issuance_outside_run",
    )
    for name in contract["required_jobs"]:
        matches = [j for j in server["jobs"] if j["name"] == name]
        require(
            len(matches) == 1 and matches[0]["conclusion"] == "success",
            "required_job:" + name,
        )
    producers = [j for j in server["jobs"] if j["name"] == contract["producer_job"]]
    require(len(producers) == 1, "ambiguous_producer")
    for name in contract["source_checks"]:
        matches = [s for s in producers[0]["steps"] if s["name"] == name]
        require(
            len(matches) == 1 and matches[0]["conclusion"] == "success",
            "required_step:" + name,
        )
    return {
        "reuse_source_checks": True,
        "reason": "trusted_exact_input_evidence",
        "reused_checks": sorted(contract["source_checks"]),
        "fresh_checks": contract["fresh_checks"],
        "authorizes_operation": False,
    }


def api(path):
    data = subprocess.check_output(
        ["gh", "api", "--hostname", "github.com", path], timeout=30
    )
    return strict_json(data)


def required_check_hash(rules):
    required = [
        r["parameters"] for r in rules if r.get("type") == "required_status_checks"
    ]
    require(
        required and any(r.get("required_status_checks") for r in required),
        "required_check_policy_unavailable",
    )
    return digest(json.dumps(required, sort_keys=True, separators=(",", ":")).encode())


def fetch_server(contract, artifact_id):
    repo = "repos/" + contract["repository"]
    artifact = api(f"{repo}/actions/artifacts/{artifact_id}")
    run = api(f"{repo}/actions/runs/{artifact['workflow_run']['id']}")
    jobs, page = [], 1
    while True:
        batch = api(
            f"{repo}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100&page={page}"
        )["jobs"]
        jobs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
        require(page <= 10, "too_many_jobs")
    workflow = api(
        f"{repo}/contents/{contract['issuer_workflow_path']}?ref={run['head_sha']}"
    )
    release = api(
        "repos/Synergie-ITCI/.github/git/ref/tags/" + contract["central_release"]["tag"]
    )["object"]
    for _ in range(3):
        if release["type"] == "commit":
            break
        require(release["type"] == "tag", "central_ref_type")
        release = api("repos/Synergie-ITCI/.github/git/tags/" + release["sha"])[
            "object"
        ]
    require(release["type"] == "commit", "central_tag_depth")
    selection_file = api(
        "repos/Synergie-ITCI/.github/contents/policy/framework-releases.json?ref=main"
    )
    selection = strict_json(base64.b64decode(selection_file["content"]))[
        "consumer_release_selection"
    ]
    server = {
        "repository": api(repo),
        "branch": api(f"{repo}/branches/{contract['branch']}"),
        "artifact": artifact,
        "run": run,
        "jobs": jobs,
        "workflow_bytes": base64.b64decode(workflow["content"], validate=False),
        "release_commit": release["sha"],
        "selected_release": selection["repositories"].get(
            contract["repository"], selection["default"]
        ),
        "required_check_contract_sha256": required_check_hash(
            api(f"{repo}/rules/branches/{contract['branch']}")
        ),
    }
    require(artifact["size_in_bytes"] <= 262144, "artifact_size")
    blob = subprocess.check_output(
        [
            "gh",
            "api",
            "--hostname",
            "github.com",
            f"{repo}/actions/artifacts/{artifact_id}/zip",
        ],
        timeout=30,
    )
    return server, blob


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["verify", "issue"])
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--artifact-id", default="")
    parser.add_argument("--record", type=Path)
    args = parser.parse_args()
    result = {
        "reuse_source_checks": False,
        "issued": False,
        "reason": "full_qa_required",
        "authorizes_operation": False,
    }
    try:
        contract = strict_json(args.contract.read_bytes())
        policy_bytes = POLICY_PATH.read_bytes()
        validate_contract(contract, strict_json(policy_bytes), args.operation)
        require(
            os.environ["GITHUB_REPOSITORY"] == contract["repository"]
            and os.environ["GITHUB_SHA"] == contract["source_sha"]
            and os.environ["GITHUB_REF"] == "refs/heads/" + contract["branch"],
            "current_execution_identity",
        )
        require(
            os.environ["EVIDENCE_VERIFIER_REF"] == contract["verifier_commit"],
            "executing_verifier_pin",
        )
        now = dt.datetime.now(dt.UTC)
        if args.mode == "issue":
            require(args.record is not None, "missing_record_path")
            record = record_for(
                contract,
                policy_bytes,
                int(os.environ["GITHUB_RUN_ID"]),
                int(os.environ["GITHUB_RUN_ATTEMPT"]),
                now,
            )
            args.record.write_text(json.dumps(record, sort_keys=True) + "\n")
            result["reason"] = "issued_pending_successful_run"
            result["issued"] = True
        else:
            require(re.fullmatch(r"[1-9][0-9]*", args.artifact_id), "missing_artifact")
            server, blob = fetch_server(contract, args.artifact_id)
            result = verify(contract, policy_bytes, args.operation, server, blob, now)
    except (
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        OSError,
        RuntimeError,
        zipfile.BadZipFile,
        subprocess.SubprocessError,
    ) as error:
        # Never expose tokens, private response bodies or dynamic subprocess output.
        result["reason"] = (
            str(error)
            if isinstance(error, Rejected)
            else "evidence_unavailable_or_invalid"
        )
    print(json.dumps(result, sort_keys=True))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(
                "reuse_source_checks="
                + str(result["reuse_source_checks"]).lower()
                + "\n"
            )
            output.write("issued=" + str(result.get("issued", False)).lower() + "\n")


if __name__ == "__main__":
    main()
