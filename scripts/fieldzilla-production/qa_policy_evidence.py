"""Bind review data to the activated immutable QA release that actually ran.

Executor code and QA policy are independently immutable references. Requiring
review records inside the executor release makes a main-only caller impossible
to bootstrap without repeatedly changing its own reviewed base. No live main
issuance is sufficient here: selection, tag protection/provenance, detector log,
final report and exact source/base must all agree before records are returned.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import sys
import zipfile
from datetime import datetime
from pathlib import Path

from execution_artifact import _unique_object
from execution_gate import REPOSITORY

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pr-qa"))
from release_pin import resolve_consumer_release

CENTRAL = "repos/Synergie-ITCI/.github/"
QUALITY = "pr-qa / Pull Request Quality Assurance"
DETECTOR = "pr-qa / Detect repository technologies"
POLICY_FILES = (
    "policy/pr-qa-policy.json",
    "policy/audited-migration-authorizations.json",
)


def read_central_json(api, path, sha):
    reply = api(f"{CENTRAL}contents/{path}?ref={sha}")
    if reply.get("type") != "file" or reply.get("encoding") != "base64":
        raise ValueError("Central policy content unavailable")
    encoded = reply.get("content", "")
    if not isinstance(encoded, str) or len(encoded) > 1_500_000:
        raise ValueError("Central policy content exceeds the bounded read")
    return json.loads(base64.b64decode(encoded), object_pairs_hook=_unique_object)


def read_final_report(archive, digest):
    if not isinstance(archive, bytes) or len(archive) > 1024 * 1024:
        raise ValueError("Final QA archive exceeds the bounded read")
    if hashlib.sha256(archive).hexdigest() != digest:
        raise ValueError("Final QA archive digest differs")
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        files = zipped.infolist()
        names = [item.filename for item in files]
        allowed = {
            "pr-quality-report.json",
            "pr-quality-report.md",
            "qa-packet.json",
            "gitleaks.json",
        }
        if (
            len(names) != len(set(names))
            or not set(names) <= allowed
            or names.count("pr-quality-report.json") != 1
            or sum(item.file_size for item in files) > 2 * 1024 * 1024
            or any(item.flag_bits & 1 for item in files)
            or zipped.getinfo("pr-quality-report.json").file_size > 256 * 1024
        ):
            raise ValueError("Final QA archive shape differs")
        return json.loads(
            zipped.read("pr-quality-report.json"), object_pairs_hook=_unique_object
        )


def read_detector_run_log_archive(archive):
    """Read only the unique detector log from the exact QA run's bounded archive.

    GitHub offers both per-job logs and a run-log ZIP under Actions: read. This
    equivalent source is used only when the per-job API read itself fails.
    Neither path accepts a different run or substitutes another job's log.
    """
    if not isinstance(archive, bytes) or len(archive) > 8 * 1024 * 1024:
        raise ValueError("QA run-log archive is unavailable or oversized")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            files = zipped.infolist()
            names = [item.filename for item in files]
            if (
                len(files) > 256
                or len(names) != len(set(names))
                or any(item.flag_bits & 1 for item in files)
                or sum(item.file_size for item in files) > 32 * 1024 * 1024
            ):
                raise ValueError("QA run-log archive shape differs")
            detector_name = DETECTOR.replace("/", "_")
            matches = [
                item
                for item in files
                if re.fullmatch(
                    r"[0-9]+_" + re.escape(detector_name) + r"\.txt", item.filename
                )
            ]
            if len(matches) != 1 or matches[0].file_size > 4 * 1024 * 1024:
                raise ValueError("Unique detector run log is unavailable or oversized")
            return zipped.read(matches[0])
    except zipfile.BadZipFile as error:
        raise ValueError("QA run-log archive is invalid") from error


def verify_qa_policy_evidence(
    manifest, *, checks, api, resolver=resolve_consumer_release
):
    proof = manifest.get("qa_evidence", {})
    if (
        not isinstance(proof, dict)
        or set(proof)
        != {"policy_release", "policy_sha", "run_id", "artifact_id", "archive_sha256"}
        or not re.fullmatch(r"pr-qa-v1-rc[1-9][0-9]*", str(proof.get("policy_release")))
        or not re.fullmatch(r"[0-9a-f]{40}", str(proof.get("policy_sha")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(proof.get("archive_sha256")))
        or any(
            type(proof.get(key)) is not int or proof[key] < 1
            for key in ("run_id", "artifact_id")
        )
    ):
        raise ValueError("Exact QA release and final artifact identities are required")
    central_main = api(CENTRAL + "git/ref/heads/main").get("object", {}).get("sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", central_main):
        raise ValueError("Central selection source is unavailable")
    selection = read_central_json(api, "policy/framework-releases.json", central_main)
    if not isinstance(selection, dict) or selection.get("version") != 1:
        raise ValueError("Activated consumer selection schema differs")
    release, entry = resolver(
        selection,
        REPOSITORY,
        lookup=lambda path: api(CENTRAL + path),
        list_refs=lambda path: api(CENTRAL + path),
    )
    if release != proof["policy_release"] or entry.get("commit") != proof["policy_sha"]:
        raise ValueError("QA proof does not match the activated consumer selection")

    check = checks.get(QUALITY, {})
    source = manifest["application"]["source_sha"]
    if (
        check.get("head_sha") != source
        or check.get("status") != "completed"
        or check.get("conclusion") != "success"
        or check.get("app", {}).get("slug") != "github-actions"
    ):
        raise ValueError(
            "Latest required QA check is not a governed exact-head success"
        )
    match = re.fullmatch(
        rf"https://github\.com/{re.escape(REPOSITORY)}/actions/runs/([1-9][0-9]*)/job/([1-9][0-9]*)",
        check.get("details_url", ""),
    )
    if not match or int(match[1]) != proof["run_id"]:
        raise ValueError("QA proof is not the latest required check's run")
    base = manifest["base_sha"]
    run = api(f"repos/{REPOSITORY}/actions/runs/{proof['run_id']}")
    run_prs = run.get("pull_requests")
    bound_in_run = isinstance(run_prs, list) and any(
        row.get("number") == manifest["promotion_pr"]
        and row.get("head", {}).get("sha") == source
        and row.get("base", {}).get("sha") == base
        for row in run_prs
    )
    # GitHub may remove a completed run's pull_requests association after the
    # exact PR merges. Only that empty-array case may use the merged PR's exact
    # identity; the run and artifact checks below remain required.
    if run_prs == [] and manifest.get("scope") == "production":
        pr = api(f"repos/{REPOSITORY}/pulls/{manifest['promotion_pr']}")
        bound_in_run = (
            pr.get("number") == manifest["promotion_pr"]
            and pr.get("state") == "closed"
            and bool(pr.get("merged_at"))
            and pr.get("head", {}).get("sha") == source
            and pr.get("head", {}).get("repo", {}).get("full_name") == REPOSITORY
            and pr.get("base", {}).get("ref") == "main"
            and pr.get("base", {}).get("sha") == base
        )
    if (
        run.get("id") != proof["run_id"]
        or run.get("head_sha") != source
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("event") != "pull_request"
        or run.get("path") != ".github/workflows/pr-qa.yml"
        or not bound_in_run
    ):
        raise ValueError("Final QA run source, base or PR binding differs")
    jobs = []
    for page in range(1, 11):
        reply = api(
            f"repos/{REPOSITORY}/actions/runs/{proof['run_id']}/jobs?filter=latest&per_page=100&page={page}"
        )
        rows = reply.get("jobs")
        if not isinstance(rows, list):
            raise TypeError("QA job metadata is unavailable")
        jobs.extend(rows)
        if len(rows) < 100:
            break
    else:
        raise ValueError("QA job history exceeds the bounded read")
    quality = [
        row
        for row in jobs
        if row.get("id") == int(match[2]) and row.get("name") == QUALITY
    ]
    detectors = [row for row in jobs if row.get("name") == DETECTOR]
    if (
        len(quality) != 1
        or len(detectors) != 1
        or any(
            row.get("status") != "completed" or row.get("conclusion") != "success"
            for row in [*quality, *detectors]
        )
    ):
        raise ValueError("Exact final QA and detector jobs are unresolved")
    if any(
        type(row.get("id")) is not int or row["id"] < 1
        for row in [*quality, *detectors]
    ):
        raise ValueError("QA job identities are malformed")
    try:
        logs = api(f"repos/{REPOSITORY}/actions/jobs/{detectors[0]['id']}/logs")
    except RuntimeError:
        logs = read_detector_run_log_archive(
            api(f"repos/{REPOSITORY}/actions/runs/{proof['run_id']}/logs")
        )
    if not isinstance(logs, bytes) or len(logs) > 4 * 1024 * 1024:
        raise ValueError("Detector evidence is unavailable or oversized")
    identities = re.findall(
        rb"(?m)^(?:[0-9T:.+-]+Z )?Resolved approved release (pr-qa-v1-rc[1-9][0-9]*) at ([0-9a-f]{40})\r?$",
        logs,
    )
    if identities != [(release.encode(), proof["policy_sha"].encode())]:
        raise ValueError(
            "Executing QA release does not match the activated policy proof"
        )

    metadata = api(f"repos/{REPOSITORY}/actions/artifacts/{proof['artifact_id']}")
    origin = metadata.get("workflow_run", {})
    if (
        metadata.get("id") != proof["artifact_id"]
        or metadata.get("name") != "pr-qa-results"
        or metadata.get("expired") is not False
        or metadata.get("digest") != "sha256:" + proof["archive_sha256"]
        or origin.get("id") != proof["run_id"]
        or origin.get("head_sha") != source
        or origin.get("repository_id") != 1315697868
        or origin.get("head_repository_id") != 1315697868
    ):
        raise ValueError("Final QA artifact origin, kind or digest differs")
    started = datetime.fromisoformat(quality[0]["started_at"])
    completed = datetime.fromisoformat(quality[0]["completed_at"])
    created = datetime.fromisoformat(metadata["created_at"])
    if (
        any(value.utcoffset() is None for value in (started, completed, created))
        or not started <= created <= completed
    ):
        raise ValueError("Final QA artifact is not from the latest successful job")
    report = read_final_report(
        api(f"repos/{REPOSITORY}/actions/artifacts/{proof['artifact_id']}/zip"),
        proof["archive_sha256"],
    )
    if not isinstance(report, dict):
        raise TypeError("Final QA report must be an object")
    summary = report.get("summary", {})
    if not isinstance(summary, dict):
        raise TypeError("Final QA summary must be an object")
    binding = summary.get("baseline_alignment", {})
    if not isinstance(binding, dict):
        raise TypeError("Final QA binding must be an object")
    if (
        summary.get("repository") != REPOSITORY
        or summary.get("overall_result") != "PASS"
        or binding.get("authorized") is not True
        or binding.get("source_sha") != source
        or binding.get("destination_sha") != base
    ):
        raise ValueError(
            "Final QA report does not prove the exact reviewed source/base"
        )
    return {
        path: read_central_json(api, path, proof["policy_sha"]) for path in POLICY_FILES
    }
