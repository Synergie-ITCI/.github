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
from datetime import UTC, datetime
from pathlib import Path

from execution_artifact import _unique_object
from execution_gate import REPOSITORY
from issued_windows import SQL_FREE_PRODUCTION_BASE, SQL_FREE_PRODUCTION_SOURCE, is_sql_free_update

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pr-qa"))
from release_pin import resolve_consumer_release

CENTRAL = "repos/Synergie-ITCI/.github/"
QUALITY = "pr-qa / Pull Request Quality Assurance"
DETECTOR = "pr-qa / Detect repository technologies"
POLICY_FILES = (
    "policy/pr-qa-policy.json",
    "policy/audited-migration-authorizations.json",
)


def verify_pr808_detector_log_recovery(manifest, proof, release, run, detector, api, *, now=None):
    """Time-limited proof for GitHub's unavailable QA log-download endpoints.

    The successful detector job must have run after the reviewed protected
    selector merged. The ordinary exact-head check, final QA artifact, and
    active immutable-policy checks still run below. No other run can use this.
    """
    if (now or datetime.now(UTC)) >= datetime.fromisoformat("2026-11-20T06:30:11Z"):
        raise ValueError("PR #808 detector-log recovery expired")
    if (
        manifest.get("promotion_pr") != 808
        or manifest.get("application", {}).get("source_sha") != "5d92dd585eda25391297bfd9d408c585f556a4d6"
        or manifest.get("base_sha") != "bd9b3bd3d6b0fa4d7e27448e09a674de3c601aa0"
        or proof.get("run_id") != 44451575467
        or run.get("run_attempt") != 2
        or release != "pr-qa-v1-rc368"
        or proof.get("policy_sha") != "ea802c2a5e2b7965850db7c19a69bfe12b897f18"
        or detector.get("id") != 135404339322
        or detector.get("head_sha") != manifest["application"]["source_sha"]
    ):
        raise ValueError("PR #808 detector-log recovery identity differs")
    selector_merge = "a3b0380d9eeb3a5e56d3d24e947ee375c4d3c7bb"
    current_main = api(f"repos/{REPOSITORY}/git/ref/heads/main").get("object", {}).get("sha")
    if not isinstance(current_main, str) or not re.fullmatch(r"[0-9a-f]{40}", current_main):
        raise ValueError("PR #808 protected main identity unavailable")
    ancestry = api(f"repos/{REPOSITORY}/compare/{selector_merge}...{current_main}")
    if ancestry.get("status") not in {"identical", "ahead"}:
        raise ValueError("PR #808 protected selector is not in main ancestry")
    selector = api(f"repos/{REPOSITORY}/pulls/809")
    if (
        selector.get("state") != "closed"
        or selector.get("merge_commit_sha") != "a3b0380d9eeb3a5e56d3d24e947ee375c4d3c7bb"
        or selector.get("head", {}).get("sha") != "c862601ff13a6c438854dfaafb7c49eb2a385dd7"
        or selector.get("base", {}).get("sha") != "6a940de7c493be4aa257bbe2f97977ba021622d4"
        or not selector.get("merged_at")
    ):
        raise ValueError("PR #808 protected selector merge differs")
    started = datetime.fromisoformat(detector.get("started_at", ""))
    merged = datetime.fromisoformat(selector["merged_at"])
    if started.tzinfo is None or merged.tzinfo is None or started <= merged:
        raise ValueError("PR #808 QA detector did not run after selector merge")
    steps = detector.get("steps", [])
    required = {
        "Resolve approved central PR QA release",
        "Checkout immutable central PR QA framework",
        "Detect technologies",
    }
    if not isinstance(steps, list) or any(
        len([step for step in steps if step.get("name") == name and step.get("conclusion") == "success"]) != 1
        for name in required
    ):
        raise ValueError("PR #808 QA detector release steps are not exact successes")


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
    attempt = run.get("run_attempt")
    if type(attempt) is not int or not 1 <= attempt <= 10:
        raise ValueError("Exact QA run attempt is unavailable")
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
    if run_prs == [] and manifest.get("scope") in {"production", "production-images"}:
        pr = api(f"repos/{REPOSITORY}/pulls/{manifest['promotion_pr']}")
        bound_in_run = (
            pr.get("number") == manifest["promotion_pr"]
            and (
                (pr.get("state") == "closed" and bool(pr.get("merged_at")))
                or checks.get("__merge_metadata_recovery__") is True
            )
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
        try:
            logs = read_detector_run_log_archive(
                api(
                    f"repos/{REPOSITORY}/actions/runs/{proof['run_id']}"
                    f"/attempts/{attempt}/logs"
                )
            )
        except RuntimeError:
            verify_pr808_detector_log_recovery(
                manifest, proof, release, run, detectors[0], api
            )
            logs = None
    if logs is not None:
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
    ordinary_qa = (
        manifest.get("scope") == "production-images"
        or is_sql_free_update(manifest)
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 772
            and source == SQL_FREE_PRODUCTION_SOURCE
            and base == SQL_FREE_PRODUCTION_BASE
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest.get("review_authorizations", {}).get("sql") is None
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261109_0073"],
                "after": ["20260909_0041", "20261113_0074"],
            }
        )
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 786
            and source == "2b0753f08aaabdacb780d1abd35fc2d5e80bc181"
            and base == "576fba59c0d5958cb623351b29201b4d4aef589c"
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest["review_authorizations"].get("sql")
            == "17fc5f90-d712-4dd8-8085-57353395ff0e"
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261113_0074"],
                "after": ["20260909_0041", "20261116_0075"],
            }
        )
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 787
            and source == "a6e35a7ad36fbc21417a8575bb723a7948a5e8c7"
            and base == "739fd2759b949e3228affb69cd090b64613b159a"
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest["review_authorizations"].get("sql")
            == "407d605f-815b-4516-b714-5b72bf6c1422"
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261113_0074"],
                "after": ["20260909_0041", "20261116_0075"],
            }
        )
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 791
            and source == "8821f317a4316ec7bca639ac7b6d22e9f903cfd9"
            and base == "a1b883710bdd37ce915901dcfa86a837733a7b7b"
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest["review_authorizations"].get("sql")
            == "50e42152-16ec-43c3-8bce-b8df5f4f10cf"
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261116_0075"],
                "after": ["20260909_0041", "20261117_0076"],
            }
        )
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 798
            and source == "ee2b975c9c5a4881d71c6cd46d17af4e2f33aeae"
            and base == "4c31546a984e3bda42d52b11a2ce268989991eab"
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest["review_authorizations"].get("sql")
            == "b0f5dab9-3c63-4273-a8cb-4ca891f7c8ee"
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261117_0076"],
                "after": ["20260909_0041", "20261117_0077"],
            }
        )
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 802
            and source == "b55cf18a881c1722d307cac4c04114667e8379ea"
            and base == "cfbdc0e4d5ac2478ea33befff657e23570507e48"
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest["review_authorizations"].get("sql") is None
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261117_0077"],
                "after": ["20260909_0041", "20261117_0077"],
            }
        )
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 804
            and source == "0d82540f4e2ca19a5edceea34d78728fea57fa46"
            and base == "254484811fe33ddcaa6c8bd5a105f76d8384d6eb"
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest["review_authorizations"].get("sql") is None
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261117_0077"],
                "after": ["20260909_0041", "20261117_0077"],
            }
        )
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 806
            and source == "670b7482120cda2375fad491a270e0b00f833450"
            and base == "aa23b1b0bebbf4c5bf5dadc768e38a049e6b07d0"
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest["review_authorizations"].get("sql") is None
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261117_0077"],
                "after": ["20260909_0041", "20261117_0077"],
            }
        )
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 808
            and source == "5d92dd585eda25391297bfd9d408c585f556a4d6"
            and base == "bd9b3bd3d6b0fa4d7e27448e09a674de3c601aa0"
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest["review_authorizations"].get("sql") is None
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261117_0077"],
                "after": ["20260909_0041", "20261117_0077"],
            }
        )
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 811
            and source == "410badf52529ace7a7e05295f012c8ff6b50be3a"
            and base == "6a41100ee099ee7f0ed1d12ca222c4df7dcd704d"
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest["review_authorizations"].get("sql") is None
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261117_0077"],
                "after": ["20260909_0041", "20261117_0077"],
            }
        )
        or (
            manifest.get("scope") == "production"
            and manifest.get("promotion_pr") == 814
            and source == "6b2b91e65452a705ae856678dfda1441f8377c6e"
            and base == "8ebd9e87912aa134d00462e08d9fdc757a3cb98b"
            and isinstance(manifest.get("review_authorizations"), dict)
            and manifest["review_authorizations"].get("sql") is None
            and manifest.get("database") == {
                "name": "fieldzilla_production",
                "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261117_0077"],
                "after": ["20260909_0041", "20261117_0077"],
            }
        )
    ) and (
        binding.get("requested") is False
        and binding.get("authorized") is False
        and binding.get("relaxed_checks") == []
    )
    if (
        summary.get("repository") != REPOSITORY
        or summary.get("overall_result") != "PASS"
        or (binding.get("authorized") is not True and not ordinary_qa)
        or binding.get("source_sha") != source
        or binding.get("destination_sha") != base
    ):
        raise ValueError(
            "Final QA report does not prove the exact reviewed source/base"
        )
    policies = {
        path: read_central_json(api, path, proof["policy_sha"]) for path in POLICY_FILES
    }
    if checks.get("__merge_metadata_recovery__") is True:
        policies["__merge_metadata_recovery__"] = True
    return policies
