"""Read one exact GitHub artifact without extracting or executing its contents."""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from typing import Any

MAX_ARCHIVE = 1024 * 1024
MAX_MANIFEST = 64 * 1024
NAME = "fieldzilla-application-execution-manifest"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate execution manifest property")
        result[key] = value
    return result


def read_manifest_artifact(
    *,
    metadata: dict[str, Any],
    archive: bytes,
    artifact_id: int,
    run_id: int,
    caller_sha: str,
    manifest_sha256: str,
) -> tuple[bytes, dict[str, Any]]:
    """Metadata must be freshly read from the application repository's API.

    This validates packaging, not approval, candidate compatibility or execution
    authority. No archive path is written to disk. Only the approved raw manifest
    is returned for separate context and approval checks.
    """
    if (
        type(artifact_id) is not int
        or artifact_id < 1
        or type(run_id) is not int
        or run_id < 1
        or not re.fullmatch(r"[0-9a-f]{40}", caller_sha)
        or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256)
    ):
        raise ValueError("Artifact identities must be exact")
    workflow = metadata.get("workflow_run", {})
    if (
        metadata.get("id") != artifact_id
        or metadata.get("name") != NAME
        or metadata.get("expired") is not False
        or workflow.get("id") != run_id
        or workflow.get("repository_id") != 1315697868
        or workflow.get("head_repository_id") != 1315697868
        or workflow.get("head_branch") != "main"
        or workflow.get("head_sha") != caller_sha
    ):
        raise ValueError("Artifact origin or expiry differs")
    if (
        len(archive) > MAX_ARCHIVE
        or metadata.get("digest") != "sha256:" + hashlib.sha256(archive).hexdigest()
    ):
        raise ValueError("Artifact archive digest or size differs")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            files = zipped.infolist()
            if (
                len(files) != 1
                or files[0].filename != "execution-manifest.json"
                or files[0].is_dir()
                or files[0].file_size > MAX_MANIFEST
                or files[0].flag_bits & 1
            ):
                raise ValueError(
                    "Artifact must contain only one bounded unencrypted manifest"
                )
            raw = zipped.read(files[0])
    except (zipfile.BadZipFile, RuntimeError) as error:
        raise ValueError("Execution artifact cannot be read") from error
    if hashlib.sha256(raw).hexdigest() != manifest_sha256:
        raise ValueError("Raw execution manifest differs from the approved bytes")
    payload = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(payload, dict):
        raise TypeError("Execution manifest must be an object")
    return raw, payload
