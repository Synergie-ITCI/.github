"""Validate an exact same-run image artifact before bounded private extraction."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path

from execution_artifact import _unique_object
from image_publication import DIGEST, KINDS

MAX_ARCHIVE = 2 * 1024**3
MAX_UNCOMPRESSED = 8 * 1024**3


def validate_origin(metadata, *, run_id, caller_sha, source_sha, archive_digest):
    if (
        type(run_id) is not int
        or run_id < 1
        or not re.fullmatch(r"[0-9a-f]{40}", caller_sha)
        or not re.fullmatch(r"[0-9a-f]{40}", source_sha)
        or not re.fullmatch(r"[0-9a-f]{64}", archive_digest)
    ):
        raise ValueError("Exact build-run and artifact identities are required")
    origin = metadata.get("workflow_run", {})
    if (
        metadata.get("name") != "fieldzilla-production-images-" + source_sha
        or metadata.get("expired") is not False
        or type(metadata.get("size_in_bytes")) is not int
        or not 0 < metadata["size_in_bytes"] <= MAX_ARCHIVE
        or metadata.get("digest") != "sha256:" + archive_digest
        or origin.get("id") != run_id
        or origin.get("head_sha") != caller_sha
        or origin.get("head_branch") != "main"
        or origin.get("repository_id") != 1315697868
        or origin.get("head_repository_id") != 1315697868
    ):
        raise ValueError("Image artifact is not the exact current main build run")


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_images(
    archive: Path, output: Path, *, archive_digest, source_sha, caller_sha, run_id
):
    if archive.stat().st_size > MAX_ARCHIVE or checksum(archive) != archive_digest:
        raise ValueError("Downloaded image archive digest or size differs")
    with zipfile.ZipFile(archive) as zipped:
        files = zipped.infolist()
        expected = {"api.tar", "admin-web.tar", "images.json"}
        if (
            len(files) != 3
            or {item.filename for item in files} != expected
            or sum(item.file_size for item in files) > MAX_UNCOMPRESSED
            or zipped.getinfo("images.json").file_size > 64 * 1024
            or any(
                item.flag_bits & 1
                or item.is_dir()
                or stat.S_ISLNK(item.external_attr >> 16)
                for item in files
            )
        ):
            raise ValueError("Image artifact packaging differs; nothing extracted")
        metadata = json.loads(
            zipped.read("images.json"), object_pairs_hook=_unique_object
        )
        if (
            not isinstance(metadata, dict)
            or set(metadata)
            != {
                "source_sha",
                "caller_sha",
                "run_id",
                "run_attempt",
                "platform",
                "images",
            }
            or metadata["source_sha"] != source_sha
            or metadata["caller_sha"] != caller_sha
            or metadata["run_id"] != run_id
            or metadata["run_attempt"] != 1
            or metadata["platform"] != "linux/arm64"
            or not isinstance(metadata["images"], dict)
            or set(metadata["images"]) != set(KINDS)
        ):
            raise ValueError("Image build metadata source/platform/run differs")
        for kind in KINDS:
            row = metadata["images"][kind]
            if (
                not isinstance(row, dict)
                or set(row) != {"config_digest", "archive_sha256", "archive_bytes"}
                or not DIGEST.fullmatch(str(row["config_digest"]))
                or not re.fullmatch(r"[0-9a-f]{64}", str(row["archive_sha256"]))
                or type(row["archive_bytes"]) is not int
                or row["archive_bytes"] < 1
                or row["archive_bytes"] != zipped.getinfo(kind + ".tar").file_size
            ):
                raise ValueError("Built image config/archive identities differ")
        output.mkdir(mode=0o700)
        for kind in KINDS:
            target = output / (kind + ".tar")
            # Never use archive names as paths, restore permissions, or overwrite.
            with zipped.open(kind + ".tar") as source, target.open("xb") as destination:
                os.chmod(target, 0o600)
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    destination.write(block)
            if checksum(target) != metadata["images"][kind]["archive_sha256"]:
                raise ValueError("Built image archive content differs; do not load it")
    return metadata
