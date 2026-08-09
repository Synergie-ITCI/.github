#!/usr/bin/env python3
"""Synergie Production Application Backup Framework.

The framework intentionally keeps secrets out of config and logs. Database
credentials are read from approved runtime files already present on the
production host, used through a temporary client defaults file, and removed at
the end of the run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import gzip
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


FRAMEWORK_VERSION = "2026.08.09"
DEFAULT_CONFIG = "/etc/synergie/backup-applications.json"
SAFE_RESTORE_NAME = re.compile(r"(restore|recovery|test|tmp|temp)", re.I)


class BackupError(Exception):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message: str) -> None:
    print(f"{iso_now()} {message}", flush=True)


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    return value.strip("-") or "unknown"


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def enabled_apps(config: dict[str, Any]) -> list[dict[str, Any]]:
    apps = config.get("applications", [])
    return [app for app in apps if app.get("enabled", True)]


def select_apps(config: dict[str, Any], app_name: str | None, all_apps: bool) -> list[dict[str, Any]]:
    apps = enabled_apps(config)
    if all_apps:
        return apps
    if not app_name:
        raise BackupError("provide --app or --all")
    selected = [app for app in apps if app["application_name"] == app_name or app.get("slug") == app_name]
    if not selected:
        raise BackupError(f"application not found in config: {app_name}")
    return selected


def run(
    cmd: list[str],
    *,
    stdout: Any = None,
    stderr: Any = subprocess.PIPE,
    input_file: Any = None,
    check: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        cmd,
        stdin=input_file,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=stderr,
        text=text,
        check=False,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() if isinstance(completed.stderr, str) else ""
        raise BackupError(f"command failed: {cmd[0]} exit={completed.returncode} {detail[:500]}")
    return completed


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_size(path: Path) -> int:
    return path.stat().st_size


def s3_uri(bucket: str, key: str) -> str:
    return f"s3://{bucket}/{key.lstrip('/')}"


def aws_json(args: list[str]) -> dict[str, Any]:
    completed = run(["aws", *args, "--output", "json"])
    return json.loads(completed.stdout or "{}")


def aws_text(args: list[str]) -> str:
    completed = run(["aws", *args, "--output", "text"])
    return (completed.stdout or "").strip()


def put_s3(local_path: Path, bucket: str, key: str, encryption: str) -> dict[str, Any]:
    uri = s3_uri(bucket, key)
    run(["aws", "s3", "cp", str(local_path), uri, "--sse", encryption, "--only-show-errors"])
    return aws_json(["s3api", "head-object", "--bucket", bucket, "--key", key])


def parse_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            values[key] = value
    return values


def parse_wp_config(path: str) -> dict[str, str]:
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    values: dict[str, str] = {}
    for key in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"):
        match = re.search(r"define\(\s*['\"]" + key + r"['\"]\s*,\s*['\"]([^'\"]*)['\"]", text)
        if match:
            values[key] = match.group(1)
    return values


def mysql_credentials(app: dict[str, Any], workdir: Path) -> tuple[Path, str]:
    db = app["database"]
    source = db.get("credential_source", {})
    source_type = source.get("type")
    source_path = source.get("path")
    if source_type == "mysql_root_socket":
        name = db.get("name")
        if not name:
            raise BackupError(f"database name missing for {app['application_name']}")
        defaults = workdir / f"{safe_name(app['slug'])}.mysql.cnf"
        defaults.write_text("[client]\nuser=root\n\n", encoding="utf-8")
        defaults.chmod(0o600)
        return defaults, name

    if not source_path or not Path(source_path).is_file():
        raise BackupError(f"credential source unavailable for {app['application_name']}")

    if source_type in {"laravel_env", "env"}:
        values = parse_env_file(source_path)
        name = db.get("name") or values.get("DB_DATABASE") or values.get("DB_NAME")
        user = values.get("DB_USERNAME") or values.get("DB_USER")
        password = values.get("DB_PASSWORD") or ""
        host = values.get("DB_HOST") or "localhost"
        port = values.get("DB_PORT") or "3306"
    elif source_type == "wordpress_wp_config":
        values = parse_wp_config(source_path)
        name = db.get("name") or values.get("DB_NAME")
        user = values.get("DB_USER")
        password = values.get("DB_PASSWORD") or ""
        host_value = values.get("DB_HOST") or "localhost"
        if ":" in host_value and not host_value.startswith("/"):
            host, port = host_value.rsplit(":", 1)
        else:
            host, port = host_value, "3306"
    else:
        raise BackupError(f"unsupported credential source type: {source_type}")

    expected = db.get("name")
    if not name or not user:
        raise BackupError(f"incomplete database credential reference for {app['application_name']}")
    if expected and name != expected:
        raise BackupError(f"database name mismatch for {app['application_name']}")

    defaults = workdir / f"{safe_name(app['slug'])}.mysql.cnf"
    defaults.write_text(
        "\n".join(
            [
                "[client]",
                f"host={host}",
                f"port={port}",
                f"user={user}",
                f"password={password}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    defaults.chmod(0o600)
    return defaults, name


def mysql_query(defaults: Path, query: str) -> str:
    completed = run(
        ["mysql", f"--defaults-extra-file={defaults}", "--batch", "--skip-column-names", "-e", query]
    )
    return completed.stdout or ""


def mysql_engine_summary(defaults: Path, database: str) -> dict[str, int]:
    escaped = database.replace("'", "''")
    query = (
        "SELECT COALESCE(ENGINE,'UNKNOWN'), COUNT(*) "
        "FROM information_schema.TABLES "
        f"WHERE TABLE_SCHEMA='{escaped}' AND TABLE_TYPE='BASE TABLE' "
        "GROUP BY COALESCE(ENGINE,'UNKNOWN')"
    )
    summary: dict[str, int] = {}
    for line in mysql_query(defaults, query).splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            summary[parts[0]] = int(parts[1])
    return summary


def mysql_table_count(defaults: Path, database: str) -> int:
    escaped = database.replace("'", "''")
    query = (
        "SELECT COUNT(*) FROM information_schema.TABLES "
        f"WHERE TABLE_SCHEMA='{escaped}' AND TABLE_TYPE='BASE TABLE'"
    )
    output = mysql_query(defaults, query).strip()
    return int(output or "0")


def dump_mysql(app: dict[str, Any], workdir: Path, backup_prefix: str, bucket: str, encryption: str) -> dict[str, Any]:
    defaults, database = mysql_credentials(app, workdir)
    engines = mysql_engine_summary(defaults, database)
    non_tx_engines = {
        engine: count
        for engine, count in engines.items()
        if engine.upper() not in {"INNODB", "PERFORMANCE_SCHEMA"}
    }
    if non_tx_engines:
        consistency_mode = "lock-tables-for-nontransactional-engines"
        dump_options = ["--lock-tables"]
    else:
        consistency_mode = "single-transaction"
        dump_options = ["--single-transaction"]

    table_count_before = mysql_table_count(defaults, database)
    dump_path = workdir / f"{safe_name(database)}.sql.gz"
    log(f"START db_backup app={app['slug']} database={database} consistency={consistency_mode}")
    started = time.time()
    dump_cmd = [
        "mysqldump",
        f"--defaults-extra-file={defaults}",
        "--quick",
        "--routines",
        "--triggers",
        "--events",
        "--hex-blob",
        *dump_options,
        database,
    ]
    proc = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    with gzip.open(dump_path, "wb", compresslevel=1) as gz:
        shutil.copyfileobj(proc.stdout, gz, length=1024 * 1024)
    stderr = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
    rc = proc.wait()
    if rc != 0:
        raise BackupError(f"mysqldump failed for {app['slug']} exit={rc} {stderr[:500]}")
    run(["gzip", "-t", str(dump_path)])
    duration = round(time.time() - started, 3)
    digest = sha256_file(dump_path)
    size = file_size(dump_path)
    checksum_path = workdir / f"{dump_path.name}.sha256"
    checksum_path.write_text(f"{digest}  {dump_path.name}\n", encoding="utf-8")
    db_key = f"{backup_prefix}/database/{dump_path.name}"
    checksum_key = f"{backup_prefix}/database/{dump_path.name}.sha256"
    db_head = put_s3(dump_path, bucket, db_key, encryption)
    put_s3(checksum_path, bucket, checksum_key, encryption)
    log(f"PASS db_backup app={app['slug']} database={database} size={size} duration={duration}s")
    return {
        "engine": app["database"]["engine"],
        "name": database,
        "dump_key": db_key,
        "dump_sha256": digest,
        "dump_size_bytes": size,
        "duration_seconds": duration,
        "table_count_before": table_count_before,
        "engine_summary": engines,
        "consistency_mode": consistency_mode,
        "s3_version_id": db_head.get("VersionId", "null"),
        "s3_encryption": db_head.get("ServerSideEncryption", "unknown"),
        "restore_test": {"status": "NOT_RUN"},
    }


def should_skip(rel: str, name: str, exclude_patterns: list[str]) -> bool:
    parts = set(Path(rel).parts)
    if parts & {".git", "vendor", "node_modules", "cache", "logs", "log", "sessions", "tmp", "temp"}:
        return True
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern):
            return True
    return False


def build_persistent_manifest(path: Path, path_id: str, excludes: list[str], output: Path) -> dict[str, Any]:
    files = 0
    total = 0
    with output.open("w", encoding="utf-8") as handle:
        for base, dirs, names in os.walk(path):
            rel_dir = os.path.relpath(base, path)
            if rel_dir == ".":
                rel_dir = ""
            dirs[:] = [
                d
                for d in dirs
                if not should_skip(os.path.join(rel_dir, d), d, excludes)
            ]
            for name in sorted(names):
                rel = os.path.normpath(os.path.join(rel_dir, name))
                if rel == "." or should_skip(rel, name, excludes):
                    continue
                file_path = Path(base) / name
                if not file_path.is_file():
                    continue
                digest = sha256_file(file_path)
                size = file_path.stat().st_size
                files += 1
                total += size
                handle.write(
                    json.dumps(
                        {
                            "path_id": path_id,
                            "relative_path": rel,
                            "bytes": size,
                            "sha256": digest,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
    return {"path_id": path_id, "files": files, "bytes": total, "manifest": str(output)}


def aws_sync_path(path: Path, bucket: str, key_prefix: str, excludes: list[str], encryption: str) -> None:
    cmd = [
        "aws",
        "s3",
        "sync",
        f"{path}/",
        s3_uri(bucket, key_prefix),
        "--sse",
        encryption,
        "--only-show-errors",
    ]
    for pattern in excludes:
        cmd.extend(["--exclude", pattern])
    run(cmd)


def backup_persistent(app: dict[str, Any], workdir: Path, backup_prefix: str, bucket: str, encryption: str) -> dict[str, Any]:
    configured_paths = app.get("persistent_paths", [])
    if not configured_paths:
        return {"status": "NOT_APPLICABLE", "paths": [], "total_files": 0, "total_bytes": 0, "restore_test": {"status": "NOT_APPLICABLE"}}

    default_excludes = app.get("exclude_paths", [])
    path_results = []
    total_files = 0
    total_bytes = 0
    combined_manifest = workdir / "persistent-manifest.jsonl"
    combined_manifest.write_text("", encoding="utf-8")
    log(f"START persistent_backup app={app['slug']} paths={len(configured_paths)}")
    started = time.time()
    for item in configured_paths:
        path_id = safe_name(item["id"])
        path = Path(item["path"])
        optional = bool(item.get("optional", False))
        if not path.exists():
            if optional:
                path_results.append({"path_id": path_id, "path": str(path), "status": "NOT_PRESENT", "files": 0, "bytes": 0})
                continue
            raise BackupError(f"persistent path missing for {app['slug']}: {path}")
        excludes = default_excludes + item.get("exclude_paths", [])
        manifest_part = workdir / f"persistent-{path_id}.jsonl"
        summary = build_persistent_manifest(path, path_id, excludes, manifest_part)
        current_prefix = f"{app['backup_prefix'].strip('/')}/{app['environment']}/persistent/current/{path_id}/"
        aws_sync_path(path, bucket, current_prefix, excludes, encryption)
        with combined_manifest.open("a", encoding="utf-8") as out, manifest_part.open("r", encoding="utf-8") as inp:
            shutil.copyfileobj(inp, out)
        total_files += summary["files"]
        total_bytes += summary["bytes"]
        path_results.append(
            {
                "path_id": path_id,
                "path": str(path),
                "status": "BACKED_UP",
                "files": summary["files"],
                "bytes": summary["bytes"],
                "current_prefix": current_prefix,
            }
        )
    digest = sha256_file(combined_manifest)
    manifest_key = f"{backup_prefix}/persistent/persistent-manifest.jsonl"
    manifest_head = put_s3(combined_manifest, bucket, manifest_key, encryption)
    duration = round(time.time() - started, 3)
    log(f"PASS persistent_backup app={app['slug']} files={total_files} bytes={total_bytes} duration={duration}s")
    return {
        "status": "BACKED_UP" if total_files or path_results else "NOT_APPLICABLE",
        "strategy": "versioned-s3-sync-current-prefix-plus-timestamped-manifest",
        "paths": path_results,
        "manifest_key": manifest_key,
        "manifest_sha256": digest,
        "manifest_s3_version_id": manifest_head.get("VersionId", "null"),
        "total_files": total_files,
        "total_bytes": total_bytes,
        "duration_seconds": duration,
        "restore_test": {"status": "NOT_RUN"},
    }


def start_isolated_mariadb(workdir: Path) -> tuple[Path, Path]:
    datadir = workdir / "restore-mariadb"
    socket_path = workdir / "restore.sock"
    pid_path = workdir / "restore.pid"
    datadir.mkdir(parents=True, exist_ok=True)
    run(
        [
            "mariadb-install-db",
            "--no-defaults",
            f"--datadir={datadir}",
            "--auth-root-authentication-method=normal",
            "--skip-test-db",
        ],
        stdout=subprocess.DEVNULL,
    )
    error_log = workdir / "restore-mariadb.err"
    proc = subprocess.Popen(
        [
            "mariadbd",
            "--no-defaults",
            "--datadir",
            str(datadir),
            "--socket",
            str(socket_path),
            "--pid-file",
            str(pid_path),
            "--skip-networking",
            "--user=root",
            "--innodb-buffer-pool-size=64M",
            f"--log-error={error_log}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    for _ in range(60):
        if proc.poll() is not None:
            raise BackupError(f"isolated mariadb exited early; see {error_log}")
        if socket_path.exists():
            try:
                run(["mysql", "--no-defaults", "--socket", str(socket_path), "-uroot", "-e", "SELECT 1"], stdout=subprocess.DEVNULL)
                return socket_path, pid_path
            except BackupError:
                pass
        time.sleep(1)
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    raise BackupError("isolated mariadb did not become ready")


def stop_isolated_mariadb(socket_path: Path, pid_path: Path) -> None:
    try:
        run(["mysqladmin", "--no-defaults", "--socket", str(socket_path), "-uroot", "shutdown"], check=False)
    finally:
        if pid_path.exists():
            try:
                os.kill(int(pid_path.read_text().strip()), signal.SIGTERM)
            except Exception:
                pass


def restore_test_mysql(app: dict[str, Any], db_result: dict[str, Any], workdir: Path, bucket: str) -> dict[str, Any]:
    if db_result.get("status") == "NOT_APPLICABLE":
        return {"status": "NOT_APPLICABLE"}
    socket_path, pid_path = start_isolated_mariadb(workdir)
    try:
        restore_db = f"restore_{safe_name(app['slug']).replace('-', '_')}_{int(time.time())}"[:60]
        started = time.time()
        dump_local = workdir / "restore-db.sql.gz"
        run(["aws", "s3", "cp", s3_uri(bucket, db_result["dump_key"]), str(dump_local), "--only-show-errors"])
        digest = sha256_file(dump_local)
        if digest != db_result["dump_sha256"]:
            raise BackupError(f"restore checksum mismatch for {app['slug']}")
        run(["mysql", "--no-defaults", "--socket", str(socket_path), "-uroot", "-e", f"CREATE DATABASE `{restore_db}`"])
        proc = subprocess.Popen(
            ["mysql", "--no-defaults", "--binary-mode=1", "--socket", str(socket_path), "-uroot", restore_db],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        assert proc.stdin is not None
        with gzip.open(dump_local, "rb") as dump:
            shutil.copyfileobj(dump, proc.stdin, length=1024 * 1024)
        proc.stdin.close()
        stderr = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        rc = proc.wait()
        if rc != 0:
            raise BackupError(f"isolated DB restore failed for {app['slug']}: {stderr[:500]}")
        output = run(
            [
                "mysql",
                "--no-defaults",
                "--socket",
                str(socket_path),
                "-uroot",
                "--batch",
                "--skip-column-names",
                "-e",
                f"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{restore_db}' AND TABLE_TYPE='BASE TABLE'",
            ]
        ).stdout.strip()
        restored_tables = int(output or "0")
        duration = round(time.time() - started, 3)
    finally:
        stop_isolated_mariadb(socket_path, pid_path)
    expected_tables = int(db_result.get("table_count_before") or 0)
    status = "PASS" if restored_tables == expected_tables and restored_tables > 0 else "FAIL"
    if status != "PASS":
        raise BackupError(f"restore table count mismatch for {app['slug']}: expected={expected_tables} actual={restored_tables}")
    log(f"PASS db_restore_test app={app['slug']} tables={restored_tables} duration={duration}s")
    return {
        "status": "PASS",
        "method": "isolated-temporary-mariadb",
        "duration_seconds": duration,
        "table_count_restored": restored_tables,
        "target": "temporary datadir under backup workdir; removed after validation",
    }


def sample_manifest_entries(manifest_path: Path, count: int) -> list[dict[str, Any]]:
    entries = []
    with manifest_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            entries.append(item)
            if len(entries) >= count:
                break
    return entries


def restore_test_persistent(app: dict[str, Any], persistent: dict[str, Any], workdir: Path, bucket: str, sample_count: int) -> dict[str, Any]:
    if persistent.get("status") == "NOT_APPLICABLE" or persistent.get("total_files", 0) == 0:
        return {"status": "NOT_APPLICABLE", "reason": "no persistent files configured or present"}
    manifest_local = workdir / "persistent-manifest-for-restore.jsonl"
    run(["aws", "s3", "cp", s3_uri(bucket, persistent["manifest_key"]), str(manifest_local), "--only-show-errors"])
    if sha256_file(manifest_local) != persistent["manifest_sha256"]:
        raise BackupError(f"persistent manifest checksum mismatch for {app['slug']}")
    entries = sample_manifest_entries(manifest_local, sample_count)
    restore_root = workdir / "persistent-restore-sample"
    restore_root.mkdir(parents=True, exist_ok=True)
    passed = 0
    path_prefix = {p["path_id"]: p["current_prefix"] for p in persistent.get("paths", []) if p.get("current_prefix")}
    started = time.time()
    for item in entries:
        prefix = path_prefix.get(item["path_id"])
        if not prefix:
            continue
        local = restore_root / item["path_id"] / item["relative_path"]
        local.parent.mkdir(parents=True, exist_ok=True)
        run(["aws", "s3", "cp", s3_uri(bucket, f"{prefix}{item['relative_path']}"), str(local), "--only-show-errors"])
        if sha256_file(local) != item["sha256"]:
            raise BackupError(f"persistent sample checksum mismatch for {app['slug']} path_id={item['path_id']}")
        passed += 1
    duration = round(time.time() - started, 3)
    log(f"PASS persistent_restore_test app={app['slug']} samples={passed} duration={duration}s")
    return {
        "status": "PASS",
        "method": "sample-download-from-private-s3-and-sha256-compare",
        "sample_count": passed,
        "duration_seconds": duration,
        "target": "temporary restore sample under backup workdir; removed after validation",
    }


def status_key(config: dict[str, Any], app: dict[str, Any], name: str) -> str:
    return f"{app['backup_prefix'].strip('/')}/{app['environment']}/status/{name}.json"


def write_manifest(config: dict[str, Any], app: dict[str, Any], manifest: dict[str, Any], workdir: Path) -> dict[str, Any]:
    bucket = app.get("backup_bucket") or config["defaults"]["backup_bucket"]
    encryption = app.get("encryption") or config["defaults"].get("encryption", "AES256")
    manifest_key = f"{manifest['backup_prefix']}/manifest.json"
    manifest_path = workdir / "manifest.json"
    checksum_path = workdir / "manifest.json.sha256"

    manifest_for_upload = dict(manifest)
    manifest_for_upload["manifest_s3_key"] = manifest_key
    manifest_path.write_text(json.dumps(manifest_for_upload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_sha256 = sha256_file(manifest_path)
    checksum_path.write_text(f"{manifest_sha256}  manifest.json\n", encoding="utf-8")

    head = put_s3(manifest_path, bucket, manifest_key, encryption)
    checksum_key = f"{manifest_key}.sha256"
    checksum_head = put_s3(checksum_path, bucket, checksum_key, encryption)

    manifest["manifest_s3_key"] = manifest_key
    manifest["manifest_s3_version_id"] = head.get("VersionId", "null")
    manifest["manifest_sha256"] = manifest_sha256
    manifest["manifest_checksum_s3_key"] = checksum_key
    manifest["manifest_checksum_s3_version_id"] = checksum_head.get("VersionId", "null")

    latest_path = workdir / "latest-status.json"
    latest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    put_s3(latest_path, bucket, status_key(config, app, "latest"), encryption)
    put_s3(latest_path, bucket, status_key(config, app, manifest["backup_timestamp_utc"]), encryption)
    return {"key": manifest_key, "version_id": head.get("VersionId", "null")}


def publish_alert(config: dict[str, Any], app: dict[str, Any], message: str) -> None:
    arn = app.get("monitoring", {}).get("sns_topic_arn") or config.get("monitoring", {}).get("default_sns_topic_arn")
    if not arn:
        return
    subject = f"Synergie backup failure: {app['application_name']}"[:100]
    try:
        run(["aws", "sns", "publish", "--topic-arn", arn, "--subject", subject, "--message", message], stdout=subprocess.DEVNULL)
    except BackupError as exc:
        log(f"WARN alert_publish_failed app={app['slug']} reason={str(exc)[:180]}")


def backup_one(config: dict[str, Any], app: dict[str, Any], timestamp: str, restore_test: bool, sample_count: int) -> dict[str, Any]:
    bucket = app.get("backup_bucket") or config["defaults"]["backup_bucket"]
    encryption = app.get("encryption") or config["defaults"].get("encryption", "AES256")
    backup_prefix = f"{app['backup_prefix'].strip('/')}/{app['environment']}/{timestamp}"
    workdir = Path(tempfile.mkdtemp(prefix=f"synergie-backup-{safe_name(app['slug'])}."))
    manifest: dict[str, Any] = {
        "application": app["application_name"],
        "slug": app["slug"],
        "environment": app["environment"],
        "production_host": app["production_host"],
        "root": app["root"],
        "backup_framework_version": FRAMEWORK_VERSION,
        "backup_timestamp_utc": timestamp,
        "backup_started_at": iso_now(),
        "source_host_identifier": socket.gethostname(),
        "aws_region": config["defaults"].get("aws_region", "ap-south-1"),
        "backup_bucket": bucket,
        "backup_prefix": backup_prefix,
        "encryption": encryption,
        "retention_class": app.get("retention_class", config["defaults"].get("retention_class")),
        "rpo_class": app.get("rpo_class"),
        "restore_test_class": app.get("restore_test_class"),
        "status": "STARTED",
        "database": {"status": "NOT_APPLICABLE"},
        "persistent": {"status": "NOT_APPLICABLE"},
        "production_impact": "no application deploy, restart, schema change, or production restore",
    }
    try:
        db_cfg = app.get("database", {})
        if db_cfg.get("engine") in {"mysql", "mariadb"} and db_cfg.get("name"):
            manifest["database"] = dump_mysql(app, workdir, backup_prefix, bucket, encryption)
        elif db_cfg.get("engine") == "postgresql":
            raise BackupError(f"postgresql configured but pg_dump is not available/implemented on this host for {app['slug']}")
        else:
            manifest["database"] = {"status": "NOT_APPLICABLE", "reason": "no database configured"}

        manifest["persistent"] = backup_persistent(app, workdir, backup_prefix, bucket, encryption)

        if restore_test:
            if manifest["database"].get("engine") in {"mysql", "mariadb"}:
                manifest["database"]["restore_test"] = restore_test_mysql(app, manifest["database"], workdir, bucket)
            manifest["persistent"]["restore_test"] = restore_test_persistent(
                app, manifest["persistent"], workdir, bucket, sample_count
            )
        manifest["status"] = "BACKUP_RECOVERY_CERTIFIED"
    except Exception as exc:
        manifest["status"] = "FAILED"
        manifest["failure"] = str(exc)[:1000]
        publish_alert(config, app, json.dumps({"application": app["application_name"], "status": "FAILED", "reason": manifest["failure"]}))
        log(f"FAIL app={app['slug']} reason={manifest['failure']}")
    finally:
        manifest["backup_finished_at"] = iso_now()
        try:
            manifest_ref = write_manifest(config, app, manifest, workdir)
            manifest["manifest_s3_key"] = manifest_ref["key"]
            manifest["manifest_s3_version_id"] = manifest_ref["version_id"]
        except Exception as exc:
            log(f"WARN manifest_upload_failed app={app['slug']} reason={str(exc)[:180]}")
        shutil.rmtree(workdir, ignore_errors=True)
    return manifest


def command_backup(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if config.get("defaults", {}).get("aws_region"):
        os.environ.setdefault("AWS_DEFAULT_REGION", config["defaults"]["aws_region"])
    apps = select_apps(config, args.app, args.all)
    timestamp = args.timestamp or utc_now()
    results = []
    for app in apps:
        log(f"START application_backup app={app['slug']} timestamp={timestamp}")
        results.append(backup_one(config, app, timestamp, args.restore_test, args.sample_count))
    summary = {
        "timestamp": timestamp,
        "total": len(results),
        "passed": sum(1 for item in results if item.get("status") == "BACKUP_RECOVERY_CERTIFIED"),
        "failed": sum(1 for item in results if item.get("status") == "FAILED"),
        "applications": [
            {
                "application": item["application"],
                "status": item["status"],
                "manifest_s3_key": item.get("manifest_s3_key"),
                "failure": item.get("failure"),
            }
            for item in results
        ],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 1 if summary["failed"] else 0


def read_manifest(path_or_s3: str) -> dict[str, Any]:
    if path_or_s3.startswith("s3://"):
        tmp = Path(tempfile.mkdtemp(prefix="synergie-manifest.")) / "manifest.json"
        run(["aws", "s3", "cp", path_or_s3, str(tmp), "--only-show-errors"])
        return json.loads(tmp.read_text(encoding="utf-8"))
    return json.loads(Path(path_or_s3).read_text(encoding="utf-8"))


def command_verify(args: argparse.Namespace) -> int:
    manifest = read_manifest(args.manifest)
    if manifest.get("aws_region"):
        os.environ.setdefault("AWS_DEFAULT_REGION", manifest["aws_region"])
    bucket = manifest["backup_bucket"]
    db = manifest.get("database", {})
    if db.get("dump_key") and db.get("dump_sha256"):
        tmp = Path(tempfile.mkdtemp(prefix="synergie-verify.")) / "db.sql.gz"
        run(["aws", "s3", "cp", s3_uri(bucket, db["dump_key"]), str(tmp), "--only-show-errors"])
        if sha256_file(tmp) != db["dump_sha256"]:
            raise BackupError("database checksum verification failed")
        run(["gzip", "-t", str(tmp)])
    persistent = manifest.get("persistent", {})
    if persistent.get("manifest_key") and persistent.get("manifest_sha256"):
        tmp_manifest = Path(tempfile.mkdtemp(prefix="synergie-verify-persistent.")) / "persistent.jsonl"
        run(["aws", "s3", "cp", s3_uri(bucket, persistent["manifest_key"]), str(tmp_manifest), "--only-show-errors"])
        if sha256_file(tmp_manifest) != persistent["manifest_sha256"]:
            raise BackupError("persistent manifest checksum verification failed")
    print(json.dumps({"status": "PASS", "application": manifest["application"], "manifest": args.manifest}, indent=2))
    return 0


def command_restore(args: argparse.Namespace) -> int:
    manifest = read_manifest(args.manifest)
    if manifest.get("aws_region"):
        os.environ.setdefault("AWS_DEFAULT_REGION", manifest["aws_region"])
    bucket = manifest["backup_bucket"]
    if args.target_path:
        target = Path(args.target_path).resolve()
        production_paths = [Path(manifest["root"]).resolve()]
        for item in manifest.get("persistent", {}).get("paths", []):
            if item.get("path"):
                production_paths.append(Path(item["path"]).resolve())
        if any(target == p or p in target.parents for p in production_paths):
            raise BackupError("refusing restore into production application path")
        if not SAFE_RESTORE_NAME.search(str(target)):
            raise BackupError("target path must clearly identify restore/recovery/test/tmp")
        target.mkdir(parents=True, exist_ok=True)
        persistent = manifest.get("persistent", {})
        prefixes = {p["path_id"]: p["current_prefix"] for p in persistent.get("paths", []) if p.get("current_prefix")}
        tmp_manifest = Path(tempfile.mkdtemp(prefix="synergie-restore-manifest.")) / "persistent.jsonl"
        run(["aws", "s3", "cp", s3_uri(bucket, persistent["manifest_key"]), str(tmp_manifest), "--only-show-errors"])
        if sha256_file(tmp_manifest) != persistent.get("manifest_sha256"):
            raise BackupError("persistent manifest checksum verification failed")
        with tmp_manifest.open("r", encoding="utf-8") as handle:
            for line in handle:
                item = json.loads(line)
                prefix = prefixes.get(item["path_id"])
                if not prefix:
                    continue
                local = target / item["path_id"] / item["relative_path"]
                local.parent.mkdir(parents=True, exist_ok=True)
                run(["aws", "s3", "cp", s3_uri(bucket, f"{prefix}{item['relative_path']}"), str(local), "--only-show-errors"])
                if sha256_file(local) != item["sha256"]:
                    raise BackupError("persistent restore checksum mismatch")
    if args.target_db_name:
        original = manifest.get("database", {}).get("name")
        if args.target_db_name == original or not SAFE_RESTORE_NAME.search(args.target_db_name):
            raise BackupError("refusing database restore to production-looking target DB name")
        raise BackupError("database restore requires a non-production client defaults file and is intentionally not automated here")
    print(json.dumps({"status": "PASS", "application": manifest["application"], "restored_path": args.target_path}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Synergie Production Application Backup Framework")
    sub = parser.add_subparsers(dest="command", required=True)

    backup = sub.add_parser("backup")
    backup.add_argument("--config", default=DEFAULT_CONFIG)
    backup.add_argument("--app")
    backup.add_argument("--all", action="store_true")
    backup.add_argument("--timestamp")
    backup.add_argument("--restore-test", action="store_true")
    backup.add_argument("--sample-count", type=int, default=5)
    backup.set_defaults(func=command_backup)

    verify = sub.add_parser("verify")
    verify.add_argument("--manifest", required=True)
    verify.set_defaults(func=command_verify)

    restore = sub.add_parser("restore")
    restore.add_argument("--manifest", required=True)
    restore.add_argument("--target-path")
    restore.add_argument("--target-db-name")
    restore.set_defaults(func=command_restore)
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
