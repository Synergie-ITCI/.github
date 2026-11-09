"""Prepare an explicitly opted-in database in the ephemeral PR-QA PostgreSQL service."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path

import tomllib

IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,62}")
SQL = r"""
SELECT format('CREATE ROLE %I LOGIN', :'qa_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'qa_role')
\gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'qa_db', :'qa_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'qa_db')
\gexec
"""


def configured_database(repo: Path) -> tuple[str, str] | None:
    pyproject = repo / "pyproject.toml"
    if not pyproject.is_file():
        return None
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    section = data.get("tool", {}).get("synergie_pr_qa", {}).get("postgres_test")
    if section is None:
        return None
    if not isinstance(section, dict) or set(section) != {"role", "database"}:
        raise ValueError("Invalid test PostgreSQL configuration")
    role, database = section["role"], section["database"]
    if (
        not isinstance(role, str)
        or not isinstance(database, str)
        or not IDENTIFIER.fullmatch(role)
        or not IDENTIFIER.fullmatch(database)
        or role in {"postgres", "runner"}
        or role.startswith("pg_")
        or database in {"postgres", "template0", "template1", "telepathy_test"}
    ):
        raise ValueError("Invalid test PostgreSQL identifiers")
    return role, database


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    config = configured_database(args.repo)
    if config is None:
        return 0
    role, database = config
    result = subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            "5432",
            "-U",
            "postgres",
            "-d",
            "telepathy_test",
            "-v",
            "ON_ERROR_STOP=1",
            "-v",
            f"qa_role={role}",
            "-v",
            f"qa_db={database}",
        ],
        input=SQL,
        text=True,
        capture_output=True,
        check=False,
        env={
            "PATH": os.environ.get("PATH", ""),
            "PGCONNECT_TIMEOUT": "5",
            "PGPASSFILE": "/dev/null",
        },
    )
    if result.returncode:
        raise RuntimeError("Could not prepare isolated PR-QA PostgreSQL database")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
