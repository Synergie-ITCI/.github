#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_NODE_VERSION = "20"
PREFERRED_MAJOR_ORDER = [24, 22, 20]
ALLOWED_MAJOR_MIN = 20
ALLOWED_MAJOR_MAX = 30


def main() -> int:
    repo = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
    version = resolve_node_version(repo)
    print(f"node-version={version}")
    return 0


def resolve_node_version(repo: Path) -> str:
    explicit = resolve_version_file(repo)
    if explicit:
        return explicit

    majors = sorted(explicit_engine_majors(repo))
    for preferred in PREFERRED_MAJOR_ORDER:
        if preferred in majors:
            return str(preferred)
    if majors:
        return str(majors[0])
    return DEFAULT_NODE_VERSION


def resolve_version_file(repo: Path) -> str:
    for name in [".nvmrc", ".node-version"]:
        path = repo / name
        if not path.is_file():
            continue
        value = path.read_text(encoding="utf-8", errors="ignore").strip()
        version = normalize_version_token(value)
        if version:
            return version
    return ""


def explicit_engine_majors(repo: Path) -> set[int]:
    majors: set[int] = set()
    for package_json in repo.rglob("package.json"):
        rel_parts = package_json.relative_to(repo).parts
        if any(part in {"node_modules", "vendor", ".pr-qa-framework"} for part in rel_parts):
            continue
        package = read_json(package_json)
        engines = package.get("engines", {}) if isinstance(package, dict) else {}
        node_range = str(engines.get("node", "") if isinstance(engines, dict) else "")
        for major in re.findall(r"(?<![0-9])(?:v)?([0-9]{2})(?:\.[0-9x*]+)?", node_range):
            parsed = int(major)
            if ALLOWED_MAJOR_MIN <= parsed <= ALLOWED_MAJOR_MAX:
                majors.add(parsed)
    return majors


def normalize_version_token(value: str) -> str:
    token = value.splitlines()[0].strip() if value else ""
    if not token or token in {"node", "system", "lts/*"}:
        return ""
    token = token.removeprefix("v")
    match = re.fullmatch(r"([0-9]{2})(?:\.[0-9]+(?:\.[0-9]+)?)?", token)
    if not match:
        return ""
    major = int(match.group(1))
    if ALLOWED_MAJOR_MIN <= major <= ALLOWED_MAJOR_MAX:
        return token
    return ""


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


if __name__ == "__main__":
    raise SystemExit(main())
