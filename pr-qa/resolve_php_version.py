#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_PHP_VERSION = "8.2"
PREFERRED_MAJOR_MINOR_ORDER = ["8.4", "8.3", "8.2"]
ALLOWED_VERSION_MIN = (8, 2)
ALLOWED_VERSION_MAX = (8, 4)


def main() -> int:
    repo = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
    version = resolve_php_version(repo)
    print(f"php-version={version}")
    return 0


def resolve_php_version(repo: Path) -> str:
    versions = sorted(explicit_php_versions(repo), key=version_key, reverse=True)
    for preferred in PREFERRED_MAJOR_MINOR_ORDER:
        if preferred in versions:
            return preferred
    return DEFAULT_PHP_VERSION


def explicit_php_versions(repo: Path) -> set[str]:
    versions: set[str] = set()
    for composer_file in find_composer_metadata(repo):
        data = read_json(composer_file)
        if not isinstance(data, dict):
            continue
        for requirement in php_requirements(data, composer_file.name):
            versions.update(version for version in normalize_php_versions(requirement) if allowed_version(version))
    return versions


def find_composer_metadata(repo: Path) -> list[Path]:
    metadata = []
    for name in ("composer.lock", "composer.json"):
        for path in repo.rglob(name):
            rel_parts = path.relative_to(repo).parts
            if any(part in {"vendor", "node_modules", ".pr-qa-framework"} for part in rel_parts):
                continue
            metadata.append(path)
    return metadata


def php_requirements(data: dict[str, Any], filename: str) -> list[str]:
    requirements: list[str] = []
    if filename == "composer.lock":
        for section in ("packages", "packages-dev"):
            packages = data.get(section, [])
            if not isinstance(packages, list):
                continue
            for package in packages:
                if not isinstance(package, dict):
                    continue
                requirement = (package.get("require") or {}).get("php") if isinstance(package.get("require"), dict) else None
                if requirement:
                    requirements.append(str(requirement))
        platform = data.get("platform")
        if isinstance(platform, dict) and platform.get("php"):
            requirements.append(str(platform["php"]))
        platform_dev = data.get("platform-dev")
        if isinstance(platform_dev, dict) and platform_dev.get("php"):
            requirements.append(str(platform_dev["php"]))
        return requirements

    require = data.get("require")
    if isinstance(require, dict) and require.get("php"):
        requirements.append(str(require["php"]))
    require_dev = data.get("require-dev")
    if isinstance(require_dev, dict) and require_dev.get("php"):
        requirements.append(str(require_dev["php"]))
    return requirements


def normalize_php_versions(requirement: str) -> set[str]:
    versions: set[str] = set()
    for match in re.finditer(r"(?<![0-9])([78])\.([0-9]+)(?:\.[0-9]+)?", requirement):
        major = int(match.group(1))
        minor = int(match.group(2))
        versions.add(f"{major}.{minor}")
    return versions


def allowed_version(version: str) -> bool:
    key = version_key(version)
    return ALLOWED_VERSION_MIN <= key <= ALLOWED_VERSION_MAX


def version_key(version: str) -> tuple[int, int]:
    major, minor = version.split(".", 1)
    return int(major), int(minor)


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


if __name__ == "__main__":
    raise SystemExit(main())
