"""Inspect both release JS source maps for exception-covered packages."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

PLATFORMS = ("android", "ios")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def packages_in_source(source: str) -> set[str]:
    parts = source.replace("\\", "/").split("/")
    found: set[str] = set()
    for index, part in enumerate(parts):
        if part != "node_modules" or index + 1 >= len(parts):
            continue
        package = parts[index + 1]
        if package.startswith("@") and index + 2 < len(parts):
            package += "/" + parts[index + 2]
        if package and package not in {".", ".."}:
            found.add(package)
    return found


def collect(repo: Path, head: str, covered: set[str]) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", head) or not covered:
        raise ValueError("Invalid staging SHA or covered package set")
    directory = repo / "staging-mobile-bundle-evidence"
    platforms: dict[str, dict] = {}
    for platform in PLATFORMS:
        bundle = directory / f"{platform}.bundle"
        source_map = directory / f"{platform}.map"
        if (
            not bundle.is_file()
            or not source_map.is_file()
            or not bundle.stat().st_size
        ):
            raise ValueError(f"{platform} release bundle or source map is missing")
        data = json.loads(source_map.read_text(encoding="utf-8"))
        sources = data.get("sources")
        if data.get("version") != 3 or not isinstance(sources, list) or not sources:
            raise ValueError(f"{platform} release source map is invalid")
        if not all(isinstance(source, str) and source for source in sources):
            raise ValueError(f"{platform} release module list is invalid")
        modules = sorted(source.replace(str(repo), "<repo>") for source in sources)
        packages = sorted(
            set().union(*(packages_in_source(source) for source in sources))
        )
        if not packages:
            raise ValueError(f"{platform} release source map has no package modules")
        platforms[platform] = {
            "bundle_sha256": sha256(bundle),
            "source_map_sha256": sha256(source_map),
            "module_count": len(sources),
            "modules": modules,
            "packages": packages,
            "covered_present": sorted(covered.intersection(packages)),
        }
    return {"staging_sha": head, "platforms": platforms}


def main() -> int:
    if len(sys.argv) != 4:
        return 1
    repo, manifest_file, head = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        covered = {entry["package"] for entry in manifest["advisories"]}
        evidence = collect(repo, head, covered)
        output = repo / "staging-mobile-bundle-evidence" / "bundle-evidence.json"
        output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        if any(item["covered_present"] for item in evidence["platforms"].values()):
            raise ValueError("Exception-covered package appears in a release JS bundle")
        print("Android and iOS release JS bundles exclude exception-covered packages")
        return 0
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"Release bundle check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
