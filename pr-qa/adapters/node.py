from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .base import (
    FAIL,
    PASS,
    WARNING,
    CheckResult,
    PRContext,
    TechnologyAdapter,
    command_exists,
    command_result,
    detect_package_manager,
    failed,
    find_named_files,
    first_existing_script,
    passed,
    read_json,
    restricted_license_hit,
    script_command,
    warning,
)


class NodeAdapter(TechnologyAdapter):
    key = "node"
    name = "Node.js"

    def detect(self, repo: Path) -> list[Path]:
        roots = []
        for package_json in find_named_files(repo, {"package.json"}):
            rel_parts = package_json.relative_to(repo).parts
            if "node_modules" not in rel_parts and "vendor" not in rel_parts:
                roots.append(package_json.parent)
        return sorted(set(roots))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            package = read_json(root / "package.json")
            scripts = package.get("scripts", {}) or {}
            config = ctx.adapter_config(self.key)
            check_names = config.get(
                "format_script_names",
                ["format:check", "format:ci", "prettier:check"],
            )
            script = first_existing_script(scripts, list(check_names))
            details_prefix = f"{ctx.rel(root)}: "
            if script:
                results.extend(self._ensure_dependencies(ctx, root, "Formatting"))
                if any(result.status == FAIL for result in results[-1:]):
                    continue
                outcome = ctx.run(script_command(detect_package_manager(root), script), cwd=root)
                results.append(
                    command_result(
                        "Formatting",
                        self.name,
                        outcome,
                        f"{details_prefix}`{script}` passed.",
                        f"{details_prefix}`{script}` failed.",
                        "Command execution skipped.",
                        score=8,
                    )
                )
                continue

            deps = self._merged_dependencies(package)
            if "prettier" in deps:
                results.extend(self._ensure_dependencies(ctx, root, "Formatting"))
                outcome = ctx.run(["npx", "prettier", "--check", "."], cwd=root)
                results.append(
                    command_result(
                        "Formatting",
                        self.name,
                        outcome,
                        f"{details_prefix}Prettier check passed.",
                        f"{details_prefix}Prettier check failed.",
                        "Command execution skipped.",
                        score=8,
                    )
                )
            else:
                results.append(warning("Formatting", self.name, f"{details_prefix}No check-only formatter configured."))
        return results

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            package = read_json(root / "package.json")
            scripts = package.get("scripts", {}) or {}
            names = list(ctx.adapter_config(self.key).get("lint_script_names", ["lint", "lint:ci"]))
            script = first_existing_script(scripts, names)
            prefix = f"{ctx.rel(root)}: "
            if not script:
                results.append(warning("Lint", self.name, f"{prefix}No linter script configured."))
                continue
            results.extend(self._ensure_dependencies(ctx, root, "Lint"))
            if any(result.status == FAIL for result in results[-1:]):
                continue
            outcome = ctx.run(script_command(detect_package_manager(root), script), cwd=root)
            results.append(
                command_result("Lint", self.name, outcome, f"{prefix}`{script}` passed.", f"{prefix}`{script}` failed.", score=10)
            )
        return results

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            package = read_json(root / "package.json")
            scripts = package.get("scripts", {}) or {}
            names = list(ctx.adapter_config(self.key).get("build_script_names", ["build", "production", "prod"]))
            script = first_existing_script(scripts, names)
            prefix = f"{ctx.rel(root)}: "
            if not script:
                results.append(passed("Build", self.name, f"{prefix}No Node build script configured."))
                continue
            results.extend(self._ensure_dependencies(ctx, root, "Build"))
            if any(result.status == FAIL for result in results[-1:]):
                continue
            outcome = ctx.run(script_command(detect_package_manager(root), script), cwd=root)
            results.append(
                command_result("Build", self.name, outcome, f"{prefix}`{script}` passed.", f"{prefix}`{script}` failed.", score=14)
            )
        return results

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            package = read_json(root / "package.json")
            scripts = package.get("scripts", {}) or {}
            names = list(ctx.adapter_config(self.key).get("test_script_names", ["test:ci", "test"]))
            script = first_existing_script(scripts, names)
            prefix = f"{ctx.rel(root)}: "
            if not script or self._looks_like_placeholder(scripts.get(script, "")):
                results.append(warning("Tests", self.name, f"{prefix}No automated test suite configured."))
                continue
            results.extend(self._ensure_dependencies(ctx, root, "Tests"))
            if any(result.status == FAIL for result in results[-1:]):
                continue
            outcome = ctx.run(script_command(detect_package_manager(root), script), cwd=root)
            results.append(
                command_result("Tests", self.name, outcome, f"{prefix}`{script}` passed.", f"{prefix}`{script}` failed.", score=14)
            )
        return results

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            manager = detect_package_manager(root)
            prefix = f"{ctx.rel(root)}: "
            package = read_json(root / "package.json")
            scripts = package.get("scripts", {}) or {}
            script = first_existing_script(
                scripts,
                list(ctx.adapter_config(self.key).get("dependency_audit_script_names", ["audit:ci"])),
            )
            if script:
                results.extend(self._ensure_dependencies(ctx, root, "Dependencies"))
                if any(result.status == FAIL for result in results[-1:]):
                    continue
                outcome = ctx.run(script_command(manager, script), cwd=root)
                results.append(
                    command_result(
                        "Dependencies",
                        self.name,
                        outcome,
                        f"{prefix}`{script}` dependency audit passed.",
                        f"{prefix}`{script}` dependency audit failed.",
                        score=18,
                    )
                )
            elif manager == "npm" and (root / "package-lock.json").exists() and command_exists("npm"):
                outcome = ctx.run(["npm", "audit", "--audit-level=high", "--json"], cwd=root)
            elif manager == "pnpm" and command_exists("pnpm"):
                outcome = ctx.run(["pnpm", "audit", "--audit-level", "high", "--json"], cwd=root)
            elif manager == "yarn" and command_exists("yarn"):
                outcome = ctx.run(["yarn", "npm", "audit", "--recursive", "--severity", "high", "--json"], cwd=root)
            else:
                results.append(failed("Dependencies", self.name, f"{prefix}No supported Node lockfile audit is available.", score=18))
                continue
            if script:
                continue
            if outcome.ok:
                results.append(passed("Dependencies", self.name, f"{prefix}Dependency audit passed."))
            elif self._audit_is_inherited_baseline(ctx, root, manager, outcome):
                results.append(
                    warning(
                        "Dependencies",
                        self.name,
                        f"{prefix}Inherited baseline dependency vulnerabilities detected; no new high or critical Node audit findings.",
                        [outcome.concise_output()],
                    )
                )
            else:
                results.append(failed("Dependencies", self.name, f"{prefix}Dependency audit found high or critical vulnerabilities.", [outcome.concise_output()], score=18))
        return results

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            package = read_json(root / "package.json")
            findings: list[str] = []
            for manifest in self._node_module_manifests(root):
                data = read_json(manifest)
                licence = str(data.get("license", "") or "UNKNOWN")
                if restricted_license_hit(licence):
                    name = data.get("name", manifest.parent.name)
                    findings.append(f"{name}: {licence}")
            own_licence = str(package.get("license", "") or "")
            if own_licence and restricted_license_hit(own_licence):
                findings.append(f"{package.get('name', 'package')}: {own_licence}")
            prefix = f"{ctx.rel(root)}: "
            if findings:
                results.append(warning("Licence", self.name, f"{prefix}Potential restricted or unknown licences detected.", findings[:20]))
            else:
                results.append(passed("Licence", self.name, f"{prefix}No GPL, AGPL, unknown, or unlicensed Node packages detected from installed metadata."))
        return results

    def _ensure_dependencies(self, ctx: PRContext, root: Path, gate: str) -> list[CheckResult]:
        key = f"node:{root}"
        if key in ctx.prepared:
            return []
        ctx.prepared.add(key)
        config = ctx.adapter_config(self.key)
        if config.get("install", "auto") is False or not ctx.runtime_enabled("install_dependencies", True):
            return []
        manager = detect_package_manager(root)
        if not command_exists(manager):
            return [failed(gate, self.name, f"{ctx.rel(root)}: `{manager}` is not available on the runner.")]
        install_command = self._install_command(root, manager)
        if install_command is None:
            if not ctx.runtime_enabled("allow_network_installs", True):
                return [warning(gate, self.name, f"{ctx.rel(root)}: dependency install skipped because no lockfile exists.")]
            install_command = script_command(manager, "install")
            if manager == "npm":
                install_command = ["npm", "install"]
        outcome = ctx.run(install_command, cwd=root)
        if outcome.ok:
            return []
        return [failed(gate, self.name, f"{ctx.rel(root)}: dependency installation failed.", [outcome.concise_output()], score=10)]

    def _install_command(self, root: Path, manager: str) -> list[str] | None:
        if manager == "npm" and (root / "package-lock.json").exists():
            return ["npm", "ci"]
        if manager == "pnpm" and (root / "pnpm-lock.yaml").exists():
            return ["pnpm", "install", "--frozen-lockfile"]
        if manager == "yarn" and (root / "yarn.lock").exists():
            return ["yarn", "install", "--frozen-lockfile"]
        if manager == "bun" and ((root / "bun.lockb").exists() or (root / "bun.lock").exists()):
            return ["bun", "install", "--frozen-lockfile"]
        return None

    def _merged_dependencies(self, package: dict[str, Any]) -> set[str]:
        names: set[str] = set()
        for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            names.update((package.get(key) or {}).keys())
        return names

    def _looks_like_placeholder(self, script: str) -> bool:
        lowered = script.lower()
        return "no test specified" in lowered or "exit 1" in lowered and "echo" in lowered

    def _audit_is_inherited_baseline(self, ctx: PRContext, root: Path, manager: str, outcome: Any) -> bool:
        head_findings = self._audit_fingerprints(outcome)
        if not head_findings:
            return False
        base_ref = self._audit_base_ref(ctx)
        if not base_ref:
            return False
        with tempfile.TemporaryDirectory(prefix="pr-qa-node-audit-base-") as tmp:
            base_root = Path(tmp)
            if not self._populate_base_package_metadata(ctx, root, base_ref, base_root):
                return False
            command = self._audit_command(manager)
            if not command:
                return False
            base_outcome = ctx.run(command, cwd=base_root)
            base_findings = self._audit_fingerprints(base_outcome)
        return bool(base_findings) and head_findings.issubset(base_findings)

    def _audit_base_ref(self, ctx: PRContext) -> str:
        pull_request = ctx.event.get("pull_request", {}) or {}
        return str(pull_request.get("base", {}).get("sha") or ctx.base_ref or "")

    def _populate_base_package_metadata(self, ctx: PRContext, root: Path, base_ref: str, destination: Path) -> bool:
        root_rel = ctx.rel(root)
        prefix = "" if root_rel in {"", "."} else root_rel.rstrip("/") + "/"
        copied = False
        for name in ["package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"]:
            rel = prefix + name
            completed = subprocess.run(["git", "show", f"{base_ref}:{rel}"], cwd=ctx.repo, capture_output=True, check=False)
            if completed.returncode != 0:
                continue
            target = destination / name
            target.write_bytes(completed.stdout)
            copied = copied or name == "package.json"
        return copied

    def _audit_command(self, manager: str) -> list[str]:
        if manager == "npm":
            return ["npm", "audit", "--audit-level=high", "--json"]
        if manager == "pnpm":
            return ["pnpm", "audit", "--audit-level", "high", "--json"]
        if manager == "yarn":
            return ["yarn", "npm", "audit", "--recursive", "--severity", "high", "--json"]
        return []

    def _audit_fingerprints(self, outcome: Any) -> set[str]:
        payload = self._audit_json_payload(outcome)
        if not payload:
            return set()
        findings: set[str] = set()
        vulnerabilities = payload.get("vulnerabilities")
        if isinstance(vulnerabilities, dict):
            for package_name, raw in vulnerabilities.items():
                if not isinstance(raw, dict):
                    continue
                severity = str(raw.get("severity", "unknown"))
                via_parts: list[str] = []
                for item in raw.get("via", []) or []:
                    if isinstance(item, dict):
                        via_parts.append(
                            "|".join(
                                str(item.get(key, ""))
                                for key in ["source", "name", "title", "severity", "range"]
                            )
                        )
                    else:
                        via_parts.append(str(item))
                range_value = str(raw.get("range", ""))
                findings.add(f"{package_name}|{severity}|{range_value}|{';'.join(sorted(via_parts))}")
            return findings
        advisories = payload.get("advisories")
        if isinstance(advisories, dict):
            for raw in advisories.values():
                if not isinstance(raw, dict):
                    continue
                findings.add(
                    "|".join(
                        str(raw.get(key, ""))
                        for key in ["module_name", "severity", "title", "vulnerable_versions"]
                    )
                )
        return findings

    def _audit_json_payload(self, outcome: Any) -> dict[str, Any]:
        text = "\n".join(part for part in [getattr(outcome, "stdout", ""), getattr(outcome, "stderr", "")] if part)
        if not text.strip():
            return {}
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            pass
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return {}
        try:
            parsed = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _node_module_manifests(self, root: Path) -> list[Path]:
        node_modules = root / "node_modules"
        if not node_modules.is_dir():
            return []
        manifests: list[Path] = []
        for child in node_modules.iterdir():
            if child.name.startswith("."):
                continue
            if child.name.startswith("@") and child.is_dir():
                manifests.extend(sorted(path / "package.json" for path in child.iterdir() if (path / "package.json").exists()))
            elif (child / "package.json").exists():
                manifests.append(child / "package.json")
        return manifests
