from __future__ import annotations

from pathlib import Path

from .base import (
    FAIL,
    CheckResult,
    PRContext,
    TechnologyAdapter,
    command_exists,
    command_result,
    failed,
    find_named_files,
    passed,
    read_text,
    restricted_license_hit,
    warning,
)


class PythonAdapter(TechnologyAdapter):
    key = "python"
    name = "Python"

    def detect(self, repo: Path) -> list[Path]:
        markers = {"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile", "poetry.lock", "uv.lock"}
        roots = [path.parent for path in find_named_files(repo, markers)]
        if not roots and any(repo.rglob("*.py")):
            roots = [repo]
        return sorted(set(roots))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            self._ensure_dependencies(ctx, root, results, "Formatting")
            if results and results[-1].status == FAIL:
                continue
            pyproject = read_text(root / "pyproject.toml")
            ran = False
            if "tool.black" in pyproject or command_exists("black"):
                outcome = ctx.run(["black", "--check", "."], cwd=root)
                results.append(command_result("Formatting", self.name, outcome, f"{prefix}Black check passed.", f"{prefix}Black check failed.", score=8))
                ran = True
            if "tool.ruff" in pyproject or command_exists("ruff"):
                outcome = ctx.run(["ruff", "format", "--check", "."], cwd=root)
                if outcome.ok:
                    results.append(passed("Formatting", self.name, f"{prefix}Ruff format check passed."))
                elif "unrecognized subcommand" not in outcome.concise_output().lower():
                    results.append(failed("Formatting", self.name, f"{prefix}Ruff format check failed.", [outcome.concise_output()], score=8))
                ran = True
            if not ran:
                results.append(warning("Formatting", self.name, f"{prefix}No Python formatter configured."))
        return results

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            self._ensure_dependencies(ctx, root, results, "Lint")
            if results and results[-1].status == FAIL:
                continue
            pyproject = read_text(root / "pyproject.toml")
            if "tool.ruff" in pyproject or command_exists("ruff"):
                outcome = ctx.run(["ruff", "check", "."], cwd=root)
                results.append(command_result("Lint", self.name, outcome, f"{prefix}Ruff passed.", f"{prefix}Ruff failed.", score=10))
            elif command_exists("flake8"):
                outcome = ctx.run(["flake8", "."], cwd=root)
                results.append(command_result("Lint", self.name, outcome, f"{prefix}Flake8 passed.", f"{prefix}Flake8 failed.", score=10))
            else:
                results.append(warning("Lint", self.name, f"{prefix}No Python linter configured."))
        return results

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            outcome = ctx.run(["python", "-m", "compileall", "-q", "."], cwd=root)
            results.append(command_result("Build", self.name, outcome, f"{prefix}Python bytecode compilation passed.", f"{prefix}Python bytecode compilation failed.", score=12))
        return results

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            self._ensure_dependencies(ctx, root, results, "Tests")
            if results and results[-1].status == FAIL:
                continue
            has_tests = (root / "tests").exists() or "pytest" in read_text(root / "pyproject.toml")
            if not has_tests:
                results.append(warning("Tests", self.name, f"{prefix}No automated test suite configured."))
                continue
            if command_exists("pytest"):
                outcome = ctx.run(["pytest"], cwd=root)
            else:
                outcome = ctx.run(["python", "-m", "pytest"], cwd=root)
            results.append(command_result("Tests", self.name, outcome, f"{prefix}Pytest passed.", f"{prefix}Pytest failed.", score=14))
        return results

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            command = self._pip_audit_command(root)
            if not command:
                results.append(warning("Dependencies", self.name, f"{prefix}No Python dependency manifest found; pip-audit is not applicable."))
                continue
            outcome = ctx.run(command, cwd=root)
            if outcome.ok:
                results.append(passed("Dependencies", self.name, f"{prefix}pip-audit passed."))
            elif "No module named" in outcome.concise_output():
                results.append(failed("Dependencies", self.name, f"{prefix}pip-audit is mandatory and is not installed on the runner.", score=18))
            else:
                results.append(failed("Dependencies", self.name, f"{prefix}pip-audit found vulnerabilities.", [outcome.concise_output()], score=18))
        return results

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            text = "\n".join(read_text(root / name) for name in ["requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock"])
            risky = [line.strip() for line in text.splitlines() if restricted_license_hit(line)]
            prefix = f"{ctx.rel(root)}: "
            if risky:
                results.append(warning("Licence", self.name, f"{prefix}Potential GPL, AGPL, or unknown Python licence hints detected.", risky[:20]))
            else:
                results.append(warning("Licence", self.name, f"{prefix}Python licence inventory requires pip-licenses or SBOM tooling for full coverage."))
        return results

    def _ensure_dependencies(self, ctx: PRContext, root: Path, results: list[CheckResult], gate: str) -> None:
        key = f"python:{root}"
        if key in ctx.prepared:
            return
        ctx.prepared.add(key)
        if ctx.adapter_config(self.key).get("install", "auto") is False or not ctx.runtime_enabled("install_dependencies", True):
            return
        if not ctx.runtime_enabled("allow_network_installs", True):
            results.append(warning(gate, self.name, f"{ctx.rel(root)}: Python dependency install skipped by policy."))
            return
        commands: list[list[str]] = []
        pyproject = read_text(root / "pyproject.toml")
        if (root / "requirements-dev.txt").exists():
            commands.append(["python", "-m", "pip", "install", "-r", "requirements-dev.txt"])
        if (root / "requirements.txt").exists():
            commands.append(["python", "-m", "pip", "install", "-r", "requirements.txt"])
        if (root / "pyproject.toml").exists():
            if "optional-dependencies" in pyproject and "dev" in pyproject:
                commands.append(["python", "-m", "pip", "install", "-e", ".[dev]"])
            else:
                commands.append(["python", "-m", "pip", "install", "-e", "."])
        for command in commands[:2]:
            outcome = ctx.run(command, cwd=root)
            if not outcome.ok:
                results.append(failed(gate, self.name, f"{ctx.rel(root)}: Python dependency install failed.", [outcome.concise_output()], score=10))
                return

    def _pip_audit_command(self, root: Path) -> list[str]:
        base = ["pip-audit"] if command_exists("pip-audit") else ["python", "-m", "pip_audit"]
        requirements = [name for name in ["requirements.txt", "requirements-dev.txt"] if (root / name).exists()]
        if requirements:
            command = [*base]
            for name in requirements:
                command.extend(["-r", name])
            return command
        if (root / "pyproject.toml").exists():
            return [*base, "."]
        return []
