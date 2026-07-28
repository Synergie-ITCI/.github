from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, command_result, find_files, failed, passed, read_text, warning


class GitHubActionsAdapter(TechnologyAdapter):
    key = "github_actions"
    name = "GitHub Actions"

    def detect(self, repo: Path) -> list[Path]:
        workflows = find_files(repo, [".github/workflows/*.yml", ".github/workflows/*.yaml"])
        return sorted(set(path.parent for path in workflows))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Formatting", self.name, "GitHub Actions formatting is not configured by default.")]

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        workflow_files = find_files(ctx.repo, [".github/workflows/*.yml", ".github/workflows/*.yaml"])
        if not workflow_files:
            return []
        if command_exists("actionlint"):
            return [command_result("Lint", self.name, ctx.run(["actionlint"] + [ctx.rel(path) for path in workflow_files], cwd=ctx.repo), "actionlint passed.", "actionlint failed.", score=10)]
        failures = []
        for path in workflow_files:
            text = read_text(path)
            if "jobs:" not in text or ("\non:" not in text and not text.startswith("on:")):
                failures.append(f"{ctx.rel(path)}: missing required `on` or `jobs` key.")
        if failures:
            return [failed("Lint", self.name, "GitHub Actions structural validation failed.", failures, score=10)]
        return [warning("Lint", self.name, "actionlint is not installed; basic workflow structure check passed.")]

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [passed("Build", self.name, "GitHub Actions changes are validated through lint and deployment-safety gates.")]

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Tests", self.name, "No automated GitHub Actions workflow test suite configured.")]

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Dependencies", self.name, "GitHub Actions dependency security is covered by pinned actions policy and dependency review where enabled.")]

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Licence", self.name, "GitHub Actions licence inventory is advisory only.")]
