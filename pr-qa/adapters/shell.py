from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, failed, find_files, passed, warning


class ShellAdapter(TechnologyAdapter):
    key = "shell"
    name = "Shell"

    def detect(self, repo: Path) -> list[Path]:
        files = find_files(repo, ["*.sh", "*.bash"])
        return sorted({path.parent for path in files})

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        changed = self._changed_shell(ctx, roots)
        if not changed:
            return [passed("Formatting", self.name, "No changed shell scripts detected.")]
        return [warning("Formatting", self.name, "No central shell formatter configured; shell syntax lint remains mandatory.", changed[:30])]

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        changed = self._changed_shell(ctx, roots)
        if not changed:
            return [passed("Lint", self.name, "No changed shell scripts detected.")]
        if not command_exists("bash"):
            return [failed("Lint", self.name, "`bash` is not available, shell syntax lint cannot run.", score=10)]
        failures: list[str] = []
        for rel in changed:
            outcome = ctx.run(["bash", "-n", rel], cwd=ctx.repo)
            if not outcome.ok:
                failures.append(outcome.concise_output() or rel)
        if failures:
            return [failed("Lint", self.name, "Shell syntax lint failed.", failures[:20], score=10)]
        return [passed("Lint", self.name, "Shell syntax lint passed.", changed[:30])]

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [passed("Build", self.name, "Shell scripts have no standalone build step.")]

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Tests", self.name, "Shell scripts require repository-level tests or human review for runtime semantics.")]

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [passed("Dependencies", self.name, "Shell scripts do not introduce package dependencies.")]

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [passed("Licence", self.name, "Shell scripts do not introduce third-party licences.")]

    def _changed_shell(self, ctx: PRContext, roots: list[Path]) -> list[str]:
        changed: set[str] = set()
        for root in roots:
            for rel in ctx.changed_under(root):
                if Path(rel).suffix.lower() in {".sh", ".bash"}:
                    changed.add(rel)
        return sorted(changed)
