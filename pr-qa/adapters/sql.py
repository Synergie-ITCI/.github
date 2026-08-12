from __future__ import annotations

import re
from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, failed, find_files, passed, read_text, warning


class SqlAdapter(TechnologyAdapter):
    key = "sql"
    name = "SQL/PostgreSQL"

    def detect(self, repo: Path) -> list[Path]:
        files = find_files(repo, ["*.sql", "**/*.sql"])
        return sorted({path.parent for path in files})

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        changed = self._changed_sql(ctx, roots)
        if not changed:
            return [passed("Formatting", self.name, "No changed SQL files detected.")]
        return [warning("Formatting", self.name, "No central SQL formatter configured; repository migration validators must cover syntax.", changed)]

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        findings: list[str] = []
        warnings: list[str] = []
        for rel in self._changed_sql(ctx, roots):
            text = read_text(ctx.repo / rel)
            if re.search(r"\b(drop\s+database|drop\s+schema|truncate\s+table)\b", text, flags=re.IGNORECASE):
                findings.append(f"{rel}: destructive database-wide SQL operation is not allowed in PR QA.")
            if re.search(r"\b(delete\s+from|update\s+\w+)\b", text, flags=re.IGNORECASE) and not re.search(r"\bwhere\b", text, flags=re.IGNORECASE):
                warnings.append(f"{rel}: data-changing SQL without an obvious WHERE clause requires reviewer attention.")
        if findings:
            return [failed("Lint", self.name, "SQL migration lint failed.", findings, score=18)]
        if warnings:
            return [warning("Lint", self.name, "SQL migration lint completed with reviewer warnings.", warnings)]
        return [passed("Lint", self.name, "SQL migration lint passed.")]

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [passed("Build", self.name, "SQL migrations have no standalone build step.")]

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [passed("Tests", self.name, "SQL migration execution is covered by repository-specific database validation.")]

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [passed("Dependencies", self.name, "SQL migrations do not introduce package dependencies.")]

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [passed("Licence", self.name, "SQL migrations do not introduce third-party licences.")]

    def _changed_sql(self, ctx: PRContext, roots: list[Path]) -> list[str]:
        changed: set[str] = set()
        for root in roots:
            for rel in ctx.changed_under(root):
                if Path(rel).suffix.lower() == ".sql":
                    changed.add(rel)
        return sorted(changed)
