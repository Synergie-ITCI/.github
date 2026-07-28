from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, command_result, failed, find_named_files, passed, warning


class GoAdapter(TechnologyAdapter):
    key = "go"
    name = "Go"

    def detect(self, repo: Path) -> list[Path]:
        return sorted(set(path.parent for path in find_named_files(repo, {"go.mod"})))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results = []
        for root in roots:
            if not command_exists("gofmt"):
                results.append(warning("Formatting", self.name, f"{ctx.rel(root)}: gofmt is not available."))
                continue
            outcome = ctx.run(["gofmt", "-l", "."], cwd=root)
            if outcome.ok and not outcome.stdout.strip():
                results.append(passed("Formatting", self.name, f"{ctx.rel(root)}: gofmt passed."))
            else:
                results.append(failed("Formatting", self.name, f"{ctx.rel(root)}: gofmt found unformatted files.", [outcome.concise_output()], score=8))
        return results

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return self._run_for_roots(ctx, roots, "Lint", ["go", "vet", "./..."], "go vet passed.", "go vet failed.", 10)

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        self._prepare(ctx, roots)
        return self._run_for_roots(ctx, roots, "Build", ["go", "build", "./..."], "go build passed.", "go build failed.", 12)

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        self._prepare(ctx, roots)
        return self._run_for_roots(ctx, roots, "Tests", ["go", "test", "./..."], "go test passed.", "go test failed.", 14)

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if not command_exists("govulncheck"):
            return [failed("Dependencies", self.name, "govulncheck is mandatory and is not installed on the runner.", score=18)]
        return self._run_for_roots(ctx, roots, "Dependencies", ["govulncheck", "./..."], "govulncheck passed.", "govulncheck found vulnerabilities.", 18)

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if not command_exists("go-licenses"):
            return [warning("Licence", self.name, "go-licenses is not installed on the runner.")]
        return self._run_for_roots(ctx, roots, "Licence", ["go-licenses", "check", "./..."], "Go licence check passed.", "Go licence check failed.", 0)

    def _prepare(self, ctx: PRContext, roots: list[Path]) -> None:
        if not ctx.runtime_enabled("install_dependencies", True):
            return
        for root in roots:
            key = f"go:{root}"
            if key in ctx.prepared:
                continue
            ctx.prepared.add(key)
            if command_exists("go"):
                ctx.run(["go", "mod", "download"], cwd=root)

    def _run_for_roots(self, ctx: PRContext, roots: list[Path], gate: str, command: list[str], ok: str, fail: str, score: int) -> list[CheckResult]:
        results: list[CheckResult] = []
        if not command_exists(command[0]):
            return [warning(gate, self.name, f"`{command[0]}` is not available on the runner.")]
        for root in roots:
            outcome = ctx.run(command, cwd=root)
            results.append(command_result(gate, self.name, outcome, f"{ctx.rel(root)}: {ok}", f"{ctx.rel(root)}: {fail}", score=score))
        return results
