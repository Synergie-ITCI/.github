from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, command_result, failed, find_files, find_named_files, warning


class DotnetAdapter(TechnologyAdapter):
    key = "dotnet"
    name = ".NET"

    def detect(self, repo: Path) -> list[Path]:
        markers = find_files(repo, ["*.sln", "*.csproj", "*.fsproj", "*.vbproj"])
        roots = [path.parent for path in markers if "obj" not in path.parts and "bin" not in path.parts]
        return sorted(set(roots))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return self._run(ctx, roots, "Formatting", ["dotnet", "format", "--verify-no-changes"], "dotnet format passed.", "dotnet format failed.", 8)

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Lint", self.name, ".NET linting should be configured through analyzers; build treats warnings according to project settings.")]

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        self._restore(ctx, roots)
        return self._run(ctx, roots, "Build", ["dotnet", "build", "--configuration", "Release", "--no-restore"], "dotnet build passed.", "dotnet build failed.", 12)

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if not roots:
            return []
        test_roots = [root for root in roots if "test" in root.name.lower()]
        if not test_roots:
            return [warning("Tests", self.name, "No automated test suite configured.")]
        self._restore(ctx, test_roots)
        return self._run(ctx, test_roots, "Tests", ["dotnet", "test", "--configuration", "Release", "--no-restore"], "dotnet test passed.", "dotnet test failed.", 14)

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return self._run(ctx, roots, "Dependencies", ["dotnet", "list", "package", "--vulnerable", "--include-transitive"], "dotnet vulnerable package check passed.", "dotnet vulnerable package check found vulnerabilities.", 18)

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Licence", self.name, ".NET licence inventory requires a configured SBOM or licence tool.")]

    def _restore(self, ctx: PRContext, roots: list[Path]) -> None:
        if not ctx.runtime_enabled("install_dependencies", True) or not command_exists("dotnet"):
            return
        for root in roots:
            key = f"dotnet:{root}"
            if key not in ctx.prepared:
                ctx.prepared.add(key)
                ctx.run(["dotnet", "restore"], cwd=root)

    def _run(self, ctx: PRContext, roots: list[Path], gate: str, command: list[str], ok: str, fail: str, score: int) -> list[CheckResult]:
        if not command_exists(command[0]):
            if gate == "Dependencies":
                return [failed(gate, self.name, "`dotnet` is not available on the runner.", score=score)]
            return [warning(gate, self.name, "`dotnet` is not available on the runner.")]
        results = []
        for root in roots:
            outcome = ctx.run(command, cwd=root)
            text = outcome.concise_output()
            if gate == "Dependencies" and "has no vulnerable packages" in text.lower():
                results.append(command_result(gate, self.name, outcome, f"{ctx.rel(root)}: {ok}", f"{ctx.rel(root)}: {fail}", score=score))
            elif gate == "Dependencies" and outcome.ok and "vulnerable" in text.lower() and "has the following vulnerable packages" in text.lower():
                results.append(failed(gate, self.name, f"{ctx.rel(root)}: {fail}", [text], score=score))
            else:
                results.append(command_result(gate, self.name, outcome, f"{ctx.rel(root)}: {ok}", f"{ctx.rel(root)}: {fail}", score=score))
        return results
