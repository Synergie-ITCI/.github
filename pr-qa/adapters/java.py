from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, command_result, failed, find_named_files, read_text, warning


class JavaAdapter(TechnologyAdapter):
    key = "java"
    name = "Java/Maven"

    def detect(self, repo: Path) -> list[Path]:
        roots = []
        for pom in find_named_files(repo, {"pom.xml"}):
            if not (pom.parent / "build.gradle").exists() and not (pom.parent / "build.gradle.kts").exists():
                roots.append(pom.parent)
        return sorted(set(roots))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results = []
        for root in roots:
            pom = read_text(root / "pom.xml")
            if "spotless" in pom:
                results.append(command_result("Formatting", self.name, ctx.run(["mvn", "-B", "spotless:check"], cwd=root), f"{ctx.rel(root)}: Spotless passed.", f"{ctx.rel(root)}: Spotless failed.", score=8))
            else:
                results.append(warning("Formatting", self.name, f"{ctx.rel(root)}: No Maven formatter configured."))
        return results

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results = []
        for root in roots:
            pom = read_text(root / "pom.xml")
            if "checkstyle" in pom:
                results.append(command_result("Lint", self.name, ctx.run(["mvn", "-B", "checkstyle:check"], cwd=root), f"{ctx.rel(root)}: Checkstyle passed.", f"{ctx.rel(root)}: Checkstyle failed.", score=10))
            else:
                results.append(warning("Lint", self.name, f"{ctx.rel(root)}: No Maven linter configured."))
        return results

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return self._run(ctx, roots, "Build", ["mvn", "-B", "-DskipTests", "package"], "Maven package passed.", "Maven package failed.", 12)

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return self._run(ctx, roots, "Tests", ["mvn", "-B", "test"], "Maven tests passed.", "Maven tests failed.", 14)

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results = []
        for root in roots:
            pom = read_text(root / "pom.xml")
            if "dependency-check" in pom:
                results.append(command_result("Dependencies", self.name, ctx.run(["mvn", "-B", "org.owasp:dependency-check-maven:check"], cwd=root), f"{ctx.rel(root)}: OWASP dependency check passed.", f"{ctx.rel(root)}: OWASP dependency check failed.", score=18))
            else:
                results.append(failed("Dependencies", self.name, f"{ctx.rel(root)}: No Maven dependency vulnerability audit configured.", score=18))
        return results

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Licence", self.name, "Java licence inventory requires a configured Maven licence plugin or SBOM generation.")]

    def _run(self, ctx: PRContext, roots: list[Path], gate: str, command: list[str], ok: str, fail: str, score: int) -> list[CheckResult]:
        if not command_exists("mvn"):
            return [warning(gate, self.name, "`mvn` is not available on the runner.")]
        return [command_result(gate, self.name, ctx.run(command, cwd=root), f"{ctx.rel(root)}: {ok}", f"{ctx.rel(root)}: {fail}", score=score) for root in roots]
