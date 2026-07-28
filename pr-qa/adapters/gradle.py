from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, command_result, failed, find_named_files, passed, read_text, warning


class GradleAdapter(TechnologyAdapter):
    key = "gradle"
    name = "Kotlin/Gradle"

    def detect(self, repo: Path) -> list[Path]:
        markers = {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew"}
        return sorted(set(path.parent for path in find_named_files(repo, markers)))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results = []
        for root in roots:
            build_text = self._build_text(root)
            command = self._gradle(root)
            if "spotless" in build_text:
                results.append(command_result("Formatting", self.name, ctx.run(command + ["spotlessCheck"], cwd=root), f"{ctx.rel(root)}: Spotless passed.", f"{ctx.rel(root)}: Spotless failed.", score=8))
            elif "ktlint" in build_text:
                results.append(command_result("Formatting", self.name, ctx.run(command + ["ktlintCheck"], cwd=root), f"{ctx.rel(root)}: ktlint passed.", f"{ctx.rel(root)}: ktlint failed.", score=8))
            else:
                results.append(warning("Formatting", self.name, f"{ctx.rel(root)}: No Gradle formatter configured."))
        return results

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results = []
        for root in roots:
            build_text = self._build_text(root)
            command = self._gradle(root)
            if "com.android" in build_text:
                results.append(command_result("Lint", self.name, ctx.run(command + ["lint"], cwd=root), f"{ctx.rel(root)}: Android lint passed.", f"{ctx.rel(root)}: Android lint failed.", score=10))
            elif "checkstyle" in build_text:
                results.append(command_result("Lint", self.name, ctx.run(command + ["checkstyleMain"], cwd=root), f"{ctx.rel(root)}: Checkstyle passed.", f"{ctx.rel(root)}: Checkstyle failed.", score=10))
            else:
                results.append(warning("Lint", self.name, f"{ctx.rel(root)}: No Gradle linter configured."))
        return results

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return self._run(ctx, roots, "Build", ["assemble"], "Gradle assemble passed.", "Gradle assemble failed.", 12)

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return self._run(ctx, roots, "Tests", ["test"], "Gradle tests passed.", "Gradle tests failed.", 14)

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results = []
        for root in roots:
            build_text = self._build_text(root)
            if "dependencycheck" in build_text.replace("-", "").lower():
                results.append(command_result("Dependencies", self.name, ctx.run(self._gradle(root) + ["dependencyCheckAnalyze"], cwd=root), f"{ctx.rel(root)}: OWASP dependency check passed.", f"{ctx.rel(root)}: OWASP dependency check failed.", score=18))
            else:
                results.append(failed("Dependencies", self.name, f"{ctx.rel(root)}: No Gradle dependency vulnerability audit configured.", score=18))
        return results

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Licence", self.name, "Gradle licence inventory requires a configured licence plugin or SBOM generation.")]

    def _gradle(self, root: Path) -> list[str]:
        if (root / "gradlew").exists():
            return ["bash", "./gradlew", "--no-daemon"]
        return ["gradle", "--no-daemon"]

    def _run(self, ctx: PRContext, roots: list[Path], gate: str, task: list[str], ok: str, fail: str, score: int) -> list[CheckResult]:
        results = []
        for root in roots:
            command = self._gradle(root)
            if command[0] != "bash" and not command_exists(command[0]):
                results.append(warning(gate, self.name, f"{ctx.rel(root)}: Gradle is not available on the runner."))
                continue
            outcome = ctx.run(command + task, cwd=root)
            if gate == "Tests" and "task '" in outcome.concise_output().lower() and "not found" in outcome.concise_output().lower():
                results.append(warning("Tests", self.name, f"{ctx.rel(root)}: No automated test suite configured."))
            else:
                results.append(command_result(gate, self.name, outcome, f"{ctx.rel(root)}: {ok}", f"{ctx.rel(root)}: {fail}", score=score))
        return results

    def _build_text(self, root: Path) -> str:
        return "\n".join(read_text(root / name) for name in ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"])
