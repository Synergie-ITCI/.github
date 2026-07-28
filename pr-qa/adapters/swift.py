from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, command_result, failed, find_files, find_named_files, warning


class SwiftAdapter(TechnologyAdapter):
    key = "swift"
    name = "Swift"

    def detect(self, repo: Path) -> list[Path]:
        roots = [path.parent for path in find_named_files(repo, {"Package.swift"})]
        roots.extend(path.parent for path in find_files(repo, ["*.xcodeproj/project.pbxproj", "*.xcworkspace/contents.xcworkspacedata"]))
        return sorted(set(roots))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if command_exists("swiftformat"):
            return [command_result("Formatting", self.name, ctx.run(["swiftformat", "--lint", "."], cwd=root), f"{ctx.rel(root)}: swiftformat passed.", f"{ctx.rel(root)}: swiftformat failed.", score=8) for root in roots]
        return [warning("Formatting", self.name, "swiftformat is not installed on the runner.")]

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if command_exists("swiftlint"):
            return [command_result("Lint", self.name, ctx.run(["swiftlint", "lint"], cwd=root), f"{ctx.rel(root)}: swiftlint passed.", f"{ctx.rel(root)}: swiftlint failed.", score=10) for root in roots]
        return [warning("Lint", self.name, "swiftlint is not installed on the runner.")]

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if not command_exists("swift"):
            return [warning("Build", self.name, "`swift` is not available on the runner.")]
        return [command_result("Build", self.name, ctx.run(["swift", "build"], cwd=root), f"{ctx.rel(root)}: swift build passed.", f"{ctx.rel(root)}: swift build failed.", score=12) for root in roots if (root / "Package.swift").exists()]

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        package_roots = [root for root in roots if (root / "Package.swift").exists()]
        if not package_roots:
            return [warning("Tests", self.name, "No automated Swift Package test suite configured.")]
        if not command_exists("swift"):
            return [warning("Tests", self.name, "`swift` is not available on the runner.")]
        return [command_result("Tests", self.name, ctx.run(["swift", "test"], cwd=root), f"{ctx.rel(root)}: swift test passed.", f"{ctx.rel(root)}: swift test failed.", score=14) for root in package_roots]

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [failed("Dependencies", self.name, "Swift dependency vulnerability audit requires configured tooling on the runner.", score=18)]

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Licence", self.name, "Swift licence inventory requires configured SBOM or licence tooling.")]
