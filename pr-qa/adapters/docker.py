from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, command_result, failed, find_files, passed, warning


class DockerAdapter(TechnologyAdapter):
    key = "docker"
    name = "Docker"

    def detect(self, repo: Path) -> list[Path]:
        files = find_files(repo, ["Dockerfile", "Dockerfile.*", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"])
        return sorted(set(path.parent for path in files))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Formatting", self.name, "Docker has no formatter configured by default.")]

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if not command_exists("hadolint"):
            return [warning("Lint", self.name, "hadolint is not installed on the runner.")]
        results = []
        for dockerfile in find_files(ctx.repo, ["Dockerfile", "Dockerfile.*"]):
            results.append(command_result("Lint", self.name, ctx.run(["hadolint", str(dockerfile)], cwd=ctx.repo), f"{ctx.rel(dockerfile)}: hadolint passed.", f"{ctx.rel(dockerfile)}: hadolint failed.", score=10))
        return results

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if not ctx.adapter_config(self.key).get("build_images", False):
            return [passed("Build", self.name, "Docker image builds are disabled by repository config.")]
        if not command_exists("docker"):
            return [warning("Build", self.name, "`docker` is not available on the runner.")]
        results = []
        for dockerfile in find_files(ctx.repo, ["Dockerfile", "Dockerfile.*"]):
            tag = "synergie-pr-qa-" + ctx.rel(dockerfile).replace("/", "-").replace(".", "-").lower()
            results.append(command_result("Build", self.name, ctx.run(["docker", "build", "-f", str(dockerfile), "-t", tag, "."], cwd=dockerfile.parent), f"{ctx.rel(dockerfile)}: Docker build passed.", f"{ctx.rel(dockerfile)}: Docker build failed.", score=12))
        return results

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Tests", self.name, "No automated Docker runtime test suite configured.")]

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if not command_exists("trivy"):
            return [failed("Dependencies", self.name, "Trivy is mandatory and is not installed on the runner.", score=18)]
        return [command_result("Dependencies", self.name, ctx.run(["trivy", "fs", "--severity", "HIGH,CRITICAL", "--exit-code", "1", "."], cwd=ctx.repo), "Trivy filesystem scan passed.", "Trivy found high or critical vulnerabilities.", score=18)]

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Licence", self.name, "Docker base image licence review requires SBOM tooling.")]
