from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, command_result, failed, find_files, read_text, warning


class KubernetesAdapter(TechnologyAdapter):
    key = "kubernetes"
    name = "Kubernetes"

    def detect(self, repo: Path) -> list[Path]:
        roots = []
        for path in find_files(repo, ["*.yml", "*.yaml"]):
            text = read_text(path)
            if "apiVersion:" in text and "kind:" in text:
                roots.append(path.parent)
        return sorted(set(roots))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Formatting", self.name, "Kubernetes manifests have no formatter configured by default.")]

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        manifest_paths = [ctx.rel(path) for path in find_files(ctx.repo, ["*.yml", "*.yaml"]) if "apiVersion:" in read_text(path) and "kind:" in read_text(path)]
        if not manifest_paths:
            return []
        if command_exists("kubeconform"):
            return [command_result("Lint", self.name, ctx.run(["kubeconform", "-strict"] + manifest_paths, cwd=ctx.repo), "kubeconform passed.", "kubeconform failed.", score=10)]
        if command_exists("kubeval"):
            return [command_result("Lint", self.name, ctx.run(["kubeval"] + manifest_paths, cwd=ctx.repo), "kubeval passed.", "kubeval failed.", score=10)]
        if command_exists("kubectl"):
            return [command_result("Lint", self.name, ctx.run(["kubectl", "apply", "--dry-run=client", "-f", path], cwd=ctx.repo), f"{path}: kubectl dry run passed.", f"{path}: kubectl dry run failed.", score=10) for path in manifest_paths]
        return [warning("Lint", self.name, "No Kubernetes validator is installed on the runner.")]

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Build", self.name, "Kubernetes build validation is not applicable.")]

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Tests", self.name, "No automated Kubernetes policy test suite configured.")]

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [failed("Dependencies", self.name, "Kubernetes image vulnerability scanning requires Trivy, Grype, or registry scanning.", score=18)]

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Licence", self.name, "Kubernetes licence inventory requires image SBOM tooling.")]
