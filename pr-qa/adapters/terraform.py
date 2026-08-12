from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, command_result, failed, find_files, warning


class TerraformAdapter(TechnologyAdapter):
    key = "terraform"
    name = "Terraform/OpenTofu"

    def detect(self, repo: Path) -> list[Path]:
        return sorted(set(path.parent for path in find_files(repo, ["*.tf"])))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        cli = self._cli()
        if not cli:
            return [warning("Formatting", self.name, "`tofu` or `terraform` is not available on the runner.")]
        return [command_result("Formatting", self.name, ctx.run([cli, "fmt", "-check", "-recursive"], cwd=root), f"{ctx.rel(root)}: {cli} fmt passed.", f"{ctx.rel(root)}: {cli} fmt failed.", score=8) for root in roots]

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if command_exists("tflint"):
            return [command_result("Lint", self.name, ctx.run(["tflint", "--recursive"], cwd=root), f"{ctx.rel(root)}: tflint passed.", f"{ctx.rel(root)}: tflint failed.", score=10) for root in roots]
        return [warning("Lint", self.name, "tflint is not installed on the runner.")]

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        cli = self._cli()
        if not cli:
            return [warning("Build", self.name, "`tofu` or `terraform` is not available on the runner.")]
        results = []
        init_backend = bool(ctx.adapter_config(self.key).get("init_backend", False))
        for root in roots:
            init_command = [cli, "init", "-input=false", "-no-color"]
            if not init_backend:
                init_command.append("-backend=false")
            init = ctx.run(init_command, cwd=root)
            if not init.ok:
                results.append(command_result("Build", self.name, init, f"{ctx.rel(root)}: {cli} init passed.", f"{ctx.rel(root)}: {cli} init failed.", score=12))
                continue
            validate = ctx.run([cli, "validate", "-no-color"], cwd=root)
            results.append(command_result("Build", self.name, validate, f"{ctx.rel(root)}: {cli} validate passed.", f"{ctx.rel(root)}: {cli} validate failed.", score=12))
        return results

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Tests", self.name, "No automated Terraform test suite configured.")]

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if command_exists("tfsec"):
            return [command_result("Dependencies", self.name, ctx.run(["tfsec", "."], cwd=root), f"{ctx.rel(root)}: tfsec passed.", f"{ctx.rel(root)}: tfsec failed.", score=18) for root in roots]
        if command_exists("checkov"):
            return [command_result("Dependencies", self.name, ctx.run(["checkov", "-d", "."], cwd=root), f"{ctx.rel(root)}: Checkov passed.", f"{ctx.rel(root)}: Checkov failed.", score=18) for root in roots]
        return [failed("Dependencies", self.name, "No Terraform security scanner is installed on the runner.", score=18)]

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Licence", self.name, "Terraform provider licence inventory requires SBOM tooling.")]

    def _cli(self) -> str:
        if command_exists("tofu"):
            return "tofu"
        if command_exists("terraform"):
            return "terraform"
        return ""
