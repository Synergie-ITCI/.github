from __future__ import annotations

from pathlib import Path

from .base import CheckResult, PRContext, TechnologyAdapter, command_exists, command_result, failed, find_named_files, warning


class RustAdapter(TechnologyAdapter):
    key = "rust"
    name = "Rust"

    def detect(self, repo: Path) -> list[Path]:
        return sorted(set(path.parent for path in find_named_files(repo, {"Cargo.toml"})))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return self._run(ctx, roots, "Formatting", ["cargo", "fmt", "--check"], "cargo fmt passed.", "cargo fmt failed.", 8)

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return self._run(ctx, roots, "Lint", ["cargo", "clippy", "--", "-D", "warnings"], "cargo clippy passed.", "cargo clippy failed.", 10)

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        self._prepare(ctx, roots)
        return self._run(ctx, roots, "Build", ["cargo", "build", "--locked"], "cargo build passed.", "cargo build failed.", 12)

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        self._prepare(ctx, roots)
        return self._run(ctx, roots, "Tests", ["cargo", "test", "--locked"], "cargo test passed.", "cargo test failed.", 14)

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        if not command_exists("cargo-audit"):
            return [failed("Dependencies", self.name, "cargo-audit is mandatory and is not installed on the runner.", score=18)]
        if command_exists("cargo-audit"):
            return self._run(ctx, roots, "Dependencies", ["cargo-audit", "audit"], "cargo audit passed.", "cargo audit found vulnerabilities.", 18)
        return []

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return [warning("Licence", self.name, "Rust licence inventory requires cargo-deny or cargo-about on the runner.")]

    def _prepare(self, ctx: PRContext, roots: list[Path]) -> None:
        if not ctx.runtime_enabled("install_dependencies", True) or not command_exists("cargo"):
            return
        for root in roots:
            key = f"rust:{root}"
            if key not in ctx.prepared:
                ctx.prepared.add(key)
                ctx.run(["cargo", "fetch", "--locked"], cwd=root)

    def _run(self, ctx: PRContext, roots: list[Path], gate: str, command: list[str], ok: str, fail: str, score: int) -> list[CheckResult]:
        if not command_exists(command[0]):
            return [warning(gate, self.name, f"`{command[0]}` is not available on the runner.")]
        return [command_result(gate, self.name, ctx.run(command, cwd=root), f"{ctx.rel(root)}: {ok}", f"{ctx.rel(root)}: {fail}", score=score) for root in roots]
