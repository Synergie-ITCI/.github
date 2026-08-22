from __future__ import annotations

from pathlib import Path

from .base import (
    FAIL,
    WARNING,
    CheckResult,
    PRContext,
    TechnologyAdapter,
    command_exists,
    command_result,
    failed,
    find_named_files,
    passed,
    read_json,
    restricted_license_hit,
    warning,
)


class PhpAdapter(TechnologyAdapter):
    key = "php"
    name = "PHP/Laravel"

    def detect(self, repo: Path) -> list[Path]:
        roots = [path.parent for path in find_named_files(repo, {"composer.json"})]
        if not roots and any(repo.rglob("*.php")):
            roots = [repo]
        return sorted(set(roots))

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            self._ensure_composer(ctx, root, results, "Formatting")
            if results and results[-1].status == FAIL:
                continue
            if (root / "vendor/bin/pint").exists():
                php_files = self._changed_php_files(ctx, root)
                if not php_files:
                    results.append(passed("Formatting", self.name, f"{prefix}No changed PHP files to format."))
                    continue
                outcome = ctx.run(["php", "vendor/bin/pint", "--test", *self._root_relative_files(ctx, root, php_files)], cwd=root)
                if not outcome.ok and baseline_inherited_pint_failure(ctx, outcome.concise_output()):
                    results.append(
                        CheckResult(
                            "Formatting",
                            WARNING,
                            f"{prefix}Laravel Pint reported only inherited baseline formatting issues; future formatting drift remains blocking.",
                            pint_failure_paths(outcome.concise_output()),
                            technology=self.name,
                            blocking=False,
                        )
                    )
                    continue
                results.append(command_result("Formatting", self.name, outcome, f"{prefix}Laravel Pint passed.", f"{prefix}Laravel Pint failed.", score=8))
            elif (root / "vendor/bin/php-cs-fixer").exists() or (root / ".php-cs-fixer.php").exists():
                command = ["php", "vendor/bin/php-cs-fixer", "fix", "--dry-run", "--diff"]
                outcome = ctx.run(command, cwd=root)
                results.append(command_result("Formatting", self.name, outcome, f"{prefix}PHP CS Fixer dry run passed.", f"{prefix}PHP CS Fixer dry run failed.", score=8))
            else:
                results.append(warning("Formatting", self.name, f"{prefix}No check-only PHP formatter configured."))
        return results

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            self._ensure_composer(ctx, root, results, "Lint")
            if results and results[-1].status == FAIL:
                continue
            if (root / "vendor/bin/phpcs").exists():
                outcome = ctx.run(["php", "vendor/bin/phpcs"], cwd=root)
                results.append(command_result("Lint", self.name, outcome, f"{prefix}PHP_CodeSniffer passed.", f"{prefix}PHP_CodeSniffer failed.", score=10))
                continue
            if not command_exists("php"):
                results.append(warning("Lint", self.name, f"{prefix}`php` is not available, syntax lint skipped."))
                continue
            php_files = self._changed_php_files(ctx, root)
            if not php_files:
                results.append(passed("Lint", self.name, f"{prefix}No changed PHP files to syntax lint."))
                continue
            failures: list[str] = []
            for rel in php_files[:250]:
                outcome = ctx.run(["php", "-l", rel], cwd=ctx.repo)
                if not outcome.ok:
                    failures.append(outcome.concise_output() or rel)
            if failures:
                results.append(failed("Lint", self.name, f"{prefix}PHP syntax lint failed.", failures[:20], score=10))
            else:
                results.append(passed("Lint", self.name, f"{prefix}PHP syntax lint passed for changed files."))
        return results

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            if (root / "composer.json").exists() and command_exists("composer"):
                outcome = ctx.run(["composer", "validate", "--strict", "--no-check-publish"], cwd=root)
                results.append(command_result("Build", self.name, outcome, f"{prefix}Composer validation passed.", f"{prefix}Composer validation failed.", score=12))
            else:
                results.append(passed("Build", self.name, f"{prefix}No PHP build step configured."))
        return results

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            package = read_json(root / "composer.json")
            scripts = package.get("scripts", {}) or {}
            self._ensure_composer(ctx, root, results, "Tests")
            if results and results[-1].status == FAIL:
                continue
            if "test" in scripts and command_exists("composer"):
                outcome = ctx.run(["composer", "run", "test"], cwd=root)
                results.append(command_result("Tests", self.name, outcome, f"{prefix}Composer test script passed.", f"{prefix}Composer test script failed.", score=14))
            elif (root / "vendor/bin/phpunit").exists():
                outcome = ctx.run(["php", "vendor/bin/phpunit"], cwd=root)
                results.append(command_result("Tests", self.name, outcome, f"{prefix}PHPUnit passed.", f"{prefix}PHPUnit failed.", score=14))
            elif (root / "artisan").exists() and command_exists("php"):
                outcome = ctx.run(["php", "artisan", "test"], cwd=root)
                results.append(command_result("Tests", self.name, outcome, f"{prefix}Laravel test command passed.", f"{prefix}Laravel test command failed.", score=14))
            elif (root / "phpunit.xml").exists() or (root / "phpunit.xml.dist").exists():
                results.append(warning("Tests", self.name, f"{prefix}PHPUnit config exists, but no runnable PHPUnit binary was found."))
            else:
                results.append(warning("Tests", self.name, f"{prefix}No automated test suite configured."))
        return results

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            if not (root / "composer.lock").exists():
                results.append(failed("Dependencies", self.name, f"{prefix}No composer.lock found for deterministic audit.", score=18))
                continue
            if not command_exists("composer"):
                results.append(failed("Dependencies", self.name, f"{prefix}`composer` is not available, dependency audit cannot run.", score=18))
                continue
            outcome = ctx.run(["composer", "audit", "--format=json"], cwd=root)
            if outcome.ok:
                results.append(passed("Dependencies", self.name, f"{prefix}Composer audit passed."))
            else:
                results.append(failed("Dependencies", self.name, f"{prefix}Composer audit found vulnerabilities.", [outcome.concise_output()], score=18))
        return results

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for root in roots:
            prefix = f"{ctx.rel(root)}: "
            if command_exists("composer") and (root / "composer.lock").exists():
                outcome = ctx.run(["composer", "licenses", "--format=json"], cwd=root)
                text = outcome.stdout + outcome.stderr
                risky = self._risky_licence_hits(text)
                if risky:
                    results.append(warning("Licence", self.name, f"{prefix}Potential GPL, AGPL, or unknown PHP licences detected.", risky[:20]))
                elif outcome.ok:
                    results.append(passed("Licence", self.name, f"{prefix}Composer licence report has no restricted licences."))
                else:
                    results.append(warning("Licence", self.name, f"{prefix}Composer licence report could not be generated.", [outcome.concise_output()]))
            else:
                text = (root / "composer.lock").read_text(encoding="utf-8", errors="ignore") if (root / "composer.lock").exists() else ""
                risky = self._risky_licence_hits(text)
                if risky:
                    results.append(warning("Licence", self.name, f"{prefix}Potential restricted PHP licences found in composer.lock.", risky[:20]))
                else:
                    results.append(warning("Licence", self.name, f"{prefix}Composer licence tooling unavailable."))
        return results

    def _ensure_composer(self, ctx: PRContext, root: Path, results: list[CheckResult], gate: str) -> None:
        key = f"php:{root}"
        if key in ctx.prepared:
            return
        ctx.prepared.add(key)
        if not (root / "composer.json").exists():
            return
        if ctx.adapter_config(self.key).get("install", "auto") is False or not ctx.runtime_enabled("install_dependencies", True):
            return
        if not command_exists("composer"):
            results.append(warning(gate, self.name, f"{ctx.rel(root)}: `composer` is not available, dependency install skipped."))
            return
        if not (root / "composer.lock").exists() and not ctx.runtime_enabled("allow_network_installs", True):
            results.append(warning(gate, self.name, f"{ctx.rel(root)}: Composer install skipped because no lockfile exists."))
            return
        outcome = ctx.run(["composer", "install", "--no-interaction", "--prefer-dist", "--no-progress"], cwd=root)
        if not outcome.ok:
            results.append(failed(gate, self.name, f"{ctx.rel(root)}: Composer install failed.", [outcome.concise_output()], score=10))

    def _changed_php_files(self, ctx: PRContext, root: Path) -> list[str]:
        root_rel = ctx.rel(root)
        files = []
        for rel in ctx.changed_files:
            if not rel.endswith(".php"):
                continue
            if not (ctx.repo / rel).is_file():
                continue
            if root_rel == "." or rel.startswith(root_rel.rstrip("/") + "/"):
                files.append(rel)
        return files

    def _root_relative_files(self, ctx: PRContext, root: Path, files: list[str]) -> list[str]:
        root_rel = ctx.rel(root)
        if root_rel == ".":
            return files
        prefix = root_rel.rstrip("/") + "/"
        return [rel[len(prefix) :] for rel in files if rel.startswith(prefix)]

    def _risky_licence_hits(self, text: str) -> list[str]:
        hits = []
        for line in text.splitlines():
            upper = line.upper()
            if restricted_license_hit(line):
                hits.append(line.strip())
        return hits


def baseline_inherited_pint_failure(ctx: PRContext, output: str) -> bool:
    from pr_qa import baseline_inherited_path

    paths = pint_failure_paths(output)
    return bool(paths) and all(baseline_inherited_path(ctx, path, "php_formatting") for path in paths)


def pint_failure_paths(output: str) -> list[str]:
    paths: list[str] = []
    for line in output.splitlines():
        if "⨯" not in line:
            continue
        candidate = line.split("⨯", 1)[1].strip()
        if not candidate.endswith(".php") and ".php " not in candidate:
            continue
        path = candidate.split(".php", 1)[0].strip() + ".php"
        if path and path not in paths:
            paths.append(path)
    return paths
