# Technology Adapter Guide

## Adapter Contract

Each adapter is a Python module under `pr-qa/adapters/` implementing `TechnologyAdapter`.

Required methods:

```python
detect(repo: Path) -> list[Path]
format(ctx: PRContext, roots: list[Path]) -> list[CheckResult]
lint(ctx: PRContext, roots: list[Path]) -> list[CheckResult]
build(ctx: PRContext, roots: list[Path]) -> list[CheckResult]
test(ctx: PRContext, roots: list[Path]) -> list[CheckResult]
dependencies(ctx: PRContext, roots: list[Path]) -> list[CheckResult]
licences(ctx: PRContext, roots: list[Path]) -> list[CheckResult]
```

Register the adapter in `pr-qa/adapters/__init__.py`.

## Adapter Rules

- Detect by files and manifests, not repository names.
- Support multiple roots in one repository.
- Prefer project-native commands and lockfiles.
- Run validation only. Never auto-fix.
- Never deploy.
- Never write to infrastructure state.
- Never upgrade dependencies.
- Return FAIL when mandatory security tooling is absent.
- Return WARNING only for non-blocking advisory tooling.
- Return FAIL when a configured validation command fails.

## Current Adapters

| Adapter | Detection |
| --- | --- |
| PHP/Laravel | `composer.json`, PHP files |
| Node.js | `package.json` |
| Python | `pyproject.toml`, `requirements.txt`, setup files, Python files |
| Go | `go.mod` |
| Kotlin/Gradle | Gradle files or wrapper |
| Swift | `Package.swift`, Xcode project/workspace markers |
| Java/Maven | `pom.xml` |
| .NET | `.sln`, `.csproj`, `.fsproj`, `.vbproj` |
| Rust | `Cargo.toml` |
| Docker | Dockerfile and compose files |
| Terraform | `.tf` files |
| Kubernetes | YAML manifests with `apiVersion` and `kind` |
| GitHub Actions | `.github/workflows/*.yml` |

## Adding A New Adapter

1. Create `pr-qa/adapters/<ecosystem>.py`.
2. Subclass `TechnologyAdapter`.
3. Implement detection and the six validation methods.
4. Return `CheckResult` objects through helpers in `adapters/base.py`.
5. Add the adapter to `ADAPTERS`.
6. Add one PASS, WARNING, and FAIL example to `docs/validation-report.md`.
7. Validate with `--detect-only` and a no-command smoke run.

## Command Execution

Adapters should use `ctx.run([...], cwd=root)` so command output is captured, redacted, timed out, and included in the JSON evidence trail.

Do not call `subprocess` directly inside adapters.
