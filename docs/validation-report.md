# Validation Report

Generated: 2026-07-28

## Validation Basis

This framework was designed against the Synergie governance inventory available in the workspace, including:

- `github-gitops-assessment/repo_inventory.tsv`
- `github-gitops-assessment/fast_repo_inventory.tsv`
- locally available representative repositories such as `bayer-workflow-migration`, `csr-intelligence-engine`, `jiobp-wave1-migration`, `saksham-runner-migration`, and `telemedicine-backend-uat-fix`

The inventory shows active use of PHP/Laravel, Node/React/TypeScript, Python/FastAPI, Docker, GitHub Actions, deployment scripts, mobile-style frontend/runtime repositories, and protected branches.

## Representative Coverage

| Stack | Representative Repository Evidence |
| --- | --- |
| PHP/Laravel | `bayer-workflow-migration`, `jiobp-wave1-migration`, `telemedicine-backend-uat-fix` |
| Node/Laravel Mix | `bayer-workflow-migration/package.json` |
| React/TypeScript | `csr-intelligence-engine/frontend/package.json` |
| Python/FastAPI | `csr-intelligence-engine/pyproject.toml` |
| Docker | `csr-intelligence-engine/Dockerfile` |
| GitHub Actions | local `.github/workflows/*.yml` and inventory workflow rows |
| Gradle/Kotlin/mobile runtime | `Synergie-ITCI/fleet-safety-os-edge-runtime` inventory row |
| Deployment-sensitive repos | legacy `deploy.yml` workflows across Laravel repositories |

## Local Hardening Validation

Commands executed:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -c "import ast, pathlib; [ast.parse(p.read_text(encoding='utf-8'), filename=str(p)) for p in pathlib.Path('synergie-pr-qa-framework/pr-qa').rglob('*.py')]; [ast.parse(p.read_text(encoding='utf-8'), filename=str(p)) for p in pathlib.Path('synergie-pr-qa-framework/tests').rglob('*.py')]; print('AST syntax OK')"
PYTHONDONTWRITEBYTECODE=1 python3 synergie-pr-qa-framework/pr-qa/pr_qa.py --repo synergie-pr-qa-framework --detect-only
python3 -m json.tool synergie-pr-qa-framework/policy/pr-qa-policy.json >/dev/null
python3 -m json.tool synergie-pr-qa-framework/schemas/pr-qa.schema.json >/dev/null
PYTHONDONTWRITEBYTECODE=1 python3 -c "import pathlib, sys; sys.path.insert(0, 'synergie-pr-qa-framework/pr-qa'); import pr_qa; print(type(pr_qa.parse_yaml_or_json(pathlib.Path('synergie-pr-qa-framework/.github/workflows/pr-qa.yml').read_text(encoding='utf-8'))).__name__); print(type(pr_qa.parse_yaml_or_json(pathlib.Path('synergie-pr-qa-framework/examples/caller-workflow.yml').read_text(encoding='utf-8'))).__name__)"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s synergie-pr-qa-framework/tests -v
actionlint synergie-pr-qa-framework/.github/workflows/pr-qa.yml
check-jsonschema --schemafile synergie-pr-qa-framework/schemas/pr-qa.schema.json synergie-pr-qa-framework/examples/pr-qa.yml
gitleaks detect --no-git --source synergie-pr-qa-framework --redact --exit-code 1 --report-format json --report-path /private/tmp/prqa-validation-gitleaks-framework.json
gitleaks detect --no-git --source synergie-pr-qa-framework/tests/test_pr_qa_regressions.py --redact --exit-code 1 --report-format json --report-path /private/tmp/prqa-validation-gitleaks-fixture.json
rg -n "framework-ref|runner-label|config-path|persist-credentials: true|PR_QA_FRAMEWORK_REF" synergie-pr-qa-framework/.github synergie-pr-qa-framework/examples synergie-pr-qa-framework/pr-qa synergie-pr-qa-framework/schemas synergie-pr-qa-framework/tests
find synergie-pr-qa-framework -path '*__pycache__*' -print
```

Results:

- AST syntax OK.
- Technology detection OK: `GitHub Actions`, `Python`.
- JSON policy/schema parse OK.
- Workflow and caller YAML parse OK.
- Regression suite: 10 tests passed.
- actionlint OK.
- Strict schema validation OK.
- Framework Gitleaks scan OK with fixture-only allowlist.
- Direct Gitleaks fixture scan still detects the intentional fixture secret.
- Stale workflow input scan found only the regression assertion string.
- No Python bytecode cache files remain.

NOT VERIFIED LOCALLY:

- GitHub Actions execution in GitHub-hosted runners.
- Live GitHub CODEOWNERS approval-state verification.

## Previous Smoke Test

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 synergie-pr-qa-framework/pr-qa/pr_qa.py --repo synergie-pr-qa-framework --config examples/pr-qa.yml --no-command-runs --out /private/tmp/pr-qa-smoke.md --json-out /private/tmp/pr-qa-smoke.json
```

Result:

- Report generated successfully.
- Technology detection identified Python and GitHub Actions in the framework bundle.
- The self-smoke intentionally reported protected-resource failure because the standalone bundle is not installed in a repository with CODEOWNERS coverage.

## Gate Examples

| Gate | PASS Example | WARNING Example | FAIL Example |
| --- | --- | --- | --- |
| Repository Hygiene | branch `feature/add-report-filter`, conventional commits, no generated artifacts | branch unavailable in local smoke | committed `node_modules/**`, binary `.pyc`, invalid branch name |
| Formatting | `black --check`, `prettier --check`, `terraform fmt -check` pass | no formatter configured | formatter check exits nonzero |
| Lint | ESLint, Ruff, PHP_CodeSniffer, actionlint pass | linter not configured | configured linter exits nonzero |
| Build | `npm run build`, `composer validate`, `go build`, `dotnet build` pass | no build step for non-buildable manifests | build command exits nonzero |
| Tests | PHPUnit, Pytest, Vitest, Go test pass | "No automated test suite configured." | configured tests fail |
| Git Validation | `git diff --check` clean | CRLF detected | trailing whitespace or conflict markers in diff |
| Secrets | Gitleaks and fallback scan clean | N/A; Gitleaks unavailability fails closed | API key, private key, `.env`, token, hardcoded credential |
| Dependencies | Composer/npm/dotnet audit clean | audit tooling unavailable | high or critical vulnerability found |
| Licence | no GPL/AGPL/unknown licence found | full licence inventory tooling unavailable | repository may configure restricted licence findings as blocking |
| Deployment Safety | no deployment-sensitive file changed | Dockerfile or workflow changed, risk reported | handled through risk threshold if overall risk is critical |
| Database Safety | no migrations changed | additive migration | `DROP TABLE`, `DROP COLUMN`, `TRUNCATE`, destructive delete |
| Documentation | docs updated with API/config change | docs-sensitive change without docs | repository may configure doc gate as blocking later |
| Protected Resources | protected path unchanged | protected path changed with CODEOWNERS coverage | protected path changed without CODEOWNERS coverage |
| Advisory Review | no observations | duplication, debug statements, large PR | advisory findings are non-blocking by design |
| Risk Engine | low score below warning threshold | medium/high score below fail threshold | score at or above `risk_fail` |
| Evidence | PR template fields completed | non-PR local run skipped | mandatory PR evidence missing |

## Phase 1 Validation Required Before Mandatory Enforcement

Before enabling PR QA as a required status check organisation-wide, run Phase 1 on the representative pilot set in `docs/rollout-strategy.md`.

Collect for each pilot repository:

- one passing report
- one warning report
- one intentional failure report
- runner tooling gaps
- adapter false positives
- repository-specific config changes
