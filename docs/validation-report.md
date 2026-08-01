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
PYTHONDONTWRITEBYTECODE=1 python3 -c "import ast, pathlib; [ast.parse(p.read_text(encoding='utf-8'), filename=str(p)) for p in pathlib.Path('pr-qa').rglob('*.py')]; [ast.parse(p.read_text(encoding='utf-8'), filename=str(p)) for p in pathlib.Path('tests').rglob('*.py')]; [ast.parse(p.read_text(encoding='utf-8'), filename=str(p)) for p in pathlib.Path('tools').rglob('*.py')]; print('AST syntax OK')"
PYTHONDONTWRITEBYTECODE=1 python3 pr-qa/pr_qa.py --repo . --detect-only
python3 -m json.tool policy/pr-qa-policy.json
python3 -m json.tool schemas/pr-qa.schema.json
python3 -m json.tool .github/pr-qa.schema.json
PYTHONDONTWRITEBYTECODE=1 python3 -c "import pathlib, sys; sys.path.insert(0, 'pr-qa'); import pr_qa; files=['.github/workflows/pr-qa.yml','.github/workflows/pr-qa-self.yml','.github/workflows/reusable-pr-quality-gate.yml','examples/caller-workflow.yml','examples/pr-qa.yml']; [print(f'{path}: {type(pr_qa.parse_yaml_or_json(pathlib.Path(path).read_text(encoding=\"utf-8\"))).__name__}') for path in files]"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
actionlint .github/workflows/pr-qa.yml
actionlint .github/workflows/pr-qa-self.yml
actionlint .github/workflows/reusable-pr-quality-gate.yml
gitleaks detect --no-git --source . --redact --exit-code 1 --report-format json --report-path /private/tmp/prqa-simplification-gitleaks.json
rg -n "AI_REVIEW|ai-review|ai_review.py|review_comments.py|pull-requests: write|checks: write|publisher:|GITHUB_TOKEN|github-script|pr-qa-ai-review-results|ai_advisory|AI Advisory|AI Engineering" .github examples pr-qa tests tools policy schemas
find . -path '*__pycache__*' -print
```

Results:

- AST syntax OK.
- Technology detection OK: `GitHub Actions`, `Python`.
- JSON policy and schema parse OK, including the legacy `.github/pr-qa.schema.json`.
- Workflow and caller YAML parse OK for `.github/workflows/pr-qa.yml`, `.github/workflows/pr-qa-self.yml`, `.github/workflows/reusable-pr-quality-gate.yml`, `examples/caller-workflow.yml`, and `examples/pr-qa.yml`.
- Regression suite: 20 tests passed.
- actionlint OK for all three workflow files.
- Gitleaks OK; no leaks found.
- Removed-component scan found no workflow, engine, schema, policy, example, or tool references to AI provider secrets, AI review scripts, GitHub write tokens, PR review/comment publishing, trusted publisher jobs, or AI review artifacts. Matches were limited to negative regression assertions and removal documentation.
- No Python bytecode cache files remain.

NOT VERIFIED LOCALLY:

- GitHub Actions execution in GitHub-hosted runners.
- Live GitHub CODEOWNERS approval-state verification.

## AI Review Simplification Validation

Enterprise QA remains automated. Automated AI review is removed from the active framework.

| Validation | Result |
| --- | --- |
| Reusable v1.1 workflow has no AI inputs or secrets | PASS |
| Caller workflow has no AI inputs or secrets | PASS |
| Workflow permissions are read-only | PASS |
| Trusted publisher job removed | PASS |
| GitHub Review API and issue-comment publishing removed | PASS |
| AI provider code removed | PASS |
| AI/comment lifecycle tests removed | PASS |
| Removed implementation preserved on `feature/automated-ai-review-v1.1` | PASS |
| Manual Codex review documented | PASS |

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
| Dependencies | Composer/npm/dotnet audit clean | no dependency manifest or non-blocking licence inventory gap | high or critical vulnerability found |
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
