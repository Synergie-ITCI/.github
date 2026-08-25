# Synergie Developer Governance & PR-QA Handoff

Version/date: 2026-08-25

Audience: Synergie developers and IT team

## 1. One-page developer summary

Synergie uses a governed pull-request flow. Developers should create work branches from the correct integration branch, open pull requests into the next branch in the path, let the required checks run, and fix only the failing area shown by PR-QA.

Current live path:

```text
Feature branch
-> development
-> staging
-> main
-> production deployment only through the governed deployment process
```

Normal feature work goes to `development`. Validated development work is promoted to `staging`. Release candidates are promoted from `staging` to `main`. Production deployment is separate; merging to `main` does not mean production deploys.

What must pass:

- `pr-qa / Pull Request Quality Assurance` is the live required PR-QA status context in the active organization rulesets.
- `Architecture Governance` runs for central `.github` changes to `main` that touch `.github/**`, `policy/**`, `pr-qa/**`, or `tests/**`.
- Wrapper workflows may add branch-specific checks such as Governance Preflight, Recovery Readiness, Production Release Preflight, phpMyAdmin production policy, Production Recoverability Check, and the wrapper-owned PR-QA job.

Human approval:

- Pull requests authored by `SaurabhVermaIN` do not require an independent human review under the current central policy.
- Automated QA still remains mandatory for `SaurabhVermaIN` PRs.
- Pull requests authored by anyone else require independent review under central policy. Developer self-approval does not satisfy that policy.
- Gate C (`staging -> main`) and Gate D production deployment require explicit Saurabh release authorization.

Never bypass:

- Do not disable or bypass PR-QA.
- Do not hide findings.
- Do not push directly around protected branch controls.
- Do not add ad-hoc deployment paths.
- Do not commit secrets or real credentials.
- Do not create fake project-root files just to satisfy CI.

## 2. Branch-by-branch matrix

| Promotion | Purpose | PR Required? | Checks Run | Human Approval | Merge Condition | Deployment? |
| --- | --- | --- | --- | --- | --- | --- |
| feature branch -> `development` | Normal code integration. | Yes, where branch rules require PRs. | PR-QA through the repository caller. Always includes static governance gates. Technology gates run when matching files or project roots are detected. | Saurabh approval is not required merely for normal development integration unless the author/review policy or repository rules require it. | Required checks pass, no merge conflict, PR conversation requirements satisfied, and review policy satisfied. | No production deployment. |
| `development` -> `staging` | Promote validated integration work to staging. | Yes. | Synergie Quality Gate when configured: Governance Preflight, optional Recovery Readiness evidence, then central PR-QA. PR-QA still runs static, technology, evidence, review, risk, secret, deployment, migration, and protected-resource gates as applicable. | Saurabh approval is not required merely to place validated work on staging. | Source must match the configured staging source, usually `development`; required checks pass. | Staging deployment only if a governed staging deployment process is separately configured. |
| `staging` -> `main` | Gate C release QA and release baseline approval. | Yes. | Synergie Production Gate when configured: Production Release Preflight, optional rollback evidence, phpMyAdmin production policy, Production Recoverability Check, and Synergie Release QA through central PR-QA. Generic PR-QA may cover this boundary until a wrapper owns it. | Explicit Saurabh release authorization is required. If `SaurabhVermaIN` authored the PR, the independent-review exception applies, but automated checks still apply. | Source must match configured production source, usually `staging`; required checks pass; release approval policy satisfied. | No. Main is the approved release baseline, not automatic production deployment. |
| `main` -> production deployment | Deploy approved release to production. | Not treated as a normal code PR transition. | Gate D deployment controls, production approval, exact approved SHA/artifact verification, recovery/rollback evidence, and deployment-specific policy checks. | Explicit Saurabh production approval required. | Use the governed deployment path for the exact approved SHA/artifact. | Yes, only through the governed deployment process. |

PR-QA gate categories:

- Always or generally run: Baseline Alignment, Config Validation, Repository Integrity, Repository Hygiene, Git Validation, Secrets, Protected Resources, Deployment Risk, Migration Risk, Risk Engine, Evidence, Review Policy.
- Technology/file dependent: Formatting, Lint, Build, Tests, Dependencies, Licence. These depend on detected language/project roots and available repository-defined commands.
- Branch or production stricter gates: Governance Preflight, Recovery Readiness, Production Release Preflight, phpMyAdmin production policy, Production Recoverability Check, branch-promotion path checks, rollback evidence where configured.

## 3. What developers should run before pushing

Use the repository's existing commands. Do not invent root-level files or new CI configuration just to make PR-QA detect a different project.

Before opening a PR:

- Start from the correct base branch for the promotion.
- Sync your branch using the normal development workflow; avoid accidental merge commits where policy disallows them.
- Run the repository formatter if one exists.
- Run the repository linter if one exists.
- Run the relevant tests for the changed project root.
- Run the build command if the repository defines one.
- Check dependency changes and lockfiles.
- Never commit secrets, `.env` files with real values, private keys, tokens, or credentials.
- Verify migrations are forward-safe and use the repository's migration framework.
- Remove generated files, junk files, local caches, build output, and unrelated artifacts.
- Make deployment, Docker, infrastructure, or workflow changes only when intentional and explained.
- Complete the PR template evidence.
- For nested projects, run commands in the real project root, not necessarily the repository root.

Useful generic commands when the repository supports them:

```bash
git status
git fetch origin
git diff --check
```

For application checks, use the repository's existing command such as `npm run test`, `composer run test`, `php artisan test`, `python -m pytest`, `go test ./...`, `dotnet test`, `cargo test`, or the command documented by that repository. If the repository does not define a command, do not create a fake one only for CI.

## 4. PR evidence requirements

Every PR should explain enough for a reviewer and PR-QA to understand the change:

- Business purpose: what user, operational, security, or maintenance problem this solves.
- Testing performed: exact local or CI checks run, or a clear reason a check is not applicable.
- Rollback strategy: how to recover if the change causes trouble.
- Linked issue: the issue, ticket, or tracking reference.
- Screenshots/evidence: required for UI changes where applicable.

A good submission is short but specific. For example:

- Business purpose: "Fix invoice date validation so users cannot submit future dates."
- Testing performed: "Ran repository test command; manually verified invoice form validation."
- Rollback strategy: "Revert this PR; no migration or deployment state change."
- Linked issue: "Issue #123."

## 5. Human review policy

### PR authored by `SaurabhVermaIN`

Current central policy says an independent human review is not required for PRs authored by the verified GitHub identity `SaurabhVermaIN`. This is not a QA bypass. Automated PR-QA, security checks, production controls, mergeability checks, and evidence requirements remain mandatory.

Live organization rulesets currently enforce pull-request requirements with `required_approving_review_count = 0`, conversation resolution enabled, stale review dismissal enabled, and required PR-QA status checks.

### PR authored by another developer

Current central policy requires independent review for non-`SaurabhVermaIN` authors. The Executive Release Authority is `SaurabhVermaIN`. Developer self-approval does not satisfy the policy. Non-authority reviewers may provide feedback, but protected release approval depends on the central review policy and the relevant branch rules.

## 6. Common PR-QA failures

| Failure | What it means | What developer should do |
| --- | --- | --- |
| Formatting | A formatter found files that do not match repository style. | Run the repository formatter in the real project root, commit the formatted files, and push again. |
| Lint | Static analysis found code or configuration issues. | Run the repository linter, fix reported issues, and push again. |
| Build | The project cannot build or required validation failed. | Run the same build command locally where possible, fix the compile/configuration error, and push again. |
| Tests | Automated tests failed. | Run the repository test command, fix the failing behavior or test expectation, and push again. |
| Secrets | PR-QA detected a possible committed secret or unsafe credential indicator. | Remove the secret-bearing change. If a real credential was exposed, rotate or revoke it. Cleaning only the current tree may not be enough if history exposed it. |
| Dependency vulnerabilities | A dependency audit found high-risk vulnerable packages or required audit inputs are missing. | Update dependencies or lockfiles using the repository package manager. Do not suppress the audit without governance approval. |
| Repository Hygiene | The branch history or naming does not match policy. | Rebase or rebuild the branch using the normal workflow, remove accidental merge commits, and push again. |
| Accidental merge commits | The branch contains merge history not permitted for the PR. | Rebase/update the branch cleanly from the intended base branch; do not merge unrelated branch history into the feature branch. |
| Branch behind base | The source branch is behind the target branch. | Update the source branch from the target branch using the normal repository workflow, then push again. |
| Missing/stale required check | The ruleset requires a check context that is not present on the current head SHA. | Confirm the repository caller uses the canonical workflow and that rulesets require the exact emitted context, currently `pr-qa / Pull Request Quality Assurance` for the generic caller. |
| Protected Resources | Files such as workflows, policy, deployment, Docker, infra, or CODEOWNERS-adjacent resources changed without the expected ownership evidence. | Add required ownership/review evidence or split the protected change into the governed workflow. |
| Migration/database safety | Migration files changed, or destructive database operations may be present. | Make migrations forward-safe, use the repository migration framework, add rollback/recovery notes, and ask the maintainer if a governed migration path is needed. |
| Deployment Risk | Deployment, production, infrastructure, Docker, or privileged workflow content changed. | Confirm the change is intentional, include deployment and rollback evidence, and use the governed deployment path. |
| Oversized/risk-engine finding | The PR is too large or combines high-risk areas. | Split unrelated work into smaller PRs and keep production-sensitive changes isolated. |
| Incomplete PR evidence | Required PR body fields are missing or placeholder text remains. | Fill in business purpose, testing, rollback, linked issue, and UI evidence where relevant. |

If PR-QA does not provide a deterministic fix, use this fallback: Next action: review the technical details or contact the repository maintainer.

## 7. Node / frontend project-root behaviour

Repositories may contain frontend projects in subdirectories. PR-QA detects real Node project roots from `package.json` files and then narrows checks to the deepest changed relevant project root. If a repository has `frontend/package.json`, PR-QA should run Node checks there.

Developers should not create fake root-level files such as:

- `package.json`
- ESLint configuration
- Vite configuration
- `index.html`

Only add these files when they are truly part of the application architecture. In monorepos and nested projects, keep commands, lockfiles, and configuration with the project they belong to.

## 8. Deployment rules

Passing PR-QA means the PR met the configured quality and governance gates. It does not automatically mean deployment.

Deployment rules:

- Merging into `main` and production deployment are separate governed events unless a repository has an explicitly approved deployment process.
- Gate D governs deployment from an approved `main` release to production.
- Deployment, UAT, Lightsail, Docker, infrastructure, SSH, Terraform/OpenTofu, Kubernetes, nginx/apache, and production workflow changes are higher risk.
- Developers must not insert ad-hoc deployment mechanisms.
- Existing governed deployment paths must be used.
- Production deployment must use the exact approved SHA or artifact and preserve rollback/recovery evidence.

## 9. Database and migrations

Migration expectations:

- Use the repository's existing migration framework.
- Make migrations forward-safe where possible.
- Do not manually edit the production database as part of normal release work.
- Destructive operations such as dropping tables, dropping databases, truncating data, deleting data, or removing/renaming columns trigger stronger scrutiny and may block.
- Add rollback or recovery notes for database changes.
- Validate migrations with the repository's normal test/build path; central PR-QA classifies risk but does not replace application migration execution evidence.

## 10. Secrets and credentials

Never commit real secrets. This includes `.env` files with real values, API keys, tokens, private keys, production database credentials, cloud credentials, certificates, and passwords.

Safe handling:

- Keep real values in approved secret stores or GitHub environments/secrets, not in Git.
- Use `.env.example`, `.env.sample`, or `.env.template` only with placeholder values.
- If a credential is accidentally committed, remove it from the PR and rotate or revoke the credential. Do not assume deletion from the latest commit is enough if history exposed it.
- Do not paste actual secret values into PR comments, issue comments, logs, documents, or screenshots.
- PR-QA uses Gitleaks plus fallback/encoded scans and redacts sensitive values from developer-facing output.

## 11. Protected resources

The central policy applies additional scrutiny to protected paths. Simplified developer list:

- `.github/**`
- `.gitleaks.toml`
- `CODEOWNERS`, `docs/CODEOWNERS`, `.github/CODEOWNERS`
- `policy/**`
- `schemas/**`
- `deployment/**`, `deploy/**`
- `infra/**`, `terraform/**`
- `k8s/**`, `kubernetes/**`
- `Dockerfile`, `Dockerfile.*`, `docker-compose*.yml`, `docker-compose*.yaml`
- `nginx/**`, `apache/**`
- `scripts/deploy*`
- `.env.example`

Changing these files is allowed only when intentional and supported by the right evidence. Protected-resource changes may require ownership coverage, review evidence, or a separate governed workflow.

## 12. Risk Engine

The Risk Engine gives the PR an overall risk score and may warn or fail depending on the configured thresholds.

Things that increase risk:

- Very large changes.
- Many changed files.
- Production, deployment, workflow, Docker, infrastructure, or privileged operation changes.
- Migration/database changes.
- Protected-resource changes.
- Security-sensitive content.
- Failing or warning gates from other parts of PR-QA.

Current central thresholds include 200 changed files, 5000 additions, risk warning at 40, and risk fail at 85. Splitting unrelated work into smaller PRs is preferred.

## 13. Developer workflow examples

### A. Normal small feature

```text
Create feature branch from development
-> make small code change
-> run repository formatter/linter/tests
-> open PR to development
-> PR-QA passes
-> review policy satisfied
-> merge to development
```

### B. Database/migration change

```text
Create feature branch from development
-> add forward-safe migration using repository framework
-> run repository tests and migration validation
-> include rollback/recovery notes in PR
-> open PR to development
-> PR-QA migration and test gates run
-> fix any migration-risk findings
-> merge only after required checks and review policy pass
```

### C. Deployment-sensitive change

```text
Create branch from the correct governed source
-> isolate deployment/infra change from unrelated code
-> document deployment purpose and rollback
-> open PR to the required promotion branch
-> production/staging wrapper checks run where configured
-> PR-QA, recovery, and deployment policy evidence pass
-> obtain required release/deployment authorization
-> merge or deploy only through governed process
```

## 14. Before you ask IT/Governance for help

Check these first:

- Read the human-friendly PR-QA error.
- Identify "What failed", "Why", and "What to do".
- Open the job summary or PR-QA report artifact if needed.
- Run the relevant local command in the real project root.
- Fix only the failing area.
- Push again and wait for the current-head checks.
- Do not bypass checks.
- Escalate when the failure looks like central PR-QA detection/configuration rather than application code.

## 15. Governance source-of-truth appendix

Authoritative sources used for this handoff:

| Source | Purpose |
| --- | --- |
| `.github/workflows/pr-qa.yml` | Active reusable PR-QA workflow. Consumer repositories call this canonical central workflow at `@main`; it owns the active immutable PR-QA release pin. |
| `.github/workflows/pr-qa-self.yml` | Central repository self-caller for PR-QA on `.github` pull requests. |
| `.github/workflows/architecture-governance.yml` | Central architecture governance check for `.github` changes to `main` that touch workflow, policy, PR-QA, or tests. |
| `.github/workflows/synergie-quality-gate.yml` | Reusable staging-quality wrapper with promotion preflight, recovery evidence, and central PR-QA. |
| `.github/workflows/synergie-production-gate.yml` | Reusable production-release wrapper with production preflight, rollback/recovery checks, phpMyAdmin policy, and central PR-QA. |
| `policy/pr-qa-policy.json` | Central PR-QA policy, gates, thresholds, protected paths, review policy, evidence requirements, and secret scanning settings. |
| `policy/status-check-registry.json` | Registry of intended status contexts. This file currently contains a stale PR-QA context; live organization rulesets are operational truth. |
| `docs/executive-release-policy.md` | Human review and Executive Release Authority policy. |
| `docs/company-branch-release-governance.md` | Branch/promotion model. Its status-check context text is stale where it differs from live rulesets. |
| `docs/onboarding-guide.md` | Repository onboarding flow, canonical caller, and ruleset alignment requirements. |
| `tools/onboard_repo.py` | Authoritative onboarding automation and exact generic caller context constant. |
| Organization rulesets `Main branch protection baseline` and `No unreviewed self-merge baseline` | Live merge enforcement for PR requirement, required PR-QA context, conversation resolution, and review-count settings. |

Current active PR-QA release:

```text
PR_QA_FRAMEWORK_RELEASE = pr-qa-v1-rc70
```

Consumer repositories use the canonical central caller:

```yaml
uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@main
```

Do not instruct consumer repositories to pin individual RC tags. The central workflow owns the active immutable PR-QA release pin.

## Governance inconsistencies found

Live enforced behavior and current central workflow are operational truth.

| Item | Current live truth | Stale source/config |
| --- | --- | --- |
| Required generic PR-QA status context | `pr-qa / Pull Request Quality Assurance` in the active organization rulesets and onboarding tool. | `policy/status-check-registry.json` still lists `Pull Request Quality Assurance / Pull Request Quality Assurance`. |
| Branch governance status-check text | Repository rulesets must require the exact context emitted by that repository. For the generic caller, that is `pr-qa / Pull Request Quality Assurance`. | `docs/company-branch-release-governance.md` still lists `Pull Request Quality Assurance / Pull Request Quality Assurance`. |
