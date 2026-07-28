# Rollout Strategy

## Principle

Roll out PR QA in phases. The framework becomes mandatory only after representative validation and approval.

The workflow validates and reports only. Branch Protection remains the enforcement point for required checks and merge decisions.

## Phase 0: Central Framework Readiness

Complete before touching participating repositories:

- reusable workflow committed in `Synergie-ITCI/.github`
- adapter engine committed in `Synergie-ITCI/.github`
- config schema published
- administrator guide reviewed
- runner tooling baseline agreed
- sample reports reviewed by engineering leadership

Exit criteria:

- central workflow can be called from a test repository
- report artifacts are generated
- secret findings are redacted
- no deployment or infrastructure mutation occurs

## Phase 1: Representative Pilot

Pilot 3-5 repositories covering Synergie's active technology stack.

Recommended pilot set from the available governance inventory:

| Repository | Coverage |
| --- | --- |
| `Synergie-ITCI/csr-intelligence-engine` | Python/FastAPI, React, TypeScript, Docker, GitHub Actions, CODEOWNERS |
| `Synergie-ITCI/bayer.synergieinsights.in` | PHP/Laravel, Composer, Laravel Mix/Node, production deployment workflow |
| `Synergie-ITCI/fleet-safety-os-frontend` | React, TypeScript, React Native-style frontend workflow |
| `Synergie-ITCI/fleet-safety-os-edge-runtime` | Gradle/Kotlin/mobile runtime pattern |
| `Synergie-ITCI/telemedicine-backend` | PHP/Laravel backend and deployment-sensitive workflow changes |

Phase 1 rules:

- create one onboarding PR per repository
- add only the caller workflow, `.github/pr-qa.yml`, and PR template
- do not change application code
- do not change deployment workflows
- do not change CODEOWNERS
- do not change Branch Protection until pilot results are approved

Exit criteria:

- each pilot repository has at least one PR QA run
- PASS, WARNING, and FAIL examples are captured
- false positives are triaged
- required runner tooling gaps are documented
- leadership approves Phase 2

## Phase 2: Organisation Rollout

Only after Phase 1 approval:

1. Generate onboarding PRs for the remaining repositories.
2. Keep each PR thin and reviewable.
3. Track PR URL, status, and check result centrally.
4. Do not merge onboarding PRs automatically.
5. After adoption, mark PR QA as a required check through Branch Protection or rulesets.

## Rollback

Rollback is repository-local:

1. Revert the onboarding PR that added `.github/workflows/pr-qa.yml`.
2. Leave the central framework untouched unless the central workflow caused cross-repository failure.
3. If the central workflow is faulty, pin callers to the last known good tag or revert the central workflow change.

## Governance Reporting

Maintain a rollout register with:

- repository
- default branch
- criticality
- onboarding PR
- PR QA result
- warnings accepted
- blocking failures
- owner approval
- required-check activation date
