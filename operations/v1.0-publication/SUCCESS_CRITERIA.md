# Success Criteria

Release reference: `pr-qa-v1-rc2`

These criteria define successful publication and rollout. They do not change framework behavior.

## Phase 1: Publication Success

Publication succeeds only when:

| Criterion | Required Result |
| --- | --- |
| Central publication PR | reviewed, approved, and manually merged |
| Workflow validation | `actionlint` passes in central repository |
| Schema validation | sample config validates against hardened schema |
| Regression suite | passes in central repository |
| Security scanner validation | framework scan clean, fixture scan detects expected secret |
| Release tag | `pr-qa-v1-rc2` created at approved commit |
| Tag protection | release ref protected from mutation |
| GitHub release | published against `pr-qa-v1-rc2` |
| Workflow resolution | caller can resolve reusable workflow at release ref |
| Application rollout | not started |

## Phase 2: Single Pilot Success

Pilot succeeds only when:

| Criterion | Required Result |
| --- | --- |
| Pilot repository | exactly `Synergie-ITCI/csr-intelligence-engine` |
| Rollout PR | opened and left unmerged |
| Scenario PR base | rollout branch, not `main` |
| Normal feature scenario | PASS or expected WARNING |
| Broken build scenario | FAIL |
| Secret scenario | FAIL and redacted |
| Deployment change scenario | classified according to policy |
| Migration scenario | classified according to policy |
| Documentation scenario | PASS or low-risk report |
| Production deployment | not triggered |
| False negatives | none high severity |
| Evidence | complete |

## Phase 3: Pilot Review Success

Pilot review succeeds only when:

| Criterion | Required Result |
| --- | --- |
| Runtime | acceptable p50 and p95 agreed by Release Manager |
| False positives | no publication blocker |
| False negatives | none high severity |
| Developer feedback | no blocker |
| Reviewer feedback | no blocker |
| Workflow stability | no systemic workflow failures |
| Runner stability | no systemic runner failures |
| Recommendation | PASS |

## Phase 4: Expanded Pilot Success

Expanded pilot succeeds only when:

| Criterion | Required Result |
| --- | --- |
| Repository count | exactly three total repositories |
| Stack diversity | Python/React, Laravel/PHP, mobile/edge runtime covered |
| Rollout PRs | opened and left unmerged unless owners approve after pilot |
| Scenario matrix | completed for all three repositories |
| Secret detection | expected synthetic secrets blocked in every repository |
| Workflow resolution | succeeds for every repository |
| Runner stability | no systemic failures |
| Evidence | complete for each repository |
| Recommendation | PASS |

## Phase 5: Organisation Rollout Success

Organisation rollout succeeds only when:

| Criterion | Required Result |
| --- | --- |
| Wave 1 | five rollout PRs opened, reviewed, and owner-managed |
| Wave 2 | fifteen rollout PRs opened after Wave 1 success |
| Wave 3 | remaining active repositories handled after Wave 2 success |
| Automatic merge | none |
| Branch Protection changes | none |
| Executive approval | `SaurabhVermaIN` approval required for protected-branch rollout PRs |
| Developer self-approval | no protected-branch merge from self-approval |
| Mandatory gates | build, tests, secrets, dependency security, deployment risk, migration risk, documentation validation, protected resource validation, and repository integrity executed or failed closed |
| Rollout file scope | only `.github/workflows/pr-qa.yml` and `.github/pr-qa.yml` when required |
| Dashboard | all rollout PRs tracked |
| Rollback readiness | verified for each wave |
| Owner feedback | no unresolved blockers |

## Overall Stop Conditions

Stop rollout immediately if:

- release tag is mutable, missing, deleted, or retargeted
- reusable workflow cannot resolve at `pr-qa-v1-rc2`
- mandatory security scanners do not execute
- synthetic secret is not blocked
- any secret appears unredacted in logs or artifacts
- production deployment is triggered unexpectedly
- high-severity false negative is found
- systemic runner instability prevents reliable conclusions
- repository owners cannot review rollout PRs
