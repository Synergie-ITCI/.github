# CI/CD efficiency audit

**Snapshot:** 19 November 2026. The central source snapshot was verified against `Synergie-ITCI/.github` `main` at `f9cc21b03e28ec11ebe4bdbac4735b35bc696daf`. This public report contains aggregate inventory and workflow evidence. The full 82-repository inventory is retained in the private CI/CD Efficiency workspace because many repository names and configurations are private.

## Executive summary

Synergie's measured CI time is concentrated in a small set of paths. During 20 October–19 November 2026, GitHub returned **4,446 workflow runs across 24 active repositories** from an inventory of **82 repositories**. Thirty-four repositories have a central PR-QA caller on their default branch; the central repository runs self-QA. Eight other repositories have workflow files but no default-branch central PR-QA caller, and 39 have no `.github/workflows` directory on the default branch. This is a file inventory, not a determination that any repository should be enrolled or has a broken protection rule.

The largest summed workflow lifetimes belong to FieldZilla staging deployment, FieldZilla Architecture Governance and PR-QA, and central PR-QA/Architecture Governance. Workflow lifetime includes waiting, reruns, and external operations, so it is **not billed runner time**. A ten-run job sample for each leading path supplies a narrower runner-runtime proxy. Within central self-QA, 30 recent successful runs spent a median **21 seconds** starting PostgreSQL containers even though the central regression tests use fixtures rather than a live database. A bounded change in this PR skips the PostgreSQL service for central self-QA only; consumer QA still receives `postgres:16`.

There is no measured after-state or runner-minute saving yet. Governed PR runs must prove the service is absent and exact-current-head PR-QA and Architecture Governance checks pass. Broader caching, parallelism, and deployment changes need workload-specific evidence and separate review.

## Architecture and execution path

```mermaid
flowchart LR
    PR[Application PR] --> Caller[Repository PR-QA caller]
    Caller --> Resolver[Central reusable workflow and resolver]
    Resolver --> Tag[Approved immutable QA release]
    Tag --> Detect[Technology detection]
    Detect --> Static[Current-run static and security gates]
    Static --> Technical[Technical adapters or verified exact-input baseline]
    Technical --> Governance[Current-run governance and review gates]
    Governance --> Checks[Required checks at exact head]
    Checks --> Promotion[Governed branch promotion]
    Promotion --> Artifact[Immutable artifact and provenance]
    Artifact --> Deploy[Separate approved deployment workflow]
    Deploy --> Health[Target runtime and health verification]
```

The [central caller](../.github/workflows/pr-qa-self.yml) and [reusable PR-QA workflow](../.github/workflows/pr-qa.yml) use separate technology detection and QA jobs. Consumer callers use either central `@main` or an approved immutable release reference. The resolver verifies the [release manifest](../policy/framework-releases.json), selected protected tag, and provenance before the QA engine is used. The QA job repeats identity verification, checks out the same release, and confirms its commit. These repeated reads protect the detector/QA boundary; they are not assumed redundant.

The [engine](../pr-qa/pr_qa.py) executes static preflight, then formatting, lint, build, tests, dependencies and licence adapters, then current-run governance. Its [adapter registry](../pr-qa/adapters/__init__.py) has 15 technology adapters, with shared command/context handling in `adapters/base.py`. SQL and shell adapters skip unrelated changed files; other adapters generally validate detected project roots. The workflow conditionally installs Node, PHP, Python, Go, Java, OpenTofu, Docker scanner, and .NET tooling according to detector outputs and verified technical-baseline reuse. PostgreSQL had been the exception: it was declared as an unconditional service before any step could inspect repository requirements.

The [Architecture Governance workflow](../.github/workflows/architecture-governance.yml) independently validates permanent JSON, runs the central regression suite, and verifies registered release/tag protection. Its overlap with PR-QA testing is intentionally preserved pending an exact-head contract review. Immutable release provenance, consumer selection, and deployment authorization remain separate from ordinary PR validation. The [branch and release model](company-branch-release-governance.md) is feature → development → staging → main with a separate production approval gate; current central governance PR practice and effective rulesets must be honored before merge.

## Inventory method

The connected GitHub installation search returned 82 repositories on 19 November. For each default branch, the audit read `.github/workflows/pr-qa.yml` and, when absent, listed `.github/workflows`. Classification is therefore based on actual files, not repository names. Of 34 central callers, **22 use `@main`**, while **12 use immutable RC references**. The central repository has self-QA rather than a consumer caller. Eight repositories have other workflow files; 39 have no workflow directory on their default branch. One repository has a nonstandard default branch spelling, and several use `master` or another branch. These facts do not establish which repositories require onboarding; effective rulesets, active PR traffic, and owner intent need review first.

## Thirty-day workflow baseline

GitHub Actions `actions/runs` data were read for 20 October–19 November. The two busiest repositories were split into shorter date ranges to avoid GitHub's 1,000-result retrieval ceiling. Run counts are exact for the returned window at capture; one new run arrived between the initial count and final fetch. Durations below are `updated_at − run_started_at` for completed runs, rounded to seconds. P75/P95 use nearest rank. Summed elapsed hours rank **delay**, not cost; reruns and environment waiting can inflate the sum. The sampled runner column sums non-skipped job `completed_at − started_at` across the latest ten completed runs for each path and is **not a 30-day billing total**.

Across the 4,446 returned runs, GitHub reported 3,172 successes, 777 failures, 381 cancellations, 109 skips, six startup failures, and one run still in progress. For the 4,445 completed runs with timestamps, mean/median/P75/P95 lifetime was **185/136/207/533 seconds**, with **228 summed elapsed hours**. These totals are workflow lifetime, not billed runner consumption.

| Rank | Repository / workflow | Runs | Mean / median / P75 / P95 (s) | Summed elapsed (h) | Latest 10 job runtime (min) |
| ---: | --- | ---: | --- | ---: | ---: |
| 1 | FieldZilla `staging-deploy.yml` | 184 | 940 / 627 / 1304 / 2226 | 48.0 | 93.0 |
| 2 | FieldZilla `architecture-governance.yml` | 661 | 216 / 233 / 256 / 293 | 39.7 | 33.5 |
| 3 | FieldZilla `pr-qa.yml` | 564 | 192 / 136 / 321 / 439 | 30.1 | 25.3 |
| 4 | Central `pr-qa-self.yml` | 595 | 155 / 180 / 206 / 224 | 25.7 | 26.3 |
| 5 | Central `architecture-governance.yml` | 528 | 150 / 146 / 174 / 196 | 22.0 | 20.3 |
| 6 | RoadSense `pr-qa.yml` | 351 | 116 / 133 / 147 / 173 | 11.3 | 26.9 |
| 7 | FieldZilla `fieldzilla-production-hosting.yml` | 170 | 229 / 60 / 88 / 1149 | 10.8 | 82.8 |
| 8 | FieldZilla `fieldzilla-staging-images.yml` | 38 | 659 / 597 / 799 / 1044 | 7.0 | 132.9 |
| 9 | Scholarships `pr-qa.yml` | 213 | 82 / 90 / 100 / 115 | 4.9 | 15.8 |
| 10 | Scholarships `scholarships-first-cutover-prepare.yml` | 11 | 962 / 1096 / 1874 / 2243 | 2.9 | 175.1 |

These paths have very different operations and outcomes. For example, FieldZilla production-hosting is a multipurpose dispatcher, so its 60-second median must not be called a production deployment median. A recent FieldZilla staging-deploy [run 44090408349](https://github.com/Synergie-ITCI/programme-management-platform/actions/runs/44090408349) spent 210 seconds on backend tests, 133 on architecture tests, 56 on Admin tests, and 56 installing Admin dependencies; it failed. A [staging-image run 43561348821](https://github.com/Synergie-ITCI/programme-management-platform/actions/runs/43561348821) spent 204 seconds on API/Worker build and 532 on Admin build, sequentially. Among 13 successful production-image dispatches in the latest 500 FieldZilla repository runs, build-job median/P90 was **853/1233 seconds**, and separate publication-job median/P90 was **227/279 seconds**. These are stronger build-path evidence than theoretical speed estimates.

Within the latest 30 successful central PR-QA runs, the Phase 2/3 validation step had median/P95 **133/170 seconds**, PostgreSQL container initialization **21/23 seconds**, and mandatory Python tool setup **6/10 seconds**. Detector job median/P95 was **7/10 seconds**; QA job **181/216 seconds**. Repeated detector and QA checkouts/base fetches consumed only a few seconds in sampled runs. Removing those Git operations first would have little measured impact and could break exact base/head validation.

The GitHub run and job timestamps do not expose billed rounded minutes, cost, pure runner queue latency, or human approval wait as separate categories. Job `created_at → started_at` mixes scheduling and possible environment waits. No billed-minute or monetary saving is claimed. Cache hit/miss rates, full PR-to-merge delay, and comparable ECS rollout timing remain unmeasured. Same-head run counts include legitimate retries, synchronization and event changes; they are not labeled waste without event-level cause review.

## Ranked findings and plan

| Priority | Evidence / cause | Action and boundary |
| --- | --- | --- |
| High | Central self-QA starts PostgreSQL on every run; 21-second median startup across 30 sampled successes, 595 central runs in the window. Central tests use fixtures and no live PostgreSQL connection. | **Implemented in this PR:** conditional service image blank only for `Synergie-ITCI/.github`. Preserve service for every consumer. Validate with actionlint, regression tests and exact-head hosted runs. Prospective saving must be measured after activation. |
| High | FieldZilla image build jobs take 853-second median / 1233-second P90 in a 13-run production cohort; staging example has sequential API/Admin builds. | Assess isolated cache trust, storage cost and build reproducibility; then pilot independent builds or cache on a separate governed FieldZilla branch. Do not alter immutable image digest, review, or one-use publication contracts. |
| Medium | FieldZilla staging-deploy has 48 elapsed hours across 184 runs, with backend/architecture/admin tests and dependency setup dominant in inspected jobs. | Classify failure and workflow operation types; compare test dependency graphs before parallelizing. Keep mandatory full checks for security, governance and shared code. |
| Medium | Central and FieldZilla PR-QA plus Architecture Governance account for high execution volume. Phase 2/3 dominates central QA; exact-input technical baseline reuse already exists. | Measure cache hits and adapter-level durations; avoid duplicate cache machinery. Review independent adapters for isolated parallel execution only after proving workspace and failure aggregation safety. |
| Medium | Some repositories track central caller `@main`; others pin immutable RCs. Routine central selector changes can cause base advancement, as shown by central PR #601. | Keep the existing release architecture, inventory caller/engine compatibility, and consider governed consumer selection where already supported. Do not replace protected immutable engine refs with moving refs. |
| Investigate | 39 default branches have no workflow directory; eight have independently maintained workflows. | Confirm activity, effective rulesets, intended CI contract and deployment architecture before recommending enrollment. No blanket workflow copy. |

The changes here require no new cache, runner fleet, service, approval, deployment, or AWS mutation. Larger job-graph changes, PostgreSQL conditionality for consumers, cache exports, and deployment optimizations are deliberately separate because their dependency and security contracts require more evidence.

## Verification and before/after

The condition uses GitHub's documented empty-service-image behavior: an empty `jobs.<job_id>.services.<service_id>.image` skips service startup. `github.repository != 'Synergie-ITCI/.github'` returns `postgres:16` for all consumer repositories and an empty string for central self-QA. The existing service configuration and conditional database setup steps remain unchanged. [GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idservicesservice_idimage) documents this behavior.

Local `actionlint` and the targeted workflow regression test pass. The full local regression run was interrupted after it stalled on a test fixture's local Git push; no local full-suite PASS is claimed. For PR #734 commit `934de46`, [Architecture Governance run 44503474880](https://github.com/Synergie-ITCI/.github/actions/runs/44503474880) and [PR-QA run 44503474807](https://github.com/Synergie-ITCI/.github/actions/runs/44503474807) both passed. The PR-QA job list has no `Initialize containers` step and its `Prepare PostgreSQL test database` step was skipped. Architecture Governance runs the complete central regression suite. These runs validate that commit; a later documentation update requires exact-head checks again. Before/after workflow lifetime, initialization time, job runtime, and failure mix will be recorded against the 30-run central sample above after a comparable post-change cohort. **Actual saving: UNCONFIRMED.**

## Risks and follow-up

- The central service skip relies on the current central test contract. If central tests later require a real database, restore the service or explicitly declare that dependency.
- A public central repository must not publish the complete private repository inventory or unredacted operational details. The restricted workspace retains the full mapping and raw run IDs.
- Build cache storage, poisoning resistance, and recurring cost remain **COST_UNCONFIRMED**. The previously prepared FieldZilla opt-in cache branch defaults off and has no PR or dispatch; it is not an active optimization.
- No production deployment, infrastructure mutation, ruleset change, or protected-branch merge is part of this audit.

**Status: PARTIAL.** The audit and one low-risk central change are in PR #734; hosted QA has passed on a prior PR commit, while final exact-head checks and post-change measurements are required before claiming an efficiency improvement. The next action is to complete governed review, reverify exact-head checks, then decide whether to release the change immutably.
