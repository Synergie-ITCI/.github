# CI/CD efficiency audit

**Snapshot:** 19 November 2026. The central source snapshot was verified against `Synergie-ITCI/.github` `main` at `f9cc21b03e28ec11ebe4bdbac4735b35bc696daf`. This public report contains aggregate inventory and workflow evidence. The full 82-repository inventory is retained in the private CI/CD Efficiency workspace because many repository names and configurations are private.

## Executive summary

Synergie's measured CI time is concentrated in a small set of paths. During 20 October–19 November 2026, GitHub returned **4,446 workflow runs across 24 active repositories** from an inventory of **82 repositories**. Thirty-four repositories have a central PR-QA caller on their default branch; the central repository runs self-QA. Eight other repositories have workflow files but no default-branch central PR-QA caller, and 39 have no `.github/workflows` directory on the default branch. This is a file inventory, not a determination that any repository should be enrolled or has a broken protection rule.

The largest summed workflow lifetimes belong to FieldZilla staging deployment, FieldZilla Architecture Governance and PR-QA, and central PR-QA/Architecture Governance. Workflow lifetime includes waiting, reruns, and external operations, so it is **not billed runner time**. A ten-run job sample for each leading path supplies a narrower runner-runtime proxy. Within central self-QA, 30 recent successful runs spent a median **21 seconds** starting PostgreSQL containers even though the central regression tests use fixtures rather than a live database. The bounded change merged in [PR #734](https://github.com/Synergie-ITCI/.github/pull/734) skips the PostgreSQL service for central self-QA only; consumer QA still receives `postgres:16`.

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
| High | Central self-QA starts PostgreSQL on every run; 21-second median startup across 30 sampled successes, 595 central runs in the window. Central tests use fixtures and no live PostgreSQL connection. | **Merged through PR #734:** conditional service image blank only for `Synergie-ITCI/.github`. Preserve service for every consumer. Validate with actionlint, regression tests and exact-head hosted runs. Prospective saving must be measured after activation. |
| High | FieldZilla image build jobs take 853-second median / 1233-second P90 in a 13-run production cohort; staging example has sequential API/Admin builds. | Assess isolated cache trust, storage cost and build reproducibility; then pilot independent builds or cache on a separate governed FieldZilla branch. Do not alter immutable image digest, review, or one-use publication contracts. |
| Medium | FieldZilla staging-deploy has 48 elapsed hours across 184 runs, with backend/architecture/admin tests and dependency setup dominant in inspected jobs. | Classify failure and workflow operation types; compare test dependency graphs before parallelizing. Keep mandatory full checks for security, governance and shared code. |
| Medium | Central and FieldZilla PR-QA plus Architecture Governance account for high execution volume. Phase 2/3 dominates central QA; exact-input technical baseline reuse already exists. | Measure cache hits and adapter-level durations; avoid duplicate cache machinery. Review independent adapters for isolated parallel execution only after proving workspace and failure aggregation safety. |
| Medium | Some repositories track central caller `@main`; others pin immutable RCs. Routine central selector changes can cause base advancement, as shown by central PR #601. | Keep the existing release architecture, inventory caller/engine compatibility, and consider governed consumer selection where already supported. Do not replace protected immutable engine refs with moving refs. |
| Investigate | 39 default branches have no workflow directory; eight have independently maintained workflows. | Confirm activity, effective rulesets, intended CI contract and deployment architecture before recommending enrollment. No blanket workflow copy. |

The changes here require no new cache, runner fleet, service, approval, deployment, or AWS mutation. Larger job-graph changes, PostgreSQL conditionality for consumers, cache exports, and deployment optimizations are deliberately separate because their dependency and security contracts require more evidence.

## Verification and before/after

The condition uses GitHub's documented empty-service-image behavior: an empty `jobs.<job_id>.services.<service_id>.image` skips service startup. `github.repository != 'Synergie-ITCI/.github'` returns `postgres:16` for all consumer repositories and an empty string for central self-QA. The existing service configuration and conditional database setup steps remain unchanged. [GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idservicesservice_idimage) documents this behavior.

Local `actionlint` and the targeted workflow regression test pass. The full local regression run was interrupted after it stalled on a test fixture's local Git push; no local full-suite PASS is claimed. For PR #734 final head `bdf3e99`, [Architecture Governance run 44511874508](https://github.com/Synergie-ITCI/.github/actions/runs/44511874508) and [PR-QA run 44511874457](https://github.com/Synergie-ITCI/.github/actions/runs/44511874457) both passed. It merged to main as `d63f241`. The PR-QA job list has no `Initialize containers` step and its `Prepare PostgreSQL test database` step was skipped. Architecture Governance runs the complete central regression suite. These runs validate that exact PR head; a later change requires new exact-head checks. Before/after workflow lifetime, initialization time, job runtime, and failure mix will be recorded against the 30-run central sample above after a comparable post-change cohort. **Actual saving: UNCONFIRMED.**

## Risks and follow-up

- The central service skip relies on the current central test contract. If central tests later require a real database, restore the service or explicitly declare that dependency.
- A public central repository must not publish the complete private repository inventory or unredacted operational details. The restricted workspace retains the full mapping and raw run IDs.
- Build cache storage, poisoning resistance, and recurring cost remain **COST_UNCONFIRMED**. The previously prepared FieldZilla opt-in cache branch defaults off and has no PR or dispatch; it is not an active optimization.
- No production deployment, infrastructure mutation, ruleset change, or protected-branch merge is part of this audit.

**Status: PARTIAL.** The audit and central service change merged through PR #734 with exact-head hosted QA. Post-change measurements remain necessary before claiming a measured efficiency improvement. The next action is to gather a comparable run cohort and decide whether an immutable framework release is needed for consumers.

## Central engine code-level follow-up — 19 November 2026

This section evaluates the central engine separately from [PR #734](https://github.com/Synergie-ITCI/.github/pull/734). It uses `main` at `d63f2410e9598b36fd19fac87632a2fe56182900` after PR #734; the engine and adapter source did not change in that interval. No FieldZilla deployment or AWS workflow is changed here.

### Causes and implementation

- `pr-qa/adapters/base.py` used `Path.rglob('*')` in both file helpers and filtered `node_modules`, `vendor`, `.terraform`, and other exclusions only after descending into them. Fifteen adapters independently invoked those helpers; Python fallback detection added another filtered recursive search. The marker-free PHP fallback intentionally still scans for any PHP file, including excluded dependency directories, because removing that legacy signal would change technology selection. `RepositoryFileInventory` now uses one `os.walk` with directory pruning, includes hidden files and symlinked files, and does not follow symlinked directories. The 15 adapters apply their existing name/glob filters to that inventory for normal detection; the rare marker-free PHP fallback remains a separate compatibility scan. `PRContext.run` invalidates its snapshot after a command, so later validation searches can see generated files. Each engine invocation owns its own inventory; there is no cross-workspace cache. Standalone Node and PHP version resolvers also now prune their existing exclusion sets during traversal; their selection logic remains unchanged.
- `pr_qa.py` invokes technology detection once per process, but the QA job starts separate processes for static preflight, technical baseline key, baseline verification, and full validation. The first three are sequential on the same runner before repository-controlled commands. An optional snapshot under `RUNNER_TEMP`, bound to the resolved repository path and exact `HEAD`, lets the two baseline steps reuse static detection. It is rejected outside GitHub Actions or outside runner temporary storage, and invalid input falls back to fresh detection. The full validation phase does not receive the cache and detects afresh after tool setup. The detector job remains independent because GitHub jobs have isolated workspaces, and its release/security identity checks are unchanged. Older approved engine releases ignore the new environment variable and keep their current behavior.
- `promotion_direct_tree_equivalent_checkpoint` performed one `rev-parse` for every commit reachable from the main base plus each candidate staging commit. Two `git log --format=%H %T` calls now return the same commit/tree pairs for the original ranges. The existing shallow-repository and missing-reference failures remain fail closed. `promotion_direct_size_accounting` already caches the checkpoint result within a `PRContext`, so no additional policy cache is introduced.

### Equivalent fixture measurements

The baseline and proposed source were run on the same Mac and fixtures. These are **synthetic, local measurements**, not hosted runner savings. Detection results and root counts matched for every fixture. Small-fixture values are medians of 20 executions; the large fixture and static engine values are single paired executions.

| Fixture / operation | Baseline | Proposed | Result |
| --- | ---: | ---: | --- |
| Node detection | 3.4 ms | 0.4 ms | same one technology/root |
| Laravel with `vendor` detection | 3.4 ms | 0.4 ms | same one technology/root |
| Python detection | 1.9 ms | 0.3 ms | same one technology/root |
| Shell/infrastructure detection | 3.3 ms | 0.5 ms | same two technologies/roots |
| Multi-technology detection | 4.5 ms | 1.2 ms | same six technologies/roots |
| 60,000 excluded dependency files, multi-stack detection | 15.297 s | 0.003 s | same six technologies/roots |
| Same 60,000-file fixture, complete static engine process | 14.56 s | 0.316 s | both returned the same failure status for incomplete synthetic governance evidence |
| Same fixture, standalone Node version resolver | 0.230 s | 0.054 s | same Node 20 output |
| Same fixture, standalone PHP version resolver | 0.143 s | 0.053 s | same PHP 8.2 output |
| Central `.github` checkout detection | 0.503 s | 0.119 s | same three technologies/roots |
| Local Scholarships checkout detection | 0.100 s | 0.044 s | same two technologies/roots |
| Local FieldZilla checkout detection | 0.548 s | 0.433 s | same eight technologies and 19 roots; marker-free PHP fallback still scans for compatibility |
| Promotion checkpoint on the same 100-commit range | 18.67 s | 0.126 s | same empty checkpoint |

Instrumented detection on the large fixture observed **16 `rglob` traversals and 960,096 yielded entries**, of which 960,048 were under excluded directories. The proposed detector used **one `os.walk` traversal, one entered directory, and zero excluded directories entered**. In the promotion fixture, the base had 1,233 reachable commits and the candidate range had ten non-merge first-parent commits; the original path needed approximately 1,248 Git invocations, while the proposed path needs five including existence and shallow checks. These measurements do not establish a proportional reduction in the hosted Phase 2/3 validation step, where external tools and test suites dominate. Runner-minute and monetary savings remain **UNCONFIRMED**.

The runner-local detection snapshot is expected to reduce four QA-job technology-detection executions to two when the updated engine is active: one during static preflight and one during full validation. Detector-job execution remains separate. This count is from the workflow call graph and the snapshot regression test; hosted execution and release activation still require verification. A tiny synthetic static engine fixture showed no material total-time difference (0.264 versus 0.260 seconds median over ten runs), illustrating that the gain depends on repository size and excluded dependency content.
The real-checkout measurements use existing local snapshots, not live consumer heads, and are discovery benchmarks only. Exact detected root paths also matched between implementations on both local consumer snapshots.

### Duplicate staging/main QA assessment and separate migration

The [generic caller](../examples/caller-workflow.yml) triggers for every non-draft PR and uses `pr-qa-${{ github.repository }}-${{ github.event.pull_request.number }}` with cancellation enabled. The [branch-governance template](../workflow-templates/synergie-branch-governance.yml) triggers for staging/main with a different concurrency group and calls [staging quality](../.github/workflows/synergie-quality-gate.yml) or [production gate](../.github/workflows/synergie-production-gate.yml); each wrapper has `run-pr-qa: true` and invokes the central engine. If both templates are deployed unfiltered in one consumer, staging/main PRs can run QA twice. The generic context is `pr-qa / Pull Request Quality Assurance`; wrapper status naming must be verified on that repository's live run before any rule migration. The [onboarding guide](onboarding-guide.md) already instructs owners to exclude wrapper-owned boundaries from the generic caller.

The current 82-default-branch inventory found **34 central generic callers and no consumer workflow file named as the branch-governance template**. Organization code search for the wrapper calls and `run-pr-qa: true` found only central templates and framework files. No affected consumer is confirmed on its default branch; this does not rule out nondefault or newly created branches. Do not change rulesets in this PR. If a consumer adopts the wrapper, first inventory that repository's caller and exact required status contexts, capture an exact-head successful wrapper run, then scope the generic caller only for the wrapper-owned branch while preserving the required PR-QA context through a governed ruleset migration. Validate both staging and main plus an ordinary development PR before retiring any duplicate path. Never leave a required check absent.

### Validation boundary

Targeted inventory, cache-boundary, Python adapter, and promotion regression tests pass locally. `actionlint` passes for `pr-qa.yml`. The complete local suite ran 1,348 tests in 559 seconds: 22 runtime-certifier harness tests errored because the restricted local sandbox denied Unix socket binding (`PermissionError: Operation not permitted`); two tests were skipped. This is a local environment blocker, not a PASS or a demonstrated engine regression. The earlier quiet invocation was interrupted during a long test; an isolated reproduction completed in 2.3 seconds, and the verbose full run continued through that test, so no fixture Git-push deadlock was established. Governed PR-QA, Architecture Governance, full central regression, exact-head checks, and representative consumer compatibility remain required before activation. The new engine is not active in immutable consumer releases merely because this PR exists or later merges.
