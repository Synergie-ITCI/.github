# Expanded Pilot Runbook

Release reference: `pr-qa-v1-rc2`

Objective: after a successful single-repository pilot, expand validation to three total repositories with different technology and operational profiles. Rollout PRs are opened only and are never merged automatically.

## Entry Criteria

| Requirement | Required State |
| --- | --- |
| Publication | PASS |
| Single repository pilot | PASS |
| Pilot blockers | None open |
| Pilot evidence | Complete and reviewed |
| Release reference | Still immutable and protected |

## Expanded Pilot Set

| Repository | Stack Coverage | Why Included |
| --- | --- | --- |
| `Synergie-ITCI/csr-intelligence-engine` | Python, React/Node, Docker, migrations, deployments | Baseline pilot repository with broadest coverage |
| `Synergie-ITCI/bayer.synergieinsights.in` | Laravel/PHP, Node assets, deployment workflow | Representative production Laravel application with deployment-sensitive workflow history |
| `Synergie-ITCI/fleet-safety-os-edge-runtime` | mobile/edge runtime, Gradle-like build, staging deployment | Covers mobile/edge build and runner behavior distinct from web/backend apps |

Do not add additional repositories during the expanded pilot. If one repository is unavailable, stop and request Release Review Board approval for a substitute.

## Repository Preflight

Run for each repository:

```bash
export TARGET_REPO=<owner/repo>
gh repo view "$TARGET_REPO" --json nameWithOwner,defaultBranchRef,isArchived,isPrivate
gh api "repos/$TARGET_REPO/branches"
gh api "repos/$TARGET_REPO/actions/permissions"
gh api "repos/$TARGET_REPO/contents/.github?ref=<default-branch>"
gh pr list --repo "$TARGET_REPO" --state open --limit 20
```

Expected:

- repository is accessible
- default branch is usable
- repository is not archived
- Actions are enabled
- open PR volume is low enough to avoid disruption

## Rollout PR Pattern

For each repository:

```bash
export RELEASE_REF=pr-qa-v1-rc2
export ROLLOUT_BRANCH=rollout/pr-qa-v1-rc2
git clone "git@github.com:$TARGET_REPO.git" "/tmp/pr-qa-expanded-$(basename "$TARGET_REPO")"
cd "/tmp/pr-qa-expanded-$(basename "$TARGET_REPO")"
git fetch origin --prune
git switch -c "$ROLLOUT_BRANCH" "origin/<default-branch>"
mkdir -p .github/workflows
cp /absolute/path/to/synergie-pr-qa-framework/examples/caller-workflow.yml .github/workflows/pr-qa.yml
cp /absolute/path/to/synergie-pr-qa-framework/examples/pr-qa.yml .github/pr-qa.yml
rg -n "pr-qa-v1-rc2" .github/workflows/pr-qa.yml .github/pr-qa.yml
actionlint .github/workflows/pr-qa.yml
check-jsonschema --schemafile /absolute/path/to/synergie-pr-qa-framework/schemas/pr-qa.schema.json .github/pr-qa.yml
git diff --check
git add .github/workflows/pr-qa.yml .github/pr-qa.yml
git commit -m "ci: add Synergie PR QA framework expanded pilot"
git push -u origin "$ROLLOUT_BRANCH"
gh pr create \
  --repo "$TARGET_REPO" \
  --base "<default-branch>" \
  --head "$ROLLOUT_BRANCH" \
  --title "ci: add Synergie PR QA framework expanded pilot" \
  --body "Expanded pilot rollout PR for Synergie PR QA Framework v1.0 using reusable workflow ref $RELEASE_REF. Do not merge automatically."
```

## Scenario Coverage

Repeat the same scenario model from the single pilot:

- normal feature PR
- broken build
- secret
- deployment change
- migration
- documentation change

Each scenario PR targets that repository's `rollout/pr-qa-v1-rc2` branch and is closed after evidence collection.

## Expanded Pilot Evidence

Record per repository:

| Evidence | Required |
| --- | --- |
| Rollout PR URL | yes |
| Six scenario PR URLs | yes |
| Workflow run IDs | yes |
| Report artifacts | yes |
| Runtime p50 and p95 | yes |
| False positives | yes |
| False negatives | yes |
| Runner failures | yes |
| Reviewer feedback | yes |
| Developer feedback | yes |

## Expanded Pilot PASS Conditions

Expanded pilot passes only if:

- all three rollout PRs open cleanly
- no rollout PR is merged automatically
- all scenario PRs resolve the reusable workflow at `pr-qa-v1-rc2`
- expected failures fail reliably
- expected low-risk changes avoid unexpected failure
- no unredacted secret appears in logs, summaries, or artifacts
- no deployment executes unexpectedly
- no high-severity false negative is recorded
- runner instability is not systemic

## Expanded Pilot STOP Conditions

Stop if:

- any repository cannot resolve the reusable workflow
- any mandatory security scanner does not execute
- synthetic secret is missed in any repository
- runner failures prevent a confident assessment
- operational evidence is incomplete
- developer or reviewer feedback identifies a publication blocker
