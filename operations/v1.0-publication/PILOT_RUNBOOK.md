# Pilot Runbook

Release reference: `pr-qa-v1-rc2`

Pilot repository: `Synergie-ITCI/csr-intelligence-engine`

Objective: introduce the framework into exactly one repository through a rollout PR only, then validate behavior with controlled scenario PRs that target the rollout branch. No rollout PR is merged during the pilot.

## Why This Repository

`Synergie-ITCI/csr-intelligence-engine` is the single best first pilot because inventory shows:

- active private repository with default branch `main`
- protected `main`
- CODEOWNERS present
- multiple workflows: `backend-ci.yml`, `frontend-ci.yml`, `deploy-uat.yml`, `release.yml`
- multiple environments: `development`, `staging`, `production`
- representative Python, React/Node, Docker, database migration, deployment, and documentation surfaces

This gives broad signal from one repository while honoring the one-repository pilot constraint.

## Entry Criteria

| Requirement | Required State |
| --- | --- |
| Publication | Central release `pr-qa-v1-rc2` published and protected |
| Workflow resolution | `Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2` resolves |
| Repository access | Operator can branch and open PRs in `csr-intelligence-engine` |
| Branch protection | No changes planned |
| Deployment safety | Scenario PRs target rollout branch, not `main` |

## 1. Prepare Pilot Branch

```bash
export ORG=Synergie-ITCI
export PILOT_REPO=Synergie-ITCI/csr-intelligence-engine
export RELEASE_REF=pr-qa-v1-rc2
export ROLLOUT_BRANCH=rollout/pr-qa-v1-rc2
export WORKDIR=/tmp/pr-qa-pilot-csr-intelligence-engine
git clone "git@github.com:$PILOT_REPO.git" "$WORKDIR"
cd "$WORKDIR"
git fetch origin --prune
git switch -c "$ROLLOUT_BRANCH" origin/main
```

## 2. Add Caller Workflow Only

Copy only the approved rollout files:

```bash
mkdir -p .github/workflows
cp /absolute/path/to/synergie-pr-qa-framework/examples/caller-workflow.yml .github/workflows/pr-qa.yml
cp /absolute/path/to/synergie-pr-qa-framework/examples/pr-qa.yml .github/pr-qa.yml
cp /absolute/path/to/synergie-pr-qa-framework/examples/pull_request_template.md .github/pull_request_template.md
```

Verify the caller reference:

```bash
rg -n "Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2" .github/workflows/pr-qa.yml
actionlint .github/workflows/pr-qa.yml
check-jsonschema --schemafile /absolute/path/to/synergie-pr-qa-framework/schemas/pr-qa.schema.json .github/pr-qa.yml
git diff --check
```

## 3. Open Rollout PR

```bash
git add .github/workflows/pr-qa.yml .github/pr-qa.yml .github/pull_request_template.md
git commit -m "ci: add Synergie PR QA framework pilot"
git push -u origin "$ROLLOUT_BRANCH"
gh pr create \
  --repo "$PILOT_REPO" \
  --base main \
  --head "$ROLLOUT_BRANCH" \
  --title "ci: add Synergie PR QA framework pilot" \
  --body "Pilot rollout PR for Synergie PR QA Framework v1.0 using reusable workflow ref $RELEASE_REF. This PR must not be merged during pilot validation."
```

Required state:

- PR remains open.
- PR is not merged.
- Branch Protection is unchanged.
- Deployment workflows are not triggered manually.

## 4. Scenario Execution Model

All scenario PRs must target `rollout/pr-qa-v1-rc2`, not `main`.

This lets GitHub evaluate the new caller workflow from the rollout branch without changing the protected default branch or production deployment state.

Each scenario PR must be:

- created from a short-lived branch
- marked draft
- labeled `pr-qa-pilot`
- closed after evidence collection
- never merged

## 5. Scenario Matrix

| Scenario | Branch | Change Type | Expected Outcome |
| --- | --- | --- | --- |
| Normal feature PR | `pilot/pr-qa-normal` | Small safe application or test-only change | PASS or expected WARNING |
| Broken build | `pilot/pr-qa-broken-build` | Synthetic change that makes existing build/test fail | FAIL with clear build/test evidence |
| Secret | `pilot/pr-qa-secret` | Approved synthetic secret fixture, never a real credential | FAIL from secret detection with redacted report |
| Deployment change | `pilot/pr-qa-deployment-change` | Synthetic deployment workflow or deploy manifest edit | WARNING or FAIL according to policy |
| Migration | `pilot/pr-qa-migration` | Synthetic database migration file | WARNING or FAIL according to migration policy |
| Documentation change | `pilot/pr-qa-docs` | Docs-only change | PASS or low-risk report |

Do not use real credentials, real customer data, or production deployment changes in any scenario.

## 6. Scenario PR Command Pattern

For each scenario:

```bash
git switch "$ROLLOUT_BRANCH"
git pull --ff-only origin "$ROLLOUT_BRANCH"
git switch -c "<scenario-branch>"
# Apply the approved synthetic scenario change.
git status --short
git diff --check
git add <scenario-files>
git commit -m "test: pr qa pilot <scenario-name>"
git push -u origin "<scenario-branch>"
gh pr create \
  --repo "$PILOT_REPO" \
  --base "$ROLLOUT_BRANCH" \
  --head "<scenario-branch>" \
  --draft \
  --title "test: PR QA pilot <scenario-name>" \
  --body "Synthetic PR QA pilot scenario. Target is rollout branch only. Do not merge."
```

After the workflow completes:

```bash
gh pr checks --repo "$PILOT_REPO" <scenario-pr-number>
gh run list --repo "$PILOT_REPO" --branch "<scenario-branch>" --limit 5
gh run view --repo "$PILOT_REPO" <run-id> --json conclusion,status,createdAt,updatedAt,url
gh run download --repo "$PILOT_REPO" <run-id> --dir "/tmp/pr-qa-pilot-evidence/<scenario-name>"
gh pr close --repo "$PILOT_REPO" <scenario-pr-number> --comment "Closing completed synthetic PR QA pilot scenario. No merge."
```

## 7. Evidence Register

Record one row per scenario:

| Field | Required Value |
| --- | --- |
| Scenario | normal, broken build, secret, deployment change, migration, docs |
| PR URL | GitHub PR URL |
| Base branch | `rollout/pr-qa-v1-rc2` |
| Run URL | GitHub Actions run URL |
| Runtime | start, end, total minutes |
| Expected result | PASS, WARNING, or FAIL |
| Actual result | PASS, WARNING, or FAIL |
| Report artifact | path or URL |
| False positive | yes/no |
| False negative | yes/no |
| Reviewer notes | required |
| Developer notes | required |

## Pilot Review Inputs

Collect:

- runtime p50 and p95 across scenario PRs
- false positives
- false negatives
- developer feedback
- reviewer feedback
- workflow stability
- runner stability
- report readability
- redaction correctness

## Pilot PASS Conditions

Pilot passes only if:

- rollout PR opens cleanly and remains unmerged
- reusable workflow resolves at `pr-qa-v1-rc2`
- normal and documentation PRs do not fail unexpectedly
- broken build fails
- synthetic secret fails and is redacted
- deployment and migration changes are classified according to policy
- no production deployment executes
- no Branch Protection change occurs
- no high-severity false negative is found
- runner instability is not observed

## Pilot STOP Conditions

Stop if any of these occur:

- reusable workflow cannot resolve
- required scanner does not run
- secret scenario is not blocked
- report exposes an unredacted secret
- deployment workflow runs unexpectedly
- GitHub Actions permissions are insufficient
- runner instability prevents reliable results
- rollout PR requires application-code changes to function
