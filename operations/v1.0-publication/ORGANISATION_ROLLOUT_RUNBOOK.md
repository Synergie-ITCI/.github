# Organisation Rollout Runbook

Release reference: `pr-qa-v1-rc2`

Objective: after successful publication, single pilot, and expanded pilot, open rollout PRs across the organisation in controlled waves. Do not merge rollout PRs automatically. Do not change Branch Protection during rollout.

## Entry Criteria

| Requirement | Required State |
| --- | --- |
| Publication | PASS |
| Single pilot | PASS |
| Expanded pilot | PASS |
| Rollback path | Tested through PR close/revert procedure |
| Monitoring | Dashboard ready |
| Stakeholder approval | Release Manager, CTO, DevSecOps, QA, repository owners |
| Executive Release Authority | `SaurabhVermaIN` is configured as required reviewer or sole role holder |
| Last push approval | enabled on protected branches |
| Repository profile | `application` unless governance has approved another profile |

## Rollout Principles

- Open pull requests only.
- Repository owners decide merge timing.
- No automatic merge.
- No Branch Protection updates.
- No deployment workflow changes except the caller workflow PR content.
- Enterprise PR QA must complete for every rollout PR and subsequent pull request.
- Production application repositories use the `application` profile by default.
- The `framework` profile is not used for rollout repositories unless the target is an approved internal engineering framework.
- `SaurabhVermaIN` is the only reviewer who may satisfy protected-branch approval.
- No developer may approve their own pull request.
- `require_last_push_approval` remains enabled.
- Administrator bypass is permitted only for the Executive Release Authority after QA has completed, with a mandatory reason and retained audit evidence.
- Pause waves on the first systemic blocker.

## Wave Plan

### Wave 1: 5 Repositories

| Repository | Reason |
| --- | --- |
| `Synergie-ITCI/csr-intelligence-engine` | Pilot baseline and broad stack coverage |
| `Synergie-ITCI/telemedicine-backend` | Active backend and deployment-sensitive PHP/Laravel-style coverage |
| `Synergie-ITCI/fleet-safety-os-frontend` | Frontend/mobile workflow coverage |
| `Synergie-ITCI/fleet-safety-os-backend` | Backend staging workflow coverage |
| `Synergie-ITCI/bayer.synergieinsights.in` | Production Laravel/deployment workflow coverage |

### Wave 2: 15 Repositories

| Repository |
| --- |
| `Synergie-ITCI/Castrol` |
| `Synergie-ITCI/fleet-safety-os-edge-runtime` |
| `Synergie-ITCI/jiobp.synergielms.com` |
| `Synergie-ITCI/saksham` |
| `Synergie-ITCI/projectdemo.synergielms.com` |
| `Synergie-ITCI/muskaan` |
| `Synergie-ITCI/datamatics.synergielms.com` |
| `Synergie-ITCI/fis.synergielms.com` |
| `Synergie-ITCI/synergielms.com` |
| `Synergie-ITCI/TelemedicineNew` |
| `Synergie-ITCI/scholarship_app` |
| `Synergie-ITCI/verification_service` |
| `Synergie-ITCI/face-duplicate` |
| `Synergie-ITCI/bdpp-admin-auth` |
| `Synergie-ITCI/bdpp-admin-analytics-frontend` |

### Wave 3: Remaining Active Repositories

Wave 3 includes the remaining non-archived repositories with usable default branches from the organisation inventory, excluding repositories with no default branch until repository hygiene is remediated by repository owners.

## Preflight Per Repository

```bash
export TARGET_REPO=<owner/repo>
export DEFAULT_BRANCH=<default-branch>
gh repo view "$TARGET_REPO" --json nameWithOwner,defaultBranchRef,isArchived,isPrivate
gh api "repos/$TARGET_REPO/actions/permissions"
gh api "repos/$TARGET_REPO/branches/$DEFAULT_BRANCH/protection"
gh api "repos/$TARGET_REPO/rulesets"
gh api "repos/$TARGET_REPO/contents/.github?ref=$DEFAULT_BRANCH"
gh pr list --repo "$TARGET_REPO" --state open --limit 20
```

Expected:

- repository accessible
- default branch exists
- repository not archived
- Actions enabled
- protected-branch rulesets require Enterprise PR QA
- protected-branch rulesets require Executive Release Authority approval
- last-push approval is enabled
- bypass actors are restricted to the Executive Release Authority
- repository profile is recorded in the operations dashboard
- open PR volume reviewed
- repository owner notified

## Rollout PR Command Pattern

```bash
export RELEASE_REF=pr-qa-v1-rc2
export ROLLOUT_BRANCH=rollout/pr-qa-v1-rc2
export TARGET_REPO=<owner/repo>
export DEFAULT_BRANCH=<default-branch>
export LOCAL_DIR="/tmp/pr-qa-rollout-$(basename "$TARGET_REPO")"
git clone "git@github.com:$TARGET_REPO.git" "$LOCAL_DIR"
cd "$LOCAL_DIR"
git fetch origin --prune
git switch -c "$ROLLOUT_BRANCH" "origin/$DEFAULT_BRANCH"
mkdir -p .github/workflows
cp /absolute/path/to/synergie-pr-qa-framework/examples/caller-workflow.yml .github/workflows/pr-qa.yml
cp /absolute/path/to/synergie-pr-qa-framework/examples/pr-qa.yml .github/pr-qa.yml
cp /absolute/path/to/synergie-pr-qa-framework/examples/pull_request_template.md .github/pull_request_template.md
rg -n "Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2" .github/workflows/pr-qa.yml
actionlint .github/workflows/pr-qa.yml
check-jsonschema --schemafile /absolute/path/to/synergie-pr-qa-framework/schemas/pr-qa.schema.json .github/pr-qa.yml
git diff --check
git add .github/workflows/pr-qa.yml .github/pr-qa.yml .github/pull_request_template.md
git commit -m "ci: add Synergie PR QA framework"
git push -u origin "$ROLLOUT_BRANCH"
gh pr create \
  --repo "$TARGET_REPO" \
  --base "$DEFAULT_BRANCH" \
  --head "$ROLLOUT_BRANCH" \
  --title "ci: add Synergie PR QA framework" \
  --body "Adds the approved Synergie Enterprise PR QA Framework v1.0 caller workflow pinned to $RELEASE_REF. Repository owners must review. Protected-branch approval must be satisfied by the Executive Release Authority. Do not merge automatically."
```

## Wave Exit Criteria

Each wave may proceed only when:

- all rollout PRs opened successfully
- no rollout PR was merged automatically
- every merged rollout PR has Executive Release Authority approval or a recorded administrator bypass
- every administrator bypass includes a reason and retained QA evidence
- at least 90 percent of rollout PR checks completed without runner infrastructure failure
- every secret-detection failure was expected and redacted
- no high-severity false negative is reported
- repository owner feedback has no unresolved blocker
- rollback procedure remains viable for every open PR

## Wave Stop Criteria

Pause the rollout if:

- reusable workflow resolution fails in more than one repository
- scanner execution is inconsistent across repositories
- self-hosted runner instability affects deployment-sensitive repositories
- any real secret appears in logs or artifacts
- false positives block ordinary documentation or low-risk changes at unacceptable frequency
- repository owners cannot review rollout PRs
- a protected-branch PR merges through developer self-approval
- a non-authority reviewer satisfies protected-branch approval
- administrator bypass is used without completed QA evidence or a specific reason

## Completion Criteria

Organisation rollout is complete only after all selected repositories have:

- an owner-approved rollout PR
- Executive Release Authority approval for non-Saurabh-authored pull requests, or the recorded `SaurabhVermaIN` author exception after all automated gates pass
- a passing or policy-accepted PR QA run
- owner-controlled manual merge
- post-merge workflow verification
- monitoring entry in the operations dashboard
