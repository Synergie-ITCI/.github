# Rollback Runbook

Release reference: `pr-qa-v1-rc2`

Objective: disable, revert, or suspend the rollout without disrupting application repositories or production deployments.

## Rollback Principles

- Prefer closing unmerged rollout PRs.
- Do not delete evidence.
- Do not alter Branch Protection.
- Do not force-push release tags.
- Do not rewrite application repository history.
- Communicate rollback state to repository owners before action.

## Scenario 1: Rollout PR Not Merged

Use this path for pilot, expanded pilot, or organisation rollout PRs that remain open.

```bash
export TARGET_REPO=<owner/repo>
export PR_NUMBER=<number>
gh pr close "$PR_NUMBER" \
  --repo "$TARGET_REPO" \
  --comment "Closing Synergie PR QA rollout PR as part of approved rollback. No merge occurred."
```

Optional branch cleanup after owner approval:

```bash
git push origin --delete rollout/pr-qa-v1-rc2
```

Expected:

- rollout PR closed
- default branch unchanged
- no workflow remains active from the rollout branch

## Scenario 2: Rollout PR Merged In One Repository

Use a normal revert PR. Do not push directly to the default branch.

```bash
export TARGET_REPO=<owner/repo>
export DEFAULT_BRANCH=<default-branch>
export REVERT_BRANCH=revert/pr-qa-v1-rc2
git clone "git@github.com:$TARGET_REPO.git" "/tmp/pr-qa-rollback-$(basename "$TARGET_REPO")"
cd "/tmp/pr-qa-rollback-$(basename "$TARGET_REPO")"
git fetch origin --prune
git switch -c "$REVERT_BRANCH" "origin/$DEFAULT_BRANCH"
git rm .github/workflows/pr-qa.yml
git rm .github/pr-qa.yml
git rm .github/pull_request_template.md
git status --short
git diff --check
git commit -m "ci: revert Synergie PR QA framework rollout"
git push -u origin "$REVERT_BRANCH"
gh pr create \
  --repo "$TARGET_REPO" \
  --base "$DEFAULT_BRANCH" \
  --head "$REVERT_BRANCH" \
  --title "ci: revert Synergie PR QA framework rollout" \
  --body "Reverts the Synergie PR QA rollout in this repository. This PR does not change application code or deployments."
```

If a repository already had a PR template before rollout, restore that exact previous template from Git history instead of deleting it.

## Scenario 3: Framework Release Must Be Suspended

Use this if the central reusable workflow has a production issue after publication.

```bash
export CENTRAL_REPO=Synergie-ITCI/.github
export RELEASE_REF=pr-qa-v1-rc2
gh release edit "$RELEASE_REF" \
  --repo "$CENTRAL_REPO" \
  --prerelease \
  --latest=false
```

Then:

- pause all open rollout PRs
- notify repository owners
- close or hold scenario PRs
- open a central incident record
- preserve tag, workflow, run logs, and artifacts

Do not delete or retarget `pr-qa-v1-rc2` without explicit Release Review Board approval.

## Scenario 4: Caller Workflow Must Be Disabled Temporarily

If a repository owner needs a temporary hold before a revert PR merges, close or keep the rollout PR unmerged. If already merged, open a revert PR and request expedited review.

Do not add repository secrets, bypass approvals, disable GitHub Actions globally, or edit Branch Protection as a rollback shortcut.

## Rollback Evidence

Record:

| Field | Required |
| --- | --- |
| Trigger | incident, false positive, false negative, runner instability, owner request |
| Repository | owner/repo |
| PR URL | rollout or revert PR |
| Workflow run URL | if applicable |
| Action taken | close, revert PR, release suspension |
| Time started | timestamp |
| Time completed | timestamp |
| Approval | approver and channel |
| Residual impact | none, low, medium, high |

## Rollback Exit Criteria

Rollback is complete only when:

- affected rollout PRs are closed or reverted
- no automatic merge occurred
- impacted repositories have no unexpected active PR QA caller workflow
- repository owners are notified
- incident evidence is preserved
- Release Manager records final status
