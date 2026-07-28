# Publication Runbook

Release reference: `pr-qa-v1-rc2`

Central repository: `Synergie-ITCI/.github`

Objective: publish the approved framework package into the central GitHub repository, create an immutable release reference, verify workflow integrity, and stop before any application rollout.

## Entry Criteria

| Requirement | Required State |
| --- | --- |
| Release approval | v1.0 approved for publication |
| Local package | RC2 documents and validation evidence present |
| Framework code | Frozen |
| GitHub permissions | Maintainer or release-manager access to `Synergie-ITCI/.github` |
| Release identity | `pr-qa-v1-rc2` only |
| Executive Release Authority | `SaurabhVermaIN` configured as required reviewer or sole role holder |
| Required QA | Enterprise PR QA required before merge |
| Last push approval | enabled |

## Operator Variables

Set these values exactly before running publication commands:

```bash
export ORG=Synergie-ITCI
export CENTRAL_REPO=Synergie-ITCI/.github
export RELEASE_REF=pr-qa-v1-rc2
export RELEASE_BRANCH=release/pr-qa-v1-rc2-publication
export APPROVED_SOURCE=/absolute/path/to/synergie-pr-qa-framework
export WORKDIR=/tmp/synergie-pr-qa-publication
```

`APPROVED_SOURCE` must point to the approved RC2 package. Do not use a partially edited working directory.

## 1. Authentication And Access Check

```bash
gh auth status
gh api user
gh repo view "$CENTRAL_REPO" --json nameWithOwner,defaultBranchRef,isPrivate
gh api "repos/$CENTRAL_REPO/actions/permissions"
gh api "repos/$CENTRAL_REPO/rulesets"
gh api rate_limit
```

Expected:

- `gh auth status` shows a valid authenticated user.
- The authenticated user can read `Synergie-ITCI/.github`.
- Actions permissions are readable.
- Rulesets are readable and confirm protected-branch governance.
- API rate limit has enough remaining calls for publication and verification.

Stop if any command fails.

## 2. Clone Central Repository

```bash
git clone "git@github.com:$CENTRAL_REPO.git" "$WORKDIR"
cd "$WORKDIR"
git remote -v
git fetch origin --tags --prune
git status --short
git branch --show-current
git ls-remote --tags origin "$RELEASE_REF"
```

Expected:

- Remote is `Synergie-ITCI/.github`.
- Working tree is clean.
- No existing remote tag named `pr-qa-v1-rc2`.

Stop if the tag already exists and does not point to the approved commit.

## 3. Create Publication Branch

```bash
git switch -c "$RELEASE_BRANCH" origin/main
git status --short
```

Expected:

- Branch is created from the current central default branch.
- Working tree is clean before package copy.

## 4. Copy Approved Framework Package

Use a controlled copy from the approved source package. Preserve the approved directory structure.

```bash
mkdir -p .github/workflows pr-qa schemas policy examples docs releases operations tests
cp "$APPROVED_SOURCE/.gitleaks.toml" ".gitleaks.toml"
cp "$APPROVED_SOURCE/.github/workflows/pr-qa.yml" ".github/workflows/pr-qa.yml"
cp -R "$APPROVED_SOURCE/pr-qa/." "pr-qa/"
cp -R "$APPROVED_SOURCE/schemas/." "schemas/"
cp -R "$APPROVED_SOURCE/policy/." "policy/"
cp -R "$APPROVED_SOURCE/examples/." "examples/"
cp -R "$APPROVED_SOURCE/docs/." "docs/"
cp -R "$APPROVED_SOURCE/releases/." "releases/"
cp -R "$APPROVED_SOURCE/operations/." "operations/"
cp -R "$APPROVED_SOURCE/tests/." "tests/"
cp "$APPROVED_SOURCE/README.md" "README.md"
```

If the central repository has existing unrelated organisation files, do not delete or overwrite them unless they are part of the approved framework package path.

## 5. Local Publication Validation

```bash
git status --short
git diff --check
git diff --stat
rg -n "Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2|ref: pr-qa-v1-rc2" .github examples
! rg -n "Synergie-ITCI/\\.github/\\.github/workflows/pr-qa\\.yml@(pr-qa-v1-rc1|pr-qa-v1|latest)([\"'[:space:]#]|$)|ref:[[:space:]]*[\"']?(pr-qa-v1-rc1|pr-qa-v1|latest)[\"']?([[:space:]#]|$)" .github examples
actionlint .github/workflows/pr-qa.yml
check-jsonschema --schemafile schemas/pr-qa.schema.json examples/pr-qa.yml
python3 -m json.tool policy/pr-qa-policy.json >/dev/null
python3 -m json.tool schemas/pr-qa.schema.json >/dev/null
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 pr-qa/pr_qa.py --repo . --detect-only
PYTHONDONTWRITEBYTECODE=1 python3 pr-qa/pr_qa.py --repo . --repository-profile framework --static-only --out /tmp/prqa-publication-self-report.md --json-out /tmp/prqa-publication-self-report.json
gitleaks detect --no-git --source . --redact --exit-code 1 --report-format json --report-path /tmp/prqa-publication-gitleaks-framework.json
gitleaks detect --no-git --source tests/test_pr_qa_regressions.py --redact --exit-code 1 --report-format json --report-path /tmp/prqa-publication-gitleaks-fixture.json
trivy fs --scanners vuln,secret,misconfig --format json --output /tmp/prqa-publication-trivy.json .
```

Expected:

- `git diff --check` exits 0.
- Version audit confirms active reusable workflow references use `pr-qa-v1-rc2` and do not use `pr-qa-v1`, `pr-qa-v1-rc1`, or `latest`.
- `actionlint` exits 0.
- Schema, JSON, Python regression, detect-only, and security scans behave exactly as recorded in the RC2 validation report.
- Framework self-validation uses the explicit `framework` repository profile. Approved governance assets pass repository integrity, approved regression fixtures are classified as isolated, and workflow/protected-resource/deployment warnings remain visible.
- Framework Gitleaks scan has 0 findings.
- Fixture Gitleaks scan detects the expected regression fixture finding.

Stop if any mandatory validation fails.

## 6. Commit Publication Package

```bash
git add .gitleaks.toml .github/workflows/pr-qa.yml pr-qa schemas policy examples docs releases operations tests README.md
git diff --cached --check
git diff --cached --stat
git commit -m "release: publish Synergie PR QA framework v1.0"
git rev-parse HEAD
git push -u origin "$RELEASE_BRANCH"
```

Record:

- commit SHA
- branch URL
- validation command output

The `release:` commit type is an approved governed release-publication convention. Do not use informal release messages outside the configured convention.

## 7. Open Publication Pull Request

```bash
gh pr create \
  --repo "$CENTRAL_REPO" \
  --base main \
  --head "$RELEASE_BRANCH" \
  --title "release: publish Synergie PR QA framework v1.0" \
  --body "Publishes the approved Synergie PR QA Framework v1.0 package with immutable reusable workflow reference $RELEASE_REF. This PR does not roll out the framework to application repositories."

export PUBLICATION_PR_NUMBER=<created-publication-pr-number>
```

Required governance approval:

- Executive Release Authority: `SaurabhVermaIN`

Supplemental publication sign-off:

- Release Manager
- Principal DevSecOps Engineer
- Platform Owner
- GitHub Organisation Administrator

Supplemental sign-off does not satisfy protected-branch approval unless the reviewer is also the Executive Release Authority.

Do not merge until all approvals and PR checks pass.

Publication governance requirements:

- PR QA must complete before any merge decision.
- `SaurabhVermaIN` is the only reviewer who may satisfy the protected-branch approval requirement.
- No author or last pusher may satisfy their own approval.
- `require_last_push_approval` must remain enabled.
- If the publication PR is authored or last-pushed by `SaurabhVermaIN`, GitHub must not treat the PR as self-approved.
- If GitHub blocks the Executive Release Authority from approving because of self-approval protection, use GitHub Administrator Bypass only after QA has completed.
- The administrator bypass reason is mandatory.
- Preserve the PR QA Markdown report, PR QA JSON report, and emergency override audit artifact with the publication evidence.

Record before merge:

```bash
gh pr view "$PUBLICATION_PR_NUMBER" \
  --repo "$CENTRAL_REPO" \
  --json author,headRefName,headRefOid,mergeStateStatus,reviewDecision,latestReviews,statusCheckRollup,url
```

Expected:

- PR QA evidence is available.
- protected-branch review decision is satisfied by the Executive Release Authority, or GitHub Administrator Bypass is explicitly required for an Executive-authored or last-pushed PR.
- no merge occurs without either a valid Executive Release Authority approval or a recorded administrator bypass.

## 8. Post-Merge Integrity Verification

After the publication PR is approved and manually merged:

```bash
git switch main
git pull --ff-only origin main
git rev-parse HEAD
git show --stat --oneline HEAD
actionlint .github/workflows/pr-qa.yml
check-jsonschema --schemafile schemas/pr-qa.schema.json examples/pr-qa.yml
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Record the approved merge commit SHA as:

```bash
export APPROVED_COMMIT_SHA=<approved-merge-commit-sha>
```

## 9. Create Immutable Release Tag

Create the release tag only after post-merge validation passes.

```bash
git tag -s "$RELEASE_REF" "$APPROVED_COMMIT_SHA" -m "Synergie Enterprise PR QA Framework v1.0"
git show "$RELEASE_REF" --stat --oneline
git push origin "$RELEASE_REF"
git ls-remote --tags origin "$RELEASE_REF"
```

If signing is not configured, stop for release-manager approval before using an annotated tag:

```bash
git tag -a "$RELEASE_REF" "$APPROVED_COMMIT_SHA" -m "Synergie Enterprise PR QA Framework v1.0"
```

Required control:

- Enable tag protection or repository ruleset protection for `pr-qa-v1-rc2`.
- Never force-push, delete, or retarget the release tag.

## 10. Publish GitHub Release

```bash
gh release create "$RELEASE_REF" \
  --repo "$CENTRAL_REPO" \
  --title "Synergie Enterprise PR QA Framework v1.0" \
  --notes-file releases/rc2/README.md

gh release view "$RELEASE_REF" --repo "$CENTRAL_REPO"
```

Expected:

- Release points to `pr-qa-v1-rc2`.
- Release notes match `releases/rc2/README.md`.
- No application repositories are modified.

## 11. Verify Reusable Workflow Resolution

```bash
gh workflow view pr-qa.yml --repo "$CENTRAL_REPO"
gh api "repos/$CENTRAL_REPO/contents/.github/workflows/pr-qa.yml?ref=$RELEASE_REF"
git archive --format=tar "$RELEASE_REF" | shasum -a 256
```

Record:

- workflow API response status
- workflow file SHA
- tag object SHA
- archive SHA-256

## Publication Exit Criteria

| Criterion | Required Result |
| --- | --- |
| Central repository publication PR | Merged manually after approvals |
| Release tag | `pr-qa-v1-rc2` exists and is protected |
| GitHub release | Published against `pr-qa-v1-rc2` |
| Workflow resolution | API can read `.github/workflows/pr-qa.yml` at `pr-qa-v1-rc2` |
| Integrity evidence | commit SHA, tag SHA, workflow SHA, archive hash recorded |
| Application rollout | Not started |

Proceed to pilot only if every criterion passes.
