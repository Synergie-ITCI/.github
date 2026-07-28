# Inline Review Comments Architecture

Status: Version 1.1 governed enhancement, pending review

## Purpose

Inline GitHub Pull Request review comments make line-specific QA findings visible at the affected code location. The existing Markdown report, JSON report, GitHub job summary, and workflow artifacts remain authoritative evidence.

This capability is reporting only. It does not approve, merge, bypass Branch Protection, suppress QA, alter findings, or change gate outcomes.

## Components

| Component | Responsibility |
| --- | --- |
| `.github/workflows/pr-qa.yml` | Runs PR QA in a read-only untrusted job and invokes inline review publication from a fresh trusted publisher job. |
| `pr-qa/pr_qa.py` | Adds `inline_review.findings` to the JSON report for findings with a specific file and line. |
| `pr-qa/review_comments.py` | Publishes, updates, and removes Synergie-owned inline review comments through the GitHub Pull Request Review API. |
| `pr-qa/evidence.py` | Validates downloaded QA report evidence as untrusted data before publication. |
| `tests/test_pr_qa_regressions.py` | Verifies QA findings produce redacted, line-specific inline review payloads. |
| `tests/test_review_comments.py` | Verifies diff mapping, batching, de-duplication, update, removal, and redaction logic without network calls. |

## Permissions

The reusable workflow grants write permission only to the trusted publisher job:

```yaml
permissions:
  contents: read
```

The untrusted `detect` and `qa` jobs remain `contents: read`. The trusted `publisher` job uses:

```yaml
permissions:
  contents: read
  pull-requests: write
```

`pull-requests: write` is required only to create, update, and remove Pull Request review comments. No repository administration, deployment, package, environment, or CODEOWNERS permission is requested.

Participating caller workflows must grant the same minimum pull request write permission, because a reusable workflow cannot reliably publish review comments if the caller constrains the token to read-only pull request scope.

## Data Flow

1. PR QA executes normally in the read-only QA job.
2. The QA engine writes the existing Markdown and JSON reports with schema, completion, sanitisation, repository, PR number, and head SHA metadata.
3. The QA job uploads report evidence as an artifact.
4. The trusted publisher job starts on a fresh runner and checks out only `job.workflow_repository` at `job.workflow_sha`, the exact commit that defines the called reusable workflow.
5. The publisher downloads only the QA evidence artifact and validates expected filenames, regular files, no symlinks, maximum file sizes, schema, completion, sanitisation, repository, PR number, and head SHA.
6. The review comment service reads the GitHub pull request event and validated QA JSON report.
7. The service fetches the PR file diff through the GitHub API.
8. Findings are published only if their file and line are present in the pull request diff.
9. Existing Synergie-owned comments are matched by fingerprint marker and trusted bot/app author.
10. New replacement comments are batched into one Pull Request review before obsolete comments are updated or removed.

## GitHub Mechanism

The implementation uses the GitHub Pull Request Review API:

- `GET /repos/{owner}/{repo}/pulls/{pull_number}/files`
- `GET /repos/{owner}/{repo}/pulls/{pull_number}/comments`
- `POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews`
- `PATCH /repos/{owner}/{repo}/pulls/comments/{comment_id}`
- `DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}`

The service does not use Issues comments, Checks annotations, reviewdog, Octokit, or GitHub CLI for inline comments.

## Comment Model

Each comment includes:

- title
- severity: `BLOCKING`, `WARNING`, or `ADVISORY`
- explanation
- recommendation
- originating QA gate

Deterministic QA comments contain this internal marker:

```text
<!-- synergie-pr-qa:inline-review fingerprint=<fingerprint> -->
```

AI Engineering Review comments contain this separate marker:

```text
<!-- synergie-ai-review:inline-review fingerprint=<fingerprint> -->
```

Markers are used only for de-duplication and self-healing. Comments without the active marker namespace and trusted publisher author are never modified. QA comment lifecycle runs never edit AI comments, and AI comment lifecycle runs never edit QA comments.

Before any create, update, or delete operation, the publisher fetches the current PR head SHA and compares it with the workflow event and QA report head SHA. If the PR has received a newer commit or force-push, publication and cleanup are skipped.

## Security

Secrets are redacted before entering the JSON report and before comments are rendered. The comment body never includes token, password, API key, or private key values.

Gitleaks and fallback secret scanning behavior are unchanged. Inline comments consume QA findings; they do not suppress or reclassify them.

No repository-controlled command runs inside the trusted publisher job. The publisher treats downloaded artifacts only as validated data and does not execute artifact contents.

## Diff Position Rules

The review service parses GitHub's PR patch hunks and publishes comments only to valid diff positions.

Supported positions:

- added lines in new files
- changed lines in modified files
- changed lines in renamed files
- removed lines on the left side where the QA finding explicitly supplies `side: LEFT`

Findings that cannot be mapped to a valid PR diff line remain visible in the Markdown report, JSON report, workflow summary, and artifacts.

## Governance Invariants

- QA always executes.
- QA findings remain truthful.
- Inline comments are reporting only.
- GitHub Branch Protection remains the merge authority.
- No application repository is modified by this enhancement.
- Publication and rollout require the normal governed pull request process.
