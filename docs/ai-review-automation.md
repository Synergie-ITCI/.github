# AI Pull Request Review Automation

Status: Version 1.1 governed enhancement, pending review

## Purpose

AI Pull Request Review automates the advisory engineering review that was previously initiated manually through Codex. It runs only after Enterprise PR QA has completed successfully, including runs that contain non-blocking warnings.

Enterprise PR QA remains the deterministic gatekeeper. AI Review never changes QA results, risk score, merge readiness, approval state, Branch Protection, CODEOWNERS, release governance, or merge requirements.

## Execution Model

The automation runs inside GitHub Actions. It does not depend on a local Mac, an open Codex workspace, or an interactive ChatGPT session.

The caller example is pinned to the pending immutable `pr-qa-v1.1` release reference. Inside the reusable workflow, framework source is also checked out from `Synergie-ITCI/.github` at `pr-qa-v1.1`. The governed implementation pull request does not create the release tag; the tag must be created and protected only during reviewed publication.

Required sequence:

1. Developer opens or updates a pull request.
2. Enterprise PR QA runs in a read-only untrusted QA job.
3. The QA job uploads sanitized report evidence.
4. A fresh trusted publisher job checks out only `Synergie-ITCI/.github@pr-qa-v1.1`.
5. The publisher validates the evidence bundle, repository, PR number, head SHA, schema, completion, sanitisation, and explicit QA PASS.
6. The AI Review Service analyzes only reviewable changed lines.
7. Inline GitHub Pull Request review comments are created, updated, or removed only after current-head verification.
8. The AI Review Markdown and JSON reports are retained with the publisher artifacts.
9. Executive Release Authority review remains required before merge.

## Components

| Component | Responsibility |
| --- | --- |
| `.github/workflows/pr-qa.yml` | Separates read-only untrusted QA from the trusted publisher job that invokes AI Review after validated final QA PASS evidence. |
| `pr-qa/evidence.py` | Validates downloaded QA evidence as untrusted data before comments or provider calls are allowed. |
| `pr-qa/ai_review.py` | Builds the changed-line context, calls the provider, normalizes findings, writes reports, and publishes advisory comments. |
| `pr-qa/review_comments.py` | Manages GitHub Review API comment lifecycle, de-duplication, updates, and stale comment removal. |
| `docs/ai-review-developer-guide.md` | Developer-facing behavior and expectations. |
| `docs/ai-review-validation.md` | Validation evidence and manual production checks. |

## Provider Abstraction

The workflow calls the AI Review Service, not a provider directly.

Current approved provider name:

```text
codex
```

The provider is configured through the reusable workflow inputs and GitHub secrets. Another approved provider can be substituted later without changing the workflow structure.

Provider request shape:

```json
{
  "provider": "codex",
  "model": "codex-review-v1",
  "context": {
    "pull_request": {},
    "instructions": {},
    "files": []
  }
}
```

Provider response shape:

```json
{
  "summary": "Short review summary.",
  "findings": [
    {
      "path": "src/example.py",
      "line": 42,
      "severity": "MEDIUM",
      "category": "Possible Bug",
      "observation": "The value may be None before it is dereferenced.",
      "why_it_matters": "This can fail at runtime for missing input.",
      "recommendation": "Guard the value or return early.",
      "stable_id": "optional-provider-stable-id"
    }
  ]
}
```

Findings are accepted only when `path` and `line` map to a changed pull request diff line.

## GitHub Configuration

Caller workflows must grant:

```yaml
permissions:
  contents: read
  pull-requests: write
```

`pull-requests: write` is required to create Pull Request review comments. No deployment, environment, package, CODEOWNERS, or repository administration permission is requested.

Configure approved provider credentials as repository or organisation secrets:

```text
AI_REVIEW_PROVIDER_URL
AI_REVIEW_PROVIDER_TOKEN
```

Configure approved provider destinations as variables:

```text
AI_REVIEW_APPROVED_HOSTS
AI_REVIEW_APPROVED_INTERNAL_HOSTS
```

Host matching is exact. A URL such as `approved.example.com.attacker.net` does not match `approved.example.com`.

If the endpoint, token, or approved-host governance is missing or invalid, the AI Review step reports `AI Review unavailable` and exits successfully. Enterprise QA is unaffected.

## Scope Controls

AI Review analyzes only changed pull request diff lines. It ignores:

- generated directories
- vendor dependencies
- `node_modules`
- `Pods`
- build output
- distribution output
- binary files
- lock files
- framework regression fixtures

The provider receives redacted diff context and instructions that exclude deterministic QA responsibilities.

## Comment Lifecycle

AI comments use this marker namespace:

```text
<!-- synergie-ai-review:inline-review fingerprint=<fingerprint> -->
```

QA comments use a separate namespace:

```text
<!-- synergie-pr-qa:inline-review fingerprint=<fingerprint> -->
```

The lifecycle manager modifies only comments carrying the matching namespace. AI Review never edits QA inline comments, and QA never edits AI inline comments.

On each successful AI Review run:

- new findings are batched into one submitted GitHub Pull Request review
- existing matching comments are updated after publication succeeds
- obsolete AI comments are removed only after publication succeeds and the PR head SHA is still current
- no ordinary issue comments are created

If the provider is unavailable, existing AI comments are left untouched to avoid hiding unresolved observations during an outage.
If the workflow run is stale because the PR was force-pushed or updated, publication and cleanup are skipped.

## Failure Behavior

AI Review failures never fail Enterprise QA.

Failure examples:

- provider endpoint unavailable
- provider authentication missing
- rate limit
- invalid provider response
- GitHub comment publication issue

The workflow reports the failure in `pr-qa-results/ai-review-report.md` and `pr-qa-results/ai-review-report.json`.

## Governance Invariants

- AI Review is advisory only.
- AI findings never block merges.
- Enterprise QA remains the only automated blocking quality gate.
- Executive Release Authority review remains required.
- GitHub Branch Protection remains authoritative.
- No application repository code is modified by the framework.
