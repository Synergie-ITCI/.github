# AI Review Developer Guide

## Purpose

AI Review provides automated Staff Engineer-style feedback on pull request changes after Enterprise PR QA has completed successfully.

It is advisory. It does not approve a pull request, block a pull request, change QA status, or replace Executive Release Authority review.

## What You Will See

When a finding maps to a changed line, GitHub shows an inline Pull Request review comment.

Each comment includes:

- severity
- category
- observation
- why it matters
- recommended improvement

AI Review also writes:

```text
pr-qa-results/ai-review-report.md
pr-qa-results/ai-review-report.json
```

These artifacts appear alongside the normal Enterprise PR QA report artifacts.

AI Review is published from a separate trusted GitHub Actions job. Repository build, lint, and test commands run earlier in the read-only QA job and never receive the AI provider credential or pull request write token.

## Severity

| Severity | Meaning | Merge Effect |
| --- | --- | --- |
| `CRITICAL` | Likely production issue requiring attention | advisory only |
| `HIGH` | Potential production defect | advisory only |
| `MEDIUM` | Likely engineering improvement | advisory only |
| `LOW` | Minor maintainability issue | advisory only |
| `INFO` | Suggestion or clarification | advisory only |

No AI severity blocks merge. Enterprise QA and GitHub Branch Protection remain authoritative.

## Review Scope

AI Review looks only at changed pull request lines. It may use nearby diff context to understand the change, but it does not perform a full repository audit.

AI Review ignores generated files, vendor dependencies, binary files, lock files, and framework regression fixtures.

## Updating Comments

When you push a new commit:

1. Enterprise PR QA reruns.
2. If QA succeeds, AI Review reruns.
3. The publisher confirms the workflow event, QA report, and current pull request head SHA all match.
4. New AI findings are added in a batched review.
5. Existing AI comments are updated or removed only after publication succeeds and the head SHA is still current.

The automation avoids reposting duplicate comments.

## If AI Review Is Unavailable

The PR may show `AI Review unavailable` in the job summary or artifacts. This does not fail Enterprise QA and does not change merge governance.

Examples include provider downtime, missing provider credentials, unapproved provider destination, missing authoritative QA PASS evidence, rate limits, stale workflow runs after force-push, or comment publication issues.

## Review Expectations

Treat AI comments like senior engineering advice:

- address clear bugs or safety issues
- use judgement for maintainability suggestions
- ask the repository owner or Executive Release Authority when a recommendation conflicts with product constraints
- do not treat AI comments as approval

SaurabhVermaIN remains the Executive Release Authority for protected-branch approval.
