# Removed AI Review Inventory

Generated: 2026-07-28

## Summary

Enterprise PR QA v1.1 no longer contains automated AI review infrastructure. The active framework validates, reports, and enforces deterministic QA only.

## Removed Components

| Component | Removed From Active Framework |
| --- | --- |
| AI Review Service | `pr-qa/ai_review.py` |
| Provider abstraction | `AIReviewProvider`, `ProviderResult`, fixture and HTTP provider implementations |
| HTTP AI provider | provider request, timeout, redirect, response parsing, and destination validation code |
| Provider credentials | `AI_REVIEW_PROVIDER_URL`, `AI_REVIEW_PROVIDER_TOKEN` |
| Provider host governance | `AI_REVIEW_APPROVED_HOSTS`, `AI_REVIEW_APPROVED_INTERNAL_HOSTS` |
| AI workflow inputs | `ai-review-provider`, `ai-review-model` |
| Trusted publisher job | reusable workflow `publisher` job |
| Pull Request Review API publishing | `pr-qa/review_comments.py` and `pull-requests: write` permissions |
| Inline AI comments | AI marker namespace and lifecycle handling |
| Inline QA comment publishing | QA comment publisher and comment lifecycle manager |
| AI review artifacts | `ai-review-report.md`, `ai-review-report.json`, `pr-qa-ai-review-results` |
| AI regression tests | `tests/test_ai_review.py`, AI/comment lifecycle tests in `tests/test_review_comments.py` |
| AI documentation | AI automation, developer, validation, self-review, remediation, and inline-comment architecture docs |

## Retained Components

| Component | Status |
| --- | --- |
| Enterprise QA | retained |
| Build validation | retained |
| Test execution | retained |
| Secret scanning | retained |
| Dependency scanning | retained |
| Deployment validation | retained |
| Migration validation | retained |
| Deterministic architecture checks | retained |
| Risk scoring | retained |
| Governance and Executive Release Authority | retained |
| QA reports and JSON evidence | retained |
| Artifact retention | retained |
| Rollout framework | retained |
| Merge queue compatibility | retained |
| Branch protection model | unchanged |

## Non-Goals

This simplification does not modify application repositories, deployment logic, branch protection, CODEOWNERS, repository permissions, or rollout eligibility policy.
