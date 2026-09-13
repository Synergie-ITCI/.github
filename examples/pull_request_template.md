# Pull Request

## Business Purpose

Describe the user, operational, compliance, or engineering reason for this change.

## Testing Performed

List the local, automated, staging, or manual validation completed for this PR.

## Rollback Strategy

Explain how this change can be reverted or safely backed out if validation fails.

## Linked Issue

Link the ticket, incident, change request, or approval record.

## Screenshots

Add screenshots for user-interface changes. Use `N/A` only when the PR has no UI impact.

## Operational Notes

Mention migrations, environment variables, deployment changes, background jobs, queues, scheduled tasks, or monitoring changes.

## PR Consolidation

ADDITIONAL_PR_REQUIRED: NO | YES — <reason>

REMAINING_PR_COUNT: <number>

Before creating another sequential PR for this repository-scoped objective, state why this open PR cannot be reused, the exact technical or governance reason, whether separation is unavoidable, and the expected remaining PR count.

## Pre-Merge Checklist

- [ ] Current PR HEAD has been validated; earlier PASS evidence is reused only when relevant inputs are unchanged.
- [ ] Required tests, fixtures, documentation, workflow references, and review fixes are included in this PR.
- [ ] Downstream callers, releases, migrations, rollback, and cross-repository dependencies have been inspected where applicable.
- [ ] Release impact is documented, including whether a tag or activation update is required.
