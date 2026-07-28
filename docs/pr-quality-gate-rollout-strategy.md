# PR Quality Gate Rollout Strategy

## Phase 1: Representative Validation

Validate the central gate against representative repositories before making it a
required branch-protection check.

Recommended stack coverage:

- Laravel/PHP LMS repository
- Node or React repository
- React Native repository
- Kotlin/Gradle repository
- Swift package repository

## Phase 2: Organisation Rollout

After Phase 1 is accepted, merge thin caller workflow PRs for confirmed active
repositories.

Existing caller workflow PRs created before this enterprise upgrade should remain
unmerged until Phase 1 is complete. They are safe to keep open because they only
add `.github/workflows/pr-quality-gate.yml`.

## Phase 3: Required Status Check

Only after successful repository validation, manually add `PR Quality Gate` to
branch protection as a required status check.
