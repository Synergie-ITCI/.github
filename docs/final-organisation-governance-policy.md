# Final Organisation Governance Policy

## Scope

This policy applies to every active Synergie repository onboarded to the Enterprise PR QA Platform and every pull request targeting a protected branch in those repositories.

The production framework source of truth is:

```text
Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2
```

No moving references such as `main`, `latest`, development branches, or alias tags may be used for organisation rollout.

## Final Rules

1. Every pull request targeting a protected branch must execute the Enterprise PR QA Framework.
2. Build, tests, secret scanning, dependency security, deployment risk, migration risk, documentation validation, protected resource validation, and repository integrity may never be skipped.
3. QA findings must remain truthful, visible, and unmodified.
4. `SaurabhVermaIN` is the mandatory Executive Approver for every protected-branch pull request.
5. Developers may never approve their own pull requests.
6. If `SaurabhVermaIN` authors or last-pushes a pull request, QA still executes and GitHub remains authoritative. If `require_last_push_approval` blocks self-approval, GitHub Administrator Bypass may be used only under the Executive Release Policy with a mandatory reason and retained audit record.
7. Rollout pull requests introducing Enterprise PR QA follow the same governance and may not merge without `SaurabhVermaIN` approval or a documented Executive administrator bypass path.
8. No automatic merges, direct commits, framework edits, application code edits, deployment edits, infrastructure edits, CODEOWNERS edits, or Branch Protection edits are authorised as part of rollout.

## Merge Authority

The PR QA framework validates and reports. GitHub Branch Protection and repository rulesets remain the only merge authority.

The framework must never:

- approve a pull request
- merge a pull request
- bypass Branch Protection
- suppress a QA finding
- alter a QA result for governance convenience

## Required Evidence

Every protected-branch pull request must retain:

- QA run URL
- Markdown QA report
- JSON QA report
- changed-file list
- approval event from `SaurabhVermaIN`, or administrator bypass evidence when the Executive Release Policy applies
- emergency override audit artifact when administrator bypass is used

Every administrator bypass audit record must include:

- actor
- repository
- branch
- commit SHA
- PR number
- timestamp
- reason
- QA summary at the time of override

## Rollout Constraint

Rollout pull requests may add only:

```text
.github/workflows/pr-qa.yml
.github/pr-qa.yml
```

The repository configuration file is included only when required. All other repository changes require a separate approved pull request outside the Enterprise PR QA rollout.
