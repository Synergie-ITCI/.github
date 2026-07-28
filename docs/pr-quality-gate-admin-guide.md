# PR Quality Gate Administrator Guide

The Synergie PR Quality Gate is owned centrally in `Synergie-ITCI/.github`.
Repository teams consume it through a thin caller workflow.

## Operating Rules

- Do not change branch protection automatically.
- Do not approve or merge PRs from the automation.
- Keep `Synergie-ITCI/.github/.github/workflows/reusable-pr-quality-gate.yml` as the only central entry point.
- Keep all reusable logic in `tools/pr_qa_gate.py`.
- Add new ecosystem support as a `TechnologyAdapter`.

## Required Branch Protection Step

After a repository has passed rollout validation, an administrator may manually
add `PR Quality Gate` as a required status check in branch protection.

Do this only after at least one representative PR has completed successfully.

## Emergency Disable

Repository-level `.github/pr-qa.yml` may temporarily disable a gate:

```yaml
checks:
  evidence_validation: false
```

Disabling gates should be time-bound and recorded in the PR body.
