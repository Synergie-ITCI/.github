# Migration Guide For Existing Repositories

1. Confirm the repository is mapped to a Synergie system and domain.
2. Confirm `.github/CODEOWNERS` exists on the default branch.
3. Add the thin caller workflow.
4. Open a validation PR.
5. Fix objective blockers reported by the gate.
6. Tune `.github/pr-qa.yml` only when a repo has a legitimate ecosystem-specific exception.
7. After stable validation, add the status check manually to branch protection.

Do not use the QA rollout to change application code, deployment logic, branch
protection, permissions, or CODEOWNERS.
