# RC2 Residual Risk Register

Release version: `pr-qa-v1-rc2`

| Risk | Status | Publication Impact | Required Control |
| --- | --- | --- | --- |
| Real Git repository validation not executed in this workspace | OPEN | Publication must not proceed until `git diff --check` and diff review pass in the central repo | Run the publication checklist in `Synergie-ITCI/.github` |
| GitHub Actions execution not performed for RC2 | OPEN | Workflow behavior is locally validated but not proven in GitHub Actions | Run a controlled test PR before rollout |
| `pr-qa-v1-rc2` release reference not created | OPEN | Caller workflows cannot resolve RC2 until publication creates/protects the release ref | Create/protect the ref during approved publication |
| Central runner image not verified for RC2 | OPEN | Mandatory scanners may fail in GitHub-hosted or central runner context | Run runner validation before controlled pilot |
| GitHub connector/private PR access not revalidated | OPEN | Automation around pilot evidence may be incomplete | Verify connector access before pilot execution |
| Third-party GitHub Actions are tag-pinned, not SHA-pinned | ACCEPTED FOR RC2 | External action tag risk remains operationally governed | Enforce allowed-actions policy or SHA pin before broad rollout |
| Framework `.gitleaks.toml` allowlists one intentional fixture | ACCEPTED FOR RC2 | Safe if kept framework-only | Do not copy framework `.gitleaks.toml` into application repositories |

## Risk Decision

RC2 has no remaining engineering blockers in this workspace.

The open items are operational publication checks that must be executed in the real central repository and GitHub Actions environment.
