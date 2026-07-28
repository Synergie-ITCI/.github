# RC2 Known Limitations

Release version: `pr-qa-v1-rc2`

| Limitation | Status | Notes |
| --- | --- | --- |
| Real central Git repository validation not executed here | NOT EXECUTED | Required by `PUBLICATION_CHECKLIST.md` |
| GitHub Actions workflow execution not executed here | NOT EXECUTED | Must run in the real GitHub environment |
| Controlled test PR not executed here | NOT EXECUTED | Must run before rollout |
| `pr-qa-v1-rc2` reference not created here | NOT EXECUTED | Must be created/protected during approved publication |
| Application repository compatibility not retested live here | NOT EXECUTED | Covered by the controlled pilot after publication verification |
| Framework Gitleaks allowlist is framework-only | ACCEPTED | Do not copy `.gitleaks.toml` into application repositories |

## Readiness Statement

RC2 does not claim deployment, tag creation, central publication, or organisation rollout.

RC2 claims only that the publication package is internally consistent and ready for real-GitHub publication verification.
