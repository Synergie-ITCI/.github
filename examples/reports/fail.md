# PR QUALITY REPORT

Repository: `Synergie-ITCI/jiobp.synergielms.com`
Base Ref: `main`
Head Ref: `feature/sso-login-module`
Detected Technologies: PHP/Laravel, Node.js, GitHub Actions
PR Size: 18 files, +618 / -44

| Gate | Result |
| --- | --- |
| Repository Hygiene | PASS |
| Formatting | PASS |
| Lint | PASS |
| Build | PASS |
| Tests | WARNING |
| Git Validation | PASS |
| Secrets | FAIL |
| Dependencies | SKIP |
| Licence | SKIP |
| Deployment Risk | SKIP |
| Migration Risk | SKIP |
| Documentation | SKIP |
| Protected Resources | SKIP |
| Architecture | SKIP |
| Risk Engine | SKIP |
| Evidence | SKIP |
| Review Policy | SKIP |

Risk Score: 0 / 100

Overall Result: FAIL

Merge Readiness: NOT READY FOR HUMAN REVIEW

## Findings

- FAIL Secrets: High-confidence secret indicators found in changed files.
  - `.env`: environment file committed.
  - `app/Services/SsoClient.php:42`: generic credential assignment.
- WARNING Tests [PHP/Laravel]: No automated test suite configured.

## Audit Note

Secret detection is fail-fast. Later gates are skipped after a blocking secret finding, while the final report is still generated.
