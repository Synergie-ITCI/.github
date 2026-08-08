# PR QUALITY REPORT

Repository: `Synergie-ITCI/bayer.synergieinsights.in`
Base Ref: `staging`
Head Ref: `feature/training-report-changes`
Detected Technologies: PHP/Laravel, Node.js, GitHub Actions
PR Size: 12 files, +342 / -76

| Gate | Result |
| --- | --- |
| Repository Hygiene | PASS |
| Formatting | WARNING |
| Lint | WARNING |
| Build | PASS |
| Tests | WARNING |
| Git Validation | PASS |
| Secrets | PASS |
| Dependencies | WARNING |
| Licence | WARNING |
| Deployment Risk | WARNING |
| Migration Risk | PASS |
| Documentation | WARNING |
| Protected Resources | PASS |
| Architecture | WARNING |
| Risk Engine | WARNING |
| Evidence | PASS |
| Review Policy | PASS |

Risk Score: 43 / 100

Overall Result: PASS

Merge Readiness: READY FOR HUMAN REVIEW

## Findings

- WARNING Formatting [PHP/Laravel]: No check-only PHP formatter configured.
- WARNING Lint [PHP/Laravel]: PHP_CodeSniffer is not configured; syntax lint fallback passed.
- WARNING Tests [Node.js]: No automated test suite configured.
- WARNING Dependencies: Gitleaks/actionlint/hadolint runner tooling should be installed for fuller coverage.
- WARNING Documentation: configuration changes were made without documentation updates.
- WARNING Architecture: 2 advisory observation(s).

## Audit Note

Warnings are review evidence. Human reviewers decide whether warnings are acceptable for the change.
