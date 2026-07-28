# RC2 Release Checklist

Release version: `pr-qa-v1-rc2`

## Completed In RC2 Package

| Item | Status | Evidence |
| --- | --- | --- |
| Standardise release identity | PASS | Active release references use `pr-qa-v1-rc2` |
| Correct README/release docs consistency | PASS | RC2 package uses one state model: not published, real-GitHub verification pending |
| Correct configuration documentation | PASS | Regex YAML examples are quoted |
| Prepare publication verification checklist | PASS | `PUBLICATION_CHECKLIST.md` |
| Audit publication package links/references | PASS | `PACKAGE_AUDIT.md` |
| actionlint | PASS | reusable workflow validates locally |
| schema validation | PASS | sample config validates against hardened schema |
| regression suite | PASS | 10 tests passed |
| Gitleaks framework scan | PASS | 0 findings |
| Gitleaks fixture detection | PASS | 1 expected finding |
| JSON validation | PASS | policy/schema parse cleanly |
| No deployment | PASS | not executed |
| No tag | PASS | not executed |
| No publication | PASS | not executed |
| No application repository changes | PASS | not executed |

## Must Complete During Publication

The items below are not claimed as complete in RC2 because they require the real central Git repository and GitHub Actions environment:

| Item | Status |
| --- | --- |
| Review RC2 diff in actual Git repository | PENDING REAL-GITHUB PUBLICATION |
| Run `git diff --check` in actual Git repository | PENDING REAL-GITHUB PUBLICATION |
| Run actionlint in actual Git repository | PENDING REAL-GITHUB PUBLICATION |
| Run full validation matrix in CI runner image | PENDING REAL-GITHUB PUBLICATION |
| Execute reusable workflow in GitHub Actions | PENDING REAL-GITHUB PUBLICATION |
| Open controlled test PR | PENDING REAL-GITHUB PUBLICATION |
| Validate runner scanner inventory | PENDING REAL-GITHUB PUBLICATION |
| Create/protect `pr-qa-v1-rc2` release reference | PENDING REAL-GITHUB PUBLICATION |
| Publish release notes/artifacts | PENDING REAL-GITHUB PUBLICATION |

## Release Manager State

RC2 is ready for publication verification.

RC2 is not deployed, tagged, or published.
