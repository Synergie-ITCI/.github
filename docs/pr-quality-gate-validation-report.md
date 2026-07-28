# PR Quality Gate Validation Report

Status: ready for representative repository validation

Central static validation completed locally:

- Python compile check for `tools/pr_qa_gate.py`
- YAML parse check for reusable workflow
- `git diff --check`
- Local smoke run of `tools/pr_qa_gate.py`

Representative validation must be completed through normal PRs before making
`PR Quality Gate` a required branch-protection check.

Known expected findings during validation:

- Existing repositories without complete PR template evidence will fail evidence validation.
- Repositories with pre-existing failing test scripts will fail the Tests gate.
- Deployment workflow caller PRs will warn under Deployment Risk and Protected Resource Validation.

These findings are intentional and auditable.
