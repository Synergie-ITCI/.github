# RC2 Validation Report

Release version: `pr-qa-v1-rc2`

Generated: 2026-07-28

## Summary

| Validation Step | Status | Evidence |
| --- | --- | --- |
| Python syntax validation | PASS | `AST syntax OK` |
| Python regression suite | PASS | 10 tests passed |
| Workflow YAML parse validation | PASS | reusable workflow, caller workflow, and sample config parsed as dictionaries |
| actionlint | PASS | `actionlint synergie-pr-qa-framework/.github/workflows/pr-qa.yml` exited 0 |
| Strict schema validation | PASS | `check-jsonschema ... examples/pr-qa.yml` -> `ok -- validation done` |
| JSON validation | PASS | policy and schema parsed with `python3 -m json.tool` |
| Gitleaks framework scan | PASS | framework scan with `.gitleaks.toml` returned 0 findings |
| Gitleaks fixture detection | PASS | isolated fixture scan returned 1 expected finding |
| Detect-only smoke | PASS | detected `GitHub Actions` and `Python` |
| Version reference audit | PASS | active release references standardised on `pr-qa-v1-rc2` |
| Internal package link audit | PASS | markdown links in the RC2 package resolve locally |
| Git validation in real framework repository | NOT EXECUTED | Must run in the actual central Git repository before publication |
| GitHub Actions workflow execution | NOT EXECUTED | Must run from the real central repository before publication |
| Controlled test PR | NOT EXECUTED | Must run in GitHub before publication/rollout |

## Commands Executed Locally

```bash
actionlint synergie-pr-qa-framework/.github/workflows/pr-qa.yml
check-jsonschema --schemafile synergie-pr-qa-framework/schemas/pr-qa.schema.json synergie-pr-qa-framework/examples/pr-qa.yml
gitleaks detect --no-git --source synergie-pr-qa-framework --redact --exit-code 1 --report-format json --report-path /private/tmp/prqa-rc2-gitleaks-framework.json
gitleaks detect --no-git --source synergie-pr-qa-framework/tests/test_pr_qa_regressions.py --redact --exit-code 1 --report-format json --report-path /private/tmp/prqa-rc2-gitleaks-fixture.json
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s synergie-pr-qa-framework/tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -c "import ast, pathlib; [ast.parse(p.read_text(encoding='utf-8'), filename=str(p)) for p in pathlib.Path('synergie-pr-qa-framework/pr-qa').rglob('*.py')]; [ast.parse(p.read_text(encoding='utf-8'), filename=str(p)) for p in pathlib.Path('synergie-pr-qa-framework/tests').rglob('*.py')]; print('AST syntax OK')"
PYTHONDONTWRITEBYTECODE=1 python3 -c "import pathlib, sys; sys.path.insert(0, 'synergie-pr-qa-framework/pr-qa'); import pr_qa; print(type(pr_qa.parse_yaml_or_json(pathlib.Path('synergie-pr-qa-framework/.github/workflows/pr-qa.yml').read_text(encoding='utf-8'))).__name__); print(type(pr_qa.parse_yaml_or_json(pathlib.Path('synergie-pr-qa-framework/examples/caller-workflow.yml').read_text(encoding='utf-8'))).__name__); print(type(pr_qa.parse_yaml_or_json(pathlib.Path('synergie-pr-qa-framework/examples/pr-qa.yml').read_text(encoding='utf-8'))).__name__)"
python3 -m json.tool synergie-pr-qa-framework/policy/pr-qa-policy.json >/dev/null
python3 -m json.tool synergie-pr-qa-framework/schemas/pr-qa.schema.json >/dev/null
PYTHONDONTWRITEBYTECODE=1 python3 synergie-pr-qa-framework/pr-qa/pr_qa.py --repo synergie-pr-qa-framework --detect-only
```

## Regression Suite Result

```text
Ran 10 tests

OK
```

## Publication Validation Not Executed Here

The following checks must be completed in the real central Git repository and GitHub environment:

- `git diff --check`
- full validation matrix in the central repository
- GitHub Actions workflow execution
- controlled test PR
- runner validation
- release reference creation
- release publication

These were intentionally not executed during RC2 preparation.
