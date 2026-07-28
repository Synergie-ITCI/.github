# RC2 Publication Checklist

Release version: `pr-qa-v1-rc2`

This checklist must be executed inside the real central framework repository and GitHub environment. It was prepared during RC2 and intentionally not executed here.

## 1. Repository Preparation

```bash
git status --short
git branch --show-current
git remote -v
```

Expected:

- repository is `Synergie-ITCI/.github`
- working tree contains only approved RC2 changes
- branch is the approved release branch

## 2. Git Validation

```bash
git diff --check
git diff --stat
git diff -- .github/workflows/pr-qa.yml examples/caller-workflow.yml examples/pr-qa.yml docs releases/rc2
```

Expected:

- no whitespace errors
- no conflict markers
- diff scope matches approved RC2 publication package

## 3. Workflow And Schema Validation

```bash
actionlint .github/workflows/pr-qa.yml
check-jsonschema --schemafile schemas/pr-qa.schema.json examples/pr-qa.yml
python3 -m json.tool policy/pr-qa-policy.json >/dev/null
python3 -m json.tool schemas/pr-qa.schema.json >/dev/null
```

Expected:

- all commands exit 0

## 4. Python And Regression Validation

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 pr-qa/pr_qa.py --repo . --detect-only
```

Expected:

- regression suite passes
- detect-only identifies GitHub Actions and Python

## 5. Security Scanner Validation

```bash
gitleaks detect --no-git --source . --redact --exit-code 1 --report-format json --report-path /tmp/prqa-rc2-gitleaks-framework.json
gitleaks detect --no-git --source tests/test_pr_qa_regressions.py --redact --exit-code 1 --report-format json --report-path /tmp/prqa-rc2-gitleaks-fixture.json
trivy fs --scanners vuln,secret,misconfig --format json --output /tmp/prqa-rc2-trivy.json .
```

Expected:

- framework Gitleaks scan exits 0 with 0 findings
- direct fixture scan exits nonzero with the expected fixture finding
- Trivy executes successfully

## 6. Runner Validation

```bash
python3 --version
git --version
gh --version
gitleaks version
actionlint --version
jq --version
check-jsonschema --version
node --version
npm --version
php -v
composer --version
go version
govulncheck -version
java -version
gradle --version
dotnet --version
trivy --version
tfsec --version
checkov --version
pip-audit --version
cargo-audit --version
```

Expected:

- every mandatory scanner required by selected pilot repositories is available

## 7. GitHub Actions Workflow Execution

Create an internal release-validation branch in the central repository and run the reusable workflow through a controlled test caller.

Expected:

- reusable workflow resolves at `Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2`
- all checkout steps use `persist-credentials: false`
- static preflight runs before setup/build/test phases
- report artifacts are produced
- no sensitive artifacts are uploaded

## 8. Controlled Test PR

Open one controlled test PR against a non-production pilot/test repository.

Expected:

- caller workflow resolves `pr-qa-v1-rc2`
- normal safe change produces PASS or expected WARNING
- intentional fixture failure produces FAIL
- report is understandable and redacted
- no merge occurs

## 9. Release Reference Creation

Only after all previous steps pass:

```bash
git tag pr-qa-v1-rc2 <approved-commit-sha>
git push origin pr-qa-v1-rc2
```

Expected:

- tag points to the approved RC2 commit
- tag protection or equivalent release governance is enabled

## 10. Release Publication

Publish RC2 release notes and attach/record the validation evidence.

Expected:

- published release references exactly `pr-qa-v1-rc2`
- no non-RC2 caller guidance remains in active release instructions
- rollout remains paused until controlled pilot approval
