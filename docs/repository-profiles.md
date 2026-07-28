# Repository Profiles

## Purpose

Repository profiles let PR QA apply governance-aware classification without weakening technical validation.

The default profile is `application`. Production repositories must not inherit framework fixture behavior.

## Profiles

| Profile | Purpose |
| --- | --- |
| `application` | production and customer-facing application repositories |
| `framework` | internal engineering frameworks carrying policy, schema, test, and release-governance assets |
| `infrastructure` | Terraform, Kubernetes, and deployment-control repositories |
| `library` | shared libraries consumed by applications |
| `documentation` | documentation-only repositories |

## Approved Governance Assets

The central policy defines approved governance assets such as:

- `.gitleaks.toml`
- `.github/**`
- `.gitignore`
- `.editorconfig`
- `.github/CODEOWNERS`
- `policy/**`
- `schemas/**`

These assets bypass only the unexpected-hidden-file integrity finding. They do not bypass protected-resource review, workflow warnings, deployment warnings, secret scanning, or Branch Protection.

Unknown hidden files continue to fail.

## Framework Regression Fixtures

The `framework` profile may classify centrally approved regression fixture paths as non-blocking when the fixture content is intentionally used to test detection.

Current approved fixture path:

```text
tests/test_pr_qa_regressions.py
```

Controls:

- Gitleaks still executes.
- The isolated fixture scan must still detect the intentional fixture.
- Fallback secret detection still blocks the same path under the `application` profile.
- Production repositories do not receive fixture classification by default.

## Operator Usage

Use `application` for rollout repositories unless an approved governance decision assigns another profile.

Use `framework` only for internal framework self-validation, for example:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 pr-qa/pr_qa.py \
  --repo . \
  --repository-profile framework \
  --event-path /tmp/pr-event.json \
  --out /tmp/pr-quality-report.md \
  --json-out /tmp/pr-quality-report.json
```
