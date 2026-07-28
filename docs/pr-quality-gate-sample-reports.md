# Sample PR Quality Gate Reports

## PASS

```text
PR QUALITY REPORT

Repository: Synergie-ITCI/example
Detected Technologies: PHP, Laravel

Repository Hygiene
PASS

Git Validation
PASS

Secrets
PASS

Tests
PASS

Evidence Validation
PASS

Risk Engine
LOW
Risk Score: 12 / 100

Overall Result
PASS

Merge Readiness
READY FOR REVIEW
```

## WARNING

```text
Deployment Risk
WARN

Warnings
- Deployment Risk (.github/workflows/deploy.yml:1): Deployment/infrastructure-related file changed; reviewer should inspect manually.

Overall Result
PASS
```

## FAIL

```text
Secrets
FAIL

Blocking Findings
- Secrets (android/app/keystorecred:1): Sensitive credential-like file is part of this PR.

Overall Result
FAIL

Merge Readiness
NOT READY
```
