# Residual Risk Register

| Risk | Status | Compensating Control | Owner |
| --- | --- | --- | --- |
| Live CODEOWNERS approval state cannot be verified locally | PARTIALLY CLOSED | Branch Protection must require CODEOWNERS review before merge. Add GitHub API verification in a future online integration. | GitHub administrators |
| Third-party GitHub Actions are tag-pinned, not SHA-pinned | OPEN | Use GitHub org rules to restrict allowed actions; pin SHAs during controlled pilot hardening. | DevSecOps |
| Gitleaks release asset availability | PARTIALLY CLOSED | The workflow installs pinned Gitleaks `8.30.1` with SHA-256 verification before Phase 1 and fails closed if installation or execution is unavailable. | DevSecOps |
| Non-Python dependency scanners may not be installed on all runners | OPEN | The reusable workflow bootstraps Python pip-audit. Central runner images or stack-specific bootstrap must still provide Composer audit, npm audit, govulncheck, Trivy, tfsec/Checkov, etc. | DevSecOps |
| Highly custom encoded/split secrets may evade fallback scanner | PARTIALLY CLOSED | Mandatory Gitleaks plus custom Synergie rules; expand regression corpus during pilot. | Security |
| Full migration semantic parsing is ecosystem-specific | PARTIALLY CLOSED | Current parser catches prior bypass and common destructive patterns; add AST/database-specific parsers per adapter over time. | QA/Security |
| Mutable release tags could undermine immutable framework ref | OPEN | Protect `pr-qa-v1.1` tag or replace with commit SHA after release approval. | GitHub administrators |
| Self-hosted runner contamination | PARTIALLY CLOSED | Workflow now uses GitHub-hosted runners only; keep PR QA off persistent self-hosted runners unless they are ephemeral and isolated. | DevSecOps |
| Executive Reviewer availability gates engineering review | ACCEPTED | Enterprise QA remains automated; Saurabh performs engineering review manually using Codex's native GitHub integration before Executive approval. | Executive Release Authority |
