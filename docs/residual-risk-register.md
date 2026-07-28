# Residual Risk Register

| Risk | Status | Compensating Control | Owner |
| --- | --- | --- | --- |
| Live CODEOWNERS approval state cannot be verified locally | PARTIALLY CLOSED | Branch Protection must require CODEOWNERS review before merge. Add GitHub API verification in a future online integration. | GitHub administrators |
| Third-party GitHub Actions are tag-pinned, not SHA-pinned | OPEN | Use GitHub org rules to restrict allowed actions; pin SHAs during controlled pilot hardening. | DevSecOps |
| Gitleaks must exist on every publication runner | OPEN | Local RC2 validation has Gitleaks installed and passing; central runner image must also include Gitleaks because the workflow fails if unavailable. | DevSecOps |
| Dependency scanners may not be installed on all runners | OPEN | Central runner image/tool bootstrap must provide Composer audit, npm audit, pip-audit, govulncheck, Trivy, tfsec/Checkov, etc. | DevSecOps |
| Highly custom encoded/split secrets may evade fallback scanner | PARTIALLY CLOSED | Mandatory Gitleaks plus custom Synergie rules; expand regression corpus during pilot. | Security |
| Full migration semantic parsing is ecosystem-specific | PARTIALLY CLOSED | Current parser catches prior bypass and common destructive patterns; add AST/database-specific parsers per adapter over time. | QA/Security |
| Mutable release tags could undermine immutable framework ref | OPEN | Protect `pr-qa-v1-rc2` tag or replace with commit SHA after release approval. | GitHub administrators |
| Self-hosted runner contamination | PARTIALLY CLOSED | Workflow now uses GitHub-hosted runners only; keep PR QA off persistent self-hosted runners unless they are ephemeral and isolated. | DevSecOps |
