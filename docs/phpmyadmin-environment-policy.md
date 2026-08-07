# Synergie phpMyAdmin Environment Policy

phpMyAdmin is permitted for local, development, and staging/UAT work when it is secured. Production must not expose phpMyAdmin.

## Company Policy

| Environment | Policy |
| --- | --- |
| Local / feature | Allowed. |
| Development | Allowed. |
| Staging / UAT | Allowed with controls. |
| Main / production | Prohibited. |

## Staging / UAT Controls

Staging phpMyAdmin must:

- require authentication
- use HTTPS
- connect only to development, staging, or UAT databases
- avoid production database names, hosts, users, and credentials
- avoid hardcoded passwords or database credentials in Git
- use environment-specific secrets/configuration
- avoid empty-password login and config auth
- restrict access by network, VPN, IP allowlist, or equivalent controls where practical

If staging phpMyAdmin points to production database metadata, classify the release as:

```text
STAGING PHPMYADMIN POINTS TO PRODUCTION DATABASE
```

Do not rewrite staging database targets automatically without separate approval.

## Production Gate

The reusable production gate runs:

```text
phpmyadmin-production-check
```

The check blocks staging-to-main PRs that introduce production runtime exposure for phpMyAdmin. It scans runtime and deployment surfaces including:

- phpMyAdmin packages and installation references
- Docker and Docker Compose services
- Apache aliases and virtual hosts
- Nginx locations
- Caddy routes
- Kubernetes workloads, services, and ingresses
- Terraform and CloudFormation resources
- deployment scripts
- production routes such as `/phpmyadmin`, `/phpMyAdmin`, and `/pma`

The check intentionally ignores documentation-only references, tests, examples, and staging-only configuration when they do not affect production runtime exposure.

New production exposure fails with:

```text
PRODUCTION PHPMYADMIN POLICY VIOLATION
```

Existing production exposure outside the current PR diff is reported as:

```text
PRE-EXISTING PRODUCTION PHPMYADMIN VIOLATION
```

Pre-existing exposure must be remediated through a controlled production change. The reusable policy never uninstalls phpMyAdmin, deletes server configuration, restarts production, or changes database access.

## Rollback

To roll back this policy extension:

1. Revert the commit that added `tools/phpmyadmin_policy.py`.
2. Revert the `phpmyadmin-production-check` step in `.github/workflows/synergie-production-gate.yml`.
3. Revert the `phpmyadmin` section in `.github/synergie-governance.schema.json` and `examples/synergie-governance.yml`.
4. Revert this document and related documentation updates.

Do not modify application repositories, production servers, phpMyAdmin installations, or databases as part of rollback unless a separate production remediation is explicitly approved.
