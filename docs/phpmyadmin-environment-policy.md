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

Before adding or exposing phpMyAdmin outside a developer laptop, the repository must map:

```text
repository -> branch -> actual environment -> actual server -> actual database
```

Branch names are not runtime evidence. A `staging` branch does not prove that a staging server, staging database, or staging phpMyAdmin endpoint exists.

Staging phpMyAdmin must:

- require authentication
- use HTTPS
- connect only to development, staging, or UAT databases
- avoid production database names, hosts, users, and credentials
- avoid hardcoded passwords or database credentials in Git
- use environment-specific secrets/configuration
- avoid empty-password login and config auth
- restrict access by network, VPN, IP allowlist, or equivalent controls where practical
- use an application-scoped database user or access group approved by the application owner
- avoid one company-wide shared database administrator account

If staging phpMyAdmin points to production database metadata, classify the release as:

```text
STAGING PHPMYADMIN POINTS TO PRODUCTION DATABASE
```

Do not rewrite staging database targets automatically without separate approval.

If staging/UAT phpMyAdmin runtime configuration exists but `.github/synergie-governance.yml` does not map the branch, actual environment, server, and database, classify it as:

```text
PHPMYADMIN ENVIRONMENT MAPPING MISSING
```

If a repository attempts to declare a shared company-wide phpMyAdmin administrator account, classify it as:

```text
SHARED PHPMYADMIN ADMIN ACCOUNT PROHIBITED
```

## Application-Scoped Access

phpMyAdmin access is granted per application. A developer may access only the databases assigned to that application and environment.

Do not create or reuse:

- one DBA account shared by all developers
- one phpMyAdmin endpoint pointed at multiple unrelated application databases
- production database credentials in local, development, staging, or UAT phpMyAdmin

The application owner must approve the application-specific developer group or database role. Credentials must live in environment secrets or server configuration, never in Git.

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

Production must also stay disabled in repository governance config:

```yaml
phpmyadmin:
  production:
    allowed: false
```

If a repository changes this to `true`, the policy fails with:

```text
PRODUCTION PHPMYADMIN ENABLED IN GOVERNANCE CONFIG
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
3. Revert the phpMyAdmin reusable validation workflow, schema, template, and examples.
4. Revert this document and related documentation updates.

Do not modify application repositories, production servers, phpMyAdmin installations, or databases as part of rollback unless a separate production remediation is explicitly approved.
