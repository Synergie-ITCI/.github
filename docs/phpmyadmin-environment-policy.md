# Synergie phpMyAdmin Environment Policy

phpMyAdmin is permitted for local, development, and staging/UAT work when it is secured. Production must not expose phpMyAdmin.

The same company pattern applies to PostgreSQL administration with pgAdmin:
development, staging, and UAT pgAdmin are allowed only when authenticated,
mapped to a verified non-production PostgreSQL database, and scoped to the
assigned application owner. Production pgAdmin is prohibited.

## Company Policy

| Environment | Policy |
| --- | --- |
| Local / feature | Allowed. |
| Development | Allowed. |
| Staging / UAT | Allowed with controls. |
| Main / production | Prohibited. |

## PostgreSQL / pgAdmin Policy

pgAdmin follows the phpMyAdmin control model with PostgreSQL-specific role
constraints:

- expose pgAdmin only on verified non-production runtimes
- use `/synergie-pgadmin/` or an equivalent protected non-production route
- require HTTPS, an outer access gate, and pgAdmin authentication
- map repository -> branch -> actual environment -> server -> PostgreSQL database -> PostgreSQL role -> verified developer owner
- use a dedicated application/environment-scoped PostgreSQL role where practical
- do not use `postgres`, superuser, CREATEROLE, BYPASSRLS, replication, production application roles, shared company roles, or cross-application roles
- do not grant public PostgreSQL `5432` access to enable pgAdmin
- preserve existing Row Level Security behavior; do not grant BYPASSRLS for convenience
- do not store PostgreSQL, pgAdmin, or Basic Auth credentials in Git

If staging/UAT pgAdmin points to production database metadata, classify the release as:

```text
STAGING PGADMIN POINTS TO PRODUCTION DATABASE
```

If staging/UAT pgAdmin runtime configuration exists but `.github/synergie-governance.yml` does not map the developer owner, branch, actual environment, server, PostgreSQL database, role identity, and database scope, classify it as:

```text
PGADMIN ENVIRONMENT MAPPING MISSING
```

If the developer owner is not verified, classify it as:

```text
PGADMIN DEVELOPER OWNER NOT VERIFIED
```

If a pgAdmin role uses `postgres`, superuser, CREATEROLE, BYPASSRLS, global/shared, or production privileges, classify it as:

```text
PGADMIN POSTGRES ROLE NOT LEAST PRIVILEGE
```

If a pgAdmin role can administer unrelated application databases, classify it as:

```text
PGADMIN DATABASE ACCESS NOT SCOPED
```

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
- use a database identity scoped only to the assigned application database for that environment
- avoid root, global administrator, shared DBA, production application, or production database credentials
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

If a repository attempts to declare unrestricted or cross-application database administration through phpMyAdmin, classify it as:

```text
PHPMYADMIN DATABASE ACCESS NOT SCOPED
```

If a staging/UAT phpMyAdmin runtime uses a root, global administrator, shared, or production database user identity, classify it as:

```text
STAGING PHPMYADMIN DATABASE USER NOT LEAST PRIVILEGE
```

## Application-Scoped Access

phpMyAdmin access is granted per application. A developer may access only the databases assigned to that application and environment.

The phpMyAdmin interface is not the control boundary. The underlying database user or database role must also be scoped to a single non-production database for the assigned application, for example `saksham_staging` only for Saksham staging. That database identity may have development/staging administration privileges inside that one database, but it must not have global server, cross-database, production, or unrelated application privileges.

Do not create or reuse:

- one DBA account shared by all developers
- one phpMyAdmin endpoint pointed at multiple unrelated application databases
- one database user that can administer multiple unrelated application databases
- root, global administrator, or production application database credentials
- production database credentials in local, development, staging, or UAT phpMyAdmin

The application owner must approve the application-specific developer group or database role. Credentials must live in environment secrets or server configuration, never in Git.

## Standard Non-Production Operating Pattern

Use the Sankalp staging rollout as the reusable Synergie pattern for future development, staging, and UAT applications:

- expose phpMyAdmin only on the approved application vhost, not globally
- use `/synergie-pma/` as the standard route unless an application has a documented conflict
- require HTTPS before exposure
- require an outer Apache Basic Auth gate or stronger equivalent
- store only Apache-compatible password hashes in the Basic Auth file
- keep the Basic Auth file outside every document root, for example under `/etc/apache2`
- use phpMyAdmin cookie authentication for database login
- do not store database passwords in phpMyAdmin config, Apache config, Git, PR comments, or documentation
- set `AllowNoPassword` to false
- set `AllowArbitraryServer` to false unless a separate non-production exception is approved
- set secure and HTTP-only login cookies where supported
- restrict phpMyAdmin's server entry to the one approved non-production database
- disable any package-provided global Apache `/phpmyadmin` alias
- include the phpMyAdmin Apache alias only inside the approved non-production HTTPS vhost
- validate unrelated vhosts do not inherit `/synergie-pma/` or `/phpmyadmin`
- validate public DNS for the non-production hostname resolves to the approved non-production host before declaring the URL ready

The underlying database user remains the real isolation boundary. The database user must be scoped to the assigned application and environment database. A staging database user may administer that staging database, but it must not have global server privileges, `SUPER`, `CREATE USER`, `FILE`, unnecessary `PROCESS`, `GRANT OPTION`, production database access, or cross-application database access.

## Reusable Onboarding Automation

Use the credential-free generator before future non-production onboarding:

```bash
python3 tools/phpmyadmin_nonprod_onboarding.py \
  --application-name Sankalp \
  --environment staging \
  --hostname sankalp-staging.synergieinsights.in \
  --database-name sankalp_staging_db \
  --database-user-identity sankalp_staging_user \
  --database-scope sankalp_staging_db \
  --developer-identity "Raveesh Yadav" \
  --db-classification staging \
  --https-available true \
  --output-dir /tmp/synergie-pma-sankalp-staging
```

The generator refuses production environments, production database classifications, root/global database users, global or cross-application scopes, database names that do not carry the application/environment scope, missing developer ownership, and missing HTTPS. It never generates or stores credentials.

## Credential Delivery

Temporary plaintext bootstrap material is allowed only long enough to deliver a generated Basic Auth credential through the approved secure channel. It must be root-only while it exists.

Do not print, commit, paste, or log the credential. After secure delivery is confirmed, remove the bootstrap file and verify it is absent. If delivery cannot be confirmed, keep the root-only bootstrap file temporarily and report:

```text
CREDENTIAL DELIVERY CONFIRMATION REQUIRED
```

Public endpoint validation must use the real hostname resolution, not only a forced local `--resolve` test. A forced direct-to-host check is useful for diagnosing Apache readiness, but the operating pattern is not complete until DNS also resolves to the approved non-production host.

## Credential Rotation

Rotate a developer's Basic Auth credential without changing application database credentials:

1. Generate a strong replacement password on the target non-production host.
2. Update the Apache Basic Auth file with an Apache-compatible hash such as bcrypt or APR1.
3. Validate the new credential reaches the phpMyAdmin login page.
4. Validate the old credential no longer authenticates.
5. Deliver the new credential through the approved secure channel.
6. Remove any temporary plaintext bootstrap material after delivery confirmation.

Do not rotate merely for demonstration. Rotate when access changes, delivery is uncertain, compromise is suspected, or periodic policy requires it.

## Developer Revocation

To revoke a developer's phpMyAdmin access without uninstalling phpMyAdmin, changing application database credentials, affecting another developer, or restarting unrelated services:

```bash
sudo cp -a /etc/apache2/<application-pma>.htpasswd /etc/apache2/<application-pma>.htpasswd.$(date -u +%Y%m%dT%H%M%SZ).bak
sudo htpasswd -D /etc/apache2/<application-pma>.htpasswd <basic-auth-username>
sudo apache2ctl configtest
sudo systemctl reload apache2
```

Validate the removed identity receives `401` and any remaining authorized identities still work.

## Runtime Rollback

Rollback removes the vhost exposure and leaves application databases untouched:

```bash
sudo cp -a /etc/apache2/sites-enabled/<vhost>.conf /etc/apache2/sites-enabled/<vhost>.conf.rollback.$(date -u +%Y%m%dT%H%M%SZ)
sudo sed -i '\#IncludeOptional /etc/apache2/conf-available/<application-pma>.conf#d' /etc/apache2/sites-enabled/<vhost>.conf
sudo apache2ctl configtest
sudo systemctl reload apache2
```

Do not enable a global `/phpmyadmin` alias during rollback. Do not modify production, production databases, production Apache, production credentials, or unrelated vhosts.

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
