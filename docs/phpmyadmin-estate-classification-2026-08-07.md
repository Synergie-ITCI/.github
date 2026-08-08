# phpMyAdmin Estate Classification - 2026-08-07

Scope: read-only GitHub repository and deployment-configuration search across active `Synergie-ITCI` repositories. No production servers, databases, Apache/Nginx/Caddy configs, or phpMyAdmin installations were modified.

## Searches Performed

- `phpmyadmin`
- `"/phpmyadmin"`
- `PMA_HOST`
- `PMA_PASSWORD`
- `phpmyadmin/phpmyadmin`

## Findings

### COMPLIANT

- `Synergie-ITCI/synergielms.com`
  - Documentation and internal IT portal UI explicitly state that phpMyAdmin/Adminer/database consoles are not exposed.
  - No runtime phpMyAdmin route, Docker image, package, or PMA environment variable was found by GitHub code search.

### STAGING PHPMYADMIN PRESENT - SECURE

- None proven from repository evidence.

### STAGING PHPMYADMIN REQUIRES HARDENING

- None found from repository evidence.

### PRE-EXISTING PRODUCTION PHPMYADMIN VIOLATION

- None found from repository/deployment configuration evidence.

### NO PHPMYADMIN

All active repositories except the references listed below had no GitHub code-search match for `phpmyadmin`, `"/phpmyadmin"`, `PMA_HOST`, `PMA_PASSWORD`, or `phpmyadmin/phpmyadmin`.

Non-runtime references found:

- `Synergie-ITCI/BP-New`
  - `application/logs/log-2020-09-01.php`
  - `application/logs/log-2020-09-10.php`
  - Classification: historical 404 log entries for automated requests to phpMyAdmin/PMA paths; not deployment exposure.
- `Synergie-ITCI/BP`
  - `application/logs/log-2020-09-01.php`
  - `application/logs/log-2020-09-10.php`
  - Classification: historical 404 log entries for automated requests to phpMyAdmin/PMA paths; not deployment exposure.
- `Synergie-ITCI/synergielms.com`
  - `INTERNAL_IT_PORTAL_V1_RELEASE_REPORT.md`
  - `resources/views/admin-pages/internal-it/show.blade.php`
  - Classification: documentation/UI text stating direct database consoles are not exposed; not deployment exposure.

### MANUAL REVIEW REQUIRED

- Runtime server exposure outside repository/deployment configuration was not verified in this pass. The reusable policy distinguishes this explicitly: repository absence does not prove production absence.
- A later controlled read-only runtime audit may probe approved production and staging URLs for `/phpmyadmin`, `/phpMyAdmin`, and `/pma`, and inspect server configuration through the approved operational access path.

## Result

Repository/deployment-config classification: PASS

Runtime exposure classification: NOT VERIFIED

## 2026-08-08 Governance Update

The reusable governance framework now requires an explicit phpMyAdmin environment map before non-production runtime phpMyAdmin is treated as configured:

```text
repository -> branch -> actual environment -> actual server -> actual database
```

GitHub branch names and GitHub environment names are evidence of release workflow shape only. They are not sufficient proof of an actual phpMyAdmin runtime, web-server target, or database target.

### GitHub Environment Evidence Found

The following active repositories had GitHub environments that may correspond to non-production targets and should be prioritized for application-owner mapping before any runtime phpMyAdmin setup:

| Repository | GitHub environment evidence | Runtime phpMyAdmin status |
| --- | --- | --- |
| `fleet-safety-os-backend` | `uat` | NOT VERIFIED |
| `fleet-safety-os-edge-runtime` | `uat` | NOT VERIFIED |
| `fleet-safety-os-frontend` | `uat` | NOT VERIFIED |
| `muskaan` | `staging` | NOT VERIFIED |
| `projectdemo.synergielms.com` | `projectdemo-legacy-staging`, `projectdemo-production` | NOT VERIFIED |
| `sankalp` | `sankalp-uat`, `sankalp-production` | NOT VERIFIED |
| `scholarship_app` | `uat` | NOT VERIFIED |
| `synergie-hub` | `production` only | Production phpMyAdmin prohibited; no non-production GitHub environment found |
| `telepathy-operations-web` | `staging`, `production` | NOT VERIFIED |

No repository in this update had a verified combination of non-production server, document root or equivalent runtime path, and non-production database name sufficient to deploy or expose phpMyAdmin. Runtime installation/configuration therefore remains intentionally not performed.

### Repository Connection Status

The company-level reusable policy is implemented in `Synergie-ITCI/.github`. Application repositories should connect to it only after the central governance PR is merged to `.github@main`; otherwise callers that reference `Synergie-ITCI/.github/...@main` cannot resolve the new reusable workflow.

Until each application maps an actual non-production server and database in `.github/synergie-governance.yml`, any proposed staging/UAT phpMyAdmin runtime configuration must fail non-production validation with:

```text
PHPMYADMIN ENVIRONMENT MAPPING MISSING
```
