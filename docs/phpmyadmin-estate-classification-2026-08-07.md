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
