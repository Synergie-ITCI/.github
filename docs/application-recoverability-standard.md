# Synergie Application Recoverability Standard

This standard exists so Synergie can recover production applications when the
production server, staging server, developer laptops, original developer, local
folders, and manually preserved ZIP files are all unavailable.

The core control is:

> Ignored from Git must never mean not backed up anywhere.

Every recovery-critical component must either be tracked in Git, tracked in Git
LFS, stored in approved immutable artifact/object storage, stored in approved
secret management, covered by database backup, or covered by persistent storage
backup. If none of those is true, the application is not recoverable.

## Source Of Truth Classes

Store in Git:

- application source, routes, controllers, models, services, migrations, views,
  templates, scripts, build configuration, deployment templates, restore
  runbooks, dependency manifests, dependency lockfiles, and public static assets
  required to build or run the application
- sanitized `.env.example` or equivalent environment schema
- sanitized Apache/Nginx/Caddy, cron, systemd, supervisor, queue, and scheduler
  templates when application-specific

Store in Git LFS or approved versioned artifact storage:

- large required media, model files, training assets, design/runtime binaries,
  large PDFs/templates, and binary libraries that are not reproducibly
  downloadable elsewhere

Restore reproducible dependencies instead of committing:

- `vendor/`, `node_modules/`, virtualenvs, Gradle caches, build caches, and
  generated dependency directories
- required evidence: manifest, lockfile, runtime version, and build command

Store secrets only in approved secret management:

- AWS Secrets Manager or SSM Parameter Store
- never Git, PR comments, Slack, email, local notes, or recovery ZIP files

Protect database and persistent runtime data outside Git:

- production databases need backup frequency, retention, encryption, restore
  procedure, last successful backup, and restore-test evidence
- uploads, user media, documents, attachments, generated certificates, and other
  persistent runtime data must live in object storage or independently backed-up
  persistent storage

Runtime-generated data normally does not need recovery:

- logs, caches, sessions, temporary files, and local build outputs, unless an
  application explicitly classifies one as recovery-critical

## Recovery Manifest

Every deployable application repository must contain:

```text
.github/synergie-recovery.yml
```

The manifest is machine-readable and must not contain secret values. It must
classify source, assets, dependencies, external artifacts, secret references,
database backups, persistent uploads, deployment traceability, health checks,
rollback, RTO/RPO, and recovery ownership.

The schema is published at:

```text
.github/synergie-recovery.schema.json
```

An example is available at:

```text
examples/synergie-recovery.yml
```

## Ignore Policy

Normally safe to ignore:

- `.env`, logs, cache, temporary files, IDE metadata, OS files, dependency
  folders, build caches, and generated runtime files

Never blindly ignore:

- application assets, custom public JavaScript/CSS, custom images, templates,
  application-specific libraries, custom fonts, certificate templates without
  private key material, generated-looking files required at runtime, and
  application-owned frontend bundles when deployment depends on committed
  prebuilt assets

Broad rules such as `public/*`, `assets/*`, `uploads/*`, `storage/*`, or
`storage/app/public/*` are prohibited unless the recovery manifest classifies
the data and names the tested source of truth.

If a required path declared in `.github/synergie-recovery.yml` is excluded by
`.gitignore`, `.git/info/exclude`, `.dockerignore`, `.npmignore`, deployment
packaging rules, or artifact ignore rules, the gate fails with:

```text
RECOVERY-CRITICAL FILE EXCLUDED FROM SOURCE OF TRUTH
```

## Deployment Traceability

Every production deployment must answer:

```text
WHAT EXACT GIT COMMIT IS RUNNING?
```

The preferred marker is `.deployed_commit` or an external equivalent that does
not interfere with the application. Production releases must be created from a
clean reviewed commit:

```text
Git commit -> clean checkout -> dependency restore -> build -> recovery/assets
verification -> release artifact -> SHA-256 -> manifest -> deployment
```

Production release artifacts, checksums, manifests, commit SHA, and deployment
metadata must be retained in company-controlled storage for rollback and
recovery.

## Branch Integration

Feature to development:

- no new company-wide blocking recoverability gate

Development to staging:

- Recovery Readiness Check is part of the staging quality gate
- required source paths present
- required assets present or externally referenced
- LFS paths mapped and available where applicable
- lockfiles present
- environment template present
- recovery manifest valid
- no recovery-critical ignored files
- secret scan clean
- build reproducible

Staging to main / production:

- all staging checks pass
- deployment artifact is reproducible
- artifact manifest and SHA-256 are generated
- commit SHA is recorded
- database backup policy exists
- persistent upload backup exists
- secret references are resolvable by the approved release role
- rollback artifact exists
- health checks are defined
- recovery-critical server-only file count is zero

No production release may pass with:

```text
RECOVERY-CRITICAL SERVER-ONLY FILES > 0
```

## Restore Testing

A backup is not reliable merely because a backup job says successful. Each
application class must have a controlled restore-test cadence. Initial
certification must prove restoration from company-controlled systems only:

- clean infrastructure/environment
- source, assets, dependencies, and configuration restored
- secrets resolved by reference
- database restored from backup or test-safe copy
- persistent assets restored
- application started
- health checks passed
- no developer laptop or individual developer required

Certification statuses:

- `RECOVERY CERTIFIED`
- `RECOVERY CERTIFIED WITH CONDITIONS`
- `NOT RECOVERABLE`
- `UNKNOWN`

Any recovery dependency on a named person, employee laptop, local folder, private
note, Slack/email message, or manual ZIP fails with:

```text
PERSON-DEPENDENT RECOVERY ASSET
```

## AWS Backup Baseline

Use a cost-conscious baseline by criticality:

- EC2/EBS, RDS, and supported persistent resources should use encrypted backups
  with retention aligned to RTO/RPO and business criticality
- critical applications should evaluate cross-account or cross-Region copies
- high-risk systems should evaluate AWS Backup Vault Lock or S3 Object
  Lock/versioning
- do not enable irreversible compliance-mode locks without explicit approval

Start with additive controls and recovery documentation. Do not mass-delete
server files, rotate all secrets, rewrite all infrastructure, or run destructive
restore tests against production.
