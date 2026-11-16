# Synergie Company Recovery Scorecard - 2026-08-09

- Generated from live production metadata at `2026-08-09T11:00:47Z` UTC; backup rollout evidence added on `2026-08-09T12:18:17Z` UTC.
- Core control: `Ignored from Git must never mean not backed up anywhere.`
- Scope: company application recoverability, not a production release.

## Company Status

`NOT FULLY RECOVERABLE AS A COMPANY - COMPANY BACKUP RECOVERY CERTIFIED FOR NON-SANKALP P0`

The 20 non-Sankalp P0 production applications now have independent encrypted logical DB backups, persistent-data backups where applicable, and restore-test evidence in company-controlled S3. This closes the urgent backup-source-of-truth gap. Full recovery certification remains blocked by canonical recovery manifests, secret source governance, deployment traceability, and clean-room web restore proof.

Sankalp remains tracked separately as `RECOVERY CERTIFIED WITH CONDITIONS` because provider access and clean-room web restore conditions are separate from this company backup rollout.

## Evidence

| Evidence | Value |
| --- | --- |
| Scorecard PR | `https://github.com/Synergie-ITCI/.github/pull/26` |
| Scorecard branch | `feature/company-recovery-scorecard-20260809` |
| Original SSM live inventory command | `3ea44e66-feda-43a8-814c-45bc93fd5d2f` |
| Backup rollout report | `docs/company-backup-rollout-2026-08-09.md` / `docs/company-backup-rollout-2026-08-09.json` |
| Bridgestone backup SSM command | `fc2e443a-150f-45b7-a8b1-e576d09c4ca5` |
| Remaining 19-app backup SSM command | `94439e53-5b4c-49cc-bc86-0a6aaa112a43` |
| Framework final deploy SSM command | `288795e7-5b11-4eb7-849f-4aa1dc9fecc4` |
| Bridgestone verify smoke SSM command | `415c77f4-1c7d-49ef-bf58-9ba1002ff8c3` |
| EC2 instance | `i-060e4ec1fd5345c30` / `t3.xlarge` / public IP `13.204.116.185` / private IP `172.31.34.212` |
| Runtime observed | Apache 2.4.52, PHP 8.1.2, MariaDB 10.6.23, Composer 2.10.2 |

## Scorecard

| Metric | Result |
| --- | ---: |
| GitHub repositories inspected | 71 |
| Deployable candidates in GitHub inventory | 59 |
| Host-matched GitHub repositories | 14 |
| Canonical recovery manifests observed in prior main-branch inventory | 0 |
| Active roots on production EC2 | 24 |
| Active production roots | 21 |
| Production-hosted non-production roots | 3 |
| Fully recovery-certified production apps | 0 |
| Recovery certified with conditions | 1 |
| Not fully recoverable production apps | 20 |
| P0 production apps excluding Sankalp | 20 |
| Non-Sankalp P0 backup recovery certified | 20 |
| Non-Sankalp P0 DB restore tests passed | 20 |
| Non-Sankalp P0 persistent restore tests passed | 18 |
| Non-Sankalp P0 persistent backup not applicable | 2 |
| Non-Sankalp parsed DB-backed prod apps missing independent backup proof | 0 |
| Non-Sankalp persistent bytes without backup proof | 0 |
| Production apps with Git checkout | 6 / 21 |
| Production apps with deployed marker | 2 / 21 |
| Production apps with env template | 13 / 21 |
| Production apps with lockfiles | 16 / 21 |
| Production apps with parsed database names | 21 / 21 |
| Production persistent data observed | 32.83 GiB |
| Non-Sankalp backup persistent bytes backed up | 25.20 GiB |

## Backup Framework

- Framework artifact: `s3://synergie-production-app-backups-918870682888-ap-south-1/framework/releases/20260809/synergie-backup-framework-20260809.tar.gz`
- Artifact VersionId: `4Fmolm.bm8Vn64YfsSof_O7Ke.OiozK5`
- Artifact SHA-256: `086c1f77faecfbcc211ee5461404070e6e21e3c55422b9f41885af48f672de84`
- Production install: `/opt/synergie-backup-framework/releases/20260809` with current symlink `/opt/synergie-backup-framework/current`
- Config: `/etc/synergie/backup-applications.json` mode `0640`
- Schedule: `10 21 * * * root /usr/local/sbin/synergie-backup-application.sh --config /etc/synergie/backup-applications.json --all --restore-test >> /var/log/synergie-production-app-backup.log 2>&1`
- Monitoring: S3 latest status objects plus SNS failure topic `arn:aws:sns:ap-south-1:918870682888:synergie-monitor-platform-alerts`

## S3 Backup Controls

- Bucket: `s3://synergie-production-app-backups-918870682888-ap-south-1`
- Private by control: Block Public Access enabled, bucket-owner-enforced object ownership, explicit TLS-only deny.
- Encryption and retention: SSE-S3/AES256, versioning enabled, daily current 45 days, daily noncurrent 35 days, weekly prefix 90 days.
- Access: production EC2 role has required backup/restore object actions; no public policy path exists.

## Backup Rollout Applications

| App | Backup Status | DB | DB Restore | Persistent Restore | Persistent Backed Up |
| --- | --- | --- | --- | --- | ---: |
| `bayer` | `BACKUP_RECOVERY_CERTIFIED` | `bayer_db` | `PASS` | `PASS` | 636333 B |
| `bridgestone` | `BACKUP_RECOVERY_CERTIFIED` | `bridgestone_db` | `PASS` | `PASS` | 15.47 GiB |
| `datamatics-lms` | `BACKUP_RECOVERY_CERTIFIED` | `datamatics_lms` | `PASS` | `PASS` | 47497 B |
| `dhansamvaad` | `BACKUP_RECOVERY_CERTIFIED` | `dhansamvaad_db` | `PASS` | `PASS` | 5.48 MiB |
| `fis-lms` | `BACKUP_RECOVERY_CERTIFIED` | `fis_db` | `PASS` | `PASS` | 45.75 MiB |
| `icicir2s` | `BACKUP_RECOVERY_CERTIFIED` | `icicir2s_db` | `PASS` | `PASS` | 14 B |
| `jiobp-lms` | `BACKUP_RECOVERY_CERTIFIED` | `jiobp_db` | `PASS` | `NOT_APPLICABLE` | 0 B |
| `jiobpcares` | `BACKUP_RECOVERY_CERTIFIED` | `jiobpcares_db` | `PASS` | `PASS` | 8.15 GiB |
| `jiobptransporter` | `BACKUP_RECOVERY_CERTIFIED` | `jiobptransporter_db` | `PASS` | `PASS` | 14 B |
| `mobilekids` | `BACKUP_RECOVERY_CERTIFIED` | `mobilekids_db` | `PASS` | `PASS` | 34413 B |
| `projectdemo-lms` | `BACKUP_RECOVERY_CERTIFIED` | `projectdemo_db` | `PASS` | `PASS` | 69.33 MiB |
| `sankalptraining-lms` | `BACKUP_RECOVERY_CERTIFIED` | `sankalptraining_db` | `PASS` | `PASS` | 14 B |
| `shareasmile` | `BACKUP_RECOVERY_CERTIFIED` | `shareasmile_db` | `PASS` | `PASS` | 8.11 MiB |
| `syncsr` | `BACKUP_RECOVERY_CERTIFIED` | `shorturl_db` | `PASS` | `PASS` | 14 B |
| `synergie-hub` | `BACKUP_RECOVERY_CERTIFIED` | `synergie_hub` | `PASS` | `NOT_APPLICABLE` | 0 B |
| `synergielms-root` | `BACKUP_RECOVERY_CERTIFIED` | `lms_db` | `PASS` | `PASS` | 47497 B |
| `telemedicine` | `BACKUP_RECOVERY_CERTIFIED` | `telemedicine_db` | `PASS` | `PASS` | 1.17 GiB |
| `timesheet-lms` | `BACKUP_RECOVERY_CERTIFIED` | `timesheet_db` | `PASS` | `PASS` | 14 B |
| `wearesynergie` | `BACKUP_RECOVERY_CERTIFIED` | `wearesynergie_website` | `PASS` | `PASS` | 110.12 MiB |
| `wearesynergie-insights` | `BACKUP_RECOVERY_CERTIFIED` | `wearesynergie_db` | `PASS` | `PASS` | 183.44 MiB |

## Sankalp Status

| Field | Status |
| --- | --- |
| Certification | `RECOVERY CERTIFIED WITH CONDITIONS` |
| PR | `https://github.com/Synergie-ITCI/sankalp/pull/19` |
| PR state | draft, open, merge state clean, head `36682a1125bb7a9f3367e32952608a07158c88fd` |
| Logical DB backups | S3 backups for `sankalp_db` and `sankalptraining_db`, restore-tested |
| Persistent backups | S3 backup and representative restore for `assets/SurveyData`, `assets/ASSETS`, `assets/recharge` |
| Remaining restore blocker | Full clean-room web restore is pending |

## AWS Backup And Cost

- Backup plans: 1 (`sankalp-production-ebs-daily-35d`).
- Backup vaults: 1 (`synergie-sankalp-recovery-vault`).
- EBS recovery points: 1 completed point protecting `vol-03d5e3fb77ec77d35` with reported size `320.00 GiB` and 35-day retention.
- Application backup bucket measured versioned footprint: `25.370 GiB`.
- AWS Cost Explorer August month-to-date unblended total: USD 298.37 for 2026-08-01 through 2026-08-09, queried with End=2026-08-10 exclusive.
- Application backup storage-only estimate: about USD 0.63/month at USD 0.025/GB-month for current footprint, before request charges and changed-file version growth.

| Top Cost Service | MTD USD |
| --- | ---: |
| Amazon Lightsail | 122.52 |
| Amazon Elastic Compute Cloud - Compute | 67.46 |
| Tax | 45.53 |
| EC2 - Other | 43.97 |
| Amazon Simple Storage Service | 13.57 |
| Amazon Virtual Private Cloud | 3.76 |
| AWS Secrets Manager | 0.92 |
| AWS Cost Explorer | 0.36 |
| AWS Key Management Service | 0.25 |


## Full Application Recovery Reconciliation

Status after full-recovery pass: `NOT FULLY RECOVERABLE`.

| Metric | Result |
| --- | ---: |
| Applications processed | 20 |
| Full application recovery certified | 0 |
| Recovery certified with conditions | 0 |
| Ready for clean-room restore | 0 |
| Not recoverable | 20 |
| External-provider blocked | 0 |
| Source complete | 4 |
| Assets complete | 1 |
| Runtime reproducible | 5 |
| Canonical deploy trace known | 7 |
| Valid recovery manifests | 0 |
| Clean-room restore attempted | 0 |
| Server-only source/asset gap files | 35900 |
| Persistent-like files requiring classification | 19109 |
| Selected-repo redacted secret-scan findings | 132 |

Detailed report: `docs/company-full-recovery-reconciliation-2026-08-09.md` / `docs/company-full-recovery-reconciliation-2026-08-09.json`.

## Control Gaps

- Backup source-of-truth gap: closed for the 20 non-Sankalp P0 production apps by restore-tested encrypted S3 backups.
- Full recovery remains blocked by canonical recovery manifests, clean-room web restore evidence, deployment traceability, and approved external secret/source mapping.
- Secrets: most apps still rely on server-local env/wp-config style secrets; backups intentionally avoid printing or persisting secret values by using the local MariaDB root socket under SSM/root context.
- Traceability: only Sankalp and Telemedicine have any deployed marker, and neither is certified as canonical production release evidence.
- Ignore policy: every ignored recovery-critical component must now be represented in each app recovery manifest with a tested alternate source of truth.

## Production Changes This Turn

- Ran read-only SSM inventory probes; no secret values intentionally collected into durable artifacts.
- Removed embedded GitHub access-token material from Bayer and FIS production Git remote URLs by setting credential-free origin URLs.
- Created central private encrypted versioned S3 application backup bucket with TLS-only policy, lifecycle retention, and production EC2 role access.
- Deployed Synergie Production Application Backup Framework to /opt/synergie-backup-framework and installed daily cron schedule.
- Executed restore-tested logical DB and persistent backup rollout for all 20 non-Sankalp P0 production apps.
- No application code deploy, restart, schema change, production restore, or application data write was performed.

## Certification Lists

- `COMPANY BACKUP RECOVERY CERTIFIED`: 20 non-Sankalp P0 production apps listed in the backup rollout table.
- `RECOVERY CERTIFIED`: none.
- `RECOVERY CERTIFIED WITH CONDITIONS`: `sankalp.synergieinsights.in`.
- `NOT FULLY RECOVERABLE - BACKUP LAYER CERTIFIED`: all 20 non-Sankalp P0 production apps.
- `NOT CERTIFIED - production-hosted non-production root`: `projectdemo-staging`, `sankalpdev.synergieinsights.in`, `wearesynergie.synergieinsights.in/synergiestaging`.

## Full Application Recovery Remediation

Status after remediation pass: `PARTIALLY RECOVERY CERTIFIED`.

| Metric | Result |
| --- | ---: |
| Full application recovery certified | 1 |
| Recovery-canonical clean-room passed | 1 |
| Ready for clean-room pending | 0 |
| Not recoverable | 19 |
| Manifests created | 1 |
| Manifests valid | 1 |
| Artifacts created | 1 |
| Clean-room attempted | 1 |
| Clean-room passed | 1 |
| Env names resolved this run | 155 |
| Secret names still blocked/unknown | 200 |

Detailed remediation report: `docs/company-full-recovery-remediation-2026-08-09.md` / `docs/company-full-recovery-remediation-2026-08-09.json`.

## Highest Priority Next Action

Approve value-safe, one-application-at-a-time SSM SecureString migration for Bayer so its manifest can be created and clean-room restore can run.
