# Synergie Production Application Backup Rollout - 2026-08-09

- Overall backup status: `COMPANY BACKUP RECOVERY CERTIFIED`.
- Full application recovery status: `NOT FULLY RECOVERABLE AS A COMPANY`.
- Scope: 20 non-Sankalp P0 production applications.
- Core control: `Ignored from Git must never mean not backed up anywhere.`

## Framework

- Branch: `feature/company-recovery-scorecard-20260809`
- PR: `https://github.com/Synergie-ITCI/.github/pull/26`
- Artifact: `s3://synergie-production-app-backups-918870682888-ap-south-1/framework/releases/20260809/synergie-backup-framework-20260809.tar.gz`
- Artifact VersionId: `4Fmolm.bm8Vn64YfsSof_O7Ke.OiozK5`
- Artifact SHA-256: `086c1f77faecfbcc211ee5461404070e6e21e3c55422b9f41885af48f672de84`
- Production release: `/opt/synergie-backup-framework/releases/20260809`
- Installed config: `/etc/synergie/backup-applications.json`
- Schedule: `10 21 * * * root /usr/local/sbin/synergie-backup-application.sh --config /etc/synergie/backup-applications.json --all --restore-test >> /var/log/synergie-production-app-backup.log 2>&1`

## Bucket Controls

- Bucket: `s3://synergie-production-app-backups-918870682888-ap-south-1` in `ap-south-1`
- Block Public Access: enabled for ACLs and policies.
- Object Ownership: bucket-owner enforced.
- Encryption: SSE-S3 / AES256 by default; uploaded artifacts verified AES256.
- Versioning: enabled.
- Lifecycle: current daily objects expire after 45 days; noncurrent daily versions after 35 days; weekly prefix after 90 days; incomplete multipart uploads after 7 days.
- Bucket policy: production EC2 role access only for required bucket/object actions plus explicit TLS-only deny.

## Totals

| Metric | Value |
| --- | ---: |
| Apps in scope | 20 |
| Backup recovery certified | 20 |
| Failed | 0 |
| DB restore tests passed | 20 |
| Persistent restore tests passed | 18 |
| Persistent not applicable | 2 |
| Compressed DB dump bytes | 163.23 MiB |
| Persistent bytes backed up | 25.20 GiB |
| Persistent files backed up | 15694 |

## Applications

| App | Status | DB Restore | Persistent Restore | DB Dump | Persistent | Manifest |
| --- | --- | --- | --- | ---: | ---: | --- |
| `bayer` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 48.77 MiB | 636333 B | `applications/bayer/production/20260809T120444Z/manifest.json` |
| `bridgestone` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 820112 B | 15.47 GiB | `applications/bridgestone/production/20260809T115852Z/manifest.json` |
| `datamatics-lms` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 3.70 MiB | 47497 B | `applications/datamatics-lms/production/20260809T120632Z/manifest.json` |
| `dhansamvaad` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 15.17 MiB | 5.48 MiB | `applications/dhansamvaad/production/20260809T120654Z/manifest.json` |
| `fis-lms` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 7.71 MiB | 45.75 MiB | `applications/fis-lms/production/20260809T120733Z/manifest.json` |
| `icicir2s` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 15442 B | 14 B | `applications/icicir2s/production/20260809T120803Z/manifest.json` |
| `jiobp-lms` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `NOT_APPLICABLE` | 7.08 MiB | 0 B | `applications/jiobp-lms/production/20260809T120819Z/manifest.json` |
| `jiobpcares` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 436248 B | 8.15 GiB | `applications/jiobpcares/production/20260809T120843Z/manifest.json` |
| `jiobptransporter` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 281853 B | 14 B | `applications/jiobptransporter/production/20260809T121144Z/manifest.json` |
| `mobilekids` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 7.30 MiB | 34413 B | `applications/mobilekids/production/20260809T121201Z/manifest.json` |
| `projectdemo-lms` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 149049 B | 69.33 MiB | `applications/projectdemo-lms/production/20260809T121237Z/manifest.json` |
| `sankalptraining-lms` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 537650 B | 14 B | `applications/sankalptraining-lms/production/20260809T121259Z/manifest.json` |
| `shareasmile` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 13946 B | 8.11 MiB | `applications/shareasmile/production/20260809T121315Z/manifest.json` |
| `syncsr` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 2.55 MiB | 14 B | `applications/syncsr/production/20260809T121333Z/manifest.json` |
| `synergie-hub` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `NOT_APPLICABLE` | 5664 B | 0 B | `applications/synergie-hub/production/20260809T121351Z/manifest.json` |
| `synergielms-root` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 56.62 MiB | 47497 B | `applications/synergielms-root/production/20260809T121403Z/manifest.json` |
| `telemedicine` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 2.84 MiB | 1.17 GiB | `applications/telemedicine/production/20260809T121607Z/manifest.json` |
| `timesheet-lms` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 242162 B | 14 B | `applications/timesheet-lms/production/20260809T121657Z/manifest.json` |
| `wearesynergie` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 3.85 MiB | 110.12 MiB | `applications/wearesynergie/production/20260809T121713Z/manifest.json` |
| `wearesynergie-insights` | `BACKUP_RECOVERY_CERTIFIED` | `PASS` | `PASS` | 5.26 MiB | 183.44 MiB | `applications/wearesynergie-insights/production/20260809T121744Z/manifest.json` |

## Bridgestone Evidence

- SSM command: `fc2e443a-150f-45b7-a8b1-e576d09c4ca5`
- Status: `BACKUP_RECOVERY_CERTIFIED`
- DB: `bridgestone_db`; dump `820112 B`; restore tables `21`; restore status `PASS`
- Persistent: `15.47 GiB` across `7444` files; sample restore `PASS` with `5` samples
- Manifest: `applications/bridgestone/production/20260809T115852Z/manifest.json`

## Monitoring

- Latest status objects: `applications/<app>/production/status/latest.json and timestamped status JSON`
- Failure alerts: `arn:aws:sns:ap-south-1:918870682888:synergie-monitor-platform-alerts`
- SNS policy statement verified: `AllowSynergieProductionBackupRolePublish`

## Cost

- Measured versioned bucket footprint: `25.370 GiB`.
- AWS Pricing API S3 Standard Mumbai first-50-TB rate: `$0.025/GB-month`.
- Storage-only run-rate for current footprint: about `$0.63/month`, about `0.213%` of August MTD unblended spend.
- Request, lifecycle, and future changed-file/version growth are billed separately and should be reviewed in Cost Explorer after metering settles.

## Production Safety

- No application code was deployed.
- No application restart was performed.
- No production schema or application data write was performed.
- No production restore target was used.
- Restore tests used isolated temporary MariaDB datadirs and temporary persistent sample directories, then cleaned them up.

## Remaining Full-Recovery Gaps

- canonical recovery manifests for every app
- approved secret source mapping outside server-local env/wp-config files
- deployable source traceability and release markers
- clean-room web restore proof
- documented rollback/runbook evidence

## Next Action

Add canonical recovery manifests and clean-room restore proof for the 20 backup-certified non-Sankalp P0 apps, starting with Bridgestone.
