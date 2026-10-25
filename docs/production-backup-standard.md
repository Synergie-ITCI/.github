# Synergie Production Backup Standard

This standard extends the Synergie Application Recoverability Standard. It does
not replace the full recovery certification gate.

Backup certification answers one question:

```text
Can Synergie independently back up and restore the production database and
persistent application files from company-controlled systems?
```

An application is not fully `RECOVERY CERTIFIED` until source, secrets,
deployment traceability, runtime, health checks, rollback, and clean-room web
restore requirements also pass.

## Framework

The standard implementation is the Synergie Production Application Backup
Framework:

- `tools/backup/backup-application.sh`
- `tools/backup/verify-backup.sh`
- `tools/backup/restore-application.sh`
- `tools/backup/synergie_backup.py`
- `config/backup-applications.json`
- `config/backup-applications.yml`

Production installs the framework under:

```text
/opt/synergie-backup-framework
/usr/local/sbin/synergie-backup-application.sh
/usr/local/sbin/synergie-verify-backup.sh
/usr/local/sbin/synergie-restore-application.sh
/etc/synergie/backup-applications.json
```

## Storage

Backups are stored in the private company-controlled bucket:

```text
s3://synergie-production-app-backups-918870682888-ap-south-1
```

Required bucket controls:

- Block Public Access: enabled
- Object Ownership: bucket-owner enforced
- Default encryption: SSE-S3 / AES256
- Versioning: enabled
- TLS-only bucket policy: enabled
- Lifecycle: current objects expire after 45 days; noncurrent versions expire
  after 35 days; incomplete multipart uploads abort after 7 days

Do not mix these backups with public asset buckets or application media buckets.

## Backup Layout

Each run writes timestamped metadata:

```text
applications/<app>/production/<UTC timestamp>/database/
applications/<app>/production/<UTC timestamp>/persistent/
applications/<app>/production/<UTC timestamp>/manifest.json
applications/<app>/production/<UTC timestamp>/manifest.json.sha256
applications/<app>/production/status/latest.json
applications/<app>/production/status/<UTC timestamp>.json
```

Persistent files are synchronized to:

```text
applications/<app>/production/persistent/current/<path-id>/
```

S3 versioning and the timestamped persistent manifest provide restore evidence
without uploading a full duplicate of every unchanged file on every run.

## Database Backups

MariaDB/MySQL backups use logical dumps. The framework never copies live
database data directories.

The production rollout uses the local MariaDB root socket through the EC2/SSM
managed instance context, so application DB passwords are not printed, uploaded,
or embedded in scripts. Application runtime secret references remain documented
in `config/backup-applications.yml`.

The dump mode is engine-aware:

- transactional tables use `--single-transaction`
- nontransactional engines trigger a table-locking dump mode for consistency

Backup artifacts include compressed dump, SHA-256 checksum, S3 encryption
metadata, dump duration, table count, and storage-engine summary.

The timestamped application manifest is uploaded with a sidecar SHA-256 file.
The status objects record the manifest S3 key, S3 VersionId, and checksum
metadata so future verification does not depend on SSM command output.

## Persistent Files

Only configured persistent data paths are backed up. Do not back up full app
roots as persistent data.

Excluded by default:

- Git metadata
- dependency directories
- cache, logs, sessions, temp files
- generated local backups and SQL dumps
- known WordPress cache/staging/security-plugin export directories

Each run produces a private JSONL persistent-file manifest with SHA-256 hashes.
Do not paste file names from persistent manifests into public tickets or chat;
file names may contain user or business data.

## Restore Tests

Backup upload is not certification. A passing backup run must verify:

- DB dump checksum
- gzip integrity
- DB restore into isolated temporary MariaDB under the backup work directory
- restored table count matches source table count
- persistent manifest checksum
- representative persistent-file downloads from private S3 match SHA-256

Restore testing must not write into production DBs or production application
paths. Temporary restore datadirs and sample file destinations are removed after
validation.

## Restore Tool Safety

`restore-application.sh` refuses to restore into:

- the production application root
- configured production persistent paths
- production-looking database names
- paths that do not clearly identify restore, recovery, test, tmp, or temp

There is no casual force flag. Production-target restore requires a separate
approved incident procedure.

## Scheduling

The production schedule is:

```text
10 21 * * * root /usr/local/sbin/synergie-backup-application.sh --config /etc/synergie/backup-applications.json --all --restore-test >> /var/log/synergie-production-app-backup.log 2>&1
```

This is 21:10 UTC daily. The schedule is intentionally simple and auditable.
Do not create duplicate cron or systemd schedules.

## Monitoring

Each application writes `status/latest.json` and a timestamped status object to
S3. Failures publish to the configured SNS topic where the EC2 role has
permission. The default route is:

```text
arn:aws:sns:ap-south-1:918870682888:synergie-monitor-platform-alerts
```

Owner-specific routing can be added per application after ownership is verified.

## Statuses

Use these statuses for the backup rollout:

- `BACKUP RECOVERY CERTIFIED`
- `BACKUP IMPLEMENTED - RESTORE TEST PENDING`
- `BLOCKED - DB ACCESS`
- `BLOCKED - PERSISTENT PATH UNKNOWN`
- `BLOCKED - SECRET SOURCE`
- `NOT APPLICABLE`

Do not mark an application fully `RECOVERY CERTIFIED` solely because this backup
standard passes.
