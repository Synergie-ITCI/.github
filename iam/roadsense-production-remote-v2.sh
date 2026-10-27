#!/usr/bin/env bash
# Executed only by the governed central Gate D workflow through the exact SSM node.
set -euo pipefail
umask 077

bucket='synergie-production-app-backups-918870682888-ap-south-1'
network='scholarship-uat_default'
service='roadsense-next'
quota_dir='/var/lib/roadsense/semantic'
quota_db="$quota_dir/quota.sqlite3"
identity_dir='/var/lib/roadsense/identity'
identity_db="$identity_dir/identity.sqlite3"
ses_credentials="$identity_dir/ses-credentials"
old_name=''
candidate=''
new_named=0
old_stopped=0
tmp_dir="$(mktemp -d /tmp/roadsense-release.XXXXXX)"

on_exit() {
  local rc="$1"
  trap - EXIT
  if (( rc != 0 )); then
    if (( new_named == 1 )); then
      docker stop "$service" >/dev/null 2>&1 || true
      docker rm "$service" >/dev/null 2>&1 || true
    fi
    if [[ -n "$old_name" ]] && docker inspect "$old_name" >/dev/null 2>&1; then
      docker rename "$old_name" "$service" >/dev/null 2>&1 || true
      docker start "$service" >/dev/null 2>&1 || true
    elif (( old_stopped == 1 )) && docker inspect "$service" >/dev/null 2>&1; then
      docker start "$service" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "$candidate" ]] && docker inspect "$candidate" >/dev/null 2>&1; then
    docker stop "$candidate" >/dev/null 2>&1 || true
    docker rm "$candidate" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
  exit "$rc"
}
trap 'on_exit $?' EXIT

[[ -n "${RELEASE_JSON_B64:-}" ]]
printf '%s' "$RELEASE_JSON_B64" | base64 -d > "$tmp_dir/release.json"
release="$tmp_dir/release.json"

jq -e 'keys == ["database_s3_version","database_sha256","environment","image_archive_sha256","image_digest","image_s3_version","policy_version","release_id","rollback_database_sha256","rollback_image_digest","source_sha","ssm_target"]' "$release" >/dev/null
get_value() { jq -er --arg key "$1" '.[$key] | select(type == "string")' "$release"; }
release_id="$(get_value release_id)"
source_sha="$(get_value source_sha)"
image_digest="$(get_value image_digest)"
archive_sha="$(get_value image_archive_sha256)"
image_version="$(get_value image_s3_version)"
database_sha="$(get_value database_sha256)"
database_version="$(get_value database_s3_version)"
policy_version="$(get_value policy_version)"
rollback_image="$(get_value rollback_image_digest)"
rollback_database="$(get_value rollback_database_sha256)"
[[ "$release_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$ ]]
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]]
[[ "$database_sha" =~ ^[0-9a-f]{64}$ ]]
[[ "$rollback_image" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$rollback_database" =~ ^[0-9a-f]{64}$ ]]
[[ "$image_version" =~ ^[A-Za-z0-9+/=._-]{1,128}$ ]]
[[ "$database_version" =~ ^[A-Za-z0-9+/=._-]{1,128}$ ]]
[[ "$(get_value environment)" == 'roadsense-production' ]]
[[ "$(get_value ssm_target)" == 'mi-0dade13fd68d1b435' ]]
[[ "$policy_version" == '2026-10-27-scoped-publication-owner-approved-candidate-v1' ]]
[[ "$database_sha" == '5f26e3081b65b095389eeaeeb1871e27c001928138a71e1363a976a402731512' ]]
[[ "$database_version" == 'llxUjX.WIAcZoPCnuCoBuZ3OsAJnXiwk' ]]

test "$(docker inspect "$service" --format '{{.State.Status}}')" = 'running'
test "$(docker inspect "$service" --format '{{.Image}}')" = "$rollback_image"
test "$(docker exec "$service" sha256sum /data/road_safety_pilot.sqlite | awk '{print $1}')" = "$rollback_database"
test "$(docker inspect "$service" --format '{{.HostConfig.NetworkMode}}')" = "$network"
! docker inspect "${service}-rollback-${release_id}" >/dev/null 2>&1
candidate="${service}-candidate-${release_id}"
! docker inspect "$candidate" >/dev/null 2>&1

# The ledger outlives container replacement. Once initialized, its loss is a
# hard failure: silently creating a fresh ledger would reset paid allowances.
if [[ ! -e /var/lib/roadsense/.semantic-quota-initialized ]]; then
  [[ ! -e "$quota_dir" && ! -e "$quota_db" ]]
  install -d -m 0700 -o 10001 -g 10001 "$quota_dir"
  install -m 0600 -o 10001 -g 10001 /dev/null "$quota_db"
  install -m 0600 /dev/null /var/lib/roadsense/.semantic-quota-initialized
fi
[[ -d "$quota_dir" && ! -L "$quota_dir" && -f "$quota_db" && ! -L "$quota_db" ]]
test "$(stat -c '%u:%g:%a' "$quota_dir")" = '10001:10001:700'
test "$(stat -c '%u:%g:%a' "$quota_db")" = '10001:10001:600'
python3 - "$quota_db" "$quota_dir/backup-${release_id}.sqlite3" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as source, sqlite3.connect(sys.argv[2]) as backup:
    assert source.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    source.backup(backup)
PY
chown 10001:10001 "$quota_dir/backup-${release_id}.sqlite3"
chmod 0600 "$quota_dir/backup-${release_id}.sqlite3"

# Identity state and the SES-only credential file stay on the private host
# mount. Preserve a versioned, restore-checked snapshot before migration.
[[ -d "$identity_dir" && ! -L "$identity_dir" && -f "$identity_db" && ! -L "$identity_db" ]]
[[ -f "$ses_credentials" && ! -L "$ses_credentials" ]]
test "$(stat -c '%u:%g:%a' "$identity_dir")" = '10001:10001:700'
test "$(stat -c '%u:%g:%a' "$identity_db")" = '10001:10001:600'
test "$(stat -c '%u:%g:%a' "$ses_credentials")" = '10001:10001:600'
printf '%s  %s\n' \
  '3a126f34394c6b63562b166d08ce32e86a0ca0665f7449ac25f4017695a49734' \
  /usr/local/sbin/roadsense-identity-backup | sha256sum -c - >/dev/null
printf '%s  %s\n' \
  '47c27c9db3f93fe91551d207fdacdb66e57fb88e74b5ca7bde8abb58b22bbb5d' \
  /usr/local/sbin/roadsense-auth-refresh-ses | sha256sum -c - >/dev/null
python3 /usr/local/sbin/roadsense-identity-backup > "$tmp_dir/identity-backup.json"
test "$(jq -r '.restore_check' "$tmp_dir/identity-backup.json")" = 'PASS'
python3 /usr/local/sbin/roadsense-auth-refresh-ses > "$tmp_dir/ses-refresh.log"

# A short-lived named credential is kept in SSM. Only its digest and expiry
# enter the container; the raw token never enters command arguments or logs.
aws ssm get-parameter --region ap-south-1 --name /synergie/roadsense/pilot/admin-token \
  --with-decryption --output json |
  python3 -c 'import hashlib,json,sys,time
p=json.loads(json.load(sys.stdin)["Parameter"]["Value"])
assert set(p)=={"admin_id","token","expires_at"}
assert p["admin_id"]=="saurabhverma" and isinstance(p["token"],str)
assert 16<=len(p["token"])<=256 and isinstance(p["expires_at"],int)
assert time.time()<p["expires_at"]<=time.time()+86400
print("ROADSENSE_SEMANTIC_ADMIN_ID="+p["admin_id"])
print("ROADSENSE_SEMANTIC_ADMIN_TOKEN_SHA256="+hashlib.sha256(p["token"].encode()).hexdigest())
print("ROADSENSE_SEMANTIC_ADMIN_TOKEN_EXPIRES_AT="+str(p["expires_at"]))' > "$tmp_dir/admin.env"
cat > "$tmp_dir/runtime.env" <<EOF
ROADSENSE_SEMANTIC_ENABLED=0
ROADSENSE_SEMANTIC_QUOTA_DB=$quota_db
ROADSENSE_SEMANTIC_MODEL=gpt-6-luna
ROADSENSE_SEMANTIC_DAILY_USD_BUDGET=0.25
ROADSENSE_SEMANTIC_INPUT_PRICE_PER_MILLION=0.10
ROADSENSE_SEMANTIC_OUTPUT_PRICE_PER_MILLION=0.50
ROADSENSE_SEMANTIC_HOURLY_LIMIT=5
ROADSENSE_SEMANTIC_DAILY_TOKEN_BUDGET=50000
ROADSENSE_SEMANTIC_RETRIES=0
EOF
cat "$tmp_dir/admin.env" >> "$tmp_dir/runtime.env"
cat > "$tmp_dir/auth.env" <<EOF
ROADSENSE_AUTH_ENABLED=1
ROADSENSE_AUTH_DB=$identity_db
ROADSENSE_AUTH_HOSTS=roadsense.synergieinsights.in,127.0.0.1,roadsense-next
AWS_SHARED_CREDENTIALS_FILE=$ses_credentials
AWS_EC2_METADATA_DISABLED=true
EOF
aws ssm get-parameter --region ap-south-1 --name /synergie/roadsense/auth/signing-key \
  --with-decryption --output json |
  python3 -c 'import json,sys
key=json.load(sys.stdin)["Parameter"]["Value"]
assert isinstance(key,str) and len(key)>=32 and "\n" not in key and "\r" not in key
print("ROADSENSE_AUTH_SECRET_KEY="+key)' >> "$tmp_dir/auth.env"
cat "$tmp_dir/auth.env" >> "$tmp_dir/runtime.env"
aws secretsmanager get-secret-value --region ap-south-1 \
  --secret-id 'arn:aws:secretsmanager:ap-south-1:918870682888:secret:/synergie/roadsense/evaluation/openai-api-key-GfBGoT' \
  --output json |
  python3 -c 'import json,sys
secret=json.loads(json.load(sys.stdin)["SecretString"])
assert set(secret)=={"ROADSENSE_OPENAI_API_KEY"}
key=secret["ROADSENSE_OPENAI_API_KEY"]
assert isinstance(key,str) and len(key)>=20 and "\n" not in key and "\r" not in key
print("ROADSENSE_OPENAI_API_KEY="+key)' >> "$tmp_dir/runtime.env"

key="applications/roadsense/images/${archive_sha}/roadsense-image.tar"
aws s3api get-object --bucket "$bucket" --key "$key" --version-id "$image_version" \
  "$tmp_dir/roadsense-image.tar" >/dev/null
printf '%s  %s\n' "$archive_sha" "$tmp_dir/roadsense-image.tar" | sha256sum -c - >/dev/null
docker load -i "$tmp_dir/roadsense-image.tar" >/dev/null
test "$(docker image inspect "$image_digest" --format '{{.Id}}')" = "$image_digest"
test "$(docker image inspect "$image_digest" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')" = "$source_sha"
test "$(docker image inspect "$image_digest" --format '{{index .Config.Labels "org.synergie.roadsense.database.sha256"}}')" = "$database_sha"

# Migration runs against the durable identity mount before the candidate can
# serve traffic. A migration failure leaves the current application untouched.
docker run --rm --network none \
  --mount "type=bind,src=$identity_dir,dst=$identity_dir" \
  --env-file "$tmp_dir/auth.env" --entrypoint python3 "$image_digest" \
  -m identity.manage migrate --noinput > "$tmp_dir/identity-migration.log"
python3 /usr/local/sbin/roadsense-identity-backup > "$tmp_dir/identity-migrated-backup.json"
test "$(jq -r '.restore_check' "$tmp_dir/identity-migrated-backup.json")" = 'PASS'

docker run -d --name "$candidate" --network "$network" --restart no \
  --mount "type=bind,src=$quota_dir,dst=$quota_dir" \
  --mount "type=bind,src=$identity_dir,dst=$identity_dir" \
  --env-file "$tmp_dir/runtime.env" "$image_digest" >/dev/null
for _ in $(seq 1 40); do
  if [[ "$(docker inspect "$candidate" --format '{{.State.Health.Status}}')" == 'healthy' ]]; then
    break
  fi
  sleep 2
done
test "$(docker inspect "$candidate" --format '{{.State.Health.Status}}')" = 'healthy'
test "$(docker exec "$candidate" sha256sum /app/publication_policy.json | awk '{print $1}')" = '003023b6060daeb99534baafc82616867b7dd5df3ba0c91af97034a8a4522e25'

docker exec -i "$candidate" python3 - "$database_sha" "$policy_version" <<'PY'
import json, sqlite3, sys, urllib.request
from urllib.error import HTTPError
from pathlib import Path
from api import RoadSafetyRepository
from identity.ses import ses_client
expected_db, expected_policy = sys.argv[1:]
with urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=8) as response:
    health = json.load(response)
assert health['status'] == 'ok'
assert health['read_only'] is True
assert health['database_sha256'] == expected_db
assert health['publication_policy_version'] == expected_policy
assert health['publication_review_status'] == 'owner_approved_pending_governed_release'
assert not __import__('ask_semantic').SemanticService.api_enabled()
assert __import__('os').environ['ROADSENSE_SEMANTIC_ENABLED'] == '0'
assert len(__import__('os').environ['ROADSENSE_OPENAI_API_KEY']) >= 20
assert __import__('semantic_quota').durable_store_ready('/var/lib/roadsense/semantic/quota.sqlite3')
assert __import__('os').environ['ROADSENSE_AUTH_ENABLED'] == '1'
assert ses_client() is not None
with urllib.request.urlopen('http://127.0.0.1:8765/account/login/', timeout=8) as response:
    assert response.status == 200
try:
    urllib.request.urlopen('http://127.0.0.1:8765/api/meta', timeout=8)
except HTTPError as error:
    assert error.code == 401
else:
    raise AssertionError('Unauthenticated analytics API was accessible')
repo = RoadSafetyRepository(Path('/data/road_safety_pilot.sqlite'))
with repo.connect() as conn:
    corrected = conn.execute("SELECT COUNT(*) FROM current_authoritative_observation WHERE revision_status='source_correction'").fetchone()[0]
    published = conn.execute("SELECT COUNT(*) FROM publication_observation WHERE revision_status='source_correction'").fetchone()[0]
assert corrected == 3394
assert published == 231
assert len(repo.publication_policy.approved_observations) == 231
assert len(repo.publication_policy.rules) == 11
assert repo.publication_policy.quarantines("road_category", "accidents", 2018, "IN-TN", "other_roads")
PY

# Test the actual container verifier with the raw credential on stdin only.
aws ssm get-parameter --region ap-south-1 --name /synergie/roadsense/pilot/admin-token \
  --with-decryption --output json |
  docker exec -i "$candidate" python3 -c 'import json,sys
from semantic_quota import verified_principal
p=json.loads(json.load(sys.stdin)["Parameter"]["Value"])
assert verified_principal({"X-RoadSense-Admin-Token":p["token"]}) is not None
assert verified_principal({"X-RoadSense-Admin-Token":p["token"]+"forged"}) is None'

old_name="${service}-rollback-${release_id}"
docker stop "$service" >/dev/null
old_stopped=1
docker rename "$service" "$old_name"
docker rename "$candidate" "$service"
candidate=''
new_named=1
docker update --restart unless-stopped "$service" >/dev/null
test "$(docker inspect "$service" --format '{{.State.Health.Status}}')" = 'healthy'
test "$(docker inspect "$service" --format '{{.Image}}')" = "$image_digest"
test "$(docker exec "$service" sha256sum /data/road_safety_pilot.sqlite | awk '{print $1}')" = "$database_sha"
test "$(docker exec "$service" sha256sum /app/publication_policy.json | awk '{print $1}')" = '003023b6060daeb99534baafc82616867b7dd5df3ba0c91af97034a8a4522e25'
# Caddy must keep challenging unauthenticated public requests; no credential is logged here.
status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time 15 https://roadsense.synergieinsights.in/next/)"
test "$status" = '401'
echo "ROAD_SENSE_RELEASE_ACTIVE=$release_id"
echo "ROAD_SENSE_IMAGE_DIGEST=$image_digest"
echo "ROAD_SENSE_DATABASE_SHA256=$database_sha"
echo "ROAD_SENSE_POLICY_VERSION=$policy_version"
