#!/usr/bin/env bash
# Executed only by the governed central Gate D workflow through the exact SSM node.
set -euo pipefail
umask 077

bucket='synergie-production-app-backups-918870682888-ap-south-1'
network='scholarship-uat_default'
service='roadsense-next'
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
[[ "$policy_version" == '2026-10-16-release-candidate-hold-v1' ]]
[[ "$database_sha" == 'aaac711b0df078d12714bbd03cff72df7ae49418b8434be1a2864f1536575fa1' ]]
[[ "$database_version" == 'fa2rByaK4AljcFIOosf0ftI5602evy7c' ]]

test "$(docker inspect "$service" --format '{{.State.Status}}')" = 'running'
test "$(docker inspect "$service" --format '{{.Image}}')" = "$rollback_image"
test "$(docker exec "$service" sha256sum /data/road_safety_pilot.sqlite | awk '{print $1}')" = "$rollback_database"
test "$(docker inspect "$service" --format '{{.HostConfig.NetworkMode}}')" = "$network"
! docker inspect "${service}-rollback-${release_id}" >/dev/null 2>&1
candidate="${service}-candidate-${release_id}"
! docker inspect "$candidate" >/dev/null 2>&1

key="applications/roadsense/images/${archive_sha}/roadsense-image.tar"
aws s3api get-object --bucket "$bucket" --key "$key" --version-id "$image_version" \
  "$tmp_dir/roadsense-image.tar" >/dev/null
printf '%s  %s\n' "$archive_sha" "$tmp_dir/roadsense-image.tar" | sha256sum -c - >/dev/null
docker load -i "$tmp_dir/roadsense-image.tar" >/dev/null
test "$(docker image inspect "$image_digest" --format '{{.Id}}')" = "$image_digest"
test "$(docker image inspect "$image_digest" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')" = "$source_sha"
test "$(docker image inspect "$image_digest" --format '{{index .Config.Labels "org.synergie.roadsense.database.sha256"}}')" = "$database_sha"

docker run -d --name "$candidate" --network "$network" --restart no "$image_digest" >/dev/null
for _ in $(seq 1 40); do
  if [[ "$(docker inspect "$candidate" --format '{{.State.Health.Status}}')" == 'healthy' ]]; then
    break
  fi
  sleep 2
done
test "$(docker inspect "$candidate" --format '{{.State.Health.Status}}')" = 'healthy'

docker exec -i "$candidate" python3 - "$database_sha" "$policy_version" <<'PY'
import json, sqlite3, sys, urllib.request
from pathlib import Path
from api import RoadSafetyRepository
expected_db, expected_policy = sys.argv[1:]
with urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=8) as response:
    health = json.load(response)
assert health['status'] == 'ok'
assert health['read_only'] is True
assert health['database_sha256'] == expected_db
assert health['publication_policy_version'] == expected_policy
assert health['publication_review_status'] == 'awaiting_per_scope_publication_approval'
repo = RoadSafetyRepository(Path('/data/road_safety_pilot.sqlite'))
with repo.connect() as conn:
    corrected = conn.execute("SELECT COUNT(*) FROM current_authoritative_observation WHERE revision_status='source_correction'").fetchone()[0]
    published = conn.execute("SELECT COUNT(*) FROM publication_observation WHERE revision_status='source_correction'").fetchone()[0]
assert corrected == 3163
assert published == 0
PY

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
# Caddy must keep challenging unauthenticated public requests; no credential is logged here.
status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time 15 https://roadsense.synergieinsights.in/next/)"
test "$status" = '401'
echo "ROAD_SENSE_RELEASE_ACTIVE=$release_id"
echo "ROAD_SENSE_IMAGE_DIGEST=$image_digest"
echo "ROAD_SENSE_DATABASE_SHA256=$database_sha"
echo "ROAD_SENSE_POLICY_VERSION=$policy_version"
