#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?}"
: "${IOS_BUNDLE_ID:?}"
: "${APPLE_TEAM_ID:?}"
: "${APP_STORE_CONNECT_KEY_ID:?}"
: "${APP_STORE_CONNECT_ISSUER_ID:?}"
: "${APP_STORE_CONNECT_API_KEY:?}"
: "${IOS_DISTRIBUTION_P12_BASE64:?}"
: "${IOS_DISTRIBUTION_P12_PASSWORD:?}"
: "${IOS_PROVISIONING_PROFILE_BASE64:?}"

mobile_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$mobile_root"
test "$(xcodebuild -version | sed -n 's/^Xcode \([0-9]*\).*/\1/p')" -ge 26

if ! grep -Fq "PRODUCT_BUNDLE_IDENTIFIER = $IOS_BUNDLE_ID;" ios/SurveyMobApp.xcodeproj/project.pbxproj; then
  echo 'The iOS project bundle identifier does not match the release environment.' >&2
  exit 1
fi

umask 077
signing_dir="$RUNNER_TEMP/fieldzilla-signing"
mkdir -p "$signing_dir" "$HOME/private_keys" "$HOME/Library/MobileDevice/Provisioning Profiles"
keychain="$signing_dir/fieldzilla.keychain-db"
api_key_path="$HOME/private_keys/AuthKey_${APP_STORE_CONNECT_KEY_ID}.p8"
cleanup() {
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -f "$api_key_path"
  rm -rf "$signing_dir"
}
trap cleanup EXIT

printf '%s' "$IOS_DISTRIBUTION_P12_BASE64" | base64 -D > "$signing_dir/distribution.p12"
printf '%s' "$IOS_PROVISIONING_PROFILE_BASE64" | base64 -D > "$signing_dir/profile.mobileprovision"
printf '%s' "$APP_STORE_CONNECT_API_KEY" > "$api_key_path"
openssl cms -verify -inform DER -noverify -in "$signing_dir/profile.mobileprovision" \
  -out "$signing_dir/profile.plist" >/dev/null

profile_uuid=$(/usr/libexec/PlistBuddy -c 'Print :UUID' "$signing_dir/profile.plist")
profile_name=$(/usr/libexec/PlistBuddy -c 'Print :Name' "$signing_dir/profile.plist")
profile_app_id=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "$signing_dir/profile.plist")
test "$profile_app_id" = "$APPLE_TEAM_ID.$IOS_BUNDLE_ID"
cp "$signing_dir/profile.mobileprovision" "$HOME/Library/MobileDevice/Provisioning Profiles/$profile_uuid.mobileprovision"

keychain_password=$(openssl rand -hex 24)
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security list-keychains -d user -s "$keychain"
security default-keychain -s "$keychain"
security import "$signing_dir/distribution.p12" -k "$keychain" \
  -P "$IOS_DISTRIBUTION_P12_PASSWORD" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain"

build_number="${GITHUB_RUN_NUMBER}.${GITHUB_RUN_ATTEMPT}"
xcodebuild -workspace ios/SurveyMobApp.xcworkspace -scheme SurveyMobApp \
  -configuration Release -destination 'generic/platform=iOS' \
  -derivedDataPath "$RUNNER_TEMP/FieldZillaDerivedData" \
  -archivePath "$RUNNER_TEMP/FieldZilla.xcarchive" \
  "CURRENT_PROJECT_VERSION=$build_number" \
  'CODE_SIGN_STYLE=Manual' "DEVELOPMENT_TEAM=$APPLE_TEAM_ID" \
  "PROVISIONING_PROFILE_SPECIFIER=$profile_name" \
  'CODE_SIGN_IDENTITY=Apple Distribution' archive

app_path="$RUNNER_TEMP/FieldZilla.xcarchive/Products/Applications/SurveyMobApp.app"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app_path/Info.plist")" = "$IOS_BUNDLE_ID"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app_path/Info.plist")" = "$build_number"
app_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app_path/Info.plist")
[[ "$app_version" =~ ^[0-9]+(\.[0-9]+){1,2}$ ]]
codesign --verify --deep --strict "$app_path"
codesign -d --entitlements "$signing_dir/archive-entitlements.plist" "$app_path" 2>/dev/null
archive_app_id=$(/usr/libexec/PlistBuddy -c 'Print :application-identifier' "$signing_dir/archive-entitlements.plist")
archive_team_id=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.team-identifier' "$signing_dir/archive-entitlements.plist")
test "$archive_app_id" = "$APPLE_TEAM_ID.$IOS_BUNDLE_ID"
test "$archive_team_id" = "$APPLE_TEAM_ID"

export IOS_BUNDLE_ID APPLE_TEAM_ID profile_name signing_dir
python3 - <<'PY'
import os
import plistlib

with open(os.path.join(os.environ['signing_dir'], 'ExportOptions.plist'), 'wb') as output:
    plistlib.dump({
        'method': 'app-store-connect',
        'signingStyle': 'manual',
        'teamID': os.environ['APPLE_TEAM_ID'],
        'provisioningProfiles': {os.environ['IOS_BUNDLE_ID']: os.environ['profile_name']},
        'uploadSymbols': True,
    }, output)
PY
xcodebuild -exportArchive -archivePath "$RUNNER_TEMP/FieldZilla.xcarchive" \
  -exportPath "$signing_dir/export" -exportOptionsPlist "$signing_dir/ExportOptions.plist"
ipa="$signing_dir/export/SurveyMobApp.ipa"
test -f "$ipa"
unzip -q "$ipa" -d "$signing_dir/ipa-contents"
ipa_app="$signing_dir/ipa-contents/Payload/SurveyMobApp.app"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$ipa_app/Info.plist")" = "$IOS_BUNDLE_ID"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$ipa_app/Info.plist")" = "$build_number"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$ipa_app/Info.plist")" = "$app_version"
codesign --verify --deep --strict "$ipa_app"
ipa_sha256=$(shasum -a 256 "$ipa" | awk '{print $1}')
xcrun altool --upload-app --type ios --file "$ipa" \
  --apiKey "$APP_STORE_CONNECT_KEY_ID" --apiIssuer "$APP_STORE_CONNECT_ISSUER_ID"
export app_version build_number ipa_sha256
python3 - <<'PY'
import json
import os
from pathlib import Path

evidence = {
    'source_sha': os.environ['GITHUB_SHA'],
    'github_run_id': os.environ['GITHUB_RUN_ID'],
    'github_run_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
    'bundle_id': os.environ['IOS_BUNDLE_ID'],
    'team_id': os.environ['APPLE_TEAM_ID'],
    'version': os.environ['app_version'],
    'build_number': os.environ['build_number'],
    'ipa_sha256': os.environ['ipa_sha256'],
    'upload_result': 'altool_accepted',
}
Path(os.environ['RUNNER_TEMP'], 'fieldzilla-ios-release-evidence.json').write_text(
    json.dumps(evidence, sort_keys=True, indent=2) + '\n', encoding='utf-8')
PY
echo "FieldZilla TestFlight upload accepted: bundle $IOS_BUNDLE_ID, build $build_number, commit $GITHUB_SHA"
