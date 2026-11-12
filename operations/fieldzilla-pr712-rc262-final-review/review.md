# FieldZilla #712 final-base review

Status: proposed; not active until protected central merge, immutable release publication, FieldZilla-only selection, and exact-head governed QA.

- Application PR: #712 (`release/fieldzilla-production-application` into `main`).
- Exact head: `31ceb2e0e320037e2f9dbc89928b17872d7cb609`.
- Exact base: `49cbd740c123d097875b600a7280ecb229b46202` (merged #728).
- The rebased branch is linear; the rc262 production/image/bootstrap caller is byte-identical to base.
- `apps/mobile/ios/Podfile.lock` SHA-256 remains `363c313d49dfcb2c8b344d022b368fddc9da3c1fad2a3606fc00d449929dd73e`. The owner-approved two-entry `.gitleaksignore` SHA-256 is `78dff6b487005772e3054e3c348a4cd7eb4ec653ddc948482d38c888dc673827`. Redacted candidate-range scan and allowlist regression passed.
- Both bounded records receive new exact-head/base IDs and issue time. Their `2026-11-13T05:05:32Z` expiry, 844 non-deleted-file bound, 148858 effective-addition cap, overlay source/scope, SQL SHA-256, five DELETE fingerprints, and approved reviewer remain unchanged.
- Scholarships policy and consumer selection remain unchanged.
- No image publication, AWS apply, Gate C/D, production deployment, or staging change is authorized by these records.
