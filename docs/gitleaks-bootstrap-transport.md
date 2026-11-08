# Mandatory Gitleaks bootstrap transport repair

The official browser-download URL for the unchanged Gitleaks 8.30.1 Linux x64
archive returned HTTP504 in FieldZilla full QA and in required central PR-QA,
blocking even the protected fail-safe disable. No secret finding was produced;
installation failed before scanning. The official asset API returned the same
8,230,402 bytes with published SHA256
`551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`, including
an anonymous no-credential download. Asset ID is 378332058.

Use that official API route first, with the existing official browser route as
an availability fallback. Both use bounded HTTPS requests and must pass the
same pinned size and digest before extraction or installation. Bad content is
fatal and never falls through to another route. Both unavailable is fatal. Tool
version, scanner coverage, exit-code enforcement, framework engine/policy pins,
required checks and QA-reuse opt-ins do not change. No mirror, secret or IAM is
introduced. See https://docs.github.com/en/rest/releases/assets#get-a-release-asset.

Central self-QA uses the candidate reusable workflow through the existing
relative caller. Consumers already call pr-qa.yml@main; a protected central merge
would therefore activate this bootstrap repair for those callers immediately,
while their selected immutable engine remains unchanged. This exact shared
effect requires central governance review before merge. Do not claim that old
immutable tags contain the repair; no tag or consumer-selection change is part
of this proposal. Retain release-drift evidence for governance disposition.

Tests execute the actual shell with simulated HTTP and real size, SHA256, tar
and installation checks in temporary directories: valid content, alternate-route
availability, both unavailable, equal-size tamper, truncation and wrong version.
Full central regression and normal hosted exact-head checks remain mandatory.
