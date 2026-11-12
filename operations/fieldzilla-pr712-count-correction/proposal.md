# FieldZilla #712 exact count correction

Status: proposed, not active. Fresh [PR-QA run 43196813516](https://github.com/Synergie-ITCI/programme-management-platform/actions/runs/43196813516) used rc256 on application head `07c42b603d9f994895872e7ca92d8600d4674fbb` and base `28cb6e7c8941e4c93365270b0dc1821ed8978b4f`. Phase 1 failed closed because it measured **844 changed files**, below the authorized minimum **846**.

The prior candidate's merge-base diff contained 846 nondeleted paths. The new linear candidate has 844 because `.github/workflows/fieldzilla-production-hosting.yml` and `deploy/production/hosting/rehearsal/bootstrap/README.md` are now byte-identical to protected main. The new candidate tree changes from the former reviewed tree only in the approved rc255 image caller references.

Change only #712's minimum and maximum changed-file bounds to **844**. The maximum narrows by two; the effective-addition cap, exact head/base, authorization ID and marker, source overlay, SQL review and five DELETE fingerprints, reviewer, expiry, scanner guards and all other repositories stay unchanged. This does not approve images, AWS apply, Gate C/D or production deployment.

The review uses `changed_file_count` plus `diff_size`, which the active immutable rc256 cannot replace with central live-only size decisions. A new immutable release and FieldZilla-only selector are required after this central correction merges.
