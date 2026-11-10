# PR712 exact-head rebind and initial-import size decision

PROPOSED ONLY. Merging this proposal requires a new exact-head issuance approval;
publication and FieldZilla activation remain separate gates. No runtime action,
application merge, staging action, migration or APK publication is authorized.

Application: PR712, head c92beeb7f493739d9685402925f3104f9716924d,
base c8aee71a61059392f17343eac434d2a73dfb3b4c. Existing owner review5837789245
is carried forward only for the 40 unchanged deployment paths and identical
historical SQL/five spans. It does not approve the new threshold exception or
claim to review a different application commit. New head adds only Vite7.3.8
and three bounded async UI test waits, with all navigation assertions preserved.
Local Admin tests330/330, production build/typecheck, lint0errors and audit0high/
0critical passed. Governed run42795797076 stopped before Dependencies because
its old exact-head binding correctly failed closed. Architecture is independent.

The supported initial-import authorization waives only changed_file_count and
diff_size for this PR/head/base, capped at844 measured files and148759 effective
additions (raw164817 additions,16058 generated-lock additions excluded). No scan,
security, test, build, architecture, deployment or release guard is relaxed.
Ordinary thresholds remain200files/5000additions. Expiry is unchanged:
11 November2026 07:04:04UTC. Stop on expiry or any ref/content/count change.

A size-compliant mechanical split needs at least30 slices by additions alone,
fragmenting the previously reviewed application and changing each subsequent
base. It is not a practical substitution for the coherent initial import.
A useful functional split remains: keep the existing application import in712;
review the new application executor separately after its base is available.
That execution work is not silently included in this authorization.

The old active records are replaced, not duplicated, because the existing
baseline rejects duplicate PR records and the SQL selector uses one PR record.
Prior records remain in immutable rc228/source812084ade2727c5702c9ccf8e3e7c771d956d169,
Git history and proposal.json.previous_* for audit. New UUIDs distinguish the
proposed decision. All other policy values and records are byte-equivalent after
normalizing this one record; tests enforce that.

After separately authorized issuance: publish a new immutable central release
through the approved publisher and its provenance/protection checks, then obtain
separate exact consumer-selection activation and marker-update approval. Do not
edit the application marker early or rerun unchanged QA needlessly. Recheck live
application head/base, hashes, checks and expiry at each gate.

Rollback before activation: reviewed revert of this issuance; rc228 remains the
executing consumer. After activation: separately reviewed selection revert to
rc228 restores the previous fail-closed head binding, not a runtime rollback.
No database or production writes are part of this proposal.
