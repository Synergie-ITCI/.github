# PR712 format-only exact rebind proposal

PROPOSED ONLY. Issuance, immutable publication and FieldZilla activation remain
separate gates. No application merge, AWS operation, staging change, migration,
cutover or APK publication is included.

Application head47782d529195999ab52408c8e3b6de1fbd9c0d38 / basec8aee71a61059392f17343eac434d2a73dfb3b4c changes only formatting of the mobile audit baseline architecture test. Its AST and assertions are unchanged. The exact approved baseline file, lock, advisory, severity, fingerprint and expiry are unchanged. The full API candidate passes Ruff format (544files) and lint; both baseline contract checks pass.

Governed rc230 run42812387687 cleared Phase1 and all dependency audits, including the Linux mobile audit. Its only failures were Ruff format and line length in this test. The new head resolves those failures without changing application behavior, published history or scanner logic. Full exact-head QA remains required after separate activation.

The formatter adds24 lines. The proposed bound is844 files /148823 effective additions, replacing the prior148799 cap only for this exact head/base. Only one existing source-overlay hash changes; no new allowed path is added. Expiry stays2026-11-11T07:04:04Z. Stop on different refs, scope, findings or expiry.

Review5837789245 carries forward only for the unchanged40 deployment paths and identical historical SQL/five spans. It does not authorize this issuance. Prior records remain in immutable rc230, Git history and proposal.previous_*; replace only the single existing record for this PR. Organization defaults and every scanner/test/release guard remain unchanged.

Before each issuance/publication/activation gate, recheck exact refs, required checks, hashes, measured scope and expiry. Before activation, rollback is a reviewed issuance revert; afterward, a separate selection revert to rc230 restores the prior fail-closed binding. Neither is a runtime rollback.
