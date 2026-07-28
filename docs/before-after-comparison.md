# Before vs After Comparison

| Area | Before | After |
| --- | --- | --- |
| Policy | Repository config could disable any gate | Central immutable policy defines mandatory gates |
| Config source | PR-head `.github/pr-qa.yml` was trusted | Base-branch config only; PR config changes fail |
| Execution order | Format/lint/build/test ran before secrets | Static preflight runs first; failures stop dynamic execution |
| Checkout credentials | PR checkout used default credentials | `persist-credentials: false` on every checkout |
| Framework ref | Caller could pass framework ref | Caller uses immutable `@pr-qa-v1.1`; no `framework-ref` input |
| Secret scanning | Gitleaks optional; fallback weak | Gitleaks mandatory; fallback scans encoded and alternate text encodings |
| Command artifacts | Raw stdout/stderr serialized | Redacted excerpts only |
| Protected resources | CODEOWNERS read from PR head | CODEOWNERS read from base branch; CODEOWNERS edits fail |
| Generated artifacts | Root-only glob matching | Path-component matching catches nested generated artifacts |
| Unknown code | No technology marker meant gates passed | Unknown executable extensions fail in Phase 1 |
| Migrations | Simple regex | Normalized destructive-token detection and framework method patterns |
| Dependency audits | Missing tools were warnings | Missing mandatory audit tooling fails dependency gate |
| Evidence | `#123` could be treated as missing | Issue references like `#123` are accepted |
| Binary files | All binary files failed | Common screenshot/document evidence extensions are allowed within size limits |
