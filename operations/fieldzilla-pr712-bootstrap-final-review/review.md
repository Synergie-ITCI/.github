# FieldZilla #712 final production-bootstrap review

- Application PR: https://github.com/Synergie-ITCI/programme-management-platform/pull/712
- Exact linear head: `38faf43fcac0e8f9e9dedd2cfe2b33900e870efd`; final application main base: `3b119debc7daf28da3249abb025dbabaf6745f9c` (merged #730).
- The branch has 17 nonmerge commits and 844 nondeleted changed paths. It preserves the production hosting caller and bootstrap source byte-for-byte from main. The 148858 effective-addition cap, 45-path source overlay, SQL SHA-256, five audited DELETE fingerprints, reviewer and `2026-11-13T05:05:32Z` expiry remain unchanged.
- The only candidate overlay hash changed is `.gitleaksignore` to owner-approved SHA-256 `41686f777309b582eac62a73b97d681424ce9e40bc4e5893769a22ce1e1d347e`. The byte-identical Podfile.lock remains SHA-256 `363c313d49dfcb2c8b344d022b368fddc9da3c1fad2a3606fc00d449929dd73e`. The redacted candidate scan found zero leaks; the allowlist regression caught altered content, a real secret in the same file and the same checksum in another file.
- This proposal changes only FieldZilla #712's two exact head/base authorization records and their IDs/marker. It does not select a release, publish images, grant AWS apply, approve Gate C/D or change Scholarships.
