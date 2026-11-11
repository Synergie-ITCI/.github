# Scholarships first PHP 8.3 transition: separate Gate D contract proposal

This is a review proposal, not authorization or an installed production path.
The normal Scholarships Gate D workflow in PR #15 requires an exact-SHA
rollback release and an already-active PHP 8.3 FPM Apache vhost. The present
production service is an unversioned PHP 7 mod_php tree. It fails that
certifier, as intended.

The existing Runtime Certifier has a one-time `legacy-baseline` mode, but its
only recorded tuple is for another repository and is expired. Custom SSM
document mode rejects `legacy-baseline`, and the existing legacy exception
uses generic `AWS-RunShellScript`. None is a valid Scholarships authorization.

## Smallest bounded extension to review

1. Establish the exact legacy host and application-tree fingerprint, database
   engine/schema and private-document inventory through read-only inspection.
   Create independently verified, access-restricted application and database
   backups, including a disposable restore test, before maintenance. Record
   immutable artifact hashes, host ID and expiry. This requires a separate
   approved backup operation; no hash or baseline is invented in this PR.
2. Prepare one fixed, versioned SSM transition document with typed inputs for
   the approved host, legacy baseline hash, target Apache/PHP 8.3 config hash,
   backup identities and run ID. It must contain no arbitrary shell-command
   parameter. The role must allow only that document on that host. GitHub must
   require an exact run-bound production approval before OIDC credentials.
3. Before changing Apache, verify the approved backups, restoration evidence,
   application/data identity, PHP 8.3 FPM package/socket, vhost candidate,
   syntax, private-file denial and migration compatibility. During maintenance,
   make the PHP switch as one bounded operation. On any failed local PHP
   request, authenticated smoke, or private-file test, restore only the prior
   Apache/PHP service configuration using the captured checksum. A database
   restore remains separately authorized and cannot be automatic.
4. Extend the immutable Runtime Certifier **only for an exact, short-lived
   Scholarships legacy tuple** to support a fixed custom read-only SSM
   document. Require the immutable baseline archive and reference, checksum,
   non-consumption marker, active PHP 8.3 FPM serving path, bounded output and
   post-transition certification. Reject PHP 7, wrong host, wrong artifact,
   missing backup, already-consumed authorization and unapproved document.
5. Run synthetic positive and negative tests for backup corruption, wrong
   host/artifact, omitted approval, legacy PHP still serving, migration failure,
   failed HTTP smoke, private-document exposure and interrupted cutover.
   Independently review the SSM document, IAM role, rollback implementation and
   exact tuple before a new immutable central release. No production dispatch
   follows merely from PR merge or QA PASS.

The first-transition workflow must be separate from recurring application
releases. Once the host serves PHP 8.3 FPM and the first release has a verified
exact SHA, the normal PR #15 Gate D workflow can be used for later releases.
