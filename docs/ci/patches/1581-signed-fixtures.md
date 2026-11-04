# Signed gate fixture publication

Apply `1581-signed-fixtures.patch` from the repository root after the xtask
change lands. It makes the authorized request's SHA the Linux ARM64 fixture
publisher checkout and build input. The dependent Mac job downloads that
same run's SHA-and-attempt artifact and selects exactly one content-addressed
archive. The archive's manifest binds its input identity and executable hashes.
No per-Mac fixture store configuration is required.

The existing publisher recipe and setup steps come from `kernel-runtime.yml`;
the workflow binding checks they stay equal. The signed gate additionally
checks the manifest's source SHA against the authorized request before restore.
General fixture commands retain their input-identity reuse policy.

Validate publication with one owner-requested signed gate on a fixture-changing
PR. Confirm `fixture-restore.log` succeeds and the receipt's
`fixture_validation.bundle_source_head` equals the request SHA. This live Mac
acceptance remains a director action; the worker's Linux tests cannot prove it.

Independent review by a fresh Sol agent found no P0, P1 or P2 findings in the
workflow wiring or archive admission. It independently checked patch application;
it did not claim runtime acceptance.
