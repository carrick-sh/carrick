# Validation follow-up

No product behavior changed after the measured candidate. Two additional helper
tests verify propagation of clean/indeterminate interior failures without edge
work, and rejection of malformed/overflowing ranges before backend access.
Five helper tests pass. Ten existing production foreign-COW tests pass, including
reversible-boundary rollback, invalidation failure, exact parent-owner isolation,
and single-commit contention. These exercise production carrier components but
NOT the composed discard path; that failure-injection obligation remains open.

The first public conformance-probes attempt failed before probe execution:
accessx, abortdeath, and acceptsock were missing. Both complete ARM64 libc probe
sets were then built locally from current source and hashed. The strict closure
inventory reports no missing required binaries but flags28 performance binaries
per lane as extra; no exact closure-inventory claim. The public semantic gate
uses its declared probe population and is being rerun separately. The setup
failure is preserved and is not a runtime-regression diagnosis.

The after-build run completed756 unique rows but stopped shard2 on the stale
writeseek oracle. Native ARM64 Docker re-blessed only writeseek in both libc
variants. Output bodies did not change; only source hashes changed.

The subsequent public gate exited0: 910 unique generic probe rows across
three signed shards, dedicated signed cases, CLI process-boundary checks, and
66 retained arm64 PASS rows. Known-gap policy remains unchanged.
The final legacy harness reports46 passed,1 ignored; x86 lanes absent. This is
a public baseline-gate pass, not100% Linux conformance or complete promotion.
Frozen measured CLI SHA remained 3e2521515cc0af0324dbd2f7639bd43ea27fc324dd84e1dbd69a4e508e780972. Signed embed identities and cleanup
receipts are preserved separately; CLI and embed artifacts are not conflated.

Still open: composed production discard failure injection, registered structural
scale binding, backend matrix, smoke/full ecosystem promotion and concurrent
scaling. No new workload performance measurement in this validation follow-up.
