# Integrated EL1 gate: memory performance remains red

Source: `3667731b2d65347a3f8a5bf4166f397e18098ff7`.
The signed release CLI was built once and frozen before
`just --no-deps el1-gate`. The command exits 1 at its signed embed step.
Forty-one EL1 tests pass, including the new fault-entry witness; the sole
failure is `el1_memory_first_touch_stays_in_guest`. The unentitled negative
control also passes. Both scoped cleanup counts are zero.

Both processes preserve zero-fill and private contents at all three scales.
Total pages 512/2048/8192 incurred 614/2148/8293 host exits. The first
incremental slope is 0.9987 exits/page, above the unchanged <0.125 ceiling.
This is the expected missing in-guest service, not first-touch acceptance.
Printed CPU/wall diagnostics are not workload timing acceptance.

All eight executed signed test binaries were copied and hash-verified before
further signing; receipt.json records their frozen paths, SHA-256, CDHash,
UUID, entitlement and DOF. The CLI hash remains unchanged. The runner does
not emit its normal success receipt for a failed run, so this independent
failure receipt is retained with the complete log.

The recipe stopped before public probes, selected LTP and inotify timings.
Those steps did not run, and no smoke/full promotion is claimed. Probe
freshness was independently checked: 516 musl and 516 GNU executable hashes
match the previous inventory and their source tree is unchanged.
