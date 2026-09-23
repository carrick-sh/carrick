# Partial DONTFORK recovery

Part of the approved ecosystem correctness goal. Image overhead is explicitly deferred by the user. This work proceeds independently from TCP recovery.

## Current evidence

Original node-app-smoke fails with the explicit PartialOmit refusal in crates/carrick-vmm-hvf/src/trap/process_plan.rs:518. Fresh native arm64 Docker passes the full original node workload (target/conformance/sep13-review/fresh-oracle/results.json). No claim yet that a particular commit introduced it.

The existing memflagmatrix lifecycle maps one page and omits that entire mapping (conformance-probes/src/bin/memflagmatrix.rs:479); it does not exercise a hole within one mapping. ThreadMappingDesc carries semantic start/end, stage-1 IPA, physical IPA, host owner generation and backing owner separately (persistent_executor.rs:67). A partial semantic omission must not discard the whole physical owner or inherit the excluded leaves.

## Implementation requirements

- Extend existing embedded generic coverage with a multi-page mapping whose middle 4 KiB page is DONTFORK, plus prefix/suffix omissions and DOFORK restoration. Check child mincore errno numerically for the hole, bytes in retained neighbors, parent bytes, and child COW isolation. Include a hole within a 16 KiB host granule and multiple projection ranges. Bound all waits and use the source-hash-validated native arm64 oracle. Prove red against current signed runtime before fixing.
- Replace the all-or-nothing physical-descriptor refusal with semantic projection partitioning. Preserve backing owner and generation while selecting only inherited stage-1 leaves and exact inventory extents; never treat semantic VA as global IPA. Split semantic descriptors only where required; do not duplicate ownership or manufacture host allocations for omitted leaves.
- Preserve independent kernel state/page tables, shared-mm behavior, WIPEONFORK ranges, shared mapping behavior and rollback across stage-1/stage-2/inventory publication. Validate overlapping and adjacent projection ranges through existing typed projection contracts.
- Tests must distinguish projection metadata correctness from actual child memory behavior. Host projection tests alone cannot close the guest failure.
- Director reviews transaction/owner lifetime, runs signed reducer and original node-app-smoke, then the unchanged full promotion ladder on frozen artifact. Any red blocks promotion.

No blanket omission, fallback errno, inherited excluded memory, timeout increase, new expected gap, or performance claim.

Signed red-first established: target/conformance/sep13-review/partial-dontfork-embed-red.log reports exact PartialOmit fatal at VA0x6000008000..0x600000c000 on unchangedruntime main7a. Both nativearm64 Docker libc oracles pass all4 cases; musl signedfatal stops beforegnu. Negativecontrol passed, cleanup0. Exact post-run artifact provenance is partial-dontfork-red-artifact.json, summary partial-dontfork-red-summary.json. No aggregate signed receipt exists for failed runs (script only publishes onsuccess). Sol now owns projection implementation in .worktrees/sep13-partial-dontfork; no guestacceptance or merge yet.
