# First-touch maintenance census

Retained discard-edge artifact; no product change or performance gain claimed.
One wave of eight Node app-smoke processes on the pinned image in trace8/inputs.json.
All eight success markers, GROUP_DONE, root exit zero and scoped cleanup zero.
No DTrace errors/drops. High-perturbation caller stacks are counts, not timing.

The count() scope aggregation and independent caller aggregation both total
19,378 full-ASID maintenance requests. The old scalar events++ summary reports
19,371 because concurrent updates are not atomic. It is not the authoritative
count. The exact script used is archived; the durable script now uses a presence
flag rather than a scalar counter. No trace is silently replaced.

11,864 requests are sparse materialization during resident-fault handling;
11,835 share the dominant sparse-materialization -> protect_range ->
resolve_mutating_fault stack. See summary.json and all resolved stacks for the
remaining callers. Requests are emitted before vCPU execution; whole workload
completion is confirmed, but individual maintenance completion is not bracketed.

Symbol qualification: live probe PC 0x10532c120 minus exact-artifact USDT nop
0x100d50120 yields slide 0x45dc000, load address 0x1045dc000. nm/otool and
signed identity are archived. Binary SHA256 is recorded in inputs.json.

## Source findings and decision

Aarch64EngineCore::pt_edit_and_flush already skips maintenance when
PageTableApplyOutcome.flush_required is false. Do not assume two flushes per
first-touch. sparse_materialization::publish_replacing unconditionally requests
maintenance after host table sync. The widened pristine window is published in
separate compound-size chunks. Each successful chunk requests maintenance.

map_private_aliased initially builds valid shadow descriptors; local publication
then set_prot_none invalidates them before sync_to_host. write_desc only changes
shadow bytes. sync_to_host rereads the final shadow value for every dirty entry,
so the intermediate valid shadow leaf does not itself prove a live valid leaf
was exposed. However existing valid translations, table splits/reclamation,
replacement owners, rollback and foreign publication still require auditing.
Blindly honoring set_prot_none.flush_required would also see the intermediate
shadow-valid state rather than the live preimage. Do not simply omit the flush.

Next bounded intervention: prove publication-maintenance requirements from live
preimages and structural edits, preserving necessary barriers and rollback.
Start with fresh local holes under exact-MM exclusion; retain foreign and
replacement semantics. A red-first production-path contract must count actual
maintenance requests at scales 1/8/32/128 and prove bytes, protection boundaries,
residency and fork peers. Paired uninstrumented original/concurrent Node timing
decides whether a reduction matters; recurrence does not predict wall-time gain.
The previous rejected private-publication foreign-copyout failure remains open.
