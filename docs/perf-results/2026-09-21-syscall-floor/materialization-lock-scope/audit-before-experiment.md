# Materialization lock-scope audit

Status: source-backed experiment selection, not an implemented optimization or
proven speedup. The current Node concurrency timings remain authoritative.

## Findings that constrain the intervention

Local materialize_sparse_mmap_extent_inner acquires FrameRegistryGuard before
publish_replacing. That call includes authority reservation, host backing
allocation/zeroing or file mapping, global IPA reservation, stage-2 map and owner
registration, inventory staging, stage-1 edit/sync, flush_stage1, authority apply,
old-owner retirement and new alias registration. Thus the measured operation
hold is not one homogeneous publication cost.

prepare is NOT a pure allocation function: it creates stage-2 and custody state.
GlobalFrameOwnerRollback holds custody and retires recorded IPA/length keys on
drop. Moving it requires preserving exact owner lifetime and avoiding reuse
between preparation and publication; an Arc to custody alone is not proof that
VM destruction cannot run. Idle retirement only retries queued generations;
carrier drain separately enumerates owners. Review the call-site lifecycle
exclusion before moving this across any such boundary.

Foreign ordinary COW already prepares an owner before acquiring its publication
FrameRegistryGuard. Foreign pristine/private-file materialization calls publish
without this local guard, under exact-MM exclusion. These provide useful
precedents but do not prove the local path's different lifetime context safe.

frame_inventory::stage_mapping_in explains the shared-frame invariant: staging
makes a shared frame reusable by another installer, so publication must finish
before releasing the registry guard. No experiment may separate those steps.
The current guard also spans flush_stage1. Its contribution has not been
isolated, and moving only prepare might have no measurable effect.

## Bounded next intervention and acceptance

Split preparation from publish_replacing, preserving the existing foreign
wrapper behavior. Move only local preparation before FrameRegistryGuard while
retaining exact-MM exclusion and old-owner retirement ordering. The prepared
value must bind its semantic range/custody and unwind safely on every error.
Do not remove the publication guard or move shared inventory staging outside it.

Before implementation, bind a red-first production-path test showing backing
preparation occurs while another independent frame publication can progress.
The test must exercise real preparation under the existing test backend, not
merely assert textual call order or run scripted closures. Also test failed
publication returns the original mapping/alias/owner fingerprint, and exact
custody remains valid across the preparation/publication gap. This is a new
materialization cost contract, not coverage supplied by anonymous-discard-edges.

Then compare frozen signed control/candidate artifacts, warmed ABBA, original
Node plus concurrent groups 1 and 8, with all samples retained. Keep only a
repeatable untraced improvement and preserved semantics. A lower lock hold count
or sum alone is insufficient; if workload impact is absent, reject the change.

## Baseline verification

RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf --lib sparse -- --test-threads=1
completed successfully: 17 passed, 0 failed, 491 filtered out, 0.06 seconds test
time. Includes sparse replacement failure preserving preimage, exact MM/ASID
permit checks, owner pinning and rollback-arena retirement tests. This is current
VM-free baseline evidence, not the new red-first contract or signed acceptance.
No runtime behavior changed in this audit. No guest or Docker timings occurred
during compilation. CPU-affinity receipt separately archived and verified.
