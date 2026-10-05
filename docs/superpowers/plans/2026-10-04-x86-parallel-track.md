# x86 acceleration on the shared kernel core

Plan of record, owner direction 2026-10-05: start x86 alongside N1 so additional
Linux/KVM capacity finds ownership defects in the **same kernel code** that
AArch64 executes. N1 keeps first priority on the Mac lanes. This document
claims no implementation or runtime acceptance; Carrick remains experimental.

Authorities: [approved core split, PR #19](https://github.com/carrick-sh/carrick/pull/19),
[native ownership](2026-10-02-el1-native-ownership.md),
[KVM carrier details](2026-10-04-kvm-hvpatch-carrier.md),
[PR #7 grant-service handoff](https://github.com/carrick-sh/carrick/pull/7),
[approved capacity plan #4](https://github.com/carrick-sh/carrick/pull/4),
[contracts](../../conformance-contracts.md) and [AGENTS.md](../../../AGENTS.md).
The owner direction supersedes deferred-x86 sequencing and deferred neutral
package naming, preserving those plans' ownership and cost requirements.

## Stack on N1; synchronize ownership changes

Document base is main `80bc107de10f5c71dd57be9fac55a1ce394b46b3`.
The **implementation track starts on work/n1**, using these inspected inputs:

| Ref / inspected SHA | Input |
| --- | --- |
| `github/work/n1`, `299b19ca11756dab8444227970af12b6df9145f4` | N1 owner sources below |
| PR #7, `786f6f4b3cd001e28d89d15b81e0c3cb8c04de34` | `crates/carrick-el1/src/personality/mm_portal/x86_tests.rs`, `crates/carrick-mmu-core/src/owner_mmu.rs`; both exist here, not at the inspected N1 head |
| PR #19, `486394ebf2486e6491459c1540d49bbbf7318318` | `docs/superpowers/specs/2026-10-04-personality-core-split.md` |
| PR #4, `a98b655f528ee8aa61b5033a3036382853d834c9` | `docs/superpowers/plans/2026-10-04-elastic-ci-and-pr-bus.md` |

The owner permits extraction **before N1 lands**, accepting conflicts when the
parallel track learns from them. Consume reviewed #7 transfer/fork seams on
the current N1 stack; do not wholesale replace newer files with #7's snapshot.
One implementation still means moving the owner and switching both ISA callers.

**Sync with N1:** the x86 integrator fetches/rebases at each day's start, before
push/integration, and immediately after an N1 owner fix. Record the exact N1
SHA, selected #7 commits, symbol fence and witness results for each extraction.
The integrator resolves x86-stack conflicts; the N1 driver reviews ownership/
wire changes; the director owns final integration and the signed gate. Preserve
N1 fixes and main's newer hardware witnesses; never resurrect an old owner to
avoid a conflict. Unsettled interfaces stay visible as integration work, not a
reason to build an x86 copy or wait for all of N1.

```sh
git fetch github work/n1:refs/remotes/github/work/n1
git rebase github/work/n1
```

**Learning flows both ways:** every shared-owner defect gets a deterministic
red witness, exact source/operation identity, command and failure log, plus a fix
to the moved shared code. The director routes that packet to the N1 driver;
N1 incorporates the fix with its author preserved. Rebase x86 onto that fix,
remove superseded patches and rerun both ISA VM-free witnesses. No private
x86 correction while ARM keeps the defective owner. Signed acceptance remains
the integration bar; source presence or a KVM pass is not N1 acceptance.

## Shared-core extraction order

Destinations are **planned modules/packages**, not existing file claims.
Sources marked N1 are checked at the ref above; refresh them at every sync.
Move responsibilities once, delete displaced bodies, and keep both images and
VM-free tests calling the same implementation. Linux brk/placement, clone
flags, errno, robust/clear-tid, signal and fd policy stay in one Linux client.

| Order / piece | Source paths → destination | ISA seam retained / unchanged-ARM gate |
| --- | --- | --- |
| **0: consume existing substrate** | Shared identities/journals exported by `crates/carrick-mmu-core/src/aarch64/descriptor_txn.rs` and reused by `crates/carrick-mmu-core/src/x86/descriptor_txn.rs` stay in **mmu-core**. Claims/queues in `crates/carrick-sched-core/src/lib.rs` and `crates/carrick-sched-core/src/object_wait.rs`, admission/drain accounting in `crates/carrick-sched-core/src/occupancy.rs` and `crates/carrick-sched-core/src/spaces.rs` stay in **sched-core**. Consume Phase B claims in `crates/carrick-el1-abi/src/thread_lifecycle.rs` and neutral extent/pin records in `crates/carrick-el1-abi/src/metadata_extent.rs`; split only fields the extraction needs. | Native state, descriptor encoding and invalidation remain behind `crates/carrick-guest-arch/src/lib.rs` and ISA adapters. **A + AM + AW** for shared-source edits. This prerequisite does not defer the N1 owner extractions below. |
| **1: MM owner transaction, first** | N1 `crates/carrick-el1/src/personality/mm_portal/production.rs`, `crates/carrick-el1/src/personality/reservations/storage.rs`, `crates/carrick-el1/src/personality/reservations/prepared.rs`, `crates/carrick-el1-abi/src/mm_portal.rs` → **carrick-core::mm::{transaction,transfer,reservation}**, neutral transport in **carrick-core-abi**. Move admission, range storage, select/revalidate, prepared permits, commit/cancel and prefix custody; Linux reservation interpretation moves to **carrick-personality-linux::mm** with its callers. | Integrate #7's `OwnerMmu` seam against current N1. Translation/COW classification, executable coherence and HVC/native-entry transport remain adapters; no ARM TrapFrame or errno lowering in core. **A + AM**. |
| **2: fork commit/COW** | N1 `crates/carrick-el1/src/personality/mm_portal/fork.rs`, `crates/carrick-el1-abi/src/mm_portal_fork.rs`, `crates/carrick-aarch64/src/fork.rs`, `crates/carrick-el1/src/cow.rs` → **carrick-core::mm::{fork,cow}** and core-abi. Move census, unpublished child, parent undo, commit/abort and retained-custody receipt validation. Linux DONTFORK/WIPEONFORK/task birth remain the Linux client. | `PhysicalForkBuilder` host custody and ARM HVC/control-window/TTBR geometry stay adapters; x86 supplies geometry through the same fork body. **A + AF**. |
| **3a: grant/return receipts** | N1 `crates/carrick-el1-abi/src/mm_portal_grant.rs`, `crates/carrick-el1-abi/src/cow_grants.rs`, `crates/carrick-el1/src/personality/mm_portal/production.rs`, `crates/carrick-el1/src/alloc.rs`, `crates/carrick-el1/src/fault.rs` → **carrick-core::mm::{frames,capacity,fault}**, neutral generation/receipt records in core-abi. Move reservation-window authentication, logical frame references, extent accounting and exact settlement. | #7 leaves `serve_grant`/`PortalGrantSlot` ARM-shaped: split that wire/backend seam once. x86 Map/Publish must be one rollback-capable owner publication. Resolver, mapped-aperture/allocator hardware hooks and stage-2 supply remain adapters; `host-test` cannot enable production. **A + AM + AR**. |
| **3b: retirement custody, paired with grants** | N1 `crates/carrick-aarch64/src/stage1_authority.rs`, `crates/carrick-runtime/src/hvpatch/stage1_mm.rs`, `crates/carrick-vmm-hvf/src/trap/carrier_custody.rs`, `crates/carrick-kernel/src/kernel/frame_inventory.rs` → neutral close/drain/pin/receipt validation and quarantine/reuse in **carrick-core::mm::retirement**, composing sched-core occupancy. Switch N1 `crates/carrick-aarch64/src/engine.rs` protocol callers to it. | Host pointers, physical ledgers/map/unmap/quota remain host-side. ARM boot relocation/ASID/TLBI/HVF and x86 CR3/shootdown/KVM memslots stay adapters. Neither memslot deletion nor one CR3 reload authorizes reuse. **A + AR**. |
| **4: zone/wait records** | Keep sched-core algorithms from order 0. N1 `crates/carrick-el1/src/personality/mm_portal/edit_wait.rs`, `crates/carrick-el1/src/sched/object_wait.rs` and neutral lifecycle fields → **carrick-core::wait/lifecycle** plus core-abi. Compose exact record generations, release-before-enroll, one-winner wake/cancel and owned continuations. | Native context/resume/notify hooks, IRQ masks, GIC/APIC, timers and park/wake instructions remain ISA-specific. Context sidecars hold machine state, never a second wait/runnable ledger. Linux futex/clear-tid policy stays outside core. **A + AW**. |

Existing timer/pipe/fd cores remain shared dependencies. #19 identifies Linux
policy within them: do not classify entire crates as neutral or move fd/exec,
itimer or SIGPIPE policy into core. No broad package rename, empty facade,
x86-only owner, alternative permit/cursor, or copied MM/scheduler graph.

## Gates for every shared extraction

**A:** run moved witnesses with both ISA backends, then:

```sh
cargo test --locked -p carrick-mmu-core -p carrick-sched-core -p carrick-el1-abi --lib
cargo test --locked -p carrick-conformance-contract --lib personality_boundary
```

At the selected N1 snapshot, run `cargo test --locked -p carrick-el1 --lib personality::mm_portal::tests`
before extraction; move those assertions with the owner into the **new**
`cargo test --locked -p carrick-core --test x86_acceleration` suite afterward.
Do not retain an old implementation just to keep its test target alive.

The Mac runner rebuilds/signs the integrated SHA with `just build`, then runs
`just --no-deps test-embed el1_ --nocapture`. This signed packet includes these
existing witnesses plus the N1 driver's current witness set; zero/missing
required bindings fail. CLI and embed executables have separate identities.

| Gate | Existing witnesses to preserve |
| --- | --- |
| **AM: MM/transfer** | N1 `crates/carrick-el1/src/personality/mm_portal/tests.rs`: `transfer_revalidates_exact_mm_before_copy`, `prepared_copy_commit_and_cancel_never_acquire_held_root_or_editor`. N1 `crates/carrick-embed/tests/el1_host_copyout.rs`: `el1_host_copyout_into_and_out_of_untouched_reserved_memory`, `el1_host_buffers_follow_reused_mapping_in_two_live_processes`. `crates/carrick-embed/tests/el1_sched.rs`: `el1_sched_mm_occupancy_two_processes`, `el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation`. |
| **AF: fork/COW** | N1 portal tests: `owner_fork_live_store_failure_restores_parent_and_refuses_child`, `owner_fork_parent_copyout_abort_retains_live_split_arena`. Signed scheduler suite: `el1_fork_cow_resolves_in_guest`, `el1_tlb_fork_and_exec_leave_no_stale_translation`. |
| **AW: wait/lifetime** | N1 portal tests: `owner_wait_release_before_enrollment_never_parks_a_lost_edge`, `pending_brk_scrub_must_not_wait_for_its_own_gate`. Sched-core `crates/carrick-sched-core/src/tests.rs`: `records_are_reused_with_a_new_incarnation`. Signed scheduler suite: `el1_metadata_allocator_delayed_owner_parks_participants`, `el1_thread_lifecycle_cleartid_tid_reuse`. Bind N1's clear-child-tid-across-exec witness too; tid reuse alone does not prove it. |
| **AR: return/reuse** | N1 portal tests: `partial_retired_compound_replacement_preserves_live_neighbor`, `grant_resume_reselects_generation_range_protection_and_source_changed_while_parked`. N1 runtime stage1 suite: `reusable_root_slot_stays_quarantined_without_backend_retirement_receipt`, `committed_mm_reuses_neither_asid_nor_root_until_all_residency_acks`. Signed scheduler suite: `el1_anonymous_mapping_retirement_returns_and_reuses_frames`, cross-vCPU stale-translation and current exact table/root custody bindings. Retain the negative invalidation control. |

Compare pre/post-move receipts: HEAD, CLI/test/fixture SHA-256, CDHash, LC_UUID,
entitlement, DOF, layout hashes and run-ID-scoped cleanup. Preserve assertions
and work budgets. The director's qualified runner/batch gate owns `just accept`,
`just el1-gate`, then exact-CLI promotion through
`just --no-deps conformance-probes`, `just --no-deps conformance smoke` and
`just --no-deps conformance full`. Verify SHA/CDHash each rung; no rebuild/re-sign
between CLI rungs. Docker stays a separate director phase. A missing/red
**affected** signed witness blocks integration; other unresolved N1/N3
gates remain disclosed. Workers run focused checks and push, not full/remote gates.

## CPL0 milestones

The `x1_`/`x2_`/`x3_` names below are **new tests to add**, not current passes.
Bind X1 to N1's `kernel.el1.mm-exclusive-owner` and existing
`kernel.el1.stage1-publication`/`kernel.mm.address-space-occupancy`; X2 adds
`kernel.fork.stage1-image`; X3 adds `kernel.mm.pt-pause-drain-acknowledgement`,
`kernel.scheduler.runnable-progress` and N1's `kernel.el1.elastic-frame-extents`.
Register missing execution bindings red-first in the existing contract harness.
All commands run from repo root. Every KVM rung first builds its exact image:

```sh
cargo build --locked --release -p carrick-x86-cpl0 --target x86_64-unknown-none
```

| Milestone | Shared execution / N1 defects it would catch | VM-free first → exact KVM command |
| --- | --- | --- |
| **X1a: bootstrap on the N1 stack** | Boot one process using existing shared AddressSpaces/occupancy and ZoneTables claims; execute CPL3 bytes and shared robust-list serving. Preserve native context/TLS/XSAVE; reject recycled record/root identity. This catches zone-record reuse/admission errors. It is X1's bootstrap portion, developed alongside the owner moves rather than a substitute for them. | `cargo test --locked -p carrick-x86 --lib cpl0_scheduler::tests` → new test in `crates/carrick-vmm-kvm/tests/cpl0_entry.rs`: `CARRICK_RUN_ID=x1a-bootstrap cargo test --locked -p carrick-vmm-kvm --test cpl0_entry x1_boot_shared_substrate -- --exact --nocapture` |
| **X1: shared MM owner** | After orders 1/3a/3b, CPL0 executes the moved N1 MM owner, allocator/fault/grant hooks. Lazy touch/protect/unmap/remap and real-byte transfer; a second live MM with the same VA rejects the wrong physical pin. Host supplies physical backing/copy only. Catches stale generations, grant completion/pin ordering and partial-grant retirement. | New `cargo test --locked -p carrick-core --test x86_acceleration x1_shared_mm_owner -- --exact` → new `crates/carrick-vmm-kvm/tests/carrier_memory.rs` case: `CARRICK_RUN_ID=x1-mm cargo test --locked -p carrick-vmm-kvm --test carrier_memory x1_shared_mm_owner -- --exact --nocapture` |
| **X2: fork/COW** | Fork extraction starts beside order 1; executing X2 needs X1 plus order 2. CPL0 uses the same unpublished-fork/commit/abort body; parent and child execute private same-VA writes. Inject failed child publication and parent copyout during pending fork; retain exact custody across abort. Zero host fork projection/process creation. Catches partial-grant retirement and fork receipt/pin lifetime defects. | New `cargo test --locked -p carrick-core --test x86_acceleration x2_shared_fork_cow -- --exact` → new `carrier_memory` case: `CARRICK_RUN_ID=x2-fork cargo test --locked -p carrick-vmm-kvm --test carrier_memory x2_shared_fork_cow -- --exact --nocapture` |
| **X3: grant/wait/retirement** | After orders 3a/3b/4, two processes exercise release-before-enroll, record reuse, brk scrubbing its own closed gate, delayed/duplicate grants, partial compound returns, exec/clear-tid and root-slot reuse. Waits release capacity and preserve prefixes; exact drain/pin/retirement receipts alone permit reuse. Clear-tid uses the same N1/N2 Linux exec/exit client as ARM. Catches all six neutral classes: zone reuse, partial retirement, brk self-wait, grant/pin ordering, clear-tid across exec, root reuse. | New `cargo test --locked -p carrick-core --test x86_acceleration x3_shared_protocol -- --exact` → new `crates/carrick-vmm-kvm/tests/cpl0_progress.rs` case: `CARRICK_RUN_ID=x3-protocol cargo test --locked -p carrick-vmm-kvm --test cpl0_progress x3_shared_protocol -- --exact --nocapture` |

X1–X3 must execute linked production core **inside CPL0**. Existing host-driven
`carrier_memory` callbacks are hardware preparation only; the new cases use
owner-issued receipts. Require nonzero populations, CPL0 owner entry/completion
counts and zero semantic host forwards for admitted operations. Both images
link the same moved source; boundary checks reject owner bodies in x86 adapters.
Receipt mutations must fail the same invariant on both ISA VM-free bindings.

Preserve N1 budgets at 16/64/256 touched pages and 16/512 unrelated mappings:
touched-leaf/tree-height work, extent crossings and retained bytes. VM-free
geometry covers 4 KiB and 16 KiB compound custody; willow has 4 KiB host pages.
X3 uses `max(32, actual_executor_count + 1)` participants, overrides unset,
and proves progress with every default lease occupied. Until carrier plan M5
binds the persistent pool, a bounded CPL0 fixture does not close production
pool exhaustion; retain its separate runtime witness.

Mac-only seams remain: root relocation/boot pools, sparse-arena VM mapping,
legacy IPA indexing and the signed gate preamble. KVM cannot qualify them.
X1–X3 do not close whole N1, N3's exit ceilings, OCI carrier M5/M6 or <=2x cost.

## Capacity

- **Now:** foreground VM-free/KVM witnesses on carrick VM 210, nested on willow;
  no Docker. Separate worker checkouts/build outputs; never replace an image
  under a live guest. Export source/image/test hashes, nesting/capability
  identity, results and scoped cleanup.
- **Next, #4:** ephemeral one-job KVM runners extend existing
  `crates/carrick-xtask/src/ci_scaler.rs` and `.github/workflows/willow-pilot.yml`.
  Preserve pool/VMID/ledger fences and protected VMs. The pilot allows one clone
  and 80% projected CPU admission; expansion requires recaptured capacity and
  approved provisioning. Queue when full; no VM 210 resizing in this track.
  Qualify exact-SHA execution, cancellation, evidence export and teardown before
  required merge-group use. Current pilot runs entry tests, not X1–X3 acceptance.
- **Elastic bare-metal x86 KVM:** adds isolated parallel populations, multi-vCPU
  shootdowns, long generation/reuse campaigns and quiet same-ISA timing without
  nested exit/steal distortion. Provider/spend/quota remain owner decisions;
  #4 records AWS declined on cost. Require live KVM and ephemeral JIT/cleanup
  qualification. More x86 lanes offload shared-core discovery from the Mac;
  they add neither ARM/HVF coverage nor signed-host capacity.

## First two weeks: two workers, optional third

Assignments below are future work. Start immediately on `work/n1` with reviewed
#7 seams. A owns transfer/reservation symbols; B owns fork capsules; optional C
owns grant/retirement custody. Overlap with N1 is authorized. One x86 integrator
owns manifests/exports/inventories and shared-file conflict resolution, checked
with the N1 driver. With two workers, A takes custody after the MM move.

| Days / worker | Task and source fence | Exact verification |
| --- | --- | --- |
| **1–3 / A** | Move order 1's MM admission/select/revalidate/prepare/commit symbols and records; switch ARM and x86 callers once. Use #7's real two-MM transfer fixture, including wrong-output pin and 16/64/256 work reds. Source fence is order 1, not a second MM implementation. | Before move: `cargo test --locked -p carrick-el1 --lib personality::mm_portal::tests`; after move: new exact core X1 command above; `cargo test --locked -p carrick-mmu-core --lib x86::descriptor_txn::tests`; **A + AM** |
| **1–4 / B** | Move order 2's unpublished fork/undo/commit capsule against A's exact MM capabilities; reuse #7's fork geometry seam. Inject parent-write/abort/stale-child receipt defects before adding CPL0 transport. | New exact core X2 command above; `cargo test --locked -p carrick-el1-abi --lib mm_portal_fork`; **A + AF** |
| **1–5 / optional C, otherwise A on days 4–7** | Move orders 3a/3b's grant and retirement receipt/custody validation. Coordinate the ARM-shaped grant slot, real inventory callbacks and pin-before-return ordering with N1; register X1–X3 bindings in `conformance-contracts/contracts`. | New exact core X3 command above; `cargo test --locked -p carrick-el1-abi --lib mm_portal`; `cargo test --locked -p carrick-conformance-contract --lib personality_boundary`; **A + AM + AR** |
| **4–8 / B** | X1a then X1 CPL0 integration in `crates/carrick-x86-cpl0/src/entry.rs`, `crates/carrick-x86-cpl0/Cargo.toml`, `crates/carrick-x86/src/cpl0_scheduler.rs`, `crates/carrick-vmm-kvm/src/cpl0_boot.rs`, `crates/carrick-vmm-kvm/src/carrier_memory.rs`, and the existing KVM test files above. Bind the shared allocator/fault/grant hooks; no private x86 heap or owner. | `cargo test --locked -p carrick-x86 --lib cpl0_scheduler::tests`; image build and exact X1a/X1 KVM commands above; `CARRICK_RUN_ID=week1-entry cargo test --locked -p carrick-vmm-kvm --test cpl0_entry -- --nocapture` |
| **6–10 / B; A or C** | B executes X2's shared fork/COW; A/C composes order 4 and X3's two-process wait/reuse/retirement controls. Feed each red/fix back to N1 and sync before the integrated run. Keep unresolved production-pool/exec bindings explicit. | Image build, both exact X2 commands and both exact X3 commands above; **A + AF + AW + AR** |

Each implementation task also runs `just fmt-check`, focused crate Clippy with
`--all-targets -- -D warnings`, and `just lint-domains`, then pushes/reacts to
runner checks. Shared changes need fresh green signed witnesses at their
integrated SHA, scheduled behind N1. The two-week goal is shared-owner learning
and X1/X2 execution; X3/whole-N1 acceptance remains evidence-driven. No retry,
larger timeout/pool, polling or reduced
concurrency closes a failed semantic, structural or runtime witness.

## Document verification

Only this plan changes. Verify cited paths with `git ls-files` in main and
ref-specific temporary indexes for N1/#7/#19/#4; destinations/new tests are
explicitly future. Run `just fmt-check` and `git diff --check`. No Docker, KVM
guest, signed/HVF test or acceptance receipt is claimed for this docs-only task.
