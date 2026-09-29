# EL1 migration: current completion controller

> **For agentic workers:** Execute the current authorized task with
> `superpowers:executing-plans`; use delegated execution only when authorized.
> This controller is director-owned. Workers report evidence and proposed
> status changes; the director maintains this file.

**Updated:** 2026-09-29, from local Git state, source inspection and retained
receipts. After requesting the refresh, the user explicitly said "Set the
goal and go." The end-to-end goal is active; execution is in task A below.

**Goal:** Complete the accepted EL1 migration through the x86 ring-0 venue,
with one authoritative owner and one semantic implementation per object,
verified Linux behavior, bounded work and the per-workload ≤2x native-Linux
objective. A branch merge or a focused green test does not close a checkpoint.

**Architecture:** Shared neutral cores with venue adapters; guest-kernel
ownership of Linux semantics. Preserve elastic bulk host frame grants/returns,
host-scheduled vCPUs, host-native I/O and the substrate/personality boundary.
Host requests are validated, batched and asynchronous; a guest wait releases
execution capacity. Retain adapters needed by other backends until their
replacement is accepted; delete superseded semantic paths.

**Tech stack:** Rust; HVPatch/AArch64 EL1 on macOS/HVF first; shared x86 engine
and real KVM/bhyve/NVMM execution for the x86 venue.

**Authorities:** [accepted design](../specs/2026-09-24-el1-kernel.md),
[AGENTS.md](../../../AGENTS.md),
[contracts](../../conformance-contracts.md), and this controller.
[Previous controller](2026-09-29-el1-controller-history.md) preserves the full
historical campaign verbatim. The local handoff is
`.worktrees/EL1-HANDOFF-2026-09-29.md`; this controller supersedes its stale
status/order statements where explicitly corrected below.

## Current state and evidence rules

At refresh, the implementation baseline on local `main` and local
remote-tracking `origin/main` is `a70b40466`. The documentation commit for
this refresh advances local main only; no remote fetch was performed.
Batch 3 is on `integ/batch3`, unlanded. Its scheduler correction is
`a2c0fcee3`, following the atomic re-park correction `0e1d7c12c` and exact
zone handback targeting `da84671b7`. The latter has a deterministic red-first
reaped-child witness, continuation authentication and pre-enrollment kick
controls. Direct adoption reserves ownership before publishing readiness.
Final kernel/semantics 2,462 (one existing ignore), three focused controls
and affected Clippy passed. Serial kernel 109 and runtime 630 passed before
the ordering-only follow-up. Registry, clean-source lint and exact contract
coverage passed; the 595-row authority census remains macOS-only.

Fresh signed source `257de53e0` passed 49 unique positive EL1 executions
across nine artifacts, the unentitled negative control and scoped cleanup.
The nine executable SHA-256 hashes were independently matched to the
retained `exact-zone-wake/signed-artifacts.jsonl`; full output and final
source-gate logs are in that receipt directory. This replaces `8916e1fe2`
as current scheduler regression evidence, but does not supply deterministic
signed race bindings, historical crash attribution or full task-A acceptance.
New focused signed source `2e6e3794a` adds the notification capture audit
event (`b55e57803`) and a deterministic three-process fixture. Delivery is
held across the exact parent's reap: the retained pre-fix method produces one
reaped-wake rejection; restored exact targeting produces zero. Entitlement
negative controls and cleanup passed. See `notification-order/` for both
artifacts, the controlled source patch and the initially non-discriminating
fixture result. This closes this producer's signed interleaving gap only; the
49-execution receipt above predates the new audit event and is not full-tree
acceptance for this source. Clean compiler gates and broad regressions remain
pending for the audit event.

VM-free additions now prove exact retirement after control/failed-load
settlement (110 serial kernel passes) and enforce zero retired-delivery wake
publications at 1/8/32 with excess-work negative controls. Those scoped
observations do not establish total scheduler work or signed cost.

All twelve active
batch/memory/IPC/sigsuspend worktrees inventoried below were clean at the
initial refresh inspection; only batch 3 has been advanced in this goal.

Evidence labels:
- **Source-confirmed:** code or Git ancestry inspected on the named revision;
  not a claim that it compiles or runs.
- **Receipt-confirmed:** retained results inspected; valid only for their
  recorded source/artifact/fixture population, not the new merged tree.
- **Handoff claim:** prior worker/director report not independently requalified
  here. “Ready” means a review candidate, never automatic acceptance.
- **Accepted slice:** historical acceptance for a named limited surface, not
  completion of its containing checkpoint or current full-tree acceptance.

| Checkpoint | Current state | Completion boundary |
|---|---|---|
| 0: scheduler/address-space execution | Implemented on main; batch 3 still has lifecycle blockers | Preserve scheduling, wake, GIC/timer, occupancy and address-space-switch contracts on the integrated artifact |
| 2: memory | First-touch, resident permission and resident munmap slices historically accepted; ownership migration incomplete | Anonymous semantics, faults, COW, descriptor publication and elastic return owned in EL1; all host writers converted before pause removal |
| 2a: host namespace cost | Earlier namespace budget work merged; full objective open | Containment/coherence plus controlled Linux ratios and native macOS I/O controls; finish before checkpoint 4 |
| 3: descriptors/IPC/signals | Pipe/eventfd foundation and fixtures in separate branches; no checkpoint acceptance | Full descriptor lifecycle, in-zone IPC/readiness/signals and all assigned ownership obligations |
| 4: names/page cache | Pending | EL1 name/dentry/stat/page-cache ownership with host namespace/writer coherence; retire old file zone |
| 5: process lifecycle | Pending | EL1 fork/exec, image loading and process lifecycle; host only supplies boundary services |
| 6: x86 venue | Pending; hardware/oracle availability not verified in this refresh | Same neutral cores in ring 0, each declared backend qualified with real execution and native x86 oracle |
| Final acceptance | Pending | Entire declared conformance/workload denominator, provenance, cost gates, dead-path removal and unresolved-item closure |

Main includes batches 1/2 (handoff batches `043ffbcc9` and `a70b40466`):
namespace/syscall budgets, futex-exit bounds, close locking, directory identity,
idle service rescue, fixture port/liveness fixes, dispatch/empty-steal cost
reductions and carrier-CPU attribution. Merged presence does not transfer their
old gate results to future integrations.

Two obsolete open items are corrected: parked-EL1-thread crash registers have
an implementation and signed fixture on main (`4d43ade6a`); the personality
boundary has a mechanical gate for scheduler/MMU cores (`26f104341`,
`1bc6c8900`). Preserve those gates and extend coverage as new cores move;
neither is still “not implemented.” Derived entrant bounds, GIC/SPI recovery
obligations, complete boundary coverage and paired attribution remain open
until their own receipts close them. Do not re-open historically accepted
memory traces absent a new failure.

## Branch inventory and integration dependencies

All paths are under `.worktrees/`. Heads below are verified local snapshots.
Do not discard a branch because a subset was merged elsewhere.
Bring this controller forward from main when integrating an older branch;
do not overwrite it with that branch's pre-refresh controller.

| Worktree / branch | Head | Disposition |
|---|---|---|
| `wt-batch3` / `integ/batch3` | `a2c0fcee3` implementation; signed `257de53e0` | Current blocker owner; review original slot-liveness/pgrp/ICMP changes, notification fix and deferred-handback identity correction together |
| `wt-cp2-descr` / `work/cp2-el1-descriptor-owner` | `c555f5dd1` | Review candidate; 9 signed filters and first-touch slopes 0.004–0.009 are handoff claims |
| `wt-cp2-cow` / `work/cp2-hvf-cow-adapters` | `d581dd099` | Ancestry-confirmed in descriptor branch; do not merge it a second time |
| `wt-cp2-return` / `work/cp2-elastic-return` | `8f268dee4` | Review candidate; scoped grant/return accounting and signed green are handoff claims |
| `wt-cp2-tests` / `work/cp2-ownership-tests` | `45fa94124` | Contains deliberately red ownership witnesses; dedicated host-COW accessor still panics |
| `wt-cp2-reserve` / `work/cp2-el1-reservations` | `f2efa3716` | Explicit unverified WIP; reservation provider/projection and host authority work incomplete |
| `wt-cp3-adapter` / `work/cp3-ipc-adapter` | `b0313df83` | Explicit interrupted WIP; runtime glue exists but is not accepted |
| `wt-cp3-host` / `work/cp3-ipc-host` | `77b6f40a1` | Shared backing/lifetime foundation; descriptor-table integration and host blocking continuation open |
| `wt-cp3-fixture` / `work/cp3-ipc-fixture` | `fd27e748d` | Five signed acceptance tests plus report validators/contracts; baseline red is a handoff claim |
| `wt-cp3-objects` / `work/cp3-ipc-shared-objects` | `bb93917a4` | Ancestry-confirmed in adapter branch |
| `wt-cp3-waits` / `work/cp3-ipc-object-waits` | `7debfcc13` | Ancestry-confirmed in adapter branch |
| `wt-sigsuspend` / `work/rt-sigsuspend-parallel-flake` | `5011caffa` | Unverified WIP; establish root cause/pre-change evidence before considering integration |

Preserve `wt-slotlive` (`1cd5071d6`), `wt-pgrpsnap` (`849e2119c`) and
`wt-icmpflake` (`2a097c0bd`) until batch-3 integration is accepted. Older
`wt-sysret` (`56f848a2b`) and `el1-inotify` (`7eb9a6853`) are not part of the
next slice; inventory their work before reuse/cleanup. Reuse suitable existing
checkouts; retire worktrees only after verifying no task/process relies on them
and saving recoverable state. Never sweep shared probe/build storage.

## Execution order and review focus

The next authorized implementation proposal is **A**, followed by **B**, **C**,
then **D**. This preserves the handoff's bounded overlap between memory and IPC;
C does not mean checkpoint 3 is complete before memory closes. Later stages
remain part of the denominator but get bounded briefs from live source when
reached, rather than speculative interfaces now.

Review focus across every slice: exact task/MM/record generation after reuse;
two live processes with overlapping VAs and independent identity; partial I/O
and SA_RESTART during exec/exit; rollback under allocation/publication refusal;
coherence with host file mutations and shared aliases. Each owning task below
must provide those witnesses where applicable.

### A. Close batch-3 lifecycle blockers

Sources: `crates/carrick-runtime/src/vcpu_loop/{wait_wake.rs,zone.rs,executor/}`,
`crates/carrick-kernel/src/{el1_zone.rs,kernel/scheduler.rs}`, and
`crates/carrick-sched-core/src/`. Contract for the new notification reduction:
`kernel.wait.child-exit-notification-lifecycle` (currently branch-local).

- [x] Preserve the original two failures and distinguish their boundaries.
- [x] Reduce delayed parent notification to a deterministic VM-free red;
  `932a33568` uses the existing exact task/thread/generation wake API.
- [x] Retain 630 runtime passes/8 existing ignores, Clippy and registry checks;
  signed shard at `df9741d88`: 314 musl/glibc executions, negative control and
  zero scoped leftovers. These are receipt-confirmed, not rerun for this edit.
- [ ] Attribute the historical `otmpfileforkexec` reaped-task wake to an exact
  producer/interleaving. The reduction is a real defect but not that attribution.
- [x] Reduce deferred evacuation identity reuse, fix it with retained
  RecordRefs (`3981c0366`), and preserve the red/green witness at 1/8/32
  records. Kernel/semantics 2,459 passes, serial-host 109 passes, kernel
  Clippy and `just lint-domains` passed. The authority census is the macOS
  subset (595 unchanged rows); non-macOS profiles remain pending. All 14
  signed `el1_sched` tests at `0542e2d2f` passed, with negative entitlement
  control and zero scoped leftovers. This is regression evidence; signed
  deterministic interleaving and WorkObservation bindings remain open.
- [x] Preserve identity at the earlier core publication boundary (`99c8cd5ac`):
  three red-first callback/returned-batch/executor-take witnesses. Core 53,
  EL1 host-test 74, kernel/semantics 2,459, serial-host 109 and runtime 630
  passed (existing ignores unchanged). At `40a707ba0`, all 49 selected signed
  EL1 executions across nine executables passed, with negative control and
  zero scoped leftovers. Clippy and lint passed. These are regression receipts,
  not historical attribution or deterministic signed-interleaving closure.
- [ ] Repair the newly reproduced producer lifetime defect: Host becomes
  visible before `claim_for_host` finishes unlinking. Cancellation can free
  and reuse that slot; the old producer then removes the replacement waiter's
  queue entry while it remains Parked (deterministic count 0 instead of 1).
  Two VM-free reds are retained in the branch receipt's `host-publication/`.
  Implementation census/order: `2026-09-29-el1-handback-publication.md`.
  The guest placement preparation now moves futex unlinking before target
  queue-lock release; its 1/8/32-waiter witness was red and is green. This
  does not repair the host-transfer red or close this checklist item.
  The producer-transfer implementation now passes the two restored red-first
  witnesses, waitv/cancellation and host-request controls (core 58, EL1 host
  74, ABI 32, kernel/semantics 2,459, serial-host 109, runtime 630; existing
  ignores unchanged). The combined fixes now have signed EL1 regression
  coverage at `257de53e0`; deterministic signed interleavings and the remaining
  retirement/restore lifetime audit are still required. See `owned-transfer/`
  and `exact-zone-wake/` for their distinct proof scopes.
  Cancellation-before-El1Held and delayed flag writes now have red-first
  repairs using incarnation-bound requests; incarnation exhaustion is also
  fail-closed. Core62/EL1host74/ABI32 and the broader VM-free regressions
  passed; see `tagged-requests/`. RecordRef still does not grant exclusive
  field access; post-publication retirement/restore audit remains open.
  Scheduler handback wakes now use exact targets: the captured-key/reaped-child
  witness is red-first, and matching continuation plus pre-enrollment delivery
  controls pass. Remaining producer/service/restore lifetime boundaries and
  deterministic signed bindings stay open; historical attribution is separate.
- [ ] Reduce Python's `SnapshotRestoreFailed`: record 1/incarnation 35925 was
  `Parked { seq: 17965 }` during host materialization; subsequent MM cleanup
  aborted. Compare against main before calling it a batch regression.
- [ ] Capture carrier stacks, event ring and core on reproduction; prove the
  failing ownership transition in a deterministic contract, then fix it.
  Deferred evacuation now has a deterministic red-first identity reduction:
  after cancellation/reuse, a saved bare RecordId publishes the replacement
  incarnation. Retaining RecordRef fixes that reduction at 1/8/32 records.
  Attribution to the historical Python crash is still open; see the branch
  receipt's deferred-handback section. A rebuilt, pinned Python run at
  `5ce5bd059` passed (395 tests, 51 skips), with no fatal capture triggered.
- [x] Bind delayed parent notification to deterministic signed capture/reap/
  delivery ordering. Source `2e6e3794a` passes with zero reaped wake attempts;
  the same fixture with the retained pre-fix method fails at one attempt.
  This is producer proof, not attribution of the original otmp failure.
- [ ] Close the notification contract's scoped structural observation gap;
  run the complete batch gate below on the final candidate.
- [ ] Accept and integrate locally only when all blockers/gates close.

Receipt on branch `integ/batch3`:
`docs/perf-results/2026-09-29-el1-batch3-resume/README.md` and its raw artifacts
(initial receipt commit `11e8c6a29`, extended by the deferred-handback
receipts). Read it in `wt-batch3`; it is not on main yet. Quiet Python passes
and 100 passing probe diagnostics do not erase the original reds.

### B. Integrate reviewed memory foundations

Consumes A's accepted base; produces one reviewed descriptor/return foundation
without claiming the still-disabled guest descriptor lane is active.

- [ ] Review descriptor + elastic-return diffs and branch-local receipts;
  preserve exact MM/frame/IPA/owner domains and rollback receipts.
- [ ] Integrate `work/cp2-el1-descriptor-owner` and `work/cp2-elastic-return`,
  reconciling interfaces/layout before running the memory regression net.
- [ ] Review T6 witnesses and wire a real scoped HostCowStats embed accessor.
  `wt-cp2-tests/.../tests/el1_sched.rs::host_cow_resolutions` currently panics;
  do not replace it with host-fault counts, zero, ignore or expected-green.
- [ ] Keep future-feature red witnesses explicit on their development branch
  until they are satisfiable. Never mark an intentionally red gate accepted.
- [ ] Record which foundation contracts are proven and which ownership gates
  remain open; pass the full batch gate before accepting this integration.

Source-confirmed in descriptor `vcpu_loop/signal.rs`:
`GuestDescriptorLanePrecondition::current()` has `fork_parent_arming=true`,
`host_copyout=false`, `backend_writers=false`. Descriptor Prepare/Publish/
Protect/Retire/CowRepoint/ForkArm machinery is not full production ownership.

### C. Complete the pipe/eventfd vertical

Consumes reviewed adapter, host and fixture branches; produces live in-guest
pipe/eventfd service with exact descriptor/operation lifetime. Checkpoint 3
still includes the broader work in E.

- [ ] Review and reconcile adapter + host + fixture on one integration base.
  T1 objects and T2 waits are already ancestors of the adapter. Host prerequisite
  subsets were merged; do not assume the complete host branch is integrated.
- [ ] Compile/test the existing runtime glue before adding missing code.
  Contrary to the handoff, the adapter already contains the handback intercept
  before ordinary preparation (`vcpu_loop/mod.rs`), owed host-wake delivery at
  `served_with_work`, backing registration (`runtime.rs`), and interrupt/restart/
  partial-progress helpers (`vcpu_loop/zone.rs`). `7baabfd95` and the top WIP
  contain code, not verified completion. Audit ordering and every return path.
- [ ] Complete the host-originated blocking continuation sharing the existing
  completion engine; `block_on_object` was not found in either active branch.
  Turn `serial_host_el1_ipc_blocking_eventfd_write_retains_value_until_capacity`
  green without dropping the pending value or parking an executor on guest work.
- [ ] Complete table publication/create/fork/unshare/destroy, dup/dup2/fcntl,
  CLONE_FILES, exec CLOEXEC, SCM_RIGHTS/install_pin and endpoint retirement.
  Unpublished tables must continue to fail closed to the host path.
- [ ] Turn all five `el1_ipc_*` signed witnesses green: `fd_lifetime`,
  `park_wake_races`, `pipe_eventfd_roundtrips`, `mixed_venue_lifecycle`,
  `signal_restart_and_partial_write`. Use scales 1/8/64 and two-process pairs;
  require nonzero guest parks, zero IPC-caused exits per round trip, correct
  bytes/errno/SIGPIPE/restart behavior and complete scoped counters.
- [ ] Run the full batch gate and accept only this named vertical.

The fixture handoff reports ~261k host exits and ~64k service placements per
baseline test, all five red on absent guest parks. Requalify that baseline
against the actual integrated fixture; do not infer execution from validators.

### D. Finish checkpoint-2 memory ownership

Consumes B, the reservation branch and ownership fixtures; produces full
anonymous-memory ownership with no remaining host descriptor writer/pause.

- [ ] Reproduce/reduce the reservation fixture race in
  `vcpu_loop/memory.rs::production_carrier_active_target_services_publication_at_its_next_entry`.
  The source still polls `is_quiescing` for one second while LeaveGuestOnKick
  clears guest entry; a latched handshake is a proposal, not a verified fix.
- [ ] Review the unverified reservation-provider/projection WIP; complete the
  carrier-owned metadata resolver across runtime/HVF. Reuse the present
  `plan_host_first_touch` / `commit_host_first_touch_after_guest_publish` split.
- [ ] Move anonymous-private facts from MemState to the authoritative shared
  reservation model: brk/mmap/munmap/mprotect, VMA split/merge, FirstTouchArming,
  madvise/mincore, proc maps, fork/exec/exit and exact lifecycle handoff in
  `dispatch/mm_authority.rs`. Preserve file/shared-mapping semantics.
- [ ] Activate `dispatch_anonymous_with_reservations` in personality dispatch
  only after those authorities are joined; no independent EL1 policy cache.
- [ ] Complete copyout conversion, guest replacement-frame COW copy window,
  fork arming/publication and all remaining backend writers. Prove foreign
  accesses, two-live-MM isolation, denied access and rollback/refusal behavior.
- [ ] Publish the complete writer census; only then remove the host page-table
  pause. Prove first-touch/COW in guest, prompt scoped frame return/reuse and
  pause-free two-MM progress using the strengthened T6 witnesses.
- [ ] Pass semantic and scaling contracts, full batch gate and workload ratios;
  accept checkpoint 2 only after the integrated ownership path is active.

Frozen layout: counters `[0x100000,0x120000)`, SharedReservations
`[0x120000,0x180000)`, descriptor transactions `[0x180000,0x1A0000)`;
IPC table map region offset `0x103_0000`. Adapter IPC window is
`0x2D_0C00_0000` with 2 MiB directory + 128 MiB pool. Coordinate any change
centrally and prove layout bounds; these are interface assignments, not
permission to overlap or silently resize regions.

### E. Close all remaining ownership stages

| Stage | Required deliverable and decisive proof |
|---|---|
| 2a host namespace | Finish measured namespace budget/cost work before names/cache ownership; transactions preserve containment and physical/cache coherence, including rename no-op/hardlinks; controlled Linux ratios plus native macOS I/O controls |
| 3 remainder | EL1 fd tables/descriptions/offsets/flags, AF_UNIX, timerfd, epoll/poll/select, signals and in-zone loopback; preserve credentials, peer/SCM identity, readiness, partial operations and cancellation under exhausted default executor capacity |
| 4 names/cache | Authoritative EL1 dentry/stat/name resolution and host-file page cache; validated host namespace operations, host-writer/shared-alias coherence, mutation rollback; remove replaced file-zone implementation |
| 5 lifecycle | EL1 fork/exec/address-space lifecycle and image loading; parent/child identity, vfork sharing, exec sibling drain, wait/reparent/reap, credentials/rlimits/pgrps/sessions; ptrace and core semantics with host core-file output |
| 6 x86 | Same neutral semantic cores through shared x86 engine; native x86 oracle and real KVM/bhyve/NVMM lane evidence for the declared support matrix; no translated amd64 Docker substitute |

Clocks remain guest reads of calibrated vvar/CNTVCT where appropriate; external
sockets/DNS, contained host-file operations, shared host-file aliases, CLI
terminal/stdin/stdout and process-boundary reporting retain the host roles in
the design. These boundaries must be audited, not counted as missing EL1 work
or accidentally migrated into duplicate semantics.

Before each stage starts, attach its bounded source/contract/fixture brief and
explicit acceptance population here. Keep every ownership row in the design
assigned to a stage. Verify x86 hardware/oracle availability early enough that
checkpoint 6 is a named dependency, not a surprise final omission.

## Common acceptance and landing protocol

1. Review the exact diff and relevant contracts; reduce new failures red-first
   in the cheapest capable layer. Assert semantics and deterministic work.
2. Integrate onto the current accepted base; commit, reconcile inventories on
   a clean tree, inspect generated changes, then run `just lint-domains` and
   full `just ci`. No stale branch-local result qualifies the merged tree.
3. With no guest alive, `just build`; record HEAD, SHA-256, CDHash, LC_UUID,
   hypervisor entitlement and DOF. Record each signed embed executable
   separately. Preserve fixture source/executable hashes and image digests.
4. Run the batch regression population: `roreadwrite`, `protnonesyscall`,
   `memflagmatrix`, `coredumpbit`; empty `mmapprivfile` diff; `windowcoherence`
   four executions per libc; signed `carrick-embed el1_` plus changed contracts
   and crash-register witness; full `just --no-deps conformance-probes`.
5. Run the eight cpython suites twice: fork1, wait3, wait4, threading,
   concurrent_futures, multiprocessing_fork, mmap, subprocess; Go build twenty
   times. These are fixed acceptance populations, not retry-until-green.
   Preserve every failure/automatic-confirmation result. Existing serial
   oracle orchestration is not permission to reduce fixture concurrency.
6. Run `just --no-deps el1-gate` on the built artifact and the applicable smoke
   and full conformance promotion (`just --no-deps conformance smoke`, then
   `just --no-deps conformance full`). Check CLI identity between rungs;
   rebuild/re-sign invalidates prior artifact acceptance. The current el1-gate
   recipe is only one required population, not the entire migration gate.
7. Measure uninstrumented release workloads on a quiet host against pinned
   same-image native Linux, serialized Carrick/Docker phases, with the contract's
   declared statistic/sample count. Start with Go build, cpython-threading and
   cpython-subprocess; final acceptance covers the full declared ecosystem.
   Keep raw Linux ratios and native macOS I/O controls separate. CPU attribution
   profiles diagnose cost; they are not timing acceptance.
8. Record run IDs and prove scoped cleanup. Advance status only for the
   proven population; then integrate accepted work locally and reverify the
   final merged artifact. No push/PR is authorized by this documentation edit.
   Do not follow the old scratch script's unconditional push instructions.

Memory regression filters: `el1_memory_first_touch_stays_in_guest`,
`el1_memory_fault_entry_preserves_context`,
`el1_anonymous_permission_transitions_stay_in_guest`,
`el1_anonymous_mapping_retirement_returns_and_reuses_frames`,
`el1_fork_cow_resolves_in_guest`, `discard_fork_threads_contract`,
`el1_sched_mm_occupancy_two_processes`,
`el1_sched_signal_reaches_a_parked_thread`,
`el1_sched_exec_from_a_sibling_with_parked_threads`,
`crash_core_attributes_the_el1_parked_sibling_registers`; add the reservation,
discard/exit-return and pause-free tests when their implementation is joined.
Use function-name filters with `scripts/test-signed.sh`, not filenames.

## Stop conditions and definition of completion

A semantic mismatch, load-dependent failure, lost wake, ownership ambiguity,
structural-budget failure or invalid measurement stops promotion. Missing
identity, dropped/unknown counters, absent required execution bindings and
unavailable native hardware/oracles remain explicit blockers. A ≥10x ratio
for a valid completing workload returns immediately to correctness triage;
ratios above the ≤2x objective remain performance failures. Timeout rows are
not ratios. Do not weaken budgets, inflate timeouts, poll away races, reduce
concurrency, hide red fixtures, or use passing reruns to dismiss failures.

Every acceptance update records: exact revision/artifacts, merged versus
branch-local state, contracts and before/after ownership census, red/green
witnesses, completed row counts, timing controls, cleanup, removed paths and
remaining blockers. Update this controller after each accepted batch so the
next agent does not reconstruct state from chronological reports.

The migration is complete only when checkpoints 0/2/2a/3/4/5/6 and final
acceptance are closed on the declared support/workload population; all design
ownership rows have accepted owners, production routing uses them by default,
replaced paths are removed, and no required proof is deferred. This remains
experimental software, not a claim of a hardened boundary or production
readiness.
