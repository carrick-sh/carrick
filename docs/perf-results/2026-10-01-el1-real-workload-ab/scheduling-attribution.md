# What is in the "executor scheduling" bucket?

**Status (2026-10-01):** diagnosis only. No fix is implemented here. The host
was shared with other workers, so every time below is a sample share or a
ratio of counts. Absolute times "suggest"; nothing here confirms a timing.

## The question

On the quiet-host campaign `el1ab-202610010107` (binary sha256 `c2c6b14f…`,
harness HEAD `2bfa005b`, EL1 descriptor lane off), the
`hvpatch-carrier-cpu-attribution` profile filed 12–17% of sampled carrier CPU
as `executor_scheduling`:

| workload | profile `executor_scheduling` | population |
|---|---|---|
| go-build | 968 (11.5%) | 8402 |
| cpython-threading | 1220 (13.7%) | 8904 |
| node-core-worker-message-port | 1862 (16.7%) | 11123 |

What work is in that bucket, and is it structurally necessary?

## Answer in one paragraph

Most of it is not scheduling. The bucket is a catch-all. The classifier walks
each stack from leaf to root and takes the first match, and its scheduling
patterns (`executor::`, `run_executor_loop`, `executor_worker`, `::schedule`)
match the **root** frames of every executor thread. As a result, any carrier
work under the executor loop that no finer rule names lands in the bucket:
fault settlement, fork preparation, address-space teardown, and even the CLI's
image-reference regex compile. Re-filed by what the code does, real
per-quantum scheduling (park/claim, task switch, wait-service enrollment,
run-state bookkeeping) is **4.6% (cpython), 6.8% (go) and 9.4% (node)** of
carrier CPU. It scales with **blocked quanta** (one per guest wait that gives
up its executor), not with guest exits or with thread count. Roughly half of
it is avoidable host-syscall and bookkeeping work.

## Method

- **Stacks.** The campaign's raw `user-stacks` aggregations
  (`target/perf/el1-workload-ab/el1ab-202610010107-attribution/*-lane-off-carrier-cpu-attribution.raw`
  in `.worktrees/wt-land-g2`) were re-symbolized offline against the exact
  binary. Carrick frames used its symbol table. Shared-cache frames used
  `dladdr` on the same boot; the shared-cache slide is fixed per boot, and the
  host had not rebooted since the capture. The profile's `classify_frame` was
  mirrored exactly. First, the mirror reproduced the profile's own numbers
  sample for sample (node 1862 / 5143 / 2216 / 7 / 333 ...). Then each stack
  was re-filed by its semantic frames. One sample is about 1.0 ms of on-CPU
  time (`profile-997`, per CPU).
- **Event counts.** New captures used a new durable script,
  [`scripts/dtrace/hvpatch-executor-sched-events.d`](../../../scripts/dtrace/hvpatch-executor-sched-events.d).
  It counts lease settlements by kind, executor claims and load/save/switch
  phases, load continuity, exits by class, forwarded syscalls, reactor cycles
  and fork quiesces. It also counts the carrier's host
  `write`/`poll`/`close`/`psynch_cv*` syscalls, keyed by call site. The three
  captures are under [`scheduling-events/`](scheduling-events/). They ran on the
  same binary with the harness's exact argv (`plan --check-harness`) and
  `CARRICK_EL1_DESCRIPTOR_LANE=0`, with run ids `schdiag-ev-4` (node),
  `schdiag-ev-py` and `schdiag-ev-go`. All three exited 0 with clean scoped
  reaping. They are separate runs from the sampled campaign, so the
  per-event ratios below join two runs. Blocking counts vary about 20% between
  node runs: an earlier capture, `schdiag-ev-1`, had 14823 blocked
  continuations against 12258 in `schdiag-ev-4`.

## The profile's two classification defects

1. **Stab aliases erase names.** `SymbolTable::from_macho` keeps every nlist
   entry, including debug-map stabs, and dedups by address while keeping the
   first entry. For a function with a debug map, the first entry at its address
   is an `N_BNSYM` stab with an empty name. That frame resolves to
   `+0x… (in carrick)` with no name and matches no rule. The classifier then
   walks outward to the executor root. With stabs skipped, node `sched` falls
   from 1862 to 1634 and `lock_wait` rises from 7 to 128. go falls from 968 to
   903, and cpython from 1220 to 1076.
2. **Root frames act as a catch-all.** The patterns `executor::`,
   `run_executor_loop`, `executor_worker` and `::schedule` match frames
   present on every executor stack (`::schedule` also matches tokio's
   `scheduler::current_thread` in the CLI main thread). The bucket therefore
   absorbs everything unnamed that runs under the loop.

These two defects are a measurement lever. Fix the symbolizer and match
scheduling only on leafward frames, and the profile will tell the truth.

## What the bucket actually holds

Re-filed lane-off samples (corrected symbolization). "% all" is the share of
the whole carrier population.

| re-filed bucket | node | go | cpython | what it is |
|---|---|---|---|---|
| **A** mm-mutation / fault settle | 321 (2.9%) | 78 (0.9%) | 61 (0.7%) | `with_mm_mutation_authority` → `resolve_mutating_fault` → `settle_guest_frame_grants` / `reconcile_guest_frame_commits`, `PtPauseGuard` drop. **Fault service, misfiled.** |
| **C** blocked-continuation enrollment | 286 (2.6%) | 140 (1.7%) | 70 (0.8%) | `prepare_registration` + `enroll` reactor nudges (`write`), enroll recheck `poll`, `ContinuationDetail` drop (`close` of pinned fd dups) |
| **Z** loop residual | 197 (1.8%) | 93 (1.1%) | 89 (1.0%) | `run_executor_loop` / `poll_with_engine` self time, malloc/free |
| **H** guest-leave wake, kick, zone | 142 (1.3%) | 77 (0.9%) | 44 (0.5%) | `GuestLeaveWake::notify` (cvbroad), `prepare_zone_handback` write, `kick_zone_slot` |
| **E** task load/save on the vCPU | 121 (1.1%) | 101 (1.2%) | 32 (0.4%) | `overlay_task_state_on_live_executor` snapshot+restore, `flush_resident_task` (`hv_vcpu_get/set_*`) |
| **B** mm/fork quiesce park | 114 (1.0%) | 53 (0.6%) | 10 (0.1%) | `PtQuiesce::park` → `__psynch_cvwait` (sibling executors parking for a fork) |
| **D** address-space retirement | 102 (0.9%) | 98 (1.2%) | **375 (4.2%)** | `retire_detached_address_space_with` → `stage_retirement`, `AliasClassIndex::remove`, `FrameInventoryRetirementReceipt::authorizes`, `hv_vm_unmap`. **Process-exit teardown, misfiled.** |
| **I** run queue core | 84 (0.8%) | 97 (1.2%) | 133 (1.5%) | `RunQueue::park_spare` cvwait/cvsignal, `should_preempt` clock reads, `place_zone_row` |
| **F** thread run-state publication | 79 (0.7%) | 26 (0.3%) | 16 (0.2%) | `run_state::claim_record`, `ThreadRegistry::set_thread_state` (SipHash) |
| **G** job-control / ptrace-stop checks | 54 (0.5%) | 9 (0.1%) | 6 (0.1%) | `suspend_for_job_control` → `settle_task_ptrace_stop`, `KernelContext` retain/drop on every quantum |
| **J** executor receipt log | 52 (0.5%) | 9 (0.1%) | 12 (0.1%) | `ReceiptLog::record`: one pool-wide mutex per settlement, diagnostic only |
| **L** CLI startup image resolution | 39 (0.4%) | 84 (1.0%) | 73 (0.8%) | `carrick_engine::Engine::resolve` → `ImageReference::parse` regex compile (main thread). **Not the executor at all.** |
| **K** guest-run entry bookkeeping | 34 (0.3%) | 22 (0.3%) | 11 (0.1%) | `begin_guest_run` clock read, continuation resume |
| **N** fork process-plan build | 4 | 7 | 133 (1.5%) | `prepare_in_process_fork` → `build_process_spec` (`CowArmedRanges::arm`, `ForkTranslationOverlayIndex::build`). **Fork work, misfiled.** |
| M, other | 5 | 9 | 11 | |

Lane-on node has the same shape: A 461 (3.6%), C 329 (2.6%), E 148, F 123,
J 72.

**Real scheduling** (C+E+F+G+H+I+J+K+Z) comes to node 1049 (9.4%), go 574
(6.8%) and cpython 413 (4.6%). **Misfiled lifecycle and fault work**
(A+B+D+L+N) comes to node 580 (5.2%), go 320 (3.8%) and cpython 652 (7.3%).

## Top stacks (node, lane off, corrected)

| samples | % of profile bucket | stack (leaf ← root, executor root elided) |
|---|---|---|
| 114 | 6.1% | `settle_guest_frame_grants` ← `resolve_mutating_fault` ← `with_mm_mutation_authority` ← `poll_with_engine` |
| 109 | 5.9% | `write` ← `run_executor_loop+0x2a18` (the inlined `nudge_reactor` in `prepare_registration`) |
| 84 | 4.5% | `__psynch_cvwait` ← `PtQuiesce::park` ← `enter_hvpatch_guest_or_service_invalidation` |
| 68 | 3.7% | `retire_detached_task_only_engine_with_root_proof` … ← `retire_detached_address_space_with` |
| 54 | 2.9% | `poll` ← `CarrierWaitService::recheck_registration` ← `enroll` |
| 52 | 2.8% | `ReceiptLog::record` (pool-wide mutex, VecDeque window) |
| 44 | 2.4% | `run_state::claim_record` ← `publish_task_thread` ← `publish_thread_run_state` |
| 37 | 2.0% | `__psynch_cvbroad` ← `PtPauseGuard` drop ← `with_mm_mutation_authority` |
| 35 | 1.9% | `write` ← `run_executor_loop+0x2a2c` (the inlined nudge at the end of `enroll`) |
| 31 | 1.7% | `close` ← `resume_continuation` (`ContinuationDetail` drops its pinned fd dups) |

The return offsets were checked by disassembly. `+0x2a14` is
`bl CarrierWaitService::prepare_registration` and `+0x2a28` is
`bl CarrierWaitService::enroll`. The leaf `write` stub has no frame, so the
callee itself is skipped in the unwind.

## Scaling: per exit, per thread, or per quantum?

| | node (ev-4) | go | cpython |
|---|---|---|---|
| guest syscall exits (class 3) | 263000 | 75759 | 83379 |
| executor claims = load/save/switch | 15193 | 12524 | 4429 |
| blocked-continuation settlements | 12258 | 8715 | 3172 |
| guest threads that ran (distinct serials) | 318 | 408 | 827 |
| fork quiesces / ASID invalidations | 48 / 61 | 72 / 72 | 78 / 79 |
| corrected bucket per syscall exit | 6.2 µs | 11.9 µs | 12.9 µs |
| corrected bucket per thread | 5.1 ms | 2.2 ms | 1.3 ms |
| real scheduling per claim | ~69 µs | ~46 µs | ~93 µs (with idle `park_spare`); 63 µs without |
| C per blocked continuation | ~23 µs | ~16 µs | ~22 µs |
| E per claim | ~8 µs | ~8 µs | ~7 µs |
| D per ASID invalidation (per process) | ~1.7 ms | ~1.4 ms | ~4.7 ms |

- **Not per exit.** Cost per exit varies 2x, and node, the most exit-dense
  workload, is cheapest per exit. A syscall served inside the quantum pays no
  scheduling.
- **Not per thread.** Cost per thread varies 4x, in the opposite order.
- **Per blocked quantum.** C, E and the bookkeeping buckets have a near-constant
  cost per claim or per blocked continuation across all three workloads. Every
  guest wait that gives up its executor pays settle → enroll → park → wake →
  claim → load: about 45–70 µs of carrier CPU. Node issues the most blocking
  waits (26771 `epoll_pwait` forwarded in the campaign, about 12–15k blocking).
- **Lifecycle work scales per process and fork, times sibling threads.** That
  covers D, N and B (node parks 2052 times for 48 forks, about 43 parks per
  fork). This is fork/exit cost, not scheduling.

Exact host syscalls per blocked continuation (node `schdiag-ev-4`, 12258
blocks):

| call site | count | per block |
|---|---|---|
| `write` nudge in `prepare_registration` | 12258 | 1.00 |
| `write` nudge at the end of `enroll` | 12258 | 1.00 |
| `poll` recheck in `enroll` | 7648 | 0.62 |
| `close` of `ContinuationDetail` fd dups (plus the matching `fcntl(F_DUPFD_CLOEXEC)` in `own_wait_fds`) | 7790 | 0.64 |
| `write` from producer subscriptions (`install_producer_subscriptions` closure) | 5807 | 0.47 |
| `write` from the enroll recheck that published an event | 1693 | 0.14 |
| reactor `poll` cycles (reactor thread) | 21841 | 1.78 |

go and cpython show exactly 2.00 nudges per block (8715/8715 and 3172/3172).

## Avoidable work versus the inherent cost of the HVF model

**Inherent, given one HVF vCPU multiplexing many guest tasks:**

- E, the register save/restore on a task switch, at about 7–8 µs per claim.
  Every `hv_vcpu_get/set_*` call takes Hypervisor.framework's
  `os_unfair_lock` and an owner-thread check. 72% of node loads switch to a
  different thread. The 28% that reload the same thread already take the
  `reaffirm_resident_task_state_on_live_executor` path.
- I, executors parking and unparking on the run-queue condvar. This is the
  price of a bounded pool that releases leases on guest waits (AGENTS:
  "a guest wait releases execution capacity").
- A wake mechanism per blocked wait. The reactor and the kick are necessary in
  some form.

**Avoidable:**

- **Doubled reactor nudges and redundant per-wait host syscalls in the wait
  service (C).** Each block issues 2 nudges, plus 0.6 recheck `poll`, plus
  0.64 `fcntl` dup and `close`, and wakes the reactor about 1.8 times.
- **The settle scan in A.** `GuestGrantLedger::settle_ready` locks all 256
  `EL1_STACK_SLOTS` mutexes on every mm-mutating fault boundary, even when
  nothing is pending. With the lane off, nothing is ever pending.
  `GuestGrantLedger` already keeps an `occupied` counter "so a boundary with
  nothing pending skips the scan". `guest_grants_awaiting_settlement()` reads
  it, but neither `settle_ready` nor `settle_guest_frame_grants` checks it
  (still true on `main` at 3ab5c9956). The leaf
  `settle_guest_frame_grants+0x10c` sits in that loop's inlined
  `RawMutex::lock`.
- **Per-quantum bookkeeping (F, G, J).** This covers the pool-wide
  `ReceiptLog` mutex, SipHash `ThreadRegistry` updates, and building and
  dropping `KernelContext` for a job-control check on every quantum.
- **Misfiled lifecycle costs (D, N, B).** These are real costs, but they
  belong to fork and exit work. cpython's teardown is 4.7 ms per process
  (`AliasClassIndex::remove`, `stage_retirement`, receipt authentication) and
  is worth its own investigation.

## Levers (estimates in % of carrier CPU, lane off)

1. **Make the wait-service enrollment one coalesced nudge, with no per-wait
   fd dup.** Nudge once after `enroll`, only when the registration needs the
   reactor (it has host fds or a deadline), and coalesce with an atomic
   nudge-pending flag that the reactor clears on drain. Pin waited fds through
   the existing `OpenDescription` `Arc` instead of a `F_DUPFD_CLOEXEC` dup per
   wait. Skip the enroll-time host `poll` when the producer generations
   captured at prepare time are unchanged. This would remove about 60% of C:
   **~1.5% node, ~1.0% go, ~0.5% cpython** (9%, 9% and 3% of the profile's
   bucket), plus a share of the reactor-thread wakeups.
2. **Skip the empty settle scan.** Return early from
   `settle_guest_frame_grants`/`settle_ready` when `occupied == 0`. When it is
   not zero, index pending grants by `mm_key` instead of locking 256 slots.
   That removes most of A's `settle_guest_frame_grants` leaf: **~1.1–1.2% node**
   (122 + 15 samples, about 7% of the bucket), ~0.2% go and cpython. Lane on
   has the same shape with A at 461 samples, so it may be worth more there. The
   change is small and local, and it is the cheapest lever.
3. **Strip diagnostic and redundant bookkeeping from each quantum.** Make
   `ReceiptLog` per executor or a lock-free ring, since only the debug table
   reads it. Make `claim_record`/`set_thread_state` keyed without SipHash. Gate
   `suspend_for_job_control`'s `KernelContext` build on a stop-pending bit.
   This would remove most of F, G and J: **~1.4% node**, ~0.4% go, ~0.3%
   cpython.

Together the three levers remove about 4% of node carrier CPU, roughly a
quarter of what the profile called "scheduling". That is not enough by itself
to bring node's 2.16x under 2x. **Fix the profile's classifier first** (the
stab alias and the root-frame catch-all) so later rankings see A, D, N and B as
fault and lifecycle cost rather than scheduling.

**Aside, outside this question.** The node shard forwards 48,494
`clock_gettime` calls to the host (the largest forwarded row; see the campaign
exit attribution). That points to a clock id the vDSO does not serve, and is
worth a separate look.
