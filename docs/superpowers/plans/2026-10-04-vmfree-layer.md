# VM-free concurrent scenario testing

Design plus a separate, non-product prototype; no runtime capability activated.
Base `b148d69eb1135f55ab915ae6dff36c2d6c97576d`, x86_64 Linux Willow VM.
Paths below are repository-relative, anchors at that base unless qualified.
Read [contracts](../../conformance-contracts.md), the
[controller](2026-09-26-el1-completion.md),
[N2 creation plan](2026-10-04-el1-n2-creation.md) and
[kernel semantics guide](../../conformance-testing.md#kernel-semantics-suite).

**Goal:** discover ordering bugs with deterministic scheduling of concurrent
test scenarios, retain failing schedules, and replay them as regression tests.
Use the real kernel scheduler, admission transactions and owned continuations;
extend the same scenario vocabulary to the common `carrick-el1` personality.
Semantic results and deterministic work budgets are separate required assertions.
VM-free tests never establish hardware, guest instructions or runtime ratios.

**Decision:** seeded scenario exploration first; bounded Loom models for selected
atomic algorithms afterward. No source-copy harness in the implementation.
The director confirmed this choice and allowed OUT_DIR instrumentation **only
for the prototype**. No signed/HVF test or Docker runs belong to this task.

Snapshots inspected without merging: `work/fork-fdpin` = `c0b5cd424`;
`work/kvm-carrier-design` = `9f1294afe` (its plan's anchors are at `00cd94614`);
`origin/work/n1` = `8d5df2d2e`. Requested remote fork/carrier refs are absent
in this clone; use these local refs, read carrier plan via `git show`, and
refresh all collision lists at handoff. Cloudmac `work/setid-churn` is a brief
supplied by the owner, not source inspected here.

## 1. Current layer and four gaps

| Surface / anchor | Models now / limit |
| --- | --- |
| `crates/carrick-kernel-example/src/operand.rs:177`, `:229`, `:242`, `:313`; `src/sys.rs:1` | Six canonical syscall operands, literal/slot/last-child, nested buffer relocations, saved returns/output words, expected return/errno/death. `Step::Sys` followed by `ChildMarker` supplies the child's program; persistent buffers express shared futex words. |
| `src/scripted.rs:156`, `:165`, `:198`, `:1079`, `:1160` (same crate) | Boot real Kernel/dispatcher, activate its file authority, reserve/prepare/commit fork and thread clones through public operations. Fork copies memory/slots and gets a new dispatcher/MM; threads share memory/dispatcher/futex table and hold exact thread contexts. No host fork. |
| `src/memory.rs:7`, `:13`; `src/process.rs:88`, `:126`, `:206`, `:291` | Bounded 1 MiB Vec-backed guest memory; own CarrierProcess/MmBackend/stage-1 projection implementations, ASID/generation bindings. No real page tables, guest instructions, physical inventory or foreign-MM user-copy endpoint. |
| `src/driver.rs:228`, `:376`, `:394`, `:430`, `:520` | Real dispatch, captured generation, owned BlockedContinuation, CarrierWaitService enrollment/event/resume and common completion folding. Exact liveness cancels exit_group siblings. Futex completion can avoid redispatch; some readiness outcomes legitimately redispatch once. Default signals/timers work; handler execution/stop are refused at `:165`/`:171`. |
| `src/report.rs:38`, `:85`; `src/scripted.rs:169`, `:256`; `src/contracts.rs:23`, `:283`, `:804`, `:939` | Graph-scoped WorkScope, completions/output bytes/deaths/task counts, per-pid/tid labeled dispatches. ContractObservations bind semantic assertions, fixture/revision/scale/completeness and snapshots to registry evaluation in `tests/contracts.rs:1`. Futex, fd-copy, fork-image admission and scheduler progress/cost families already exist. |
| **Gap 1:** `src/scripted.rs:1151`, `:1210`; `src/driver.rs:119`, `:430` | Root executes on caller; each new task spawns another host thread; each blocked task retains its driver thread. Kernel leases exist, but this runner neither bounds workers nor relinquishes a worker to another task. Pool exhaustion, wait lease release and stranded-worker tests cannot be inferred from its passes. `tests/scheduler_handoff.rs:288` already uses two-process kernel scheduler authorities directly; reuse it. |
| **Gap 2:** `src/driver.rs:319`, `:546`; `src/scripted.rs:1099`, `:1120`, `:1139` | Rejects vfork in clone outcome validation; catch-all refuses Exec. Fork always allocates/copied memory, discards optional parent-wait handle: merely removing rejection would violate vfork. No successor image/exec state machine. |
| **Gap 3:** `src/operand.rs:147`, `:315`; `src/scripted.rs:443`, `:531`; `src/driver.rs:367` | Manual ScriptCheckpoint and await_parked, OS threads and yield_now. No seeded coordinator, logical event order, schedule trace or replay. Checkpoints are useful existing witnesses, not general exploration. |
| **Gap 4:** `crates/carrick-el1/src/personality/dispatch.rs:60`, `:94`, `:186`, `:259`; `crates/carrick-el1/tests/n2_creation_baseline.rs:11` | Native region-based tests exercise the real router; ordinary host entry returns Forward. Baseline creation test lacks admitted lifecycle/IPC state; it proves forwarding attribution, not composed execution. Harness calls host dispatcher instead. Current ThreadCpu/UserWord (`src/sched.rs:20`, `:54`) still expose ARM frames/root/interrupt details. |

Budgets are exact/upper/affine, evaluated at at least three scale points.
`conformance-contracts/contracts/fork-filetable.toml:23` requires one task
admission and `copy_bytes <= 96 + 32*n`; futex contention requires exact wake
cardinality, one enrollment per blocking episode and zero parked redispatch;
scheduler contracts bound queue work, not elapsed time. WorkMetric taxonomy is
`crates/carrick-observability/src/work_meter.rs:19`. Metrics require the
`conformance-metrics` feature: an ordinary disabled harness snapshot becomes an
empty default (`scripted.rs:258`), which is **not** a measured zero. New runners
require present counters and reject disabled/unknown/dropped/overflowed evidence.
Scheduling decisions and logical ticks are test diagnostics, not guest work.

Applicable existing IDs: `kernel.fork.filetable`, `kernel.futex.contention`,
`kernel.scheduler.runnable-progress`, `kernel.scheduler.host-wait-handoff`,
`kernel.el1.thread-lifecycle`, `kernel.el1.ipc-fd-authority`,
`kernel.el1.ipc-lifecycle`, `kernel.el1.ipc-two-process`. Register the proposed
`kernel.fd.wait-admission-retirement` and missing creation-admission/setid
contracts red-first; the fix commit names the fd contract but does not register
a descriptor. N2's creation-native-path remains its owner's contract. Linux
authority is fork/clone/close/exit_group/execve/vfork/setresuid/futex man-pages
and committed oracle outputs; internal contention must not invent guest EAGAIN.

## 2. Scheduling, replay and atomic checks

Add a graph-owned coordinator and **one** typed `schedule_point!` hook API in
the original sources. Hooks exist only in explicitly selected test builds,
compiled out of release/product closure; verify that mechanically. No ambient
process-global seed/env mutation, raw host pid, function-address identity or
per-test named barrier. Proposed opt-in:

```rust,ignore
ScriptedBackend::new()
    .with_schedule(Schedule::explore(seed).max_transitions(10_000))
    .run_root(scenario)?;
// Schedule::replay(receipt) validates every decision and consumes the suffix.
```

Coordinator owns actor states Runnable/Waiting/Retired, exact TaskKey/ThreadKey
and execution generation; service actors and logical timers are explicit.
Register a child before publication makes it selectable. Sort eligible actors
by stable scenario identity; a versioned seeded generator chooses transitions.
Every wait transfers control to another eligible actor; wake marks the exact
generation selectable. Clock advances only to the next admitted deadline when
no runnable actor exists. External readiness is an injected event transcript;
real host-I/O tests stay in the existing unscheduled lane until their endpoint
is controllable. Never hold a coordinator permit while blocking in an OS lock
or reactor. Fixed wall watchdog detects harness failure; guest deadlines and
progress assertions use logical time/transition work, without polling.

| Schedule point in real code | Purpose / constraints |
| --- | --- |
| `kernel/operations/thread.rs:290`, `thread_ledger.rs:270`, `:277`; `kernel/exec.rs:246`, `:462` under `crates/carrick-kernel/src/` | Before reservation, birth record, settled publication, first-entry, exec admission/commit and cancellation. A test creation actor may drive public prepared operations directly: the harness's dispatcher lock currently hides some birth/update races. Never copy transaction bodies. |
| `kernel/operations/identity.rs:218`; `kernel/operations.rs:831` | Reservation epoch capture, admission attempt, owned admission wait and publication; credential/fork semantics remain the existing owner. Hook a suspension after unlocking, not a wait inside the registry guard. |
| Harness `driver.rs:228`, `:270`, `:386`, `:394`, `:405`; `scripted.rs:1236` | Before lock acquisition/after release; after blocking admission, before continuation consumption, enroll/check/park and terminal fd retirement. These expose the demonstrated fd-pin window and wake-before-enroll race. |
| Kernel `continuation/wait_service.rs:1172`, `:1680`, `:1725`; `scheduler.rs:4604`, `:4682` | Enrollment, ready publication, event consumption, lease settlement; transport publication does not confer task liveness. Retain prefix and endpoint lifetime through cancellation. |
| `crates/carrick-sched-core/src/object_wait.rs:249`, `:407`, `:426`; fd-core `src/lib.rs:1436`, `:1585` | Check/enroll epoch, claim/cancel/reuse and pin/unpin boundaries. Gate lock attempts **before** acquisition and wake effects **after** unlock; do not suspend a lock holder merely to impose a test order. Atomic internals use the separate model below. |

Lock hooks must identify the authority/incarnation and failed acquisition as
a dependency; a test synchronization adapter suspends that actor and receives
the real unlock notification. It must not retry try_lock in a polling loop.
Start with safe unlocked seams, then add this adapter in landing 2. An all-waiting
state with no admitted completion/deadline reports a dependency graph and owned
continuations. Runnable spinning exhausts the deterministic transition budget.
Bound exploration by seeds, actors and transitions; never retry a failed seed
for a green verdict. Shrink actor/decision prefixes only while preserving the
same semantic/work failure and runnable validity, then commit the regression.

Receipt: schema/PRNG version, seed, source and fixture hashes, backend, scale,
logical events, point ID + visit ordinal + exact authority, runnable set and
selected actor, result and WorkSnapshot. Replay refuses mismatched fixture,
point, generation, runnable set or unconsumed trace. An intentional red/green
revision comparison retains both source identities and explicitly permits
only that pair; ordinary replay cannot silently accept source drift. Different
semantic venues reuse the scenario and assertions, not necessarily the same
internal schedule. Each venue records its own trace.

### Tool choice and checked licenses

Checked upstream license text and documentation on 2026-10-04:

| Approach | Evidence / recommendation |
| --- | --- |
| Seeded scenario coordinator | Real fd-pin prototype below reproduces an ownership-ordering defect without replacing kernel synchronization types. Scales to composed creation and bounded workers. Choose as the main runner; sampled schedules do not prove all executions or weak-memory ordering. |
| [Loom 0.7.2](https://docs.rs/loom/0.7.2/loom/), [MIT license](https://github.com/tokio-rs/loom/blob/master/LICENSE) | Models instrumented atomics/synchronization and memory-order alternatives; ordinary core/std atomics are invisible. Requires test-only substitutions; large models grow combinatorially and relaxed-memory coverage has documented limits. Use bounded production-algorithm models for 2–3 actors and 1–2 records, not the whole kernel/VFS/reactor. |
| [Shuttle](https://docs.rs/shuttle/latest/shuttle/), [Apache-2.0 license](https://github.com/awslabs/shuttle/blob/main/LICENSE) | Offers randomized scheduling and replay through substituted primitives; does not replace weak-memory checking. Compatible alternative for small synchronization tests, but replacing all parking_lot/reactor operations adds no demonstrated advantage over the proposed graph coordinator. Do not add both dependencies initially. |

Carrick is Apache-2.0 OR MIT (`Cargo.toml:28`); these checked licenses introduce
no GPL source. Pin chosen tool/dependency versions and check their full license
closure with the existing deny gate before adding them; no blanket transitive
license claim is made by inspecting only the top-level license.

Concrete model scope: sched-core object epoch/enrollment vs notify/cancel/reuse
(`object_wait.rs:118`, `:249`, `:407`), fd-core table sequence vs pin/last unpin
(`lib.rs:456`, `:470`, `:1436`, `:1585`). Substitute atomics in those **same**
algorithms under a test configuration; const/shared-ABI layout and no_std
production builds retain core atomics. Do not model a rewritten pseudocode twin.
Pipe-core contains **no atomics** (`src/lib.rs:9`, `:16`): Pipe uses exclusive
BorrowMut/venue locks. Keep its byte/prefix/EOF tests as ordinary state-machine
tests; model the venue's atomic lock/wake wrapper in
`carrick-el1-abi/src/ipc.rs:399` plus sched-core, not an invented pipe atomic.
A weakened ordering mutation must fail each atomic witness before acceptance.

### Prototype: one previously fixed ordering bug

Separate prototype commit contains
[`prototypes/vmfree-scheduler`](../../../prototypes/vmfree-scheduler/README.md).
It compiles the actual public-kernel harness, inserting generic scheduling calls
in OUT_DIR only; no tracked product changes or synthetic buggy/fixed switch.
Script: pipe → sibling read → fork second live process → both exit_group.
No checkpoint, await_parked, sleep or bespoke barrier. Discovery starting at
seed 0 finds **seed 5**; replay has 16 decisions. Child registration is ordered
before OS spawn, so eligibility does not depend on thread arrival.

On unchanged kernel `b148d69eb`, the focused test and replay fail with pid1/tid2
`Unsupported(continuation build failed: failed to pin an exact fd description)`.
On `c0b5cd424`, same seed/trace passes: 3 tasks, 6 dispatches, one read admission,
zero redispatch/park, no read completion after group retirement. Fixed branch's
manual checkpoint helpers are never invoked. Source/trace identities, exact
commands and limits are in the prototype README. This proves feasibility for
one real defect; it is not a second re-derived defect or general exploration
acceptance. The prototype rejects external reactor waits, uses global raw-tid
state and does not model internal locks or memory reordering. Delete it in M1.

## 3. Faithful executor capacity

| Reuse / extraction anchor | Boundary |
| --- | --- |
| Kernel `scheduler.rs:2034`, `:3197`, `:3587`, `:4604`, `:4682` | SubmissionAuthority, RunningTask/ThreadExecutionLease, bound/spare registration, blocked/owned-continuation settlement. Reuse now; a scripted quantum returns owned state instead of parking a worker. |
| Kernel `continuation.rs:209`; `continuation/wait_service.rs:1031` | Capture/result/cancellation and wait enrollment/reactor already portable. Keep real operation tokens, endpoint guards, partial byte offsets and generations; never restart an admitted write from zero. |
| Runtime `vcpu_loop/executor/pool.rs:47`, `:91`, `:104`, `:112`, `:786`, `:929`; `executor.rs:46`, `:1324` | Real config/count policy (one bound worker per guest CPU; default 2*CPU spares, ceiling/reserve), receipt/lifecycle and worker claim/load/run/save/settle loop. Extract generic policy **once**, remove displaced bodies, use from runtime and harness. No task-count-sized worker pool. |
| Runtime `executor/backend.rs:432`, `:438`; `binding.rs:26`, `:33`, `:310`, `:435`, `:516`; `settlement.rs:19`, `:66`, `:379`; `residency.rs:38` | Persistent factory/executor/task binding/submission, host-wait token, resolver, settlement and residency are useful seams but still reference TrapError, HVPatch ASID/kick/retirement and ABI zone materialization. Extract neutral custody/error/retirement traits with typed receipts; hardware audit and CPU materialization stay in the backend. Not directly importable portable APIs today. |
| Runtime `continuation/quantum.rs:49`, `:674`, `:732`; `vcpu_loop/continuation.rs:1` | Task binding/quantum plus logical job completion/process drain contain useful completion policy but intentionally name HVPatch. Extract only shared completion/settlement needed by actual callers; leave MM/root ownership with N1. No copied fake runtime loop. |

Proposed destination: new host-portable `carrick-executor-core` (name confirmed
at handoff), depending on existing kernel/HAL, never a VMM. Runtime becomes the
hardware adapter; kernel-example uses ScriptedExecutor and a resumable ScriptTask
(PC, slots, memory, pending operation/prefix). This preserves the harness's
no-runtime/VMM dependency gate. Scheduler owns leases; the test coordinator
chooses when a quantum/service actor executes, not which task is legally owned.
Receipts count worker occupied-by-guest-wait == 0, lease acquire/release,
single claim/load/save/settle, exact completion, live workers and teardown.

Run default pool at 1/8/32 guest CPUs with more runnable/waiting tasks than bound
plus spare workers; one runnable reader must unblock 32 partial writers while
all other capacity is occupied. Also test long wait **with spare capacity**,
fork admission before child lease wait, exec/exit cancellation, two independent
same-VA MMs, stolen work/affinity and stopped-target owner service. Larger
pools, reduced concurrency, synthetic short writes and blocking workers cannot
close these contracts. Use real host-wait-handoff tests (`scheduler_handoff.rs`)
as the initial kernel-only fixtures, then rerun through the extracted worker.

**N1 collision fence:** inspected diff from `fda4e0350` to `8d5df2d2e` touches
runtime `vcpu_loop/{binding,lifecycle,memory,quiesce,reservations,signal,zone}.rs`,
`executor/backend.rs`, `hvpatch/stage1_mm.rs`, runtime lib; kernel scheduler,
MM occupancy/dispatch and EL1 owner/router/ABI; sched-core
`{lib,object_wait,spaces,completion_queue}.rs`. Pool/worker/quantum files are
not in that frozen diff, but extraction crosses its backend and retirement
authorities. **All runtime extraction waits for N1's actual landing**, as does
EL1 owner wiring. File-disjoint kernel-only fixture design may proceed now.

## 4. vfork, exec and composed creation scenarios

Extend driver with typed scripted image/child programs, not a successful-exec
return value. Vfork consumes ClonePlan sharing mode, shares AddressSpace and
TaskMemory with the child and retains VforkParentWait (`kernel/operations.rs:187`,
`:241`, `:907`). Parent suspends without retaining a worker. Child exit or
successful successor publication releases it exactly once; failed exec leaves
it suspended. Fork continues to copy, CLONE_FILES shares slots, OFDs share
cursor, successor CLOEXEC affects only its unshared table.

Exec drives real prepare/no-return/commit and scheduler publication
(`kernel/exec.rs:96`, `:173`, `:207`, `:246`, `:462`). Bind new memory/ASID,
execution generation, file and signal resources, then replace the remaining
script with the registered image program. Before no-return failure preserves
old image/resources; afterward failure is terminal. Inject failure at each
existing prepared boundary; never emulate transaction policy in the harness.
Use N1's landed successor/retirement and shared cursor authority, N2 E's real
loader when available. Script execution proves publication/rollback, not ELF
instruction execution, signal frames, TLBI or I-cache behavior.

One `CreationScenario` under kernel-example supplies operations, image handles,
injected events/failures, scales 1/8/32, **two live processes** with equal VAs,
typed observations and contract assertions. Reuse across N2:

| N2 landing | Driver witness |
| --- | --- |
| A | Composed fork/pipe/wait + clone/join + vfork/exec baseline; per-operation admitted/served/forwarded work, no attribution from stale syscall numbers. |
| B | Full/partial writer suspended, close/reuse, fork/exec CLOEXEC, exact payload/EOF/EPIPE and wake-before-enroll; same description/cursor once. |
| C | Immediate birth signal, masked SIGCHLD, timer/readiness/interruption and reused identity; handler/frame/restart execution stays signed. |
| D | Birth vs exec/exit admission, UID limit vs internal contention, TID commit rollback, zombie/wait/reap and exhausted default pool. |
| E | Failed image prepare, predecessor preservation, successor publish, vfork release-once and shared cursor copy/commit cancellation. |

## 5. Test architecture backend for the common kernel

For common personality, add test-only `KernelArch` adapter after carrier **M1
defines** the seam and **M2 wires** a normalized entry to the real common router
(carrier plan `:114`, `:292`, `:315`). A trait declaration alone is insufficient.
Retain sealed production arch implementations; expose a narrowly gated test
adapter factory inside guest-arch, not an unrestricted production escape.

- Entry: typed canonical request/native ABI and synthetic saved context,
  complete register/TLS/restart ownership; no fake ARM frame for x86.
- MM/user-copy: bounded per-owner arenas, issued root/backing generations,
  explicit shared edges, access/protection/COW and injected fault/rollback.
  Consume N1's owner/permits; test backing never grants semantic authority.
- Interrupts: virtual clock/timer/wake queue, mask/ack and park events, exact
  CPU/record generation. No privileged instructions or host sleeps.
- Crossings: owned byte/readiness/capacity/terminal/control requests and
  deterministic completions; forbid generic host semantic syscall fallback.

Use existing ThreadCpu/UserWord/MemoryValidator/UserCopy seams
(`carrick-el1/src/sched.rs:20`, `:54`; `file.rs:138`, `:229`) behind KernelArch.
Admit real lifecycle/IPC/reservation storage and call common entry, not the
host-only Forward stub. Missing routes are UnsupportedLayer with a failing
capability binding; never silently execute the host dispatcher to make them
green. Hardware adapters still require their own executing tests.

## 6. Six reviewable landings

These fences authorize **future implementation only**. Each landing registers
its missing contract/bindings, preserves original red provenance and collects
semantic + complete structural observations; no ignored/inverted reds.

### M1 — scenario scheduling and strict replay

- **Fence:** new test coordinator crate/module, kernel-example schedule/report
  plumbing, typed hooks at unlocked driver/birth/terminal seams; product
  release closure assertion and recipe. Remove prototype instrumentation.
- **Red:** retained seed-5 fd-pin scenario on `b148d69eb`; wrong runnable-set,
  generation/fixture and trailing-trace mutation controls fail replay. Existing
  unscheduled semantics continue to run. This is real red #1, already shown.
- **Accept:** `cargo test -p carrick-kernel-example --test schedule_replay`;
  `just test-kernel-semantics`; `just check-layering`; common gates below.
- **Waits:** no N1 runtime work. Green fd ownership assertion waits for
  `work/fork-fdpin`; do not land an expected Unsupported as a conformant result.

### M2 — admission/wake regression scenarios and small atomic models

- **Fence:** generic admission/lock/wake hooks in kernel operations/ledger and
  wait service; new kernel-example `admission_interleavings.rs`; bounded Loom
  config/tests in sched/fd cores and existing IPC wrapper, contracts/lockfile.
  No semantic fix owned by another branch.
- **Red #2:** retrieve exact pre-fix source of Cloudmac `work/setid-churn`;
  seed a sibling birth reservation against valid setresuid, release admission
  as a scheduler event: old guest EAGAIN must fail, fixed operation completes
  once without busy redispatch. This brief is not yet a source-qualified red.
  Also re-derive exec-close vs late sibling first-entry, enroll/wake lost-wake
  and claim/reuse queue cleanup cases (`sched-core/src/tests.rs:1722`, `:2195`)
  using shared hooks rather than the old bespoke pauses. Never invent an old
  implementation to claim historical reproduction.
- **Budgets:** one birth/publication, no credential update redispatch while
  admitted waiting, no stale entry/completion; wake work scales only with
  affected waiters at 1/8/32. Reduced ordering/epoch mutations fail Loom models.
- **Accept:** `cargo test -p carrick-kernel-example --test admission_interleavings`;
  `cargo test -p carrick-sched-core -p carrick-fd-core -p carrick-pipe-core`;
  dedicated bounded Loom recipe added here; `just test-kernel`; common gates.
- **Waits:** setid-churn fix/source handoff; sched-core/EL1-ABI edits wait for
  N1 and lifecycle Phase B. Kernel-only hook preparation can proceed after M1.

### M3 — real worker/lease policy with scripted quanta

- **Fence:** extract executor policy/neutral traits into executor-core once;
  runtime worker/pool/binding/backend/settlement/residency/quantum adapters,
  harness resumable driver and `executor_capacity.rs`; contracts. No MM policy.
- **Red:** current one-thread-per-task runner cannot satisfy bounded worker
  occupancy (a capability refusal alone is not the semantic red). With real
  pre-correction worker policy, exhaust default capacity with 32 partial
  writers and runnable reader; assert no stranded reader, prefix exactly once,
  zero workers held by guest waits. Disable lease release as a negative
  control. Long wait with spare capacity must release too; retain 1/8/32 scales.
- **Accept:** `cargo test -p carrick-executor-core`; `cargo test -p carrick-kernel-example --test executor_capacity`;
  existing scheduler_handoff suite; `just test-kernel`; runtime host tests and
  backend signed integration on its capable lane, common gates.
- **Waits:** N1 landed retirement/backend interfaces; lifecycle Phase B;
  coordinate carrier pool extraction so both lanes consume one implementation.

### M4 — vfork/exec and composed creation programs

- **Fence:** kernel-example operand/image registry/process/driver and
  `creation_scenarios.rs`, new rollback/creation tests and contract bindings;
  consume public kernel APIs without changing their semantics.
- **Red:** old vfork/exec refusal is a harness capability red only; real
  semantic controls omit shared-MM release, wake parent before successor
  runnable, omit CLOEXEC unshare or rollback a successor into old identity.
  Each must fail the two-live-process composition. Preserve M2 admission reds.
- **Accept:** `cargo test -p carrick-kernel-example --test creation_scenarios`;
  `just test-kernel-semantics`; complete exact admissions, release-once,
  prefix/cursor and zero parked redispatch at 1/8/32; common gates.
- **Waits:** M1/M3 and N1 exec/cursor handoff. N2 A uses the baseline driver;
  B–E extend bindings in their landings, not parallel transaction owners.

### M5 — test architecture drives the common entry

- **Fence:** guest-arch gated test adapter, new harness arch backend/arena and
  `common_entry.rs`, common test feature/dependency wiring only. No new policy.
- **Red:** two same-VA MMs with different bytes; wrong root/context/TLS/wake
  generation mutation fails. Admitted robust-list route mutates real common
  state; fallthrough Forward cannot count as served. Unimplemented creation
  routes remain explicitly unsupported until N2, not successful fallback.
- **Accept:** `cargo test -p carrick-guest-arch`; `cargo test -p carrick-el1`;
  `cargo test -p carrick-kernel-example --test common_entry`; layering/release
  adapter exclusion and common gates.
- **Waits:** carrier M1 **and M2** normalized common entry; narrow N1 export
  handoff and landed MM owner for memory scenarios. No KVM/HVF needed here.

### M6 — common creation regressions and permanent contract bindings

- **Fence:** composed scenario bindings in kernel-example and EL1 tests,
  contract descriptors/inventory, suite recipes/docs/CI; no product algorithms.
- **Red:** same Linux assertions and work slopes through host graph and common
  personality for N2 A–E; fd-pin/held-birth ordering regressions plus
  wake/enroll/cancel/reuse and partial-write pool exhaustion. Each binding has
  a lane-specific retained schedule and mutation-sensitive failure; unsupported
  route or unknown budget blocks that binding, not converted to zero/skip.
- **Accept:** shared creation test recipe added here; `just test-kernel`;
  `cargo test -p carrick-el1 -p carrick-sched-core -p carrick-fd-core -p carrick-pipe-core`;
  complete observations at 1/8/32, common gates and N2's executing gates.
- **Waits:** M2–M5 and N2 B–E/lifecycle Phase B actual landings. N2 A may use
  earlier host baseline; no cycle requiring N2 E before the baseline exists.

Common future host gates: `just fmt-check`, `just test`, `just ci`, `just accept`
on a capable host/profile, layering and license gates. Linux-portable accept
profile is in flight on `work/accept-linux`; use it after landing and retain its
receipt, never pretend current Mac-only accept ran here. Product-connected
behavior also requires signed embed, conformance-probes, smoke/full on the
exact artifact, followed by serialized same-image native oracle/timing evidence
owned by the director. Test-layer greens cannot waive N1/N2 or hardware gates.

## 7. Risks and recommendations

| Risk / decision | Recommendation |
| --- | --- |
| Deterministic gate hides real races | Explore at authority boundaries, retain unscheduled parallel tests and atomic models. A gate's mutex makes weak memory invisible; never advertise exhaustive correctness. |
| Lock holder or external wait pins coordinator | Schedule before acquisition/after unlock, model wait dependencies explicitly. Reject uncontrollable endpoints until supported; use fixed diagnostic watchdog, no retry/polling. |
| Duplicate harness/semantic paths | Prototype source instrumentation is temporary. One real hook API and one extracted worker/transaction implementation, remove old body; scripted backend supplies inputs, not Linux answers. |
| N1/Phase B move interfaces | Freeze hashes for evidence, refresh source/collision list at landing. Defer runtime/MM/ABI extraction; tests can be prepared in new files now. |
| Trace drifts or memory grows with churn | Stable typed point/authority keys and fixture/schema hashes, explicit mismatch, bounded decisions with overflow failure. A stored failing schedule is a regression, not a lucky seed rerun. |
| WorkScope missing features | Require present complete metrics; release timing remains uninstrumented. Do not count scheduling overhead as guest work or empty snapshots as zeros. |
| Sealed KernelArch cannot be implemented externally | Gated adapter factory inside guest-arch; preserve production sealing and deny its feature in product closure. Wait for real common-entry wiring, not only trait declarations. |
| Second historical red lacks source here | Recommend held-birth setid case; acquire old/fixed hashes from its owner before M2. Until then label handoff, keep it an acceptance dependency rather than fabricate reproduction. |
| Scope expands to hardware emulation | Model ownership/context/copy/fault events needed by scenarios only. Page-table hardware, privileged entry, handler execution and I-cache/TLBI retain hardware bindings. |

## Planning verification

Exemption: this plan and `prototypes/vmfree-scheduler/` are outside the product
execution path; no Linux semantic or production work expectation changed.
Relevant contract families are fd lifetime, creation admission, scheduler/wait,
EL1 lifecycle/IPC and MM isolation. Only fd-pin has new actual red/green evidence.

Prototype verification is recorded in its README. Seed 5 and its stored replay
fail on the pre-fix kernel and pass on `c0b5cd424`; failing assertions remain
visible rather than ignored. `cargo fmt --manifest-path prototypes/vmfree-scheduler/Cargo.toml -- --check`,
`just fmt-check` and `git diff --check` validate the final sources/docs.
No signed/HVF, Docker, runtime ratio, full kernel suite or `just accept` was
attempted for this docs/prototype task. Future milestone commands are acceptance
requirements, not receipts from this planning VM.
