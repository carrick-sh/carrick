# N2: serve process and thread creation in EL1

Execution plan, 2026-10-04. Planning complete; implementation and signed
acceptance are not claimed. Base: `fda4e0350a86f9099d8dbf8383e01a0607a55928`.
This is N2 in the owner-adopted [N0–N4 order](2026-10-02-el1-native-ownership.md),
not a replacement for N1 or N3. It targets spawn **8.448x** and fork+exec
**6.700x** native arm64 Docker; thread creation is already **1.546x** in the
[report-only impact receipt](../../perf-results/2026-10-02-stage2a-landing-impact.md).
Exit removal is not a predicted CPU speedup. Preserve thread performance and
measure each operation, not just CLI wall time.

Read with the [spec](../specs/2026-09-24-el1-kernel.md#where-the-cost-is-now),
[controller](2026-09-26-el1-completion.md),
[lifecycle plan](2026-09-30-el1-thread-lifecycle.md),
[fd/IPC plan](2026-10-02-el1-step3-fds-ipc.md), and
[conformance contracts](../../conformance-contracts.md). N0–N4 supersedes the
older controller's prohibition on EL1 task ownership and the lifecycle plan's
suggestion to re-register a looser exit ceiling. Neither ceiling changes.

## Evidence and source keys

Paths below are relative to `crates/`; `file:line` anchors refer to the base
above unless marked N1. They name the entry of the relevant code, not a claim
that every invocation causes an exit.

| Key | Path |
| --- | --- |
| dispatch | `carrick-el1/src/personality/dispatch.rs` |
| lifecycle | `carrick-el1/src/personality/lifecycle.rs` |
| fault | `carrick-el1/src/fault.rs` |
| vector | `carrick-mem/src/memory.rs` |
| trap | `carrick-vmm-hvf/src/trap.rs` |
| loop | `carrick-runtime/src/vcpu_loop/mod.rs` |
| binding / quiesce / exec | `carrick-runtime/src/vcpu_loop/{binding,quiesce,exec}.rs` |
| proc | `carrick-kernel/src/dispatch/proc.rs` |
| graph | `carrick-kernel/src/kernel/operations.rs` |
| fd | `carrick-fd-core/src/lib.rs` |

Two external branch snapshots were read without merging them:

- N1: `origin/work/n1` at `8d5df2d2e0f235f9ad82ec2cd59dac13efcfb832`,
  `docs/superpowers/plans/2026-10-02-el1-native-ownership.md`, especially
  lines 819 (owner adapter), 940 (production UserTransfer), 1261 (fork),
  1376 (prepared-copy ruling), 1424 (permit receipt), 1559 (maintenance root).
  These are checkpoint receipts, not whole-N1 acceptance.
- Attribution: `origin/work/step2-prep` at
  `f6e90773fde4bbeb92368c9cd1bcad932ae903d5`,
  `docs/perf-results/2026-10-02-fork-cow-exit-attribution.md`, capture g on
  `0d7d166f6`. The file is not on this base; recover it with
  `git show origin/work/step2-prep:docs/perf-results/2026-10-02-fork-cow-exit-attribution.md`.
  Its raw target logs and signed executable are not available here; the
  receipt says the original executable was subsequently replaced.

**Evidence rule:** all current runtime paths below are **source-read, needs
signed confirmation**, except the explicitly bounded VM-free observations
below. Capture g describes its own artifact, not current main or N1. No source
reading can reconstruct the exact order or multiplicity of asynchronous exits.
The tables enumerate exit-producing routes and internal hops separately.

Separate test commit `8e11c1ed9` adds only
`carrick-el1/tests/n2_creation_baseline.rs`:

- The region-based dispatcher forwards close/pipe2/ppoll/exit_group/
  set_tid_address/setitimer/sched_setaffinity/rt_sigaction/gettid/execve/
  wait4/execveat, preserves arguments, and increments one forward per call.
  It supplies no lifecycle/IPC/scheduler admission; it makes no claim about
  admitted thread clone, memory or futex execution. Three repetitions check
  accounting, not a scaling law.
- First-touch faults at one VA in two live address spaces publish distinct
  exact-MM capacity requests and do **not** increment syscall-forward counts,
  even with stale x8=clone. This uses the real fault router and a refusing COW
  adapter, not physical backing or an executing EL0.
- The current futex decoder accepts private WAIT, rejects shared WAIT and
  futex_waitv. Existing full crate tests exercise admitted lifecycle and
  scheduler protocols; these additions do not duplicate those fixtures.

`cargo test -p carrick-el1 --test n2_creation_baseline` passes (3 tests).
These are green baseline characterizations, **not** red-first proof of an
N2 implementation. Milestone A must add the positive ownership/work contract
and record its behavioral red before implementation.

## 1. The paths today

### Common exit ledger

EL0 SVC enters the vector, calls the EL1 personality, and either returns,
parks/switches in EL1, or exits. `dispatch:264`, `vector:4799`, `vector:5054`
and `vector:5168` distinguish these routes:

| Vehicle | Why it exits; current serving venue |
| --- | --- |
| HVC #2, SVC | `Action::Forward` reaches the syscall mailbox; `trap:8353` decodes it; `loop:1658` invokes host kernel dispatch. A served-with-work return can use this vehicle too, but `loop:1526` settles the already-completed operation, rather than replaying it. Pending signal/work gating at `dispatch:303` can force an otherwise servable call out. |
| HVC #2, non-SVC | Unhandled lower-EL abort or system-register trap; `trap:8177` classifies underlying ESR, `trap:8391` handles an idle syscall mailbox. `fault:784` can request a frame grant or refuse COW/editor admission without any Linux service begin. Host memory/capacity/fault/signal venues then act. |
| HVC #1 | A host-requested EL1 maintenance call completes: ASID/TLBI, descriptor drain, lifecycle/root publication/retirement. `carrick-aarch64/src/engine.rs:1894`, `:1969`, `carrick-el1/src/fault.rs:597`. These can nest under one outer fork/exec service; do not count a function entry as an extra exit. |
| HVC #5 | EL1 has parked the thread and needs host service/handback; `vector:5183`, `carrick-el1/src/sched.rs` idle paths. Host runtime owns the subsequent service/adoption. In-guest WFI itself is not a host exit. |
| HVC #4 | Lower-EL kick IRQ leaves for host control/signal work; `vector:4818`. |
| HVF canceled | Cross-thread cancellation, sometimes absorbed inside EL1 before continuing; `carrick-aarch64/src/engine.rs:2419`. Not an HVC and not necessarily a pause or wait. |
| Exceptional outside g | Direct stage-2 faults (`trap:8013`), metadata supply, trapped register emulation, or HVC #3 fatal current-EL exception (`vector:519`). These must stay in the census; HVC #3 is failure, never budgeted normal work. |

### Fork (AArch64 clone without CLONE_VM)

1. **Libc setup:** masks/altstack and eligible robust setup can be EL1-served
   (`lifecycle:130`); pending work may still cause HVC #2. Stack allocation,
   protection and deallocation pass through admitted anonymous policy
   (`dispatch:332`) or host memory dispatch. Pipes/ppoll and child setup are
   independent SVC/HVC #2 operations, not part of the clone syscall itself.
2. **Clone boundary:** process flags fail the thread-only EL1 predicate
   (`lifecycle:389`), then HVC #2 reaches `proc:3399`. Host flag/permission
   decoding returns `DispatchOutcome::Fork`; `graph:549` (`PreparedFork`)
   and `graph:949` reserve and publish exact child identity/resources.
3. **Admission and memory:** `quiesce:436` closes fork admission and drains
   siblings before building the child; kicks/cancellations/idle handbacks
   may occur. `carrick-vmm-hvf/src/trap/process_plan.rs:344` onward projects
   inherited mappings and arms COW; maintenance can use HVC #1. This is
   replaced by N1's owner fork, not reimplemented by N2.
4. **Resource publication:** graph fork copies or shares FileTable, Sighand,
   credentials and task edges; runtime TID/pidfd copyout and child register
   installation run before child publication (`binding:786`, `graph:949`).
   These host calls are work under clone, not one exit per owner. Host
   executor adoption/placement may cause subsequent idle/kick boundaries.
5. **Both returns and faults:** parent gets pid, child gets zero. Writes use
   EL1 COW if authorized, otherwise the HVC #2 non-SVC/capacity routes above
   (`fault:794`, `:890`). Host invalidation may add HVC #1. Exact live
   interleavings require signed confirmation.
6. **Child completion:** close/exit/exit_group and parent ppoll/wait4 use
   host services unless an existing EL1 subset applies. Host terminal code
   closes fds before MM retirement (`binding:894`); graph exit publishes
   zombie/status/SIGCHLD (`kernel/operations/exit.rs:647`, prefix
   `carrick-kernel/src/`). Parent wait consumes through `proc:3193` and
   `kernel/operations/wait.rs:245`; blocked resumes can arrive on HVC #5.
   Retirement may complete with HVC #1. Never sum these descriptions with
   the already-counted clone/wait service exits.

### vfork + exec (CLONE_VM | CLONE_VFORK, no CLONE_THREAD)

1. Same SVC/HVC #2 process-clone route; `proc:3470` selects vfork. Runtime
   keeps the shared MM instead of constructing a COW child
   (`carrick-runtime/src/vcpu_loop/lifecycle.rs:122`).
2. `binding:820` consumes `SuspendVfork`, enrolls `HvpatchBlockInput::Vfork`
   and retains the parent's frame/child identity. Parent suspension releases
   execution capacity. Scheduling and handback can add #5/#4/canceled exits;
   they are not additional clone calls.
3. Child performs signal/fd preparation then execve/execveat via HVC #2 and
   the exec sequence below. Shell implementations need not use this shape:
   the spawn-loop receipt does not distinguish fork from vfork.
4. Successful exec detaches only the child from the shared root and releases
   the exact vfork waiter; child _exit also releases it. Failed exec returns
   to the child, leaving the parent suspended until exec/exit. The retained
   frame/control tests are at `binding:7811`, `:7898`, `:7965`; their live
   ordering is source-read, needs signed confirmation. Parent wait4 later
   consumes child exit, separately from vfork release.

### clone(thread)

1. Libc maps stack/TLS and prepares mask/altstack; memory eligibility and
   pending work determine the common routes. `lifecycle:389` requires the
   supported thread flags, nonzero stack and an open serving page.
2. With a claimable lifecycle entry and zone record, EL1 claims identity,
   captures TID outputs, copies mask/affinity at claim, publishes Born and
   queues the child (`lifecycle:413`, `:439`). No SVC forward on success.
   Refusal/exhaustion/gates return to host HVC #2; `proc:188`, `:3440` produce
   the thread plan and `binding:1812` publishes through host clone handling.
3. Child setup and gettid/affinity may forward independently. Current
   `lifecycle:120` has no gettid arm; the pending Phase B branch is described
   by the spec as adding it. Re-inventory Phase B before implementing N2.
4. Private futex join can park/wake in EL1 (`personality/sched.rs:15`, `:35`);
   shared/unsupported variants or missing admission forward. EL1 switched-in nonleader
   exit clears TID under its predicates (`lifecycle:507`), but a nonempty
   robust list explicitly refuses at `lifecycle:527` (no walker on this base).
   Host-loaded, last-thread/group and refused exits go to the host owner.
   Host settlement/adoption is still a venue dependency, not sole EL1 task
   graph ownership. Signal delivery and stop/control may force exits.

### execve / execveat

1. HVC #2 reaches `proc:3335` / `:3353`: checked argv/env/path reads, size
   checks, fd/path resolution. Output is `DispatchOutcome::Execve`.
2. Host `exec:1304` performs observer admission and `load_execve_image`
   (`carrick-runtime/src/runtime/exec.rs:87`);
   `exec:1456` drives the replacement. Contained real-file lookup/read is a
   necessary host crossing; interpreting ELF/PT_INTERP, choosing Linux
   permissions, auxv/stack/TLS and image identity is currently host semantic
   work under this same exit. Do not invent a host exit for each read.
3. `exec:494` closes clone admission; `carrick-kernel/src/kernel/exec.rs:96`
   (`PreparedExec`) retains rollback/no-return authority. Sibling drain,
   fd unshare/CLOEXEC, Sighand reset and successor publication are host-owned
   graph operations. #4/canceled/#5 may accompany drain, not one per sibling.
4. `carrick-vmm-hvf/src/trap/execve_rebuild.rs:444`, `:542`, `:933` switch
   stage-2 and rebuild roots/image; maintenance completes through #1. N1
   supplies the memory-side successor transaction; N2 moves loader and task
   orchestration into EL1. Terminal old-MM retirement differs from exec
   handoff; preserve `Stage1Authority` revocation rules.
5. Return enters the successor, never the old exec syscall. Dynamic loader
   open/read/stat/file-mmap/close/mprotect/brk, subsequent thread creation,
   exit and parent wait can each generate the corresponding common exits.
   Failed pre-commit exec preserves the old task; a failure after no-return
   follows terminal policy, not a fabricated successful rollback.

### Capture g: preserve counts, correct one label

| Numeric ID(s) | g HVC #2 count / per fork | Current owner/venue anchor | N2 destination |
| --- | --- | --- | --- |
| 220 clone | 180 / 9 | `proc:3399`, `lifecycle:389` subset | Task owner + N1 MM + fd/signal owners |
| 93 exit, 94 exit_group | 160, 21 / 8, 1.05 | `lifecycle:507`; `kernel/operations/exit.rs:258` (kernel prefix) | Task termination + robust/fd/wait/signal owners |
| 96 set_tid_address, 178 gettid | 21, 160 / 1.05, 8 | `proc:1765`; dispatch fallthrough | Exact thread control/identity |
| 122 sched_setaffinity | 160 / 8 | `proc:2025` | Task permission + guest CPU placement |
| **103 setitimer** | 21 / 1.05 | `carrick-kernel/src/dispatch/time.rs:391` | Process timer/signal owner, pending census |
| 134 rt_sigaction | 5 / .25 | `carrick-kernel/src/dispatch/signal.rs:2047` | Sighand/delivery owner |
| 214/215/222/226 brk/munmap/mmap/mprotect | 1/205/251/106 / .05/10.25/12.55/5.3 | `dispatch:332`, kernel `dispatch/mem/` | N1 production MM owner |
| 57 close, 59 pipe2, 64 write | 160/40/3 / 8/2/.15 | `carrick-kernel/src/dispatch/fs.rs:668`, `fs/pipe.rs:942`; `dispatch:413` IPC subset | One fd/description + pipe owner; host only for external writes |
| 73 ppoll, 98 futex, 260 wait4 | 101/133/20 / 5.05/6.65/1 | kernel `dispatch/net.rs:3187`, `proc:3193`; EL1 `personality/sched.rs:15` subset | Object/child wait owners + signals |

Kernel-prefixed abbreviated entries refer to `carrick-kernel/src/`.
The receipt labels 103 as set_robust_list. **Erratum:** ABI
`carrick-abi/src/syscall.rs:432` assigns set_robust_list=99 and `:436`
assigns setitimer=103; `lifecycle:33` uses 99. Director confirms preserving
numeric counts and requiring 99 **and** 103 in the next census. Do not remove
the 21 events or silently change the receipt. Keep 99 in N2 setup coverage;
include 103's process timer owner until the trace resolves the label.

The quoted categories remain 728 lifecycle/identity/signal (including the
suspect timer label), 563 memory, 457 IPC/wait = 1748 HVC #2 exits.
There are **423 unassigned HVC #2**, plus **366 canceled, 393 idle, 50 kick,
240 maintenance**, totaling **3220 = 161/fork**, against 144/20 = 7.2.
Only 54 idle exits join resumed services (50 ppoll, four wait4). Six host
fault-COW resolutions are .3/fork; 179 HVC exits associated with ASID
invalidation overlap the services. No additive savings claim follows.

Source narrows the 423's possible producers without assigning invented counts:

| Candidate family | Source discriminator and remaining evidence |
| --- | --- |
| First-touch/grant request | `fault:890` publishes `FrameGrantRequest` then returns Forward; VM-free test above proves zero syscall-forward increments. Join underlying ESR/FSC, mailbox request and exact MM; do not call this COW. |
| COW refusal/editor busy | `fault:794`–`:834`, `trap:8177`; distinguish no grant, closed editor, executable copy and actual six host fault resolutions. A permission abort alone does not identify the cause. |
| Other lower-EL faults / system registers | `trap:8180` records EC/FSC/sysreg/emulated-system-register subcounts; `trap:8391` has no syscall request. g's 377 EC36 events cover the **whole capture**, not this window; none may be subtracted from 423. |
| Already served, owes work | `vector:5054`, `loop:1526` bypass normal redispatch. Join the served boundary and exact operation before classifying; masks, IPC wakes and retirement can contribute. |
| Internal handback/engine work | `loop:1510` handles IPC handback before ordinary dispatch; join operation/record generation and resume identity, not host thread proximity. |

**Quantitative attribution gained from source: zero of the 423 can be assigned
a defensible exact count.** The producers and discriminators above are the
additional attribution. Milestone A captures every HVC's underlying exception,
SVC number/arguments (all six), exact TaskKey/MM/record/operation generation,
served-with-work/handback state, capacity request/completion and boundary id.
Join maintenance call reason, initiating kick stack/target, cancellation PC/EL
and absorbed state, pause begin/drain/end, idle reason and resumed service.
Use existing USDT/carrick trace, no one-off tracer or printf. Unknown/drop/
window-overflow is IncompleteMeasurement, never a residual budget allowance.

## 2. Target authorities and ceilings

One task graph, one fd namespace and one signal state per Linux sharing
relationship. Extract existing policy into no_std/shared cores and change its
venue; do not maintain host and EL1 registries and periodically reconcile them.
EL1 task policy invokes the N1 owner directly; it must not make an EL1→host→EL1
round trip merely to request Fork or Exec.

| Owner | Exact authority to preserve/reuse; target service |
| --- | --- |
| Task | `TaskKey`, `ThreadKey`, execution generation, `Task` (`kernel/objects/task.rs:553`), `PreparedFork` (`graph:549`), `PreparedExec` (`kernel/exec.rs:96`), `ThreadLedger` and its `ThreadIdentityPool` (`kernel/thread_ledger.rs:223`, `:126`), `ThreadLifecyclePage`, `EntryRef`/`ClaimedEntry`, `ThreadControlSlot` (`carrick-el1-abi/src/thread_lifecycle.rs:325`, page at `:497`). Move graph mutation/publication policy into EL1-capable storage; host observer accesses same exact authority. No new EL1 pid table. Claim binds creds/mask/affinity/uid credit; child not runnable until MM/fd/signal/TID commit. |
| Memory | N1 `El1MmHandle`, closed `TransferIntent`, production `MmPortal`, `AddressSpaces`/`SpaceEditor`, admitted reservation root and exact physical custody. N1 Fork supplies live COW child, shared-MM handles supply vfork/thread, ExecPrepare/ExecCommit supplies successor. The portal is an owner interface, not N0's deleted private MM graph. Capacity and HostBacking supply resources only. |
| Fds | `carrick_fd_core::Authority`, `TableId`, `Description`, `OfdKey`, `OfdPin`, `BackingToken` (`fd:87`, `:119`, `:139`, `:712`). The mapped `IpcFdAuthority` (`carrick-el1-abi/src/ipc.rs:150`) is the existing adapter. Existing `FileTable` and `FileDescription` (`carrick-kernel/src/kernel/objects.rs:2317`, `:1128`) must use this single namespace for stdio, files, pipes, eventfd, epoll and socket descriptions. `Authority::fork` (`fd:1344`) copies slots while retaining descriptions; CLONE_FILES shares table identity; exec unshares before `Authority::exec` (`fd:1390`) closes CLOEXEC. Host backing tokens confer no fd semantics. |
| Wait | `RecordRef`/record incarnation, `OperationToken`, `ObjectWaitKey`, `WakeEffects` (`carrick-sched-core/src/object_wait.rs:25`, `:56`), existing IPC operation pins and exact child `WaitOutcome`/`ChildWaitPrecheck` (`kernel/operations/wait.rs:115`, `:139`). One owned enroll/park/wake/resume episode; mixed host readiness is input to this same wait owner. Child zombie consumption, vfork release and futex join remain distinct events. |
| Signals/timers | `Sighand`, `TaskPendingSignals`, `ThreadSignalState` (`kernel/objects/signal.rs:34`, `:330`, `:577`) and authoritative ABI `ThreadControlSlot` masks/altstack. Reuse `carrick-signal-core/src/lib.rs:22` (`SignalSet`), `:51` (`PendingSet`) and `:131` (`PendingQueue<T>`); keep Linux policy in the personality. Move action, pending selection, frame/restart/sigreturn and child notification together. CLONE_SIGHAND shares; fork copies dispositions and caller mask without copying pending signals; exec resets caught handlers and altstack. Process-scoped setitimer uses this owner plus a clock input, never the carrier's process timer. |

Here and below `kernel/...` in authority rows has the `carrick-kernel/src/`
prefix. The proposed task transaction extraction goes in new
`carrick-sched-core/src/task_lifecycle.rs`; keep Linux flag/errno/signal policy
in EL1 personality adapters. Extend the existing signal core, not a new crate.
These extraction filenames are design choices;
the listed identities and single-owner rules are mandatory, not proposed
additional registries.

Host crossings that remain: contained real-file name/metadata/byte I/O
(including ELF/interpreter reads and coherent file-backed mappings), external
network/CLI terminal I/O, physical extent grants/returns and stage-2 custody,
host clock calibration/input, and root-command completion to the CLI. Warm
CNTVCT/vvar reads and guest timer expiry need no per-call host clock exit.
Ptrace/observer requests may cross the API boundary but ask the same owner;
they cannot install a second host clone/signal/exec path.

| Operation | Required ceiling at N2 composition |
| --- | --- |
| fork + exit + wait, resident resources | **0 semantic host dispatches/op**, 0 host COW resolutions, 0 host page-table pause operations. EL1 graph/MM/fd/signal/wait handles all six fork hops. Capacity shortage is an owned service, not forwarding. |
| clone(thread) + setup + join/exit | **0 semantic host dispatches/op**, zero guest-wait host-worker occupancy; no per-thread host adoption/settle requirement. Reuse Phase B identity and robust protocol. |
| vfork + exec + wait | **0 semantic host dispatches/op**; EL1 shared-MM lifetime + exec transaction + exact parent release. Physical/file services separately bounded below. |
| execve / execveat | **0 semantic host dispatches/op**, including loader interpretation, fd unshare/CLOEXEC, sibling drain and signal reset. Host ELF reads are byte services, not host exec dispatch. |
| Existing 20-fork COW window | Total exits **<= forks*pages/4 + 64**: **144/384/1344** at pages **16/64/256**; incremental slope **< .125 per added fork-page**; `hvf_syscall_exits <= 64` unchanged. Do not subtract startup or exempt capacity exits from the total. |

The first four are structural per-op ceilings, not fabricated measured total
exit baselines for exec/thread. For operations with real external work, propose
an additional A-binding limit of **at most two exits per submitted backend
batch** (submit and completion), **zero per internal owner hop**. Bound batch
population by requested file spans/bytes and N1's frozen extent geometry,
not by an observed number of arbitrary tiny requests. For an operation needing
B necessary file/clock batches and C capacity batches, added exits <=2(B+C);
warm in-zone operations have B=C=0. This is a **new proposed contract** to
register red-first, not an accepted relaxation of the existing absolute window.
Cold bytes, path components, short-I/O and grants/returns must have independent
complete counters. Freeze exact fixtures/chunk sizes before claiming the bound.
No syscall-count-to-speedup arithmetic: all three creation per-op medians must
meet **<=2x native arm64 Docker**, with correctness first and thread regression
visible. N3 retains whole-window reconciliation and controlled ratio closure;
N2 must hand it the unchanged red populations, not declare them accepted.

## 3. N1 and Phase B dependencies

| Consume | Why / wait condition |
| --- | --- |
| Production owner adapter and UserTransfer | Exact carrier/MM/incarnation/root validation, retained custody pins, permission/fault/prefix behavior, executable I-cache publication and stopped-target service. No protection-mirror check or host raw-copy escape in admitted tasks. Bind to N1's real service, never its deleted N0 model. |
| Owner Fork | N1 plan:1261: live VMAs/leaves, DONTFORK/WIPEONFORK, private-file token/offset/generation, parent-owned deferred returns, rollback and child execution gate. Outstanding transfer admission refusal must become an owned retry/park in task orchestration, not guest EAGAIN caused by internal contention. |
| Venue-3 prepared-copy permit | Plan:1376/1424: prepare after readiness, bounded range and lifetime, separate semantic admission from editor; overlapping edits defer, unrelated edits proceed; commit/cancel wakes exactly once. No permit survives a blocking host wait. Aggregate record I/O prepares all-or-cancels; internal chunk size never truncates a datagram. Needed by TID/status/signal copies and host-file/pipe consuming operations. |
| Shared description cursor (pending, director ruling) | N1 is implementing an **owned shared cursor authority on the open file description**, shared through dup/fork/SCM_RIGHTS: staged pread, then prepare, then commit, serialized like Linux f_pos. It was not in fetched 8d5df2d2e. No type name or verified implementation claimed. N2 must consume that authority for file read/write/loader concurrency, not invent a per-fd lock or replay a consumed read. |
| MM edit completion / service progress | Reuse N1's exact-incarnation object wait namespace and owned `WakeEffects` delivered after unlock (plan:1416/1435), including handback. No polling bitmap, spinning, or host-worker wait. Default-pool exhaustion must still allow stopped-target owner service. |
| Exec/retirement and Capacity | Wait for N1 successor prepare/commit and terminal root revocation, physical extent/partial-compound budgets and bulk supply. Fork/UserTransfer checkpoint greens do not prove these. N1 still records 64 GiB/16 TiB capacity and file MAP_FIXED policy reds. |
| Lifecycle Phase B | Rebase onto its accepted identity, gettid, robust exit, fork/exec gate, tgkill-after-clone and epollstopcont/futexforkwakegroups repairs. Spec branch status is a report, not source-verified acceptance here. N2 extends it to process ownership; do not rewrite it. |

**Can start now, file-disjoint from inspected N1:** new creation fixtures under
`carrick-el1/tests/` and `carrick-kernel-example/tests/` (new filenames),
fd-core/pipe-core tests and core algorithms, graph work in
`carrick-kernel/src/kernel/{operations.rs,operations/thread.rs,operations/wait.rs,operations/exit.rs,thread_ledger.rs,exec.rs}`,
and signal policy extraction from `kernel/objects/signal.rs` into the existing
`carrick-signal-core/src/lib.rs` plus new personality adapter files. These paths are
absent from `git diff --name-only fda4e0350 origin/work/n1`. New core files can
be prepared, but publication/wiring waits; coordinate Phase B's overlapping
lifecycle ownership separately. File-disjoint means preparable, not
independently acceptable without N1.

**Must wait/rebase:** `personality/dispatch.rs`, `personality/mod.rs`, EL1 ABI
layout/lib, all mm_portal/fault/reservation work, sched-core lib/object_wait/
spaces, runtime binding/quiesce/memory/zone/signal, kernel MM/signal dispatch,
HVF process_plan/execve_rebuild, shared contract/inventory/probe registries.
N1 already touches these. Reserve `kernel/objects.rs` for its pending cursor
work even though it is absent from the fetched diff. Do not edit the N1-owned
creation contract concurrently. Refresh this diff against the actual landing;
the frozen branch is neither a file lock nor a promise its scope will not grow.

## 4. Five reviewable landings

Each landing has one capability boundary and its own red/green receipt. Scope
fences below are for **future implementation**, not permission for this docs
change to edit those files. A new contract registers production, VM-free,
signed and Docker bindings; absent bindings remain UnsupportedLayer. No
ignored failing tests or baseline assertion inverted to pretend success.
Linux authority is the cited man-page contract already recorded in the repo;
consult clean-room specifications/native oracle for unresolved behavior, never
GPL implementations.

### A. Freeze creation accounting and the composed red witness

- **Fence:** `conformance-contracts/contracts/el1-creation-native-path.toml`
  (after N1 handoff), creation entries in inventory/surfaces; new
  `carrick-el1/tests/n2_creation_owner.rs`,
  `carrick-kernel-example/tests/n2_creation.rs`; existing signed
  `carrick-embed/tests/el1_sched.rs` and its fixture/report code;
  `carrick-observability/src/probes.rs`, `carrick-cli/src/trace_profile.rs`,
  durable `scripts/dtrace/fork-cow-exit-attribution.d`. No product routing.
- **Contract:** existing N1 `kernel.el1.creation-native-path`,
  `kernel.el1.fork-cow`, `kernel.el1.fork-lifecycle-exits`; preserve
  `kernel.fork.stage1-image`. Register all 18 numeric IDs plus 99,
  execve/execveat and loader boundary, zero semantic dispatch and proposed
  backend-batch bound. Validate one operation's completion once across resumes.
- **Red first:** run composed fork/pipe/wait, thread join and vfork/exec
  scenarios at 1/8/32 concurrent creators with two live same-VA MMs and
  default slots. Inject close/reuse, source partial read and failed image
  prepare. Current host dispatch violates zero work budget even where Linux
  results pass. Signed current artifact retains 20x16 red and newly complete
  attribution; unknown events fail closed. A missing API compile failure is
  not the red. Reuse existing signed/next probes for guest execution.
- **Impact:** none; this stops misattribution and provides the comparison base.
- **Accept:** `cargo test -p carrick-el1 -p carrick-el1-abi -p carrick-sched-core`;
  `cargo test -p carrick-kernel-example --test n2_creation`; signed
  `just test-embed el1_fork_cow_resolves_in_guest --nocapture` retains expected
  pre-change failure, not an acceptance pass. Common host checks below.

### B. One descriptor owner and creation IPC waits

- **Fence:** `carrick-fd-core/src/lib.rs`, `carrick-pipe-core/src/lib.rs`,
  kernel `kernel/objects.rs` (after cursor), `dispatch/{fd_table,fd_wait,io_pipe}.rs`,
  `dispatch/fs/{pipe,fd_helpers}.rs`, `dispatch/net.rs`; EL1
  `personality/{dispatch,ipc}.rs`, `substrate/ipc.rs`; ABI IPC storage and
  sched-core object-wait completion; their existing tests and A bindings.
- **Contract:** creation-native-path plus existing fd/IPC contracts from the
  step-3 plan. Pipe pair publication is atomic; CLONE_FILES shares slots,
  fork shares OFDs but not slots, CLOEXEC affects only the unshared successor;
  final endpoint close, EOF/EPIPE/SIGPIPE and blocked operation lifetime agree.
  ppoll all-zone and mixed sets use one enrollment and absolute deadline;
  future signal owner supplies temporary-mask policy. No second host pipe wait.
- **Red first:** core tests at 1/8/64 fd/pipe populations; block partial writer,
  close/reuse fd, fork then exec and consume remaining bytes exactly once;
  race readiness before/after enrollment. VM-free default-pool exhaustion
  with runnable reader proves zero worker occupancy. Signed `el1_ipc_`
  family binds actual copyout/park/resume, EINTR/partial/restart and mixed host
  readiness; conformance-next adds only missing byte/errno oracle witnesses.
- **Impact:** removes the eligible portion of g's 457 IPC/wait HVC population;
  wait4 remains D. No promise that all .15 writes/fork are in-zone. Spawn/fork
  pipe handshakes improve structurally; thread join must not regress.
- **Accept:** `cargo test -p carrick-fd-core -p carrick-pipe-core`;
  `just test-kernel`; `just test-embed el1_ipc_ --nocapture`; A plus common gates.

#### B-prep handoff

Portable preparation on `work/n2b-core`, based on `ad3e127a9`, extends only
fd-core/pipe-core code. It is not landing-B activation or signed acceptance.
Red commit `96d3a60a5` records compiling behavioral failures: two single-slot
installs leave a reader published after pair refusal, and readiness bits lose
a write/drain edge before enrollment. Existing clone/fork/exec/pin semantics
were green, and are reused rather than replaced. New bindings live in each
crate's `b_prep_*` tests, extending ipc-fd-authority, ipc-object-state and
ipc-lifecycle. Shared contract/probe registry edits wait for N1.

- Call `Authority::transaction(table)?.install_pair(min, [&reader, &writer],
  cloexec)` on the single descriptor authority after preparing both OFD pins
  and resources. Refusal publishes neither slot and preserves both pins;
  success leaves those preparation pins caller-owned. Drop the transaction
  before copies, I/O, services or release effects. Pair copyout needs N1's
  aggregate prepare/commit and owner cancellation/rollback. There is no
  consuming copy callback under the table lock and no private scratch table.
- CLONE_FILES keeps one TableId with venue-owned sharing counts. Fork retains
  the existing OFDs in private slots; exec unshares before the existing
  CLOEXEC sweep. Task successor publication and old-table last-owner release
  stay with the task owner. Suspended I/O retains OfdPin plus exact endpoint,
  source authority, operation token and WriteProgress, never a numeric fd.
- `PipeRecord` IS a shared ABI record: `carrick-el1-abi/src/ipc.rs` embeds it
  in IpcObjectState and includes its size in `LAYOUT_FACTS`/`IPC_LAYOUT_HASH`.
  This preparation preserves its seven-u64/56-byte layout. The pipe-core
  readiness API instead takes a caller-owned `ReadinessRevision` through
  `Pipe::with_revision`. Landing B must supply one persistent revision word
  per exact object incarnation and bind it on **all** mutation views under
  the object lock. Adding that word to the shared object/PipeRecord after N1
  requires coordinated IPC layout facts/hash and ABI version updates in both
  venues, layout tests and signed verification; do not insert it independently.
- The wait owner must observe/enroll/probe under the same object authority,
  then recheck the operation if readiness or revision changed before parking.
  An unbound snapshot returns RevisionUnavailable; revision overflow refuses
  before effects. Neither is a Linux errno. Deliver WakeSet after unlocking
  to exact enrolled waiters. Revisions are not readiness grants or a substitute
  for authenticated operation/object incarnation. This slice owns no queue,
  timer, temporary-mask policy, executor or host readiness proxy.
- `Step::broken_pipe_signal()` returns the SIGPIPE decision as data, including
  EPIPE after partial progress. The personality delivers the signal and chooses
  EPIPE versus the preserved prefix; the core never raises it or restarts at
  zero. The final OFD/pin release drives endpoint release exactly once.

VM-free tests cover 1/8/64 descriptors/pairs and simultaneously blocked writers.
Pair allocation uses at most `2 * (2 * bitmap_levels - 1)` bitmap reads; a
three-page stream copies exactly twice its delivered bytes and visits six
pages per pipe. These do not establish zero EL1 host dispatch or default-pool
exhaustion. The integration director still owns task publication, actual
copyout/park/resume/cancellation, the 32-writer default-pool witness, registry
bindings, signed `el1_ipc_`, pinned native-arm64 Docker and common gates.
No signed/HVF test, Docker or `just accept` runs on this Linux preparation box.

### C. Signal, timer and wait interruption have one EL1 owner

- **Fence:** kernel `kernel/objects/signal.rs`, `dispatch/{signal,time}.rs`,
  `carrick-el1-abi/src/thread_lifecycle.rs`; existing
  `carrick-signal-core/src/{lib,fasync}.rs`, new EL1
  `personality/{signal,timer}.rs` and dispatch; dependency/export changes in
  EL1 Cargo.toml and personality/mod.rs; runtime `vcpu_loop/signal.rs` reduced
  to external input; signal frame HAL hooks and A/next/signed bindings.
- **Contract:** N1's `kernel.el1.signal-delivery-owner` and creation-native-path.
  Actions, pending state, mask, temporary masks, altstack, frame delivery,
  sigreturn validation and restart are one authority. Include process timer
  arming/expiry/cancel for numeric 103 until census resolves it; clock input
  crosses, carrier process timers do not model guest process state.
- **Red first:** two-process signal-core tests at 1/8/32 targets: immediate
  tgkill after birth, masked SIGCHLD, CLONE_SIGHAND, fork/exec resets, duplicate
  timer completion, reused task id, wait interruption vs readiness, partial
  write and SA_RESTART. Shared core tests prove deterministic selection/work;
  signed handler frames, sigreturn/protection faults, stop/continue and timer
  delivery are indispensable. Reuse killrt/epollstopcont, without retries.
- **Impact:** removes signal-triggered forwards/served-with-work tails, not
  merely the five sigaction exits. Timer's 21 events remain provisional.
- **Accept:** `cargo test -p carrick-signal-core`; `just test-kernel`;
  `just test-embed el1_ --nocapture`; `just conformance-probes`; A/common gates.

#### C-prep handoff

The `work/n2c-core` preparation extends only `carrick-signal-core` (plus
this subsection). No kernel, EL1 personality, HAL or shared registry wiring
is changed. This is a VM-free policy binding for
`kernel.el1.signal-delivery-owner`, not acceptance of landing C.

- `policy` extracts the kernel object's first-standard/FIFO-real-time pending
  algorithm using the existing core payload queue and set. It adds typed Linux
  signal/action/mask policy, handler entry, fork/exec reducers, child decisions
  and exact-key inboxes. `ActionInheritance::Shared` returns the existing
  sighand key for CLONE_SIGHAND; `Copied` returns independent actions. The
  production graph must publish that edge, not create another authority.
- The crate remains `no_std` with no dependencies. Its minimal `Signal` and
  block-mask equivalents use Linux asm-generic numbering; `carrick-abi` remains
  the wire-ABI source of truth, but currently has a std dependency closure.
  AArch64 and x86_64 share numbers. `HandlerReturnPolicy` distinguishes the
  AArch64 kernel/vDSO fallback from x86_64's required registered restorer.
  Restorer preflight happens before handler entry; the HAL still validates
  and builds frames. Unsupported wire fields remain the adapter's concern.
- `wait` returns continue, committed readiness, successful byte prefix,
  restart or EINTR. The syscall adapter supplies the operation's restart
  class (including socket timeout state) and the original caught handler's
  SA_RESTART. A readiness *hint* is not committed completion. The real wait
  authority must arbitrate the race and preserve its continuation/cursor.
- `timer` owns one ITIMER_REAL state per exact process key. Injected elapsed
  real-time values and typed spans use nanoseconds. `set` returns old state
  and a completion ticket; `expire` authenticates owner, arm sequence and
  deadline and returns one SIGALRM-generation effect plus the next ticket.
  The adapter enqueues SIGALRM into this same process pending owner. Delayed
  expiry advances periodic phase with constant arithmetic, never a tick loop.
  Cancel/rearm reject old tickets; fork is disarmed and exec retains the timer.
  Overflow/sequence exhaustion are explicit refusals with unchanged state.
  Preserve the timer authority across rearm/exec; recreating it for the same
  live key would discard its arm sequence. Task/thread keys must include the
  existing graph generation, not just a reusable PID/TID.

The `policy_contract` fixtures cover 1/8/32 target populations with two
independent process owners, immediate exact-thread enqueue, masked SIGCHLD,
CLONE_SIGHAND, fork/exec, reused IDs, duplicate/stale/foreign timer completion,
temporary-mask handler restoration, nested masks, partial I/O and restart.
Target selection counts actual inspected rows and asserts `examined <= N`
(the last-eligible case is exactly N); no unrelated process may be chosen.
Pending summaries/counts select in O(1), queues cost O(log 64) plus affected
payload destruction, and timer catch-up does not scale with missed ticks.
These are pure fixtures, not scheduled tgkill-birth or guest frame proofs.

Red evidence on main `ad3e127a9` with tests only: `cargo test -p
carrick-signal-core` exits 101 because `payload_policy_is_caller_selected`
returns 3 instead of retained 2 and
`standard_coalescing_retains_first_payload_including_absence` returns the
second payload instead of the first. The policy contracts separately produce
capability compile reds (missing policy/timer/wait modules and typed set
operations); they are not claimed as executable semantic reds. During
preparation the one-shot metadata assertion also caught an over-broad reset
before it was aligned with the existing kernel test. Architecture restorer
fixtures were added before their API (capability compile red).

Findings for the integrating owner (source inspection, no kernel changes):

| Current representation/behavior | Core policy / handoff decision | Linux authority |
| --- | --- | --- |
| Core `PendingQueue::publish(coalesce=true)` replaced the old payload, unlike kernel `PendingQueue::enqueue_standard`. Its existing child-watch caller uses this for standard signals. | Coalescing now keeps the first pending instance, including no payload; FIFO remains FIFO. The existing generic queue test was corrected red-first. | [signal(7), standard queueing](https://man7.org/linux/man-pages/man7/signal.7.html) |
| `TaskPendingQueue::recipient` defaults to the leader and keeps a named recipient per signal; other kernel wait logic can retarget. | Pure process-target selection uses the first live, unblocked exact key in caller order. Revalidate and publish under admission; leave pending when all eligible threads block it. This is a selection-interface difference, not proof the full kernel path violates Linux. | [signal(7), process-directed delivery](https://man7.org/linux/man-pages/man7/signal.7.html) |
| Kernel default delivery folds SIGCONT into Ignore and all fatal defaults into Terminate. | Core returns Continue and distinguishes core-dump defaults. Generation-time SIGCONT resume/stop cancellation must occur even with a caught/ignored disposition; this slice does not implement job-control graph mutation or dump production. | [signal(7), default actions](https://man7.org/linux/man-pages/man7/signal.7.html) |
| `Sighand::autoreaps_children` and child-exit notification are separate helpers; the latter has no stop/continue event parameter. | `child_decision` returns independent auto-reap and notification data, including SA_NOCLDWAIT's caught notification and SA_NOCLDSTOP's stop/continue suppression. This must not remove waitable stop/continue events. | [sigaction(2)](https://man7.org/linux/man-pages/man2/sigaction.2.html), [wait(2)](https://man7.org/linux/man-pages/man2/wait.2.html) |
| Kernel thread `set_blocked` accepts an arbitrary set; dispatch currently sanitizes and separately arms the restore mask. | Core block-mask construction removes SIGKILL/SIGSTOP. Temporary replacement and handler restore-mask selection are one transition; caller must enroll the wait atomically with it. | [sigprocmask(2)](https://man7.org/linux/man-pages/man2/sigprocmask.2.html), [sigsuspend(2)](https://man7.org/linux/man-pages/man2/sigsuspend.2.html) |
| Current `dispatch/time.rs::setitimer` treats null `new_address` as None and only mutates inside `if let Some(v)`, leaving an armed timer unchanged. It stores `Instant` and invokes backend timer delivery. | Adapter must translate null new-value to a zero spec (disarm), then use the exact process timer transition and injected clock. ABI-pointer validation/old-value copy faults remain adapter work. | [setitimer(2), Linux null-new-value behavior and process timer rules](https://man7.org/linux/man-pages/man2/setitimer.2.html) |
| Runtime restart uses syscall-number classification, boundary/EINTR predicates and continuation restart state. | Core takes a restart class and committed progress explicitly. Never restart ppoll/pselect/sigsuspend; interrupted slow I/O with a prefix succeeds with that prefix. Preserve the owned endpoint/cursor in integration. | [signal(7), syscall interruption](https://man7.org/linux/man-pages/man7/signal.7.html) |

Fork/exec/sharing rules follow [fork(2)](https://man7.org/linux/man-pages/man2/fork.2.html),
[execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html),
[clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html) and signal(7).
SA_RESETHAND preserves flags/mask/restorer while changing disposition, matching
the kernel's existing `sa_resethand_resets_disposition_to_default_on_handler_entry`
test; exec keeps only ignored action records, matching `Sighand::for_exec`.
Pending process/thread owners survive exec and clear on fork. Masks stay
independent even when sighand is shared.

Portable verification: `cargo test -p carrick-signal-core` (12 unit tests,
18 policy contracts), `cargo clippy -p carrick-signal-core --all-targets -- -D
warnings`, and `just fmt-check`. Clippy exits zero but reports the existing
Linux-invalid `libc::proc_listallpids` catalog entry in root `clippy.toml`.
No signed/HVF, Docker, `just accept`, kernel or EL1 binding gate was run on this
Linux box, as instructed. Frame/protection/sigreturn, altstack, job-control,
permission/sender validation, RLIMIT_SIGPENDING admission, shared publication,
wait races and signed exact-artifact promotion remain integration work under
section 3; no new graph, lock, host timer or scheduler is supplied here.

### D. Task birth, process exit and child waits execute in EL1

- **Fence:** kernel `kernel/{operations.rs,operations/thread.rs,operations/exit.rs,operations/wait.rs,thread_ledger.rs}`,
  `kernel/objects/{task,thread}.rs`, new
  `carrick-sched-core/src/task_lifecycle.rs` and its lib.rs export; ABI
  `thread_lifecycle.rs`,
  EL1 `personality/{lifecycle,dispatch}.rs`; runtime
  `vcpu_loop/{binding,lifecycle,quiesce,zone}.rs` and executor adoption;
  kernel `dispatch/proc.rs`; N1 owner calls only, no MM implementation edits.
- **Contract:** creation-native-path, thread-lifecycle, child exit notification
  and scheduler lifecycle. One transaction claims identity/uid credit, obtains
  MM and fd/signal edges, validates TID outputs, then publishes child runnable.
  Failure unwinds all edges once. Thread clone, process clone/fork and vfork
  share graph semantics; observer/tracer/seccomp policy cannot fall back to a
  second owner. Exit includes robust/clear-tid, last thread, exit_group,
  fd release, zombie/rusage/SIGCHLD, reparent/reap and exact vfork release.
- **Red first:** VM-free shared task/kernel scenarios 1/8/32, two live parents:
  clone during fork/exec close, pool exhaustion, uid-limit exhaustion, failed
  MM/fd/TID commit, stale completions after identity reuse, robust death,
  WNOHANG/ECHILD/SA_NOCLDWAIT and delayed parent notification. Signed
  TRACECLONE/seccomp, parked-thread register capture, forkexecstorm,
  exitgroupthreads/futexforkwakegroups and all fork-COW scales bind real
  routing. Preserve oracle-qualified TID copyout errno/ordering; do not guess
  Linux behavior from the current rollback implementation.
- **Impact:** targets clone/exit/identity/affinity/wait4 and associated control
  churn (most of g's 728 plus wait4), beyond Phase B's thread-only subset.
  This is the first fork/exit/wait vertical with no required host task service.
- **Accept:** `cargo test -p carrick-sched-core`; `just test-kernel`;
  `just test-embed el1_ --nocapture`; `just conformance-probes`; A/common gates.

### E. Exec loader and successor commit run in EL1

- **Fence:** kernel `kernel/exec.rs`, `dispatch/proc.rs` and existing executable
  authority (`dispatch/executable_authority.rs`); runtime
  `{runtime/exec.rs,vcpu_loop/exec.rs}`; `carrick-mem/src/{elf,memory}.rs`
  loader extraction into new `carrick-el1/src/personality/exec.rs` and shared
  parser module/export plumbing (one parser, remove the displaced body);
  fd/signal commit interfaces from B/C, N1 ExecPrepare/ExecCommit calls,
  HVF `trap/execve_rebuild.rs` removal of displaced policy, A/next fixtures.
  Full names/page-cache ownership and AF_UNIX implementation remain N4.
- **Contract:** creation-native-path, MM exclusive-owner, image permissions,
  I-cache publication, carrier isolation. Host supplies contained immutable
  byte spans/source identities; EL1 chooses ELF/interpreter mappings and builds
  argv/env/auxv/stack/TLS/vDSO. Commit orders sibling cancellation, unshared
  CLOEXEC and signal reset with successor publication. Pre-no-return failure
  preserves old image/fds/signals; post-no-return failure is terminal.
- **Red first:** VM-free loader + task tests inject failure at each prepare/
  publication step, missing interpreter, invalid ELF and non-UTF8 arguments;
  concurrent shared-description reader verifies cursor advances once only
  after copy commit. Failed exec on vfork keeps parent blocked, success/exit
  releases once. Signed execveat retained-fd identity, two-MM same-VA mapping,
  stale-TLBI/I-cache negative controls, nxwritableimage, forkexecstorm and
  parked-sibling exec are mandatory. Extend conformance-next, no new CLI probes.
- **Impact:** targets the remaining spawn 8.448x and fork-exec 6.700x paths;
  includes dynamic loader scaffolding, not just the execve SVC. Full cache is
  unnecessary for cold byte service. Actual <=2x per-op result belongs to the
  controlled N3 receipt; a regression or structural failure blocks promotion.
- **Accept:** extracted loader tests; `just test-kernel`;
  `just test-embed el1_ --nocapture`; `just conformance-probes`; all common
  gates and creation impact commands below. Hand N3 a complete exit census.

### Common gates and N3 handoff

For each connected behavioral landing, on the capable macOS lane:
`just fmt-check`, `just test`, `just ci`, `just accept`, `just el1-gate`.
Reconcile inventories on the clean integrated tree before lint. The current
Linux planning box must **not** run these signed/HVF gates or Docker; full
`just test-kernel` also has known host-assumption failures here. Commands in
milestones are future acceptance commands, not claims they ran for this plan.

For final promotion build/sign with no guest alive, record source/fixture/image
identity and each executable's SHA-256/CDHash/LC_UUID/entitlement/DOF. Preserve
the exact probe-tested CLI through `just --no-deps conformance-probes`,
`just --no-deps conformance smoke`, `just --no-deps conformance full`; signed
embed artifacts have separate identities. Use the full regression population
in the controller, including its fixed Python8x2 and Go20 runs. Preserve the
frozen admission reds and any Phase B fixes with their original provenance;
no branch-local or earlier artifact pass carries over.

Uninstrumented impact, following `docs/impact-receipts.md` (capable host only):

```sh
just xtask impact carrick --artifact /path/to/base/carrick --out target/impact/n2-base.json
just xtask impact carrick --artifact target/release/carrick --out target/impact/n2-candidate.json
just xtask impact docker --out target/impact/n2-docker.json
just xtask impact report --base target/impact/n2-base.json --candidate target/impact/n2-candidate.json --docker target/impact/n2-docker.json --out target/impact/n2-report.md
```

Pin all image digests and rebuild/hash the ARM64 perf_fork_exec executable
(the historical receipt caught a stale one). Fixed samples, normal concurrency,
quiet host, same-image native arm64 Docker only after all Carrick runs stop.
Compare per-op medians for all three creation rows, also true/node startup
controls; report ranges, all failures and host CPU separately. Trace runs
supply counts, never timing acceptance. N3 closes unexplained control/idle/
maintenance residuals and whole-window/ratio budgets, without widening them.
Every run stamps CARRICK_RUN_ID and proves `scripts/sudo/kill.sh <run-id>`
cleanup. Unknown measurements, missing bindings or >=10x valid completing
workloads stop promotion; a timeout is not a ratio.

## 5. Decisions and risks

| Question/risk | Recommendation |
| --- | --- |
| Task graph is std/host-shaped; EL1 cannot just borrow an Arc<Kernel> | Extract existing transaction/state rules and typed storage access into one shared core, keep host observers as clients. Reject a second task table plus settle mirror. Portable preparatory refactor may land before activation; it confers no zero-exit claim. |
| All-owner publication can leak a child or deadlock | Prepared task transaction owns rollback tokens; acquire no subsystem lock across I/O, MM service suspension or scheduler wait. Publish child runnable last. Fault every acquisition/commit seam, including cancellation after resource preparation. |
| Tracer/seccomp closes Phase B serving gates | N2 must execute their Linux policy through the same task/signal owner. Real external observer notification is allowed; generic host syscall forwarding is not. Keep TRACECLONE and immediate tgkill as release blockers. |
| Source-only 423 attribution and mislabeled 103 | Do not distribute residuals proportionally. A's signed exact-identity census is mandatory; include process timer owner now (director agreed), later narrow only with raw numeric evidence. |
| Pending N1 cursor code and advancing branch | Contract dependency only, no invented type. Refresh N1 diff/receipts at handoff; verify dup/fork/SCM_RIGHTS shared offset and short-copy cancellation before loader cutover. |
| Same VA, different MM; stale completion after exec/reuse | Every permit, operation, root and wake authenticates generation. Child MM closed until commit; retire descriptors/root reachability before pooled backing reuse. Two live processes in every composed fixture. |
| Capacity service when all default workers are waiting | EL1-owned continuation and reusable service capacity; no target EL0 execution, no extra worker count, no poll/retry deadline. Consume N1's stopped-target proof and repeat in the creation composition. |
| Prepared copy vs source consumption | Prepare after readiness and before consuming bytes; pin description/cursor and preserve prefix. No permit across blocking I/O. All-or-cancel aggregate for atomic records, user-sized truncation only. |
| Exec rollback, vfork and sibling exit race | One explicit no-return point and exact predecessor/successor authorities. Keep failure-before-commit and terminal-after-commit paths distinct; wake parent only on child MM release/exit. |
| Host-file cache/coherence could expand N2 without bound | Pull in contained loader byte/name service and file-mapping closure only. Keep full coherent names/page cache N4; no stale cached bytes or host ELF semantic fallback as a shortcut. |
| Need total numeric exit ceilings for exec/thread beyond existing fork window | Use zero semantic dispatch plus the proposed bounded backend-batch rule now; register it in A with fixed input geometry and negative controls. Do not infer a total budget from the fork trace or relax the existing total window. |

Documentation/test-only exemption: this change adds this plan and one new
portable integration test; it changes no production guest semantics or work.
Applicable families are creation-native-path, fork-COW, MM ownership and
thread lifecycle. No N2 implementation, signed/HVF test, Docker oracle or
`just accept` was attempted on this x86_64 Linux box.


## Planning verification

On this Linux worktree, foreground commands completed with exit status 0:

```sh
cargo test -p carrick-el1 --test n2_creation_baseline
cargo test -p carrick-el1 -p carrick-el1-abi -p carrick-sched-core
just fmt-check
git diff --check
```

The first focused attempt failed to compile because HardwareCpu is exported
only for target_os=none; the test now uses an uninhabited NoCpu adapter and
cannot execute hardware operations. The focused and full reruns pass. These
results establish portable source/test consistency only. Signed confirmation,
native ARM64 oracle and the milestone acceptance commands above remain open
for implementation; they do not block completion of this planning task.
