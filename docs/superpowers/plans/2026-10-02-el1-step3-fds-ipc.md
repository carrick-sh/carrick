# EL1 migration step 3: descriptor and IPC ownership

Design pass, 2026-10-02. Source inspected: `4c4d06b4c345550da68b4b8cd44dfd8f6e53457b`.
This document proposes implementation milestones; it claims no implementation
or runtime acceptance. Only this document is changed by this design pass.

Authorities: [design of record](../specs/2026-09-24-el1-kernel.md),
[rulebook](../../../AGENTS.md), [contracts](../../conformance-contracts.md),
[active controller](2026-09-26-el1-completion.md),
[lifecycle plan](2026-09-30-el1-thread-lifecycle.md), and
[fork/exit investigation](../../perf-results/2026-10-01-el1-forkexit-investigation.md).
The owner approved finishing the migration. Each cutover deletes its displaced
host semantics in the same landing; adding an EL1 implementation beside a
host implementation is not an independently landable milestone.

## Outcome and boundary

EL1 is the single owner of guest descriptor namespaces, OFD identity, offsets,
status flags, descriptor flags, pins, finalization, pipes, AF_UNIX, eventfd,
in-zone readiness, and Linux signal disposition/queue/delivery. Fork copies
slots and shares OFDs; CLONE_FILES shares the table; exec unshares before its
CLOEXEC sweep. In-flight I/O and SCM_RIGHTS own exact OFD pins, never a reusable
fd number. Two containers with equal numeric ids must remain isolated.

The host retains contained host-file and external-socket handles and the CLI
terminal. It validates owner generation, containment, quotas and request
extents. File bytes travel with explicit offsets; namespace operations remain
host operations until step 4. Host socket readiness becomes completion input,
not another guest epoll or fd table. Host requests are asynchronous: a waiter
releases guest execution capacity; completion wakes the exact operation.
No guest pipe, AF_UNIX endpoint, eventfd or signal queue needs a host fd.

Reuse `carrick-fd-core`, `carrick-pipe-core`, the shared IPC records and the
scheduler's object waits. HVF executes the shared cores at EL1. Other backends
execute those same cores in-process through adapters until their privileged
venue exists; they must not retain the old semantic implementations. x86
ring-0 remains deferred, as the controller directs.

A single core with two execution venues is permissible; two mutable models
of the same object are not. A host hypercall handler may allocate backing,
validate an external operation or publish a completion. It may not choose a
guest fd, advance a guest cursor or separately release a guest OFD. Diagnostics
and /proc read the authoritative records; immutable classification and host
resource custody are not functional copies.

### Scope edges that must be explicit

Timerfd, inotify, pidfd, synthetic files/devices, guest ptys, netlink and local
TCP appear in `OpenDescription`. Their descriptors and OFD metadata join the
one table in M1 even when their object payload is outside this step. This
plan does not claim those payloads have moved. Their adapters access the same
records and cannot maintain private flags or cursors. Timerfd/signalfd readiness
and signal-generated timer events must compose with M3/M5; the host clock is
input, not guest signal authority. Dentry/page-cache policy and full fork/exec
orchestration remain steps 4/5. Host-side fork/exec orchestration must invoke
the one table lifecycle operation meanwhile.

## Inventory of the current implementation

Paths below are relative to the repository. Names are existing symbols,
not proposed APIs; proposed contracts and ABI additions are labeled below.

| Surface | Current code and ownership seam |
|---|---|
| Descriptor model | `crates/carrick-kernel/src/kernel/objects.rs`: `FileTable` owns `open_files`, `next_fd`, `reserved_slots`, stdio markers, functional gates and subscriptions; `for_fork_copy` clones the host slot map and retains descriptions. `FileDescription` owns functional references, pins and epoll-owner notifications. |
| Guest projection | `kernel/objects/ipc.rs` under the same crate: `Binding::new`, `sync_slot`, `sync_stdio`, `FileTable::publish_ipc`, `sync_ipc_slot`, `retire_ipc`. The host map serializes publication into `HostTable`, so the shared table is still a projection. `kernel/continuation/ipc.rs::publish_file_table` installs that binding at boundaries. |
| Shared table | `crates/carrick-fd-core/src/lib.rs` and README: `Core`, `Authority`, `OfdPin`, table generations, shared offsets/flags, bitmap allocation, fork, exec, unshare and final-release callbacks. `crates/carrick-kernel/src/el1_ipc/table.rs::HostTable` wraps creation, replacement, close, fork, exec and destruction. |
| OFD backing | `dispatch/fd_table.rs`: `OpenDescription`, `OpenDescriptionBase`, backing-specific cursors, `EventFdState`, `EpollInterest`, host fd custody. `dispatch/fs/fd_helpers.rs`: `first_free_fd`, `reserve_slot_at_or_above`, installation helpers, `open_file_with_authority`. `dispatch/fs/close_dup.rs`: `duplicate_fd`, `duplicate_fd_to`, `dup`, `dup2`, `dup3`, `close`, `close_range`. `dispatch/fs/locks.rs` contains fcntl/record-lock policy and `register_logical_lock_retirement`; close-time lock cleanup is not just final-OFD cleanup. |
| Pipe | `dispatch/fs/pipe.rs`: `PipeInner` already uses shared IPC object state; `HostEndpointOwnership`, endpoint leases, `read_pipe`, `write_pipe`, `PipeWriteOperation`, `wait_for_pipe_readable`, `pipe2`, `set_capacity`, `take_pipe_bytes`, `tee_in_memory_pipes`, `transfer_in_memory_pipes`. `read_poll_fd`/`write_poll_fd`, `prime_channel`, `update_readiness` build host readiness proxies. |
| Eventfd | `dispatch/fd_table.rs::EventFdState::{create,read_with,write_value}` operates on a shared counter, not a copied host counter. `dispatch/net.rs::eventfd2` still creates and installs it through host dispatch. |
| IPC records and execution | `crates/carrick-el1-abi/src/ipc.rs`, `ipc/epoll.rs`: `IpcDirectory`, `IpcRegion`, `IpcBacking`, `IpcOperation`, `IpcOpToken`, object generations, subscriptions, epoll membership/harvest. `crates/carrick-el1/src/substrate/ipc.rs::transfer` is shared transfer logic; `personality/ipc.rs::serve_ipc` and `personality/ipc/epoll.rs::serve` decode Linux calls. `sched/object_wait.rs` parks in the zone. |
| Host completion | `crates/carrick-kernel/src/kernel/continuation/ipc.rs`: `ZoneHostServices`, `take_handback`, `interrupted`, `finish`, `interrupt`, `complete_handback`. Partial writes resume at `progress.written`; cancellation and final pins are owned. `kernel/continuation.rs`: `BlockedContinuation`, `SignalMaskContinuationState`, `WaitOnFdsSelect`, `WaitOnPollFds`, `WaitOnSignals`; `continuation/wait_service.rs` is the carrier wait service. |
| Readiness | `dispatch/net.rs::poll_ready_events`, `pselect6`, `ppoll`; `dispatch/net/epoll_ops.rs` is host epoll dispatch; `epoll_zone.rs::ZoneEpoll` bridges shared epoll creation/control/harvest. `fd_table.rs::EpollInterest` still holds host sampling/edge fields. Zone `epoll_pwait` over pipe/eventfd members is already landed; do not reimplement it. |
| AF_UNIX | `dispatch/net/lifecycle.rs`: `socket`, `socketpair`, `bind`, `listen`, `accept`, `accept4`, `connect` mix host and pure socket branches. `unix_pure.rs::PureSocketInner` owns stream/datagram state, shutdown, readiness and credentials; `UnixSocketRegistry` owns abstract/pathname registration. That file also contains local TCP behavior: deleting the whole file would remove unrelated functionality. `send_recv.rs` and `sockopt.rs` decode data/ancillary/option behavior. |
| Rights transport | `dispatch/net/scm_rights.rs::VAULT`, `park`, `claim`, `gc`, `InFlightRights`: host pipe placeholders retain guest descriptions across host-backed AF_UNIX messages. This is guest-to-guest transport to delete, not the final hypercall design. True host-peer received fds still need a validated import. |
| Signals | `dispatch/signal.rs`: `SignalView`, syscall handlers, `route_thread_signal`, `hvpatch_exact_process_signal`, `hvpatch_specific_thread_signal`, queued-info and host/xsignal routing. `kernel/objects/signal.rs`: `Sighand`, `PendingQueue`, `TaskPendingSignals`, `ThreadSignalState`, `SignalAuthority`, dequeue/reservation and handler-frame ownership. `crates/carrick-runtime/src/vcpu_loop/signal.rs`: `deliver_fault_signal`, `deliver_pending_signal_with_restart`, `deliver_reserved_signal_with_restart`, `deliver_signal_with_restart`; `vcpu_loop/binding.rs` completes sigreturn. |

Existing ABI constraints are not the end-state allocation policy:
`IPC_FD_TABLES=256`, `IPC_OPERATIONS=1024`, segmented object/OFD stores and
`IPC_RING_STOCK=512`. Current refusal comments permit host-only tables or
forwarded allocation. M1/M2 must replace that with growth of the same owner
or a genuine Linux resource error before effects. Exhaustion cannot reactivate
the deleted host table. Keep backing elastic, return retired extents, never
map Rust pointers, Arc headers or host locks into the guest aperture.

## Cost ranking and entry dependencies

The design's post-1d profile measured **13% syscall service**, **11% process
and page-table work**, **68% guest execution including exits**, and **1% host
scheduling** on go build. This is an unpaired historical profile, not a current
per-subsystem breakdown. It does not justify calling any particular fd/IPC
operation 13% of CPU or predicting a 13% workload saving.

Prioritize the fd foundation and pipe lifecycle/poll because the lifecycle
plan explicitly identifies forwarded `pipe2/close/poll/ppoll` as residual
fork-round work. Preserve the landed eventfd/epoll wait gain rather than
rewriting it: `kernel.el1.epoll-zone` records 29k–43k forwarded epoll_pwait
and 66k–73k EL1 boundaries on the earlier node MessagePort workload.
AF_UNIX and full delivery follow by dependency, not an invented measured
ranking. Refresh the carrier CPU census and syscall distribution on the
previous main and after every milestone; re-rank independent work only with
completed, attributed operations and uninstrumented paired timing.

The investigation's Phase A checkpoint is 74 passed / six failed signed
EL1 tests, with sigmask/altstack forwarded slopes zero and exit slope about
0.9974. Fork-COW remains 3442 exits against 144, despite correct data. No
step-3 claim may treat zero fault-class exits as zero host COW work. Preserve
independent COW counters and the existing ceiling; no budget edits here.

Dependencies before functional cutover:

- Integrate Phase B settlement, clone/exit identity publication, admission
  closing, exact control-slot teardown and fork/exec cancellation. M1 must
  settle births before selecting a task's table; M5 must target born threads
  immediately and retire queued signals before identity reuse.
- Integrate memory root/descriptor-lane work: retained shared metadata must
  survive host fork, exact owner generation and two-live-MM alias checks;
  mapping retirement must revoke guest references before reuse. Pipe/user
  copy and signal frames depend on correct COW, faults and MM switching.
- Resolve the six recorded signed failures (reservations, concurrent delegated
  VMA ops, MAP_FIXED over COW, fork-COW, TRACECLONE, spawn-slope) with their
  owning work. They remain failures, not a skip list. Contracts can be authored
  meanwhile; no milestone is accepted with a red mandatory suite.
- Coordinate with file-zone/name-resolution work on every OFD cursor and
  `el1_delegation` recall site; M1 removes semantic duplication without moving
  page-cache or namespace policy prematurely. Do not merge stale inventories.
- Ptrace/seccomp must gate or observe the same core, never select an old owner.
  TRACECLONE is separate unfinished functionality in the investigation.

## Landing policy shared by every milestone

For each milestone: add/extend the named contracts red-first, preserve the
pre-change failure and source/fixture hashes, move or extract the one shared
implementation, switch all consumers, delete old writers, then run acceptance.
A compile failure alone does not prove a behavioral defect. Correct existing
semantics may stay green; the new exit/ownership/structural assertion must
have a discriminating red. Register new contract IDs and bindings during
implementation, not in this docs-only pass.

Two live processes are mandatory for all authority witnesses, supplemented
by two live kernels/carriers with equal numeric ids and overlapping user VAs.
Use VM-free core reducers for ordering/refcounts/budgets, signed embed for
EL0 memory and delivery, and same-source native arm64 Docker for semantics.
New executable probes belong in `carrick-conformance-next`; no new CLI
subprocess probe path. All waits are bounded by existing contract deadlines.

Each milestone is default-on. An optional exact `=0` bisection hatch chooses
**execution venue for the same authority**, never a legacy table or another
object implementation; values such as `false` and ` 0` do not disable it.
Proposed temporary names below are policy proposals, not existing APIs.
The cutover commit deletes old semantics. After both venue controls and full
acceptance pass, remove that milestone's hatch and its HVF host-venue branch,
rerun acceptance on the resulting artifact, and only then mark it proven.
A milestone may land for review with its temporary hatch, but cannot be
called proven while it survives. Bisect older commits for the legacy owner.
No default-off rollout, indefinite fallback, retries or timeout inflation.

## M1 — One descriptor table and one OFD authority (Sol)

Outcome: every backing kind, including stdio, resolves through the same
`carrick-fd-core` table. Resource creation returns an opaque backing token;
EL1 installs the descriptor. Shared core operations own dup/close/fcntl flags,
seekable offsets, fork/unshare/exec sweeps and final releases. Until step 5,
host fork/exec calls that same lifecycle core as an adapter. Serialize shared
cursor reservation/commit so concurrent non-positioned I/O cannot overlap;
positioned I/O does not change the cursor, and host append preserves host
atomic append semantics. A failed request rolls back its reservation exactly.
Host handle custody is indexed by token, never a second guest slot map.

Red-first: extend `kernel.fork.filetable`, `kernel.el1.ipc-fd-authority`
(documented in fd-core; register missing descriptor/bindings), and propose
`kernel.el1.fd-single-owner`. Two live forked processes share offsets/status
but not CLOEXEC; CLONE_FILES processes share the table; exec/CLOSE_RANGE_UNSHARE
leave peers intact. Race close/dup2/SCM pins with fd reuse and finalization;
include bare stdio, failed pair copyout, close-time POSIX lock release and
last-pin/mapping release. Use fd-core's 65/4096/65536 scales and add sparse
high-fd fork coverage; preserve bitmap logarithmic lookup/allocation budgets,
zero steady-state allocation and exactly-once release. Reconcile existing
fork-filetable populated-descriptor budgets with backed-capacity scans before
choosing an algorithm; do not silently widen the contract.

Delete in order within this landing:

1. Host slot selection/duplication/stdio-marker logic in
   `dispatch/fs/fd_helpers.rs::{first_free_fd,reserve_slot_at_or_above}` and
   installation helpers, and semantic bodies in `dispatch/fs/close_dup.rs`.
   Rewrite all creation consumers to install in the one table.
2. `kernel/objects/ipc.rs::Binding` projection, `sync_slot`, `sync_stdio`,
   `publish_ipc`, `sync_ipc_slot`, projection-aware guard mirroring and
   `kernel/continuation/ipc.rs::publish_file_table`'s snapshot admission.
   Publish table identity once, not host contents on each boundary.
3. `FileTable`'s `open_files`/`next_fd`/reserved-slot and stdio authorities,
   `for_fork_copy`/exec host-map scans and independent FileDescription fd
   reference accounting. Keep observers as core views. Delete backing cursor
   and status copies in `dispatch/fd_table.rs` and file-zone recall/copy paths
   only after every reader, mmap pin, lock cleanup and /proc view is converted.
   Retain host-file byte/mapping custody and lock backends.

Temporary hatch proposal: `CARRICK_EL1_FDS=0`, same-core venue only.
Acceptance: all commands in A below, plus focused fd-core tests and the new
signed two-process binding. Sol owns this cutover: cross-backing pins, exec,
file zone and observers make it unsuitable for a Flash implementation brief.

## M2 — Pipe/eventfd creation, I/O, close and continuations (Sol cutover)

Depends on M1 and Phase B/memory bindings. The pipe/eventfd record already
exists; move lifecycle and remaining operation ownership, not a second ring
or counter. EL1 creates pipe2/eventfd2, manages capacity/ring backing and
final endpoint release, executes read/write/readv/writev and resumes partial
operations. Growth asks the host for bulk metadata/frame backing; the host
cannot allocate a guest fd or run the pipe operation. Keep PIPE_BUF atomicity,
lazy ring allocation, F_GETPIPE_SZ/F_SETPIPE_SZ, splice/tee ownership and
host-file-to-pipe transfers. A genuine file byte crossing uses a hypercall,
while pipe-to-pipe transfer remains internal.

Red-first: extend `kernel.el1.ipc-two-process`; propose
`kernel.el1.ipc-lifecycle`. Two live processes close/reuse numeric descriptors
while a blocked write holds its endpoint; exhaust the default executor pool
with 32 writers and a runnable reader. Test EOF/EPIPE/SIGPIPE, zero-length
writes, eventfd semaphore/max-counter overflow, nonblock, faults after partial
progress, signal restart and exec/exit cancellation. Reuse ABI tests
`el1_ipc_blocked_write_resumes_from_its_continuation_without_replay` and
`el1_ipc_two_processes_with_overlapping_user_vas_complete_their_own_reads`.
At 1/8/64 pairs and three creation counts require zero per-operation host
semantic dispatch slope, no allocation in backed steady-state transfers,
linear byte/affected-waiter work, no replay and balanced pins/ring return.
Resource-pressure growth must not strand a waiter or revive old semantics.

Delete: `dispatch/fs/pipe.rs` host `pipe2`, `read_pipe`, `write_pipe`,
`PipeWriteOperation`, `wait_for_pipe_readable` and endpoint ownership/close
machinery once all callers use the shared core; move its splice/tee logic to
the one implementation rather than dropping support. Delete
`fd_table.rs::EventFdState` semantic wrapper and host `net.rs::eventfd2`
creation body. Remove host semantic handback completion in
`kernel/continuation/ipc.rs::{interrupted,finish,interrupt,complete_handback}`
for these objects and their runtime callers; preserve only completion/cancel
adapters needed by real host crossings and other backends using the same core.
Do not delete readiness proxies yet: M3 owns their remaining mixed-wait users.

Temporary hatch proposal: `CARRICK_EL1_IPC_LIFECYCLE=0`, same-core venue.
Acceptance: A plus all inherited IPC contracts and new lifecycle bindings.
Flash can implement bounded ABI/core fixture additions after Sol fixes the
contract and ownership brief; Sol implements growth, continuation integration,
splice and final cutover. A fixture-only patch is not M2 acceptance.

## M3 — One readiness/wait owner, including mixed sets (Sol)

Depends on M1/M2. Keep landed zone epoll harvest; move epoll creation/control
and poll/ppoll/select/pselect decode and enrollment to EL1. All-zone sets
park and wake through object queues; mixed sets combine host readiness
completions and zone notifications in one EL1 wait. The host owns only
external multiplexer subscriptions, tagged with operation/registration
incarnation. Ready snapshots must not retarget to a recycled fd.

Red-first: extend `kernel.el1.epoll-zone`; propose
`kernel.el1.poll-select-owner`. Two live processes share an epoll OFD while
closing/reusing target fds; cover fork aliases, last-OFD detach, nested epoll
cycle rejection, LT/ET/ONESHOT, maxevents, stale completions, POLLNVAL versus
select EBADF, timeout zero/finite/infinite, copyout faults and simultaneous
host/zone readiness. For ppoll/pselect/epoll_pwait use the Phase A control
slot's mask; atomically install/enroll/recheck and restore exactly once on
ready, timeout, EINTR and cancellation. Delivery stays with its current single
owner until M5. Test an external socket and pipe in one set with a peer
process, and a signal during WFI/host completion. At 1/8/64 members require
zero all-zone host semantic dispatch slope and queue work proportional to
registered/ready members, not unrelated object population; no periodic scan.

Delete: all-zone semantic branches of `dispatch/net.rs::{pselect6,ppoll,
poll_ready_events}` and host `epoll_ops.rs` creation/control/wait semantics;
replace `epoll_zone.rs::ZoneEpoll` host control/harvest owner with adapters.
Remove in-zone `EpollInterest` sampling and software edge-latch state in
`fd_table.rs`; retain external readiness tokens as completion inputs.
Then delete pipe `prime_channel`, `update_readiness`, `read_poll_fd`,
`write_poll_fd` and leases retained solely for host proxies, and eventfd
host subscription/proxy use for guest waiters. Remove pure-zone
`WaitOnFdsSelect`/`WaitOnPollFds` semantic completion paths from
`kernel/continuation.rs` and readiness/wait-service modules. Keep host wait
service for true host I/O; do not remove it globally.

Temporary hatch proposal: `CARRICK_EL1_WAITSETS=0`, same-core venue; retire
existing `CARRICK_EL1_EPOLL=0` with this acceptance. Acceptance: A, inherited
zone pingpong and new mixed-set/mask contracts. Sol required for enrollment,
signal masking, ET state and stale completion authority; Flash is suitable
only for separately specified decode/errno fixtures.

## M4 — All guest AF_UNIX objects and ancillary data (Sol)

Depends on M1–M3. One AF_UNIX core handles socketpair and named sockets,
STREAM/DGRAM/SEQPACKET, abstract and pathname addresses, bind/listen/connect/
accept/shutdown, options, byte/message queues, readiness, credentials and
rights. Pathname lookup/permission and socket-node creation still request
contained namespace operations until step 4; socket protocol state is EL1's.
SCM_RIGHTS carries owned OFD pins; receiving allocates descriptors in the
receiver's table with MSG_CMSG_CLOEXEC and Linux truncation/failure rules.
Credentials name the guest sender at the required send/connect instant,
including SO_PEERCRED/SO_PASSCRED, never the carrier's Darwin uid/pid.

Red-first: propose `kernel.el1.unix-owner` and `kernel.el1.unix-rights`.
Two live processes send a pipe writer/eventfd/epoll/host-file description,
close the sender alias before recv, reuse that number, and require original
flags/cursor/EOF lifetime at the receiver. Include queued-message socket
close, cyclic rights graphs and bounded reclamation, ancillary truncation,
fault rollback, peer credentials, backlog/nonblock, stream partial writes,
datagram boundaries/peek/truncation, seqpacket, shutdown/HUP and pathname
unlink/rebind. Use two namespaces with identical abstract/pathname bytes.
Scale 1/8/64 sockets/messages: zero guest-to-guest host fd creation or transport
calls, linear queued-byte/pin work and no historical VAULT scans. Extract
semantics from clean-room specs/oracle, never GPL kernel sources.

Delete AF_UNIX host and pure branches in `net/lifecycle.rs`, `send_recv.rs`,
`sockopt.rs` after all guest AF_UNIX consumers resolve the one core. Delete
AF_UNIX portions of `unix_pure.rs::{PureSocketInner,UnixSocketRegistry}`
including `register_abstract`, `register_pathname`, send/recv and poll behavior;
extract shared/local-TCP users before removal, not a blanket file deletion.
Delete guest-to-guest `scm_rights.rs::{VAULT,park,claim,gc,InFlightRights}`
placeholder transport and its lifecycle/send-recv call sites. Real host-peer
socket crossings retain explicit host backend adapters, including validated
fd import/export; they must not route ordinary guest peers through placeholders.
Do not retain an unreachable legacy AF_UNIX branch behind a hatch.

Temporary hatch proposal: `CARRICK_EL1_UNIX=0`, same-core venue.
Acceptance: A plus socket/rights Docker differential and signed two-process
bindings. Sol required: namespace identity, message pin lifetime, cyclic
reclamation and host-peer boundary remain architectural work. Flash may
implement bounded layout/decode tests after those decisions are fixed.

## M5 — Signal queues, routing and delivery at EL1 (Sol)

Depends on Phase B and M1–M4 wait/cancel ownership. Phase A blocked masks and
altstack are reused in place. Move Sighand and task/thread pending queues,
action snapshots/reservations, permission checks and selector routing, signal
frames, restart decisions and rt_sigreturn to one EL1 personality core.
Deliver at every EL0 return, including compute-loop IRQ and fault returns,
not only forwarded syscall boundaries. Host terminal/core/exit-status events
become authenticated inputs/outputs; the host does not select a guest signal
recipient. SIGCHLD and job-control stop/continue compose with current host
process orchestration through the same identity authority pending step 5.

Red-first: extend `kernel.signal.lease-gap`,
`kernel.el1.thread-lifecycle`, `kernel.signal.job-control-wait-interruption` where
applicable; propose `kernel.el1.signal-delivery-owner`. Two live processes
with multiple threads race tgkill against born-thread publication, mask
changes, exit/reuse, fork and exec; check permissions/sender siginfo and
CLONE_SIGHAND sharing. Standard signals coalesce, realtime payloads stay FIFO;
fork clears pending, exec preserves required pending/mask and resets caught
actions/altstack. Test SA_RESTART/SA_NODEFER/SA_RESETHAND, interrupted partial
pipe/socket I/O, ppoll/pselect masks, sigsuspend/sigtimedwait/signalfd,
SIGSTOP/SIGCONT/SIGKILL, queued SIGCHLD, nested altstack frames, siglongjmp,
fault signals and malformed sigreturn frames, guest-visible PSTATE, tracing
and seccomp. At 1/8/32/128 targets require no population scan for exact thread
routing and zero host semantic dispatch slope for repeated in-zone delivery;
queues charge/return SIGPENDING resources and teardown leaves no stale pins.

Delete semantic handlers/routing/pending consumption in `dispatch/signal.rs`,
`kernel/objects/signal.rs::{Sighand,PendingQueue,TaskPendingSignals,
ThreadSignalState,SignalAuthority}` as host-owned implementations after every
observer is a core view. Move shared pure logic, do not duplicate it.
Delete guest frame/delivery/restart bodies in
`runtime/vcpu_loop/signal.rs::{deliver_fault_signal,
deliver_pending_signal_with_restart,deliver_reserved_signal_with_restart,
deliver_signal_with_restart}` and host sigreturn restoration in `binding.rs`.
Remove host signal-mask restoration and guest-signal wait completion in
`kernel/continuation.rs` and guest-directed xsignal/host-kill transport branches.
Retain host signal capture for genuine terminal/platform events as input,
and host core-file writing/CLI status as output, without guest semantics.

Honor the design's personality split: bitsets, neutral queue/timer mechanisms,
frames storage and scheduling remain substrate; Linux numbers, siginfo/frame
layouts and restart classes belong to personality. Inspect
`carrick-signal-core`/`carrick-timer-core` dependencies and update the mechanical
boundary gate rather than hard-coding Linux values in scheduler/ABI substrate.
The image already has `personality/` and `substrate/`; extend that structure.

Temporary hatch proposal: `CARRICK_EL1_SIGNAL_DELIVERY=0`, same-core venue;
retire overlapping Phase A mask hatches when their owner is fully proven.
Acceptance: A plus all signal/thread lifecycle bindings and both-libc signal
oracle rows. Sol required throughout production cutover. Flash is appropriate
for precise layout/roundtrip fixtures only after Sol specifies the frame ABI.

## A — Mandatory acceptance for each M1–M5

Each milestone references this entire block, including the creation workloads;
none substitutes its focused tests for it. Run on the integrated milestone,
and again after hatch removal. No runtime commands are executed by this
design pass.

Cheap-layer commands, followed by host CI and signed acceptance:

```sh
cargo test -p carrick-fd-core -p carrick-pipe-core -p carrick-el1-abi -p carrick-el1 --lib
just test-kernel
just ci
CARRICK_RUN_ID=step3-Mn-el1 ./scripts/test-signed.sh carrick-embed el1_ --nocapture
just el1-gate
just --no-deps conformance smoke
just --no-deps conformance full
```

Replace `Mn` with the milestone and give each attempt a unique ID. Use the
rulebook's serial-host partition for any newly added host-mutating tests.
`just el1-gate` builds/signs the CLI and signs embed tests separately: record
each executable's identity, not one fictitious artifact for both. Freeze the
final CLI from that gate for promotion and performance. No guest may be live
during rebuild; no relink or re-sign between CLI rungs. Rebuild after merge,
not just in a worker branch. Negative entitlement control must pass; inspect
SHA-256, CDHash, LC_UUID, entitlement and DOF, source/fixture/image identity,
both raw streams and run-ID scoped cleanup for every receipt. Freshly build
and hash both libc probe sets before claiming their oracle coverage.

Paired ecosystem correctness commands use existing harness options
(`crates/carrick-conformance/src/main.rs`), immutable signed paths supplied
by the director, and a frozen source-valid oracle. First deliberately refresh
Docker after all Carrick runs stop if the images/declarations changed.

```sh
cargo run -p carrick-conformance -- --carrick-bin "$step3_base_bin" --require-cached-oracle --suite go-build --suite cpython-threading --suite cpython-subprocess --jsonl "$step3_out/base-ecosystems.jsonl"
cargo run -p carrick-conformance -- --carrick-bin "$step3_candidate_bin" --require-cached-oracle --suite go-build --suite cpython-threading --suite cpython-subprocess --jsonl "$step3_out/candidate-ecosystems.jsonl"
```

For timing run the exact suite commands/images/flags from
`scripts/conformance/suites.toml` through its `argv::carrick_argv` launch
shape, measuring each invocation separately with `/usr/bin/time -l` and unique
run IDs. Use three fixed ABBA rounds (six observations per artifact), cold
Go cache as declared, identical image digests and --fs host. Report wall and
carrier CPU separately; harness Cargo CPU is not carrier CPU. Preserve all
failed observations; ABBA is a measurement design, not retry-until-green.
Use the pinned Docker counterpart in a later serial phase. A migration
regression is reported per the spec, with its attribution and next owner;
it is not a performance win or completion of the <=2x end-state goal.

Per-operation creation commands are already implemented in
`crates/carrick-xtask/src/impact.rs` and declared in
`scripts/perf/manifests/impact-creations.toml`/`impact-windows.json`:

```sh
cargo run -p carrick-xtask -- impact carrick --artifact "$step3_base_bin" --samples 10 --workload spawn-loop --workload thread-spawn --workload fork-exec --out "$step3_out/base-creations.json"
cargo run -p carrick-xtask -- impact carrick --artifact "$step3_candidate_bin" --samples 10 --workload spawn-loop --workload thread-spawn --workload fork-exec --out "$step3_out/candidate-creations.json"
cargo run -p carrick-xtask -- impact docker --samples 10 --workload spawn-loop --workload thread-spawn --workload fork-exec --out "$step3_out/docker-creations.json"
cargo run -p carrick-xtask -- impact report --base "$step3_out/base-creations.json" --candidate "$step3_out/candidate-creations.json" --docker "$step3_out/docker-creations.json" --out "$step3_out/creations.md"
```

Set the three shell variables to preserved base/candidate executable paths
and an evidence directory before running. The tool does not currently expose
go-build/cpython rows as impact workloads; use the ecosystem commands above,
not invented `impact --workload go-build` options. Build/hash
`conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec`
first. Defaults are 1000 spawn-loop, 1000 thread-spawn and 200 fork-exec ops;
`--operations` changes only the first two and is for smoke, not acceptance.
Require one excluded warm-up, ten completed measured samples, exactly one
nonzero guest timing window, per-op denominators, matching declaration/probe
hashes and no cleanup/timeout errors. Impact timing is observational, not a
replacement for registered structural or <=2x Docker contracts. Run base and
candidate batches on a quiet host, pair batch order across milestones and
report noise; do not assert a controlled gain from a single batch.

Finally inspect the diff/deletion census: enumerate remaining callers of every
removed writer above, demonstrate zero old semantic owners, reconcile pinned
inventories on clean committed sources, and run `just lint-domains`. Retain
other-backend adapter compile coverage and state pending hardware lanes
explicitly. Add the milestone's as-built note to the design of record during
implementation. This plan commit does not authorize a push.

## Risks and decisions still requiring implementation design

- M1 is broad because every descriptor kind participates. Splitting it into
  parallel fd namespaces would reintroduce the root defect. Extraction-only
  review commits can precede it, but cannot claim ownership migration.
- Exact cursor reservation, external append atomicity, async owner/O_ASYNC,
  close-time record locks and mapped-file pins need an explicit per-backing
  transition census before M1 code. The existing fd core is a foundation,
  not proof that all those consumers already use it.
- Metadata growth and shared-page mapping under COW/exec must be transactional.
  Removing host fallback reveals real capacity limits; do not turn a storage
  request into EMFILE, freeze a fixed RAM pool or silently lose functionality.
- Host completion cancellation versus last close must retain one operation
  and one pin. No lock spans user copy, a host request, context switch or WFI;
  preserve member-before-epoll ordering and enroll/recheck wake discipline.
- AF_UNIX rights cycles, pathname identity and real host peers are not fully
  specified by the present shared ABI. Sol must fix concrete layouts and
  reclamation budgets in a reviewed implementation brief before delegation.
- Signal delivery couples scheduler ownership, masks, reserved actions,
  ptrace/job control, fault contexts and restart semantics. Porting only the
  handler builder leaves a second owner; M5 must retire the entire delivery
  transaction and all host-return callers together.
- Live EL1 is harder to inspect. Extend authoritative counters/census/event
  records and durable trace profiles; zero events mean missing evidence.
  Instrumented runs cannot supply uninstrumented workload timing.
- Scope is large and other workers are editing lifecycle/MM. Rebase the source
  census before each cutover. Preserve unrelated dirt; no stash, blanket sync,
  budget changes or acceptance exclusions. Default executor exhaustion and two
  live process coverage are mandatory; increasing the pool hides the defect.

All production cutovers require Sol. Gemini Flash tasks are precise only for
bounded red fixtures, ABI layout tests and byte-identical core extraction
with an explicit symbol fence and acceptance command. No milestone as a whole
is Flash-ready today. The director reviews every deletion and owns integrated
signed/runtime acceptance; worker reports alone do not establish completion.
