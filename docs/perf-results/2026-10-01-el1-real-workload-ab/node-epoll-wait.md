# Node message-port shard: can its epoll waits stay in the zone?

**Date:** 2026-10-01. **Status:** diagnosis only. Nothing here is
implemented.

**Question.** The node-core `parallel/test-worker-message-port*` shard (26
tests) is the one real workload above the 2x goal: about 2.1 s under Carrick
against 0.97 s under Docker on a quiet host. Its wall time is bounded by
blocked-wait wake latency, and Carrick forwards every `epoll_pwait` to the
host. Could those waits block and wake inside the zone (EL1) without a host
round trip, and what stands in the way?

**Answer.** Yes, structurally. Every epoll set this shard builds contains
only carrick-owned IPC-pool objects: one eventfd and one pipe read end per
libuv loop. No epoll set holds a host-backed fd, and only 0.7 to 1.5% of the
waits are untimed. Three things stand in the way:

1. EL1 has no epoll service. `epoll_pwait` (nr 22) has no arm in the EL1
   dispatcher, so every call is forwarded.
2. Every epoll registration on an IPC object is a host subscription, so each
   EL1-served eventfd or pipe read/write still exits to the host to deliver
   the owed wake. That is another 66k to 73k exits per run, on top of the
   epoll forwards.
3. The wake reaches the waiter through the host, never in the zone: an
   EVFILT_USER trigger, the carrier wait-service reactor, a scheduler wake,
   an executor claim, a host re-dispatch of `epoll_pwait`, and finally a
   vCPU entry.

## Artifact and method

- Tree: `main` at `313a1ab00`, built and signed with `just build`.
  `target/release/carrick`: SHA-256 `bfdc722f404c7d2a862e96c71d28af0f49b947fe43b6a90f18f19ecb6c5b1848`,
  CDHash `68b641e32d1261a5df2f58972d3be8b37b17e6de`, LC_UUID
  `56D5FB15-3AB0-3277-9078-5937ACD453D7`, `__dof_carrick` present,
  hypervisor entitlement applied by `build-signed.sh`.
- Workload argv: exactly as `el1_workload_ab.py plan --check-harness` prints
  it (image `localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0`,
  `--fs host`, `--max-traps` off, entrypoint `nodejs-conformance`). Every run
  printed `All tests passed.`
- **Exact counts, untraced.** `CARRICK_EL1_CENSUS=<dir>` gives the EL1
  served/forwarded counters per syscall, the host services, the
  continuation re-dispatches and the EL1 boundaries. Run ids
  `epdiag-c1`, `epdiag-c3`, `epdiag-c4`.
- **Attribution, traced.** `carrick trace --script
  scripts/dtrace/hvpatch-epoll-wait-zone-census.d` (new, durable). It
  records fd type by creating syscall, epoll set composition at every wait,
  wait outcome, the wake path keyed on the exact `ThreadSerial`, and the
  host CPU spent in `settle_el1_boundary`/`service_host_wake`. Run ids
  `epdiag-t13` through `epdiag-t16`. The script is HIGH-perturbation (7 to
  40 s traced against 4 to 6 s untraced). Its membership counts are exact;
  its latencies and CPU only suggest.
- The host was shared and loaded (load average 17 to 28) throughout. All
  timing here **suggests**; nothing is confirmed. Counts are reliable.

## 1. Which fds the epoll sets watch

From the traced runs; identical in t13, t14, t15 and t16:

| epoll_ctl ADD | count | backing |
|---|---:|---|
| eventfd (libuv `uv_async`, the MessagePort wake) | 112 | in-zone: IPC-pool object (`EventFdState`, `crates/carrick-kernel/src/dispatch/fd_table.rs:157`) |
| pipe read end (from `pipe2`) | 112 | in-zone: IPC-pool `PipeReader` (`crates/carrick-kernel/src/dispatch/fs/pipe.rs:970`) |
| AF_UNIX socket, timerfd, inotify, host socket/pipe/file, pidfd | 0 | none |

There were 224 epoll_ctl calls per run, all ADD with no MOD or DEL traffic,
and 113 `epoll_create1` (one epoll per libuv loop: the main thread plus each
Worker). **Every `epoll_pwait` in every traced run was classed `zone-only`.**

Other fd installs during the run: 1343 files (`openat`), 307 pipes, two
AF_UNIX `socket()` fds and about 10 unclassified. None of them was added to
an epoll set. Forwarded `read`/`write` went to files (about 440 reads and
117 writes); no forwarded read or write touched an eventfd or a pipe.

## 2. Why EL1 forwards each `epoll_pwait`

The sole reason is that **EL1 has no epoll service.** The EL1 entry
`dispatch_syscall` (`crates/carrick-el1/src/personality/dispatch.rs:60`)
reaches `dispatch_syscall_with_lifecycle` (`:259`). Its `match nr`
(`:504`) has arms only for inotify (27, 28), file read/write/lseek/pread/pwrite
(62, 63, 64, 67, 68) and the allocator control. Pipe and eventfd read/write
(`:394`), futex (`:472`), lifecycle calls and anonymous memory are taken
before the `match`. Number 22 falls through to the unconditional forward at
`:641-644`. The entry check at `:306` (pending host work forwards anything
that is not an IPC transfer) would forward it as well, but it is not the
deciding gate: the call has nowhere to go even with no work pending.

None of the other candidate reasons applies to this workload:

| candidate | observed |
|---|---|
| non-zone fd in the set | never (section 1) |
| timeout needing a host timer | about 34 to 39% of calls have a finite timeout, but EL1 already arms per-thread deadlines on the virtual timer (`crates/carrick-el1/src/sched.rs:181-242`, deadline stored at `:228`, expiry at `:373-391`) |
| blocking | 13 to 19% of calls block (`epoll-result` kind 1); EL1 already parks in the zone for futex and pipe/eventfd waits (`crates/carrick-el1/src/sched/object_wait.rs`) |
| signal mask | not measured per call. libuv passes a NULL mask unless `UV_LOOP_BLOCK_SIGNAL` is set; a non-NULL mask can stay forwarded |

Wait mix in the traced runs (t13 and t16; the counts move with timing):

| timeout | t13 | t16 | outcome |
|---|---:|---:|---|
| 0 (poll) | 33 233 | 30 330 | 62 to 70% returned ready, the rest returned empty |
| finite | 21 788 | 15 532 | about 43% blocked on the instance kqueue |
| infinite | 300 | 364 | about 81% blocked |

Untraced census, exact counts:

| run | wall | epoll_pwait forwarded | host CPU in those services | redispatches (blocked, then woken) | write served/forwarded/boundary | read served/forwarded/boundary | all EL1 boundaries |
|---|---:|---:|---:|---:|---|---|---:|
| epdiag-c1 | 4.28 s | 38 590 | 341 ms | 6 378 (75 ms) | 40 511 / 119 / 40 324 | 31 156 / 460 / 30 131 | 71 018 |
| epdiag-c3 | 6.03 s | 43 380 | 535 ms | 10 214 (149 ms) | 40 570 / 119 / 40 386 | 33 012 / 471 / 32 001 | 72 994 |
| epdiag-c4 | 4.02 s | 28 864 | 244 ms | 3 370 (49 ms) | 40 504 / 118 / 40 321 | 25 959 / 452 / 24 932 | 65 826 |

The second structural cost is the `el1_boundaries` column: **99.5% of
EL1-served writes and about 97% of EL1-served reads still return through the
host.** The epoll registration on an IPC object is a host subscription:
`HostIpc::wait_queue` subscribes on enrollment
(`crates/carrick-kernel/src/el1_ipc.rs:547-576`). The epoll's callback
enrollment (`crates/carrick-kernel/src/dispatch/net/epoll_ops.rs:3497`) then
makes `host_subscribers > 0`. Every `IpcObjectGuard::publish`
(`crates/carrick-el1-abi/src/ipc.rs:1872`) then owes the host a wake. The
EL1 adapter marks pending host work
(`crates/carrick-el1/src/personality/ipc.rs:460-461`), and
`leave_served_with_work` returns through the host
(`crates/carrick-el1/src/personality/dispatch.rs:418-419`). The subscription
covers the whole object, not one lane. An eventfd *read* (which publishes
the writers lane) therefore owes a wake to an epoll that only asked for
`EPOLLIN`.

## 3. The wake path and its latency

The forwarded-write path does not occur in this workload. No eventfd or pipe
write was forwarded. All 62k to 75k `EpollKqueue::wake_parked` producer edges
per traced run came from `service_host_wake`, that is, from writes and reads
EL1 had already served. The only other producers were 160 forwarded `close`
calls (worker teardown), 224 other forwarded syscalls and 64 calls outside
any service.

**Path, from a write served in EL1 to the waiter running again:**

1. A WorkerThread calls `write(eventfd)`. EL1 serves it in
   `serve_ipc` → `run` (`crates/carrick-el1/src/personality/ipc.rs:395`):
   `transfer`, `publish` (`host_owed`, because the epoll is a host
   subscriber), `mark_pending_host_work`, then `Returned`.
2. Dispatch returns `leave_served_with_work`
   (`crates/carrick-el1/src/personality/dispatch.rs:418`), and **the
   writer's vCPU exits** to the host.
3. The host runs `settle_el1_boundary`
   (`crates/carrick-kernel/src/el1_delegation.rs:48`) →
   `deliver_ipc_host_wakes` (`crates/carrick-kernel/src/kernel/core.rs:1270`) →
   `HostIpc::service_host_wake` (`crates/carrick-kernel/src/el1_ipc.rs:611`) →
   `WaitQueue::wake_all` → the epoll callback enrollment
   (`epoll_ops.rs:3497`) → `EpollKqueue::wake_parked`
   (`crates/carrick-kernel/src/dispatch/mod.rs:962`), which triggers
   EVFILT_USER on the epoll's kqueue. The writer then re-enters its vCPU.
4. The waiter had parked as a continuation polling the instance kqueue fd
   (`epoll_ops.rs:2014`, `WaitOnFds`). The carrier wait-service reactor
   (`crates/carrick-kernel/src/kernel/continuation/wait_service.rs`) sees the
   fd readable, and that produces the `hvpatch-scheduler-wake` of the
   Blocked thread.
5. An executor claims the thread (`hvpatch-executor-claim`) and
   **re-dispatches `epoll_pwait` on the host**, draining the kqueue and
   re-sampling readiness. That is the census `redispatches` column.
6. The executor writes the events out, and `vcpu-run-enter` runs the waiter.

**Latency on the EL1-served path** (traced; t16 has n=3570 wakes, t13
n=4447; log2 buckets, so these suggest):

| segment | t16 p50 | t13 p50 | p99 |
|---|---|---|---|
| producer `wake_parked` → scheduler wake | 16–32 µs | 16–32 µs | < 0.5–2 ms |
| scheduler wake → executor claim | 64–128 µs | 64–128 µs | < 8–16 ms |
| scheduler wake → vCPU running | 64–128 µs | 256–512 µs | < 8–16 ms |
| park duration (all epoll waits) | 128–256 µs | 256–512 µs | < 131–262 ms |

The latencies above leave out the writer's own exit and re-entry in step 2.
Host CPU per boundary, traced and inflated by the nested pid probes: about
3.7 to 6.9 µs in `settle_el1_boundary` over 149k to 168k calls per run.

Forwarded `close` path (n=152, worker teardown): producer → wake p50 64–128
µs; wake → run p50 1–2 ms. Those wakes compete with teardown for executors.

Waits woken by their timeout with no producer since the park
(`no-wake-parked-since-park`, n=553 in t16): wake → run p50 64–128 µs.

The in-zone alternative (an EL1 object-wait wake, which EL1 already uses for
futex and pipe/eventfd readers) was not timed here.

## 4. Design sketch: in-zone blocking epoll over in-zone fds

This sketch follows two owner rulings: "Epoll is carrick-owned" (one epoll
state machine, owned by carrick, with no second path) and "Carrick-owned
waiters: probe after enroll" (`WaitQueue` has no generation, so readiness is
re-probed after enrollment).

1. **One epoll record in the shared IPC region.** Add an `IpcBacking::Epoll
   { object }` record next to pipes and eventfds. It holds the interest list
   (member object handle with generation, requested events, data, ET and
   ONESHOT flags, and a per-item consumption sequence), a ready list (a
   bitmap or ring of item indices, set under the member's object lock) and
   the epoll's own object-wait key. It also keeps a count of host-backed
   members and of host subscribers to the epoll itself.
   This record *is* the epoll state for both venues: the host's
   `epoll_ctl`/`epoll_pwait` read and write it as well. Host-backed members
   keep the kqueue only for their own readiness, so no second epoll model
   exists.
2. **Member back-links instead of host subscriptions.** A member object
   carries a short list of (epoll, item) links, the BSD knote/knlist shape.
   `IpcObjectGuard::publish` walks the links under the object lock: it marks
   the item ready in the epoll record and queues an `ObjectWakeEffects` on
   the epoll's wait key. The host is owed a wake only when the *epoll* has a
   host subscriber (nested in a host `poll`, or a host-parked waiter) or the
   member itself has one. Links are lane-aware: an `EPOLLIN`-only item does
   not fire on a writers-lane publish.
3. **`epoll_pwait` in EL1** (a new arm before `dispatch.rs:504`). If the
   epfd backs onto a zone epoll with no host-backed members and a NULL
   sigmask: harvest the ready list. For each item, re-read the member's
   level under its lock, apply LT, ET or ONESHOT, and copy events with the
   validated user copy. With nothing ready and `timeout == 0`, return 0.
   Otherwise snapshot the epoll wait epoch, enroll, **re-probe** the ready
   list and the members, then park with `park_object` (the SVC is the
   resumption PC, as for pipes) and a deadline from the timeout on the EL1
   virtual timer. Pending host work at park time follows the existing rule:
   park in the zone, leave `Idle`, and the host settles the thread and
   delivers a signal as EINTR.
4. **The host stays involved only at real crossings.** A host-backed member
   forwards the call (today's path). A host waiter on the epoll keeps a host
   subscription on the epoll record, not on each member. `epoll_ctl` can
   stay host-served: it ran 224 times per run.
5. **Contracts first** (`carrick-conformance-contract`): red-first
   `carrick-conformance-next` probes for a two-thread and a two-process
   eventfd ping-pong through epoll, with a structural budget of zero host
   exits per round trip and zero host epoll services. Further probes:
   LT/ET/ONESHOT across EL1 and host venues, a timeout (0, finite, infinite),
   EINTR from a signal while parked, and close-while-waiting. Run the probe
   with the default pool exhausted.

**What it would remove** (counts exact, time estimates suggest only):

- **All forwarded `epoll_pwait` calls:** 28.9k to 43.4k per run (the
  director's 38k), because every set is zone-only. 60 to 75% of them are
  `timeout=0` polls. In EL1 such a poll becomes a ready-list check with no
  exit. Today each one costs a vCPU exit plus about 8.8 µs of host service
  CPU (census: 341 ms over 38.6k calls).
- **The owed-wake boundaries:** 66k to 73k per run. With no host
  subscribers on members, an EL1-served write or read no longer exits. The
  traced host cost was 3.7 to 6.9 µs of `settle_el1_boundary` each, plus
  the exit and re-entry.
- **The blocked-wake host hop:** 3.4k to 10.2k re-dispatched waits per run.
  Each pays the director's 45 to 70 µs of carrier CPU and, traced, a
  producer → running p50 of roughly 100 to 500 µs through the reactor,
  scheduler, executor and re-dispatch. In the zone this becomes an EL1
  object-wait wake.
- **Wall time:** the shard's gap to Docker is about 1.13 s (2.1 s against
  0.97 s). The waits sit on MessagePort ping-pong chains between threads, so
  most of the per-wake host hop lies on the critical path. Removing the host
  hop from the 3.4k to 10.2k blocked wakes, and the exits from 30k timeout=0
  polls and about 70k boundaries, **suggests 0.4 to 0.8 s of that 1.13 s.**
  That would bring the shard to roughly 1.3 to 1.7 s, about 1.4x to 1.8x
  Docker. This estimate is not measured: the in-zone wake cost was not
  timed, and the traced latencies come from a perturbed run on a loaded
  host. Confirm it with an untraced A/B on a quiet host once a prototype
  exists.

## Open

- The per-call signal mask of `epoll_pwait` was not recorded (the args probe
  carries arg0 to arg3; the mask is arg4).
- The latency of the in-zone wake (EL1 `notify_object` → SGI → waiter
  running) was not measured. It is the denominator of the gain estimate.
- In the 313a1ab00 build the event-ring FDOPEN record and
  `event_ring_host_fd` are inlined into the install helpers. The script
  therefore reads backing from the fd type, which is exact for eventfd, pipe
  and socketpair but `unknown` for the two AF_UNIX `socket()` fds (neither
  was in an epoll set).
