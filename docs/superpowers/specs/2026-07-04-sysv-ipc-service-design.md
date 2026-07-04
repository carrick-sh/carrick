# SysV IPC service design

Date: 2026-07-04

## Context

The LTP 20260529 re-bless exposed a SysV IPC cluster:

- `ltp-msgctl*`
- `ltp-msgget*`
- `ltp-msgrcv*`
- `ltp-msgsnd*`
- `ltp-msgstress01`

Carrick currently runs Linux processes as real host processes, with a
hardware-virtualized vCPU per guest thread and a Rust syscall translation layer.
Guest thread scheduling is already a separate M:N concern: it decides when guest
threads get scarce vCPU execution resources. SysV IPC is a different domain. It
is a Linux kernel object service shared by processes, not a property of the guest
thread scheduler.

The `msgstress01` trace showed two separate issues:

1. A real fork/admission pressure point: one child reached `msgsnd`, filled the
   queue, then looped on `EAGAIN`; the paired reader had not reached `msgrcv`
   because it was delayed in fork/HVF VM rebuild and global VM permit admission.
2. A broader throughput mismatch: once the immediate fork-admission issue was
   mitigated, small reduced runs completed, but the default LTP stress workload
   remained structurally too large for a file-backed message-queue hot path.

Changing `/proc/sys/kernel/threads-max` to make LTP choose fewer queues is not
the right architecture. It conflates guest thread capacity, host process fanout,
and SysV IPC throughput. `threads-max` should not become a hidden test-shaping
knob.

## Goals

- Model SysV message queues as Carrick-provided Linux kernel objects shared by
  real forked Carrick host processes.
- Preserve Linux-visible semantics for queue identity, permissions, limits,
  accounting, blocking, `IPC_RMID`, `msgctl` queries, and `/proc/sysvipc/msg`.
- Keep M:N scheduling separate from IPC capacity and queue behavior.
- Avoid per-message filesystem rewrites or polling sleeps in the hot path.
- Use typed domain values and bitflags at service boundaries.
- Provide deterministic conformance probes for wakeup and fanout behavior before
  relying on broad LTP verdicts.

## Non-goals

- Do not read Linux kernel source to implement this service. Behavior must come
  from man pages, Linux ABI documentation, and the differential Docker oracle.
- Do not emulate Linux by delegating to Darwin SysV message queues. Darwin's
  limits, namespace, and global behavior are not suitable for Carrick's Linux
  ABI model.
- Do not use POSIX message queues or Mach ports as the public SysV abstraction.
  They do not directly model SysV keys, ids, type-selective receive, `msgctl`,
  or `/proc/sysvipc/msg`.
- Do not tune `/proc/sys/kernel/threads-max` to pass `msgstress01`.
- Do not add known-gaps, baseline edits, shell wrappers, or suite-specific
  harness overrides.

## Architecture

Introduce a `SysvIpcService` boundary owned by the runtime. Dispatch handlers
call the service; they do not own queue persistence or wakeup mechanics.

The service owns:

- message queue ids and key lookup
- id sequence/generation handling
- `IPC_PRIVATE` allocation
- permissions, uid/gid/cuid/cgid/mode
- queue limits: `msgmax`, `msgmnb`, `msgmni`
- queue contents and message/byte accounting
- send and receive wait queues
- `IPC_STAT`, `IPC_SET`, `IPC_RMID`
- `IPC_INFO`, `MSG_INFO`, `MSG_STAT`, `MSG_STAT_ANY`
- `/proc/sysvipc/msg` snapshots

The service must be reachable from every real host process in one Carrick run
scope after `fork(2)`. It should use fork-coherent shared state rather than
per-process maps.

## Storage and discovery

Use a small durable namespace anchor only for discovery, ownership, and cleanup.
Do not store the live message queue contents by rewriting queue files on every
operation.

The first implementation should use a shared-memory service region for live
state:

- fixed-size service header with magic/version
- queue table
- message storage arena or ring segments
- waiter metadata
- accounting counters

The namespace anchor may live under Carrick's existing scoped temporary root. It
is not the queue hot path.

## Synchronization

Use host-kernel-backed synchronization for interprocess coordination. The service
must avoid in-process-only `HashMap` or process-local condition variables for
shared queue state.

Blocking behavior:

- `msgsnd(... IPC_NOWAIT)`: return `EAGAIN` when the queue lacks message or byte
  capacity.
- blocking `msgsnd`: wait until capacity is available, a deliverable signal
  interrupts the wait, or the queue is removed.
- `msgrcv(... IPC_NOWAIT)`: return `ENOMSG` when no matching message exists.
- blocking `msgrcv`: wait until a matching message exists, a deliverable signal
  interrupts the wait, or the queue is removed.
- `IPC_RMID`: marks the queue removed, wakes all waiters, and removes it from id
  and key lookup.

The service should use explicit wait/wake paths. Guest-visible SysV IPC should
not depend on repeated `usleep` polling inside Carrick.

## Typed domains

Use strong types for service internals and public helper APIs:

- `MsgQueueId`
- `MsgKey`
- `MsgType`
- `MsgBytes`
- `MsgQueueBytes`
- `MsgQueueLimit`
- `MsgSeq`
- `MsgOpFlags` bitflags
- `MsgCtlCmd` enum if it improves command dispatch clarity

Raw integer values should enter and leave only at syscall wire, procfs text, and
shared-memory layout boundaries. Constructors must name semantic crossings.

## Procfs and sysctls

The SysV procfs/sysctl surface comes from the service:

- `/proc/sys/kernel/msgmax`
- `/proc/sys/kernel/msgmnb`
- `/proc/sys/kernel/msgmni`
- `/proc/sysvipc/msg`

The service may advertise conservative SysV queue limits if those are the real
limits it enforces. That is different from changing unrelated process/thread
limits to influence LTP's workload selection.

## Relationship to M:N scheduling and fork admission

M:N scheduling remains responsible for guest thread execution. It is not the
source of SysV IPC semantics.

Forked Carrick guest processes still create real host processes and may rebuild
VM/vCPU state. Blocking waits should release scarce vCPU/VM resources where the
backend supports reclaim, but that is a scheduling/admission concern. The SysV
IPC service should remain correct regardless of whether a waiter currently owns
a vCPU slot.

## Migration plan

1. Keep the diagnostic DTrace scripts that proved the `msgstress01` failure
   shape, but treat them as diagnostics, not product behavior.
2. Remove the tactical `/proc/sys/kernel/threads-max` capacity clamp from the
   implementation path.
3. Add a `SysvIpcService` facade around the existing SysV message operations so
   dispatch has a stable target boundary.
4. Move current queue metadata and procfs rendering behind the service API.
5. Replace per-message queue-file rewrites with shared service-state storage.
6. Add explicit wait/wake support for blocking send and receive.
7. Add deterministic conformance probes for:
   - forked writer/reader queue handoff
   - `IPC_NOWAIT` empty/full behavior
   - `IPC_RMID` waking blocked senders/receivers
   - `MSG_COPY`, `MSG_EXCEPT`, and type-selective receive
8. Rerun the SysV LTP cluster, then the larger re-bless gate.

## Validation

Required local gates for this track:

- `just lint-domains`
- `just check -p carrick-runtime`
- `just conformance-probes` for any added probe
- focused SysV LTP suites:
  - `ltp-msgctl01`
  - `ltp-msgctl02`
  - `ltp-msgctl03`
  - `ltp-msgctl04`
  - `ltp-msgctl06`
  - `ltp-msgctl12`
  - `ltp-msgget01`
  - `ltp-msgget02`
  - `ltp-msgget04`
  - `ltp-msgget05`
  - `ltp-msgrcv01`
  - `ltp-msgrcv02`
  - `ltp-msgrcv03`
  - `ltp-msgrcv05`
  - `ltp-msgrcv06`
  - `ltp-msgrcv07`
  - `ltp-msgrcv08`
  - `ltp-msgsnd01`
  - `ltp-msgsnd02`
  - `ltp-msgsnd05`
  - `ltp-msgsnd06`
  - `ltp-msgstress01`

Completion for the overall goal still requires the full re-bless list in
`docs/2026-07-03-bless-regressions.md` to match the Docker oracle in a fresh
`just conformance full`, plus `just ci`.

## Implementation decisions

- The first implementation uses one mmap-backed service file per Carrick run
  scope. It may contain multiple logical regions, but discovery and cleanup use
  one anchor.
- The first wait/wake implementation uses the existing process-shared futex
  abstraction where available, backed by Darwin `__ulock` on macOS/HVF.
- SysV message queues, semaphores, and shared memory remain separate services.
  They should share a small namespace helper for scoped paths, ownership, and
  stale cleanup, but not one monolithic service implementation.
