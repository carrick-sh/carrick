# WS-H4 — Container lifecycle & io_uring-over-kqueue (design spec)

Status: **spec only** (per the review-remediation roadmap; these are the two
largest strategic items and are scheduled by demand). This document is the
brainstorm→spec deliverable; each half becomes its own implementation plan when
picked up.

## Context

`agy-report.md` items #11 (container lifecycle) and #13 (io_uring). carrick today
runs a single OCI image to completion via `Runtime::execute(&RunSpec)`
(`crates/carrick-runtime/src/execute.rs`) with a docker-compatible `run` frontend
(image config, `-e/-w/-v/--entrypoint`, bind mounts). It is a one-shot
`run`-and-exit model: no detached containers, no `start/stop/restart`, no
`exec`-into-running, no lifecycle state machine. io_uring is entirely absent —
`io_uring_setup`/`enter`/`register` (syscalls 425–427) are `Deferred` in the
aarch64 table and return ENOSYS, so liburing-based workloads fall back to their
epoll/threadpool path (correct, but a hard wall for io_uring-only code).

Both are large. This spec fixes the *shape* of each so they can be built
incrementally without rework, and states explicit non-goals so scope stays bounded.

---

## Part A — Container lifecycle

### Goal

A persistent, addressable container with the standard state machine
`created → running → (paused) → stopped → removed`, so carrick can back a
`docker`-like CLI (`create`, `start`, `stop`, `restart`, `kill`, `rm`, `exec`,
`ps`, `logs`) rather than only `run`.

### Architecture

1. **Lifecycle owner outside the guest.** A container is a host-side supervisor
   process (one per container) that owns the guest's root vCPU thread, its
   rootfs mount, its log fds, and its OCI config. The guest pid still mirrors a
   host pid (carrick's core invariant), so the supervisor is the natural place
   to hold `waitpid` and the kqueue `EVFILT_PROC` death-watch — it reuses the
   SIGCHLD/`register_child_exit_watch` machinery already in `carrick-hvf`.

2. **State store.** A per-container directory under a state root
   (`$XDG_STATE_HOME/carrick/<id>/`): `config.json` (the resolved `RunSpec`),
   `state.json` (the OCI runtime-state schema — `ociVersion`, `id`, `status`,
   `pid`, `bundle`), `pidfile`, and `<id>.log` (stdout/stderr, the `logs`
   source). Reusing the OCI state schema keeps a future `runc`-shim path open.

3. **Control plane.** A unix socket per container
   (`.../<id>/control.sock`) carrying length-prefixed JSON commands
   (`Stop{timeout}`, `Kill{signal}`, `Pause`, `Resume`, `Exec{argv,env,tty}`,
   `Inspect`). `stop` = deliver SIGTERM (cross-process delivery already exists),
   wait `timeout`, then SIGKILL. `pause`/`resume` = quiesce/resume the vCPU
   threads (the fork-quiesce barrier in `carrick-hvf` already pauses all
   siblings — generalize it to an explicit lifecycle pause).

4. **`exec` into a running container.** Spawn a new guest thread group sharing
   the container's mount namespace + rootfs (a sibling root task, not a fork of
   the entrypoint). This is the one genuinely new runtime primitive; everything
   else composes existing parts.

### Phasing

- **H4-A1:** state store + `create`/`start`/`rm` (no exec, no pause) — detach a
  `run` into a supervised background container with a pidfile and logs.
- **H4-A2:** `stop`/`kill`/`restart`/`ps`/`logs`/`inspect` over the control sock.
- **H4-A3:** `pause`/`resume` (lifecycle reuse of the quiesce barrier).
- **H4-A4:** `exec` (new sibling-root primitive).

### Non-goals

Networking namespaces / CNI, cgroup resource limits as *enforcement* (report
elsewhere), image build, a daemon/REST API. Single-host, single-user.

### Verification

A lifecycle integration test: `create` a long-running guest, assert `state.json`
status transitions, `exec` a second process that observes the first via
`/proc`, `stop` and assert graceful SIGTERM-then-SIGKILL ordering, `rm` and
assert state-dir cleanup. Cross-check `state.json` against the OCI schema.

---

## Part B — io_uring over kqueue

### Goal

Implement enough of io_uring (`io_uring_setup`/`enter`/`register`) that liburing
default workloads make forward progress, by translating SQEs into carrick's
existing dispatch + Darwin `kqueue` readiness machinery.

### Architecture

io_uring is a shared-memory ring ABI: the guest mmaps an SQ ring + CQ ring + SQE
array (offsets from `io_uring_setup`'s returned `io_uring_params`), fills SQEs,
and calls `io_uring_enter` to submit/wait. The translation:

1. **`io_uring_setup(entries, params)`** — allocate the three regions in the
   guest mmap arena (carrick controls the arena, so the rings are ordinary guest
   memory carrick can read coherently), fill `params` offsets/features, and
   return a ring fd as a new `OpenDescription::IoUring` variant holding the ring
   geometry + a per-ring `kqueue`.

2. **`io_uring_enter(fd, to_submit, min_complete, flags)`** — read `to_submit`
   SQEs from the SQ ring; for each, **dispatch the equivalent syscall through the
   existing `SyscallDispatcher`** (IORING_OP_READV→readv, OP_WRITEV→writev,
   OP_FSYNC→fsync, OP_RECVMSG/SENDMSG, OP_ACCEPT, OP_CONNECT, OP_POLL_ADD,
   OP_TIMEOUT, OP_NOP, OP_CLOSE, OP_OPENAT). Push a CQE (user_data + result) onto
   the CQ ring for each. For ops that would block, register the fd on the ring's
   kqueue (mirrors the epoll-over-kqueue path) and complete the CQE when ready,
   so `min_complete` waits via the same `ThreadWaiter`/kqueue wait the rest of
   the runtime uses. This is the key insight: **io_uring becomes a batching
   front-end over the dispatch table we already have**, not a new I/O engine.

3. **`io_uring_register`** — fixed files/buffers as an optimization; phase 1
   supports the buffer/file registration tables but treats them as plain
   indirection (no zero-copy fast path).

### Phasing

- **H4-B1:** setup + enter with OP_NOP/READV/WRITEV/FSYNC/CLOSE (synchronous
  ops, immediate CQEs) — passes liburing's basic ring smoke tests.
- **H4-B2:** OP_POLL_ADD + OP_TIMEOUT + blocking completion via the ring kqueue
  (the `min_complete` wait path).
- **H4-B3:** socket ops (ACCEPT/CONNECT/RECVMSG/SENDMSG), registered files/buffers.

### Non-goals

SQPOLL kernel-thread mode, IOPOLL, zero-copy send, registered eventfd, the
newest opcodes. Phase 1 targets correctness/forward-progress, not the io_uring
performance win (which a kqueue translation can't fully deliver anyway).

### Verification

Differential against Docker via the `ltp-conformance` loop: a liburing probe
(static-linked) doing ring read/write/fsync of a file and a poll-add on a pipe,
diffed line-exact carrick vs Docker. Then liburing's own `test/` smoke binaries
under the LTP-style sweep.

### Risk note

io_uring's CQ-overflow, SQE-linking (IOSQE_IO_LINK), and the memory-ordering
contract on the ring head/tail indices are the subtle parts; phase 1 keeps a
single in-order submission path and a CQ sized to the SQ to sidestep overflow,
expanding only as a workload demands it.
