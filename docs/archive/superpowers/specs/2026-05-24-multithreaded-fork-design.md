# Multithreaded fork/vfork on carrick — design

Date: 2026-05-24
Status: approved (brainstorming)

## Goal

Let a multithreaded guest process `fork`/`vfork` (and thus `fork`+`execve`)
correctly and robustly. Today `runtime::handle_fork` returns **ENOSYS when
`live_count > 1`**, so carrick cannot fork a multithreaded process. This blocks
Go entirely (`os/exec` spawns via `clone(CLONE_VM|CLONE_VFORK|CLONE_PIDFD)` from
a heavily-multithreaded runtime), and any threaded program that spawns a child.

This is the core architecture gap for Go support. It must be solved correctly:
fork-in-a-multithreaded-process is subtle (the classic locked-lock-in-child
deadlock), so the design is conservative and deterministic.

## The problem precisely

macOS `fork(2)` replicates **only the calling thread**. carrick runs each guest
thread on its own macOS thread with its own HVF vCPU in one shared VM. After a
host fork:

- The child has exactly one macOS thread (the caller). The other guest threads'
  vCPUs/macOS-threads do **not** exist in the child.
- The child inherits a **copy** of all carrick-internal Rust state — the thread
  registry (`live_count = N`), the `FutexTable` (waiter queues), the
  `VcpuKicker` (N vCPU handles), the `threads` JoinHandle vec, and **every
  lock** (the dispatcher's `open_files` RwLock, `next_fd` Mutex, futex shard
  mutexes, …) in **whatever state they held at the fork instant**.
- If another thread held a carrick lock when the fork happened, the child
  inherits it **locked with no owner** → the child deadlocks on its next
  syscall (execve/dup3 touch `open_files`).

So a correct multithreaded fork must give the child (a) clean unlocked carrick
state and (b) single-threaded bookkeeping.

## Approach: hybrid quiesce + child-reset

The two halves solve different problems and are both required:

- **Quiesce (lock safety):** pause all OTHER guest threads at a lock-safe point
  before forking, so no carrick lock is held at the fork instant.
- **Child-reset (phantom threads):** in the child, re-initialize the per-thread
  bookkeeping to single-threaded (the vanished threads' entries are stale).

Quiesce-only leaves stale registry/futex/kicker entries; reset-only can itself
deadlock acquiring an inherited-locked lock. Together: robust.

## Components

### `src/fork_quiesce.rs` — `QuiesceBarrier` (process-wide)

```
quiescing: AtomicBool          // run loops check this at the top
paused:    Mutex<usize> + Condvar  // count of threads parked at the barrier
fork_lock: Mutex<()>           // serializes concurrent forks
```

- `begin_quiesce(others: usize) -> bool`: set `quiescing`, wake all other
  threads (caller does the kick/notify), wait until `paused == others` or a
  bounded timeout; return success.
- `park_if_quiescing(this_running: &mut bool)`: called at the run-loop top; if
  `quiescing`, increment `paused`, wait on the condvar until `!quiescing`, then
  decrement. No carrick lock is held here.
- `end_quiesce()`: clear `quiescing`, notify the condvar (parent resume path).

Process-wide (like `host_signal`) because all vCPU threads share it and it must
survive being referenced from the run loop without the dispatcher lock.

### `runtime.rs` changes

1. **Run-loop top check** (`run_vcpu_until_exit`, before `next_syscall`):
   `BARRIER.park_if_quiescing(...)`. This is the lock-safe point — each loop
   iteration acquires and releases its syscall's locks within the iteration, so
   nothing is held here.

2. **`handle_fork` orchestration** (replace the `live_count > 1` ENOSYS guard):
   - Take `fork_lock`.
   - `others = live_count - 1`. If `others > 0`: `begin_quiesce(others)`, then
     `kicker.kick_all_except(this_tid)` + `futex.notify_all()` + wake io_wait
     waiters (the existing process-directed-signal wake paths) so blocked
     threads return to the run-loop top and park.
   - On quiesce timeout: `end_quiesce()`, drop `fork_lock`, complete the syscall
     with `-EAGAIN`, return (no hang, legitimate `fork` errno).
   - Otherwise proceed to `engine.fork()` exactly as today (snapshot is now
     race-free since all threads are parked).
   - **Parent**: `end_quiesce()` (resume the parked threads), drop `fork_lock`,
     existing parent restart, return `child_pid`.
   - **Child**: the parked threads don't exist. Extend the existing reset:
     fresh `ThreadRegistry(this_tid)` (already), **fresh `FutexTable`**,
     **fresh `VcpuKicker`** (register only this vCPU), **clear `threads`**, plus
     existing host_signal/guest_cpu/waiter reinit. `quiescing` is false in the
     child (the parent or the child's fresh barrier state). Drop `fork_lock`.

3. **Wait predicates**: futex `wait_prepared_*` and `io_wait::wait` gain a
   `quiescing` check so a blocked thread wakes for the quiesce (reuse the
   existing `interrupted()`/self-pipe plumbing — a process-directed wake).

### pidfd integration (folds in the prior pidfd plan's Task 2/3)

Once fork works from multithreaded, thread `CLONE_PIDFD`'s target address out of
`clone`/`clone3` (the `parent_tid`/`clone_args.pidfd` field). In the parent's
`ForkOutcome::Parent` arm, allocate a pidfd for `child_pid` via the committed
`SyscallDispatcher::open_pidfd` helper and write the fd number to that address.
Wire `waitid(P_PIDFD)` → resolve pidfd → `waitpid(host_pid)`. Revisit `rseq` only
if `os/exec` still needs it after fork works.

## Error handling

- Quiesce timeout → `-EAGAIN` to the guest (valid `fork` errno), threads resumed.
- `engine.fork()` failure → existing `restart_after_fork_error` + propagate
  (after `end_quiesce()` so threads don't stay parked).
- The fork mutex guarantees one quiesce at a time; a second forking thread is
  itself a "non-forking other thread" from the first's perspective and parks at
  the barrier (it isn't holding `fork_lock` yet) — no deadlock.

## Testing

- **New `fixtures/mn-probes` probe**: a multithreaded program (N worker threads
  doing futex/compute) that then `fork`+`exec`s a child which prints a token;
  parent waits and verifies. Run under carrick vs the Docker `linux/arm64`
  oracle.
- **go-conformance gate**: `os/exec` carrick PASS matches Docker (was 10 vs 36),
  `sync` `TestMutexMisuse`, `os/signal` pidfd cases.
- **No-regression**: existing multithreaded Go c50 (must stay ~99%),
  single-threaded fork (`apt-get install hello` — the v1 milestone), the lib
  test suite, and the conformance shell suite.
- **Stress**: fork+exec in a loop from a goroutine-heavy Go program (catch
  quiesce races / lock leaks).

## Risks / open questions

- **Quiesce of a thread mid-host-syscall that ISN'T interruptible**: blocking
  host calls in carrick are bounded/poll-based (kqueue slices, futex slices), so
  a thread always returns to the run-loop top within a slice; the timeout covers
  pathological cases. Verify no truly-unbounded blocking host call exists on the
  hot path.
- **Forked child that does NOT exec** (rare): handled — the child has a full
  private memory copy and one thread; the reset makes it a valid single-threaded
  process. Most uses (Go, posix_spawn) exec immediately.
- **`vfork` shared-memory semantics**: carrick implements vfork as a real fork
  (private copy), as it already does for glibc posix_spawn. Valid because the
  child only runs async-safe code + execve; the quiesce removes the race the
  shared-memory model was avoiding. Document that we don't honor literal
  CLONE_VM page sharing between parent and child.
- **Signal pump**: already stopped/restarted across fork by `ForkCoordinator`;
  the quiesce is orthogonal (it pauses guest vCPU threads, not the pump).
