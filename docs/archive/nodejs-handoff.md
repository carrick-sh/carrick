# Node.js/V8/libuv bring-up handoff

Date: 2026-05-31
Workspace: `/Volumes/CaseSensitive/carrick`
Branch: `main`

## Current status

2026-05-31 UPDATE — the remaining worker hang is RESOLVED. Four logical commits
are on `main`:

- `43c18ca` Allow scheduler queries for live guest tids
- `96a1e9b` Terminate sibling threads on leader exit_group
- `ae06588` Keep epoll waiters reachable after an in-memory wake drain  ← THE hang
- `a70fdcc` Add epollinmemwake regression probe for the in-memory wake drain
- `3e27d42` Run shebang-script entrypoints like Docker / execve(2)
- `8d31a8e` Return ELOOP when open follows a symlink cycle (libuv fs_file_loop)
- `55e893b` Honor AT_SYMLINK_NOFOLLOW in overlay set_times / lutimes (libuv fs_lutime)
- `da9ba67` dup(2) returns the lowest free fd, not a floor of 3 (libuv pipe_close_stdout_read_stdin)

## libuv conformance (2026-05-31)

libuv (`/opt/libuv-src/build/uv_run_tests_a`, ~327 runnable tests) is now
**~325/327 passing**. Run tests as uid 1000 with `test/` copied to a writable
cwd PARENT (fixtures are at the relative `test/fixtures/...`), and run them
SINGLE — concurrent HVF VMs starve each other into false timeouts (a `-P4`
sweep produced 4 bogus "wedges" that all pass in ~8s single). There is NO
suite wedge; the suite is just slow (~1s/test), so a short timeout looks like a
stall. Of 37 contaminated full-suite failures, only TWO were real carrick gaps
(both fixed above: ELOOP, lutimes); the rest were missing-fixture / wrong-cwd /
cross-test-state artifacts. Probes: openeloop, lutimesym.

libuv is now **~326/327** (`da9ba67` fixed pipe_close_stdout_read_stdin — it
WAS the dup floor after all: the child's `close(0); dup(pipe_read)` returned a
freed fd >= 3 instead of 0, so uv_pipe_open(0) wrapped a dead fd and uv_run
crashed; an isolated in-image C repro pinned dup=4-vs-Docker-0).

`ipc_heavy_traffic_deadlock_bug` is now FIXED too (`e403a38`): carrick's writev
looped per-iovec and, on a later iovec's EAGAIN, returned the error — discarding
bytes already written, so libuv re-sent from offset 0 forever and no uv_write
completed (deadlock; bw stuck at 0). Fix: return the partial total on mid-iovec
EAGAIN, and stop after a short iovec write. Isolated via a socketpair+fork+libuv
repro (no uv_spawn). Probe `writevpartial`.

**All four identified libuv carrick gaps are fixed (ELOOP, lutimes, dup,
writev-partial).** libuv full-suite confirmation in progress.

`app-smoke` and `v8-smoke` now exit `rc=0` under Carrick (were: app-smoke
TIMEOUT rc=137). Root cause + verification are in the "Remaining Node worker
hang" section below (now marked RESOLVED). The shebang fix lets the conformance
image run via its NATIVE entrypoint (a bash script) under Carrick — e.g.
`carrick run --entrypoint /usr/local/bin/nodejs-conformance <image> -- --runner
carrick --suite <s> --line 26`. Still open: full `node-core`/`libuv`
conformance, a `/proc/self/task` ENOENT gap, and the architectural follow-up to
retire the in-memory `EVFILT_USER` epoll path in favour of pure kqueue.

The original WIP batch (the first two commits) was parked in:

```text
stash@{0}: On main: nodejs bring-up scheduler exitgroup worker handoff WIP
```

If later stashes move the index, find it by message:

```sh
git stash list | rg 'nodejs bring-up scheduler exitgroup worker handoff WIP'
```

Image under test:

```sh
localhost:5005/carrick-nodejs-conformance@sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2
```

Node paths:

```sh
/opt/node-src/v24/out/Release/node
/opt/node-src/v26/out/Release/node
```

Relevant refs in the image:

- Node 24: `v24.16.0`
- Node 26: `v26.2.0`
- libuv: `v1.52.1`

## Already committed

### `e4600b2 Avoid SMCCC-shaped HVC for syscall forwarding`

Root cause: Apple/HVF consumes `hvc #0` as SMCCC when `x0` low32 looks like an
SMCCC function id. Carrick's guest syscall forwarding could therefore disappear
before the runtime saw the trap.

Fix:

- Switch EL1 vector syscall forwarding to `hvc #2`.
- Add the V8 mmap-hint reducer.
- Treat `MADV_DONTFORK` and `MADV_DOFORK` as no-op success for Carrick's
  current address-space model.

### `281881e Report host sockets as read-write to guests`

Root cause: Linux sockets report `O_RDWR` through `fcntl(F_GETFL)`, but
Carrick's `HostSocket` descriptions stored only mutable status bits. Socketpair
endpoints looked `O_RDONLY` to Node/libuv child stdio paths.

Fix:

- Report host sockets as read-write at the guest fd status layer.
- Add probes for `execpipe`, `execsocket`, and `fdstatus`.

## Uncommitted work in progress

Tracked modifications:

- `crates/carrick-runtime/src/dispatch/proc.rs`
- `crates/carrick-runtime/src/runtime.rs`
- `crates/carrick-runtime/tests/integration/syscall_thread.rs`

New probe files:

- `conformance-probes/src/bin/schedthread.rs`
- `conformance-probes/src/bin/exitgroupthreads.rs`
- `conformance-probes/src/bin/exitgroupmainthreads.rs`

Temporary diagnostics, likely do not commit as-is:

- `scripts/node-worker-diagnose.js`
- `scripts/dtrace/trace-node-worker-events.d`
- `scripts/dtrace/trace-node-worker-profile.d`

Unrelated untracked files were already present and should be left alone:

- `docs/cpython-baseline/*.jsonl`
- `scripts/dtrace/trace-mm-full.d`
- `scripts/dtrace/trace-node-stdio.d`

## Scheduler gap

Root cause: Node/V8 asks about worker scheduling policy through pthread APIs,
which reach Linux `sched_getscheduler(tid)` and `sched_getparam(tid)`. Carrick
accepted the calling task and host-visible pids, but it did not resolve live
guest thread tids from `ThreadRegistry`. Node logged:

```text
[mutex.cc : 956] RAW: pthread_getschedparam failed: 1
```

Current WIP fix:

- Resolve sched pid arguments against:
  - `0`
  - Carrick's process pid
  - `LINUX_BOOTSTRAP_PID`
  - the current guest tid
  - live sibling tids from `ThreadRegistry`
  - host pids visible through `kill(pid, 0)`, including `EPERM` as "exists"
- Keep negative pids on `EINVAL`.
- Keep unknown tids on `ESRCH`.

Regression coverage added:

- Runtime tests:
  - `sched_getscheduler_accepts_live_sibling_tid`
  - `sched_getparam_accepts_live_sibling_tid`
  - `sched_getscheduler_unknown_sibling_tid_is_esrch`
- Probe:
  - `schedthread`

Verification already run:

```sh
cargo test -p carrick-runtime --test integration sched_get -- --nocapture
scripts/build-probes.sh
CARRICK_INSECURE_REGISTRIES=localhost:5005 scripts/run-probe.sh schedthread
```

Observed `schedthread` output matched:

```text
child_tid_positive=true
sched_getscheduler_live_thread_is_other=true
sched_getscheduler_live_thread_errno_zero=true
sched_getparam_live_thread_rc_zero=true
sched_getparam_live_thread_errno_zero=true
sched_getparam_live_thread_priority_zero=true
```

## Exit-group gap

Root cause: `exit_group(2)` is process-wide even when issued by the guest
leader. Carrick only hard-exited from the threaded runtime's `Exit` branch when
the caller was a non-leader thread, so a leader `exit_group` could return from
the vCPU loop while sibling host threads kept the process alive.

Current WIP fix:

- In the threaded `DispatchOutcome::Exit` branch, call `_exit(code)` whenever
  the exiting guest thread is not the last live thread.
- Preserve plain `exit(2)` for non-last guest threads because that path routes
  through `ThreadExit` before the `Exit` branch.

Probe coverage added:

- `exitgroupmainthreads`: main guest thread spawns a sibling and calls
  `exit_group(0)`.
- `exitgroupthreads`: forked child spawns a sibling and calls `exit_group(37)`;
  this is useful, but it was not the main-process bug.

Important testing footgun:

`scripts/run-probe.sh exitgroupmainthreads` is not a valid check for the
main-process bug because the shell wrapper makes the probe a forked child.
Use `run-elf` directly.

Verification already run:

```sh
target/release/carrick run-elf --raw conformance-probes/target/aarch64-unknown-linux-musl/release/exitgroupmainthreads
```

Result: exited cleanly with `rc=0`.

## Remaining Node worker hang

The scheduler fix removed the Node scheduler warning, but Node 26 `app-smoke`
still times out under Carrick after printing success:

```json
{"duration_sec":120,"filter":"","libuv_ref":"v1.52.1","line":"26","node_ref":"v26.2.0","returncode":137,"runner":"carrick","signature":"app-smoke ok","status":"TIMEOUT","suite":"app-smoke"}
```

Stdio alone is not the remaining bug. This reducer exits successfully:

```sh
target/release/carrick run --raw \
  --entrypoint /opt/node-src/v26/out/Release/node \
  localhost:5005/carrick-nodejs-conformance@sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2 \
  -- -e "console.log('x'); console.error('e'); process.exit(0);"
```

Observed output:

```text
x
e
rc=0
```

Small worker reducer:

```sh
target/release/carrick run --raw \
  --entrypoint /opt/node-src/v26/out/Release/node \
  localhost:5005/carrick-nodejs-conformance@sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2 \
  -- -e 'console.error("before"); const {Worker}=require("worker_threads"); const w=new Worker("const {parentPort}=require(\"worker_threads\"); parentPort.postMessage(42);",{eval:true}); console.error("after worker"); w.on("message", m => console.log("msg", m)); w.on("exit", c => { console.error("exit", c); process.exit(0); });'
```

Observed in repeated runs:

```text
before
after worker
```

or, in slower/instrumented runs:

```text
before
after worker
msg 42
exit 0
```

Then Carrick remains alive until scoped cleanup kills it.

Host sample after the worker reducer hung:

- Process title was `carrick:<run-id>: WorkerThread`.
- Main Carrick thread was parked in `ThreadWaiter::wait` / `kevent`.
- `DelayedTaskScheduler` was also parked in `ThreadWaiter::wait` / `kevent`.
- Several `node-V8Worker` threads and `SignalInspector` were parked in
  `FutexTable::wait_prepared_with_token`.

Sample file from that run:

```text
/tmp/node-worker-sample-28714.sample.txt
```

Log file from that run:

```text
/tmp/node-worker-sample-28714.log
```

Trace evidence from `scripts/dtrace/trace-node-worker-events.d`:

- The root Node process does not reliably issue `exit_group(94)` on the leader
  path before the hang window.
- Helper/worker threads issue `exit(93)`.
- The trace shows repeated futex wake/wait and epoll activity during worker
  teardown.
- A worker-thread sample is a better next diagnostic than tracing full
  `app-smoke`.

Latest trace file:

```text
/tmp/node-worker-trace-26792.trace
```

## Recommended next step

Stay focused on the worker reducer, not full `app-smoke`.

The leading question is why a guest worker process that has completed the JS
worker lifecycle still leaves host vCPU threads parked forever:

- Is an eventfd/epoll wake being lost during worker startup or teardown?
- Is a futex wake happening before the waiter registers, or against the wrong
  guest tid/address?
- Is the leader parked in an epoll wait that should be interrupted by
  `process.exit(0)` or by worker teardown?

Suggested next diagnostic:

1. Keep the reducer command above.
2. Add or refine a trace that includes:
   - `clone(220)`
   - `exit(93)`
   - `exit_group(94)`
   - `futex(98)` operation, address, expected value, return value
   - `epoll_pwait(22)` epfd, timeout, return value
   - `eventfd2(19)`, `read(63)`, `write(64)`, `close(57)`, `fcntl(25)`
   - `io-wait-begin` and `io-wait-end`
3. Map host thread ids to guest tids at clone time.
4. Identify the final blocking syscall for the leader and for each live V8
   worker thread after the JS `exit` handler has fired.
5. Only then add the narrow probe. Avoid changing epoll/futex behavior from a
   hypothesis alone.

Use scoped cleanup only:

```sh
export CARRICK_RUN_ID=node-worker-<unique>
sudo -n scripts/sudo/kill.sh "$CARRICK_RUN_ID"
```

Do not use broad `pkill -f carrick`.

## Commit guidance

Do not fold the remaining worker hang into the scheduler commit unless the same
root cause is proven. The clean split is:

### Commit 1: scheduler

Suggested subject:

```text
Allow scheduler queries for live guest tids
```

Suggested message:

```text
Allow scheduler queries for live guest tids

Node/V8 asks pthreads for worker scheduling state, which reaches
sched_getscheduler(tid) and sched_getparam(tid). Carrick only treated pid 0,
the process pid, and the bootstrap alias as self, so live guest thread ids from
ThreadRegistry returned ESRCH. Node surfaced that as pthread_getschedparam
warnings during worker startup.

Resolve sched_* pid arguments against the current guest tid and live sibling
tids before falling back to host pid probing, while preserving EINVAL for
negative pids and ESRCH for unknown tids. Add runtime coverage plus a
schedthread probe for the Node worker shape.

Verification:
- cargo test -p carrick-runtime --test integration sched_get -- --nocapture
- scripts/build-probes.sh
- CARRICK_INSECURE_REGISTRIES=localhost:5005 scripts/run-probe.sh schedthread
```

### Commit 2: main exit_group

Suggested subject:

```text
Terminate sibling threads on leader exit_group
```

Suggested message:

```text
Terminate sibling threads on leader exit_group

exit_group is process-wide even when issued by the guest leader. Carrick only
hard-exited from the threaded runtime when a non-leader reached the Exit branch,
so a leader exit_group could return from the vCPU loop while sibling host
threads kept the process alive.

Treat any Exit outcome with live sibling threads as whole-process termination.
A plain exit(2) with live siblings still routes through ThreadExit before this
branch, preserving thread-exit semantics.

Verification:
- target/release/carrick run-elf --raw conformance-probes/target/aarch64-unknown-linux-musl/release/exitgroupmainthreads
```

### Commit 3: worker teardown

Do not draft this commit message yet. The root cause is not proven. The message
should name the exact futex/epoll/eventfd invariant once the reducer explains
why worker teardown leaves Carrick alive.

## Pause point

No commit has been made for the current WIP. There are no known stale scoped
Node/Carrick processes left running from this handoff run.
