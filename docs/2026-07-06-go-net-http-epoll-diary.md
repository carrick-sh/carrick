# Go net/http epoll investigation diary

## Context

Goal: unblock the conformance bless without accepting sleeps, repolls, or
large Carrick-vs-Docker timing gaps as fixes. The immediate suspect is
edge-triggered epoll emulation on macOS/BSD kqueue during the Go `net/http`
conformance workload.

Oracle timing for the focused case:

```sh
/usr/bin/time -p docker run --rm localhost:5005/carrick-go-conformance:1.24 \
  sh -lc 'cd /usr/local/go/src/net/http && \
  /conformance/net_http.test -test.v -test.run "^TestTransportConcurrency/h1$" \
  -test.short -test.timeout=120s'
```

Outcome: PASS, `real 0.19`.

## 2026-07-06

### Hypothesis: the 50 ms filtered backstop is hiding a kqueue registration bug

Test:

- Added `epoll-masked` and `epoll-rebind` USDT diagnostics.
- Ran bounded `carrick trace` against full Go `net/http` conformance command.
- Captured `target/conformance/logs/trace-rebind-full-210135.dtrace`.

Outcome:

- Trace showed repeated `epoll-result ready=0 wait=1 timeout=-1 kind=1`.
- The parked wait was immediately waking on kqueue fd `16408`.
- Masked samples were dominated by already-latched readiness:
  `raw=0x4 last=0x4`, `raw=0x11 last=0x11`, `raw=0x5 last=0x5`.
- Interpretation: the backstop is not the root cause. The host kqueue is being
  left readable for readiness the guest ET latch is intentionally masking.

Commit:

- `1bdd8241 diagnostics(runtime): trace epoll host rebinds`

### Hypothesis: masked wakes are caused by unread socket bytes whose count did not grow

Test:

- Extended `epoll-masked` payload with host fd, current `read_avail`, and
  `last_read_avail`.
- Ran bounded trace against the full Go `net/http` conformance command.
- Captured `target/conformance/logs/trace-avail-full-211222.dtrace`.

Outcome:

- Final repeated masked lines included sockets with:
  `raw=0x5 last=0x5 read_avail=127 last_read_avail=127`
  and `read_avail=125 last_read_avail=125`.
- Write-only masked fds had `raw=0x4 read_avail=0`, but were collateral after
  the instance kqueue woke.
- Interpretation: for ET reads, kqueue is waking on "bytes remain readable",
  while Linux ET semantics only allow a new guest event when the unread byte
  count grows or guest I/O consumes the latch.

Commit:

- `3ac3d083 diagnostics(runtime): trace epoll masked byte counts`

### Hypothesis: BSD ET reads should use kqueue `NOTE_LOWAT` at the delivered byte watermark

Grounding:

- Apple kqueue documentation says `EVFILT_READ` socket readiness is subject to
  a low-water mark, and `NOTE_LOWAT` can set a per-filter threshold.
- A local C host probe showed Darwin kqueue also honors `NOTE_LOWAT` for pipes:
  with lowat 2, one byte did not fire and two bytes did.

Implementation experiment:

- Added `Interest::read_lowat`.
- Added `Kevent::read_lowat(fd, flags, lowat)`.
- Set `read_lowat = last_read_avail + 1` only for ET read interest after
  readable state has already been delivered and unread bytes remain.
- Guarded the hint to host sockets and host pipes.
- Changed BSD rearm scheduling to rebind only when effective host registration
  changes, not every latch bookkeeping update.

Tests:

```sh
cargo test -p carrick-host-bsd read_lowat_sets_note_and_threshold -- --nocapture
cargo test -p carrick-runtime epoll_interest_tests -- --nocapture
cargo test -p carrick-runtime --test integration epoll -- --nocapture
just fmt-check
just build -p carrick-cli
```

Outcome:

- All listed tests passed.
- The existing integration assertions confirmed latch-masked ET readiness no
  longer leaves the epoll instance kqueue fd immediately readable.

### Focused timing check after low-water experiment

Test:

```sh
target/release/carrick run --name go-net-http-h1-lowat-warm-* \
  --max-traps 18446744073709551615 --raw --fs host \
  -w /usr/local/go/src/net/http \
  localhost:5005/carrick-go-conformance:1.24 \
  /conformance/net_http.test -test.v \
  -test.run '^TestTransportConcurrency/h1$' \
  -test.short -test.timeout=120s
```

Outcome:

- PASS.
- Warm timings: `real 1.75`, `real 1.79`.
- Docker oracle was `real 0.19`, so focused h1 remains roughly 9x slower.
- Interpretation: low-water changes may fix a correctness/park-set invariant,
  but they are not the dominant focused h1 performance root cause.

### Focused trace after low-water experiment

Test:

- Ran `carrick trace --script scripts/dtrace/epoll-wait-debug.d` around the
  focused h1 case.
- Captured `target/conformance/logs/trace-h1-lowat-212447.dtrace`.

Outcome:

- PASS.
- Trace overhead inflated wall time to `real 20.40`.
- Aggregate showed only two kqueue `io_wait` handoffs for the focused h1 run:
  the previous massive immediate kqueue wake pattern was not present in this
  focused case.
- Interpretation: low-water changes reduce the specific already-latched
  readable-kqueue shape, but focused h1 is still slow for another reason.

### Full selected Go net/http after low-water experiment

Test:

```sh
CARRICK_RUN_ID=go-net-http-selected-lowat-212526 \
  timeout 180s target/release/carrick-conformance \
  --tier full --suite go-net_http --workers 1 --force \
  --jsonl target/conformance/go-net_http-lowat.jsonl
```

Outcome:

- Timed out at 180s (`RC=124`).
- lldb snapshot: `target/conformance/logs/lldb-go-net-http-selected-lowat-212526-10053.txt`.
- Backtrace at attach time showed guest threads parked in futex waits.
- Event ring tail still ended with repeated quiet `EPWAIT kq=16408 ready=0 timeout=-1`.
- Interpretation: selected full `go-net_http` remains blocked. The low-water
  experiment did not resolve the full-suite blocker, and may still be involved
  if the watermark is stale. Need compare against the diagnostic checkpoint.

### In progress: compare against diagnostic checkpoint without low-water behavior

Test:

- Stashed tracked low-water behavior edits as `lowat-behavior-wip`.
- Rebuilt/signed the committed diagnostic checkpoint.
- Running:

```sh
CARRICK_RUN_ID=go-net-http-selected-diag-* \
  timeout 180s target/release/carrick-conformance \
  --tier full --suite go-net_http --workers 1 --force \
  --jsonl target/conformance/go-net_http-diag.jsonl
```

Expected interpretation:

- If the diagnostic checkpoint also times out, the full-suite blocker predates
  the low-water experiment.
- If the diagnostic checkpoint completes or fails differently, drop or rework
  the low-water behavior patch before committing it.

Outcome:

- Diagnostic checkpoint also timed out at 180s:
  `RUN_ID=go-net-http-selected-diag-212942 RC=124`.
- Interpretation: the selected full `go-net_http` blocker predates the
  low-water behavior experiment. The low-water patch should be judged as a
  separate kqueue ET correctness/park-set fix, not as the full-suite fix.

### Restored low-water experiment after diagnostic comparison

Test:

```sh
just fmt-check
cargo test -p carrick-host-bsd read_lowat_sets_note_and_threshold -- --nocapture
cargo test -p carrick-runtime epoll_interest_tests -- --nocapture
cargo test -p carrick-runtime --test integration epoll -- --nocapture
```

Outcome:

- `fmt-check`, host-bsd low-water constructor test, and runtime interest tests
  passed.
- The full epoll integration slice failed:
  `epoll_et_read_growth_does_not_rearm_latched_read_level`.
- The failing assertion was the existing invariant that a latched read-growth
  ET delivery must not leave the epoll instance kqueue fd immediately readable.
- Interpretation: do not commit the low-water behavior patch yet. Earlier green
  result was not sufficient; isolate whether this is deterministic or ordering
  dependent before changing behavior again.

Follow-up:

```sh
for i in 1 2 3 4 5; do
  cargo test -p carrick-runtime --test integration \
    epoll_et_read_growth_does_not_rearm_latched_read_level -- --nocapture
done

cargo test -p carrick-runtime --test integration epoll -- \
  --nocapture --test-threads=1
```

Outcome:

- The isolated failing test passed 5/5.
- The full epoll integration slice passed with `--test-threads=1`.
- Interpretation: the failure is order/concurrency sensitive in the integration
  gate, not a simple deterministic failure of that individual test. Do not use
  serial-only success as the final gate.

### Hypothesis: process-global in-memory epoll wake registry pollutes parallel tests

Grounding:

- `EPOLL_INMEM_KQUEUES` was process-global. Parallel integration tests create
  multiple independent `SyscallDispatcher`s in one host process.
- Any eventfd/timerfd/netlink/FIFO in-memory wake in one dispatcher could fire
  `EVFILT_USER(0)` on another dispatcher's epoll kqueue.
- That explains the failed `poll(kqueue_fd)` assertion: the fd can be readable
  because of a cross-dispatcher user wake, not because the watched host pipe is
  still level-ready.

Implementation experiment:

- Moved the epoll wake registry into `IoState`.
- Passed the registry into each `EpollKqueue`.
- Routed eventfd/netlink/FIFO in-memory wakeups through
  `SyscallDispatcher::notify_inmem_epoll()`.
- Moved fork-child clearing to `SyscallDispatcher::epoll_after_fork_child()`.

Tests:

```sh
cargo test -p carrick-runtime epoll_shim::tests -- --nocapture
cargo test -p carrick-runtime epoll_kqueue_tests -- --nocapture
cargo test -p carrick-runtime --test integration epoll -- --nocapture
```

Outcome:

- The registry unit, epoll-kqueue unit, and one default-parallel epoll
  integration slice passed.
- A stress repeat of the default-parallel epoll slice then failed in
  `epoll_wakes_accepted_socket_after_peer_write`.
- That accepted-socket test passed 5/5 when isolated.
- Interpretation: dispatcher-local wake registry removes one cross-dispatcher
  wake bug, but the default-parallel epoll integration slice is still not stable
  enough to treat the low-water behavior patch as complete.

Follow-up:

- Temporarily disabled only the low-water arming condition while keeping the
  dispatcher-local registry.
- Default-parallel epoll integration slice passed.

Interpretation:

- Socket low-water arming is implicated in the accepted-socket parallel failure.
- Back out the low-water experiment for now. Keep the dispatcher-local wake
  registry fix because it is independently grounded and removes the
  cross-dispatcher `EVFILT_USER` broadcast.

Verification after backing out low-water:

```sh
just fmt
for i in 1 2 3; do
  cargo test -p carrick-runtime --test integration epoll -- --nocapture
done
```

Outcome:

- All three default-parallel epoll integration slices passed.
- Interpretation: dispatcher-local wake registry is stable enough to commit as
  a separate fix. Low-water remains a rejected/parked experiment until it can
  explain and pass the accepted-socket parallel case.
