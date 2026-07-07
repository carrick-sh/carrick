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

### Focused h1 after dispatcher-local wake registry

Test:

```sh
just build -p carrick-cli
target/release/carrick run --name go-net-http-h1-registry-* \
  --max-traps 18446744073709551615 --raw --fs host \
  -w /usr/local/go/src/net/http \
  localhost:5005/carrick-go-conformance:1.24 \
  /conformance/net_http.test -test.v \
  -test.run '^TestTransportConcurrency/h1$' \
  -test.short -test.timeout=120s
```

Outcome:

- Timed out at 35s (`RUN_RC=124`), after printing the test start but before
  PASS.
- Interpretation: dispatcher-local registry as committed regresses the focused
  h1 workload. Do not treat `8a819e30` as good until the missing wake path is
  identified or the commit is reverted.

### Hypothesis: lldb capture must be part of the runner, not an ad-hoc shell loop

Grounding:

- A bad zsh deadline handler found matching `carrick:<run-id>` pids but tried to
  attach to the whitespace-joined pid list as one lldb target. That produced no
  useful capture.
- A POSIX shell handler that wrote a `ps` snapshot and attached one pid at a
  time captured the h1 failure:
  `target/conformance/logs/lldb-handler-runs/h1-posix-3-215106.lldb.txt`.
- The capture showed:
  - supervisor parent in `carrick_runtime::namespace::supervisor::run`, blocked
    in `kevent`, with an empty event ring;
  - guest/init child with event-ring history and vCPU threads parked in
    futex/poll paths;
  - cores for both matched Carrick processes.

Implementation:

- Added `carrick debug lldb-run -- <run args>`.
- The runner re-execs the signed Carrick binary as `run`, injects `--name
  <run-id>` when the forwarded args do not already name the container, sets
  `CARRICK_RUN_ID`, redirects guest output to `<run-id>.guest.log`, and monitors
  the child.
- On deadline it records a manifest, `ps` snapshot, lldb transcript, `carrick
  eventring`, `thread backtrace all`, and modified-memory cores unless
  `--no-core` is set. Cleanup is scoped to the run id.
- Checked the Rust LLDB crate surface with `cargo search lldb`: `lldb` and
  `lldb-sys` exist, but the first runner deliberately stays on `lldb --batch`
  because that preserves the operator transcript and the existing Python plugin
  contract. Revisit a binding only if the command boundary becomes the limiting
  factor.

Validation:

```sh
cargo fmt --check
cargo check -p carrick-cli
cargo clippy -p carrick-cli -- -D warnings
just build -p carrick-cli

target/release/carrick debug lldb-run \
  --deadline-seconds 1 \
  --out-dir target/conformance/logs/lldb-run-smoke \
  --run-id h1-injected-name-smoke-* \
  --no-core -- \
  --max-traps 18446744073709551615 --raw --fs host \
  -w /usr/local/go/src/net/http \
  localhost:5005/carrick-go-conformance:1.24 \
  /conformance/net_http.test -test.v \
  -test.run '^TestTransportConcurrency/h1$' \
  -test.short -test.timeout=120s
```

Outcome:

- Clippy initially rejected the earlier scalar `epoll_masked` probe call shape.
  The probe now takes a semantic `EpollMaskedProbe` struct while preserving the
  existing pointer-to-wire-payload USDT ABI for `epoll-wait-debug.d`.
- Clippy also rejected the runner's first `dump_lldb` helper for the same
  scalar-list reason; the lldb dump configuration is now a context struct.
- The first final smoke exposed a macOS `ps` parser bug: right-aligned pid
  fields confused the split logic. The parser now reads the first two
  whitespace fields as `pid`/`ppid` and joins the remaining command snapshot.
- The forced-deadline smoke exited `124`, wrote a manifest whose `run_args`
  included injected `--name h1-final-smoke-*`, attached lldb to the parent and
  child scoped processes, dumped the event rings and host backtraces, then
  reaped only the matching run id.
- A real 35s h1 run timed out and produced:
  - `target/conformance/logs/lldb-run-h1/h1-integral-runner-215807.lldb.txt`
  - `target/conformance/logs/lldb-run-h1/h1-integral-runner-215807.84408.core`
  - `target/conformance/logs/lldb-run-h1/h1-integral-runner-215807.84473.core`
  - `target/conformance/logs/lldb-run-h1/h1-integral-runner-215807.guest.log`
- The reproduced failure shape matches the hand handler: parent in supervisor
  `kevent`, child stuck after entering `TestTransportConcurrency/h1`.

Interpretation:

- The debugger capture path is now a Carrick command and should be the default
  for deadline-based hang investigation. Continue root-cause from the captured
  child event ring/backtraces instead of adding timing backstops.

### Hypothesis: the non-perturbing ring needs the actual wait handoff and masked bits

Test:

- Added always-on event-ring events:
  - `EPWFD fd=<host fd> events=<poll mask> timeout=<ms>` for epoll wait
    handoffs.
  - `EPMASK origin=<path> raw=<bits> last=<bits>` for readiness masked by the
    guest ET latch.
- Rebuilt/signed and reran `carrick debug lldb-run` around focused h1 until a
  deadline fired.

Outcome:

- Captured `target/conformance/logs/lldb-run-h1-epwfd/h1-epwfd-catch-2-221901.lldb.txt`.
- The ring alternated:
  - `EPWAIT kq=16408 ready=0 timeout=119989`
  - `EPWFD fd=16408 events=0x1 timeout=119989`
- Captured `target/conformance/logs/lldb-run-h1-mask/h1-mask-catch-1-222058.lldb.txt`.
- The masked samples were repeated already-latched ET readiness:
  - `EPMASK origin=2 raw=0x4 last=0x4`
  - `EPMASK origin=2 raw=0x5 last=0x5`
- Interpretation: the non-perturbed failure is not a long sleep. Carrick
  samples only latched ET state, returns a `POLLIN` wait on the epoll kqueue
  fd, and immediately wakes again.

### Hypothesis: ET host registration must spend kqueue edges and re-arm explicitly

Implementation experiment:

- Added `Interest::read_lowat`.
- Added `Kevent::read_lowat(fd, flags, lowat)` backed by `NOTE_LOWAT`.
- For BSD edge-triggered registrations, added `EV_DISPATCH` so a returned
  kqueue event disables its filter until Carrick re-arms it.
- Made drained host edges and masked ET samples rebind through
  `epoll_effective_interest`, so:
  - latched `EPOLLOUT` removes the host write filter;
  - latched unread `EPOLLIN` on host sockets/pipes re-arms read at
    `last_read_avail + 1`;
  - duplicated guest fds sharing one host fd use the lowest needed low-water
    threshold, while any unlatched reader clears the low-water hint;
  - edge rebinds delete the old kqueue filter before adding the new one so stale
    pending readiness does not survive a threshold/mask change.

Focused tests:

```sh
cargo check -p carrick-cli
cargo test -p carrick-runtime --test integration epoll -- --nocapture
just build -p carrick-cli
```

Outcome:

- `cargo check -p carrick-cli` passed.
- The default-parallel epoll integration slice passed with 30 tests, including:
  - `epoll_wakes_accepted_socket_after_peer_write`
  - `threaded_epoll_wait_wakes_when_peer_thread_writes_to_accepted_socket`
  - `epoll_et_read_growth_does_not_rearm_latched_read_level`
- Five focused h1 samples passed:
  - first cold-ish run `real 4.12`
  - warm runs `real 1.72`, `1.75`, `1.75`, `1.76`
- Docker oracle warm samples were `real 0.23`, `0.19`, `0.18`.
- Interpretation: the focused h1 timeout flake improved, but warm Carrick h1 is
  still roughly an order of magnitude slower than the Docker oracle.

### Broader go-net_http still has a masked-kqueue blocker

Test:

```sh
CARRICK_RUN_ID=go-net-http-lowat2-* \
  timeout 180s target/release/carrick-conformance \
  --tier full --suite go-net_http --workers 1 --force \
  --jsonl target/conformance/go-net-http-lowat2-*.jsonl
```

Outcome:

- Timed out at 180s before writing any JSONL rows.
- Direct raw-suite `lldb-run` captures also timed out:
  - `target/conformance/logs/lldb-go-net-http-suite/go-net-http-suite-maskrearm-223748.lldb.txt`
  - `target/conformance/logs/lldb-go-net-http-suite/go-net-http-suite-deleteadd-224122.lldb.txt`
- The raw-suite guest log advanced into broader package execution and then
  timed out around `TestTransportConcurrency/h1` or later concurrent tests.
- The ring still showed repeated:
  - `EPMASK origin=2 raw=0x5 last=0x5`
  - `EPMASK origin=2 raw=0x4 last=0x4`
  - `EPWAIT ... ready=0`
  - `EPWFD ... events=0x1`
- Interpretation: the current low-water/EV_DISPATCH/delete-add work is not the
  full architectural fix. It is a useful focused h1 improvement and diagnostic
  checkpoint, but the full `go-net_http` suite still has a masked kqueue
  readiness path that keeps the epoll instance fd poll-readable.

### Hypothesis: terminal ET readiness must also disarm host write filters

Grounding:

- A current-state `carrick debug lldb-run` capture hit the same broad-suite
  masked-kqueue pattern at `TestTransportConcurrency/h1`:
  `target/conformance/logs/lldb-go-net-http-current/go-net-http-current-lldb-225110.lldb.txt`.
- A focused `carrick trace` run showed the dominant repeated set included
  fds with `raw=0x11 last=0x11 read_avail=8388608`, while
  `epoll-rebind` kept `effective=0x3` (read + write) for those host fds.
- Interpretation: after a terminal `EPOLLHUP`/`EPOLLERR` edge is already
  latched for an ET registration, a host write filter can keep waking the
  kqueue even though the Linux-facing sampler will not deliver a new event.

Implementation:

- `epoll_effective_interest` now drops BSD host write interest for ET
  registrations when `last_ready` includes `EPOLLOUT`, `EPOLLHUP`, or
  `EPOLLERR`, unless a guest write hit backpressure and explicitly needs a
  writability wake.
- Added a unit test for terminal latch write-filter suppression.

Verification:

```sh
cargo test -p carrick-runtime epoll_interest_tests -- --nocapture
cargo test -p carrick-runtime --test integration epoll -- --nocapture
cargo fmt --check
cargo check -p carrick-cli
just build -p carrick-cli
```

Outcome:

- The focused gates passed.
- Five focused h1 samples before later experiments passed with warm timings
  still around `real 1.76-1.86`; Docker oracle for the same focused case was
  around `real 0.18-0.23`, so the focused performance gap remains.
- A broad 60s `lldb-run` progressed past `TestTransportConcurrency/h1` and
  into later SOCKS/round-trip tests instead of stopping in the old
  `EPWAIT ready=0` / `EPWFD POLLIN` loop.
- A broad raw run still timed out at 240s while making progress; the Docker
  oracle completed the same raw command in `real 4.43`.
- Interpretation: this is real liveness progress and removes one pathological
  masked-kqueue source, but `go-net_http` remains unblessable because the broad
  suite is still more than an order of magnitude slower than Docker.

### Rejected experiment: short nanosleep as yield

Grounding:

- Post-terminal-fix `carrick trace --script scripts/dtrace/epoll-wait-debug.d`
  reduced kqueue-fd waits from roughly 208k/20s to about 1.1k/20s, but showed
  tens of thousands of empty-fd waits.
- `carrick trace --script scripts/dtrace/trace-profile.d` on focused h1 showed
  `nanosleep` dominating the syscall count.

Experiment:

- Tried routing sub-100us `WaitOnSleep` outcomes through `thread::yield_now`
  instead of the signal-aware empty-fd waiter.

Outcome:

- Rejected and reverted. One of five focused h1 samples timed out at 45s, and
  warm passing samples remained around `real 1.77-1.79`.
- Interpretation: short-sleep yielding is not a valid fix. The remaining
  performance work needs better evidence about why Go emits so many short
  sleeps and whether Carrick is forcing those sleeps through a path Linux avoids,
  not an approximation that changes scheduling semantics.

### Rejected experiment: explicit `NOTE_LOWAT=1` for fresh ET reads

Grounding:

- Post-commit raw suite:
  `target/conformance/logs/go-net-http-raw-231737.guest.log`.
  It timed out at 180s at `TestTransportConcurrency/h1`.
- Deadline handler:
  `target/conformance/logs/lldb-go-net-http-postcommit/go-net-http-lldb-232051.lldb.txt`.
  The ring showed the old masked loop, now with `raw=0x5/0x4` equal to
  `last=0x5/0x4`.
- Structured `epoll-masked` tail trace:
  `target/conformance/logs/go-net-http-masktail-232444.dtrace`.
  The loop was origin 2 over ET sockets requesting `0x80002005`; one fd had
  `raw=0x5 read_avail=112 last_read_avail=112`, the rest had `raw=0x4`.
- Host changelist trace:
  `target/conformance/logs/go-net-http-kevent-233018.dtrace`.
  Carrick did install `NOTE_LOWAT` for latched read-byte-count sockets, while
  sockets whose only latched bit was `EPOLLOUT` were rearmed with plain read
  filters.
- Host primitive tests added in `carrick-host-bsd` prove kqueue can suppress
  read readiness until low-water growth, can rearm that threshold after an edge,
  and still reports EOF with `NOTE_LOWAT=1`.

Experiment:

- Tried setting `read_lowat=Some(1)` for ET read registrations before a read
  edge has latched, while preserving `last_read_avail + 1` after a read edge.

Outcome:

- Rejected and reverted. The broad suite got past `TestTransportConcurrency/h1`
  but focused `TestOmitHTTP2Vet` regressed:
  `target/conformance/logs/go-net-http-vet-234031.guest.log` failed with
  `SIGTRAP` in a child Go compiler process.
- Attribution run with the pre-experiment committed binary:
  `target/conformance/logs/go-net-http-vet-prelowat-234125.guest.log` passed
  `TestOmitHTTP2Vet` in `real 32.30`.
- Interpretation: explicit low-water on fresh ET read filters changes runtime
  scheduling/visibility enough to expose or cause a Go toolchain failure. It is
  not acceptable as the fix even though it moves the broad suite past h1.

### Diagnostics: fd-bearing masked-readiness event ring

Implementation:

- Added `EPMASKFD` to the always-on event ring and `scripts/carrick_lldb.py`.
  It records `origin`, guest fd, and host fd next to the existing `EPMASK`
  `origin/raw/last` record.

Verification:

```sh
cargo fmt --check
cargo check -p carrick-cli
cargo test -p carrick-host-bsd read_lowat -- --nocapture
just build -p carrick-cli
target/release/carrick debug lldb-run --deadline-seconds 160 ...
```

Outcome:

- The new lldb handler capture
  `target/conformance/logs/lldb-go-net-http-fdmask/go-net-http-lldb-fdmask-234440.lldb.txt`
  shows the masked loop without DTrace perturbation:
  repeated origin-2 samples over guest fds `7`, `9`, `10`, `12`, `13`, `14`,
  `15`, and `16`, with host fds in the `146..162` range. The repeated masks
  remain `raw=0x4 last=0x4` and `raw=0x5 last=0x5`.

### Rejected experiment: disarm all terminal ET read filters

Hypothesis:

- Since kqueue still reports EOF even with a read low-water mark, terminal ET
  read filters may need the same disarm treatment as terminal ET write filters.

Experiment:

- Tried suppressing the host read filter whenever an ET registration had read
  interest and `last_ready` already contained a terminal bit
  (`EPOLLHUP`/`EPOLLERR`/`EPOLLRDHUP`).

Outcome:

- Rejected and reverted. Focused `TestOmitHTTP2Vet` failed twice:
  `target/conformance/logs/go-net-http-vet-termread-235643.guest.log` failed in
  `real 19.63`, and
  `target/conformance/logs/go-net-http-vet-termread2-235713.guest.log` failed in
  `real 8.24`.
- Interpretation: terminal read suppression cannot be registration-wide. The
  Go toolchain still needs some terminal/read state to be visible or rearmed in
  cases unrelated to the h1 loop.

### Diagnostics: drained edge source event ring

Implementation:

- Added `EPEDGE` to the always-on event ring and `scripts/carrick_lldb.py`. It
  records the guest fd, translated kqueue edge bits, and the drained readiness
  count at the kqueue-drain point.

Verification:

```sh
cargo fmt --check
cargo check -p carrick-cli
just build -p carrick-cli
target/release/carrick debug lldb-run --deadline-seconds 160 ...
CARRICK_RUN_ID=go-net-http-vet-diagonly2-235952 timeout 60s \
  target/release/carrick run --raw --fs host \
  -w /usr/local/go/src/net/http \
  localhost:5005/carrick-go-conformance:1.24 \
  /conformance/net_http.test -test.v -test.run '^TestOmitHTTP2Vet$' -test.short
```

Outcome:

- `target/conformance/logs/lldb-go-net-http-edge/go-net-http-lldb-edge-235017.lldb.txt`
  shows the repeated wake source is guest fd 6, repeatedly draining
  `edge=0x2009` (`EPOLLIN|EPOLLERR|EPOLLRDHUP`) with count 24.
- In the same loop, Carrick recomputes readiness as `raw=0x11`
  (`EPOLLIN|EPOLLHUP`) and masks it because `last=0x11`.
- A first focused diagnostic-only vet run
  `target/conformance/logs/go-net-http-vet-diagonly-235825.guest.log` failed
  with a Go compiler `SIGTRAP`, but an immediate repeat
  `target/conformance/logs/go-net-http-vet-diagonly2-235952.guest.log` passed in
  `real 31.90`. Treat the SIGTRAP as a flake until a deterministic reproducer
  proves otherwise.
- Interpretation: the likely bad loop is not "read filters are always armed
  after terminal state"; it is narrower. A masked terminal edge is drained from
  kqueue, then the same host filter is rearmed even though that exact terminal
  edge produced no guest-visible delta.

### Rejected experiment: suppress rearm only for masked terminal edges

Hypothesis:

- If the bad loop is caused by one drained terminal edge being immediately
  rearmed after producing no guest-visible delta, the update path can suppress
  only that host rearm and leave ordinary terminal/read registration behavior
  unchanged.

Experiment:

- Converted the wait-loop update tuple to a local struct and added a
  `suppress_host_rearm` decision only for `edge_drained && masked_ready` events
  whose drained edge carried `EPOLLRDHUP`, `EPOLLHUP`, or `EPOLLERR`.

Outcome:

- Rejected and reverted. It fixed the focused h1 reproducer:
  `target/conformance/logs/go-net-http-h1-maskterm-000424.guest.log` passed in
  `real 1.66`.
- It regressed focused `TestOmitHTTP2Vet` in 2 of 3 samples:
  `target/conformance/logs/go-net-http-vet-maskterm-000406.guest.log`,
  `target/conformance/logs/go-net-http-vet-maskterm1-000432.guest.log`, and
  `target/conformance/logs/go-net-http-vet-maskterm2-000449.guest.log` failed;
  `target/conformance/logs/go-net-http-vet-maskterm3-000458.guest.log` passed in
  `real 32.02`.
- Interpretation: the rearm is still serving another Go toolchain path. The
  h1 loop needs either a more fd/state-specific condition or a different
  architecture for terminal kqueue edges rather than suppressing the host
  rearm in the generic ET update path.

### Rejected experiment: merge drained terminal edge bits into ET readiness

Hypothesis:

- The drained kqueue edge reported `EPOLLIN|EPOLLERR|EPOLLRDHUP`, while
  Carrick's live recompute reported only `EPOLLIN|EPOLLHUP`. Preserving the
  drained edge's Linux-reportable terminal bits might let Go observe the
  half-close/error edge instead of spinning on a masked `IN|HUP` latch.

Experiment:

- Tried OR-ing drained edge bits into the recomputed readiness mask, limited to
  bits Linux could report for that registration (`requested|EPOLLHUP|EPOLLERR`).

Outcome:

- Rejected and reverted. It fixed the focused h1 reproducer:
  `target/conformance/logs/go-net-http-h1-edgebits-001104.guest.log` passed in
  `real 1.74`.
- Focused `TestOmitHTTP2Vet` under the experiment passed once, then failed
  twice:
  `target/conformance/logs/go-net-http-vet-edgebits1-000942.guest.log` passed in
  `real 32.92`;
  `target/conformance/logs/go-net-http-vet-edgebits2-001015.guest.log` failed
  in `real 30.37`; and
  `target/conformance/logs/go-net-http-vet-edgebits3-001046.guest.log` failed
  in `real 17.96`.
- A rebuilt committed baseline then failed the same focused vet case 3/3:
  `target/conformance/logs/go-net-http-vet-baseline1-001213.guest.log`,
  `target/conformance/logs/go-net-http-vet-baseline2-001231.guest.log`, and
  `target/conformance/logs/go-net-http-vet-baseline3-001248.guest.log`.
- Docker oracle for the exact vet case passed in `real 5.49`.
- Interpretation: vet is a current independent correctness/performance blocker,
  not a reliable guard for h1 attribution. The edge-bit merge still lacks a
  clean acceptance signal and should stay reverted until vet's SIGTRAP path is
  understood.

### Diagnostics: SIGTRAP/vet signal trace

Grounding:

- Go's conformance harness documents that some Go debug-call paths intentionally
  use in-guest `SIGTRAP`/`BRK`, so the vet failures may be a guest signal
  delivery/resume issue rather than epoll.

Trace:

- Added temporary trace script
  `target/conformance/logs/sigtrap-vet.d` for `vcpu-fault`,
  `vcpu-fault-regs`, `signal-publish`, `signal-deliver`, `signal-inject`, and
  `signal-restore`.
- Ran:
  `target/conformance/logs/go-net-http-vet-sigtrace-001436.dtrace` with guest
  log `target/conformance/logs/go-net-http-vet-sigtrace-001436.guest.log`.

Outcome:

- Under trace, focused `TestOmitHTTP2Vet` passed in `real 36.06`, but the outer
  `timeout 90s` returned `124` because the trace wrapper did not shut down
  cleanly before the timeout.
- The trace tail showed heavy signal 23 publish/deliver traffic and no fault
  lines in the sampled tail.
- Interpretation: the trace perturbs the failure and is not yet enough. The
  next diagnostic should dump from the runtime's guest-fault/termination handler
  or teach the debug runner to trigger lldb on the observed failing exit path,
  not only on a wall-clock deadline.

### Diagnostics: stop-on-signal lldb runner for vet

Hypothesis:

- The vet `SIGTRAP` failure needed to be caught before the failing compiler
  process exited. A wall-clock deadline runner was too late because the failing
  process had already died.

Experiment:

- Extended `carrick debug lldb-run` with `--stop-on-signal 5`. The runner sets a
  diagnostic env var for the scoped child. Runtime signal-delivery paths raise
  `SIGSTOP` just before delivering the selected Linux signal, and the runner
  detects stopped scoped processes, dumps lldb/event-ring/cores, resumes them,
  and then performs scoped cleanup.
- Ran focused vet with run id
  `go-net-http-vet-stoptrap2-002455`.

Outcome:

- The runner stopped and dumped the failing compiler child before Go printed its
  crash. The stopped child was
  `/usr/local/go/pkg/tool/linux_arm64/compile ... -p sort ...`.
- lldb showed thread #1 stopped at host
  `libdispatch.dylib::_dispatch_sema4_create_slow.cold.5` on `brk #0x1`,
  reached from Rust's Darwin thread parker while waiting in
  `std::sync::RwLock` during
  `carrick_runtime::fs_resolve_cache::ResolveCache::put`.
- The event ring for the compiler child had only startup/open activity and no
  epoll loop, so this was not the previous h1 epoll terminal-edge loop.
- Interpretation: the apparent guest `SIGTRAP` was masking a host-side Darwin
  trap in Carrick's runtime, hit under concurrent Go compiler `openat` path
  resolution.

### Fix: classify Darwin BRK as host fault and remove std RwLock from resolve cache

Hypotheses:

- H1: Carrick's HVF host routed handler was converting Darwin host `SIGTRAP`
  into a guest signal because the classifier only treated `si_code > 0` as a
  synchronous host fault.
- H2: The underlying host trap came from the resolve cache's use of
  `std::sync::RwLock`, whose Darwin wait path uses libdispatch semaphores. The
  rest of the runtime filesystem hot path already uses `parking_lot::RwLock`.

Tests:

- A throwaway host probe installed `SA_SIGINFO` for `SIGTRAP` and executed
  `brk #1`; macOS reported `sig=5 si_code=0 si_pid=0`.
- After teaching the HVF classifier about that no-sender Darwin `brk` shape,
  focused vet no longer produced a guest Go crash dump, but still failed with
  host `signal: trace/breakpoint trap`, confirming the host trap was real.
- Swapped `fs_resolve_cache::ResolveCache` from `std::sync::RwLock` to
  `parking_lot::RwLock`.

Outcome:

- Focused checks passed:
  `cargo fmt --check`;
  `cargo test -p carrick-runtime fs_resolve_cache`;
  `cargo test -p carrick-vmm-hvf darwin_brk_trap_is_classified_as_host_fault`;
  `cargo test -p carrick-runtime exec_helpers::tests::debug_stop_signal_selector_accepts_comma_list`;
  `cargo check -p carrick-cli`;
  `just build -p carrick-cli`.
- Focused Carrick vet now passes twice:
  `target/conformance/logs/go-net-http-vet-lockfix1-003616.guest.log`
  (`real 32.79`) and
  `target/conformance/logs/go-net-http-vet-lockfix2-003720.guest.log`
  (`real 32.23`).
- Focused Carrick h1 still passes:
  `target/conformance/logs/go-net-http-h1-lockfix1-003713.guest.log`
  (`real 1.77`).
- Fresh Docker oracle timings, run after Carrick runs completed:
  `target/conformance/logs/docker-go-net-http-vet-lockfix-003803.log`
  passed vet in `real 4.11`;
  `target/conformance/logs/docker-go-net-http-h1-lockfix-003807.log`
  passed h1 in `real 0.19`.

Interpretation:

- Correctness blocker: fixed. The vet crash was a real Carrick host-runtime
  trap exposed through guest signal delivery.
- Performance is still not clean: vet is roughly 8x Docker wall-clock and h1 is
  roughly 9x Docker wall-clock. That is close enough to the "order of magnitude"
  threshold to keep treating this as performance debt during the bless campaign,
  not as a completed performance story.

### Full bless attempt: first fail-fast blocker is accept02

Hypotheses:

- H1: The first fail-fast diff, `ltp-accept02`, is not a timing problem. The
  Docker oracle reports success while Carrick reports `TFAIL: Multicast group
  was copied!`, so the likely gap is Linux-visible multicast socket state.
- H2: Direct multicast membership forwarding is not the issue. Carrick already
  rejects `IP_ADD_MEMBERSHIP`/`IPV6_JOIN_GROUP` as unsupported with `ENODEV`;
  `accept02` uses the protocol-independent `MCAST_*` path Carrick accepted as a
  no-op because Darwin has no matching optnames.

Tests:

- Ran full unfiltered `scripts/conformance/run-full.sh --bless`; it did not
  bless. The log
  `target/conformance/logs/conformance-bless-20260707-003946.log` fail-fasted
  after 51 gating verdicts with `ltp-accept02` as the first listed blocker.
- Ran focused Carrick and Docker reproducer for `accept02`. Carrick failed with
  `TFAIL: Multicast group was copied!`; Docker passed with
  `TPASS: Multicast group was not copied: EADDRNOTAVAIL (99)`.
- Added Linux-visible per-socket bookkeeping for protocol-independent
  `MCAST_JOIN_GROUP`/`MCAST_LEAVE_GROUP` and source-specific variants. Accepted
  sockets start with an empty membership set, matching Linux's rule that
  listener multicast memberships are not copied across `accept`.

Outcome:

- Helper checks passed:
  `cargo fmt --check`;
  `cargo test -p carrick-runtime mcast_membership_tests`;
  `cargo check -p carrick-cli`;
  `just build -p carrick-cli`.
- Focused Carrick `ltp-accept02` now passes:
  `target/conformance/logs/ltp-accept02-mcaststate-005017.carrick.log`.
- Timed focused Carrick run:
  `target/conformance/logs/ltp-accept02-mcaststate-time-005034.carrick.log`
  passed in `0.32 real`.
- Fresh Docker oracle run:
  `target/conformance/logs/ltp-accept02-mcaststate-docker-005023.docker.log`
  passed in `0.279 total`.

Interpretation:

- `accept02` was a modeled-state bug, not a slow-case symptom and not a host
  kqueue/epoll issue. The fix is a graceful Linux-visible failure on accepted
  sockets (`EADDRNOTAVAIL`) rather than a no-op success.
- Focused timing is acceptable here: Carrick is close to Docker for this case,
  so the larger performance outliers in the bless log remain separate targets.

### Second bless attempt: classify acct/bind, fix chroot root semantics

Hypotheses:

- H1: After fixing `accept02`, the early `acct01` and `bind06` regressions are
  classification/environment diffs, not Carrick runtime crashes.
- H2: `chroot04`/`chroot02` are real filesystem semantics bugs. Carrick records
  the new root for `getcwd`, but absolute path resolution still uses global `/`,
  and `chroot` does not check search permission on the final new-root directory
  before returning the capability error.

Tests:

- Reran full `scripts/conformance/run-full.sh --bless`; it did not bless, but
  `ltp-accept02` now matched. The log
  `target/conformance/logs/conformance-bless-20260707-005118.log` fail-fasted
  at 52 cached-oracle gating verdicts.
- Focused `acct01`: Carrick skipped because `/proc/config.gz` reports
  `CONFIG_BSD_PROCESS_ACCT` absent; Docker broke because the container could not
  acquire a block device. This is classification/baseline debt.
- Focused `bind06`: Carrick skipped because `AF_PACKET`/protocol 17 is not
  supported; Docker broke on unprivileged namespace setup. This is also
  classification/baseline debt.
- Focused `chroot04`: Carrick returned `EPERM` for a no-search-permission
  directory where Docker/Linux returned `EACCES`.
- Focused `chroot02`: Carrick succeeded at `chroot(tmpdir)` but `stat` of an
  absolute path inside the new root missed the file; Docker/Linux found it.

Outcome:

- Added resolver support for `io.chroot_root` on absolute paths, including the
  resolve-cache key so pre- and post-chroot absolute lookups cannot alias.
- Added a final-directory search-permission check for `chroot` before the
  capability check, preserving Linux's lookup-error precedence over `EPERM`.
- Focused checks passed:
  `cargo fmt --check`;
  `cargo test -p carrick-runtime chroot_`;
  `cargo check -p carrick-cli`;
  `just build -p carrick-cli`.
- Focused Carrick/Docker matches:
  `target/conformance/logs/ltp-chroot04-chrootfix-010138.carrick.log`
  passed in `0.62 real`, Docker
  `target/conformance/logs/ltp-chroot04-chrootfix-010138.docker.log`
  passed in `0.262 total`;
  `target/conformance/logs/ltp-chroot02-chrootfix-010139.carrick.log`
  passed in `0.34 real`, Docker
  `target/conformance/logs/ltp-chroot02-chrootfix-010139.docker.log`
  passed in `0.191 total`.

Interpretation:

- `acct01` and `bind06` should be marked/classified rather than treated as
  root-cause runtime bugs in this pass.
- `chroot02`/`chroot04` were real correctness bugs and are now fixed.
- Focused chroot timing is not pathological; the large performance outliers
  remain the process/pipe/epoll-heavy cases from the full-run summary.

### connect02: IPV6_ADDRFORM and TCP AF_UNSPEC disconnect

Hypotheses:

- H1: `ltp-connect02` is a real missing socket semantic. Focused Carrick failed
  at `setsockopt(IPV6_ADDRFORM)` with `ENOPROTOOPT`; Docker passed.
- H2: Accepting `IPV6_ADDRFORM` is not sufficient. The LTP test converts an
  accepted IPv6 TCP socket to IPv4, calls `connect(AF_UNSPEC)` to disconnect it,
  then reuses the same fd with `bind`/`listen`.

Tests:

- Read the LTP patch/source context for `connect02` to confirm the syscall
  sequence. The test loops over: connect IPv4 client, accept on IPv6 listener,
  `setsockopt(SOL_IPV6, IPV6_ADDRFORM, AF_INET)`, `connect(AF_UNSPEC)`, then
  `bind`/`listen`/accept on the same fd.
- First implementation only relabeled Carrick's guest-visible family from
  `AF_INET6` to `AF_INET`. Focused Carrick then advanced to the next failure:
  `connect(AF_UNSPEC)` returned `EISCONN`.
- Added modeled stream-socket disconnect: for `connect(AF_UNSPEC)` on a stream
  socket, Carrick swaps the open description's host backing fd for a fresh
  nonblocking socket with the stored guest family/type. This preserves the guest
  fd/open-description identity while giving later `bind`/`listen` an unconnected
  host socket.

Outcome:

- Focused checks passed:
  `cargo fmt --check`;
  `cargo test -p carrick-runtime ipv6_addrform_relabels_guest_family`;
  `cargo check -p carrick-cli`;
  `just build -p carrick-cli`.
- Focused Carrick `ltp-connect02` now passes:
  `target/conformance/logs/ltp-connect02-addrform-reset-011611.carrick.log`
  (`1.21 real`).
- Separate Docker oracle run also passes:
  `target/conformance/logs/ltp-connect02-addrform-reset-011611.docker.log`
  (`0.269 total`).

Interpretation:

- `connect02` was a real socket-state bug, not a baseline/classification issue.
- Focused timing is slower but not pathological; the large outliers remain the
  full-run process/pipe/epoll cases.

### delete_module02: module-infrastructure gap marker

Hypothesis:

- H1: `ltp-delete_module02` is not a useful Carrick implementation target during
  this bless pass. `delete_module` is deferred module infrastructure, and the
  Docker container does not provide a clean privileged module oracle either.

Tests:

- Focused Carrick:
  `target/conformance/logs/ltp-delete-module02-classify-012426.carrick.log`.
  The test reports `TCONF: syscall(106) __NR_delete_module not supported on your
  arch`, with summary `skipped 1`.
- Focused Docker oracle, run separately:
  `target/conformance/logs/ltp-delete-module02-classify-012426.docker.log`.
  Docker runs the assertions but four privileged/module cases fail with `EPERM`;
  only the non-superuser `EPERM` case passes.

Outcome:

- Added `known_gaps = ["summary"]` to `ltp-delete_module02` in
  `scripts/conformance/suites.toml`.

Interpretation:

- This records the current diff as a missing/deferred module facility plus
  container-oracle limitation, rather than spending this pass implementing Linux
  module loading/unloading on macOS.
