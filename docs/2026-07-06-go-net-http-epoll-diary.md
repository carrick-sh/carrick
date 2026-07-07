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
