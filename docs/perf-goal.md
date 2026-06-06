# Carrick First-Principles Performance Goal

> Required workflow for agentic workers: keep this file current as the work
> moves. Use checkbox status for task progress, record measurement evidence
> here or in `docs/perf-results/*.jsonl`, and keep runtime changes separate
> from result-documentation commits when practical.

## Goal

Find and land significant Carrick performance gains by removing whole classes of
runtime work:

- guest traps and VM exits
- host syscalls, Mach calls, `kevent`, `hv_vm_map`, and page-table churn
- guest/host copies and temporary allocation
- page dirtying that expands fork snapshots, resident scans, and writeback
- VFS metadata/path walks and whole-file rootfs or overlay materialization
- per-wait descriptor pinning, fd duplication, transient kqueue registration,
  and wake bookkeeping

The performance work should improve static and dynamic workloads. Dynamic
interposition can be considered later, but the runtime remains the correctness
authority.

## Non-Goals

- Do not pursue ptrace in this plan.
- Do not weaken conformance gates to improve benchmark appearance.
- Do not claim runtime wins from static inspection alone.
- Do not build a general `LD_PRELOAD` compatibility layer before a dynamic
  workload proves trap count is still the bottleneck.
- Do not optimize syscall-dispatch mechanics before removing larger traps,
  host syscalls, copies, page dirtying, or kernel wait setup.
- Do not take deep fork-snapshot architecture risk before lower-risk mmap,
  iovec, VFS, and wait-path work has been measured.

## Cost Model

Rank candidate work by the size of unavoidable cost it removes:

1. Guest traps and VM exits.
2. Host syscalls, Mach calls, `kevent`, `hv_vm_map`, and TLB/page-table churn.
3. Guest/host memory copies and temporary allocation.
4. Page dirtying that later expands fork snapshots, resident scans, and writeback.
5. VFS metadata/path walks and whole-file rootfs or overlay materialization.
6. Per-wait descriptor pinning, fd duplication, transient kqueue registration,
   and wake bookkeeping.

Every optimization must answer:

- What whole unit of work disappears?
- Which test, probe, trace, or benchmark proves it disappeared?
- Which workload classes benefit?
- Which workload classes do not benefit?

## Design Position

The original `LD_PRELOAD` direction is useful only for narrow dynamic-libc
workloads. It cannot help static Go or musl binaries, direct syscall users, or
semantics where Carrick must arbitrate fd state, blocking behavior, signals,
futexes, process metadata, kernel-visible side effects, or guest memory
ownership.

Preferred order:

1. Keep identity and safe process-metadata syscalls in the EL1 shim where the
   semantics are already local and stable.
2. Collapse runtime work that happens after a trap: vector I/O, mmap zeroing,
   wait setup, VFS read/writeback, and overlay materialization.
3. Add dynamic workloads that prove trap count is still dominant after the
   structural runtime work.
4. If proven, add narrow interposers for specific semantic islands, such as
   batching libc writes to a known pipe/socket or answering explicitly cached
   process metadata.
5. Keep the syscall runtime authoritative. Interposition is a fast path, not a
   correctness layer.

## Current Branch State

Branch: `codex/perf-mmap-lazy-zero`

Recent landed slices:

- `14999846d766db29f7333fffa47d5d103914f26b` - `perf(mem): skip fresh anon mmap zero writes`
- `306a359` - `docs(perf): record mmap churn result`
- `d41e658` - `perf(io): stage pwritev buffers once`
- `efd09cdb8115dd5895d13212e945886337fb5f9a` - `perf(io): use borrowed pwritev buffers`
- `f820d05` - `docs(perf): record pwritev burst result`
- `45086059c0ecb4a0a4dd6f03968a5bbf8f0b1d9d` - `perf(io): use borrowed readv buffers`
- `e79d547` - `docs(perf): record preadv burst result`
- `dd72b8eff34b3f6c5e82dc211cff6d5b19584508` - `perf(io): move blocking write buffers`
- `8e72886` - `docs(perf): record blocking write ownership`
- `6e2ee14` - `perf(fs): write dirty file ranges`
- `e9cdb83` - `perf(fs): avoid payload reads for metadata opens`
- `22c5283` - `docs(perf): record large meta improvement`
- `54356c8` - `perf(fs): add overlay small update workload`
- `3e1ad50` - `perf(fs): run memory workload directly`
- `8647339` - `docs(perf): record overlay small update result`
- `e831ee0` - `docs(perf): record dirty range comparison`
- `4430ac2` - `perf(fs): lazily copy up rootfs writes`
- `2744261` - `docs(perf): record rootfs cow benchmark`

## Current Evidence

### Anonymous mmap lazy-zero

Workload: `perf_mmap_churn`, 64 untouched 8 MiB private anonymous mappings.

- Before `14999846`: manual Carrick samples `54937.750`, `57827.458`,
  `55593.333` us.
- After `14999846`: Carrick p50 `831.708` us, p95 `897.625` us.
- Docker control p50 `60.667` us, p95 `197.750` us, noisy.
- Correctness probes matched Docker/Linux: `mmapzerofill`, `mmaprecl`, and
  `forkcow`.

### Borrowed pwritev

Workload: `pwritev_burst`.

- Runtime evidence: payload `read_bytes` calls dropped from `2` to `0`;
  host-pointer hits rose from `0` to `2`.
- Benchmark rows in `docs/perf-results/2026-06-05-syscall.jsonl`: Carrick p50
  `20849.208` us, p95 `26075.417` us, noisy; Docker p50 `3478.459` us,
  p95 `3654.750` us.

### Borrowed readv and preadv

Workload: `preadv_burst`.

- Runtime evidence: borrowed `readv`/`preadv` writes guest payloads through host
  pointers; watched `write_bytes` calls dropped to `0`.
- Benchmark rows in `docs/perf-results/2026-06-05-syscall.jsonl`: Carrick p50
  `19852.375` us, p95 `22193.875` us, noisy; Docker p50 `2571.125` us,
  p95 `2902.375` us, noisy.

### Blocking host-write ownership

- Runtime evidence: `BlockingHostWrite` continuation preserves staged
  `Vec<u8>` pointer/capacity instead of cloning.
- Probes matched Docker/Linux: `blockingpipewrite`, `writevpartial`, and
  `sigpipewrite`.

### Dirty-range writeback

- Runtime evidence: a 1-byte write to a 4 MiB overlay file reduced max backend
  writeback payload from `4194304` bytes to at most `1` byte.
- Alternating comparison against a signed pre-dirty-range binary from
  `8e7288693149a854b6316ed794b325d9b3ca966c`:
  - current totals: `27720.709`, `13908.667`, `13440.042` us; p50 `13908.667`
    us.
  - old totals: `38911.459`, `35769.625`, `34081.042` us; p50 `35769.625`
    us.
  - result: about `2.57x` faster for `overlay_small_updates` under
    `run-elf --raw --fs memory`.

### Metadata-only VFS opens

Workload: `large_meta`, 128 metadata/open/access cycles on a 256 MiB sparse
file.

- Before metadata-open fix at `8e72886`: Carrick p50 `14185998.250` us,
  p95 `14564686.458` us; Docker p50 `291.208` us, p95 `441.125` us, noisy.
- After `e9cdb83`: Carrick p50 `26231.500` us, p95 `28435.083` us; Docker p50
  `334.750` us, p95 `373.833` us, noisy.
- This turns a roughly `48714x` metadata gap into roughly `78.36x`, so VFS
  path/setup cost still matters.

### Rootfs-backed writable COW

- RED test before the fix: `small_write_to_large_rootfs_file_does_not_copy_up_whole_file`
  failed with `max writeback payload was 4194304`.
- Implemented shared rootfs payload handles (`Arc<[u8]>`), backend
  `create_file_from_rootfs`, sparse rootfs-backed memory entries, and
  descriptor-side rootfs-backed dirty ranges.
- Writable non-truncating rootfs opens now install a COW overlay entry and
  update only dirty ranges on write.
- Truncating opens, host-backed opens, synthetic files, and full-content
  operations keep dense/fallback behavior.
- Focused checks passed:
  - `cargo test -p carrick-runtime --test integration small_write_to_large -- --nocapture`
  - `cargo test -p carrick-runtime --test integration rootfs_overlay -- --nocapture`
  - `cargo test -p carrick-runtime --test integration pwrite64_bootstrap_returns_espipe_for_streams_and_ebadf_for_rootfs_fds -- --nocapture`
  - `cargo test -p carrick-runtime --test integration copy_file_range_ -- --nocapture`
  - `cargo test -p carrick-runtime --tests --no-run`
  - `cargo fmt --all -- --check`
  - `git diff --check`
- Post-runtime-slice benchmark rows were appended to
  `docs/perf-results/2026-06-06-disk.jsonl` at
  `4430ac2be443757468915c00309a43b2ed7b9bee`:
  - `large_meta`: Carrick p50 `25647.500` us, p95 `28589.333` us, noisy;
    Docker p50 `547.584` us, p95 `673.958` us, noisy; Carrick remains about
    `46.84x` slower.
  - `overlay_small_updates`: Carrick memory-fs p50 `19890.709` us,
    p95 `21616.875` us; Docker p50 `1500.292` us, p95 `2000.458` us, noisy;
    Carrick remains about `13.26x` slower.

## Ranked Opportunities

### 1. VFS Streaming, Dirty Ranges, and Overlay Materialization

Status: highest measured priority so far, with major wins landed and more
surface still visible.

Expected removed work:

- Metadata-only operations do not read file contents.
- Small writes to large files do not clone or rewrite full payloads.
- Writable rootfs-to-overlay materialization avoids copying whole file contents
  when a range-backed backend or host fd can satisfy the mutation.
- Host-backed regular files use fd/range operations where safe.

Key code:

- `crates/carrick-runtime/src/fs_backend.rs`
- `crates/carrick-runtime/src/dispatch/fs.rs`
- `crates/carrick-runtime/src/rootfs.rs`
- `crates/carrick-runtime/src/layer_cache.rs`
- `crates/carrick-cli/tests/perf_support/cases.rs`
- `crates/carrick-cli/tests/perf_support/invoke.rs`
- `crates/carrick-cli/tests/perf_runner.rs`
- `conformance-probes/src/bin/`

Completed:

- [x] Added `overlay_small_updates` perf registry coverage.
- [x] Added a Carrick fs-mode field to perf cases; existing cases default to
  `host`, while `overlay_small_updates` runs Carrick with `--fs memory`.
- [x] Threaded fs-mode through the perf runner and result rows.
- [x] Added `conformance-probes/src/bin/perf_overlay_small_updates.rs`.
- [x] Changed Carrick memory-fs perf cases to launch static probes directly via
  `carrick run-elf --raw --fs memory <probe>` instead of stdin injection.
- [x] Changed the probe from `pwrite64` to `lseek` plus `write`, matching the
  current memory-fs dirty-range support.
- [x] Recorded current wall-time evidence.
- [x] Recorded before/after dirty-range evidence.
- [x] Added rootfs-backed COW write support.
- [x] Re-ran `large_meta` and `overlay_small_updates`.

Remaining VFS questions:

- [ ] Re-check path/open setup cost in `large_meta`, since Carrick remains about
  `46.84x` slower after payload-copy fixes.
- [ ] Identify whether the remaining `overlay_small_updates` gap is dominated by
  traps, VFS lookup/setup, memory-backend range maintenance, or host file setup.
- [ ] Add byte-copy/allocation counters for the remaining VFS hot paths where
  wall time alone is not diagnostic.

### 2. Wait Path fd Pinning and kqueue Churn

Status: retained fd pinning landed; transient kqueue setup remains.

Repeated waits on stable descriptors should not pay repeated fd duplication,
transient kqueue registration, and teardown when open-description lifetime is
already anchored.

Expected removed work:

- Fewer `dup`/close pairs per wait.
- Fewer transient `kevent` registration/deletion calls.
- Fewer allocations for wait bookkeeping.
- Less macOS kernel time in event-loop-heavy workloads.

Key code:

- `crates/carrick-hvf/src/io_wait.rs`
- `crates/carrick-runtime/src/dispatch/fs.rs`
- `crates/carrick-runtime/src/dispatch/net.rs`
- `crates/carrick-runtime/src/dispatch/mod.rs`
- fd/open-description ownership code

Known current shape:

- Direct host read/write waits carry retained host-fd owners when the
  dispatcher already has an `OpenFile` anchor, so `PinnedWaitFds` can skip
  per-wait `dup` for those descriptors.
- Raw wait targets, including broad poll/select/epoll paths where descriptor
  lifetime is not yet anchored, still use the fail-closed per-wait `dup`
  fallback.
- `HvfEventLoop` still waits through kqueue or poll fallback, and the kqueue
  path still registers and deletes fd filters around each wait.
- Runtime dispatch has `WaitOnFds`, `WaitOnFdsSelect`, and `WaitOnFdsPoll`
  paths.
- Existing probes cover many poll/epoll correctness cases, but there is no
  wait-heavy perf workload that isolates stable-fd wait setup.

Immediate measurement slice:

- [x] Inspect the wait implementation:
  - `sed -n '1,130p' crates/carrick-hvf/src/io_wait.rs`
  - `sed -n '293,430p' crates/carrick-hvf/src/io_wait.rs`
  - `sed -n '611,735p' crates/carrick-hvf/src/io_wait.rs`
  - `sed -n '743,870p' crates/carrick-hvf/src/io_wait.rs`
  - `sed -n '980,1035p' crates/carrick-hvf/src/io_wait.rs`
  - `sed -n '420,520p' crates/carrick-runtime/src/dispatch/net.rs`
  - `sed -n '1300,1340p' crates/carrick-runtime/src/dispatch/mod.rs`
- [x] Add a wait-heavy perf probe:
  `conformance-probes/src/bin/perf_wait_pipe_pingpong.rs`.
- [x] Add a perf registry case:
  - probe: `perf_wait_pipe_pingpong`
  - dimension: `syscall` unless a dedicated wait dimension is added
  - workload: `wait_pipe_pingpong`
  - metric key: `wait_pipe_pingpong_p50_us`
  - unit: `us`
  - higher is better: `false`
  - Carrick fs mode: `host`
  - scratch mount: `false`
- [x] Add correctness coverage for fd close/reuse during or near a wait if a
  narrow uncovered gap is visible.
- [x] Count current `dup`, `close`, and `kevent` setup cost with DTrace if the
  host permits it.
- [x] Implement the smallest retained-wait-target change only if count evidence
  shows the churn is still material.
- [x] Keep fd duplication fallback where descriptor lifetime cannot be anchored
  safely.
- [ ] Consider persistent kqueue subscriptions only with generation checks.
- [x] Run wake-pipe, fd-reuse, poll, select, and epoll tests before claiming
  this retained-fd runtime behavior change.
- [ ] Run signal and process-exit tests before claiming any future persistent
  kqueue subscription behavior change.

Suggested probe design:

- Use two pipes.
- Main thread writes a one-byte "go" token to a control pipe, then immediately
  blocks on reading a one-byte data pipe.
- Worker thread blocks on the control pipe and writes one byte to the data pipe
  for each token.
- The main thread measures the blocking read loop after warmup.
- This should exercise the runtime `WaitOnFds` path on a stable fd without
  relying on an artificial timeout sleep.
- Print `wait_pipe_pingpong_p50_us`, `wait_pipe_pingpong_p95_us`,
  `wait_pipe_pingpong_min_us`, `iters`, and `nproc`.

Suggested checks:

```sh
cargo test -p carrick-cli --test perf_runner perf_support::cases::tests -- --nocapture
cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin perf_wait_pipe_pingpong
./scripts/build-probes.sh
CARRICK_PERF_FILTER=wait_pipe_pingpong CARRICK_PERF_REPS=3 CARRICK_PERF_WARMUP=1 CARRICK_PERF_COOLDOWN_SECS=0 cargo test -p carrick-cli --test perf_runner perf_gate -- --nocapture --include-ignored
```

Suggested host syscall count attempt:

```sh
sudo dtrace -qn 'syscall::dup:return /execname == "carrick"/ { @["dup"] = count(); } syscall::kevent:return /execname == "carrick"/ { @["kevent"] = count(); } syscall::close:return /execname == "carrick"/ { @["close"] = count(); } tick-5s { exit(0); }' -c 'target/release/carrick run-elf --raw --fs host conformance-probes/target/aarch64-unknown-linux-musl/release/perf_wait_pipe_pingpong'
```

If DTrace is blocked by host policy, record that explicitly and keep the slice
to wall-time plus runtime-path evidence.

Progress:

- 2026-06-06: Added RED syscall registry coverage for `wait_pipe_pingpong`;
  pre-fix `cargo test -p carrick-cli --test perf_runner perf_support::cases::tests::registry_contains_syscall_perf_surface -- --nocapture`
  failed with `missing perf workload wait_pipe_pingpong`.
- 2026-06-06: Added the `wait_pipe_pingpong` syscall perf case, then watched
  `registered_perf_probes_have_sources` fail with missing
  `conformance-probes/src/bin/perf_wait_pipe_pingpong.rs`.
- 2026-06-06: Added `perf_wait_pipe_pingpong`, a two-pipe handoff probe where
  the main thread sends a control byte and then blocks reading a stable data
  pipe fd while a worker writes the response byte.
- 2026-06-06: Focused checks passed:
  `cargo test -p carrick-cli --test perf_runner perf_support::cases::tests -- --nocapture`,
  `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin perf_wait_pipe_pingpong`,
  `./scripts/build-probes.sh`, `cargo fmt --all -- --check`, and
  `git diff --check`. `./scripts/build-probes.sh` still emits existing warnings
  in older probes, but the new probe built and appeared in the aarch64 static
  release output.
- 2026-06-06: Filtered perf run passed:
  `CARRICK_PERF_FILTER=wait_pipe_pingpong CARRICK_PERF_REPS=3 CARRICK_PERF_WARMUP=1 CARRICK_PERF_COOLDOWN_SECS=0 cargo test -p carrick-cli --test perf_runner perf_gate -- --nocapture --include-ignored`.
  Rows were appended to `docs/perf-results/2026-06-06-syscall.jsonl` at
  `2744261696c548258d221abfcebc63cf2ccaa874`: Carrick p50 `16.083` us,
  p95 `16.375` us; Docker p50 `23.708` us, p95 `23.750` us. Carrick was
  `1.47x` lower latency on this narrow pipe handoff workload.
- 2026-06-06: DTrace host syscall count over one direct Carrick run of the
  probe (`500` warmup plus `3000` measured handoffs) counted `dup=6999`,
  `close=7059`, and `kevent=14091`. This confirms the current wait path still
  pays roughly two fd pins and four kqueue calls per handoff even when the
  watched descriptors are stable.
- 2026-06-06: Count evidence justified a narrow retained-wait-target change:
  `WaitFds` now carries private `HostFdRef` lifetime guards, direct host
  read/write waits mark their fds anchored when an `OpenFile` owner is already
  available, and `PinnedWaitFds` skips `dup` only for anchored fds. Raw
  wait targets still use the fail-closed `dup` fallback.
- 2026-06-06: Added correctness coverage for the retained target: the new
  `anchored_wait_fd_uses_original_fd_without_closing_it` test failed before
  `PinnedWaitFds` honored anchored fds (`left: 5`, `right: 3`) and passes after
  the change. The dispatcher test
  `anchored_wait_fds_keep_host_fd_live_after_open_file_drop` proves the
  `WaitFds` guard keeps a host fd pollable after the original `OpenFile` drops,
  modeling guest close/reuse while the runtime is parked.
- 2026-06-06: Focused runtime checks passed:
  `cargo test -p carrick-hvf io_wait::tests -- --nocapture`,
  `cargo test -p carrick-runtime anchored_wait_fds_keep_host_fd_live_after_open_file_drop -- --nocapture`,
  `cargo test -p carrick-runtime --test integration kqueue_wait -- --nocapture`,
  `cargo test -p carrick-runtime --test integration epoll_waits_on_host_backed_edge_interests_when_no_event_is_ready -- --nocapture`,
  `cargo test -p carrick-runtime --test integration epoll_wakes_accepted_socket_after_peer_write -- --nocapture`,
  `cargo test -p carrick-runtime --test integration ppoll_reports_eventfd_pipe_and_invalid_fd_readiness -- --nocapture`,
  `cargo test -p carrick-runtime --test integration pselect6_reports_eventfd_pipe_and_write_readiness -- --nocapture`,
  `cargo test -p carrick-runtime --test integration close_of_added_fd_auto_removes_it_from_epoll_interest -- --nocapture`,
  `cargo test -p carrick-runtime --tests --no-run`, `cargo fmt --all -- --check`,
  `git diff --check`, and `./scripts/build-signed.sh`.
- 2026-06-06: Post-runtime-slice filtered perf run passed at
  `db6d5cc86d583e94cba4c2f9473f667117cdbd51` and appended rows to
  `docs/perf-results/2026-06-06-syscall.jsonl`: Carrick p50 `15.542` us,
  p95 `16.000` us; Docker p50 `23.667` us, p95 `23.667` us. Direct DTrace on
  the same probe counted `close=61` and `kevent=14069`, with no `dup` entries in
  the aggregation. The retained-fd slice removed the per-wait `dup` churn and
  most matching close churn; transient kqueue registration/deletion remains.

### 3. Borrowed Guest-Memory I/O Follow-Through

Status: main fast paths landed; follow-up measurement remains useful.

Expected removed work already achieved:

- `pwritev` can use one host `libc::pwritev` when all non-empty guest iovecs
  expose readable host pointers.
- `readv` and `preadv` can use host `libc::readv`/`libc::preadv` when all
  non-empty guest iovecs expose writable host pointers.
- Fallback staging reads each non-empty payload once.
- Blocking host-write continuations can own already-staged buffers instead of
  cloning them.

Follow-up tasks:

- [ ] Add syscall-count evidence for borrowed vector I/O workloads, not only
  byte-copy tests.
- [ ] Re-check socket/pipe vector I/O paths for avoidable staging or cloning.
- [ ] Re-check stdio stream paths where validation ordering prevents direct
  borrowed I/O.
- [ ] Keep fallback tests for mixed host-pointer/non-host-pointer memory.

### 4. Anonymous mmap Lazy-Zero and Mapping Pressure

Status: large win landed; follow-up fork and mapping-pressure work remains.

Expected removed work already achieved:

- Fresh private anonymous mappings no longer materialize and write full zero
  buffers into guest memory.
- Untouched mappings avoid eager page dirtying.

Follow-up tasks:

- [ ] Re-check shared anonymous subrange handling for remaining full-size zero
  staging.
- [ ] Re-check high-VA and alias-backed mapping paths for equivalent fresh-range
  zero materialization.
- [ ] Add a fork-heavy workload row after lazy-zero so fork benefit is measured
  directly.
- [ ] Count `hv_vm_map`/`hv_vm_unmap` on mmap-heavy workloads to separate guest
  trap cost from stage-2 mapping cost.

### 5. Targeted Trap Reduction After Measurement

Status: deferred until a workload proves trap count remains dominant.

Trap reduction should not begin with a general preload layer. Runtime work above
improves static and dynamic workloads; preload/interposition only helps
dynamic-libc callers and only for calls whose semantics can be cached or batched
safely.

Milestone tasks:

- [ ] Build or select a dynamic-libc workload dominated by small writes or
  cacheable metadata calls.
- [ ] Measure trap count and wall time after VFS, iovec, mmap, and wait-path
  work.
- [ ] Compare three designs:
  - EL1 shim extension for safe identity-style syscalls.
  - Runtime batching after trap.
  - Narrow dynamic interposer for explicitly safe libc calls.
- [ ] Implement only the smallest semantics-preserving optimization.
- [ ] Document unsupported workloads, especially static binaries and direct
  syscall users.
- [ ] Record trap-count and wall-time evidence.

### 6. Fork Snapshot Follow-Up

Status: dependent on mmap and page-dirtying evidence.

Fork cost is affected by resident and dirty page pressure. Lazy-zero and
dirty-range work should reduce avoidable fork pressure before deeper snapshot
architecture changes are attempted.

Key code:

- `crates/carrick-hvf/src/trap.rs`
- mapping metadata and memory backing helpers

Milestone tasks:

- [ ] Re-measure fork-heavy workloads after lazy-zero and dirty-range work.
- [ ] Classify remaining fork cost by mapping type:
  - private anonymous
  - shared anonymous
  - host aliases
  - stack
  - file-backed regions
- [ ] Add correctness probes before any snapshot-elision or dirty-tracking
  change.
- [ ] Only pursue deeper fork changes if mmap, iovec, VFS, and wait-path work no
  longer dominate the profile.

## Measurement Requirements

Every landed performance change records:

- workload or probe name
- before and after wall time
- before and after trap count, host syscall count, allocation count, byte-copy
  count, fd/kqueue setup count, or `hv_vm_map` count when available
- code path whose work was removed
- correctness tests or conformance probes run
- workload classes that do not benefit

Repo-local result artifacts:

- Use `docs/perf-results/*.jsonl` for benchmark rows.
- Keep manual samples in this file only when the perf harness cannot yet
  represent the workload.
- Mark noisy controls explicitly instead of hiding them.
- Keep runtime behavior commits separate from benchmark-result documentation
  commits when practical.

## Immediate Next Slice

Start wait-path fd pinning measurement.

- [x] Add `perf_wait_pipe_pingpong` and register it in the perf runner.
- [x] Run focused registry/probe checks.
- [x] Run one short Carrick-vs-Docker perf sample set.
- [x] Attempt host syscall counts for `dup`, `close`, and `kevent`.
- [x] Decide whether retained wait targets are justified by measured churn.
- [x] If justified, implement the smallest retained-wait-target change with fd
  close/reuse correctness coverage.
- [ ] Decide whether persistent kqueue subscriptions are justified by the
  remaining `kevent` count.
