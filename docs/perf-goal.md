# Carrick First-Principles Performance Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land significant Carrick performance wins by removing whole classes of runtime work: guest traps, host syscalls, guest/host copies, allocation churn, page dirtying, HVF mapping pressure, and macOS kernel wait/setup work.

**Architecture:** Optimize from first principles. Prefer changes that remove crossings, copies, dirty pages, mapping churn, and per-wait setup across dynamic and static workloads. Treat preload/interposition as a narrow measured fast path only after runtime-level batching, shim work, and structural VFS/I/O reductions have been exhausted.

**Tech Stack:** Rust, Carrick HVF runtime, Carrick syscall dispatcher, guest-memory host pointers, VFS backends, conformance probes, perf runner, macOS host syscalls, `kevent`, and HVF mapping APIs.

---

## Cost Model

Rank candidate work by the size of unavoidable cost it removes:

1. Guest traps and VM exits.
2. Host syscalls, Mach calls, `kevent`, `hv_vm_map`, and TLB/page-table churn.
3. Guest/host memory copies and temporary allocation.
4. Page dirtying that later expands fork snapshots, resident scans, and writeback.
5. VFS metadata/path walks and whole-file rootfs or overlay materialization.
6. Per-wait descriptor pinning, fd duplication, transient kqueue registration, and wake bookkeeping.

Every optimization must answer:

- What whole unit of work disappears?
- Which test, probe, trace, or benchmark proves it disappeared?
- Which workload classes benefit, and which do not?

## Design Position

The original `LD_PRELOAD` direction is useful only for narrow dynamic-libc workloads. It cannot help static Go or musl binaries, direct syscall users, or semantics where the runtime must arbitrate fd state, blocking behavior, signals, futexes, process metadata, or kernel-observable side effects.

Preferred order:

1. Keep identity and safe process-metadata syscalls in the EL1 shim where semantics are already local and stable.
2. Collapse runtime work that happens after a trap: vector I/O, mmap zeroing, wait setup, and VFS writeback.
3. Add dynamic workloads that prove trap count is still the dominant cost after structural runtime work.
4. If proven, add narrow interposers for specific semantic islands, such as batching libc writes to a known pipe/socket or answering explicitly cached process metadata.
5. Keep the syscall runtime authoritative. Interposition is a fast path, not a correctness layer.

Do not use ptrace in this performance plan.

## Current Branch State

Branch: `codex/perf-mmap-lazy-zero`

Landed slices:

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

Measured branch evidence:

- `perf_mmap_churn`, 64 untouched 8 MiB private anonymous mappings:
  - Before `14999846`: manual Carrick samples `54937.750`, `57827.458`, `55593.333` us.
  - After `14999846`: Carrick p50 `831.708` us, p95 `897.625` us.
  - Docker control p50 `60.667` us, p95 `197.750` us, noisy.
  - Correctness probes matched Docker/Linux: `mmapzerofill`, `mmaprecl`, and `forkcow`.
- `pwritev_burst`:
  - Runtime evidence: payload `read_bytes` calls dropped from `2` to `0`; host-pointer hits rose from `0` to `2`.
  - Benchmark rows in `docs/perf-results/2026-06-05-syscall.jsonl`: Carrick p50 `20849.208` us, p95 `26075.417` us, noisy; Docker p50 `3478.459` us, p95 `3654.750` us.
- `preadv_burst`:
  - Runtime evidence: borrowed readv/preadv writes guest payloads through host pointers; watched `write_bytes` calls dropped to `0`.
  - Benchmark rows in `docs/perf-results/2026-06-05-syscall.jsonl`: Carrick p50 `19852.375` us, p95 `22193.875` us, noisy; Docker p50 `2571.125` us, p95 `2902.375` us, noisy.
- Blocking host-write ownership:
  - Runtime evidence: `BlockingHostWrite` continuation preserves staged `Vec<u8>` pointer/capacity instead of cloning.
  - Probes matched Docker/Linux: `blockingpipewrite`, `writevpartial`, and `sigpipewrite`.
- Dirty-range writeback:
  - Runtime evidence: a 1-byte write to a 4 MiB overlay file reduced max backend writeback payload from `4194304` bytes to at most `1` byte.
- `large_meta`, 128 metadata/open/access cycles on a 256 MiB sparse file:
  - Before metadata-open fix at `8e72886`: Carrick p50 `14185998.250` us, p95 `14564686.458` us; Docker p50 `291.208` us, p95 `441.125` us, noisy.
  - After `e9cdb83`: Carrick p50 `26231.500` us, p95 `28435.083` us; Docker p50 `334.750` us, p95 `373.833` us, noisy.
  - This turns a roughly `48714x` metadata gap into roughly `78.36x`, so VFS path/setup cost still matters.

## Opportunity Ranking

### 1. VFS Streaming, Dirty Ranges, and Overlay Materialization

Status: highest priority.

The rootfs and overlay abstractions have already stopped reading payloads for metadata-only opens and stopped whole-file writeback for dirty ranges. The next gap is proving and improving build-tool-like workloads with many small updates over large file sets.

Expected removed work:

- Metadata-only operations do not read file contents.
- Small writes to large files do not clone or rewrite the full file.
- Writable rootfs-to-overlay materialization should avoid copying whole file contents when a range-backed backend or host fd can satisfy the mutation.
- Host-backed regular files should use fd/range operations where safe.

Key code:

- `crates/carrick-runtime/src/fs_backend.rs`
- `crates/carrick-runtime/src/dispatch/fs.rs`
- `crates/carrick-runtime/src/rootfs.rs`
- `crates/carrick-runtime/src/layer_cache.rs`
- `crates/carrick-cli/tests/perf_support/cases.rs`
- `crates/carrick-cli/tests/perf_support/invoke.rs`
- `crates/carrick-cli/tests/perf_runner.rs`
- `conformance-probes/src/bin/`

Milestone 1A: build-tool-like dirty-range workload.

- [x] Add RED perf registry coverage for a workload named `overlay_small_updates`.
  - Modify `crates/carrick-cli/tests/perf_support/cases.rs`.
  - The case should use dimension `disk`, probe `perf_overlay_small_updates`, metric `overlay_small_updates_total_us`, `mount_scratch=false`, and a Carrick fs mode of `memory`.
  - Run: `cargo test -p carrick-cli --test perf_runner perf_support::cases::tests::registry_contains_disk_perf_surface -- --nocapture`
  - Expected RED before implementation: missing `overlay_small_updates` or missing memory fs-mode metadata.
- [x] Add a narrow Carrick fs-mode field to the perf case model.
  - Existing cases should default to `host`.
  - The new workload should run Carrick with `--fs memory`.
  - Docker remains the control lane.
- [x] Thread the fs-mode through the perf runner.
  - Modify `crates/carrick-cli/tests/perf_support/invoke.rs` so `run_carrick` takes the case fs mode instead of hardcoding `--fs host`.
  - Modify `crates/carrick-cli/tests/perf_runner.rs` so Carrick result rows report the case fs mode.
  - Keep existing host-mounted cases unchanged.
- [x] Add `conformance-probes/src/bin/perf_overlay_small_updates.rs`.
  - Use `BENCH_DIR` with `/tmp` default.
  - Create a fixed set of large files, for example 16 files at 1 MiB each.
  - Use `ftruncate` or sparse creation for size setup.
  - Perform repeated 1-byte `pwrite` updates at rotating offsets, for example 512 updates total.
  - Emit `overlay_small_updates_total_us=<f>`, plus useful context such as `files`, `file_bytes`, `updates`, `write_bytes`, and `nproc`.
  - Keep the workload under the perf runner's 60-second Carrick sample deadline.
- [x] Run focused checks.
  - `cargo test -p carrick-cli --test perf_runner perf_support::cases::tests -- --nocapture`
  - `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin perf_overlay_small_updates`
  - `cargo fmt --all -- --check`
  - `git diff --check`
- [x] Record current wall-time evidence.
  - `CARRICK_PERF_FILTER=overlay_small_updates CARRICK_PERF_REPS=3 CARRICK_PERF_WARMUP=1 CARRICK_PERF_COOLDOWN_SECS=0 just bench quick`
  - Append rows to `docs/perf-results/2026-06-05-disk.jsonl`, the current disk result ledger on this branch.
- [x] Record before/after dirty-range evidence.
  - Preferred: build a temporary comparison Carrick binary from the commit immediately before `6e2ee14` and run the same probe under it.
  - If the old binary cannot run the new harness cleanly, keep wall-time before/after unchecked and rely only on byte-copy evidence until a comparable baseline is produced.
- [x] Commit as a logical docs/probe/harness slice if no runtime behavior changes are included.

Progress:

- 2026-06-06: Added RED registry coverage for `overlay_small_updates`; pre-fix `cargo test -p carrick-cli --test perf_runner perf_support::cases::tests::registry_contains_disk_perf_surface -- --nocapture` failed with `missing disk perf workload overlay_small_updates`.
- 2026-06-06: Added `PerfCase::carrick_fs_mode`, kept existing cases on `host`, registered `overlay_small_updates` with Carrick `--fs memory`, and changed perf result rows so Carrick reports the case fs mode while Docker continues to report `host`.
- 2026-06-06: Added `conformance-probes/src/bin/perf_overlay_small_updates.rs`. The probe creates 16 sparse 1 MiB files under `BENCH_DIR` or `/tmp`, then performs 512 one-byte `lseek` plus `write` updates at rotating offsets with open/close around each update.
- 2026-06-06: Focused checks passed: `cargo test -p carrick-cli --test perf_runner perf_support::cases::tests -- --nocapture`, `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin perf_overlay_small_updates`, `./scripts/build-probes.sh`, `cargo fmt --all -- --check`, and `git diff --check`.
- 2026-06-06: Initial filtered benchmark exposed a pre-existing Carrick memory-fs stdin issue: `--fs memory` receives EOF from piped host stdin, so the perf runner's base64 injection created a zero-byte `/tmp/p` and Carrick emitted `/bin/sh: 1: /tmp/p: not found`. Docker ran the same injected probe and emitted `overlay_small_updates_total_us`; Carrick `--fs host` also received the injected bytes, confirming the probe was valid and the blocker was memory-fs stdin delivery.
- 2026-06-06: Changed Carrick memory-fs perf cases to launch the static probe directly with `carrick run-elf --raw --fs memory <probe>` instead of stdin injection. This keeps host-fs cases on the existing image/injection path, keeps Docker as the injected image control, and prevents Carrick rows from claiming the Ubuntu image when they use direct `run-elf`.
- 2026-06-06: Trace-guided probe adjustment: direct `run-elf --fs memory` showed `pwrite64` returning `EBADF` on in-memory regular files, while the dirty-range path implemented in `6e2ee14` covers direct `write`/`writev`. The probe now uses `lseek` plus `write` for each one-byte update.
- 2026-06-06: Post-commit `CARRICK_PERF_FILTER=overlay_small_updates CARRICK_PERF_REPS=3 CARRICK_PERF_WARMUP=1 CARRICK_PERF_COOLDOWN_SECS=0 cargo test -p carrick-cli --test perf_runner perf_gate -- --nocapture --include-ignored` passed and appended rows to `docs/perf-results/2026-06-05-disk.jsonl`; Carrick memory-fs p50 `19734.125` us, p95 `20224.292` us; Docker p50 `1567.375` us, p95 `1788.542` us, noisy. Carrick remains about `12.59x` slower on this workload.
- 2026-06-06: Current VFS ranking after `overlay_small_updates`: keep VFS as the active target. `large_meta` remains about `78.36x` slower than Docker after the metadata-open fix, and `overlay_small_updates` is about `12.59x` slower with memory-fs dirty-range writeback. Wait-path fd/kqueue churn still needs its own workload before it can outrank these measured VFS gaps.
- 2026-06-06: Built a signed comparison binary from `8e7288693149a854b6316ed794b325d9b3ca966c`, the commit immediately before dirty-range writeback landed. Both the old and current binaries had the hypervisor entitlement, and both ran the same current `perf_overlay_small_updates` static probe under `run-elf --raw --fs memory`.
- 2026-06-06: Direct alternating before/after samples for `overlay_small_updates_total_us`: current totals `27720.709`, `13908.667`, `13440.042` us, p50 `13908.667` us; old pre-dirty-range totals `38911.459`, `35769.625`, `34081.042` us, p50 `35769.625` us. Dirty-range writeback therefore improves this workload by about `2.57x` versus the comparable old binary.

Milestone 1B: writable rootfs-to-overlay materialization.

- [ ] Add a RED test for opening a large rootfs-backed regular file for a small write.
  - The test should fail if `RootFsVfs` loads full file contents before the first small mutation.
  - Count payload-bearing `lookup` or `file_contents` calls.
- [ ] Add or reuse backend APIs that can materialize an overlay entry from metadata plus dirty ranges instead of full payload bytes.
- [ ] Preserve fallback behavior for non-regular entries, unsupported backends, and operations requiring full contents.
- [ ] Run focused open/write/stat/copy tests.
  - `cargo test -p carrick-runtime --test integration openat -- --nocapture`
  - `cargo test -p carrick-runtime --test integration write -- --nocapture`
  - `cargo test -p carrick-runtime --test integration writev -- --nocapture`
  - `cargo test -p carrick-runtime --test integration newfstatat -- --nocapture`
  - `cargo test -p carrick-runtime --test integration statx -- --nocapture`
- [ ] Re-run `large_meta` and `overlay_small_updates`.
- [ ] Commit runtime/test slice separately from benchmark result docs.

### 2. Wait Path fd Pinning and kqueue Churn

Status: next structural runtime target after VFS.

Repeated waits on stable descriptors should not pay repeated fd duplication, transient kqueue registration, and teardown when open-description lifetime is already anchored.

Expected removed work:

- Fewer `dup`/close pairs per wait.
- Fewer transient `kevent` registration/deletion calls.
- Fewer allocations for wait bookkeeping.
- Less macOS kernel time in event-loop-heavy workloads.

Key code:

- `crates/carrick-hvf/src/io_wait.rs`
- `crates/carrick-runtime/src/dispatch/fs.rs`
- fd/open-description ownership code

Milestone tasks:

- [ ] Add a wait-heavy probe that repeatedly waits on stable fds.
- [ ] Add correctness coverage for fd close/reuse during or near a wait.
- [ ] Count current `dup`, close, and `kevent` setup cost with `carrick trace` or DTrace.
- [ ] Introduce retained wait targets for open descriptions that can safely anchor host fd lifetime.
- [ ] Keep fd duplication fallback where descriptor lifetime cannot be anchored safely.
- [ ] Consider persistent kqueue subscriptions only with generation checks.
- [ ] Run wake-pipe, signal, process-exit, fd-reuse, poll, select, and epoll tests.
- [ ] Record duplicate-fd count, `kevent` setup count, and wall-time evidence.

### 3. Borrowed Guest-Memory I/O Follow-Through

Status: main fast paths landed; follow-up measurement remains useful.

Expected removed work already achieved:

- `pwritev` can use one host `libc::pwritev` when all non-empty guest iovecs expose readable host pointers.
- `readv` and `preadv` can use host `libc::readv`/`libc::preadv` when all non-empty guest iovecs expose writable host pointers.
- Fallback staging reads each non-empty payload once.
- Blocking host-write continuations can own already-staged buffers instead of cloning them.

Follow-up tasks:

- [ ] Add syscall-count evidence for borrowed vector I/O workloads, not only byte-copy tests.
- [ ] Re-check socket/pipe vector I/O paths for avoidable staging or cloning.
- [ ] Re-check stdio stream paths where validation ordering prevents direct borrowed I/O.
- [ ] Keep fallback tests for mixed host-pointer/non-host-pointer memory.

### 4. Anonymous mmap Lazy-Zero and Mapping Pressure

Status: large win landed; follow-up fork and mapping pressure work remains.

Expected removed work already achieved:

- Fresh private anonymous mappings no longer materialize and write full zero buffers into guest memory.
- Untouched mappings avoid eager page dirtying.

Follow-up tasks:

- [ ] Re-check shared anonymous subrange handling for remaining full-size zero staging.
- [ ] Re-check high-VA and alias-backed mapping paths for equivalent fresh-range zero materialization.
- [ ] Add a fork-heavy workload row after lazy-zero so fork benefit is measured directly.
- [ ] Count `hv_vm_map`/`hv_vm_unmap` on mmap-heavy workloads to separate guest trap cost from stage-2 mapping cost.

### 5. Targeted Trap Reduction After Measurement

Status: deferred until a workload proves trap count remains dominant.

Trap reduction should not begin with a general preload layer. Runtime work above improves static and dynamic workloads; preload/interposition only helps dynamic-libc callers and only for calls whose semantics can be cached or batched safely.

Milestone tasks:

- [ ] Build or select a dynamic-libc workload dominated by small writes or cacheable metadata calls.
- [ ] Measure trap count and wall time after VFS, iovec, mmap, and wait-path work.
- [ ] Compare three designs:
  - EL1 shim extension for safe identity-style syscalls.
  - Runtime batching after trap.
  - Narrow dynamic interposer for explicitly safe libc calls.
- [ ] Implement only the smallest semantics-preserving optimization.
- [ ] Document unsupported workloads, especially static binaries and direct syscall users.
- [ ] Record trap-count and wall-time evidence.

### 6. Fork Snapshot Follow-Up

Status: dependent on mmap and page-dirtying evidence.

Fork cost is affected by resident and dirty page pressure. Lazy-zero and dirty-range work should reduce avoidable fork pressure before deeper snapshot architecture changes are attempted.

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
- [ ] Add correctness probes before any snapshot-elision or dirty-tracking change.
- [ ] Only pursue deeper fork changes if mmap, iovec, VFS, and wait-path work no longer dominate the profile.

## Measurement Requirements

Every landed performance change records:

- Workload or probe name.
- Before and after wall time.
- Before and after trap count, host syscall count, allocation count, byte-copy count, fd/kqueue setup count, or `hv_vm_map` count when available.
- Code path whose work was removed.
- Correctness tests or conformance probes run.
- Workload classes that do not benefit.

Repo-local result artifacts:

- Use `docs/perf-results/*.jsonl` for benchmark rows.
- Keep manual samples in this file only when the perf harness cannot yet represent the workload.
- Mark noisy controls explicitly instead of hiding them.
- Keep runtime behavior commits separate from benchmark-result documentation commits when practical.

## Non-Goals

- Do not weaken conformance gates to improve benchmark appearance.
- Do not claim runtime wins from static inspection alone.
- Do not pursue ptrace in this plan.
- Do not build a general `LD_PRELOAD` compatibility layer before a dynamic workload proves trap count is still the bottleneck.
- Do not optimize syscall dispatch mechanics before removing larger traps, host syscalls, copies, page dirtying, or kernel wait setup.
- Do not take deep fork-snapshot architecture risk before lower-risk mmap, iovec, VFS, and wait-path work has been measured.

## Immediate Next Slice

Continue VFS dirty-range measurement with a memory-fs build-tool-like workload.

- [x] Add `overlay_small_updates` registry coverage and Carrick memory-fs case support.
- [x] Add `perf_overlay_small_updates` probe.
- [x] Run focused perf registry/probe checks.
- [x] Run current filtered benchmark and append rows.
- [x] Produce comparable before/after wall-time if an old binary can be run cleanly; otherwise leave wall-time baseline open and keep byte-copy evidence as the completed proof.
- [x] Re-rank VFS versus wait-path work after the new workload is measured.
