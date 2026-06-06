# Carrick Significant Performance Gains Goal

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land significant Carrick performance wins by removing whole classes of runtime work: guest traps, host syscalls, guest/host copies, allocation churn, page dirtying, HVF mapping pressure, and macOS kernel wait/setup work.

**Architecture:** Work from first principles. Prefer designs that reduce crossings, copies, dirty pages, mapping churn, and per-wait setup over local syscall-dispatch micro-optimizations. Treat preload/interposition as a narrow workload-specific optimization only after runtime-level batching and shim opportunities have been measured.

**Tech Stack:** Rust, Carrick HVF runtime, Carrick syscall dispatcher, guest memory/page-table machinery, VFS backends, conformance probes, perf runner, macOS host syscalls and kqueue.

---

## Current State

Branch: `codex/perf-mmap-lazy-zero`

Landed slices:

- `14999846d766db29f7333fffa47d5d103914f26b` - `perf(mem): skip fresh anon mmap zero writes`
- `306a359` - `docs(perf): record mmap churn result`
- `d41e658` - `perf(io): stage pwritev buffers once`
- `efd09cdb8115dd5895d13212e945886337fb5f9a` - `perf(io): use borrowed pwritev buffers`

Measured branch evidence:

- `perf_mmap_churn`, 64 untouched 8 MiB private anonymous mappings:
  - Before commit `be9d01a`: Carrick manual samples `54937.750`, `57827.458`, `55593.333` us.
  - After commit `14999846`: filtered `just bench quick` wrote `docs/perf-results/2026-06-05-memory.jsonl`; Carrick p50 `831.708` us and p95 `897.625` us.
  - Docker control p50 `60.667` us and p95 `197.750` us, marked noisy.
- Correctness pressure after the mmap change:
  - `scripts/run-probe.sh mmapzerofill` MATCH, `anon_mmap_is_zero_filled=true`.
  - `scripts/run-probe.sh mmaprecl` MATCH, `churn_ok=true`, `reuse_zero=true`.
  - `scripts/run-probe.sh forkcow` MATCH, including `mmap_isolated=true`.
- `pwritev` duplicate-read reduction:
  - RED test `syscall_fs::pwritev_host_file_reads_each_guest_iovec_once` initially observed four payload reads for two guest iovecs.
  - Commit `d41e658` stages each guest payload once during validation and reuses the staged buffers for host-file writes.
  - Focused checks passed:
    - `cargo test -p carrick-runtime --test integration pwritev_host_file_reads_each_guest_iovec_once -- --nocapture`
    - `cargo test -p carrick-runtime --test integration pwritev_bootstrap_validates_iovecs_and_reports_stream_errors -- --nocapture`
    - `cargo fmt --all -- --check`
- Borrowed `pwritev` host-file fast path:
  - RED test `syscall_fs::pwritev_host_file_uses_guest_host_ptrs_without_payload_reads` initially observed two payload `read_bytes` calls and zero host-pointer hits.
  - Commit `efd09cd` uses one host `libc::pwritev` when all non-empty guest iovecs expose `host_ptr_for_read`.
  - Fallback tests cover mixed host-pointer/non-host-pointer iovecs and unreadable fallback payloads.
  - Filtered `just bench quick` wrote `pwritev_burst` rows to `docs/perf-results/2026-06-05-syscall.jsonl`: Carrick p50 `20849.208` us, p95 `26075.417` us, marked noisy; Docker p50 `3478.459` us, p95 `3654.750` us.

## First-Principles Cost Model

Rank work by the amount of unavoidable cost it removes:

1. Guest traps and VM exits.
2. Host syscalls, Mach calls, `kevent`, `hv_vm_map`, and TLB/page-table churn.
3. Guest/host memory copies and temporary allocation.
4. Page dirtying that later expands fork snapshots, resident scans, and writeback.
5. VFS metadata/path walks and whole-file rootfs or overlay rewrites.
6. Per-wait descriptor pinning, fd duplication, transient kqueue registration, and wake bookkeeping.

The useful question for every proposed optimization is: what whole unit of work disappears, and which probe proves it disappeared?

## Design Position on Trap Reduction and Interposition

The original `LD_PRELOAD` idea is useful only for a narrow class of dynamic-libc workloads. It cannot help static Go or musl binaries, direct syscall users, or kernel-observable semantics that require the runtime to arbitrate fd state, blocking behavior, signals, futexes, or process metadata.

Preferred order:

1. Keep identity and safe process-metadata syscalls in the EL1 shim where semantics are already local and stable.
2. Collapse runtime work that happens after a trap, especially vector I/O, mmap zeroing, wait setup, and VFS writeback.
3. Add a dynamic workload that proves trap count is still the dominant cost after the structural runtime work.
4. If the workload proves it, add a narrow interposer for a specific semantic island, such as batching libc writes to a known pipe/socket or answering explicitly cached process metadata.
5. Keep the syscall runtime authoritative. Interposition is a fast path, not a correctness layer.

Do not use ptrace as part of this performance plan.

## Opportunity Ranking

### 1. Anonymous mmap Lazy-Zero

Status: partially landed, with measured win.

The fresh private anonymous path no longer materializes and writes a full zero buffer into guest memory. This removed a large byte-proportional cost and avoided eager page dirtying for untouched mappings.

Remaining follow-up:

- [ ] Re-check shared anonymous subrange handling for any remaining full-size zero buffer staging.
- [ ] Re-check high-VA and alias-backed mapping paths for equivalent fresh-range zero materialization.
- [ ] Add a fork-heavy workload row after the lazy-zero change so fork benefit is measured directly, not inferred.

### 2. Borrowed Guest-Memory Iovec I/O

Status: in progress.

This is the next highest-confidence structural win. The goal is to turn validated guest ranges into host `iovec` descriptors when the backend can safely expose contiguous host pointers, then call the host vector syscall once. The fallback remains the existing copy/staged path.

Expected removed work:

- One host syscall per iovec becomes one vector syscall.
- Guest payload copy into temporary `Vec<u8>` disappears on the fast path.
- Repeated payload reads are avoided on fallback.
- Blocking-write handoff can transfer an existing buffer instead of cloning it.

Key code:

- `crates/carrick-guest-mem/src/lib.rs`
  - Existing `GuestMemory::host_ptr_for_read`
  - Existing `GuestMemory::host_ptr_for_write`
- `crates/carrick-hvf/src/trap.rs`
  - HVF host-pointer implementation and permission checks
- `crates/carrick-runtime/src/dispatch/fs.rs`
  - `readv`
  - `preadv`
  - `pwritev`
  - host-file write paths
  - blocking write handoff
- `crates/carrick-runtime/src/dispatch/mod.rs`
  - `read_iovecs`
- `crates/carrick-runtime/tests/integration/syscall_fs.rs`
  - focused integration coverage

Milestone 2A: borrowed `pwritev` host-file fast path.

- [x] Add `syscall_fs::pwritev_host_file_uses_guest_host_ptrs_without_payload_reads`.
  - Use a custom test memory that implements `host_ptr_for_read` for two exact payload ranges.
  - Count payload `read_bytes` calls.
  - Expected RED on current branch: file contents are correct, but payload `read_bytes` count is `2` and host-pointer hits are `0`.
  - Expected PASS after implementation: file contents are correct, payload `read_bytes` count is `0`, host-pointer hits are `2`, and one host `pwritev` is used when observable through syscall-count tooling.
- [x] Add `syscall_fs::pwritev_host_file_falls_back_to_staging_when_any_iovec_lacks_host_ptr`.
  - First payload range returns a host pointer.
  - Second payload range returns `None`.
  - Expected result: write succeeds, file contents match, staged fallback reads each non-empty payload exactly once.
- [x] Add `syscall_fs::pwritev_host_file_reports_efault_when_fallback_payload_is_unreadable`.
  - At least one non-empty payload has no host pointer and fails `read_bytes`.
  - Expected result: Linux-compatible `EFAULT`; no partial host-file write for the invalid validation case.
- [x] Implement a helper in `crates/carrick-runtime/src/dispatch/fs.rs` that prepares `pwritev` payloads in one of two shapes:
  - `Borrowed(Vec<libc::iovec>)` when every non-empty segment has a valid `host_ptr_for_read`.
  - `Staged(Vec<Vec<u8>>)` when any non-empty segment lacks a host pointer.
- [x] Call `libc::pwritev` for host files when the helper returns `Borrowed`.
  - Convert iovec count with a checked `i32::try_from`.
  - Use `libc::iovec { iov_base: ptr as *mut libc::c_void, iov_len: len }` on macOS.
  - Return the host syscall byte count directly, including partial success.
- [x] Preserve current validation-before-stream/open-description errno behavior.
  - Guest iovec descriptors and payload accessibility are checked before stdio stream and fd-open errors where current tests require it.
- [x] Keep the staged fallback path from commit `d41e658` for non-host-pointer memory and tests using `LinearMemory`.
- [x] Run:
  - `cargo test -p carrick-runtime --test integration pwritev -- --nocapture`
  - `cargo fmt --all -- --check`
  - `git diff --check`
- [x] Record removed-work evidence and wall-time evidence for a multi-segment host-file `pwritev` workload.
- [x] Commit as `perf(io): use borrowed pwritev buffers` or a similarly scoped subject.

Progress:

- 2026-06-06: Added RED integration test `syscall_fs::pwritev_host_file_uses_guest_host_ptrs_without_payload_reads`; pre-fix behavior returned the correct file contents but read the two watched payloads through `read_bytes` and recorded zero host-pointer hits.
- 2026-06-06: Added fallback coverage `syscall_fs::pwritev_host_file_falls_back_to_staging_when_any_iovec_lacks_host_ptr` and validation coverage `syscall_fs::pwritev_host_file_reports_efault_when_fallback_payload_is_unreadable`.
- 2026-06-06: Implemented `prepare_pwritev_payloads` in `crates/carrick-runtime/src/dispatch/fs.rs`. Host-file `pwritev` now calls one `libc::pwritev` when all non-empty iovecs expose `host_ptr_for_read`; mixed or non-host-pointer memory falls back to one staged read per payload.
- 2026-06-06: Added `conformance-probes/src/bin/perf_pwritev_burst.rs` and registered `pwritev_burst` in the perf case registry.
- 2026-06-06: Pre-commit verification passed: `cargo test -p carrick-runtime --test integration pwritev -- --nocapture`, `cargo test -p carrick-cli --test perf_runner perf_support::cases::tests -- --nocapture`, `cargo fmt --all -- --check`, and `git diff --check`.
- 2026-06-06: Committed runtime/test/probe slice as `efd09cdb8115dd5895d13212e945886337fb5f9a` (`perf(io): use borrowed pwritev buffers`).
- 2026-06-06: Removed-work evidence is the RED/green integration test: payload `read_bytes` calls dropped from `2` to `0` and host-pointer hits rose from `0` to `2` for the borrowed host-file `pwritev` case.
- 2026-06-06: Post-commit `CARRICK_PERF_FILTER=pwritev_burst CARRICK_PERF_REPS=3 CARRICK_PERF_WARMUP=1 CARRICK_PERF_COOLDOWN_SECS=0 just bench quick` passed and wrote `docs/perf-results/2026-06-05-syscall.jsonl`; Carrick p50 `20849.208` us, p95 `26075.417` us, noisy; Docker p50 `3478.459` us, p95 `3654.750` us.

Milestone 2B: borrowed `readv` and `preadv` host-file fast paths.

- [x] Add `syscall_fs::readv_host_file_uses_guest_host_ptrs_for_writable_iovecs`.
  - Use a custom test memory that implements `host_ptr_for_write` for two exact writable payload ranges.
  - Expected RED on current branch: read succeeds through copied staging, but host-pointer write hits are `0`.
  - Expected PASS after implementation: host-pointer write hits match non-empty iovec count and the guest bytes are filled directly.
- [x] Add `syscall_fs::preadv_host_file_preserves_offset_with_borrowed_iovecs`.
  - File contains a known prefix and payload.
  - `preadv` reads from a non-zero offset into two borrowed guest ranges.
  - Expected result: guest memory receives exactly the offset slice and host file offset remains unchanged.
- [x] Add fallback coverage for a mixed borrowed/non-borrowed `readv` or `preadv` call.
  - Expected result: existing staging path is used, partial read behavior matches current semantics, and guest memory is updated only for bytes actually read.
- [x] Implement a writable borrowed-iovec helper using `GuestMemory::host_ptr_for_write`.
  - Use borrowed host vectors only when every non-empty target range is writable and contiguous.
  - Fall back to the existing staged read path otherwise.
- [x] Convert host-file `readv` and `preadv` paths to `libc::readv` and `libc::preadv` when safe.
- [x] Run:
  - `cargo test -p carrick-runtime --test integration readv -- --nocapture`
  - `cargo test -p carrick-runtime --test integration preadv -- --nocapture`
  - `cargo fmt --all -- --check`
  - `git diff --check`
- [ ] Record removed-work evidence and wall-time evidence for multi-segment host-file reads.
- [ ] Commit as a separate logical slice from `pwritev`.

Progress:

- 2026-06-06: Added RED integration test `syscall_fs::readv_host_file_uses_guest_host_ptrs_for_writable_iovecs`; pre-fix behavior filled both iovecs through `write_bytes` and recorded zero writable host-pointer hits.
- 2026-06-06: Added borrowed `preadv` coverage with `syscall_fs::preadv_host_file_preserves_offset_with_borrowed_iovecs`, including a follow-up `read` proving the shared host file offset is unchanged.
- 2026-06-06: Added fallback coverage `syscall_fs::readv_host_file_falls_back_to_staging_when_any_iovec_lacks_host_ptr`; mixed host-pointer/non-host-pointer memory still uses the existing staged write path.
- 2026-06-06: Implemented `prepare_readv_targets` in `crates/carrick-runtime/src/dispatch/fs.rs`. Host-file `readv` and `preadv` now call one host vector syscall when all non-empty iovecs expose `host_ptr_for_write`; mixed or non-host-pointer memory falls back to existing sequential copy behavior.
- 2026-06-06: Added `conformance-probes/src/bin/perf_preadv_burst.rs` and registered `preadv_burst` in the perf case registry.
- 2026-06-06: Focused checks passed: `cargo test -p carrick-runtime --test integration readv -- --nocapture`, `cargo test -p carrick-runtime --test integration preadv -- --nocapture`, `cargo test -p carrick-cli --test perf_runner perf_support::cases::tests -- --nocapture`, and `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin perf_preadv_burst`.
- 2026-06-06: Pre-commit hygiene passed: `cargo fmt --all -- --check` and `git diff --check`.
- 2026-06-06: Removed-work evidence is the RED/green integration test: borrowed host-file `readv`/`preadv` writes guest payloads through host pointers, with watched `write_bytes` calls dropping from the RED count to `0` and writable host-pointer hits matching the non-empty iovec count.

Milestone 2C: blocking write ownership and existing `writev` path cleanup.

- [ ] Add a test that forces the blocking-write handoff path and proves the buffer is not cloned when ownership can be moved.
- [ ] Replace clone-on-handoff with ownership transfer for already-staged write buffers.
- [ ] Confirm EINTR, EAGAIN, partial-write, and retry behavior are unchanged.
- [ ] Run focused I/O tests and relevant conformance probes.
- [ ] Record allocation or wall-time evidence for repeated small blocking writes.
- [ ] Commit as a separate logical slice.

### 3. VFS Streaming and Dirty-Range Writeback

Status: static opportunity.

The rootfs and overlay abstractions still encourage whole-file materialization for operations that should be metadata-only or fd/range-backed.

Expected removed work:

- Metadata-only operations stop reading file contents.
- Small writes to large files stop cloning or rewriting the full file.
- Host-backed regular files use fd streaming where the backend can safely expose a raw fd.

Key code:

- `crates/carrick-runtime/src/fs_backend.rs`
- `crates/carrick-runtime/src/dispatch/fs.rs`
- `crates/carrick-runtime/src/rootfs.rs`
- `crates/carrick-runtime/src/layer_cache.rs`

Milestone 3 tasks:

- [ ] Add a large-file metadata probe that opens/stats/lookups a file without reading its contents.
- [ ] Add a large-file small-write test that fails if the backend rewrites or clones the full file.
- [ ] Add backend API support for range writes or fd-backed mutation on regular mutable files.
- [ ] Keep whole-file behavior as fallback for in-memory files, symlinks, directories, and special files.
- [ ] Run focused filesystem tests and a build-tool-like workload with many small file updates.
- [ ] Record before/after wall-time and byte-copy/writeback evidence.

### 4. Wait Path fd Pinning and kqueue Churn

Status: static opportunity.

Repeated waits on stable descriptors currently pay setup costs that should be amortized or avoided when the open description lifetime is already anchored.

Expected removed work:

- Fewer `dup` and close pairs per wait.
- Fewer transient kqueue change/event/deletion allocations.
- Less macOS kernel time for event-loop-heavy workloads.

Key code:

- `crates/carrick-hvf/src/io_wait.rs`
- `crates/carrick-runtime/src/dispatch/fs.rs`
- fd/open-description ownership code

Milestone 4 tasks:

- [ ] Add a wait-heavy probe that repeatedly waits on stable fds.
- [ ] Add a correctness test for fd close/reuse during or near a wait.
- [ ] Introduce retained wait targets for open descriptions that can safely anchor host fd lifetime without `dup`.
- [ ] Keep fd duplication fallback for descriptors whose lifetime cannot be anchored safely.
- [ ] Consider persistent kqueue subscriptions only with generation checks.
- [ ] Run wake-pipe, signal, process-exit, and fd-reuse tests.
- [ ] Record duplicate-fd count, `kevent` setup count, and wall-time evidence.

### 5. Targeted Trap Reduction After Measurement

Status: deferred until a workload proves it.

Trap reduction should not begin with a general preload layer. The near-term runtime work above removes costs for dynamic and static workloads. Interposition becomes worthwhile only if a dynamic workload still shows trap count as the leading bottleneck.

Milestone 5 tasks:

- [ ] Build or select a dynamic-libc workload dominated by small writes or cacheable metadata calls.
- [ ] Measure current trap count and wall time with the runtime work above applied.
- [ ] Compare three designs:
  - EL1 shim extension for safe identity-style syscalls.
  - Runtime batching after trap.
  - Narrow dynamic interposer for explicitly safe libc calls.
- [ ] Implement only the smallest semantics-preserving optimization.
- [ ] Document unsupported workloads, especially static binaries and direct syscall users.
- [ ] Record trap-count and wall-time evidence.

### 6. Fork Snapshot Follow-Up

Status: dependent on mmap and page-dirtying evidence.

Fork cost is affected by resident and dirty page pressure. The lazy-zero work should reduce avoidable fork pressure before deeper fork architecture changes are attempted.

Key code:

- `crates/carrick-hvf/src/trap.rs`
- mapping metadata and memory backing helpers

Milestone 6 tasks:

- [ ] Re-measure fork-heavy workloads after Milestone 1.
- [ ] Classify remaining fork cost by mapping type:
  - private anonymous
  - shared anonymous
  - host aliases
  - stack
  - file-backed regions
- [ ] Add correctness probes before any snapshot-elision or dirty-tracking change.
- [ ] Only pursue deeper fork changes if mmap, iovec, VFS, and wait work no longer dominate the profile.

## Measurement Requirements

Every landed performance change records:

- Workload or probe name.
- Before and after wall time.
- Before and after trap count, host syscall count, allocation count, byte-copy count, or fd/kqueue setup count when available.
- Code path whose work was removed.
- Correctness tests or conformance probes run.
- Workload classes that do not benefit.

Repo-local result artifacts:

- Use `docs/perf-results/*.jsonl` for benchmark rows.
- Keep manual samples in `goal.md` only when the perf harness cannot yet represent the workload.
- Mark noisy controls explicitly instead of hiding them.

## Non-Goals

- Do not weaken conformance gates to improve benchmark appearance.
- Do not claim runtime wins from static inspection alone.
- Do not pursue ptrace in this plan.
- Do not build a general `LD_PRELOAD` compatibility layer before a dynamic workload proves trap count is still the bottleneck.
- Do not optimize syscall dispatch mechanics before removing larger traps, host syscalls, copies, page dirtying, or kernel wait setup.
- Do not take deep fork-snapshot architecture risk before lower-risk mmap, iovec, VFS, and wait-path work has been measured.

## Immediate Next Slice

Continue Milestone 2B.

- [ ] Add RED borrowed-host-pointer `readv` and `preadv` tests in `crates/carrick-runtime/tests/integration/syscall_fs.rs`.
- [ ] Implement writable borrowed-iovec preparation in `crates/carrick-runtime/src/dispatch/fs.rs`.
- [ ] Convert safe host-file `readv` and `preadv` calls to `libc::readv` and `libc::preadv`.
- [ ] Keep staged fallback behavior for mixed or non-host-pointer guest memory.
- [ ] Run focused `readv`/`preadv` tests, formatting, and `git diff --check`.
- [ ] Record removed-work evidence and wall-time evidence for multi-segment host-file reads.
- [ ] Commit the read-side vector I/O slice separately from `pwritev`.
