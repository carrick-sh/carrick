# Carrick Significant Performance Gains Goal

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Find and land significant Carrick performance wins by removing whole classes of runtime work: guest traps, host syscalls, guest/host copies, allocation churn, page dirtying, and HVF mapping pressure.

**Architecture:** Treat performance from first principles. Prefer changes that reduce the number of crossings or bytes touched over local dispatch micro-optimizations. Every claimed win needs a workload or probe that exposes the removed cost before and after the change.

**Tech Stack:** Rust, Carrick HVF runtime, Carrick syscall dispatcher, guest memory/page-table machinery, conformance and perf probe harnesses.

---

## First-Principles Cost Model

Performance work should be ranked by the amount of unavoidable work it removes:

1. Guest traps and VM exits.
2. Host syscalls, Mach calls, `kevent`, `hv_vm_map`, and TLB/page-table churn.
3. Guest/host memory copies and temporary `Vec<u8>` allocation.
4. Page dirtying that later expands fork snapshots, mincore scans, or writeback.
5. VFS metadata/path walks and whole-file rootfs/overlay rewrites.
6. Per-wait descriptor pinning, fd duplication, and transient kqueue registration.

This goal is intentionally not a generic profiler sweep. The target is large structural wins, especially where current code shape does work proportional to bytes, iovecs, mappings, or waits that Linux would avoid.

## Current Static Findings

No fresh benchmark was run for this review. These findings are code-shape opportunities that need measurement before a win is claimed.

### 1. Fresh Anonymous `mmap` Zeroing

The generic mmap path appears to allocate a full zero-filled buffer and write it into guest memory for broad non-`PROT_NONE` mappings. That defeats the intended lazy-zero shape for fresh anonymous mappings and can make pages resident/dirty before the guest actually touches them.

Primary evidence:

- `crates/carrick-runtime/src/dispatch/mem.rs`
  - `mmap` creates `let mut bytes = vec![0; length_usize]`.
  - Low-address mappings write those bytes into guest memory with `memory.write_bytes(address, &bytes)`.
  - `MAP_SHARED | ANONYMOUS` subrange handling also stages a zero buffer before writing.
- `crates/carrick-hvf/src/trap.rs`
  - Fork snapshots still need to reason about resident/private pages; unnecessary zero writes increase the work available to copy/scan later.

Expected impact:

- High for allocator-heavy programs.
- High for fork-heavy programs when zeroing increases resident/dirty pages.
- Potentially broad because anonymous mmap is a common runtime primitive.

Implementation direction:

- Split fresh anonymous mappings from reused mappings.
- For fresh anonymous mappings, install the mapping metadata and protections without staging a full zero buffer.
- Use existing backing-zeroing paths only when reusing an address/range that may contain stale data.
- For shared aperture and private overlay allocations, add or reuse a backing-level zero operation instead of materializing a guest-sized zero `Vec`.

Acceptance:

- A perf probe shows large anonymous mmap churn without proportional host allocation/copy.
- A correctness probe proves reused mappings are still zero-filled when Linux requires it.
- Fork-heavy pressure workloads do not regress.

### 2. Borrowed Guest-Memory Iovec I/O

Several host-fd I/O paths still loop over guest iovecs, allocate temporary buffers, copy between guest and host, and issue one host syscall per segment. `writev` has a host batching path, but the read and pwrite sides still leave substantial work on the table.

Primary evidence:

- `crates/carrick-runtime/src/dispatch/fs.rs`
  - `readv` loops over iovecs and calls the host read helper per segment.
  - `preadv` allocates a buffer and calls `pread` per iovec.
  - `pwritev` validates/reads iovecs and then reads them again for host `pwrite`.
- `crates/carrick-runtime/src/dispatch/mod.rs`
  - `read_iovecs` materializes guest iovec descriptors into a Rust `Vec`.
  - Blocking write handoff owns a `Vec<u8>` and currently clones bytes into the pending operation.

Expected impact:

- High for language runtimes and servers that use scatter/gather I/O.
- High for pipes, sockets, and file workloads with many small buffers.
- Potentially multiplicative because it reduces host syscalls and memory copies.

Implementation direction:

- Add a safe guest-memory API that converts validated contiguous guest ranges into borrowed host `iovec`/`IoSlice`/`IoSliceMut` descriptors.
- Use real host `readv`, `writev`, `preadv`, and `pwritev` when every segment is representable and permissions are valid.
- Fall back to the existing copy path for split mappings, non-contiguous ranges, or unsafe aliases.
- Avoid double guest reads in `pwritev` by validating and building the borrowed vector once.
- Avoid the extra blocking-write clone by transferring ownership of the already-staged buffer into the pending write.

Acceptance:

- A probe or benchmark demonstrates fewer host syscalls for multi-segment `readv`/`preadv`/`pwritev`.
- Existing EINTR, partial-read, partial-write, and blocking semantics remain Linux-compatible.
- Fallback behavior is covered by tests for split/invalid guest iovecs.

### 3. Trap Count Reduction Through Targeted Interposition

The EL1 syscall shim already handles safe identity syscalls such as `getpid`, uid/gid queries, and `gettid`. `read`, `write`, and `futex` still trap because correctness depends on host state, blocking behavior, and runtime coordination.

Primary evidence:

- `docs/syscall-shim-design.md`
  - Identity syscall fast paths are already present.
  - I/O and preload-based batching are explicitly deferred until a workload proves the value.
- `crates/carrick-hvf/src/trap.rs`
  - The syscall trap path still pays the VM-exit and register/materialization cost for non-shimmed syscalls.

Expected impact:

- Very high only when the workload is dynamic-libc-heavy and emits many small syscalls.
- Low or zero for static Go/musl workloads that bypass `LD_PRELOAD`.

Implementation direction:

- Do not start with a general LD_PRELOAD compatibility layer.
- First build a dynamic pipe-backed benchmark that proves small libc writes or metadata calls dominate.
- If the benchmark supports it, implement a narrow interposer that batches writes or answers explicitly cached process metadata.
- Keep syscall semantics authoritative in the runtime; interposition is an optimization, not a correctness layer.

Acceptance:

- A dynamic workload shows trap-count reduction and wall-time improvement.
- Static workloads are unaffected.
- The optimization is disabled or bypassed when semantics cannot be preserved.

### 4. Whole-File Rootfs and Overlay Copy/Rewrites

The VFS/backend interfaces still encourage whole-file materialization for operations that should be metadata-only or fd-backed. Some write paths rewrite whole contents after local modifications.

Primary evidence:

- `crates/carrick-runtime/src/fs_backend.rs`
  - `OverlayEntry::File(Vec<u8>)` carries whole file contents.
  - `file_contents` returns owned `Vec<u8>`.
  - `set_file_contents` accepts and writes owned `Vec<u8>`.
- `crates/carrick-runtime/src/dispatch/fs.rs`
  - In-memory file write paths can clone full contents for writeback.

Expected impact:

- High for build systems, package managers, and language tooling.
- High when files are large or repeatedly updated in small ranges.

Implementation direction:

- Move hot open/read/write paths toward fd-backed streaming when the host backend can supply a raw fd.
- Add dirty-range writeback for in-memory or overlay files that cannot be fd-backed.
- Avoid returning file contents from metadata-only lookup paths.
- Keep the high-level backend abstraction, but add specialized fast paths for regular host files and mutable overlay files.

Acceptance:

- A file rewrite probe shows small writes no longer cause whole-file clone/rewrite.
- Metadata-only operations do not read file contents.
- Existing rootfs/overlay correctness tests continue to pass.

### 5. Wait Path fd Pinning and kqueue Churn

The wait path duplicates watched fds and builds transient wait state for each wait. This is correct but expensive for event loops or programs that repeatedly wait on stable descriptors.

Primary evidence:

- `crates/carrick-hvf/src/io_wait.rs`
  - `PinnedWaitFds::new` duplicates watched fds.
  - `wait` and `wait_poll` rebuild/pin wait state for each call.

Expected impact:

- Medium to high for event-loop workloads.
- Lower than mmap and iovec work for general-purpose throughput unless a workload is wait-heavy.

Implementation direction:

- Introduce a retained wait target that holds the `OpenFile`/host-fd lifetime through the wait without `dup` when the open description is already stable.
- Consider persistent kqueue subscriptions for stable fds with generation checks.
- Keep the current duplication path as fallback for descriptors whose lifetime cannot be anchored safely.

Acceptance:

- A poll/epoll/select-style probe shows fewer `dup`/close and `kevent` setup calls.
- fd reuse races are covered by tests.
- Signal wake and process-exit wake paths remain correct.

### 6. Fork Snapshot Cost

Fork currently snapshots runtime/HVF state, destroys/rebuilds HVF VM state, and maps regions again in the child. Existing high-water/mincore logic is already a meaningful optimization, but dirty/resident-page pressure still determines much of the cost.

Primary evidence:

- `crates/carrick-hvf/src/trap.rs`
  - Fork snapshot and VM rebuild logic walks mappings and remaps regions.
  - Region cloning uses resident-page scanning and copying.

Expected impact:

- Very high for fork-heavy workloads.
- High implementation risk compared with mmap zeroing and iovec batching.

Implementation direction:

- First reduce avoidable page dirtying through the mmap lazy-zero work.
- Then measure remaining fork cost by mapping class: anonymous private, shared anonymous, host aliases, and stack.
- Only after measurement, consider dirty-bit tracking, snapshot elision for clean ranges, or narrower child rebuild work.

Acceptance:

- A fork-heavy probe shows reduced resident/copy work after mmap zeroing.
- Any deeper fork change has a narrow correctness probe for child visibility, private writes, and shared mappings.

## Prioritized Milestones

### Milestone 1: Measure and Fix Anonymous mmap Lazy-Zero

**Files:**

- Modify: `crates/carrick-runtime/src/dispatch/mem.rs`
- Possibly modify: `crates/carrick-mem/src/memory.rs`
- Test: existing mmap tests plus a new focused mmap-zero/reuse test
- Probe/bench: add a small mmap churn perf probe if no existing probe covers it

- [x] Add a test that maps a fresh anonymous range and verifies the runtime does not materialize or write a full zero buffer for the fresh case.
- [x] Add a test that reuses a range and verifies stale bytes are not visible.
- [x] Implement the fresh-anonymous fast path.
- [x] Run the focused mmap tests.
- [x] Run fork and mmap pressure probes.
- [ ] Record before/after numbers in a repo-local perf result artifact.
- [ ] Commit the test/probe and runtime fix as a logical slice.

Progress:

- 2026-06-06: Started Milestone 1 on branch `codex/perf-mmap-lazy-zero`. First target is a dispatcher unit test that proves fresh private anonymous `mmap` does not need a guest-visible zero write.
- 2026-06-06: Added RED unit test `dispatch::mem::tests::fresh_private_anonymous_mmap_skips_zero_write`; current mainline behavior fails with one `write_bytes` call for a fresh anonymous page.
- 2026-06-06: Implemented the low-VA anonymous mmap fast path in `crates/carrick-runtime/src/dispatch/mem.rs`. Fresh private anonymous mappings now return after restoring access/protection; reused private anonymous mappings still scrub via `zero_backing` and avoid the redundant guest-visible zero write.
- 2026-06-06: Added `dispatch::mem::tests::reused_private_anonymous_mmap_zeroes_backing_without_zero_write` and `conformance-probes/src/bin/perf_mmap_churn.rs`, then registered `mmap_churn` in the perf case registry.
- 2026-06-06: Focused checks passed: `cargo test -p carrick-runtime dispatch::mem::tests --lib -- --nocapture` (5 passed), `cargo test -p carrick-cli --test perf_runner perf_support::cases::tests -- --nocapture` (4 passed), `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin perf_mmap_churn`, and `cargo fmt --all -- --check`.
- 2026-06-06: Pressure probes passed after `just build`: `scripts/run-probe.sh mmapzerofill` MATCH (`anon_mmap_is_zero_filled=true`), `scripts/run-probe.sh mmaprecl` MATCH (`churn_ok=true`, `reuse_zero=true`), and `scripts/run-probe.sh forkcow` MATCH (`mmap_isolated=true` plus data/bss/heap isolation).

### Milestone 2: Add Borrowed Iovec Host I/O

**Files:**

- Modify: `crates/carrick-mem/src/memory.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Test: focused readv/preadv/pwritev tests

- [ ] Add tests for contiguous valid guest iovecs on host files.
- [ ] Add tests for split or invalid guest iovecs that must fall back or fail correctly.
- [ ] Add a guest-memory borrowed-iovec API with explicit lifetime and permission checks.
- [ ] Convert `readv`/`preadv`/`pwritev` host-file paths to use host vector syscalls when safe.
- [ ] Remove double guest reads in `pwritev`.
- [ ] Avoid the extra blocking-write clone where ownership can be transferred safely.
- [ ] Run focused I/O tests and relevant conformance probes.
- [ ] Record syscall-count and wall-time before/after evidence.
- [ ] Commit as one or more logical slices.

### Milestone 3: Replace Whole-File Hot Paths with Streaming or Dirty-Range Updates

**Files:**

- Modify: `crates/carrick-runtime/src/fs_backend.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs.rs`
- Test: focused rootfs/overlay writeback tests

- [ ] Identify hot lookup/open paths that only need metadata but currently materialize file contents.
- [ ] Add tests proving metadata-only paths do not read whole files.
- [ ] Add tests for small writes to large files that should not rewrite the full file.
- [ ] Introduce fd-backed or dirty-range update paths for regular mutable files.
- [ ] Preserve existing overlay/rootfs semantics for symlinks, directories, and special files.
- [ ] Run focused fs tests and a build-tool-like file workload.
- [ ] Record before/after evidence.

### Milestone 4: Reduce Per-Wait Setup Costs

**Files:**

- Modify: `crates/carrick-hvf/src/io_wait.rs`
- Possibly modify: fd/open-file ownership code in `crates/carrick-runtime/src/dispatch/fs.rs`
- Test: focused wait/fd-reuse/signal wake tests

- [ ] Add a wait-heavy benchmark or probe that repeatedly waits on stable fds.
- [ ] Add a correctness test for fd close/reuse during or near a wait.
- [ ] Add retained wait targets for open descriptions that can safely anchor host fd lifetime.
- [ ] Keep fd duplication fallback for unsafe cases.
- [ ] Measure duplicate-fd and kqueue setup reduction.
- [ ] Run existing wake-pipe, signal, and process-exit wait tests.

### Milestone 5: Revisit Targeted Interposition

**Files:**

- Modify only after measurement identifies the right integration point.
- Likely candidates: syscall shim docs, runtime trap metrics, dynamic preload/interposer code if introduced.

- [ ] Build or select a dynamic-libc workload that is dominated by small writes or cacheable metadata calls.
- [ ] Measure current trap count and wall time.
- [ ] Decide whether narrow interposition beats extending the EL1 shim or runtime batching.
- [ ] Implement only the smallest semantics-preserving optimization.
- [ ] Document unsupported/static workload boundaries.

### Milestone 6: Fork Snapshot Follow-Up

**Files:**

- Modify only after mmap lazy-zero evidence is collected.
- Likely candidates: `crates/carrick-hvf/src/trap.rs`, mapping metadata, and memory backing helpers.

- [ ] Re-measure fork-heavy workloads after Milestone 1.
- [ ] Classify remaining fork cost by mapping type.
- [ ] Add correctness probes for any snapshot-elision or dirty-tracking proposal.
- [ ] Avoid deep fork architecture changes unless the measurement shows mmap/iovec/VFS work is no longer the larger bottleneck.

## Non-Goals

- Do not weaken conformance gates to improve benchmark appearance.
- Do not claim runtime wins from static inspection alone.
- Do not start with broad ptrace or debugger support.
- Do not build a general LD_PRELOAD compatibility layer before a dynamic workload proves the trap count is the bottleneck.
- Do not micro-optimize syscall dispatch before removing larger copies, traps, host syscalls, or page dirtying.

## Reporting Requirements

For every landed performance change, record:

- The workload/probe.
- Before and after wall time.
- Before and after trap count or host syscall count when available.
- The code path whose work was removed.
- Correctness tests or conformance probes run.
- Any workload class that does not benefit.

## Recommended First Slice

Start with the fresh anonymous mmap lazy-zero work. It is the most promising first-principles target because it removes allocation, copy, page dirtying, and downstream fork work at the same time. The next best slice is borrowed guest-memory iovec I/O because it collapses repeated host syscalls and buffer copies in a common runtime path.
