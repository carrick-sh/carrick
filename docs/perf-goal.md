# Carrick First-Principles Performance Goal

Keep this file current as the active performance artifact for this branch. Record
the current theory, the measured evidence, the next slice, and the tests that
prove a claimed unit of work disappeared.

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

Dynamic interposition can still be useful, but only as a measured fast path for
dynamic workloads. The Carrick syscall runtime remains the correctness layer.

## Non-Goals

- Do not pursue ptrace in this plan.
- Do not weaken conformance gates to improve benchmark appearance.
- Do not claim runtime wins from static inspection alone.
- Do not build a general `LD_PRELOAD` compatibility layer before a dynamic
  workload proves trap count is still the bottleneck after runtime work.
- Do not optimize syscall-dispatch mechanics before removing larger traps,
  host syscalls, copies, page dirtying, or kernel wait setup.
- Do not take deep fork-snapshot architecture risk before lower-risk mmap,
  iovec, VFS, and wait-path work has been measured.

## Cost Model

Rank work by the unavoidable cost it removes:

1. Guest traps and VM exits.
2. Host syscalls, Mach calls, `kevent`, `hv_vm_map`, and TLB/page-table churn.
3. Guest/host memory copies and temporary allocation.
4. Page dirtying that later expands fork snapshots, resident scans, and
   writeback.
5. VFS metadata/path walks and whole-file rootfs or overlay materialization.
6. Per-wait descriptor pinning, fd duplication, transient kqueue registration,
   and wake bookkeeping.

Every optimization must answer:

- What whole unit of work disappears?
- Which test, probe, trace, or benchmark proves it disappeared?
- Which workload classes benefit?
- Which workload classes do not benefit?

## Design Position

The original `LD_PRELOAD` idea should be treated as a narrow fast-path option,
not as the primary architecture.

Why:

- It cannot help static Go, static musl, direct syscall users, or binaries that
  bypass libc wrappers.
- It cannot own fd semantics, blocking behavior, signals, futexes, process
  metadata, kernel-visible side effects, or guest memory ownership.
- It risks splitting correctness between user-space wrappers and the syscall
  runtime.

Preferred order:

1. Keep identity and safe process-metadata syscalls in the EL1 shim where the
   semantics are already local and stable.
2. Collapse runtime work after a trap: vector I/O staging, mmap zeroing, wait
   setup, VFS read/writeback, and overlay materialization.
3. Add dynamic workloads that prove trap count is still dominant after the
   structural runtime work.
4. If proven, add narrow interposers for specific semantic islands, such as
   batching libc writes to a known pipe/socket or answering explicitly cached
   process metadata.
5. Keep the runtime authoritative. Interposition is an optional fast path, not
   the correctness layer.

## Current Branch State

Branch: `codex/perf-mmap-lazy-zero`

Latest committed runtime slices:

- `76d0aac` - `perf(fs): fast path memory nofollow metadata`
- `0d9ee96` - `perf(fs): skip impossible memory fifo probe`
- `0a08b5f` - `perf(fs): snapshot memory overlay opens`
- `4bae00f` - `perf(fs): avoid cloning memory files on open`
- `7149ae3` - `perf(fs): fast path root f_ok access`
- `5a6be55` - `perf(fs): combine host open metadata`
- `db6d5cc` - `perf(wait): retain host fd wait targets`
- `4430ac2` - `perf(fs): lazily copy up rootfs writes`
- `6e2ee14` - `perf(fs): write dirty file ranges`
- `e9cdb83` - `perf(fs): avoid payload reads for metadata opens`
- `1499984` - `perf(mem): skip fresh anon mmap zero writes`
- `d41e658` / `efd09cdb` - `pwritev` staging and borrowed-buffer work
- `4508605` - borrowed `readv`/`preadv` work
- `dd72b8e` - blocking host-write buffer ownership

Documentation/result state:

- `docs/perf-results/2026-06-06-disk.jsonl` has appended rows for
  `overlay_small_updates` at `4bae00f`, `0a08b5f`, `0d9ee96`, and `76d0aac`.

## Current Evidence

### Anonymous mmap lazy-zero

Workload: `perf_mmap_churn`, 64 untouched 8 MiB private anonymous mappings.

- Before `1499984`: manual Carrick samples `54937.750`, `57827.458`,
  `55593.333` us.
- After `1499984`: Carrick p50 `831.708` us, p95 `897.625` us.
- Docker control p50 `60.667` us, p95 `197.750` us, noisy.
- Correctness probes matched Docker/Linux: `mmapzerofill`, `mmaprecl`, and
  `forkcow`.

What disappeared:

- Eager zero-buffer materialization and writes for fresh private anonymous
  mappings.
- Page dirtying for untouched fresh mappings.

Remaining questions:

- [ ] Count `hv_vm_map`/`hv_vm_unmap` on mmap-heavy workloads.
- [ ] Add a fork-heavy workload row after lazy-zero to measure snapshot impact.
- [ ] Re-check shared anonymous and high-VA alias paths for equivalent eager
  zeroing.

### Borrowed vector I/O

Workloads: `pwritev_burst`, `preadv_burst`.

- `pwritev` evidence: payload `read_bytes` calls dropped from `2` to `0`;
  host-pointer hits rose from `0` to `2`.
- `pwritev_burst` rows in `docs/perf-results/2026-06-05-syscall.jsonl`:
  Carrick p50 `20849.208` us, p95 `26075.417` us; Docker p50 `3478.459` us,
  p95 `3654.750` us.
- `readv`/`preadv` evidence: watched `write_bytes` calls dropped to `0` when
  writable host pointers were available.
- `preadv_burst` rows in `docs/perf-results/2026-06-05-syscall.jsonl`:
  Carrick p50 `19852.375` us, p95 `22193.875` us; Docker p50 `2571.125` us,
  p95 `2902.375` us.
- Blocking host-write continuations preserve staged `Vec<u8>` ownership instead
  of cloning.
- Probes matched Docker/Linux: `blockingpipewrite`, `writevpartial`, and
  `sigpipewrite`.

What disappeared:

- Redundant guest-memory staging for vector I/O when host pointers are directly
  usable.
- Clones of already staged buffers across blocking host-write continuations.

Remaining questions:

- [ ] Add syscall-count evidence for borrowed vector I/O workloads, not only
  byte-copy tests.
- [ ] Re-check socket/pipe vector I/O paths for avoidable staging or cloning.
- [ ] Re-check stdio stream paths where validation ordering prevents direct
  borrowed I/O.

### VFS dirty ranges and rootfs COW

Workloads: `overlay_small_updates`, `large_meta`.

Landed work:

- Added `overlay_small_updates` perf coverage.
- Added fs-mode support to perf cases and result rows.
- Changed memory-fs perf cases to run static probes directly via
  `carrick run-elf --raw --fs memory`.
- Changed the overlay probe from `pwrite64` to `lseek` plus `write`, matching
  current memory-fs dirty-range support.
- Implemented dirty-range writeback for memory overlay files.
- Implemented rootfs-backed writable COW entries backed by shared rootfs
  payload handles and dirty ranges.
- Avoided payload reads for metadata-only opens.

Evidence:

- A 1-byte write to a 4 MiB overlay file reduced max backend writeback payload
  from `4194304` bytes to at most `1` byte.
- Alternating comparison against a signed pre-dirty-range binary from
  `8e72886`:
  - current totals: `27720.709`, `13908.667`, `13440.042` us; p50
    `13908.667` us.
  - old totals: `38911.459`, `35769.625`, `34081.042` us; p50 `35769.625` us.
  - result: about `2.57x` faster for `overlay_small_updates` under
    `run-elf --raw --fs memory`.
- Rootfs COW RED test:
  `small_write_to_large_rootfs_file_does_not_copy_up_whole_file` failed with
  `max writeback payload was 4194304`.
- Rootfs COW focused checks passed:
  - `cargo test -p carrick-runtime --test integration small_write_to_large -- --nocapture`
  - `cargo test -p carrick-runtime --test integration rootfs_overlay -- --nocapture`
  - `cargo test -p carrick-runtime --test integration pwrite64_bootstrap_returns_espipe_for_streams_and_ebadf_for_rootfs_fds -- --nocapture`
  - `cargo test -p carrick-runtime --test integration copy_file_range_ -- --nocapture`
  - `cargo test -p carrick-runtime --tests --no-run`
  - `cargo fmt --all -- --check`
  - `git diff --check`
- Post-rootfs-COW rows at `4430ac2`:
  - `large_meta`: Carrick p50 `25647.500` us, p95 `28589.333` us; Docker p50
    `547.584` us, p95 `673.958` us.
  - `overlay_small_updates`: Carrick p50 `19890.709` us, p95 `21616.875` us;
    Docker p50 `1500.292` us, p95 `2000.458` us.

What disappeared:

- Whole-file writeback for small overlay writes.
- Whole-file rootfs copy-up for small writes to large rootfs files.
- Payload reads for metadata-only opens.

### VFS metadata/open amplification

Workload: `large_meta`, 128 metadata/open/access cycles on a 256 MiB sparse
file.

Evidence:

- Before metadata-open fix at `8e72886`: Carrick p50 `14185998.250` us, p95
  `14564686.458` us; Docker p50 `291.208` us, p95 `441.125` us.
- After `e9cdb83`: Carrick p50 `26231.500` us, p95 `28435.083` us; Docker p50
  `334.750` us, p95 `373.833` us.
- Direct DTrace before the two 2026-06-06 VFS slices counted `openat=1814`,
  `close=1804`, `fstatat64=1173`, `fcntl=1055`, `fgetxattr=867`, and
  `flistxattr=435`.
- Guest trace shape was the expected fixture shape: `newfstatat=289`,
  `openat=147`, `fcntl=146`, `fstat=145`, `close=146`, and `faccessat=144`.
  The gap was host-side VFS amplification inside handlers, not unexpected
  guest traps.
- Disabling fast fs made the direct run `76294.083` us total; disabling the
  stat cache made it `34109.917` us total; the default direct run was
  `21535.875` us total.

Landed host-open metadata slice:

- Added `FsBackend::open_raw_fd_with_metadata`.
- Used it in `RootFsVfs::open_for_dispatch` for host-backed overlay files.
- `HostFsBackend` now derives open fd metadata from the same fd that will back
  the guest descriptor.
- RED test
  `vfs::rootfs::tests::open_for_dispatch_prefers_combined_host_fd_metadata`
  first failed with `combined_open_calls == 0`, then passed.
- Post-change DTrace counted `openat=1670`, `close=1661`, and `fcntl=911`,
  down by about one open/close/F_GETPATH path per guest `openat`.
- Filtered perf rows at `5a6be55`: Carrick p50 `20539.542` us, p95
  `24166.958` us; Docker p50 `232.042` us, p95 `408.833` us.

Landed root `F_OK` access slice:

- Guest `faccessat` accounted for `openat=145`, `close=145`, `fcntl=144`, and
  `fstatat64=288` before the access slice.
- Added a conservative root-only absolute `F_OK` fast path before
  `resolve_at_path`: `AT_FDCWD`, mode `F_OK`, no flags, real uid `0`, no
  `/proc`/`/sys`, no VFS mount, no `..`, and only when the existing host stat
  cache can prove the path.
- Post-change attribution removed the `faccessat` `openat`/`close`/`fcntl`
  bucket and reduced its `fstatat64` count to `144`.
- Broad host counts became `openat=1525`, `close=1514`, `fcntl=767`, and
  `fstatat64=1029`.
- Filtered perf rows at `7149ae3`: Carrick p50 `16837.375` us, p95
  `17449.375` us; Docker p50 `339.959` us, p95 `343.792` us.

Remaining VFS metadata decision:

- [ ] Design a separate fast host-open path only with RED coverage for symlink,
  containment, FIFO, VFS mount, and fd-sharing invariants.
- [ ] Add byte-copy/allocation counters for remaining VFS hot paths where wall
  time alone is not diagnostic.

### Memory overlay open cloning

Workload: `overlay_small_updates`.

Measured shape before the latest slice:

- `carrick trace` guest syscall aggregation:
  - `openat=594`
  - `fcntl=593`
  - `close=593`
  - `write=583`
  - `lseek=577`
  - `ftruncate=16`
  - `unlinkat=16`
- A bounded host-attribution trace over the hot loop had effectively no host
  VFS/kernel work: `poll=1`, `madvise=1`, `sigaction=2`, `write=7`.
- Conclusion: the remaining gap was not macOS VFS time. It was repeated guest
  traps plus in-process dispatcher and memory-fs work.

RED test:

- Extended `CountingMemoryBackend` to track max lookup payload.
- `small_write_to_large_overlay_file_does_not_rewrite_whole_file` failed before
  the fix:
  `one-byte write should not clone the whole 4194304-byte file on open; max lookup payload was 4194304`.

Landed runtime slice at `4bae00f`:

- Added `SharedFileContents`.
- Added `FsBackend::shared_file_contents`.
- Changed dense memory files to hold `Arc<[u8]>`.
- Open dispatch now installs shared memory-file contents without materializing a
  full `Vec<u8>` from `lookup()`.
- A write to a dense memory file converts it into a rootfs-backed-style entry
  with a shared base and dirty range map.

Verification:

- RED then GREEN:
  `cargo test -p carrick-runtime --test integration small_write_to_large_overlay_file_does_not_rewrite_whole_file -- --nocapture`
- Focused checks passed:
  - `cargo test -p carrick-runtime --test integration small_write_to_large_rootfs_file_does_not_copy_up_whole_file -- --nocapture`
  - `cargo test -p carrick-runtime --test integration rootfs_overlay -- --nocapture`
  - `cargo test -p carrick-runtime --test integration copy_file_range_ -- --nocapture`
  - `cargo test -p carrick-runtime --test integration pwrite64_bootstrap_returns_espipe_for_streams_and_ebadf_for_rootfs_fds -- --nocapture`
  - `cargo test -p carrick-runtime --test integration truncate -- --nocapture`
  - `cargo test -p carrick-runtime --test integration fallocate -- --nocapture`
  - `cargo test -p carrick-runtime --tests --no-run`
  - `cargo fmt --all -- --check`
  - `git diff --check`
  - `./scripts/build-signed.sh`

Performance:

- Direct signed run before commit: `overlay_small_updates_total_us=8825.166`,
  p50 per update `17.291` us.
- Filtered perf rows at `4bae00f` in
  `docs/perf-results/2026-06-06-disk.jsonl`:
  - Carrick memory-fs p50 `6093.750` us, p95 `6140.375` us.
  - Docker p50 `803.625` us, p95 `906.416` us.
  - Carrick remains about `7.58x` slower than Docker on this narrow fixture.

What disappeared:

- Whole-file memory overlay clone on every open of a large file.
- The old open path cloned `4194304` bytes per open in the RED fixture; the
  fixed path shares the base payload and records only dirty ranges.

Follow-up runtime slice at `0a08b5f`:

- Post-`4bae00f` `carrick trace` still showed the same guest trap shape:
  `openat=594`, `fcntl=593`, `close=593`, `write=583`, and `lseek=577`.
- The remaining host attribution for the fixture was already effectively empty,
  so the next runtime-local target was handler work inside the repeated
  `openat` path.
- RED coverage:
  `memory_overlay_open_uses_single_backend_snapshot_for_shared_file` first
  failed because a focused rootfs dispatch helper open still reached the old
  backend passes (`lookup_kind`/metadata/shared-content lookups).
- Added `SharedFileEntry` and `FsBackend::shared_file_entry`, overridden only by
  `MemoryBackend`, so an in-memory file open can return metadata plus shared
  contents in one normalized, locked snapshot.
- `RootFsVfs::open_for_dispatch` now takes that shared-entry path before the
  generic overlay-kind path when `O_CREAT|O_EXCL` is not asking for an
  existence error.
- Focused checks passed:
  - `cargo test -p carrick-runtime --test integration memory_overlay_open_uses_single_backend_snapshot_for_shared_file -- --nocapture`
  - `cargo test -p carrick-runtime --test integration small_write_to_large_overlay_file_does_not_rewrite_whole_file -- --nocapture`
  - `cargo test -p carrick-runtime --test integration small_write_to_large_rootfs_file_does_not_copy_up_whole_file -- --nocapture`
  - `cargo test -p carrick-runtime --test integration truncate -- --nocapture`
  - `cargo test -p carrick-runtime --test integration fallocate -- --nocapture`
  - `cargo test -p carrick-runtime --test integration rootfs_overlay -- --nocapture`
  - `cargo test -p carrick-runtime --test integration copy_file_range_ -- --nocapture`
  - `cargo test -p carrick-runtime --test integration pwrite64_bootstrap_returns_espipe_for_streams_and_ebadf_for_rootfs_fds -- --nocapture`
  - `cargo test -p carrick-runtime --tests --no-run`
  - `cargo fmt --all -- --check`
  - `git diff --check`
  - `./scripts/build-signed.sh`
- Direct post-change runs were noisy but showed p50 per update around
  `9.4` us and totals around `4.9` to `5.1` ms on repeated direct runs.
- Filtered perf rows at `0a08b5f` in
  `docs/perf-results/2026-06-06-disk.jsonl`:
  - Carrick memory-fs p50 `6063.542` us, p95 `6142.084` us.
  - Docker p50 `794.542` us, p95 `818.208` us.
  - Carrick remains about `7.63x` slower than Docker.

What disappeared at `0a08b5f`:

- Separate backend kind, metadata, and shared-content passes inside
  `RootFsVfs::open_for_dispatch` for in-memory overlay files.
- No guest traps disappeared; the traced syscall counts stayed unchanged.

Follow-up runtime slice at `0d9ee96`:

- Full guest `openat` still had one pre-rootfs FIFO metadata probe for every
  memory-backed regular-file open, even though `MemoryBackend::create_fifo` is
  unsupported and the memory backend cannot contain named FIFO nodes.
- RED coverage:
  `memory_overlay_regular_open_skips_fifo_probe_when_backend_cannot_have_fifos`
  first failed with `lookup_kind calls=2`; the remaining legitimate lookup is
  trailing-symlink canonicalization, while the second was the FIFO probe.
- Added `FsBackend::may_have_fifo_nodes`, defaulting to conservative `true`,
  and overrode it to `false` for `MemoryBackend`.
- The open path now gates the FIFO-special `layered_metadata` probe on that
  capability. Host-backed overlays and custom backends keep the conservative
  behavior.
- Focused checks passed:
  - `cargo test -p carrick-runtime --test integration memory_overlay_regular_open_skips_fifo_probe_when_backend_cannot_have_fifos -- --nocapture`
  - `cargo test -p carrick-runtime --test integration memory_overlay_open_uses_single_backend_snapshot_for_shared_file -- --nocapture`
  - `cargo test -p carrick-runtime --test integration rootfs_overlay -- --nocapture`
  - `cargo test -p carrick-runtime --test integration small_write_to_large_overlay_file_does_not_rewrite_whole_file -- --nocapture`
  - `cargo test -p carrick-runtime --test integration truncate -- --nocapture`
  - `cargo test -p carrick-runtime --tests --no-run`
  - `cargo fmt --all -- --check`
  - `git diff --check`
  - `./scripts/build-signed.sh`
- Post-change `carrick trace` still showed the same guest trap shape:
  `openat=594`, `fcntl=593`, `close=593`, `write=583`, and `lseek=577`.
- Filtered perf rows at `0d9ee96` in
  `docs/perf-results/2026-06-06-disk.jsonl`:
  - Carrick memory-fs p50 `4823.792` us, p95 `5093.875` us.
  - Docker p50 `833.458` us, p95 `909.458` us.
  - Carrick remains about `5.79x` slower than Docker.

What disappeared at `0d9ee96`:

- One FIFO metadata probe per guest regular-file open under `--fs memory`.
- No guest traps disappeared; this was pre-rootfs open-handler work.

Follow-up runtime slice at `76d0aac`:

- After the FIFO slice, full memory regular-file `openat` still had one legacy
  kind lookup from trailing-symlink canonicalization falling through
  `lookup_nofollow` to the generic rootfs lookup.
- RED coverage:
  `memory_overlay_regular_open_skips_legacy_kind_lookups` first failed with
  `lookup_kind calls=1`.
- Added `FsBackend::fast_nofollow_metadata`, defaulting to conservative `None`,
  and overrode it for `MemoryBackend`.
- `RootFsVfs::lookup_nofollow` now asks this metadata-only hook before falling
  through the generic lookup. This avoids using `shared_file_entry` for
  canonicalization, so the path does not clone dirty-range maps just to answer
  metadata.
- Focused checks passed:
  - `cargo test -p carrick-runtime --test integration memory_overlay_regular_open_skips_legacy_kind_lookups -- --nocapture`
  - `cargo test -p carrick-runtime --test integration memory_overlay_regular_open_skips_fifo_probe_when_backend_cannot_have_fifos -- --nocapture`
  - `cargo test -p carrick-runtime --test integration memory_overlay_open_uses_single_backend_snapshot_for_shared_file -- --nocapture`
  - `cargo test -p carrick-runtime --test integration rootfs_overlay -- --nocapture`
  - `cargo test -p carrick-runtime --test integration small_write_to_large_overlay_file_does_not_rewrite_whole_file -- --nocapture`
  - `cargo test -p carrick-runtime --test integration truncate -- --nocapture`
  - `cargo test -p carrick-runtime --test integration copy_file_range_ -- --nocapture`
  - `cargo test -p carrick-runtime --tests --no-run`
  - `cargo fmt --all -- --check`
  - `git diff --check`
  - `./scripts/build-signed.sh`
- Post-change `carrick trace` still showed the same guest trap shape:
  `openat=594`, `fcntl=593`, `close=593`, `write=583`, and `lseek=577`.
- Filtered perf rows at `76d0aac` in
  `docs/perf-results/2026-06-06-disk.jsonl`:
  - First harness row after rebuild was a high outlier: Carrick p50
    `8966.875` us, p95 `9170.667` us; Docker p50 `892.500` us, p95
    `970.959` us.
  - Immediate rerun recovered: Carrick p50 `4734.250` us, p95 `4775.000` us;
    Docker p50 `806.375` us, p95 `1028.584` us, Docker noisy.
  - Treat the second row plus direct runs as the useful current signal, while
    keeping the high row as recorded measurement history.

What disappeared at `76d0aac`:

- The remaining legacy `lookup_kind` pass for memory regular-file opens during
  no-follow canonicalization.
- No guest traps disappeared; this was path-canonicalization handler work.

Remaining overlay decision:

- [x] Identify whether the remaining `overlay_small_updates` gap is host kernel
  time, VFS setup, trap count, or memory-backend work.
- [x] Remove the measured whole-file memory-file clone on open.
- [x] Remove the measured repeated backend passes inside the memory overlay
  `open_for_dispatch` helper.
- [x] Remove the measured impossible FIFO metadata probe for memory regular-file
  opens.
- [x] Remove the measured no-follow canonicalization legacy kind lookup for
  memory regular-file opens.
- [ ] Attribute the post-`76d0aac` full guest-open cost between VFS mount
  fallthrough/context construction, syscall dispatch, descriptor table work,
  and fd installation.
- [ ] Decide whether the remaining repeated `openat`/`fcntl`/`lseek`/`write`/
  `close` trap shape can be reduced only by a dynamic interposer or by a safe
  runtime-local fast path.

## Wait Path fd Pinning and kqueue Churn

Workload: `wait_pipe_pingpong`.

Landed work:

- Added `conformance-probes/src/bin/perf_wait_pipe_pingpong.rs`.
- Added perf registry coverage for `wait_pipe_pingpong`.
- `WaitFds` now carries private `HostFdRef` lifetime guards.
- Direct host read/write waits mark fds anchored when an `OpenFile` owner is
  already available.
- `PinnedWaitFds` skips `dup` only for anchored fds.
- Raw wait targets still use the fail-closed `dup` fallback.

Evidence:

- Initial filtered perf rows at `2744261`: Carrick p50 `16.083` us, p95
  `16.375` us; Docker p50 `23.708` us, p95 `23.750` us.
- Initial DTrace over one direct run counted `dup=6999`, `close=7059`, and
  `kevent=14091`.
- RED coverage:
  `anchored_wait_fd_uses_original_fd_without_closing_it` failed before
  `PinnedWaitFds` honored anchored fds (`left: 5`, `right: 3`) and passed after
  the change.
- Dispatcher coverage:
  `anchored_wait_fds_keep_host_fd_live_after_open_file_drop` proves the
  `WaitFds` guard keeps a host fd pollable after the original `OpenFile` drops.
- Post-change filtered perf rows at `db6d5cc`: Carrick p50 `15.542` us, p95
  `16.000` us; Docker p50 `23.667` us, p95 `23.667` us.
- Post-change DTrace counted `close=61` and `kevent=14069`, with no `dup`
  entries in the aggregation.
- Remaining kqueue shape: `kevent(nchanges=1, nevents=3)=6999` waits and
  `kevent(nchanges=1, nevents=0)=7046` delete/apply calls, plus startup noise.

What disappeared:

- Per-wait `dup` churn and most matching close churn for anchored direct
  host-fd waits.

Deferred:

- [ ] Persistent kqueue subscriptions. This could remove the delete/apply half,
  but it needs retained fd guards or generation tokens across completed waits
  and must validate signal, process-exit, fork, and wake-pipe behavior.
- [ ] Add a broader event-loop workload before taking persistent subscription
  risk; the narrow p50 movement does not justify it alone.

## Immediate Next Slice

The next slice should start from the post-`76d0aac` `overlay_small_updates`
shape.

Working theory:

- Host VFS and macOS kernel time are no longer the meaningful cost for this
  fixture.
- Whole-file memory overlay cloning on open is fixed.
- Repeated backend passes inside `open_for_dispatch` for memory files are fixed.
- Impossible FIFO metadata probes for memory regular-file opens are fixed.
- The no-follow canonicalization legacy kind lookup for memory regular-file
  opens is fixed.
- Useful committed perf rows moved from Carrick p50 `6063.542` us at `0a08b5f`
  to `4823.792` us at `0d9ee96` and `4734.250` us on the clean `76d0aac`
  rerun. The first `76d0aac` row was a high outlier and remains in the result
  log.
- Remaining cost is the repeated guest syscall pattern plus in-process runtime
  work before and after open dispatch: VFS mount fallthrough/context
  construction, fd-table installation, `fcntl`, `lseek`, `write`, and `close`.
- If the goal is to reduce traps rather than only reduce handler cost, the next
  candidate is a narrow dynamic interposer or guest-side batching workload, but
  it must be proven against a dynamic binary and must not become a correctness
  layer.

Tasks:

- [x] Re-run `carrick trace` for `overlay_small_updates` at `4bae00f` and record
  the post-fix guest syscall counts.
- [x] Add focused RED coverage for one repeated memory-file open setup cost and
  remove it with a runtime-local fast path.
- [x] Add focused RED coverage for the impossible memory-backend FIFO probe and
  remove it with a conservative backend capability hook.
- [x] Add focused RED coverage for the remaining no-follow canonicalization
  lookup and remove it with a metadata-only fast path.
- [ ] Add runtime-local counters or focused tracing around the remaining full
  guest open route: VFS-mount fallthrough/context construction, fd-table
  installation, and path record bookkeeping.
- [ ] If open/close setup dominates without host kernel work, design a RED test
  for the smallest runtime-local fast path before changing behavior.
- [ ] If trap count dominates and runtime-local work is small, add a dynamic
  workload that can justify a narrow `LD_PRELOAD`/interposer experiment.
- [ ] Keep the next runtime commit separate from the documentation/results
  commit.

Suggested commands:

```sh
./scripts/build-signed.sh
carrick trace --trace-out /tmp/carrick-overlay-small-updates.trace -- \
  run-elf --raw --fs memory \
  conformance-probes/target/aarch64-unknown-linux-musl/release/perf_overlay_small_updates

CARRICK_PERF_FILTER=overlay_small_updates \
CARRICK_PERF_REPS=3 \
CARRICK_PERF_WARMUP=1 \
CARRICK_PERF_COOLDOWN_SECS=0 \
cargo test -p carrick-cli --test perf_runner perf_gate -- --nocapture --include-ignored

jq -c empty docs/perf-results/2026-06-06-disk.jsonl
```

## Acceptance Rules

- Runtime changes get a RED test first unless the change is pure measurement or
  documentation.
- Benchmarks must record the exact `git_sha`, workload, fs mode, samples, and
  noisy flag in `docs/perf-results/*.jsonl`.
- Claims about host kernel work need DTrace, `carrick trace`, or another
  count-based source.
- Claims about copies need counters, focused tests, or a trace that proves the
  payload path disappeared.
- Do not claim a trap reduction from a handler optimization. A trap reduction
  requires fewer guest syscalls or a proven shim/interposer path.
- Keep runtime commits and result-documentation commits separate when practical.
