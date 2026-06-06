# Carrick First-Principles Performance Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Keep runtime
> commits separate from measurement/documentation commits. Steps use checkbox
> syntax for tracking.

**Goal:** Find and land significant Carrick performance gains by removing whole
classes of traps, host-kernel work, copying, allocation, page dirtying, and VFS
bookkeeping.

**Architecture:** The syscall runtime stays authoritative for Linux semantics.
Runtime fast paths are preferred when they remove proven in-handler work for all
binary types. `LD_PRELOAD`/interposer work is allowed only as a narrow measured
fast path for dynamic workloads after tracing proves trap count is still the
dominant cost.

**Tech Stack:** Rust `carrick-runtime`, `carrick-cli`, `conformance-probes`,
`carrick trace --trace-out`, DTrace for host attribution, Docker/Linux controls,
and JSONL perf rows under `docs/perf-results/`.

---

## Operating Rules

- Do not pursue ptrace in this plan.
- Do not weaken conformance gates for benchmark appearance.
- Do not claim wins from static inspection alone.
- Do not optimize syscall dispatch mechanics before larger work has been
  removed or measured.
- Do not turn `LD_PRELOAD` into a correctness layer.
- Add RED coverage before runtime behavior changes unless the change is pure
  measurement.
- Record exact `git_sha`, workload, samples, fs mode, and noisy/outlier notes
  for benchmark rows.
- Keep the next runtime commit separate from the next documentation/results
  commit.

## Cost Model

Rank candidates by the unavoidable cost they remove:

1. Guest traps and VM exits.
2. Host syscalls, Mach calls, `kevent`, `hv_vm_map`, and page-table churn.
3. Guest/host memory copies and temporary allocation.
4. Page dirtying that expands fork snapshots, resident scans, and writeback.
5. VFS metadata/path walks and whole-file rootfs or overlay materialization.
6. Per-wait descriptor pinning, fd duplication, transient kqueue registration,
   and wake bookkeeping.

Every optimization must answer:

- What whole unit of work disappears?
- Which test, counter, trace, or benchmark proves it disappeared?
- Which workload classes benefit?
- Which workload classes do not benefit?
- Did guest trap count change, or only handler cost?

## Current Branch State

Branch: `codex/perf-mmap-lazy-zero`

Latest relevant commits:

- `d59d596` - `perf(mem): skip fresh shared anon zero writes`
- `95503e5` - `docs(perf): record mmap hv map counts`
- `120aab9` - `docs(perf): decide dynamic workload gate`
- `2fc791b` - `docs(perf): record fd path result`
- `229105b` - `perf(fs): avoid duplicate fd path records`
- `af1ee02` - `docs(perf): replace first-principles plan`
- `04ffaa1` - `docs(perf): record vfs fallthrough result`
- `8a7659a` - `perf(fs): skip vfs context on rootfs open`
- `1f35251` - `docs(perf): record memory nofollow result`
- `76d0aac` - `perf(fs): fast path memory nofollow metadata`
- `4747926` - `docs(perf): record memory fifo probe result`
- `0d9ee96` - `perf(fs): skip impossible memory fifo probe`
- `b0b51cf` - `docs(perf): record memory overlay snapshot result`
- `0a08b5f` - `perf(fs): snapshot memory overlay opens`
- `071885b` - `docs(perf): record memory file open result`
- `4bae00f` - `perf(fs): avoid cloning memory files on open`

Relevant result file:

- `docs/perf-results/2026-06-06-disk.jsonl` contains
  `overlay_small_updates` rows for `4bae00f`, `0a08b5f`, `0d9ee96`,
  `76d0aac`, `8a7659a`, and `229105b`.
- `docs/perf-results/2026-06-06-memory.jsonl` contains a current
  `mmap_churn` row at `120aab9`.

## Current Evidence

### Anonymous mmap Lazy-Zero

Workload: `perf_mmap_churn`, 64 untouched 8 MiB private anonymous mappings.

Evidence:

- Before `1499984`: manual Carrick samples were about `55` to `58` ms.
- After `1499984`: Carrick p50 `831.708` us, p95 `897.625` us.
- Docker control p50 `60.667` us, p95 `197.750` us, noisy.
- Probes matched Docker/Linux: `mmapzerofill`, `mmaprecl`, and `forkcow`.

What disappeared:

- Eager zero-buffer materialization and writes for fresh private anonymous
  mappings.
- Page dirtying for untouched fresh mappings.

Remaining:

- `120aab9` trace with `scripts/dtrace/trace-hv-map-count.d` counted
  `guest mmap=69`, `guest munmap=68`, `host hv_vm_map=14`, and no
  `hv_vm_unmap` entries for `perf_mmap_churn`. The 64 workload mmaps are not
  causing one `hv_vm_map` each.
- Current `120aab9` perf row: Carrick p50 `830.667` us, p95 `873.292` us;
  Docker p50 `78.667` us, p95 `124.958` us, Docker noisy.
- `d59d596` removed eager zero-buffer materialization for fresh non-fixed
  `MAP_SHARED|MAP_ANONYMOUS` mappings in the boot-mapped shared aperture.
  Recycled shared-anon ranges still scrub stale bytes with `zero_backing`.
- Add a fork-heavy row to see whether lazy-zero reduced snapshot cost.
- Re-check high-VA alias paths for equivalent eager zero/copy behavior.

### Borrowed Vector I/O

Workloads: `pwritev_burst`, `preadv_burst`.

Evidence:

- `pwritev` payload `read_bytes` calls dropped from `2` to `0`; host-pointer
  hits rose from `0` to `2`.
- `readv`/`preadv` watched `write_bytes` calls dropped to `0` when writable
  host pointers were available.
- Blocking host-write continuations preserve staged `Vec<u8>` ownership instead
  of cloning.
- Probes matched Docker/Linux: `blockingpipewrite`, `writevpartial`, and
  `sigpipewrite`.

Known rows:

- `pwritev_burst`: Carrick p50 `20849.208` us, p95 `26075.417` us; Docker p50
  `3478.459` us, p95 `3654.750` us.
- `preadv_burst`: Carrick p50 `19852.375` us, p95 `22193.875` us; Docker p50
  `2571.125` us, p95 `2902.375` us.

Remaining:

- Add syscall-count evidence for the vector I/O workloads.
- Re-check socket/pipe vector paths for avoidable staging or cloning.
- Re-check stdio-style stream paths where validation ordering blocks direct
  borrowed I/O.

### VFS Dirty Ranges and Rootfs COW

Workloads: `overlay_small_updates`, `large_meta`.

Evidence:

- A 1-byte write to a 4 MiB overlay file reduced max backend writeback payload
  from `4194304` bytes to at most `1` byte.
- Alternating comparison against signed pre-dirty-range binary from `8e72886`:
  current p50 `13908.667` us vs old p50 `35769.625` us, about `2.57x` faster
  for `overlay_small_updates` under `run-elf --raw --fs memory`.
- Post-rootfs-COW rows at `4430ac2`:
  - `large_meta`: Carrick p50 `25647.500` us, p95 `28589.333` us; Docker p50
    `547.584` us, p95 `673.958` us.
  - `overlay_small_updates`: Carrick p50 `19890.709` us, p95 `21616.875` us;
    Docker p50 `1500.292` us, p95 `2000.458` us.

What disappeared:

- Whole-file writeback for small overlay writes.
- Whole-file rootfs copy-up for small writes to large rootfs files.
- Payload reads for metadata-only opens.

Remaining:

- Avoid any regression that re-materializes dense memory/rootfs files on open,
  metadata-only access, truncate, fallocate, copy-file-range, or writeback.
- Keep dirty-range tests close to each file operation that can materialize data.

### Host VFS Metadata Amplification

Workload: `large_meta`, 128 metadata/open/access cycles on a 256 MiB sparse
file.

Evidence:

- Before metadata-open fix at `8e72886`: Carrick p50 `14185998.250` us, p95
  `14564686.458` us; Docker p50 `291.208` us, p95 `441.125` us.
- After metadata-open fix at `e9cdb83`: Carrick p50 `26231.500` us, p95
  `28435.083` us; Docker p50 `334.750` us, p95 `373.833` us.
- Direct DTrace before the two 2026-06-06 VFS slices counted `openat=1814`,
  `close=1804`, `fstatat64=1173`, `fcntl=1055`, `fgetxattr=867`, and
  `flistxattr=435`.
- Guest trace shape was expected: `newfstatat=289`, `openat=147`,
  `fcntl=146`, `fstat=145`, `close=146`, and `faccessat=144`. The gap was
  host-side handler amplification, not unexpected guest traps.

Landed removals:

- `FsBackend::open_raw_fd_with_metadata` made host-backed overlay open derive
  metadata from the same fd that backs the guest descriptor.
- Root-only absolute `F_OK` access fast path removed the `faccessat`
  `openat`/`close`/`fcntl` bucket for the covered root-host-cache case.

Remaining:

- Consider a separate fast host-open path only with RED coverage for symlink,
  containment, FIFO, VFS mount, and fd-sharing invariants.
- Add allocation/copy counters for remaining host VFS hot paths where wall time
  alone is not diagnostic.

### Memory Overlay Open Amplification

Workload: `overlay_small_updates`.

Known guest syscall shape:

- `openat=594`
- `fcntl=593`
- `close=593`
- `write=583`
- `lseek=577`
- `ftruncate=16`
- `unlinkat=16`

Known host attribution:

- A bounded host trace over the hot loop had effectively no host VFS/kernel
  work: `poll=1`, `madvise=1`, `sigaction=2`, `write=7`.
- Conclusion: the remaining gap is repeated guest traps plus in-process
  dispatcher and memory-fs work, not macOS VFS time.

Landed removals:

- `4bae00f`: removed whole-file memory overlay clone on open by sharing dense
  memory file contents with `Arc<[u8]>`.
- `0a08b5f`: removed separate backend kind, metadata, and shared-content passes
  inside `RootFsVfs::open_for_dispatch` for in-memory overlay files.
- `0d9ee96`: removed one impossible FIFO metadata probe per memory regular-file
  open.
- `76d0aac`: removed the remaining legacy `lookup_kind` pass during no-follow
  canonicalization for memory regular-file opens.
- `8a7659a`: skipped VFS `OpenContext` construction for rootfs/overlay
  fallthrough opens.
- `229105b`: skipped duplicate `fd_open_paths` records for path-carrying
  memory `File` and `Directory` descriptors while keeping conservative records
  for named FIFO, pty, host-backed, and synthetic descriptor classes.

Useful current signal:

- `0d9ee96`: Carrick p50 `4823.792` us, p95 `5093.875` us; Docker p50
  `833.458` us, p95 `909.458` us.
- Clean `76d0aac` rerun: Carrick p50 `4734.250` us, p95 `4775.000` us; Docker
  p50 `806.375` us, p95 `1028.584` us, Docker noisy.
- Direct `8a7659a` signed runs were around `4.2` to `5.7` ms.
- `8a7659a` harness rows were noisy/high and should not be treated as the
  primary signal.
- Direct `229105b` signed runs were `8058.917`, `4995.709`, and `4510.291` us;
  treat the first as an outlier and the latter two as the useful low-overhead
  signal.
- `229105b` trace kept the same guest syscall shape: `openat=594`,
  `fcntl=593`, `close=593`, `write=583`, `lseek=577`, `ftruncate=16`,
  `unlinkat=16`.
- `229105b` harness rows were noisy/high: Carrick p50 `7562.125` us then
  `7175.000` us; Docker p50 `802.666` us then `815.166` us, with the second
  Docker row noisy.

Remaining:

- Attribute the remaining full guest-open route between fd-table installation,
  close cleanup, fd flag handling, and any non-path descriptor bookkeeping.
- Decide whether the remaining repeated `openat`/`fcntl`/`lseek`/`write`/`close`
  trap shape can be reduced only by a dynamic interposer or by a safe
  runtime-local fast path.

### Wait fd Pinning and kqueue Churn

Workload: `wait_pipe_pingpong`.

Evidence:

- Initial DTrace counted `dup=6999`, `close=7059`, and `kevent=14091`.
- `db6d5cc` removed per-wait `dup` churn for anchored direct host-fd waits.
- Post-change DTrace counted `close=61` and `kevent=14069`, with no `dup`
  entries in aggregation.

Remaining:

- Persistent kqueue subscriptions could remove the delete/apply half, but this
  needs retained fd guards or generation tokens across completed waits.
- Add a broader event-loop workload before taking persistent subscription risk.

## Primary Near-Term Bet

Start from the post-`8a7659a` `overlay_small_updates` shape.

Working theory:

- Host VFS and macOS kernel time are no longer the meaningful cost for this
  fixture.
- Whole-file memory overlay cloning on open is fixed.
- Repeated backend passes, impossible FIFO metadata probes, no-follow legacy
  kind lookup, and VFS fallthrough context construction are fixed for memory
  regular-file opens.
- Remaining cost is the repeated guest syscall pattern plus in-process runtime
  work after rootfs open dispatch: fd-table installation, path record
  bookkeeping, `fcntl`, `lseek`, `write`, and `close`.
- If trap count dominates after fd/path bookkeeping is measured, the next
  candidate is a narrow dynamic interposer or guest-side batching workload. It
  must be proven against a dynamic binary and must not own correctness.

## Task 1: Attribute fd-table and path bookkeeping

**Files:**

- Modify: `crates/carrick-runtime/src/dispatch/fs.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs/fd_helpers.rs`
- Inspect: `crates/carrick-runtime/src/dispatch/fd_table.rs`
- Inspect: `crates/carrick-runtime/src/dispatch/fs/stat.rs`

**Question:** Does a memory-backed `OpenDescription::File` or `Directory`
already carry enough path information that `fd_open_paths` is duplicate work for
ordinary `/proc/self/fd/N` readlink/stat behavior?

**Steps:**

- [x] Inspect all writers and readers of `fd_open_paths`.

  Run:

  ```sh
  rg -n "fd_open_paths|record_path|proc_self_fd_number|proc_self_fdinfo_number|install_fd_at_or_above" crates/carrick-runtime/src
  ```

- [x] Classify which descriptor families need `fd_open_paths` because the open
  description cannot answer a guest-facing path.

  Expected conservative keepers:

  - host-backed descriptors that use host-only fd metadata
  - synthetic descriptors such as `/dev/null`, pipes, sockets, eventfd, timerfd,
    epoll, tty, and other non-rootfs descriptors
  - special `/proc` or `/dev` nodes where the guest-facing readlink string is not
    simply the `OpenDescription` path

- [x] Add test-only counters for `fd_open_paths` insertions and lookups.

  Put counters next to the insertion path in `crates/carrick-runtime/src/dispatch/fs.rs`
  or in a small helper if the insertion sites are spread out:

  ```rust
  #[cfg(test)]
  static FD_OPEN_PATH_INSERTS: AtomicUsize = AtomicUsize::new(0);
  #[cfg(test)]
  static FD_OPEN_PATH_LOOKUPS: AtomicUsize = AtomicUsize::new(0);
  ```

- [x] Write the RED test for the smallest duplicate case.

  Test name:

  ```text
  memory_file_open_does_not_duplicate_path_record_for_proc_fd
  ```

  Expected RED failure before the optimization:

  ```text
  fd_open_paths insertions should be 0 for memory OpenDescription::File
  ```

- [x] Preserve `/proc/self/fd/N` behavior while removing duplicate storage.

  The intended design is:

  - `readlinkat("/proc/self/fd/N")` first asks fd-specific special cases.
  - If there is no special path record, inspect the open description.
  - For `OpenDescription::File { path, .. }` and `Directory { path, .. }`,
    return that path.
  - Keep `fd_open_paths` for descriptor classes where the open description is
    insufficient or intentionally synthetic.

  Progress at `af1ee02` plus worktree runtime changes:

  - RED observed:
    `cargo test -p carrick-runtime dispatch::fs::tests::memory_file_open_does_not_duplicate_path_record_for_proc_fd -- --nocapture`
    failed with `left: 1 right: 0`.
  - GREEN observed after the runtime change with the same command.
  - The test also verifies `readlinkat("/proc/self/fd/3")` still returns
    `/regular.bin` through `OpenDescription::open_path()`.
  - The runtime change skips `fd_open_paths` insertion only for
    `OpenDescription::File` and `OpenDescription::Directory`; named FIFO, pty,
    host-backed, and intentionally synthetic records keep the conservative map
    path.

- [x] Run focused checks.

  ```sh
  cargo test -p carrick-runtime memory_file_open_does_not_duplicate_path_record_for_proc_fd -- --nocapture
  cargo test -p carrick-runtime --test integration proc -- --nocapture
  cargo test -p carrick-runtime --test integration rootfs_overlay -- --nocapture
  cargo test -p carrick-runtime --test integration memory_overlay_regular_open_skips_legacy_kind_lookups -- --nocapture
  ```

  Additional adjacent checks run:

  ```sh
  cargo test -p carrick-runtime --test integration memory_overlay_regular_open_skips_fifo_probe_when_backend_cannot_have_fifos -- --nocapture
  cargo test -p carrick-runtime --test integration memory_overlay_open_uses_single_backend_snapshot_for_shared_file -- --nocapture
  ```

- [x] Run broad compile/format checks.

  ```sh
  cargo test -p carrick-runtime --tests --no-run
  cargo fmt --all -- --check
  git diff --check
  ```

- [x] Commit only runtime files.

  ```sh
  git add crates/carrick-runtime/src/dispatch/fs.rs crates/carrick-runtime/src/dispatch/fs/fd_helpers.rs crates/carrick-runtime/src/dispatch/fd_table.rs crates/carrick-runtime/src/dispatch/fs/stat.rs
  git commit -m "perf(fs): avoid duplicate fd path records"
  ```

  Committed as `229105b`.

## Task 2: Measure the remaining open/close route

**Files:**

- Modify if needed: `crates/carrick-runtime/src/dispatch/fs.rs`
- Modify if needed: `crates/carrick-runtime/src/dispatch/fs/fd_helpers.rs`
- Modify if needed: `crates/carrick-runtime/src/dispatch/fd_table.rs`
- Modify: `goal.md`
- Append: `docs/perf-results/2026-06-06-disk.jsonl`

**Steps:**

- [x] Build a signed binary.

  ```sh
  ./scripts/build-signed.sh
  ```

- [x] Run direct signed smoke samples for `overlay_small_updates`.

  ```sh
  target/release/carrick run-elf --raw --fs memory \
    conformance-probes/target/aarch64-unknown-linux-musl/release/perf_overlay_small_updates
  ```

  Samples at `229105b`: `8058.917`, `4995.709`, and `4510.291` us.

- [x] Run `carrick trace` with trace output separated from guest output.

  ```sh
  CARRICK_RUN_ID=perf-overlay-post-fd-path \
  target/release/carrick trace --trace-out /tmp/carrick-overlay-small-updates-post-fd-path.trace -- \
    run-elf --raw --fs memory \
    conformance-probes/target/aarch64-unknown-linux-musl/release/perf_overlay_small_updates
  ```

  Trace file: `/tmp/carrick-overlay-small-updates-post-fd-path.trace`.
  Aggregation: `openat=594`, `fcntl=593`, `close=593`, `write=583`,
  `lseek=577`, `ftruncate=16`, `unlinkat=16`.

- [x] Run the filtered perf harness.

  ```sh
  CARRICK_PERF_FILTER=overlay_small_updates \
  CARRICK_PERF_REPS=3 \
  CARRICK_PERF_WARMUP=1 \
  CARRICK_PERF_COOLDOWN_SECS=0 \
  cargo test -p carrick-cli --test perf_runner perf_gate -- --nocapture --include-ignored
  ```

- [x] Append JSONL rows with the exact current `git_sha`.

  The harness appended two Carrick/Docker row pairs for
  `229105b17d5fc1796abf48aa0098300063472638`:

  - run `cr-perf-82952`: Carrick p50 `7562.125` us, p95 `8324.708` us,
    noisy; Docker p50 `802.666` us, p95 `857.958` us.
  - run `cr-perf-83343`: Carrick p50 `7175.000` us, p95 `7902.416` us,
    noisy; Docker p50 `815.166` us, p95 `1594.958` us, noisy.

- [x] Validate result JSON and docs diff.

  ```sh
  jq -c empty docs/perf-results/2026-06-06-disk.jsonl
  git diff --check
  ```

- [x] Commit only documentation/result files.

  ```sh
  git add goal.md docs/perf-results/2026-06-06-disk.jsonl
  git commit -m "docs(perf): record fd path result"
  ```

  Committed as `2fc791b`.

## Task 3: Decide whether trap count is the real remaining bottleneck

**Files:**

- Inspect: `conformance-probes/src/bin/perf_overlay_small_updates.rs`
- Modify if dynamic coverage is needed: `conformance-probes/src/bin/`
- Modify if perf registry coverage is needed: `crates/carrick-cli/tests/perf_runner.rs`
- Modify: `goal.md`

**Decision rule:**

- If Task 1 removes measurable handler work and the remaining gap is still
  dominated by `openat`/`fcntl`/`lseek`/`write`/`close` count, move to a dynamic
  workload/interposer experiment.
- If Task 1 shows fd/path work is not measurable, do not keep shaving open
  internals unless a new counter identifies a whole removable unit of work.

Decision at `2fc791b`:

- GO for designing a dynamic/glibc workload lane.
- NO-GO for interposer implementation until that lane exists and has Carrick
  and Docker rows without an interposer.
- The current `conformance-probes` perf lane is
  `aarch64-unknown-linux-musl` and injects static probe binaries, so it cannot
  validate `LD_PRELOAD` behavior.
- `perf_stdio_burst` is useful as a static "dynamic-style" syscall-shape
  workload, but it still cannot prove a libc interposer.
- `overlay_small_updates` remains dominated by the same guest trap sequence
  after the fd path slice. Further open-handler shaving needs a new counter that
  identifies a whole removable unit; otherwise the better next question is
  whether a dynamic process can safely bypass or batch any traps.

Recommended design for the next implementation slice:

- Add a new perf-runner lane for dynamic Linux workloads, separate from the
  existing static musl probe lane.
- Build or materialize a small glibc-linked workload inside the Ubuntu guest
  environment and time only the workload body, not compile/setup time.
- First dynamic workload should mirror `overlay_small_updates` or
  `stdio_burst`, print the same `key=value` metrics, and run under Carrick and
  Docker with no interposer.
- Only after baseline rows exist should an interposer variant be added. The
  first acceptable interposer experiment must be narrow, opt-in, and measured;
  it must not own fd allocation, close semantics, signal behavior, blocking, or
  `/proc/self/fd` visibility.

Rejected next steps:

- Do not add an `LD_PRELOAD` library before a dynamic baseline lane exists.
- Do not use the current static musl probe output as evidence for or against
  interposition.
- Do not cache `open` fds or fuse `lseek` plus `write`; those change visible fd
  semantics unless proven through a much narrower design and oracle tests.

**Steps:**

- [ ] Add or select a dynamic binary workload that mirrors
  `overlay_small_updates` closely enough to test an interposer.

  Requirements:

  - dynamic libc path, not static musl
  - same repeated open/update/close shape
  - Docker/Linux control row
  - Carrick row without an interposer
  - Carrick row with any proposed interposer

- [ ] Define an interposer experiment as a measured optimization only.

  Allowed experiments:

  - batch or redirect a known libc call sequence only when fd identity,
    blocking, signals, close semantics, and visible side effects remain owned by
    the runtime
  - answer explicitly cached process metadata when the value is already stable
    and runtime-owned

  Rejected experiments:

  - fd caching that changes allocation, close, or `/proc/self/fd` visibility
  - `lseek`/`write` fusion that changes shared fd offset semantics
  - wrappers that need to emulate Linux fd, signal, or blocking correctness

- [x] Record a go/no-go decision in this file before writing interposer code.

## Task 4: Revisit mmap and fork snapshot costs

**Files:**

- Inspect: `crates/carrick-runtime/src/dispatch/mem.rs`
- Inspect: memory/fork snapshot helpers under `crates/carrick-runtime/src`
- Modify if measured: `docs/perf-results/*.jsonl`
- Modify: `goal.md`

**Steps:**

- [x] Count `hv_vm_map`/`hv_vm_unmap` for `perf_mmap_churn`.

  Added reusable trace script:

  ```sh
  scripts/dtrace/trace-hv-map-count.d
  ```

  Trace command:

  ```sh
  CARRICK_RUN_ID=perf-mmap-hv-map-$$ \
  target/release/carrick trace \
    --script scripts/dtrace/trace-hv-map-count.d \
    --trace-out /tmp/carrick-mmap-hv-map-count.trace -- \
    run-elf --raw --fs host \
    conformance-probes/target/aarch64-unknown-linux-musl/release/perf_mmap_churn
  ```

  Trace result: `guest mmap=69`, `guest munmap=68`, `host hv_vm_map=14`, and
  no `host hv_vm_unmap` entries. The workload's 64 fresh anonymous mappings are
  not producing one HVF map/unmap pair per guest mapping.

  Current perf row:

  ```sh
  CARRICK_PERF_FILTER=mmap_churn \
  CARRICK_PERF_REPS=3 \
  CARRICK_PERF_WARMUP=1 \
  CARRICK_PERF_COOLDOWN_SECS=0 \
  cargo test -p carrick-cli --test perf_runner perf_gate -- --nocapture --include-ignored
  ```

  `docs/perf-results/2026-06-06-memory.jsonl` rows at
  `120aab9971dc10e9a4604b87da482152a42d70d8`: Carrick p50 `830.667` us,
  p95 `873.292` us; Docker p50 `78.667` us, p95 `124.958` us, Docker noisy.
- [x] Inspect shared anonymous paths for remaining eager zero/copy behavior.

  Result at `d59d596`:

  - Fresh non-fixed `MAP_SHARED|MAP_ANONYMOUS` now records whether the shared
    aperture allocation came from the free list. Fresh bump allocations return
    directly from the boot-zeroed shared aperture without materializing a zero
    `Vec` or calling `write_bytes`.
  - Recycled shared-anon allocations still call `zero_backing`, preserving
    Linux's zero-fill invariant for stale shared-aperture ranges.
  - While verifying the mmap surface, the existing integration test
    `mmap_anonymous_fixed_mapping_zeroes_guest_memory_and_mprotect_munmap_are_noops`
    caught that `MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS` over dirty low memory also
    needs explicit `zero_backing`; that path now scrubs because fixed mappings
    overwrite a caller-selected range and cannot rely on the bump allocator's
    pristine-tail invariant.

  RED evidence:

  ```sh
  cargo test -p carrick-runtime fresh_shared_anon_mmap_skips_zero_write -- --nocapture
  ```

  Before the runtime change, this failed with `left: 1 right: 0` for the
  expected fresh shared-anon write count.

  GREEN and adjacent checks:

  ```sh
  cargo test -p carrick-runtime shared_anon_mmap -- --nocapture
  cargo test -p carrick-runtime --test integration mmap -- --nocapture
  cargo test -p carrick-runtime --test integration munmap -- --nocapture
  cargo test -p carrick-runtime --test integration mremap -- --nocapture
  cargo test -p carrick-runtime --tests --no-run
  cargo fmt --all -- --check
  git diff --check
  ```

  No JSONL perf row was added for this slice because the existing
  `perf_mmap_churn` workload is private anonymous mmap churn and does not
  exercise `MAP_SHARED|MAP_ANONYMOUS`. A shared-anon or fork-heavy workload is
  required before claiming a measured benchmark win from `d59d596`.

- [ ] Add a fork-heavy or shared-anon workload row after lazy-zero.
- [ ] Inspect high-VA alias paths for remaining eager zero/copy behavior.
- [ ] Add RED coverage before changing alias, COW, or shared-memory behavior.

## Task 5: Revisit wait-path kqueue churn only with a broader workload

**Files:**

- Inspect: wait and fd pinning code under `crates/carrick-runtime/src`
- Modify if adding coverage: `conformance-probes/src/bin/`
- Modify if adding perf registry coverage: `crates/carrick-cli/tests/perf_runner.rs`
- Modify: `goal.md`

**Steps:**

- [ ] Add a broader event-loop workload that performs repeated waits on stable
  descriptors and has Docker control rows.
- [ ] Measure whether `kevent` delete/apply churn is material in that broader
  workload.
- [ ] Only then design persistent kqueue subscriptions with retained fd guards
  or generation tokens.
- [ ] Validate signal, process-exit, fork, wake-pipe, and descriptor-close
  behavior before landing persistent subscriptions.

## Verification Commands

Use the narrowest command that proves the current slice, then run the broad
guards before commit.

```sh
cargo test -p carrick-runtime <focused_test_name> -- --nocapture
cargo test -p carrick-runtime --test integration proc -- --nocapture
cargo test -p carrick-runtime --test integration rootfs_overlay -- --nocapture
cargo test -p carrick-runtime --tests --no-run
cargo fmt --all -- --check
git diff --check
./scripts/build-signed.sh
jq -c empty docs/perf-results/2026-06-06-disk.jsonl
jq -c empty docs/perf-results/2026-06-06-memory.jsonl
```

Trace and perf commands:

```sh
CARRICK_RUN_ID=perf-overlay-next \
target/release/carrick trace --trace-out /tmp/carrick-overlay-small-updates-next.trace -- \
  run-elf --raw --fs memory \
  conformance-probes/target/aarch64-unknown-linux-musl/release/perf_overlay_small_updates

CARRICK_PERF_FILTER=overlay_small_updates \
CARRICK_PERF_REPS=3 \
CARRICK_PERF_WARMUP=1 \
CARRICK_PERF_COOLDOWN_SECS=0 \
cargo test -p carrick-cli --test perf_runner perf_gate -- --nocapture --include-ignored
```

## Completion Criteria

- Each runtime optimization has RED/GREEN evidence for the removed work.
- Each benchmark claim has a committed JSONL row or an explicitly documented
  direct-run sample with SHA.
- Each host-kernel claim has trace/count evidence.
- Each copy/allocation claim has counters, focused tests, or a trace that proves
  the payload path disappeared.
- Trap reductions are not claimed unless guest syscall count actually drops or
  a proven shim/interposer path bypasses the trap.
- Runtime and documentation/results changes remain in separate commits when
  practical.
