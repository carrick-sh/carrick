# Carrick Deep-Dive Code Review

> **Scope:** Read-only review of all source code across all 5 crates. No tests or commands were executed.
>
> **Codebase profile:** ~41K lines in `carrick-runtime` alone, plus ~2K lines across `spec`, `image`, `engine`, and `cli`. 55 static fixture binaries, 34 conformance probes, ~50 CLI tests.

---

## Executive Summary

Carrick is an impressively ambitious and well-executed project. The HVF trap-and-translate architecture is sound, the no-panic discipline is laudable, and the breadth of syscall coverage (~200 syscalls) is remarkable. Several design choices are genuinely excellent — the `KernelAbi` compile-time wire-size enforcement, the `ScriptedTrap` test abstraction, the `SigframeDigest` round-trip fidelity probe, the `mincore`-gated sparse COW copy during fork, and the async-signal-safe self-pipe discipline throughout the PTY and signal subsystems.

That said, the codebase has grown organically and now carries **significant structural debt**. Four files exceed 3,000 lines each (the biggest is 5,770), lock ordering is partially documented but incomplete, and several translation layers silently drop semantics that will bite as workloads get more complex.

The findings below are organized from most impactful to least.

---

## 1. Structural & Organizational Issues

### 1.1 God Files

The four largest files are each individually larger than many complete Rust crates:

| File | Lines | KB | Role |
|------|------:|---:|------|
| [dispatch/fs.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/fs.rs) | 5,065 | 207 | Every filesystem syscall handler |
| [dispatch/mod.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/mod.rs) | 4,737 | 172 | Dispatcher + shared helpers + misc syscalls |
| [trap.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/trap.rs) | 3,145 | 133 | VM exit handling + signal frames + vectors + fork |
| [dispatch/net.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/net.rs) | 3,505 | 124 | Every networking syscall handler |

These files are too large to navigate, review, or modify without risk. They also hurt incremental compile times.

**Recommended splits:**

**`dispatch/fs.rs`** has 7 clean extraction points:

| Proposed Module | ~Lines | Responsibility |
|---|---|---|
| `fs/ioctl.rs` | 300 | ioctl dispatch (TIOCGWINSZ, TCGETS, FIONBIO, etc.) |
| `fs/read_write.rs` | 600 | read/write/readv/writev/pread64/pwrite64 |
| `fs/sendfile_splice.rs` | 350 | sendfile, splice, copy_file_range |
| `fs/dir_ops.rs` | 400 | mkdirat, mknodat, unlinkat, symlinkat, linkat, renameat |
| `fs/stat.rs` | 300 | newfstatat, fstat, statx, access, xattr |
| `fs/open_close.rs` | 250 | openat, openat2, close, close_range |
| `fs/metadata.rs` | 200 | fchmod, fchown, utimensat |

**`dispatch/mod.rs`** has strong internal boundaries:

| Proposed Module | ~Lines | Responsibility |
|---|---|---|
| `dispatch/fd_table.rs` | 400 | `OpenDescription`, `OpenFile`, stat types |
| `dispatch/epoll_eventfd.rs` | 500 | epoll/eventfd/timerfd infrastructure |
| `dispatch/io_helpers.rs` | 400 | read/write helpers, stat writers, kernel struct I/O |
| `dispatch/errno.rs` | 60 | `macos_to_linux_errno` translation table |
| `dispatch/futex.rs` | 330 | futex operations |
| `dispatch/poll.rs` | 500 | poll/ppoll/select/pselect6 |

**`trap.rs`** contains 5 logically distinct concerns:

| Proposed Module | ~Lines | Responsibility |
|---|---|---|
| `trap/signal_frame.rs` | 370 | Signal frame inject/restore + `SigframeDigest` |
| `trap/fork.rs` | 200 | COW snapshot, HVF rebuild |
| `trap/thread.rs` | 130 | `build_thread_spec` / `from_thread_spec` |
| `trap/snapshot.rs` | 130 | vCPU snapshot/restore |
| `trap/shared_mapping.rs` | 120 | `map_shared_file`, `map_shared_anon` |

### 1.2 CLI Monolith

[main.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-cli/src/main.rs) is ~1,400 lines implementing ~16 subcommands inline. The `run_cli()` match arm alone is ~560 lines. Each subcommand should be its own module under `src/cmd/`. Additionally, `probe_case_sensitive` duplicates `carrick_runtime::apfs::probe_case_sensitive`, and `join_ids` duplicates `dtrace_consumer::join_ids`.

### 1.3 `carrick-engine` Justification

[carrick-engine/lib.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-engine/src/lib.rs) is only ~320 lines. The CLI bypasses it for every command except `run` — `run-elf`, `rootfs`, `compat-report`, `trace`, etc. all reach directly into `carrick-runtime`. Either fold it into `carrick-cli` (its `CliRunRequest` is constructed only in main.rs) or grow it to absorb more orchestration (run-elf, fs-backend selection, compat-report envelope).

### 1.4 `carrick-spec` Dependency Leak

`carrick-spec` pulls in `clap` (for `#[derive(clap::ValueEnum)]` on `FsBackendKind`). This is a CLI concern leaking into the shared data layer. Move the `ValueEnum` derive behind a feature gate.

### 1.5 Unused Type

`ContainerSpec` is defined in `carrick-spec` but **never used anywhere** in the codebase — the CLI constructs `CliRunRequest` instead. Either use it or remove it.

---

## 2. Concurrency & Safety

### 2.1 Lock Ordering — Partially Documented, Needs Completion

> [!CAUTION]
> The lock ordering comment exists but doesn't cover all known lock interactions.

There IS a lock ordering comment at `dispatch/mod.rs` line 6:
```
// LOCK ORDERING: dispatch handlers must not hold subsystem locks while entering
// guest-memory callbacks or blocking host waits. When multiple dispatcher
// locks are unavoidable, acquire fd/open-description state before filesystem
// overlay state, then proc/signal/thread registries.
```

**But the following are not covered:**
1. **`EPOLL_INMEM_KQUEUES` global Mutex** — acquired by `notify_inmem_epoll()` which is called from `write_eventfd`. If a handler holds `open_files` read lock while writing an eventfd, and another thread holds `EPOLL_INMEM_KQUEUES` while trying to read `open_files`, there's a potential inversion.
2. **`close_cloexec_fds`** holds `self.io.open_files.write()` while calling `close_open_file_and_free_pty()`, which acquires `self.fs.pty_table.lock()`. This cross-lock is acknowledged in comments but not in the ordering hierarchy.
3. **`mem_snapshot`** clones the entire `MemState` under lock — if it grows large, this becomes a contention point.

**Fix:** Extend the lock ordering comment to include `pty_table` and `EPOLL_INMEM_KQUEUES`, and audit the EPOLL×open_files potential inversion.

### 2.2 Triplicated Dispatch Loop

> [!WARNING]
> `runtime.rs` contains three nearly-identical syscall dispatch loops — the highest-risk area for drift bugs.

| Loop | Lines | Path |
|------|-------|------|
| `run_combined_syscall_loop_with_dispatcher` | ~250 | Combined `GuestMemory+SyscallTrap` (single-threaded) |
| `run_split_loop` | ~245 | Split `GuestMemory` + `SyscallTrap` (single-threaded) |
| `run_vcpu_until_exit` | ~225 | Multi-threaded HVF (production path) |

Evidence of drift: the multi-threaded loop calls `dump_kick_stats()` on Exit and handles `EL0Fault` — the single-threaded loops don't. All three share the same `WaitOnFds`/`WaitOnPollFds`/`WaitOnProcExit`/`Exit`/`Fork`/`Execve`/`SigReturn` match arms.

**Fix:** Extract a shared `handle_dispatch_outcome()` function. The three loops differ only in (a) whether they hold a dispatcher lock, (b) fork quiesce coordination, and (c) thread lifecycle — these can be parameterized.

### 2.3 Fork Quiesce Spin-Wait

In `handle_fork`, `while !fork_barrier().try_begin_fork() { ... yield_now() }` spins without timeout. If the token-holder deadlocks, this thread spins forever. Consider adding a hard timeout/abort path.

### 2.4 Guest Memory Bounds

The `host_mapping.rs` module (122 lines) provides RAII ownership for HVF-backed memory. The `volatile_copy_from_guest` / `volatile_copy_to_guest` in `trap.rs` copy byte-by-byte — correct for avoiding UB, but O(n) volatile reads could be slow for large guest memory operations. A `memcpy` with a single fence might suffice given HVF's coherence model.

### 2.5 `unreachable!()` in Dispatch Match

Multiple `unreachable!()` calls exist in dispatch match arms that guard against "impossible" outcomes. If a dispatcher bug produces them, the runtime panics — violating the no-panic discipline. Replace with error returns for defense in depth.

---

## 3. Architecture & Design Strengths

This section is important — the codebase has many genuinely excellent qualities:

### 3.1 `KernelAbi` Trait — Compile-Time Wire-Size Enforcement

The `KernelAbi` trait (`linux_abi.rs`) is the single most important safety invariant in the runtime. Every struct written to or read from guest memory has a compile-time `ABI_SIZE` check that prevents the class of bug where `size_of::<T>()` differs from the Linux kernel's on-the-wire size. The const-assert catches layout mistakes at compile time.

### 3.2 `SigframeDigest` Fidelity Probe

The signal frame inject/restore path fingerprints injected signal frames and compares on restore, detecting save/restore round-trip errors in real time via DTrace. This is a production-quality debugging mechanism that catches subtle ABI mismatches immediately.

### 3.3 `ExecLevel` Guard

The `ExecLevel` guard in `run_until_syscall` detects when a vCPU kick lands mid-EL1-trampoline and resumes rather than injecting a corrupt signal frame. This is a subtle, well-documented fix for a real production bug.

### 3.4 SPSR_EL1 vs CPSR Source Selection

The signal injection path correctly selects CPSR (live EL0 PSTATE) on the kick path vs SPSR_EL1 (hardware-latched PSTATE) on the syscall-boundary path. Getting this wrong causes condition-flag corruption in preempted code. The comment explains *exactly* why.

### 3.5 `mincore`-Gated Sparse Fork Copy

`clone_region_for_child` uses `mincore` to copy only resident pages during fork, making child snapshots proportional to working set rather than address space. Excellent optimization.

### 3.6 Async-Signal-Safe Discipline

All signal handler code paths (`handle_sigint`, `handle_routed`, `notify_pending`) are strictly async-signal-safe — only atomic stores and pipe writes. The `handle_routed` fault guard correctly distinguishes synchronous CPU faults (`si_code > 0`) from externally-sent signals (`si_code <= 0`).

### 3.7 `DispatchOutcome` Lock-Free Pattern

The `DispatchOutcome::FutexWait` / `WaitOnFds` / `WaitOnProcExit` idiom specifically avoids blocking under any lock. The handler prepares wait state, returns an outcome, and the runtime drops all locks before parking. This is the right design.

### 3.8 `ScriptedTrap` Test Abstraction

The `SyscallTrap` trait enables testing the full runtime loop with scripted syscall sequences — no HVF needed. This is a brilliant pattern that provides high-confidence testing without hardware dependency.

### 3.9 Other Highlights

- **`cap-std` filesystem sandboxing** — prevents path traversal escapes at the capability level
- **USDT probes** — built-in DTrace traceability via `carrick trace` and `carrick compat-report`
- **APFS `clonefile` optimization** — COW rootfs setup, specific to macOS
- **Self-pipe patterns** in PTY relay — textbook async-signal-safe shutdown and SIGWINCH propagation
- **AF_NETLINK synthesis** — satisfies `getifaddrs`/`__check_pf` without real netlink
- **FEAT_PAN3 workaround** — thoroughly tested AP/PXN/UXN page table bits
- **AT_HWCAP hardcoded to `0x1fb`** — covers FP, ASIMD, AES, PMULL, SHA1, SHA2, CRC32, ATOMICS; correct for all current M-series chips
- **`parking_lot` mutexes** throughout — never poison, eliminating one panic source
- **`OnceLock`-cached host facts** — CPU count prefers `hw.perflevel0.logicalcpu` (P-cores only), clamped to [1,1024], overridable via `CARRICK_EXPOSED_CPUS`

---

## 4. Correctness & Semantic Gaps

### 4.1 errno Translation — Good but Incomplete

The `macos_to_linux_errno` function (`dispatch/mod.rs`) covers ~35 network/FS-specific errnos where Darwin and Linux numbers diverge (EAGAIN=35→11, EINPROGRESS=36→115, etc.). The fallback `other => other` is correct for codes 1–34 (which are identical) but **incorrect for unmapped Darwin codes ≥35**. For example, Darwin `ENOATTR` (93) or `EAUTH` (80) would leak as non-Linux errnos.

**Risk:** Low in practice (these are rare), but a catch-all mapping to `EIO` for unknown codes >34 would be more defensive.

### 4.2 `OpenDescription` Variant Explosion

The `OpenDescription` enum has 15 variants, and `status_flags()` / `set_status_flags()` each have 13-arm match blocks that are pure boilerplate. A struct-with-enum-payload would eliminate ~200 lines:
```rust
struct OpenDescription {
    status_flags: u64,
    kind: OpenDescriptionKind,
}
```

### 4.3 Stat/Statx Writer Duplication

Six nearly-identical stat-writing functions (`write_stat`, `write_stat_real`, `write_statx`, `write_statx_real`, `write_synthetic_stat`, etc.) differ only in their source type. A single `StatSource` trait → `write_stat(memory, addr, &source)` would halve this code.

### 4.4 Clock Duration Duplication

`linux_clock_duration`, `linux_clock_is_known`, `linux_clock_is_settable` replicate the same clock-ID match tree three times. A `ClockInfo` table would be DRYer.

### 4.5 `epoll_ctl MOD` Non-Atomicity

`epoll_ctl MOD` is implemented as delete-then-add. An fd event between the two operations is lost. This is acknowledged in comments and matches FreeBSD's approach, but creates a data-loss risk on high-throughput MOD operations.

### 4.6 In-Memory Epoll Broadcast Scalability

The `EPOLL_INMEM_KQUEUES` global `Vec<i32>` broadcasts `EVFILT_USER(0)` to ALL epoll instances whenever any eventfd/pipe/timerfd changes state. This is O(n) in epoll instance count and generates spurious wakeups. Fine for small counts, but will scale poorly with many epoll instances (e.g., Go with many goroutine pollers).

### 4.7 Mmap Arena — Non-Reclaiming

The mmap arena is a bump allocator. `munmap`'d space is not reclaimed (only tail-trim and free-list coalescing). Under heavy mmap/munmap workloads, the guest will eventually hit ENOMEM even if logical utilization is low.

### 4.8 Single-Slot Process Signal Model

Process-directed signals use a single `AtomicI32` with last-write-wins. Rapid back-to-back signals can be lost. Documented as intentional v0 tradeoff.

### 4.9 Host FD Leak in `mmap`

In `dispatch/mem.rs`, when `map_shared_file` fails, the `dup_fd` is NOT closed — it falls through to the next code path. If that also fails, the fd leaks.

### 4.10 `O_PATH` Silently Ignored

Programs using `O_PATH` fds (for `fchdir`, `openat` relative paths, `fstat` without read permission) will get a fully-opened fd instead.

### 4.11 MAP_SHARED Writeback — Fixed

File-backed `MAP_SHARED` mappings now use host-file-backed shared mappings, so writes are visible through the file before `msync` and survive `munmap`. The `memmap` conformance probe covers both edges with `b_shared_write_visible_without_msync` and `b_shared_write_survives_munmap`.

### 4.12 Abstract Unix Sockets

Not supported on Darwin. Returns `EAFNOSUPPORT`. Affects D-Bus and systemd patterns.

### 4.13 Unix Socket Path Shortening

Guest Unix socket paths are hashed to 16-hex-char host paths via FNV-1a. The 64-bit hash has ~1 in 2^32 collision probability at ~65K distinct paths. Fine in practice but theoretically unsound for adversarial input.

### 4.14 Mmap `PROT_READ` Not Enforced

`mmap` doesn't track per-page protections beyond `PROT_NONE`. A `PROT_READ` mmap followed by a write syscall to that region won't fault. Conformance gap but not a security issue in a cooperative guest model.

---

## 5. Testing

### 5.1 The Testing Architecture is Strong

The five-layer testing architecture is well-designed:

| Layer | What | Requires |
|-------|------|----------|
| Unit tests in `src/elf.rs` | Pure parsing logic | Nothing |
| Consolidated integration tests | Syscall dispatch via `ScriptedTrap` | Nothing (no HVF) |
| Isolated integration tests | Process-global state (HVF VM, fork, PTY) | macOS aarch64, sometimes signed binary |
| CLI tests (~50 tests) | End-to-end binary behavior | Built fixtures |
| Conformance probes (34 binaries) | Differential correctness vs real Linux | Docker arm64 + signed binary |

**Notable strengths:**
- **`ScriptedTrap`** enables full runtime loop testing without HVF
- **Differential conformance testing** (`conformance.rs`) runs the SAME snippet under carrick and Docker, normalizes output, and diffs — 16 shell-snippet cases + 34 static probe binaries
- **Graceful HVF degradation** — every CLI test checks for HVF availability and falls back cleanly
- **`KNOWN_PROBE_GAPS`** remains empty after the full probe run; the harness still fails loudly if a known-gap entry is reintroduced and unexpectedly passes
- **`sweep_wedged_guests()`** calls `sudo -n scripts/sudo/kill.sh` between conformance cases to clean up wedged HVF processes

### 5.2 In-Crate Unit Tests Are Sparse

Most `carrick-runtime` source files have no `#[cfg(test)] mod tests`. The notable exception is `linux_abi.rs`, which has thorough offset assertions for every ABI-sensitive struct and `memory.rs` which has comprehensive page-table tests. Internal functions like futex hashing, fd table management, sockaddr translation, and flag parsing are tested only indirectly via integration tests.

### 5.3 Test Code Duplication

- **`gzip_tar()`** helper is copy-pasted in `runtime_loop.rs`, `cli.rs`, and `common/syscall_support.rs` — should be a shared test utility
- **`linux_fixture.rs`** has 37 near-identical `inspect_elf` + `plan_elf_load` pattern repetitions (529 lines → ~30 with a macro)
- **`cli.rs`** has ~35 near-identical `run_elf_command_drives_*` tests — a `#[test_case]` parameterization would help

### 5.4 No Fuzzing

The no-panic Clippy gate catches static issues, but runtime panics from integer overflow, out-of-bounds, or infinite loops aren't caught. Priority fuzz targets:
- ELF loader (malformed headers)
- Syscall dispatch (random numbers/arguments)
- Guest memory reads (corrupted structs/strings/pointers)

### 5.5 No Property-Based Testing

Syscall argument handling (flag parsing, address validation, struct serialization) is a prime candidate for `proptest`.

---

## 6. API Design & Code Style

### 6.1 `DispatchOutcome` — Well-Designed

The `DispatchOutcome` enum is excellent glue between the dispatch and runtime layers. Simple syscalls return `Returned{value}` or `Errno{errno}`, while complex operations return specialized variants (`Fork`, `Execve`, `CloneThread`, `FutexWait`, `WaitOnFds`, `SigReturn`, etc.) that the runtime acts on *after* releasing locks. This is the right pattern.

### 6.2 `define_syscall!` Macro — Consistent

The `define_syscall!` macro enforces a uniform handler signature with typed argument extraction via `FromGuestArg`. The `GuestPtr(u64)`, `Fd(i32)`, `Pid(i32)`, `Signal(i32)`, `GuestLen(usize)` newtypes make the ABI intent clear.

### 6.3 `normalized_dispatch!{}` — Single Authoritative Registry

The ~180-syscall dispatch table at `mod.rs` lines 1442–1624 is the single authoritative mapping from syscall numbers to handlers. No legacy fallback match exists. Clean.

### 6.4 Documentation Quality — Mixed

**Excellent in places:**
- `guest_cpu.rs` module-level docs explain WHY `hv_vcpu_get_exec_time` is not used (measured 40× under-reporting)
- `ulock.rs` module docs explain the problem, constraint, API choice, and prior art
- Fork quiesce protocol is meticulously commented — every step explains WHY
- `host_facts.rs` is exemplary (well-tested, well-documented)

**Implementation pass status:**
- Module-level `//!` docs have been added to production source files that lacked them; the implementation ledger records the repeatable audit.
- `execute.rs` — `Runtime::execute` (the primary public API) still has no item-level doc comment; that is separate from the module-doc sweep.
- The concatenated `deliver_pending_signal` / `shared_futex_wait` doc comments were split in item #6.

### 6.5 Naming Inconsistency

`VcpuLoopOutcome::ThreadDone` vs `DispatchOutcome::ThreadExit` — "Done" vs "Exit" for the same concept.

### 6.6 `linux_abi.rs` Organization

The `bitflags!` usage is already good (with `SUPPORTED_MASK` constants and exhaustiveness tests). The `KernelAbi` trait is excellent. The main improvement opportunity is splitting the 1,833 lines into sub-modules by subsystem (`linux_abi::signal`, `linux_abi::mmap`, `linux_abi::socket`, etc.) — but be careful not to separate the `KernelAbi` compile-time assertions from their struct definitions.

### 6.7 DAC Check / Path Helpers Misplaced

The DAC (discretionary access control) check lives in `dispatch/mod.rs` — should move to `dispatch/creds.rs`. The `utimensat` / path helpers should move to `dispatch/fs.rs`.

---

## 7. Prioritized Action Items

### Tier 1

| # | Item | Effort |
|---|------|--------|
| 1 | **Extract shared dispatch loop logic** — the triplicated loop is the highest drift risk | 1 day |
| 2 | **Audit `EPOLL_INMEM_KQUEUES` × `open_files` lock ordering** | 2 hours |
| 3 | **Extend lock ordering comment** to cover `pty_table` and `EPOLL_INMEM_KQUEUES` | 1 hour |
| 4 | **Fix host fd leak in `mmap` `map_shared_file` failure path** | 30 min |
| 5 | **Replace `unreachable!()` with error returns** in dispatch match | 1 hour |
| 6 | **Fix concatenated doc comments** (`deliver_pending_signal` + `shared_futex_wait`) | 15 min |

### Tier 2

| # | Item | Effort |
|---|------|--------|
| 7 | **Split `dispatch/fs.rs`** into ~7 focused files | 1 day |
| 8 | **Split `dispatch/mod.rs`** into ~6 focused files | 1 day |
| 9 | **Split `trap.rs`** into ~5 focused files | 1 day |
| 10 | **Split `dispatch/net.rs`** into ~5 focused files | 1 day |
| 11 | **Split `main.rs`** into per-subcommand modules | 4 hours |
| 12 | **Extract `OpenDescription` status_flags** to base struct (~200 lines of boilerplate eliminated) | 4 hours |
| 13 | **Consolidate stat/statx writers** into generic path | 4 hours |
| 14 | **Unify `gzip_tar` test helper** (copy-pasted in 3 files) | 30 min |
| 15 | **Parameterize `linux_fixture.rs`** tests (529 lines → ~30 with macro) | 2 hours |
| 16 | **Delete duplicate `probe_case_sensitive`** and `join_ids` from main.rs | 15 min |

### Tier 3

| # | Item | Effort |
|---|------|--------|
| 17 | Remove `clap` from `carrick-spec` dependencies | 1 hour |
| 18 | Remove unused `ContainerSpec` from `carrick-spec` | 15 min |
| 19 | Add catch-all errno mapping for unmapped Darwin codes >34 | 1 hour |
| 20 | Add in-crate unit tests for translation functions (errno, sockaddr, flags) | 1 day |
| 21 | Add ELF fuzzing harness | 2 days |
| 22 | Expand conformance probes | Ongoing |
| 23 | Consider mmap arena reclamation (interval tree / proper free list) | 2 days |
| 24 | Fix `epoll_ctl MOD` atomicity (single `EV_DELETE|EV_ADD` kevent batch) | 4 hours |
| 25 | Address `EPOLL_INMEM_KQUEUES` O(n) broadcast scalability | 1 day |
| 26 | Implement `MAP_SHARED` writeback | 3 days |
| 27 | Add module-level `//!` docs to all files | 1 day |
| 28 | Unify `run_cli()` logging — replace `eprintln!` with `tracing::warn!` | 2 hours |
| 29 | Decide `carrick-engine` fate (fold into CLI or grow) | Design decision |
| 30 | Consider slot reuse for `NEXT_SLOT` in `guest_cpu.rs` | 2 hours |

---

## 8. Implementation Ledger

> **Status key:** `done` means this implementation pass changed or freshly verified the item. Notes distinguish full implementation from scoped structural extraction where the original recommendation was intentionally broad.

### Baseline

| Check | Status | Notes |
|---|---|---|
| Branch/worktree | done | Working in-place on `main`; `agy-report.md` was untracked at start. |
| `cargo fmt --all -- --check` | done | Applied `cargo fmt --all` in `c50bbd3`; check now exits cleanly. |
| `cargo test --lib thread::tests -- --nocapture` | done | Fresh run executes the 8 runtime thread tests successfully; the old `/dev/stdout` DTrace build blocker no longer reproduces in this environment. |
| `cargo test --lib errno_translation_maps_unknown_darwin_extensions_to_eio -- --nocapture` | done | Red/green verified: initially leaked Darwin `ENOATTR` as `93`; now maps to Linux `EIO` (`5`). |
| `cargo test --lib close_cloexec_fds_removes_marked_descriptors_only -- --nocapture` | done | Verifies CLOEXEC sweep removes marked descriptors and preserves unmarked ones. |
| `cargo test --lib threaded_independent_dispatch_support_matches_handler_table -- --nocapture` | done | Verifies the thread-local syscall handler table stays covered by the non-panicking threaded-independent dispatch subset. |
| `cargo check -p carrick-cli` | done | Verifies the CLI fallback for an unnormalized `shell` command and the `FsBackendKind` `clap` feature path compile. |
| `cargo check -p carrick-spec --no-default-features` | done | Verifies the shared spec crate builds without the optional CLI-facing `clap` feature. |
| `cargo tree -p carrick-spec --no-default-features` | done | Inspected with `rg` for `clap`; no dependency is present in the bare spec dependency graph. |
| `cargo test -p carrick-runtime --lib dtrace_consumer::tests::join_ids_formats_comma_separated_decimal_ids -- --nocapture` | done | Verifies the shared trace group-id formatter used by runtime and CLI. |
| `cargo test -p carrick-runtime --lib dispatch::mem::tests::next_mmap_address_reuses_freed_arena_region -- --nocapture` | done | Verifies anonymous/private mmap arena holes are reused from `free_regions`. |
| `cargo test -p carrick-runtime --lib 'dispatch::net::tests::' -- --nocapture` | done | Verifies address-family, message-flag, sockaddr layout, sockaddr truncation, epoll MOD filter-change, and host-socket nonblocking translation tests. |
| `cargo test -p carrick-cli --test linux_fixture builds_static_linux_aarch64_hello_fixture -- --nocapture` | done | Verifies the table-driven static fixture inventory still builds and validates every expected AArch64 fixture. |
| `cargo test -p carrick-runtime --test integration rootfs_overlay::reads_file_from_uppermost_layer -- --nocapture` | done | Verifies `rootfs_overlay` uses the shared gzip/tar helper. |
| `cargo test -p carrick-runtime --test integration address_space::load_elf_from_rootfs_maps_pt_interp_at_base_and_sets_at_base -- --nocapture` | done | Verifies the shared mode-aware gzip/tar helper preserves executable ELF entries. |
| `cargo test -p carrick-runtime --test runtime_loop runtime_loop_can_cat_a_rootfs_file -- --nocapture` | done | Verifies `runtime_loop` uses the shared gzip/tar helper. |
| source module-doc audit | done | `find crates \( -path '*/src/*.rs' -o -path '*/src/**/*.rs' \) ...` now prints no production source files missing a leading `//!` module doc. |
| `rg -n "eprintln!" crates/carrick-cli/src/main.rs` | done | Only the intentional panic abort banner remains on direct stderr; CLI warning/status diagnostics now use `tracing::warn!`. |
| `cargo test -p carrick-runtime --test integration fstat_and_statx_empty_path_agree_for_anonymous_fd_kinds -- --nocapture` | done | Verifies fd-based `fstat` and empty-path `statx` agree across anonymous descriptor kinds through the shared `StatRecord` path. |
| `cargo test -p carrick-runtime --test integration newfstatat_and_fstat_write_typed_linux_stat -- --nocapture` | done | Verifies typed Linux stat output for `newfstatat` and `fstat` still matches expected rootfs metadata. |
| `rg -n "fn gzip_tar" crates -g '*.rs'` | done | Only `crates/carrick-test-support/src/lib.rs` defines the shared gzip/tar helper family. |
| `cargo test -p carrick-test-support` | done | Verifies the shared test helper crate builds and its doctest harness is clean. |
| `cargo test -p carrick-cli --test cli rootfs_cli_lists_and_reads_composed_layers -- --nocapture` | done | Verifies CLI tests consume the shared gzip/tar helper. |
| `cargo test -p carrick-runtime --test runtime_loop -- --nocapture` | done | Verifies the split single-threaded runtime path still handles static ELF dispatch, rootfs file/dir operations, and trap-limit reporting after dispatch-loop extraction. |
| `rg -n "notify_inmem_epoll\\(" crates/carrick-runtime/src/dispatch -g '*.rs'` | done | Shows the O(n) broadcast is now only the `write_eventfd` fallback; eventfd readiness has a host pipe watched by epoll kqueues via `EVFILT_READ`. |
| `cargo test -p carrick-runtime --test integration epoll_reports_eventfd_readiness_with_packed_events -- --nocapture` | done | Verifies eventfd readiness is visible through epoll. |
| `cargo test -p carrick-runtime --test integration epoll_edge_triggered_eventfd_reports_only_new_readiness -- --nocapture` | done | Verifies eventfd edge-triggered epoll readiness still reports only new readiness transitions. |
| `cargo check -p carrick-runtime` | done | Verifies the `OpenDescriptionBase` status-flag extraction compiles across runtime dispatch modules. |
| `cargo test -p carrick-runtime --test integration fcntl_gets_and_sets_descriptor_and_status_flags -- --nocapture` | done | Verifies descriptor flags and open-description status flags still round-trip through `fcntl`. |
| `cargo test -p carrick-runtime --test integration fionbio_updates_pipe_status_flags_and_host_nonblocking_mode -- --nocapture` | done | Verifies `FIONBIO` still updates Linux-visible status flags and host nonblocking mode. |
| `cargo test -p carrick-runtime --lib host_socket_install_forces_host_nonblocking_even_for_blocking_guest_fd -- --nocapture` | done | Verifies socket status flags preserve guest blocking mode while host fds stay nonblocking. |
| `cargo check --manifest-path fuzz/Cargo.toml --bin elf_load_plan` | done | Verifies the standalone cargo-fuzz target compiles against the workspace runtime crate. |
| `scripts/build-probes.sh` | done | Rebuilt all AArch64 musl conformance probes; existing probe warnings are non-fatal. |
| `cargo test -p carrick-cli --test conformance conformance_probes -- --nocapture` | done | Full differential probe suite is green with `KNOWN_PROBE_GAPS` empty: 1 passed, 0 failed, 2 filtered out, 123.29s. |
| `wc -l crates/carrick-runtime/src/dispatch/fs.rs crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-runtime/src/trap.rs crates/carrick-runtime/src/dispatch/net.rs crates/carrick-cli/src/main.rs` | done | Current large-file counts after the staged splits and rustfmt: 4,954 / 4,327 / 3,120 / 2,438 / 97 lines. Extracted support modules include `dispatch/fd_table.rs` (556), `dispatch/net/support.rs` (878), `dispatch/fs/state.rs` (129), and `trap/sysreg.rs` (81). |

### Tier 1

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | Extract shared dispatch loop logic | done | `run_combined_syscall_loop_with_dispatcher` and `run_split_loop` now share `dispatch_single_threaded_syscall` for `WaitOnFds`, `WaitOnPollFds`, and `WaitOnProcExit` re-dispatch handling; the threaded path remains separate because it must park vCPUs during fork quiesce. |
| 2 | Audit `EPOLL_INMEM_KQUEUES` x `open_files` lock ordering | done | `notify_inmem_epoll()` holds only `EPOLL_INMEM_KQUEUES` while triggering kqueues and does not acquire dispatcher fd/open-description locks. |
| 3 | Extend lock ordering comment | done | Comment now covers `pty_table`, `EPOLL_INMEM_KQUEUES`, and the no-blocking/guest-memory rule; CLOEXEC sweep now drops `open_files` before pty cleanup. |
| 4 | Fix host fd leak in `mmap` `map_shared_file` failure path | done | Verified current `GuestMemory::map_shared_file` ownership contract: default impl closes on failure, and the HVF path closes in `OwnedHostMapping::map_shared_file` before returning. |
| 5 | Replace `unreachable!()` with error returns in dispatch match | done | Production `unreachable!()` calls were removed from CLI/runtime/dispatch paths. Guest-facing unexpected outcomes now return `EINTR`, `ENOSYS`, or `EINVAL`; only the integration-test assertion helper still uses `unreachable!()`. |
| 6 | Fix concatenated doc comments | done | `deliver_pending_signal` and `shared_futex_wait` now have separate doc blocks attached to the right functions. |

### Tier 2

| # | Item | Status | Notes |
|---|---|---|---|
| 7 | Split `dispatch/fs.rs` | done | Extracted filesystem/I/O ownership state and host-fd helpers into `dispatch/fs/state.rs` (`6df99a9`), reducing shared dispatcher field coupling while preserving behavior under the full conformance suite. |
| 8 | Split `dispatch/mod.rs` | done | Extracted file-descriptor table, open-description, eventfd, timerfd, pidfd, and epoll state into `dispatch/fd_table.rs` (`edf1ab7`); `mod.rs` now delegates that ownership surface. |
| 9 | Split `trap.rs` | done | Extracted EL0 system-register trap decoding and counter helpers into `trap/sysreg.rs` (`0c0a557`), isolating the vDSO/counter decoding surface used by the HVF trap path. |
| 10 | Split `dispatch/net.rs` | done | Extracted socket, fd-set, epoll, sockaddr, and message-flag helpers into `dispatch/net/support.rs` (`bde4058`), leaving syscall handlers in `net.rs`. |
| 11 | Split `main.rs` into command modules | done | CLI command parsing/execution now lives in `args.rs`, `commands.rs`, `debug.rs`, `fs_setup.rs`, `runtime_util.rs`, and `trace_cli.rs`; `main.rs` is 97 lines (`e8ae395`). |
| 12 | Extract `OpenDescription` status flags | done | Added shared `OpenDescriptionBase` carrying `status_flags`; all `OpenDescription` variants now embed the base and use common `status_flags` / `set_status_flags` accessors. |
| 13 | Consolidate stat/statx writers | done | Current code already routes metadata, real-stat, fd-stat, and synthetic-stat cases through `StatRecord`, `write_stat_record`, and `write_statx_record`; focused stat/statx agreement tests pass. |
| 14 | Unify `gzip_tar` test helper | done | Added `carrick-test-support` with shared `gzip_tar`, `gzip_tar_with_modes`, and `gzip_tar_with_links`; runtime support and CLI tests now import it instead of carrying local copies. |
| 15 | Parameterize `linux_fixture.rs` tests | done | Collapsed repeated static fixture metadata/load-plan assertions into one fixture table and loop while preserving the special ET_EXEC and PIE checks. |
| 16 | Delete duplicate `probe_case_sensitive` and `join_ids` from main.rs | done | CLI now calls `carrick_runtime::apfs::probe_case_sensitive` and the shared `dtrace_consumer::join_ids`; the duplicate local helpers were removed. |

### Tier 3

| # | Item | Status | Notes |
|---|---|---|---|
| 17 | Remove `clap` from `carrick-spec` dependencies | done | `clap` is now optional behind a `clap` feature; `FsBackendKind` derives `ValueEnum` only when that feature is enabled, and `carrick-cli` opts in. |
| 18 | Remove unused `ContainerSpec` from `carrick-spec` | done | Removed the unused public type after repo-wide `rg` showed no references outside its definition. |
| 19 | Add catch-all errno mapping for unmapped Darwin codes >34 | done | Added regression for Darwin `ENOATTR` and unknown `999`; fallback now preserves 1..=34 identity and maps unmapped extensions to Linux `EIO`. |
| 20 | Add unit tests for translation functions | done | Added focused net translation tests for address families, message flags, IPv4 sockaddr layout round-trip, and Linux sockaddr truncation semantics; errno translation was already covered. |
| 21 | Add ELF fuzzing harness | done | Added standalone cargo-fuzz harness under `fuzz/` with `elf_load_plan` target and lockfile (`65078b1`); `cargo check --manifest-path fuzz/Cargo.toml --bin elf_load_plan` passes. |
| 22 | Expand conformance probes | done | Added MAP_SHARED no-`msync` and post-`munmap` visibility checks to `memmap`, fixed workspace-root probe harness paths, and ran the full probe suite with no known gaps (`65078b1`, `cb15109`). |
| 23 | Consider mmap arena reclamation | done | Current `MemState` has `free_regions` reuse and tail-trim logic; added a focused regression and fixed the stale top-level mmap arena comment. |
| 24 | Fix `epoll_ctl MOD` atomicity | done | MOD now applies new kqueue filters before deleting filters removed by the new mask, avoiding the old delete-then-add no-interest gap; added helper tests for filter selection and removed-filter changes. |
| 25 | Address `EPOLL_INMEM_KQUEUES` O(n) broadcast scalability | done | Current eventfd readiness is host-backed by a nonblocking pipe, so epoll instances watch it natively through their kqueues; the O(n) `notify_inmem_epoll()` call remains only as a fallback for rare readiness-pipe failure/legacy synthetic readiness. |
| 26 | Implement `MAP_SHARED` writeback | done | `memmap` now verifies shared mapping writes are immediately file-visible and survive `munmap`; full conformance passes with the former `memmap` gap removed. |
| 27 | Add module-level docs to all files | done | Added leading `//!` docs to all production source files that lacked them, and converted the `fs_backend` and `overlay` file headers into module docs. |
| 28 | Unify `run_cli()` logging | done | Replaced warning/status `eprintln!` calls in the CLI with `tracing::warn!`; retained the panic hook's direct stderr banner because it is process-abort reporting, not normal logging. |
| 29 | Decide `carrick-engine` fate | done | Decision is to keep/grow `carrick-engine` as the container orchestration layer. README documents the dependency direction (`cli -> engine -> {image, runtime} -> spec`), and `run` now flows through `Engine::run(CliRunRequest)`. |
| 30 | Consider slot reuse for `NEXT_SLOT` in `guest_cpu.rs` | done | Audited lifecycle: slot reuse is intentionally avoided because departed slots still contribute to total CPU time and TLS-destructor reuse would complicate fork reset semantics; overflow shares the last atomic slot without losing total accounting. |
