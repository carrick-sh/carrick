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

### 4.11 MAP_SHARED Writeback Not Implemented

File-backed `MAP_SHARED` mmap reads the file at mmap time but doesn't write changes back. Programs using mmap for IPC or file modification will lose writes silently.

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
- **`KNOWN_PROBE_GAPS`** tracks expected failures; if a known-gap probe unexpectedly PASSES, the test FAILS loudly (signal to remove from the list)
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

**Needs improvement:**
- `lib.rs` has no `//!` module doc comment (this is the crate root)
- `execute.rs` — `Runtime::execute` (the primary public API) has no doc comment
- Some doc comments are concatenated between adjacent functions (e.g., `deliver_pending_signal` and `shared_futex_wait` docs are jammed together)

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

> **Status key:** `open` means the report item still needs implementation or validation. `stale` means current `main` already appears to address it, pending final verification. `done` means this implementation pass changed or verified the item. `deferred` means the item is too large or design-shaped for a safe mechanical fix and needs its own plan or explicit product decision.

### Baseline

| Check | Status | Notes |
|---|---|---|
| Branch/worktree | done | Working in-place on `main`; `agy-report.md` was untracked at start. |
| `cargo fmt --all -- --check` | open | Fails before this implementation pass; rustfmt drift spans CLI/image/engine/runtime files. |
| `cargo test --lib thread::tests` | blocked | Sandboxed run failed in the USDT/DTrace build step (`dtrace: failed to open header file '/dev/stdout'`), before tests executed. Direct non-sandbox cargo commands now build. |
| `cargo test --lib errno_translation_maps_unknown_darwin_extensions_to_eio -- --nocapture` | done | Red/green verified: initially leaked Darwin `ENOATTR` as `93`; now maps to Linux `EIO` (`5`). |
| `cargo test --lib close_cloexec_fds_removes_marked_descriptors_only -- --nocapture` | done | Verifies CLOEXEC sweep removes marked descriptors and preserves unmarked ones. |
| `cargo test --lib threaded_independent_dispatch_support_matches_handler_table -- --nocapture` | done | Verifies the thread-local syscall handler table stays covered by the non-panicking threaded-independent dispatch subset. |
| `cargo check -p carrick-cli` | done | Verifies the CLI fallback for an unnormalized `shell` command and the `FsBackendKind` `clap` feature path compile. |
| `cargo check -p carrick-spec --no-default-features` | done | Verifies the shared spec crate builds without the optional CLI-facing `clap` feature. |
| `cargo tree -p carrick-spec --no-default-features` | done | Inspected with `rg` for `clap`; no dependency is present in the bare spec dependency graph. |
| `cargo test -p carrick-runtime --lib dtrace_consumer::tests::join_ids_formats_comma_separated_decimal_ids -- --nocapture` | done | Verifies the shared trace group-id formatter used by runtime and CLI. |
| `cargo test -p carrick-runtime --lib dispatch::mem::tests::next_mmap_address_reuses_freed_arena_region -- --nocapture` | done | Verifies anonymous/private mmap arena holes are reused from `free_regions`. |

### Tier 1

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | Extract shared dispatch loop logic | open | Validate current runtime drift first; requires tests around each loop. |
| 2 | Audit `EPOLL_INMEM_KQUEUES` x `open_files` lock ordering | done | `notify_inmem_epoll()` holds only `EPOLL_INMEM_KQUEUES` while triggering kqueues and does not acquire dispatcher fd/open-description locks. |
| 3 | Extend lock ordering comment | done | Comment now covers `pty_table`, `EPOLL_INMEM_KQUEUES`, and the no-blocking/guest-memory rule; CLOEXEC sweep now drops `open_files` before pty cleanup. |
| 4 | Fix host fd leak in `mmap` `map_shared_file` failure path | stale | Current `GuestMemory::map_shared_file` contract transfers fd ownership even on failure; default impl closes it, and HVF path closes in `OwnedHostMapping::map_shared_file` before returning. |
| 5 | Replace `unreachable!()` with error returns in dispatch match | done | Production `unreachable!()` calls were removed from CLI/runtime/dispatch paths. Guest-facing unexpected outcomes now return `EINTR`, `ENOSYS`, or `EINVAL`; only the integration-test assertion helper still uses `unreachable!()`. |
| 6 | Fix concatenated doc comments | done | `deliver_pending_signal` and `shared_futex_wait` now have separate doc blocks attached to the right functions. |

### Tier 2

| # | Item | Status | Notes |
|---|---|---|---|
| 7 | Split `dispatch/fs.rs` | open | Structural refactor; do after Tier 1 behavior is protected. |
| 8 | Split `dispatch/mod.rs` | open | Structural refactor; current file already contains some extracted modules. |
| 9 | Split `trap.rs` | open | Structural refactor; avoid until runtime loop work is stable. |
| 10 | Split `dispatch/net.rs` | open | Structural refactor. |
| 11 | Split `main.rs` into command modules | open | Structural refactor. |
| 12 | Extract `OpenDescription` status flags | open | Behavior-preserving refactor with high call-site count. |
| 13 | Consolidate stat/statx writers | open | Behavior-preserving refactor. |
| 14 | Unify `gzip_tar` test helper | open | Copy-paste still exists in CLI/runtime tests. |
| 15 | Parameterize `linux_fixture.rs` tests | open | Test refactor. |
| 16 | Delete duplicate `probe_case_sensitive` and `join_ids` from main.rs | done | CLI now calls `carrick_runtime::apfs::probe_case_sensitive` and the shared `dtrace_consumer::join_ids`; the duplicate local helpers were removed. |

### Tier 3

| # | Item | Status | Notes |
|---|---|---|---|
| 17 | Remove `clap` from `carrick-spec` dependencies | done | `clap` is now optional behind a `clap` feature; `FsBackendKind` derives `ValueEnum` only when that feature is enabled, and `carrick-cli` opts in. |
| 18 | Remove unused `ContainerSpec` from `carrick-spec` | done | Removed the unused public type after repo-wide `rg` showed no references outside its definition. |
| 19 | Add catch-all errno mapping for unmapped Darwin codes >34 | done | Added regression for Darwin `ENOATTR` and unknown `999`; fallback now preserves 1..=34 identity and maps unmapped extensions to Linux `EIO`. |
| 20 | Add unit tests for translation functions | open | Errno has tests; sockaddr/flags need inventory. |
| 21 | Add ELF fuzzing harness | deferred | Requires fuzzing toolchain choice and CI policy. |
| 22 | Expand conformance probes | deferred | Ongoing program, not one bounded patch. |
| 23 | Consider mmap arena reclamation | done | Current `MemState` has `free_regions` reuse and tail-trim logic; added a focused regression and fixed the stale top-level mmap arena comment. |
| 24 | Fix `epoll_ctl MOD` atomicity | open | Needs behavioral test or documented kqueue contract. |
| 25 | Address `EPOLL_INMEM_KQUEUES` O(n) broadcast scalability | open | Design-sized scalability change. |
| 26 | Implement `MAP_SHARED` writeback | deferred | Multi-day semantic feature; needs conformance spec. |
| 27 | Add module-level docs to all files | open | Documentation sweep. |
| 28 | Unify `run_cli()` logging | open | CLI behavior/logging cleanup. |
| 29 | Decide `carrick-engine` fate | deferred | Product/API decision; current implementation appears to be growing the engine. |
| 30 | Consider slot reuse for `NEXT_SLOT` in `guest_cpu.rs` | open | Needs current slot lifecycle audit. |
