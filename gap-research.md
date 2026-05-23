# Carrick Gap Research

Date: 2026-05-23
Repository: `/Volumes/CaseSensitive/carrick`
Scope: code-quality, Darwin/macOS leverage, Rust ecosystem leverage, safety, performance, correctness, and maintainability gaps.

This document consolidates the four research lanes run against the current checkout:

- Darwin/macOS leverage
- Rust ecosystem leverage
- Safety, correctness, and performance
- Legibility, complexity, and internal patterns

It is a research artifact only. It does not include implementation changes.

## Implementation Ledger

Status: in progress on branch `codex/address-gap-research`.

Baseline captured 2026-05-23:

- `cargo fmt --all -- --check`: fails on formatting drift listed in the original validation snapshot.
- `cargo clippy --all-targets`: fails because the intended test unwrap exemption is not honored for `tests/syscall_net.rs`.
- `cargo test --lib thread::tests`: passes, 8 tests.
- `cargo test --test concurrency_contracts`: passes, 16 tests.
- `cargo test --test syscall_net`: passes, 20 tests.

Work package progress:

- [x] Package 1. Fd Table and Host Fd Ownership
  - Added atomic single-fd and pair-fd install helpers and migrated fd-producing paths off allocate-then-insert.
  - Moved host fd close ownership onto cloned `OpenFile` handles and pinned blocking wait fds with duplicated host fds.
  - Verified with targeted fd allocation and wait-pin regression tests.
- [ ] Package 2. Signal Pump and Fork Discipline
  - Completed: split the async signal pump wake pipe from the blocking-I/O waiter self-pipe and made the pump drain only its dedicated pipe.
  - Verified that waiter-pipe drains cannot consume pump wake bytes.
  - Remaining: fork safety still needs a host-thread-aware coordinator and stress coverage.
- [ ] Package 3. Linux Blocking Object Semantics
  - Completed: `FIONBIO` now updates Linux-visible status flags and host nonblocking mode for host-backed fds.
  - Completed: blocking `eventfd` reads now wait and wake from writer updates while nonblocking reads still return `EAGAIN`.
  - Remaining: timerfd blocking reads must stop sleeping while holding the fd description lock.
- [ ] Package 4. ABI and Flag Types
- [ ] Package 5. Darwin Filesystem Leverage
- [ ] Package 6. VFS and Stat Ownership
- [ ] Hygiene gates and final verification sweep

## Executive Summary

Carrick is already exploiting some host value well: it uses HVF directly through `applevisor`/`applevisor-sys`, has a Darwin-specific kqueue wake path, carries a Linux errno translation layer, uses `cap-std` for host filesystem confinement, and has real test coverage around threaded dispatch, signals, ptys, networking, and guest fixtures.

The biggest remaining gaps are not that the project uses `libc`. The issue is that raw `libc` calls are often the only abstraction boundary. That makes Darwin-specific behavior harder to reason about, harder to test, and easier to accidentally flatten to the common subset of the `libc` crate. The highest-value direction is a small number of explicit host-facing modules that encode Darwin semantics: fd ownership and readiness, fork/signal discipline, APFS file operations, pty/session passthrough, mmap/HVF mapping ownership, and Linux ABI parsing.

The highest-risk correctness gaps are:

- Non-atomic fd allocation and installation under shared dispatch.
- Raw host fd lifetime not pinned across close/wait races.
- Guest `fork` allowed when the guest registry is single-threaded even though the host process has other Carrick threads alive.
- A shared signal self-pipe is consumed by both blocking waiters and the signal pump.
- Blocking eventfd semantics are incomplete.
- PROT_NONE tracking is per trap engine, not process-wide.

The highest-value macOS/Darwin opportunities are:

- Use fork discipline that accounts for host threads, not just guest vCPU count.
- Split the signal pump wake channel from parked I/O waiters, using kqueue `EVFILT_USER` or a dedicated pump pipe.
- Use real Darwin durability and APFS primitives where they matter: `fsync`, optional `F_FULLFSYNC`, `msync`, `clonefileat`/`fclonefileat`, and `copyfile`.
- Pass through real pty/session state for `TIOCGSID` rather than synthesizing bootstrap state for real ttys.

The highest-value Rust ecosystem opportunities are:

- Add direct `bitflags` types for Linux flag families.
- Extend existing `zerocopy` use to read-side ABI parsing.
- Move host socket/fd ownership toward `OwnedFd`/`BorrowedFd` plus `socket2::SockRef` where it clarifies ownership without outsourcing Linux ABI translation.
- Consider `rustix` for safe fd and mmap helpers, but keep Carrick's Linux-to-Darwin semantic translation explicit.
- Add `proptest` for ABI/path/flag normalization and possibly `loom` only after isolating OS-free concurrency primitives.

## Validation Snapshot

Commands already run during this review:

- `cargo deny check licenses`: passed.
- `cargo test --lib thread::tests`: passed, 8 tests.
- `cargo test --test concurrency_contracts`: passed, 16 tests.
- `cargo test --test syscall_thread`: passed, 12 tests.
- `cargo test --test syscall_net`: passed, 20 tests.
- `cargo test --test conformance -- --nocapture`: passed, 3 tests.

Current hygiene gaps observed:

- `cargo fmt --all -- --check` fails on formatting drift in `src/dispatch/mod.rs`, `src/lib.rs`, `src/runtime.rs`, `src/vcpu_kick.rs`, `src/vfs/proc.rs`, and `tests/syscall_net.rs`.
- `cargo clippy --all-targets` fails. The important issue is not only style warnings: it reports multiple `clippy::unwrap_used` failures in `tests/syscall_net.rs`.
- The clippy result contradicts the project expectation in `README.md:90-96` and `clippy.toml:1`, where tests are intended to be exempt from unwrap/expect/panic bans.

## External Reference Map

Primary references used for cross-checking:

- Apple kqueue manual: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html
- Apple fcntl manual, including `F_FULLFSYNC`: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html
- Darwin clonefile manual: https://keith.github.io/xcode-man-pages/clonefile.2.html
- Apple Hypervisor framework: https://developer.apple.com/documentation/hypervisor
- POSIX `fork`: https://pubs.opengroup.org/onlinepubs/9799919799/functions/fork.html
- POSIX `pthread_atfork`: https://pubs.opengroup.org/onlinepubs/9799919799/functions/pthread_atfork.html
- Linux `eventfd`: https://man7.org/linux/man-pages/man2/eventfd.2.html
- Linux `futex`: https://man7.org/linux/man-pages/man2/futex.2.html
- Linux `FUTEX_REQUEUE`: https://man7.org/linux/man-pages/man2/FUTEX_CMP_REQUEUE.2const.html
- Linux `/proc/<pid>/stat`: https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
- Rust `bitflags`: https://docs.rs/bitflags/latest/bitflags/
- Rust `zerocopy`: https://docs.rs/zerocopy/latest/zerocopy/
- Rust `socket2`: https://docs.rs/socket2/latest/socket2/
- Rust `socket2::SockRef`: https://docs.rs/socket2/latest/socket2/struct.SockRef.html
- Rust `rustix`: https://docs.rs/rustix/latest/rustix/
- Rust `cap-std`: https://docs.rs/cap-std/latest/cap_std/
- Rust `proptest`: https://docs.rs/proptest/latest/proptest/
- Rust `loom`: https://docs.rs/loom/latest/loom/
- Apple XNU source reference for private-ish Darwin primitives such as `__ulock`: https://github.com/apple-oss-distributions/xnu

## Gap Register

### D1. Fork safety is gated on guest vCPU count, not host thread reality

Severity: P1 correctness and safety.

The runtime rejects `fork` when more than one guest vCPU is live, but the host process is still multithreaded even in the single guest vCPU case. The signal pump is spawned before the vCPU loop at `src/runtime.rs:736`. Later, `DispatchOutcome::Fork` only checks `registry.live_count() > 1` at `src/runtime.rs:1103`. The fork path then calls `libc::fork()` in `src/trap.rs:1583`, re-registers DTrace probes in the child at `src/trap.rs:1596`, and rebuilds HVF state at `src/trap.rs:1608-1612`.

The POSIX fork rules are stricter than the current gate implies: after a multithreaded process forks, only the calling thread exists in the child, and operations involving inherited locks/resources can be undefined until exec unless disciplined. Carrick's child path does substantial Rust and HVF work after fork.

Recommendation:

- Treat the signal pump and any other Carrick host thread as part of the fork safety model.
- Introduce a Darwin fork coordinator around known global state: signal self-pipe, pump kqueue, fd table locks, output buffers, DTrace probe state, and HVF teardown/rebuild.
- Consider `pthread_atfork` only for narrow state repair. Do not rely on it as the sole solution; Carrick still needs an explicit "forkable host state" invariant.
- Add a stress test that forks while the signal pump is alive and while a host-side blocking waiter exists.

Validation target:

- A guest workload repeatedly forks while host interval timers/signals are active.
- The child can rebuild HVF and exit or exec without deadlock.
- The parent still delivers pending process-directed signals after child creation.

### D2. Signal self-pipe is shared by the pump and blocking I/O waiters

Severity: P1 correctness and latency.

`host_signal` maintains one process-wide self-pipe: `PENDING_PIPE_READ` and `PENDING_PIPE_WRITE` at `src/host_signal.rs:171-177`. Host signal handlers write to it through `notify_pending()` at `src/host_signal.rs:348-354`. Every `ThreadWaiter` registers the same read fd at `src/io_wait.rs:54-60`, and drains it when woken at `src/io_wait.rs:202-203`. The signal pump also watches the same read fd at `src/vcpu_kick.rs:160` and registers it with kqueue at `src/vcpu_kick.rs:186-205`.

This creates a race in the wake design: a parked blocking-I/O waiter can drain the self-pipe before the pump observes it. If the relevant guest vCPU is spinning in `hv_vcpu_run`, the wake that should cause `hv_vcpus_exit` can be consumed by a different path.

The code already recognizes this issue partially by adding `EVFILT_USER` and `notify_pump()` for process signals from normal thread context (`src/host_signal.rs:191-213`, `src/host_signal.rs:389-392`). That does not cover async host signal handler writes, because `kevent` is not async-signal-safe.

Recommendation:

- Give the signal pump its own async-signal-safe wake pipe, separate from waiter interruption.
- Keep `EVFILT_USER` for normal-thread wake sources such as interval timer threads.
- Add a monotonic pending generation counter so drain order cannot lose the obligation to kick vCPUs.
- Test with one guest vCPU busy in userspace, one sibling parked in `ppoll`, and repeated process-directed host signals.

Validation target:

- A process-directed signal always causes `kicker.kick_all()` regardless of which waiter drains the I/O self-pipe.

### D3. `FIONBIO` succeeds but does not change fd behavior

Severity: P2 correctness and compatibility.

The `ioctl(FIONBIO)` path validates the pointer and then returns success without persisting nonblocking state at `src/dispatch/fs.rs:1229-1237`. By contrast, `fcntl(F_SETFL)` is already treated as the durable path for status flags, and the surrounding fd code reads those flags for nonblocking behavior.

On Linux, `FIONBIO` is a common compatibility path for sockets and some language runtimes. Returning success while leaving behavior unchanged is a compatibility trap.

Recommendation:

- Route `FIONBIO` through the same status-flag update helper as `fcntl(F_SETFL)` for Carrick-owned fd descriptions.
- For real host sockets/pipes/files, update Carrick's Linux-visible status flags and decide explicitly whether to also call Darwin `ioctl(FIONBIO)` or `fcntl(O_NONBLOCK)` on the host fd.
- Add socket and pipe tests that set nonblocking through `FIONBIO`, then verify read/recv/write readiness behavior.

Validation target:

- `FIONBIO(1)` followed by a would-block operation returns Linux `EAGAIN`.
- `FIONBIO(0)` restores blocking semantics where Carrick can model them.

### D4. `sync`, `syncfs`, and `fsync` are successful no-ops

Severity: P2 correctness and durability.

`sync` returns success without flushing at `src/dispatch/fs.rs:3400-3405`. `syncfs` validates the fd and returns success at `src/dispatch/fs.rs:3407-3417`. `fsync` validates the fd and returns success at `src/dispatch/fs.rs:3672-3680`. At the same time, Carrick can expose real shared file mappings through `MAP_SHARED` in `src/trap.rs:944-999`.

For memory-backed ephemeral files this may be acceptable. For host-backed files and shared mappings, the current behavior loses the durability semantics callers reasonably expect. On macOS, `fsync` and `fcntl(F_FULLFSYNC)` have different durability strength; `F_FULLFSYNC` is the Darwin-specific lever.

Recommendation:

- For `HostFile`, call host `fsync`.
- For strict durability mode, optionally call `fcntl(F_FULLFSYNC)` after `fsync` on Darwin.
- For shared mapped host files, consider `msync(MS_SYNC)` on the mapped region before `fsync`.
- Keep memory backend no-op behavior explicit and documented.

Validation target:

- A host-backed file touched by a guest `fsync` results in a real host `fsync` call.
- Strict mode can be observed calling `F_FULLFSYNC` on macOS.

### D5. APFS clone/copy primitives are promised but underused

Severity: P2 performance and Darwin leverage.

`src/fs_backend.rs:13-16` describes `HostFsBackend` as an APFS scratch directory that is "reflink-seeded" through `clonefile`. Current seeding goes through `HostFsBackend::seed_from_rootfs` at `src/fs_backend.rs:624-635`, which calls `RootFs::extract_to_disk`. That path writes file contents with `std::fs::write` at `src/rootfs.rs:319-325`.

`copy_file_range` also uses a bounded read-then-write path, capped at 8 MiB, in `src/dispatch/fs.rs:2998-3078`. That is a practical generic path, but it misses APFS copy-on-write when source and destination are host files on the same volume.

Recommendation:

- Align docs and implementation: either remove the clonefile claim or add a real APFS fast path.
- For host-to-host regular file copies, try `clonefileat`/`fclonefileat` or `copyfile` first, then fall back to the existing bounded copy path on unsupported filesystems, cross-device copies, pipes, sparse edge cases, and non-host-backed fds.
- Keep the generic copy path because it is still correct for pipes, synthetic files, and memory-backed rootfs.

Validation target:

- A host-backed `copy_file_range` fixture on APFS takes the clone/copyfile fast path.
- Cross-device or unsupported copies fall back without changing Linux-visible results.

### D6. Real pty/session state is only partially passed through

Severity: P2 correctness and interactive behavior.

The tty path already passes through foreground process group changes for real ttys (`src/dispatch/fs.rs:1188-1197`). But `TIOCGSID` on stdio still writes the synthetic `LINUX_BOOTSTRAP_SID` at `src/dispatch/fs.rs:1246-1249`.

That is good enough for bootstrap cases, but interactive job-control behavior is a Darwin value area: real ptys have real session/foreground state, and Carrick should use it where available.

Recommendation:

- For real pty-backed stdio, use Darwin `tcgetsid` or the host `TIOCGSID` equivalent where available.
- Keep the bootstrap synthetic fallback for non-tty and headless cases.
- Add an interactive fixture that compares guest-observed sid/pgid behavior with host pty state.

Validation target:

- `TIOCGSID` on `-t` pty-backed stdio returns the host-backed controlling-session value translated into Carrick's guest pid model.

### R1. Linux flags need typed internal representations

Severity: P2 legibility and correctness.

The project has many raw flag constants and masks, including support checks in `src/dispatch/mod.rs:2048-2060`, socket flag stripping in `src/dispatch/net.rs:1264-1271`, clone flags in the process path, mmap/prot flags, futex flags, and `AT_*` flags. `bitflags` is already present transitively in `Cargo.lock`, but it is not a direct dependency in `Cargo.toml`.

Raw constants are appropriate for Linux UAPI numbers. They are weaker for validation logic because supported/unsupported masks are scattered and hard to audit.

Recommendation:

- Add direct `bitflags` dependency.
- Introduce typed groups such as `OpenFlags`, `AtFlags`, `MmapFlags`, `FutexFlags`, `CloneFlags`, `SocketTypeFlags`, and `FdFlags`.
- Keep syscall numbers, errno numbers, and struct layouts as explicit Linux ABI constants.
- Add unknown-bit tests for each flag family.

Validation target:

- Every flag parser has tests for accepted masks, rejected masks, and Linux errno on unknown bits.

### R2. `zerocopy` is used for writes but not enough for reads

Severity: P2 safety and ABI clarity.

Carrick already has a strong write-side ABI pattern: `KernelAbi` in `src/linux_abi.rs:943-976` and `write_kernel_struct` in `src/dispatch/mod.rs:2372-2384`. Read-side parsing still uses manual byte offsets in newer paths. For example, `read_linux_msghdr` manually slices a 56-byte Linux `msghdr` at `src/dispatch/net.rs:3094-3117`, and `ppoll` manually decodes a timespec at `src/dispatch/net.rs:779-792`.

Manual parsing is not automatically wrong, but it increases the chance of layout drift and silent truncation mistakes.

Recommendation:

- Add read-side helpers parallel to `write_kernel_struct`, probably `read_kernel_struct<T>` and `read_kernel_prefix<T>`.
- Define `#[repr(C)]` zerocopy structs for `clone_args`, `msghdr`, `mmsghdr`, `timespec`, `pollfd`, and sockaddr variants where layout is stable.
- Use explicit ABI-size constants when Linux's user ABI size is smaller than Rust's in-memory struct.

Validation target:

- Truncation, null pointer, unaligned, and overlarge length tests exist for each read-side ABI struct.

### R3. Host socket and fd ownership should use Rust ownership types where they clarify lifetime

Severity: P2 safety and maintainability.

Host socket installation creates a raw fd through `libc::socket`, then manually closes it on allocation failure and stores an `i32` in `OpenDescription::HostSocket` (`src/dispatch/net.rs:1264-1308`). More broadly, `OpenDescription` stores raw host fds for `HostPipe`, `HostFile`, and `HostSocket` (`src/dispatch/mod.rs:751-857`), and `close_open_file` manually closes them based on `Arc::strong_count` (`src/dispatch/mod.rs:2449-2484`).

`socket2` is already present transitively. It can help with socket creation and `SockRef` operations, but it should not own Linux ABI translation. Carrick still needs explicit Linux-family, socktype, errno, and flag semantics.

Recommendation:

- Move host fd ownership to a small RAII wrapper or `OwnedFd` where possible.
- Use `BorrowedFd`/`SockRef` for host socket option calls and readiness operations.
- Keep Linux-to-Darwin address, flag, and errno translation in Carrick.
- Add tests for dup/close/wait races before refactoring.

Validation target:

- Closing one duplicated guest fd does not close the host fd while another alias exists.
- Closing the last alias closes the host fd exactly once.

### R4. Keep custom kqueue wait machinery, but constrain the unsafe surface

Severity: P2 performance and maintainability.

`ThreadWaiter` owns a per-thread kqueue (`src/io_wait.rs:33-63`) and dynamically registers guest fd readiness plus the signal pipe. The signal pump uses `EVFILT_USER` and `EVFILT_READ` directly in `src/vcpu_kick.rs:186-205`. This is a good Darwin-specific design; it should not be replaced wholesale with `mio` or a generic cross-platform reactor unless Carrick is changing its runtime model.

The gap is that raw kqueue structs and fd ownership are spread across modules.

Recommendation:

- Add tiny internal wrappers for kqueue fd ownership, `kevent` construction, `EVFILT_USER` trigger, and event draining.
- Use those wrappers in `io_wait`, `vcpu_kick`, and `host_signal`.
- Consider `rustix` only where it simplifies fd ownership and syscall wrappers without hiding Darwin semantics.

Validation target:

- Unit tests can construct and drop kqueue wrappers without leaking fds.
- Signal pump and waiter tests verify independent wake channels.

### R5. Raw mmap/HVF mapping ownership needs a narrow RAII abstraction

Severity: P2 safety and legibility.

Guest memory uses raw `libc::mmap`, `munmap`, `hv_vm_map`, and manual metadata. Examples include shared file mapping at `src/trap.rs:944-999`, shared anonymous mapping at `src/trap.rs:1003-1015`, fork snapshot cloning at `src/trap.rs:2193-2236`, and raw remapping at `src/trap.rs:2239-2250`.

Generic crates such as `memmap2` are not a drop-in because Carrick must coordinate mmap ownership with HVF stage-2 mappings and fork snapshot behavior. But the current raw surface is still too broad.

Recommendation:

- Introduce a narrow `OwnedHostMapping` or similar type that owns host pointer, length, sharing mode, and unmap behavior.
- Keep HVF map/unmap calls explicit at the trap-engine layer.
- Encode whether a mapping participates in fork snapshot, `MAP_SHARED`, guest shared anonymous memory, or raw remap.

Validation target:

- Drop and fork-rebuild tests demonstrate no double-unmap and no leak for failed `hv_vm_map`.

### R6. `cap-std` is present, but one seeding path bypasses the capability surface

Severity: P3 safety and consistency.

The tar extraction path has a `cap_std::fs::Dir`-based API at `src/rootfs.rs:108-126`. But `RootFs::extract_to_disk` is path-based (`src/rootfs.rs:309-334`), and `HostFsBackend::seed_from_rootfs` calls that path-based extractor at `src/fs_backend.rs:624-635`, even though the surrounding comments describe cap-std confinement.

This is probably not an immediate vulnerability because the scratch path is owned and generated by the process, but it is a pattern gap: the capability discipline is not uniform.

Recommendation:

- Either route host seeding through a `cap_std::fs::Dir` API or document why the path-based materializer is safe and limited to process-owned scratch dirs.
- Prefer one extraction surface so tar/path sanitization rules cannot drift.

Validation target:

- Path traversal, absolute path, symlink, and hardlink extraction tests exercise the same code path used by `HostFsBackend`.

### S1. Fd allocation and installation are not atomic

Severity: P1 correctness and concurrency.

`allocate_fd` scans `open_files` under a read lock, drops that lock, and returns an fd at `src/dispatch/fs.rs:2215-2232`. `insert_open_file` later takes a write lock and inserts at `src/dispatch/fs.rs:2235-2239`. Several callers allocate and insert as separate steps, including socket creation at `src/dispatch/net.rs:1287-1295`.

Under shared dispatch, two threads can observe the same free fd and both install into it. The later insert replaces the earlier one and calls close on the replaced `OpenFile`. That is a data-race-shaped semantic bug at the Linux fd table level, even if Rust's memory safety is preserved.

Recommendation:

- Replace allocate-then-insert with an atomic `install_fd(min_fd, open_file) -> Result<i32, Errno>` that holds the write lock across scan and insertion.
- Add pair allocation for `pipe2`, `socketpair`, and similar two-fd syscalls so the pair is reserved atomically.
- Keep `dup2`/`dup3` semantics explicit because they intentionally replace a chosen fd.

Validation target:

- A concurrency test repeatedly creates sockets/pipes from multiple guest threads and asserts no duplicate fd allocation or accidental close of an unrelated fd.

### S2. Host fd lifetime is not pinned across close/wait races

Severity: P1 correctness and safety.

`open_file()` returns cloned `OpenFile` handles. `close_open_file` closes raw host fds only if `Arc::strong_count(&open_file.description) == 1` (`src/dispatch/mod.rs:2449-2484`). Blocking I/O paths can return `DispatchOutcome::WaitOnFds`, and the runtime waits outside dispatch locks at `src/runtime.rs:838-842`.

The current model has two coupled risks:

- A transient cloned `Arc` can keep `strong_count > 1` while close is processed, causing the host fd not to close when the final guest fd table entry is removed.
- A waiter may hold raw host fd integers while another thread closes and the host reuses that fd number for an unrelated object.

Recommendation:

- Move fd table entries to explicit owned host fd handles.
- For wait paths, carry a pinned/borrrowed lifetime or duplicated wait handle rather than a bare integer.
- Add a close-after-wait and wait-after-close contract test.

Validation target:

- A guest thread blocked in `ppoll` on a host fd cannot observe readiness for a different object after another thread closes and reopens fds.
- Host fd count returns to baseline after repeated dup/close/wait cycles.

### S3. Blocking timerfd reads sleep while holding the fd write lock

Severity: P2 performance and contention.

`read` takes `open_file.description.write()` at `src/dispatch/fs.rs:2452`. For `TimerFd`, it calls `read_timerfd` before dropping that lock at `src/dispatch/fs.rs:2463-2480`. `read_timerfd` can sleep until the deadline at `src/dispatch/mod.rs:3811-3819`.

This serializes other operations on the same fd description while sleeping, including timer reconfiguration. Linux timerfd behavior allows another thread to change the timer and affect blocking wait behavior.

Recommendation:

- Do not sleep while holding the `OpenDescription` write lock.
- Convert timerfd to a small state object with its own condition/wake mechanism, or return a `WaitUntilTimer` outcome to the runtime.
- Add tests where one thread blocks in `read(timerfd)` and another calls `timerfd_settime`.

Validation target:

- Re-arming a timerfd from another guest thread wakes or changes the blocked reader according to Linux semantics.

### S4. PROT_NONE tracking is per engine, not process-wide

Severity: P2 correctness.

Guest memory tracks no-access intervals in the trap engine (`src/trap.rs:912-941`). `mprotect` calls `ctx.memory.set_no_access(...)` at `src/dispatch/mem.rs:661`. But sibling trap engines are created with `no_access: Vec::new()` at `src/trap.rs:1737-1739`.

That means one guest thread can mark a range `PROT_NONE` while another thread's dispatcher memory accessor may still accept reads or writes through its own engine view.

Recommendation:

- Move no-access interval state to a process-wide shared memory metadata object.
- Keep per-engine HVF permissions in sync with the shared metadata.
- Add a threaded test where one thread `mprotect(PROT_NONE)`s a buffer and a sibling syscall attempts to read/write it.

Validation target:

- All guest syscall memory access paths enforce the latest process-wide protection metadata.

### S5. Blocking eventfd read semantics are incomplete

Severity: P2 correctness.

`eventfd` stores status flags in `OpenDescription::EventFd` (`src/dispatch/net.rs:91-95`), but `read` calls `read_eventfd` without passing those flags at `src/dispatch/fs.rs:2460-2462`. `read_eventfd` returns `EAGAIN` whenever the counter is zero at `src/dispatch/mod.rs:3734-3737`.

Linux `eventfd` blocks on zero counter unless the fd is nonblocking. The current behavior matches nonblocking reads, but not blocking eventfd reads.

Recommendation:

- Use eventfd status flags in `read_eventfd`.
- For blocking eventfd, return a wait outcome rather than `EAGAIN` when the counter is zero.
- Wake waiters from `write_eventfd` when the counter transitions from zero to nonzero.

Validation target:

- Blocking eventfd read sleeps until another guest thread writes.
- Nonblocking eventfd read still returns Linux `EAGAIN`.

### S6. FUTEX_REQUEUE is an explicit compatibility gap

Severity: P2 compatibility.

During consolidation, this finding was corrected against the current checkout. Current code explicitly returns `ENOSYS` for `FUTEX_REQUEUE` and `FUTEX_CMP_REQUEUE`, records a compatibility event, and documents why waking-instead-of-requeueing was rejected (`src/dispatch/mod.rs:2316-2335`).

That is safer than pretending to support requeue semantics, but it remains a gap for workloads that still depend on those futex operations.

Recommendation:

- Keep the explicit `ENOSYS` until a real requeue model exists.
- Add a compatibility note that modern glibc and musl condvars generally avoid this path, as the code comment says.
- Keep LTP-style futex tests around this behavior so it does not regress into a partial wake implementation.

Validation target:

- `FUTEX_(CMP_)REQUEUE` returns `ENOSYS` and emits a stable compatibility event.
- Known condvar workloads in target libc versions do not hit the gap in normal operation.

### L1. Synthetic `/proc` and `/sys` ownership is inverted

Severity: P2 architecture and legibility.

The VFS modules exist, but much of the real virtual-file rendering lives in the dispatcher. `vfs/proc.rs` and `vfs/sys.rs` are wrappers, while process stat rendering and registry data flow are rooted in dispatcher/runtime structures. Tests for `/proc` behavior are strong, but production ownership is split.

This makes virtual filesystem growth harder because new proc/sys files need dispatcher awareness instead of living in a virtual file table.

Recommendation:

- Move virtual file registration and rendering ownership into `vfs::{proc,sys}`.
- Let dispatcher open/read paths consume a `VfsNode` or `SyntheticFile` produced by the VFS layer.
- Keep runtime thread registry as data input, not as the owner of procfs formatting.

Validation target:

- Adding a new `/proc` file requires a VFS table entry and tests, not edits across dispatcher routing.

### L2. `OpenDescription` has become the fd subsystem boundary

Severity: P2 complexity and bug surface.

`OpenDescription` spans regular files, directories, synthetic files, eventfd, timerfd, epoll, pipes, host pipes, host files, host sockets, and netlink (`src/dispatch/mod.rs:751-857`). Large matches repeat across read, write, readv, writev, splice/sendfile/copy_file_range, stat, statx, lseek, and readiness handling.

This central enum is useful, but it now has too many policies attached directly to ad hoc match sites: locking policy, offset management, host fd access, writeback, readiness, fd flags, and stat identity.

Recommendation:

- Keep `OpenDescription` as the central fd object, but add helper methods or per-kind modules for common policies.
- Extract operations such as `status_flags`, `set_status_flags`, `host_fd`, `readiness`, `stat_source`, `read_at`, and `write_at`.
- Avoid trait objects until the repeated match logic is actually reduced; simple methods may be enough.

Validation target:

- Read/write/stat behavior changes can be tested against one fd operation layer instead of each syscall arm.

### L3. stat/statx construction is duplicated

Severity: P2 correctness and legibility.

The project has solid helpers for writing Linux stat/statx structures, including `write_statx_real`, `write_statx`, and synthetic variants in `src/dispatch/mod.rs:2811-3004`. But path stat logic and fd stat logic still branch separately across many file kinds in `src/dispatch/fs.rs:5035-5398`.

The recurring risk is drift: fstat and statx can disagree on mode, size, timestamps, uid/gid, or synthetic object identity.

Recommendation:

- Introduce a `StatRecord` or `GuestStatSource` intermediate representation.
- Convert path-backed, host-backed, synthetic, pipe, socket, eventfd, timerfd, and epoll objects into that representation.
- Have `stat`, `fstat`, and `statx` write from the same record.

Validation target:

- Table-driven tests assert that `stat`, `fstat`, and `statx(AT_EMPTY_PATH)` agree for every fd kind where Linux expects agreement.

### L4. Syscall metadata and routing can drift

Severity: P2 maintainability.

Syscall metadata lives in `src/syscall.rs`, while routing tables live across dispatcher modules. For example, `pselect6` and `ppoll` are labeled "fs" in `src/syscall.rs:112-119`, but route through network dispatch at `src/dispatch/net.rs:43-44`. Filesystem routing also lists them because syscall grouping and handler ownership are separate concerns.

This is not a direct runtime bug, but it reduces confidence in support-level reporting and compatibility diagnostics.

Recommendation:

- Create a single syscall manifest containing number, name, group, support level, handler module, and compatibility notes.
- Generate or verify route tables against that manifest.
- Add a test that every supported syscall has exactly one handler route.

Validation target:

- Changing a syscall's support level or handler location cannot leave stale metadata behind.

### L5. Errno translation is good but not mandatory enough

Severity: P2 correctness.

The errno translation layer is one of the stronger patterns in the codebase: `host_errno()` maps Darwin errno through `macos_to_linux_errno` (`src/dispatch/mod.rs:4363-4368`), and Linux errno constants are explicit at `src/dispatch/mod.rs:4370-4458`.

The gap is enforcement. Some paths still return raw `host_errno()` correctly, while others manually choose Linux errno. That is sometimes appropriate, but the code does not make the distinction mechanically obvious.

Recommendation:

- Require host syscall failures to flow through a `HostSyscallResult` helper or similar.
- Reserve direct `linux_errno::*` returns for Linux semantic decisions, not host errno propagation.
- Add tests for macOS values that differ numerically from Linux, especially `EAGAIN`, socket errors, and `EINPROGRESS`.

Validation target:

- No host `errno` value can escape as a Linux return without passing through translation.

### L6. The runtime loop is carrying too many responsibilities

Severity: P2 complexity.

`run_vcpu_until_exit` starts at `src/runtime.rs:775` and handles vCPU execution, syscall dispatch, blocking wait re-dispatch, signal servicing, clone, fork, exec, thread exit, registry changes, output behavior, and signal pump rebuilds. That makes it hard to reason about correctness at the fork/signal/thread boundary.

Recommendation:

- Split a `ThreadRuntime` or `VcpuRuntime` object out of the loop.
- Isolate the following transitions into named methods: syscall completion, blocking wait, fork parent/child repair, thread clone registration, exec handoff, signal service.
- Keep the hot loop direct; the point is named invariants, not abstraction for its own sake.

Validation target:

- Fork, clone, exec, and signal tests can target transition helpers or at least trace their compatibility events cleanly.

## Cross-Cutting Implementation Priorities

1. Fix fd table atomicity and host fd lifetime first. Many safety, correctness, and performance findings depend on the fd model.
2. Split signal pump wake channels and formalize Darwin fork discipline. These are the riskiest macOS-specific correctness gaps.
3. Bring blocking eventfd/timerfd behavior closer to Linux. These are guest-visible semantics and likely to affect real runtimes.
4. Add typed Linux ABI parsing and flag handling. This will reduce repeated manual validation and make future syscall work safer.
5. Add Darwin filesystem fast paths only after fd ownership is clearer. `clonefile`, `copyfile`, `fsync`, `F_FULLFSYNC`, and `msync` are useful, but they should sit on a clean host-file abstraction.
6. Consolidate virtual filesystem and stat/statx generation. This pays down complexity without changing core runtime behavior.
7. Repair hygiene gates. `cargo fmt --all -- --check` and the documented clippy gate should be trustworthy before larger refactors land.

## Suggested Work Packages

### Package 1. Fd Table and Host Fd Ownership

Goals:

- Atomic fd installation and pair reservation.
- RAII host fd ownership.
- Pinned wait handles.
- Tests for dup/close/wait races.

Files likely touched:

- `src/dispatch/mod.rs`
- `src/dispatch/fs.rs`
- `src/dispatch/net.rs`
- `src/io_wait.rs`
- `tests/concurrency_contracts.rs`
- `tests/syscall_net.rs`
- `tests/syscall_fs.rs`

### Package 2. Signal Pump and Fork Discipline

Goals:

- Dedicated pump wake pipe or generation-based wake protocol.
- Explicit fork coordinator for Darwin host state.
- Tests for fork under active signal pump and blocked waiters.

Files likely touched:

- `src/host_signal.rs`
- `src/vcpu_kick.rs`
- `src/io_wait.rs`
- `src/runtime.rs`
- `src/trap.rs`
- `tests/syscall_thread.rs`
- `tests/concurrency_contracts.rs`

### Package 3. Linux Blocking Object Semantics

Goals:

- Blocking eventfd reads.
- Timerfd waits that do not hold fd write locks.
- Clear wake behavior for eventfd/timerfd with `ppoll` and `pselect6`.

Files likely touched:

- `src/dispatch/mod.rs`
- `src/dispatch/fs.rs`
- `src/dispatch/net.rs`
- `tests/syscall_net.rs`

### Package 4. ABI and Flag Types

Goals:

- Direct `bitflags` dependency for Linux flag families.
- Read-side `KernelAbi` helpers.
- `zerocopy` structs for common guest ABI reads.
- Property tests for parsing and flag rejection.

Files likely touched:

- `Cargo.toml`
- `src/linux_abi.rs`
- `src/dispatch/mod.rs`
- `src/dispatch/fs.rs`
- `src/dispatch/net.rs`
- `src/dispatch/proc.rs`
- `tests/syscall_*`

### Package 5. Darwin Filesystem Leverage

Goals:

- Real `fsync`/`syncfs` behavior for host-backed files.
- Optional strict `F_FULLFSYNC`.
- `msync` for shared mappings where appropriate.
- APFS clone/copyfile fast path for host-backed file copies and rootfs seeding.

Files likely touched:

- `src/fs_backend.rs`
- `src/rootfs.rs`
- `src/dispatch/fs.rs`
- `src/trap.rs`
- Darwin-specific helper module, if added.

### Package 6. VFS and Stat Ownership

Goals:

- Move synthetic proc/sys ownership into VFS modules.
- Add `StatRecord` or equivalent.
- Align stat/fstat/statx behavior across fd kinds.

Files likely touched:

- `src/vfs/proc.rs`
- `src/vfs/sys.rs`
- `src/vfs/mod.rs`
- `src/dispatch/mod.rs`
- `src/dispatch/fs.rs`
- `tests/syscall_fs.rs`

## Research Assumptions and Corrections

- `FUTEX_(CMP_)REQUEUE` was corrected during consolidation. The current checkout returns `ENOSYS` with a compatibility event, so the gap is compatibility coverage, not a silent misimplementation.
- `FIONBIO` remains a success-without-effect path in the current checkout.
- The APFS clonefile finding is partly a documentation/implementation mismatch: comments promise reflink seeding, while the current seeding path writes contents through `std::fs::write`.
- The Rust ecosystem recommendation is not "add crates everywhere." For Carrick, crates are most valuable where they encode ownership, parsing, and validation. Linux ABI semantics and Darwin behavior should remain explicit in Carrick.
- The Darwin recommendation is not "avoid libc." For several Darwin APIs, `libc` may be the only practical binding. The gap is missing Carrick-level abstractions that preserve Darwin semantics and make unsafe/raw calls auditable.

## Review Bottom Line

Carrick should not self-limit to the portable subset exposed by the Rust `libc` crate, but the answer is not a broad dependency sweep. The right move is to create a small number of explicit host/Darwin and Linux-ABI boundary modules, then use Rust ecosystem crates selectively inside those boundaries:

- `bitflags` for Linux flag correctness.
- `zerocopy` for guest ABI reads and writes.
- `OwnedFd`/`BorrowedFd`, plus possibly `socket2`, for host fd/socket ownership.
- `rustix` where it reduces unsafe fd/mmap boilerplate without hiding semantics.
- `proptest` for ABI/path/flag fuzzing.
- `loom` only after the fd table or wake primitive is isolated enough to model without real kqueue/HVF.

The highest-confidence first investment is fd ownership and atomic fd installation. It will reduce correctness risk immediately and make the Darwin-specific improvements easier to land safely.
