# Carrick Deep Static Systems Audit

Date: 2026-05-29

Mode: static review only. No `cargo`, tests, examples, fixtures, generated code,
or Carrick binaries were run. Evidence came from file inspection, `rg`/`find`/
`sed`/`nl`/`wc`, prior agent lane reports, and the primary-source references
listed below.

## Current Snapshot

Workspace shape:

- Root workspace uses Rust edition 2024, resolver 2, and `crates/*` members
  (`Cargo.toml:1-8`).
- First-party crates: `carrick-abi`, `carrick-cli`, `carrick-engine`,
  `carrick-guest-mem`, `carrick-host`, `carrick-hvf`, `carrick-image`,
  `carrick-mem`, `carrick-runtime`, `carrick-spec`, `carrick-test-support`.
- Workspace clippy denies `unwrap_used`, `expect_used`, `panic`, `todo`, and
  `unimplemented` (`Cargo.toml:11-16`).
- Biggest current source surfaces by LOC are
  `crates/carrick-runtime/src/dispatch/fs.rs` (4902),
  `crates/carrick-runtime/src/dispatch/mod.rs` (4531),
  `crates/carrick-hvf/src/trap.rs` (3665),
  `crates/carrick-runtime/src/dispatch/net.rs` (2791),
  `crates/carrick-runtime/src/runtime.rs` (2578),
  `crates/carrick-runtime/src/fs_backend.rs` (2269),
  `crates/carrick-abi/src/lib.rs` (2098).

Already-landed leverage and safety worth preserving:

- ABI structs have been split into `carrick-abi`; representative packed Linux
  structs derive `zerocopy::Unaligned` (`crates/carrick-abi/src/lib.rs:85-88`).
- `KernelAbi::ABI_SIZE` centralizes Linux wire-size writes
  (`crates/carrick-abi/src/lib.rs:1089-1099`).
- Syscall arguments have typed newtypes for fd, pid, signal, guest pointer, and
  guest length (`crates/carrick-runtime/src/dispatch/abi_args.rs:1-63`).
- Linux flag families already use `bitflags!` for open, at, mmap, futex, clone,
  socket type, and fd flags (`crates/carrick-abi/src/lib.rs:1624-1696`).
- Cross-process futex support now uses public macOS `os_sync_wait_on_address`
  with shared semantics (`crates/carrick-host/src/ulock.rs:1-23`,
  `crates/carrick-host/src/ulock.rs:80-116`).
- Host syscall errno translation is centralized for many direct libc calls via
  `HostSyscallError` and `HostSyscallResult`
  (`crates/carrick-runtime/src/dispatch/mod.rs:3436-3468`).
- APFS `clonefile(2)` leverage exists for layer-cache rootfs seeding
  (`crates/carrick-runtime/src/layer_cache.rs:120-128`).

Primary references used:

- Linux `futex(2)`: https://www.man7.org/linux/man-pages/man2/futex.2.html
- Linux `openat2(2)`: https://man7.org/linux/man-pages/man2/openat2.2.html
- Apple `os_sync_wait_on_address` flags:
  https://developer.apple.com/documentation/os/os_sync_wait_on_address_flags_t
- Apple APFS cloning overview:
  https://developer.apple.com/documentation/foundation/about-apple-file-system
- Apple disk sync guidance:
  https://developer.apple.com/documentation/xcode/reducing-disk-writes
- Rust `OwnedFd`: https://doc.rust-lang.org/std/os/fd/struct.OwnedFd.html
- Rust packed-field rule: https://doc.rust-lang.org/error_codes/E0793.html
- `bitflags`: https://docs.rs/bitflags/latest/bitflags/
- Semgrep rule syntax: https://semgrep.dev/docs/writing-rules/rule-syntax

## Prioritized Findings

### P0: `F_SETFL` stores raw guest status flags

Classification: Correctness, Linux fidelity, Static enforcement

Evidence:

- `F_SETFL` strips only `O_CLOEXEC` from the guest argument and stores the result
  as open-description status flags
  (`crates/carrick-runtime/src/dispatch/fs.rs:1673-1733`).
- The stored value is later guest-visible through `F_GETFL` paths. The code also
  propagates only `O_NONBLOCK` to host fds while retaining every other guest bit
  in `OpenDescriptionBase`.

Expected behavior:

- Linux `F_SETFL` mutates only a limited set of file status flags. Access-mode
  bits are not mutable through `F_SETFL`, and unsupported or creation-only bits
  should not be stored as if they were active status.

Why current code may diverge:

- `arg & !LINUX_O_CLOEXEC` keeps access-mode bits and unrelated open flags. That
  can make later `F_GETFL` report a mode/status combination Linux would not
  preserve.

Status:

- Confirmed by static inspection. Needs a targeted Linux-vs-Carrick conformance
  probe before implementation, but the code path is concrete.

Follow-up:

- Introduce a `LINUX_F_SETFL_MUTABLE_STATUS_MASK` and set
  `next_flags = (old_access_mode_bits | mutable_status_bits_from_arg)`.
- Add a Semgrep rule for `set_status_flags($ARG)` where `$ARG` is derived from
  a syscall argument without passing through the mutable-status helper.

### P0: `openat2` accepts `RESOLVE_*` without enforcing them

Classification: Correctness, Linux fidelity, Security-adjacent

Evidence:

- `openat2` validates that `resolve` contains only `0x3f`, then passes flags and
  mode to the shared open path
  (`crates/carrick-runtime/src/dispatch/fs.rs:2447-2466`).
- The comment explicitly says Carrick does not yet enforce the restrictions
  (`crates/carrick-runtime/src/dispatch/fs.rs:2461-2465`).

Expected behavior:

- `openat2(2)` `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_XDEV`, `RESOLVE_BENEATH`, and
  related bits are path-resolution policy. Linux rejects or constrains opens
  when those policies cannot be satisfied.

Why current code may diverge:

- A guest can request a constrained open and receive an unconstrained one. This
  is materially different from returning `EINVAL` or `ENOSYS`: the guest sees
  success under a stronger policy than Carrick actually enforced.

Status:

- Confirmed by static inspection and already acknowledged in code comments.

Follow-up:

- Either enforce each accepted `RESOLVE_*` bit in path resolution or reject the
  bit with an explicit compat event until implemented.
- Add a Semgrep rule for `openat2` that requires every accepted resolve bit to
  have an enforcement branch or an explicit compatibility-gap return.

### P0: `mremap` accepts fixed/dontunmap semantics but ignores `new_address`

Classification: Correctness, Linux fidelity

Evidence:

- Handler signature names the destination `_new_address`
  (`crates/carrick-runtime/src/dispatch/mem.rs:611`).
- Accepted flags include `MREMAP_FIXED` and `MREMAP_DONTUNMAP`
  (`crates/carrick-runtime/src/dispatch/mem.rs:616`).
- Move growth allocates with `next_mmap_address(0, ...)`, not the supplied
  destination (`crates/carrick-runtime/src/dispatch/mem.rs:643-648`).

Expected behavior:

- Linux `MREMAP_FIXED` changes destination selection and requires a supplied new
  address. `MREMAP_DONTUNMAP` also changes old-range lifetime semantics.

Why current code may diverge:

- The code reports support by accepting the bits but takes the default move path
  and ignores the requested destination/lifetime behavior.

Status:

- Confirmed by static inspection. Dynamic tests should determine exact guest
  symptoms.

Follow-up:

- Reject unsupported `MREMAP_FIXED`/`MREMAP_DONTUNMAP` for now, or implement the
  destination/lifetime semantics fully.
- Add a static rule: a syscall parameter named with a leading underscore is
  forbidden when accepted flags imply the parameter matters.

### P0: Internal fd relocation silently falls back to low fds

Classification: Rust safety, Correctness, Centralization

Evidence:

- `relocate_internal_fd` returns the original fd if `F_DUPFD_CLOEXEC` fails
  (`crates/carrick-hvf/src/host_signal.rs:560-571`).
- Callers proceed as if relocation succeeded, including readiness pipes
  (`crates/carrick-runtime/src/dispatch/fd_table.rs:94-112`) and supervisor
  pipes (`crates/carrick-runtime/src/interactive_supervisor.rs:376-390`).

Expected behavior:

- Internal host fds should either be in the reserved high-fd range or creation
  should fail/degrade explicitly. A silent low-fd fallback breaks the invariant
  that internal fds cannot collide with guest-visible fds.

Why current code may diverge:

- Under fd pressure or rlimit conditions, internal fds may remain in the guest
  fd range while later code treats them as private implementation details.

Status:

- Confirmed by static inspection. Needs an fd-pressure repro later.

Follow-up:

- Make relocation fallible and update callers to return a Linux errno or disable
  the optional readiness channel explicitly.
- Add Semgrep allowlist rules for direct `pipe`, `dup`, `F_DUPFD*`, and
  relocation calls outside the host fd wrapper.

### P0: Child CPU accounting publishes pid before data

Classification: Rust safety, Correctness

Evidence:

- `record_child_exit` publishes `pid` with `compare_exchange(..., AcqRel, ...)`
  before storing `guest_ns` (`crates/carrick-host/src/guest_cpu.rs:151-156`).
- `reap_child_guest_ns` sees `pid` with Acquire, then reads `guest_ns`
  (`crates/carrick-host/src/guest_cpu.rs:165-170`).

Expected behavior:

- Publication protocols should make the payload visible before the key/state
  that readers use to consume the payload.

Why current code may diverge:

- A parent can observe the pid before the `guest_ns` Release store has occurred,
  then drain zero or stale CPU accounting.

Status:

- Confirmed by static inspection. This is a race; dynamic proof may be timing
  sensitive.

Follow-up:

- Store `guest_ns` before publishing pid, or replace the pair with a slot state
  machine (`empty -> writing -> ready`) where `ready` is the Acquire/Release key.
- Add an atomics invariant comment and a small model/unit test around slot
  publication before changing behavior.

### P1: SIGWINCH relay setup is not rollback-safe on partial failure

Classification: Rust safety, Correctness

Evidence:

- `WINCH_PIPE_WRITE` is published before handler installation and before
  `start_inner` can fail (`crates/carrick-runtime/src/pty_relay.rs:220-240`).
- `sigaction` return is ignored (`crates/carrick-runtime/src/pty_relay.rs:231`).
- The thread-spawn error path closes fds, but cannot restore a process-global
  handler already installed earlier in `start`
  (`crates/carrick-runtime/src/pty_relay.rs:284-296`).

Expected behavior:

- Process-global signal handler changes should be installed through a guard that
  either commits to the returned relay or restores state on every failure path.

Why current code may diverge:

- A failure after publishing the pipe/handler can leave stale global signal
  state pointing at closed or unintended fds.

Status:

- Confirmed by static inspection.

Follow-up:

- Add a `SigwinchInstallGuard` that checks `sigaction`, owns the pipe write fd
  until committed, and restores old disposition on drop.
- Add Semgrep rule: `libc::sigaction(...)` results must be checked outside
  tests.

### P1: Wait-fd pinning degrades to raw fd reuse risk

Classification: Rust safety, Correctness

Evidence:

- `PinnedWaitFds::new` tries `dup`, but if it fails it waits on the original fd
  and marks it unowned (`crates/carrick-hvf/src/io_wait.rs:56-69`).

Expected behavior:

- A type named and used as fd pinning should either own duplicate fds or return a
  construction error. Otherwise fd reuse can race a parked wait.

Why current code may diverge:

- If another path closes/reuses the original fd while this wait is parked,
  readiness may be observed for the wrong object.

Status:

- Confirmed by static inspection; dynamic proof needs fd-pressure timing.

Follow-up:

- Make `PinnedWaitFds::new` return `Result<Self, i32>` and surface `EMFILE` or
  an appropriate Linux errno instead of falling back.
- Prefer an `OwnedFd`-based `PinnedFd` wrapper for successful duplicates.

### P1: `waitid` leaks raw Darwin errno

Classification: Linux fidelity, Rust safety, Centralization

Evidence:

- `waitid` error paths use `std::io::Error::last_os_error().raw_os_error()` and
  pass that directly to `DispatchOutcome::errno`
  (`crates/carrick-runtime/src/dispatch/proc.rs:1121-1123`,
  `crates/carrick-runtime/src/dispatch/proc.rs:1157-1158`).
- The repo has a central host-to-Linux errno path
  (`crates/carrick-runtime/src/dispatch/mod.rs:3436-3468`).

Expected behavior:

- Guest-visible errno values should be Linux errno values. Darwin errno values
  sometimes differ, so host errno must be translated unless the code is
  deliberately returning a Linux constant.

Why current code may diverge:

- Common wait errnos overlap, but the pattern is a footgun and can leak a
  non-Linux value when a less common host errno appears.

Status:

- Confirmed pattern. Severity depends on reachable host errno set.

Follow-up:

- Replace raw `last_os_error` returns with `HostSyscallError::last().linux_errno()`
  or a narrow helper for `std::io::Error`.
- Add Semgrep rule forbidding `DispatchOutcome::errno($ERR)` when `$ERR` came
  from `raw_os_error()` or `*libc::__error()`.

### P1: `io_uring_enter` accepts more semantics than it implements

Classification: Correctness, Linux fidelity

Evidence:

- Handler ignores `_min_complete`, `_flags`, `_argp`, and `_argsz`
  (`crates/carrick-runtime/src/dispatch/mem.rs:767-768`).
- Implementation comment says synchronous completion means `min_complete` is
  already satisfied, but the loop drains until SQ head equals SQ tail rather
  than bounding work by `to_submit`
  (`crates/carrick-runtime/src/dispatch/ioring.rs:334-362`).

Expected behavior:

- Linux `io_uring_enter` arguments affect how many SQEs are submitted, how many
  completions are waited for, and which enter flags are active.

Why current code may diverge:

- Carrick exposes a simplified synchronous subset, but accepts ignored
  parameters as if the full enter contract were present.

Status:

- Confirmed static gap. Because `io_uring` support is young and intentionally
  scoped, treat as a compatibility gap rather than a regression.

Follow-up:

- Reject nonzero unsupported flags/args for now and bound SQE processing to the
  guest-requested submit count.
- Add an allowlisted "implemented subset" table for partial syscalls.

### P1: Late HVF stage-2 mapping remains on dynamic `mmap` path

Classification: Darwin leverage, Correctness, Performance

Evidence:

- `mmap(MAP_SHARED, fd)` builds a `MapHostAlias` payload
  (`crates/carrick-runtime/src/dispatch/mem.rs:256-264`,
  `crates/carrick-runtime/src/dispatch/mem.rs:328-332`).
- HVF trap code maps host aliases with `hv_vm_map`
  (`crates/carrick-hvf/src/trap.rs:1549-1562`).
- The durable memory design says ordinary guest `mmap`/`munmap`/`mprotect` and
  shared-memory lifetime should not use late `hv_vm_map`/`hv_vm_unmap`/
  `hv_vm_protect` after vCPU threads exist
  (`docs/archive/superpowers/specs/2026-05-26-durable-memory-architecture-design.md:17-24`).

Expected behavior:

- The durable direction is stable stage-2 topology with guest-visible memory
  semantics owned by stage-1 page tables
  (`docs/archive/superpowers/specs/2026-05-26-durable-memory-architecture-design.md:128-132`).

Why current code may diverge:

- The current dynamic path still depends on host/HVF remapping operations in
  ordinary mmap behavior, which is exactly the design direction the durable
  memory plan rejected for correctness and scalability.

Status:

- Confirmed as current architecture debt. Dynamic proof should focus on stale
  TLB/stage-2 behavior and mmap/fork/shared-memory interactions.

Follow-up:

- Prioritize the stable shared aperture / stage-1 manager plan before adding
  more dynamic alias cases.

### P1: `mprotect` is guest-visible only for part of memory

Classification: Correctness, Linux fidelity

Evidence:

- `mprotect` sets host-side no-access tracking and edits stage-1 page tables
  only for the private mmap arena; shared aperture and image/heap regions keep
  host-side checks only (`crates/carrick-runtime/src/dispatch/mem.rs:696-710`).

Expected behavior:

- Linux protection changes are guest-visible during execution regardless of
  which valid user mapping the address belongs to.

Why current code may diverge:

- For regions outside the private mmap arena, syscall-path checks may reject
  host reads/writes, but guest EL0 execution may not fault consistently at the
  stage-1 permission boundary.

Status:

- Confirmed as an explicit scoped limitation in the code.

Follow-up:

- Fold image/heap/shared-aperture regions into the same guest page-table
  protection source of truth, or reject/probe unsupported ranges explicitly.

### P2: POSIX timers and timerfd readiness still carry avoidable user-space machinery

Classification: Darwin leverage, Performance, Linux fidelity

Evidence:

- Epoll uses `EVFILT_USER` as an in-memory wake channel
  (`crates/carrick-runtime/src/dispatch/net.rs:854-863`) and recomputes
  in-memory fd readiness (`crates/carrick-runtime/src/dispatch/net.rs:1190-1194`).
- POSIX timers spawn a sleep/fire thread per arm
  (`crates/carrick-hvf/src/posix_timer.rs:1-15`,
  `crates/carrick-hvf/src/posix_timer.rs:135-158`).
- `darwin_kqueue` already has an `EVFILT_TIMER` wrapper
  (`crates/carrick-hvf/src/darwin_kqueue.rs:175-184`).

Expected behavior:

- Darwin `kqueue` can carry timer readiness in the kernel instead of one host
  thread per timer arm. Linux timerfd and POSIX timer semantics still need
  guest-visible expiration and overrun behavior preserved.

Why current code may diverge:

- Current design is probably correct for simple LTP paths, but it adds thread
  overhead and central wake recomputation where a native kqueue timer path may
  be simpler and cheaper.

Status:

- Confirmed opportunity, not a confirmed correctness bug.

Follow-up:

- Audit `timerfd` expiration math separately, then move POSIX timer delivery to
  the existing pump/kqueue path only with conformance probes.

### P2: APFS clone fast path is ordered after data copy in one helper

Classification: Darwin leverage, Performance

Evidence:

- `copyfile_clone_or_data` tries `COPYFILE_DATA` before `COPYFILE_CLONE`
  (`crates/carrick-runtime/src/darwin_fs.rs:19-30`).
- Rootfs layer-cache seeding does use `clonefile(2)`, so this is a narrow
  copy-file-range/sendfile fast-path issue rather than a missing APFS strategy
  (`crates/carrick-runtime/src/layer_cache.rs:120-128`).

Expected behavior:

- APFS clones are designed to be cheap same-volume copies. Apple documents APFS
  clones as reducing copy cost when source and destination are on the same
  volume.

Why current code may diverge:

- Trying data copy first may consume the opportunity to clone without copying,
  depending on `copyfile`/`fcopyfile` behavior for those flags.

Status:

- Confirmed helper ordering. Needs Darwin header/manpage verification and a
  targeted APFS probe before changing, because `copyfile` flag interactions are
  subtle.

Follow-up:

- Prefer clone-first when source/destination are regular files on the same APFS
  volume, with fallback to data copy.

### P2: TTY/session behavior is spread across host passthrough and synthetic state

Classification: Linux fidelity, Darwin leverage, Centralization

Evidence:

- `setpgid`, `getpgid`, `getsid`, and `setsid` call host process APIs directly
  (`crates/carrick-runtime/src/dispatch/proc.rs:1040-1070`).
- `/dev/tty` state is a single `PtyTable::controlling_index`
  (`crates/carrick-runtime/src/vfs/devpts.rs:24-33`).
- Host TTY helpers return raw host errno for some paths
  (`crates/carrick-runtime/src/host_tty.rs:438-458`).

Expected behavior:

- Linux job control has process groups, sessions, controlling terminals, and
  tty ioctls with Linux-specific error and permission behavior.

Why current code may diverge:

- While guest pids often mirror host pids, direct Darwin session/tty passthrough
  plus synthetic `/dev/tty` state creates multiple authorities for the same
  guest-visible model.

Status:

- Risk confirmed; exact bugs need scenario probes.

Follow-up:

- Centralize Linux job-control state and make host TTY calls a narrow backend
  behind Linux-visible policy/errno translation.

### P2: Repeated guest ABI helpers and fd/errno policy remain scattered

Classification: Centralization, Correctness

Evidence:

- Good helpers exist for `read_kernel_struct`, `read_kernel_prefix`, `read_iovecs`,
  and `read_guest_c_string`
  (`crates/carrick-runtime/src/dispatch/mod.rs:2281-2307`,
  `crates/carrick-runtime/src/dispatch/mod.rs:3086-3120`,
  `crates/carrick-runtime/src/dispatch/mod.rs:3711-3733`).
- `io_uring` has a local iovec reader and direct `as_bytes()` write path
  (`crates/carrick-runtime/src/dispatch/ioring.rs:226-235`,
  `crates/carrick-runtime/src/dispatch/ioring.rs:294-297`).
- Flag reporting exists centrally, but handler enforcement is still local
  (`crates/carrick-runtime/src/dispatch/mod.rs:1848-1898`,
  `crates/carrick-runtime/src/dispatch/mem.rs:240`,
  `crates/carrick-runtime/src/dispatch/time.rs:18-28`).
- Raw errno mapping varies by module
  (`crates/carrick-runtime/src/vfs/bind.rs:43-50`,
  `crates/carrick-runtime/src/vfs/devpts.rs:148-160`,
  `crates/carrick-runtime/src/host_tty.rs:438-458`).
- FD install and capability logic is partly centralized but repeated at
  construction and capability sites
  (`crates/carrick-runtime/src/dispatch/fs/fd_helpers.rs:29-40`,
  `crates/carrick-runtime/src/dispatch/fs/fd_helpers.rs:90-105`,
  `crates/carrick-runtime/src/dispatch/time.rs:18-28`).

Expected behavior:

- Linux ABI reads/writes, flag acceptance/rejection, host errno conversion, and
  host fd ownership are cross-cutting compatibility policy. They should be
  centralized enough that new syscalls cannot bypass them by accident.

Why current code may diverge:

- Local helper clones make it easy to fix one path and leave another with older
  bounds, errno, or layout behavior.

Status:

- Confirmed maintainability and correctness risk.

Follow-up:

- Move reusable guest ABI helpers into `carrick-guest-mem` or a narrow
  `dispatch::guest_abi` module.
- Add `SyscallFlagSpec`, `HostErrno`, `FdInstallSpec`, and `OpenDescriptionCaps`
  boundaries before adding more syscalls.

## Lead Disposition

| Lead | Disposition |
|---|---|
| `F_SETFL` raw status flags | Confirmed P0. |
| `openat2 RESOLVE_*` accepted but unenforced | Confirmed P0. |
| `mremap` fixed/dontunmap ignored | Confirmed P0. |
| `io_uring_enter` ignored args and submit bound | Confirmed P1 compatibility gap. |
| Raw Darwin errno in `waitid` | Confirmed P1 pattern. |
| `shmat` ignores addr/flags | Confirmed intentional minimal subset; keep as explicit compat gap. |
| Child CPU accounting publication race | Confirmed P0/P1 race. |
| SIGWINCH relay setup cleanup | Confirmed P1. |
| Wait-fd pinning fallback | Confirmed P1. |
| Internal fd relocation fallback | Confirmed P0/P1. |
| Fork-quiesce panic exceptions | Confirmed risk, but lower priority than fd/signal races because invariant is documented and no panic path was found in this static pass. |
| Packed ABI structs | Qualified: broad surface exists, but no concrete unaligned-reference bug found; current `zerocopy::Unaligned` and copy-out patterns are good. |
| Late HVF stage-2 mapping | Confirmed architecture debt against durable memory design. |
| Partial `mprotect` stage-1 enforcement | Confirmed scoped limitation. |
| APFS clone/data ordering | Confirmed narrow performance opportunity; rootfs clone seeding itself is already present. |
| Timerfd/POSIX timer kqueue leverage | Confirmed opportunity; not yet a correctness finding. |
| TTY/session boundary spread | Confirmed risk area; needs probes. |
| Guest ABI, flag, errno, fd, trap-loop, Darwin wrapper centralization | Confirmed broad refactor backlog; top priority is ABI/flags/errno/fd policy. |

## Not a Bug / Already Intentional

- Do not repeat the old "`bitflags` are missing" claim wholesale. Several core
  Linux flag families are already typed in `carrick-abi`; the remaining problem
  is enforcement coverage and raw flags that escaped those types.
- Do not repeat the old "__ulock private API" claim. Cross-process futex now uses
  public `os_sync_wait_on_address` with shared semantics.
- Do not repeat the old "APFS clonefile missing from rootfs seeding" claim.
  `layer_cache.rs` has a `clonefile(2)` seeding path. The current issue is the
  `copyfile_clone_or_data` helper order in another path.
- Do not promote a packed-struct finding without a concrete unaligned reference.
  The Rust rule is real, but the inspected production code generally copies
  packed fields out before use or goes through `zerocopy` helpers.
- `../archive/gap-research.md` remains historical context. This audit intentionally does
  not overwrite it or re-open already-closed items without current evidence.

## Static Enforcement Candidates

- `carrick.accepted-flags-must-be-enforced`: flag handlers that accept a mask
  containing `*_FIXED`, `RESOLVE_*`, `*_RDONLY`, or similar semantic flags
  without an enforcement branch or explicit compat-gap return.
- `carrick.f-setfl-must-mask-status`: flag `set_status_flags($ARG)` unless
  `$ARG` flows through a named mutable-status helper.
- `carrick.host-errno-must-translate`: forbid `DispatchOutcome::errno($ERR)`
  where `$ERR` came from `raw_os_error()` or `*libc::__error()` outside a
  translation helper.
- `carrick.fd-ffi-allowlist`: restrict direct `libc::close`, `dup`, `pipe`,
  `socketpair`, and `fcntl(F_DUPFD*)` to `carrick-host` fd wrappers or explicit
  local RAII types.
- `carrick.sigaction-result-checked`: require every production `sigaction` call
  to check the return value and pair process-global state with a rollback guard.
- `carrick.no-ignored-syscall-args`: flag syscall parameters prefixed with `_`
  in handlers whose accepted flags imply those parameters affect semantics.
- Rust lint follow-ups: evaluate crate-level `unsafe_op_in_unsafe_fn` and
  `clippy::undocumented_unsafe_blocks`; shrink production `unwrap_used`
  allowances; prefer `OwnedFd`/`BorrowedFd`/small newtypes for owned/pinned fd
  lifetimes.

## Implementation Backlog

1. Fix `F_SETFL` status masking and add a probe for access-mode/status
   preservation.
2. Make internal fd relocation and wait-fd pinning fallible instead of silently
   falling back to unsafe raw fd behavior.
3. Fix child CPU accounting publication ordering.
4. Add SIGWINCH relay install/rollback RAII and check `sigaction`.
5. Change `openat2` to reject or enforce each accepted `RESOLVE_*` bit.
6. Reject or implement `MREMAP_FIXED` and `MREMAP_DONTUNMAP`.
7. Translate `waitid` raw host errno through the central host-errno path.
8. Tighten `io_uring_enter` to its implemented subset and bound processing by
   `to_submit`.
9. Centralize guest ABI reads/writes and iovec/C-string helpers before adding
   more syscall families.
10. Centralize flag validation, fd installation/capability logic, and raw Darwin
    wrapper boundaries.
11. Execute the durable memory architecture: stable stage-2 topology, stage-1
    source of truth for `mmap`/`munmap`/`mprotect`, and no ordinary late HVF
    mapping after vCPU startup.
12. Evaluate kqueue timer integration for POSIX timers/timerfd after adding
    expiration/overrun probes.
13. Rework TTY/session handling behind a Linux job-control policy layer.
14. Re-order APFS copy fast path only after a targeted APFS clone/data-copy
    probe validates the intended behavior.
