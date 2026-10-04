# Personality Census: Linux Personality Separation and NT Substrate Mapping

Context: [`docs/personality-boundary.md`](personality-boundary.md) defines the substrate versus personality architecture rule and the mechanical boundary checker (`check-personality-boundary`). This document provides an exact census of all 47 crates across the Carrick workspace to feed the design of a future NT (Windows) personality executing on the same virtualization substrate alongside Linux.

## Corrections (2026-10-04)

Following code-checked review against [`docs/superpowers/specs/2026-10-04-personality-core-split.md`](superpowers/specs/2026-10-04-personality-core-split.md) (PR #19, "Evidence and corrections to the inputs"), the census incorporates the following seven architectural corrections:

1. **Boundary Gate Allowlist Scope:** The mechanical boundary gate allowlist in `crates/carrick-conformance-contract/src/personality_boundary.rs` (the constant `DEFAULT_SUBSTRATE_ALLOWLIST`) contains **seven** crates: sched, mmu, signal, timer, fd, pipe, and el1. Passing this gate demonstrates that code passes the AST syntactic lexical check, but does not prove personality neutrality.

2. **`carrick-signal-core` is LINUX-PERSONALITY:** Reclassified from neutral core to `LINUX-PERSONALITY`. `src/policy.rs` hard-codes Linux signal semantics (`Signal::KILL = 9`, `CHLD = 17`, uncatchable STOP/KILL, sigaction, and exec reset policy). The absence of a Cargo dependency on `carrick-abi` is insufficient for substrate status.

3. **`carrick-timer-core` is MIXED:** Reclassified from neutral core to `MIXED` with 10 personality/adapter items. `src/itimer.rs` defines three fixed REAL/VIRTUAL/PROF slots, process-global `SLOTS`, and BSD timer-ident/arm flags. `src/posix.rs` carries `signum` and `si_value` in `PosixTimerSpec`, and `OVERRUN_MAX` encodes POSIX saturation.

4. **`carrick-fd-core` and `carrick-pipe-core` are MIXED:** Reclassified from neutral core to `MIXED`. `carrick-fd-core` implements dense POSIX `Fd` numbers, `dup2`/`dup3`, `fork`/`exec`, mutable status-flag policy, and `CLOEXEC` handling. `carrick-pipe-core` implements `EventFd`, `EVENTFD_MAX`, and `Step::broken_pipe_signal` requesting SIGPIPE. Both function as Linux client authorities.

5. **`carrick-sched-core` is MIXED:** Reclassified from neutral core to `MIXED` with 8 items. `ThreadIdentity` carries a zero-extended Linux tid and `file_table`, plus lifecycle/control bindings. Its `ThreadCtx` is AArch64 register-shaped rather than ISA-neutral.

6. **`carrick-mmu-core` Stage-1 Translation Granule is 4 KiB:** In `crates/carrick-mmu-core/src/aarch64.rs`, `PT_PAGE` is `0x1000` (4 KiB stage-1 table page). The stage-1 translation tables are already 4 KiB; host 16 KiB backing custody is an independent host-side domain. NT requires reservation policy, not wholesale replacement of stage-1 translation.

7. **ARM64 NT TEB Register is x18:** Windows on ARM64 reserves platform register **x18** for the user Thread Environment Block (TEB) per Microsoft's ARM64 ABI conventions, rather than `tpidr_el0` (which is the Linux TLS register).

## Required Counts at a Glance

### Crates per Class

| Classification | Count | Description |
|---|:---:|---|
| **SUBSTRATE** | 5 | Personality-neutral virtualization, memory, and core data structure mechanisms. |
| **LINUX-PERSONALITY** | 6 | Dedicated Linux ABI constants, wire structs, signal delivery, policy, and syscall dispatch graph. |
| **HOST/VMM** | 10 | Hypervisor backends (HVF, KVM, bhyve, NVMM), guest ISA scaffolds, and host OS shims. |
| **TOOLING** | 8 | Conformance harnesses, test runners, contract boundary checkers, and developer workflows. |
| **MIXED** | 18 | Architecture/runtime components combining neutral substrate mechanisms with Linux-specific ABI/semantics. |
| **Total** | **47** | Workspace crate closure under `crates/`. |

### Linux-Specific Items per Crate (Substrate and Mixed)

| Crate | Classification | Linux Items | Primary Personality Entanglements |
|---|---|:---:|---|
| `carrick-fatal` | SUBSTRATE | 0 | None (clean substrate) |
| `carrick-guest-arch` | SUBSTRATE | 0 | None (clean substrate, sealed hardware trait boundary) |
| `carrick-guest-mem` | SUBSTRATE | 3 | `Aarch64SyscallFrame`, `X8664SyscallFrame`, `GuestMemory::shared_futex_location` |
| `carrick-image` | SUBSTRATE | 0 | None (clean substrate, OCI container image format/layer resolution) |
| `carrick-mmu-core` | SUBSTRATE | 0 | None (clean substrate, AArch64/x86 stage-1 page table algorithms; `PT_PAGE = 0x1000`) |
| `carrick-el1` | MIXED | 36 | EL1 Linux syscall dispatch, Linux errno returns, thread robust list setup |
| `carrick-el1-abi` | MIXED | 50 | IPC directory epoll readiness, epoll harvest/ctl, OFD growth, clone thread lifecycle |
| `carrick-el1-image` | MIXED | 0 | None in exports (binary carrier artifact of mixed `carrick-el1`) |
| `carrick-embed` | MIXED | 20 | Shared buffer futex wait/wake, futex contract runners, Linux VFS metadata |
| `carrick-engine` | MIXED | 2 | Container request resolution using `carrick-abi` and Linux process specs |
| `carrick-fd-core` | MIXED | 29 | Dense POSIX `Fd` index, `TableId`, `BadFd`, dup/close/fork/exec descriptor operations |
| `carrick-hal` | MIXED | 22 | `carrick-abi` wire structs, Linux sigframe injection, itimer signal numbers, `ThreadId` |
| `carrick-inotify-core` | MIXED | 18 | `LinuxInotifyEventHeader`, `LinuxErrno`, `LINUX_IN_*` masks, `alloc_wd` |
| `carrick-kernel-arena` | MIXED | 8 | Process table records, PID namespace slot allocation, lock owner PID |
| `carrick-mem` | MIXED | 109 | `LINUX_*` memory layout constants, Linux ELF PIE bases, VDSO layout, EL0 trampolines |
| `carrick-observability` | MIXED | 68 | USDT probes tracking host PIDs, epoll interest/ready masks, Linux syscall logging |
| `carrick-pipe-core` | MIXED | 2 | `EVENTFD_MAX` constant, `broken_pipe_signal` SIGPIPE trigger |
| `carrick-runtime` | MIXED | 7 | Combined syscall loop with `carrick-abi` dispatcher, Rosetta `/proc` interpreter path, census PIDs |
| `carrick-sched-core` | MIXED | 8 | `ThreadIdentity` carrying Linux tid and `file_table`, AArch64-shaped `ThreadCtx` |
| `carrick-spec` | MIXED | 3 | `ProcessSpec` with Linux rlimits, Linux namespace configurations |
| `carrick-thread` | MIXED | 16 | `FutexTable` private futex wait/wake/requeue, thread registry `ThreadId` |
| `carrick-timer-core` | MIXED | 10 | Fixed 3 itimer slots (`src/itimer.rs`), `PosixTimerSpec` with `signum`/`si_value`, `OVERRUN_MAX` (`src/posix.rs`) |
| `carrick-vfs` | MIXED | 48 | `FsBackend` and `Vfs` returning `LinuxErrno`, stat structures, synthetic /proc types |
| **Subtotal (Substrate)** | **SUBSTRATE (5)** | **3** | **3 items across 1 crate; 4 crates 100% clean** |
| **Subtotal (Mixed)** | **MIXED (18)** | **456** | **456 items across 17 crates; 1 artifact crate 0 exports** |
| **Total** | **Audited (23)** | **459** | **Full public item census of substrate and mixed layers** |

## Workspace Crate Classification Inventory

Every crate under `crates/` is classified according to the substrate versus personality architecture:

| Crate | Path | Class | Architectural Role |
|---|---|---|---|
| `carrick-fatal` | `crates/carrick-fatal` | **SUBSTRATE** | Fatal invariant violation sink and crash recorder (`carrick_fatal!`, `CARRICK_LAST_FATAL`) |
| `carrick-guest-arch` | `crates/carrick-guest-arch` | **SUBSTRATE** | Sealed hardware boundary, `Arch` traits, ordinals, generational types |
| `carrick-guest-mem` | `crates/carrick-guest-mem` | **SUBSTRATE** | Guest memory abstraction trait (`GuestMemory`), memory errors, syscall register frames |
| `carrick-image` | `crates/carrick-image` | **SUBSTRATE** | OCI container image reference parsing, blob store, layer cache, configuration resolution |
| `carrick-mmu-core` | `crates/carrick-mmu-core` | **SUBSTRATE** | AArch64/x86 stage-1 page table manipulation algorithms, `PageTableManager` (4 KiB `PT_PAGE = 0x1000`) |
| `carrick-abi` | `crates/carrick-abi` | **LINUX-PERSONALITY** | Linux syscall numbers, wire structures, ioctl constants, and layout assertions |
| `carrick-cli` | `crates/carrick-cli` | **LINUX-PERSONALITY** | Docker-compatible CLI binary executable for running Linux container workloads |
| `carrick-kernel` | `crates/carrick-kernel` | **LINUX-PERSONALITY** | Complete Linux kernel emulation graph: syscall dispatchers, namespaces, credentials, procfs, sysfs, devpts, sockets, IPC |
| `carrick-signal-core` | `crates/carrick-signal-core` | **LINUX-PERSONALITY** | Linux signal policy (`policy.rs`): `Signal::KILL = 9`, `CHLD = 17`, uncatchable STOP/KILL, sigaction/exec reset policy |
| `carrick-signal-linux` | `crates/carrick-signal-linux` | **LINUX-PERSONALITY** | Linux signal numbers, sigaction, siginfo structures, signal delivery frames |
| `carrick-x86-cpl0` | `crates/carrick-x86-cpl0` | **LINUX-PERSONALITY** | Native entry and boot trampoline into Carrick's in-guest Linux personality on x86_64 |
| `carrick-aarch64` | `crates/carrick-aarch64` | **HOST/VMM** | Shared AArch64 VMM engine scaffold over `Aarch64Vmm` / `Aarch64Vcpu` |
| `carrick-host` | `crates/carrick-host` | **HOST/VMM** | Darwin host helpers, guest CPU accounting, Darwin process info, host mappings |
| `carrick-host-bsd` | `crates/carrick-host-bsd` | **HOST/VMM** | BSD host platform glue: kqueue multiplexer, BSD futex, errno/signal translation |
| `carrick-host-linux` | `crates/carrick-host-linux` | **HOST/VMM** | Linux host platform glue: epoll multiplexer, Linux host syscall hooks |
| `carrick-portable` | `crates/carrick-portable` | **HOST/VMM** | Host libc portability shims for missing/divergent platform libc definitions |
| `carrick-vmm-bhyve` | `crates/carrick-vmm-bhyve` | **HOST/VMM** | FreeBSD bhyve hypervisor backend |
| `carrick-vmm-hvf` | `crates/carrick-vmm-hvf` | **HOST/VMM** | macOS Apple Silicon Hypervisor.framework (HVF) backend |
| `carrick-vmm-kvm` | `crates/carrick-vmm-kvm` | **HOST/VMM** | Linux KVM hypervisor backend |
| `carrick-vmm-nvmm` | `crates/carrick-vmm-nvmm` | **HOST/VMM** | NetBSD NVMM hypervisor backend |
| `carrick-x86` | `crates/carrick-x86` | **HOST/VMM** | Shared x86_64 VMM engine scaffold over `X86EngineCore` |
| `carrick-conformance` | `crates/carrick-conformance` | **TOOLING** | Differential conformance test runner comparing Carrick against Docker Linux oracle |
| `carrick-conformance-contract` | `crates/carrick-conformance-contract` | **TOOLING** | Conformance contract registry, structural work/timing budget models, personality boundary gate |
| `carrick-conformance-next` | `crates/carrick-conformance-next` | **TOOLING** | In-process embedded conformance test framework using `carrick-embed` |
| `carrick-coordinator` | `crates/carrick-coordinator` | **TOOLING** | Host-wide mutual exclusion lock coordinator between Carrick and Docker |
| `carrick-investigation` | `crates/carrick-investigation` | **TOOLING** | Event-sourced conformance test investigation and diagnostic engine |
| `carrick-kernel-example` | `crates/carrick-kernel-example` | **TOOLING** | VM-free scripted Linux task conformance test harness on host threads |
| `carrick-test-support` | `crates/carrick-test-support` | **TOOLING** | Shared integration test rootfs archive generators and fixtures |
| `carrick-xtask` | `crates/carrick-xtask` | **TOOLING** | Workspace development workflow tasks and maintenance scripts |
| `carrick-el1` | `crates/carrick-el1` | **MIXED** | In-guest EL1 kernel image containing both substrate mechanisms (alloc, cow, fault, lock, memory) and Linux personality (dispatch, file, inotify, sched) |
| `carrick-el1-abi` | `crates/carrick-el1-abi` | **MIXED** | Shared EL1 ABI definitions, mailboxes, wait queues, descriptor transactions, IPC directory, with epoll readiness |
| `carrick-el1-image` | `crates/carrick-el1-image` | **MIXED** | Embedded binary image artifact container for the mixed `carrick-el1` guest kernel |
| `carrick-embed` | `crates/carrick-embed` | **MIXED** | Library embedding surface (`ContainerBuilder`, `PreparedRun`), exposing futex contracts, shared buffer futexes, and Linux VFS configuration |
| `carrick-engine` | `crates/carrick-engine` | **MIXED** | Docker-style container run request merge layer, resolving CLI flags and image configs into `RunSpec` |
| `carrick-fd-core` | `crates/carrick-fd-core` | **MIXED** | Descriptor authority core acting as a Linux client: dense `Fd(i32)`, `TableId`, `dup2`/`dup3`, `fork`/`exec`, mutable status flags, CLOEXEC |
| `carrick-hal` | `crates/carrick-hal` | **MIXED** | Hardware abstraction layer traits, currently embedding `carrick-abi` wire structs, Linux sigframe injection, and futex keys |
| `carrick-inotify-core` | `crates/carrick-inotify-core` | **MIXED** | Core inotify ring buffer and watch allocation, embedding `LinuxErrno` and `LINUX_IN_*` constants |
| `carrick-kernel-arena` | `crates/carrick-kernel-arena` | **MIXED** | Shared memory arena and robust bucket locks, embedding Linux PID namespaces and process table records |
| `carrick-mem` | `crates/carrick-mem` | **MIXED** | Guest address space construction and page layout, hard-coding `LINUX_*` layout constants and ELF structures |
| `carrick-observability` | `crates/carrick-observability` | **MIXED** | Compat reporting and USDT/probe instrumentation, embedding Linux syscall tables, epoll probes, and host PIDs |
| `carrick-pipe-core` | `crates/carrick-pipe-core` | **MIXED** | Anonymous pipe buffer substrate acting as a Linux client: `EventFd`, `EVENTFD_MAX`, `broken_pipe_signal` requesting SIGPIPE |
| `carrick-runtime` | `crates/carrick-runtime` | **MIXED** | HVPatch VM carrier, vCPU loop, pty supervisor, threading loop, embedding Linux dispatcher calls and Rosetta paths |
| `carrick-sched-core` | `crates/carrick-sched-core` | **MIXED** | In-guest scheduling core with Linux client fields: `ThreadIdentity` carrying Linux tid and `file_table`, AArch64-shaped `ThreadCtx` |
| `carrick-spec` | `crates/carrick-spec` | **MIXED** | Shared container specification types (`RunSpec`, `ContainerSpec`), embedding Linux namespace configs and rlimits |
| `carrick-thread` | `crates/carrick-thread` | **MIXED** | Thread registry and futex park table, implementing Linux private futex operations (`FUTEX_WAIT`, `FUTEX_WAKE`, `FUTEX_REQUEUE`) and Linux thread IDs |
| `carrick-timer-core` | `crates/carrick-timer-core` | **MIXED** | Timer mechanism with Linux/POSIX policy: 3 fixed itimer slots (`src/itimer.rs`), `PosixTimerSpec` with `signum`/`si_value`, `OVERRUN_MAX` (`src/posix.rs`) |
| `carrick-vfs` | `crates/carrick-vfs` | **MIXED** | Filesystem model below the kernel (`Vfs`, `FsBackend`), embedding Linux errno mappings, stat structures, and synthetic /proc entries |

## Substrate Crates Census

Substrate crates are intended to be strictly personality-neutral. The following census lists all verified clean substrate crates (0 personality items) and details public types and functions where Linux concepts remain.

### `carrick-fatal` (SUBSTRATE)

**Linux Items Count:** 0.

Verified 100% personality-neutral. Contains no `carrick-abi` imports, `LINUX_*`/`SYS_*` constants, errno literals, signals, fd tables, clone flags, pid/tgid, futex ops, epoll, AF_UNIX, or /proc references in its public interface or production implementation. (Note: in `carrick-mmu-core`, stage-1 page size is explicitly 4 KiB via `PT_PAGE = 0x1000`).

### `carrick-guest-arch` (SUBSTRATE)

**Linux Items Count:** 0.

Verified 100% personality-neutral. Contains no `carrick-abi` imports, `LINUX_*`/`SYS_*` constants, errno literals, signals, fd tables, clone flags, pid/tgid, futex ops, epoll, AF_UNIX, or /proc references in its public interface or production implementation. (Note: in `carrick-mmu-core`, stage-1 page size is explicitly 4 KiB via `PT_PAGE = 0x1000`).

### `carrick-image` (SUBSTRATE)

**Linux Items Count:** 0.

Verified 100% personality-neutral. Contains no `carrick-abi` imports, `LINUX_*`/`SYS_*` constants, errno literals, signals, fd tables, clone flags, pid/tgid, futex ops, epoll, AF_UNIX, or /proc references in its public interface or production implementation. (Note: in `carrick-mmu-core`, stage-1 page size is explicitly 4 KiB via `PT_PAGE = 0x1000`).

### `carrick-mmu-core` (SUBSTRATE)

**Linux Items Count:** 0.

Verified 100% personality-neutral. Contains no `carrick-abi` imports, `LINUX_*`/`SYS_*` constants, errno literals, signals, fd tables, clone flags, pid/tgid, futex ops, epoll, AF_UNIX, or /proc references in its public interface or production implementation. (Note: in `carrick-mmu-core`, stage-1 page size is explicitly 4 KiB via `PT_PAGE = 0x1000`).

### `carrick-guest-mem` (SUBSTRATE)

**Linux Items Count:** 3.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-guest-mem/src/lib.rs:489`](crates/carrick-guest-mem/src/lib.rs#L489) | `trait` | `GuestMemory` | futex ops | futex ops: ['shared_futex_location'] |
| [`crates/carrick-guest-mem/src/lib.rs:92`](crates/carrick-guest-mem/src/lib.rs#L92) | `struct` | `Aarch64SyscallFrame` | carrick-abi | carrick-abi: ['Linux AArch64 syscall registers (x8, x0-x5)'] |
| [`crates/carrick-guest-mem/src/lib.rs:108`](crates/carrick-guest-mem/src/lib.rs#L108) | `struct` | `X8664SyscallFrame` | carrick-abi | carrick-abi: ['Linux x86_64 syscall registers (rax, rdi, rsi, rdx, r10, r8, r9)'] |

## Mixed Crates Census

Mixed crates contain runtime or substrate mechanisms that currently embed Linux personality types, wire constants, client bindings, or syscall dispatch interfaces. Each public type and function naming a Linux concept is inventoried below.

### `carrick-el1` (MIXED)

**Linux Items Count:** 36.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-el1/src/memory.rs:133`](crates/carrick-el1/src/memory.rs#L133) | `fn` | `refuse` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['SYS_BRK'], errno: ['ENOMEM'] |
| [`crates/carrick-el1/src/memory.rs:166`](crates/carrick-el1/src/memory.rs#L166) | `fn` | `decide_anonymous_syscall` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['SYS_MPROTECT', 'SYS_BRK', 'SYS_MMAP'], errno: ['ENOMEM', 'EINVAL'] |
| [`crates/carrick-el1/src/memory.rs:534`](crates/carrick-el1/src/memory.rs#L534) | `fn` | `serve_delegated_anonymous` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_MPROTECT', 'SYS_BRK', 'SYS_MMAP'] |
| [`crates/carrick-el1/src/memory.rs:685`](crates/carrick-el1/src/memory.rs#L685) | `fn` | `try_serve_munmap` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['SYS_MUNMAP'], errno: ['ENOMEM', 'EINVAL'] |
| [`crates/carrick-el1/src/memory.rs:744`](crates/carrick-el1/src/memory.rs#L744) | `fn` | `try_serve_mprotect` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['SYS_MPROTECT'], errno: ['EINVAL'] |
| [`crates/carrick-el1/src/personality/common_entry.rs:35`](crates/carrick-el1/src/personality/common_entry.rs#L35) | `fn` | `serve_canonical` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_SET_ROBUST_LIST'] |
| [`crates/carrick-el1/src/personality/dispatch.rs:259`](crates/carrick-el1/src/personality/dispatch.rs#L259) | `fn` | `dispatch_syscall_with_lifecycle` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_EPOLL_PWAIT', 'SYS_RT_SIGPROCMASK', 'SYS_WRITE'] |
| [`crates/carrick-el1/src/personality/file.rs:12`](crates/carrick-el1/src/personality/file.rs#L12) | `const` | `EBADF` | errno | errno: ['EBADF'] |
| [`crates/carrick-el1/src/personality/file.rs:13`](crates/carrick-el1/src/personality/file.rs#L13) | `const` | `EFAULT` | errno | errno: ['EFAULT'] |
| [`crates/carrick-el1/src/personality/file.rs:14`](crates/carrick-el1/src/personality/file.rs#L14) | `const` | `EINVAL` | errno | errno: ['EINVAL'] |
| [`crates/carrick-el1/src/personality/file.rs:15`](crates/carrick-el1/src/personality/file.rs#L15) | `const` | `EFBIG` | errno | errno: ['EFBIG'] |
| [`crates/carrick-el1/src/personality/file.rs:16`](crates/carrick-el1/src/personality/file.rs#L16) | `const` | `ESPIPE` | errno | errno: ['ESPIPE'] |
| [`crates/carrick-el1/src/personality/file.rs:34`](crates/carrick-el1/src/personality/file.rs#L34) | `fn` | `el1_lseek` | errno | errno: ['EINVAL'] |
| [`crates/carrick-el1/src/personality/inotify.rs:20`](crates/carrick-el1/src/personality/inotify.rs#L20) | `const` | `UNSUPPORTED_INOTIFY_MASK_FLAGS` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_MASK_ADD', 'LINUX_IN_MASK_CREATE', 'LINUX_IN_ONLYDIR'] |
| [`crates/carrick-el1/src/personality/inotify.rs:110`](crates/carrick-el1/src/personality/inotify.rs#L110) | `fn` | `el1_inotify_rm_watch` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_IGNORED'] |
| [`crates/carrick-el1/src/personality/ipc.rs:60`](crates/carrick-el1/src/personality/ipc.rs#L60) | `const` | `SYS_READ` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_READ'] |
| [`crates/carrick-el1/src/personality/ipc.rs:61`](crates/carrick-el1/src/personality/ipc.rs#L61) | `const` | `SYS_WRITE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_WRITE'] |
| [`crates/carrick-el1/src/personality/ipc.rs:62`](crates/carrick-el1/src/personality/ipc.rs#L62) | `const` | `EBADF` | errno | errno: ['EBADF'] |
| [`crates/carrick-el1/src/personality/ipc.rs:63`](crates/carrick-el1/src/personality/ipc.rs#L63) | `const` | `EAGAIN` | errno | errno: ['EAGAIN'] |
| [`crates/carrick-el1/src/personality/ipc.rs:64`](crates/carrick-el1/src/personality/ipc.rs#L64) | `const` | `EINVAL` | errno | errno: ['EINVAL'] |
| [`crates/carrick-el1/src/personality/ipc.rs:65`](crates/carrick-el1/src/personality/ipc.rs#L65) | `const` | `EPIPE` | errno | errno: ['EPIPE'] |
| [`crates/carrick-el1/src/personality/ipc.rs:185`](crates/carrick-el1/src/personality/ipc.rs#L185) | `fn` | `serve_ipc` | LINUX_*/SYS_*, epoll | LINUX_*/SYS_*: ['SYS_EPOLL_PWAIT', 'SYS_WRITE', 'SYS_READ'], epoll: ['epoll', 'EpollWait'] |
| [`crates/carrick-el1/src/personality/ipc/epoll.rs:51`](crates/carrick-el1/src/personality/ipc/epoll.rs#L51) | `const` | `SYS_EPOLL_PWAIT` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_EPOLL_PWAIT'] |
| [`crates/carrick-el1/src/personality/lifecycle.rs:40`](crates/carrick-el1/src/personality/lifecycle.rs#L40) | `const` | `SYS_EXIT` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_EXIT'] |
| [`crates/carrick-el1/src/personality/lifecycle.rs:41`](crates/carrick-el1/src/personality/lifecycle.rs#L41) | `const` | `SYS_SIGALTSTACK` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_SIGALTSTACK'] |
| [`crates/carrick-el1/src/personality/lifecycle.rs:42`](crates/carrick-el1/src/personality/lifecycle.rs#L42) | `const` | `SYS_RT_SIGPROCMASK` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_RT_SIGPROCMASK'] |
| [`crates/carrick-el1/src/personality/lifecycle.rs:43`](crates/carrick-el1/src/personality/lifecycle.rs#L43) | `const` | `SYS_GETTID` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_GETTID'] |
| [`crates/carrick-el1/src/personality/lifecycle.rs:44`](crates/carrick-el1/src/personality/lifecycle.rs#L44) | `const` | `SYS_CLONE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_CLONE'] |
| [`crates/carrick-el1/src/personality/lifecycle.rs:108`](crates/carrick-el1/src/personality/lifecycle.rs#L108) | `const fn` | `is_lifecycle_syscall` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_RT_SIGPROCMASK', 'SYS_GETTID', 'SYS_EXIT'] |
| [`crates/carrick-el1/src/personality/lifecycle.rs:123`](crates/carrick-el1/src/personality/lifecycle.rs#L123) | `fn` | `serve` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_RT_SIGPROCMASK', 'SYS_GETTID', 'SYS_EXIT'] |
| [`crates/carrick-el1/src/personality/sched.rs:5`](crates/carrick-el1/src/personality/sched.rs#L5) | `const` | `SYS_FUTEX` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_FUTEX'] |
| [`crates/carrick-el1/src/personality/sched.rs:16`](crates/carrick-el1/src/personality/sched.rs#L16) | `fn` | `is_served_futex_op` | LINUX_*/SYS_*, futex ops | LINUX_*/SYS_*: ['SYS_FUTEX'], futex ops: ['FUTEX_WAIT_BITSET_PRIVATE', 'FUTEX_WAKE_BITSET_PRIVATE', 'FUTEX_WAIT_PRIVATE'] |
| [`crates/carrick-el1/src/personality/sched.rs:31`](crates/carrick-el1/src/personality/sched.rs#L31) | `fn` | `serve_futex` | futex ops | futex ops: ['FUTEX_WAIT_BITSET_PRIVATE', 'FUTEX_WAKE_BITSET_PRIVATE', 'FUTEX_WAIT_PRIVATE'] |
| [`crates/carrick-el1/src/personality/thread_setup.rs:14`](crates/carrick-el1/src/personality/thread_setup.rs#L14) | `const` | `SYS_SET_ROBUST_LIST` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_SET_ROBUST_LIST'] |
| [`crates/carrick-el1/src/personality/thread_setup.rs:111`](crates/carrick-el1/src/personality/thread_setup.rs#L111) | `const fn` | `linux_result` | errno | errno: ['EINVAL'] |
| [`crates/carrick-el1/src/substrate/ipc.rs:123`](crates/carrick-el1/src/substrate/ipc.rs#L123) | `fn` | `transfer` | epoll | epoll: ['EpollWait'] |

### `carrick-el1-abi` (MIXED)

**Linux Items Count:** 50.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-el1-abi/src/ipc.rs:273`](crates/carrick-el1-abi/src/ipc.rs#L273) | `enum` | `IpcBacking` | epoll | epoll: ['Epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:302`](crates/carrick-el1-abi/src/ipc.rs#L302) | `const fn` | `encode` | epoll | epoll: ['Epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:317`](crates/carrick-el1-abi/src/ipc.rs#L317) | `const fn` | `decode` | epoll | epoll: ['Epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:351`](crates/carrick-el1-abi/src/ipc.rs#L351) | `enum` | `IpcObjectKind` | epoll | epoll: ['Epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:388`](crates/carrick-el1-abi/src/ipc.rs#L388) | `struct` | `IpcObjectState` | epoll | epoll: ['EpollState', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:398`](crates/carrick-el1-abi/src/ipc.rs#L398) | `struct` | `IpcObjectRecord` | epoll | epoll: ['epoll_link'] |
| [`crates/carrick-el1-abi/src/ipc.rs:493`](crates/carrick-el1-abi/src/ipc.rs#L493) | `const` | `IPC_DIRECTORY_BYTES` | epoll | epoll: ['epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:613`](crates/carrick-el1-abi/src/ipc.rs#L613) | `enum` | `IpcOpKind` | epoll | epoll: ['EpollWait'] |
| [`crates/carrick-el1-abi/src/ipc.rs:829`](crates/carrick-el1-abi/src/ipc.rs#L829) | `enum` | `IpcError` | fd tables/Fd | fd tables/Fd: ['Fd'] |
| [`crates/carrick-el1-abi/src/ipc.rs:935`](crates/carrick-el1-abi/src/ipc.rs#L935) | `unsafe fn` | `initialize` | fd tables/Fd, epoll | fd tables/Fd: ['Fd'], epoll: ['epoll_item_at', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:1173`](crates/carrick-el1-abi/src/ipc.rs#L1173) | `fn` | `grow_ofds` | fd tables/Fd | fd tables/Fd: ['Fd'] |
| [`crates/carrick-el1-abi/src/ipc.rs:1236`](crates/carrick-el1-abi/src/ipc.rs#L1236) | `fn` | `write_object_census` | epoll | epoll: ['Epoll', 'epoll_census', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:1483`](crates/carrick-el1-abi/src/ipc.rs#L1483) | `fn` | `release_backing` | epoll | epoll: ['Epoll', 'epoll_destroy'] |
| [`crates/carrick-el1-abi/src/ipc.rs:1776`](crates/carrick-el1-abi/src/ipc.rs#L1776) | `struct` | `IpcWake` | epoll | epoll: ['EpollWakes', 'epolls', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:1789`](crates/carrick-el1-abi/src/ipc.rs#L1789) | `enum` | `IpcReleased` | epoll | epoll: ['Epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:1815`](crates/carrick-el1-abi/src/ipc.rs#L1815) | `fn` | `kind` | epoll | epoll: ['Epoll'] |
| [`crates/carrick-el1-abi/src/ipc.rs:2002`](crates/carrick-el1-abi/src/ipc.rs#L2002) | `fn` | `publish` | epoll | epoll: ['Epoll', 'EpollWakes', 'epolls'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:100`](crates/carrick-el1-abi/src/ipc/epoll.rs#L100) | `enum` | `EpollMember` | epoll | epoll: ['EpollMember'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:115`](crates/carrick-el1-abi/src/ipc/epoll.rs#L115) | `const fn` | `of_backing` | epoll | epoll: ['Epoll'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:134`](crates/carrick-el1-abi/src/ipc/epoll.rs#L134) | `struct` | `EpollState` | epoll | epoll: ['EpollState'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:163`](crates/carrick-el1-abi/src/ipc/epoll.rs#L163) | `struct` | `IpcEpollItem` | epoll | epoll: ['epoll'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:196`](crates/carrick-el1-abi/src/ipc/epoll.rs#L196) | `struct` | `EpollItemRef` | epoll | epoll: ['EpollItemRef'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:203`](crates/carrick-el1-abi/src/ipc/epoll.rs#L203) | `struct` | `EpollReport` | epoll | epoll: ['EpollReport'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:212`](crates/carrick-el1-abi/src/ipc/epoll.rs#L212) | `enum` | `EpollCtlError` | epoll | epoll: ['EpollCtlError'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:240`](crates/carrick-el1-abi/src/ipc/epoll.rs#L240) | `struct` | `EpollWakes` | epoll | epoll: ['epolls', 'EpollWakes'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:245`](crates/carrick-el1-abi/src/ipc/epoll.rs#L245) | `const` | `EMPTY` | epoll | epoll: ['epolls'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:264`](crates/carrick-el1-abi/src/ipc/epoll.rs#L264) | `fn` | `iter` | epoll | epoll: ['epolls'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:273`](crates/carrick-el1-abi/src/ipc/epoll.rs#L273) | `struct` | `EpollHarvest` | epoll | epoll: ['EpollHarvest'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:343`](crates/carrick-el1-abi/src/ipc/epoll.rs#L343) | `fn` | `create_epoll` | epoll | epoll: ['EpollState', 'epoll_link', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:370`](crates/carrick-el1-abi/src/ipc/epoll.rs#L370) | `fn` | `epoll_add` | epoll | epoll: ['EpollMember', 'epoll_guard', 'epoll_link'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:449`](crates/carrick-el1-abi/src/ipc/epoll.rs#L449) | `fn` | `epoll_modify` | epoll | epoll: ['EpollMember', 'epoll_guard', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:498`](crates/carrick-el1-abi/src/ipc/epoll.rs#L498) | `fn` | `epoll_delete` | epoll | epoll: ['EpollCtlError', 'epoll_delete', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:534`](crates/carrick-el1-abi/src/ipc/epoll.rs#L534) | `fn` | `epoll_detach_file` | epoll | epoll: ['epoll_detach_file'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:558`](crates/carrick-el1-abi/src/ipc/epoll.rs#L558) | `fn` | `epoll_destroy` | epoll | epoll: ['epoll_destroy', 'epoll_link', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:611`](crates/carrick-el1-abi/src/ipc/epoll.rs#L611) | `fn` | `epoll_set_host_items` | epoll | epoll: ['epoll_set_host_items', 'epoll_state', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:623`](crates/carrick-el1-abi/src/ipc/epoll.rs#L623) | `fn` | `epoll_zone_items` | epoll | epoll: ['epoll_state', 'epoll', 'epoll_zone_items'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:634`](crates/carrick-el1-abi/src/ipc/epoll.rs#L634) | `fn` | `epoll_has_item_fd` | epoll | epoll: ['epoll_state', 'epoll_has_item_fd', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:652`](crates/carrick-el1-abi/src/ipc/epoll.rs#L652) | `fn` | `epoll_host_items` | epoll | epoll: ['epoll_host_items', 'epoll_state', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:665`](crates/carrick-el1-abi/src/ipc/epoll.rs#L665) | `fn` | `epoll_harvest` | epoll | epoll: ['EpollMember', 'EpollItemRef', 'EpollReport'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:821`](crates/carrick-el1-abi/src/ipc/epoll.rs#L821) | `fn` | `epoll_restore` | epoll | epoll: ['epoll_restore', 'EpollItemRef', 'epoll'] |
| [`crates/carrick-el1-abi/src/ipc/epoll.rs:844`](crates/carrick-el1-abi/src/ipc/epoll.rs#L844) | `fn` | `epoll_ready_probe` | epoll | epoll: ['epoll_ready_probe', 'EpollMember', 'EpollItemRef'] |
| [`crates/carrick-el1-abi/src/lib.rs:215`](crates/carrick-el1-abi/src/lib.rs#L215) | `const` | `SYS_CARRICK_EL1_CONTROL` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_CARRICK_EL1_CONTROL'] |
| [`crates/carrick-el1-abi/src/lib.rs:365`](crates/carrick-el1-abi/src/lib.rs#L365) | `const` | `EL1_ABI_LAYOUT_HASH` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['SYS_CARRICK_EL1_CONTROL'] |
| [`crates/carrick-el1-abi/src/lib.rs:2535`](crates/carrick-el1-abi/src/lib.rs#L2535) | `enum` | `IpcLeave` | epoll | epoll: ['EpollTimedWait', 'EpollHostItems', 'EpollSigmask'] |
| [`crates/carrick-el1-abi/src/lib.rs:3481`](crates/carrick-el1-abi/src/lib.rs#L3481) | `fn` | `alloc_wd` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-el1-abi/src/lib.rs:3578`](crates/carrick-el1-abi/src/lib.rs#L3578) | `fn` | `drain_into` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-el1-abi/src/thread_lifecycle.rs:339`](crates/carrick-el1-abi/src/thread_lifecycle.rs#L339) | `struct` | `BornRecord` | clone flags | clone flags: ['clone_flags'] |
| [`crates/carrick-el1-abi/src/thread_lifecycle.rs:363`](crates/carrick-el1-abi/src/thread_lifecycle.rs#L363) | `struct` | `PoolEntry` | clone flags | clone flags: ['clone_flags'] |
| [`crates/carrick-el1-abi/src/thread_lifecycle.rs:1110`](crates/carrick-el1-abi/src/thread_lifecycle.rs#L1110) | `fn` | `record_born` | clone flags | clone flags: ['clone_flags'] |
| [`crates/carrick-el1-abi/src/thread_lifecycle.rs:1233`](crates/carrick-el1-abi/src/thread_lifecycle.rs#L1233) | `fn` | `born_record` | clone flags | clone flags: ['clone_flags'] |

### `carrick-el1-image` (MIXED)

**Linux Items Count:** 0.

Contains 0 exported public types or functions with Linux concepts (binary carrier image wrapper).

### `carrick-embed` (MIXED)

**Linux Items Count:** 20.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-embed/src/contracts.rs:68`](crates/carrick-embed/src/contracts.rs#L68) | `fn` | `run_futex_structural_contract` | futex ops | futex ops: ['futex'] |
| [`crates/carrick-embed/src/contracts.rs:155`](crates/carrick-embed/src/contracts.rs#L155) | `fn` | `run_futex_timing_contract` | futex ops | futex ops: ['futex_pingpong_progress', 'futex', 'futex_pingpong_p50_us'] |
| [`crates/carrick-embed/src/contracts.rs:218`](crates/carrick-embed/src/contracts.rs#L218) | `fn` | `futex_contention_contract` | futex ops | futex ops: ['futex', 'futex_contention_contract'] |
| [`crates/carrick-embed/src/contracts.rs:229`](crates/carrick-embed/src/contracts.rs#L229) | `fn` | `run_futex_requeue_structural_contract` | futex ops | futex ops: ['futex'] |
| [`crates/carrick-embed/src/contracts.rs:313`](crates/carrick-embed/src/contracts.rs#L313) | `fn` | `run_futex_requeue_timing_contract` | futex ops | futex ops: ['futex_requeue_progress', 'futex', 'futex_pingpong_p50_us'] |
| [`crates/carrick-embed/src/contracts.rs:373`](crates/carrick-embed/src/contracts.rs#L373) | `fn` | `futex_requeue_contract` | futex ops | futex ops: ['futex_requeue_contract', 'futex'] |
| [`crates/carrick-embed/src/shared_buffer.rs:24`](crates/carrick-embed/src/shared_buffer.rs#L24) | `enum` | `SharedBufferError` | futex ops | futex ops: ['futex'] |
| [`crates/carrick-embed/src/shared_buffer.rs:82`](crates/carrick-embed/src/shared_buffer.rs#L82) | `fn` | `new` | errno | errno: ['ENOMEM'] |
| [`crates/carrick-embed/src/shared_buffer.rs:342`](crates/carrick-embed/src/shared_buffer.rs#L342) | `fn` | `shared_futex_location` | futex ops | futex ops: ['futex_key', 'shared_futex_location'] |
| [`crates/carrick-embed/src/shared_buffer.rs:378`](crates/carrick-embed/src/shared_buffer.rs#L378) | `fn` | `futex_wait` | futex ops | futex ops: ['futex_wait', 'shared_futex_location'] |
| [`crates/carrick-embed/src/shared_buffer.rs:409`](crates/carrick-embed/src/shared_buffer.rs#L409) | `fn` | `futex_wake` | futex ops | futex ops: ['shared_futex_location', 'futex_wake'] |
| [`crates/carrick-embed/src/testing/invariants.rs:213`](crates/carrick-embed/src/testing/invariants.rs#L213) | `enum` | `ExitBudgetMatcher` | pid/tgid | pid/tgid: ['Pid'] |
| [`crates/carrick-embed/src/vfs.rs:246`](crates/carrick-embed/src/vfs.rs#L246) | `fn` | `add_file_with_metadata` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EISDIR', 'LINUX_EFBIG'] |
| [`crates/carrick-embed/src/vfs.rs:313`](crates/carrick-embed/src/vfs.rs#L313) | `fn` | `add_symlink` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EINVAL'] |
| [`crates/carrick-embed/src/vfs.rs:349`](crates/carrick-embed/src/vfs.rs#L349) | `fn` | `add_host_file_with_metadata` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EISDIR'] |
| [`crates/carrick-embed/src/vfs.rs:378`](crates/carrick-embed/src/vfs.rs#L378) | `fn` | `read_file_bytes` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EISDIR', 'LINUX_EIO', 'LINUX_ENOENT'] |
| [`crates/carrick-embed/src/vfs.rs:401`](crates/carrick-embed/src/vfs.rs#L401) | `fn` | `read_file_string` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EINVAL'] |
| [`crates/carrick-embed/src/vfs.rs:1187`](crates/carrick-embed/src/vfs.rs#L1187) | `type` | `AccessFilterFn` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-embed/src/vfs.rs:1232`](crates/carrick-embed/src/vfs.rs#L1232) | `fn` | `with_access_filter` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-embed/src/vfs.rs:1471`](crates/carrick-embed/src/vfs.rs#L1471) | `struct` | `VfsEvent` | errno | errno: ['LinuxErrno'] |

### `carrick-engine` (MIXED)

**Linux Items Count:** 2.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-engine/src/lib.rs:103`](crates/carrick-engine/src/lib.rs#L103) | `struct` | `RunRequest` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-engine/src/lib.rs:321`](crates/carrick-engine/src/lib.rs#L321) | `fn` | `resolve_run_spec` | carrick-abi, pid/tgid | carrick-abi: ['carrick_abi'], pid/tgid: ['pid'] |

### `carrick-fd-core` (MIXED)

**Linux Items Count:** 29.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-fd-core/src/lib.rs:36`](crates/carrick-fd-core/src/lib.rs#L36) | `struct` | `Fd` | fd tables/Fd | fd tables/Fd: ['Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:63`](crates/carrick-fd-core/src/lib.rs#L63) | `enum` | `Error` | fd tables/Fd | fd tables/Fd: ['BadFd'] |
| [`crates/carrick-fd-core/src/lib.rs:98`](crates/carrick-fd-core/src/lib.rs#L98) | `struct` | `TableId` | fd tables/Fd | fd tables/Fd: ['TableId'] |
| [`crates/carrick-fd-core/src/lib.rs:753`](crates/carrick-fd-core/src/lib.rs#L753) | `fn` | `install_pair` | fd tables/Fd | fd tables/Fd: ['Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:808`](crates/carrick-fd-core/src/lib.rs#L808) | `fn` | `transaction` | fd tables/Fd | fd tables/Fd: ['TableId'] |
| [`crates/carrick-fd-core/src/lib.rs:1102`](crates/carrick-fd-core/src/lib.rs#L1102) | `fn` | `create_table` | fd tables/Fd | fd tables/Fd: ['TableId'] |
| [`crates/carrick-fd-core/src/lib.rs:1124`](crates/carrick-fd-core/src/lib.rs#L1124) | `fn` | `set_limit` | fd tables/Fd | fd tables/Fd: ['TableId'] |
| [`crates/carrick-fd-core/src/lib.rs:1133`](crates/carrick-fd-core/src/lib.rs#L1133) | `fn` | `open` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1152`](crates/carrick-fd-core/src/lib.rs#L1152) | `fn` | `get` | fd tables/Fd | fd tables/Fd: ['TableId', 'BadFd', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1201`](crates/carrick-fd-core/src/lib.rs#L1201) | `fn` | `refcount` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1206`](crates/carrick-fd-core/src/lib.rs#L1206) | `fn` | `set_offset` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1212`](crates/carrick-fd-core/src/lib.rs#L1212) | `fn` | `getfd` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1216`](crates/carrick-fd-core/src/lib.rs#L1216) | `fn` | `setfd` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1223`](crates/carrick-fd-core/src/lib.rs#L1223) | `fn` | `getfl` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1231`](crates/carrick-fd-core/src/lib.rs#L1231) | `fn` | `setfl` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1254`](crates/carrick-fd-core/src/lib.rs#L1254) | `fn` | `dup` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1259`](crates/carrick-fd-core/src/lib.rs#L1259) | `fn` | `dupfd` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1288`](crates/carrick-fd-core/src/lib.rs#L1288) | `fn` | `dup2` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1297`](crates/carrick-fd-core/src/lib.rs#L1297) | `fn` | `dup3` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1350`](crates/carrick-fd-core/src/lib.rs#L1350) | `fn` | `close` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1358`](crates/carrick-fd-core/src/lib.rs#L1358) | `fn` | `close_range` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1388`](crates/carrick-fd-core/src/lib.rs#L1388) | `fn` | `unshare_close_range` | fd tables/Fd | fd tables/Fd: ['TableId'] |
| [`crates/carrick-fd-core/src/lib.rs:1407`](crates/carrick-fd-core/src/lib.rs#L1407) | `fn` | `grow_table` | fd tables/Fd | fd tables/Fd: ['TableId'] |
| [`crates/carrick-fd-core/src/lib.rs:1437`](crates/carrick-fd-core/src/lib.rs#L1437) | `fn` | `fork` | fd tables/Fd | fd tables/Fd: ['TableId'] |
| [`crates/carrick-fd-core/src/lib.rs:1483`](crates/carrick-fd-core/src/lib.rs#L1483) | `fn` | `exec` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1496`](crates/carrick-fd-core/src/lib.rs#L1496) | `fn` | `destroy_table` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1529`](crates/carrick-fd-core/src/lib.rs#L1529) | `fn` | `pin` | fd tables/Fd | fd tables/Fd: ['TableId', 'BadFd', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1619`](crates/carrick-fd-core/src/lib.rs#L1619) | `fn` | `install_pin` | fd tables/Fd | fd tables/Fd: ['TableId', 'BadFd', 'Fd'] |
| [`crates/carrick-fd-core/src/lib.rs:1655`](crates/carrick-fd-core/src/lib.rs#L1655) | `fn` | `replace_pin` | fd tables/Fd | fd tables/Fd: ['TableId', 'Fd'] |

### `carrick-hal` (MIXED)

**Linux Items Count:** 22.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-hal/src/futex.rs:74`](crates/carrick-hal/src/futex.rs#L74) | `fn` | `shared_wait_sliced` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_ETIMEDOUT', 'LINUX_EINTR'] |
| [`crates/carrick-hal/src/guest_arch.rs:84`](crates/carrick-hal/src/guest_arch.rs#L84) | `trait` | `GuestArch` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-hal/src/guest_timer_bridge.rs:350`](crates/carrick-hal/src/guest_timer_bridge.rs#L350) | `fn` | `itimer_signum_for` | carrick-abi, LINUX_*/SYS_* | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_SIGVTALRM', 'LINUX_SIGPROF', 'LINUX_SIGALRM'] |
| [`crates/carrick-hal/src/guest_timer_bridge.rs:360`](crates/carrick-hal/src/guest_timer_bridge.rs#L360) | `fn` | `is_thread_cpu_clock` | carrick-abi, LINUX_*/SYS_* | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_CLOCK_THREAD_CPUTIME_ID'] |
| [`crates/carrick-hal/src/guest_timer_bridge.rs:367`](crates/carrick-hal/src/guest_timer_bridge.rs#L367) | `fn` | `is_process_cpu_clock` | carrick-abi, LINUX_*/SYS_* | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_CLOCK_PROCESS_CPUTIME_ID'] |
| [`crates/carrick-hal/src/host_signal_bridge.rs:85`](crates/carrick-hal/src/host_signal_bridge.rs#L85) | `trait` | `HostSignalBridge` | signals/SigSet | signals/SigSet: ['SigSet', 'SigBlockMask'] |
| [`crates/carrick-hal/src/pump_fork_coord.rs:19`](crates/carrick-hal/src/pump_fork_coord.rs#L19) | `trait` | `HostSignalPump` | futex ops | futex ops: ['futex'] |
| [`crates/carrick-hal/src/sigframe.rs:30`](crates/carrick-hal/src/sigframe.rs#L30) | `struct` | `InjectParams` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-hal/src/sigframe.rs:88`](crates/carrick-hal/src/sigframe.rs#L88) | `fn` | `build_sigframe` | carrick-abi, LINUX_*/SYS_*, signals/SigSet | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_SI_USER', 'LINUX_SS_ONSTACK'], signals/SigSet: ['siginfo'] |
| [`crates/carrick-hal/src/sigframe.rs:390`](crates/carrick-hal/src/sigframe.rs#L390) | `fn` | `restore_sigframe` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-hal/src/signal_arrival.rs:33`](crates/carrick-hal/src/signal_arrival.rs#L33) | `struct` | `GenericSignalArrival` | futex ops | futex ops: ['futex'] |
| [`crates/carrick-hal/src/signal_pump.rs:111`](crates/carrick-hal/src/signal_pump.rs#L111) | `fn` | `block_pump_signals_for_fork` | signals/SigSet | signals/SigSet: ['sigset_t'] |
| [`crates/carrick-hal/src/signal_pump.rs:140`](crates/carrick-hal/src/signal_pump.rs#L140) | `fn` | `publish_exited_child_watches` | errno, pid/tgid | errno: ['ESRCH', 'ECHILD'], pid/tgid: ['pid'] |
| [`crates/carrick-hal/src/signal_pump.rs:336`](crates/carrick-hal/src/signal_pump.rs#L336) | `fn` | `start_pump` | futex ops | futex ops: ['futex'] |
| [`crates/carrick-hal/src/signal_pump.rs:360`](crates/carrick-hal/src/signal_pump.rs#L360) | `fn` | `reinit_after_fork` | futex ops | futex ops: ['futex'] |
| [`crates/carrick-hal/src/threaded.rs:1657`](crates/carrick-hal/src/threaded.rs#L1657) | `fn` | `standard_size_for` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-hal/src/threaded.rs:1691`](crates/carrick-hal/src/threaded.rs#L1691) | `trait` | `RegAccess` | carrick-abi, LINUX_*/SYS_*, errno | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_X8664_USER_DS', 'LINUX_X8664_USER_CS'], errno: ['EINVAL'] |
| [`crates/carrick-hal/src/threaded.rs:2372`](crates/carrick-hal/src/threaded.rs#L2372) | `const fn` | `guest_abi` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-hal/src/threaded.rs:3455`](crates/carrick-hal/src/threaded.rs#L3455) | `trait` | `SignalPumpControl` | futex ops | futex ops: ['futex'] |
| [`crates/carrick-hal/src/trap.rs:31`](crates/carrick-hal/src/trap.rs#L31) | `struct` | `RawSyscall` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-hal/src/x8664_arch.rs:267`](crates/carrick-hal/src/x8664_arch.rs#L267) | `fn` | `new` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL0_TRAMPOLINE_BASE'] |
| [`crates/carrick-hal/src/x8664_arch.rs:1105`](crates/carrick-hal/src/x8664_arch.rs#L1105) | `fn` | `normalize_syscall` | carrick-abi, LINUX_*/SYS_* | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_AT_REMOVEDIR', 'LINUX_AT_SYMLINK_NOFOLLOW', 'LINUX_SIGCHLD'] |

### `carrick-inotify-core` (MIXED)

**Linux Items Count:** 18.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-inotify-core/src/lib.rs:8`](crates/carrick-inotify-core/src/lib.rs#L8) | `const` | `LINUX_IN_Q_OVERFLOW` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_Q_OVERFLOW'] |
| [`crates/carrick-inotify-core/src/lib.rs:9`](crates/carrick-inotify-core/src/lib.rs#L9) | `const` | `LINUX_IN_MODIFY` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_MODIFY'] |
| [`crates/carrick-inotify-core/src/lib.rs:10`](crates/carrick-inotify-core/src/lib.rs#L10) | `const` | `LINUX_IN_IGNORED` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_IGNORED'] |
| [`crates/carrick-inotify-core/src/lib.rs:11`](crates/carrick-inotify-core/src/lib.rs#L11) | `const` | `LINUX_IN_ONLYDIR` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_ONLYDIR'] |
| [`crates/carrick-inotify-core/src/lib.rs:12`](crates/carrick-inotify-core/src/lib.rs#L12) | `const` | `LINUX_IN_DONT_FOLLOW` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_DONT_FOLLOW'] |
| [`crates/carrick-inotify-core/src/lib.rs:13`](crates/carrick-inotify-core/src/lib.rs#L13) | `const` | `LINUX_IN_EXCL_UNLINK` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_EXCL_UNLINK'] |
| [`crates/carrick-inotify-core/src/lib.rs:14`](crates/carrick-inotify-core/src/lib.rs#L14) | `const` | `LINUX_IN_MASK_CREATE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_MASK_CREATE'] |
| [`crates/carrick-inotify-core/src/lib.rs:15`](crates/carrick-inotify-core/src/lib.rs#L15) | `const` | `LINUX_IN_MASK_ADD` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_MASK_ADD'] |
| [`crates/carrick-inotify-core/src/lib.rs:16`](crates/carrick-inotify-core/src/lib.rs#L16) | `const` | `LINUX_IN_ONESHOT` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_ONESHOT'] |
| [`crates/carrick-inotify-core/src/lib.rs:20`](crates/carrick-inotify-core/src/lib.rs#L20) | `struct` | `LinuxErrno` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-inotify-core/src/lib.rs:28`](crates/carrick-inotify-core/src/lib.rs#L28) | `const` | `LINUX_EINVAL` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_EINVAL'], errno: ['LinuxErrno'] |
| [`crates/carrick-inotify-core/src/lib.rs:29`](crates/carrick-inotify-core/src/lib.rs#L29) | `const` | `LINUX_ENOSPC` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOSPC'], errno: ['LinuxErrno'] |
| [`crates/carrick-inotify-core/src/lib.rs:81`](crates/carrick-inotify-core/src/lib.rs#L81) | `fn` | `alloc_wd` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOSPC'], errno: ['LinuxErrno'] |
| [`crates/carrick-inotify-core/src/lib.rs:153`](crates/carrick-inotify-core/src/lib.rs#L153) | `fn` | `push` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_Q_OVERFLOW'] |
| [`crates/carrick-inotify-core/src/lib.rs:197`](crates/carrick-inotify-core/src/lib.rs#L197) | `fn` | `pop` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_Q_OVERFLOW'] |
| [`crates/carrick-inotify-core/src/lib.rs:215`](crates/carrick-inotify-core/src/lib.rs#L215) | `fn` | `drain_into` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_IN_Q_OVERFLOW', 'LINUX_EINVAL'], errno: ['LinuxErrno'] |
| [`crates/carrick-inotify-core/src/lib.rs:381`](crates/carrick-inotify-core/src/lib.rs#L381) | `fn` | `push` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IN_Q_OVERFLOW'] |
| [`crates/carrick-inotify-core/src/lib.rs:426`](crates/carrick-inotify-core/src/lib.rs#L426) | `fn` | `drain_into` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_EINVAL'], errno: ['LinuxErrno'] |

### `carrick-kernel-arena` (MIXED)

**Linux Items Count:** 8.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-kernel-arena/src/arena.rs:50`](crates/carrick-kernel-arena/src/arena.rs#L50) | `struct` | `ArenaLayout` | pid/tgid | pid/tgid: ['ProcessSection'] |
| [`crates/carrick-kernel-arena/src/arena.rs:88`](crates/carrick-kernel-arena/src/arena.rs#L88) | `fn` | `try_claim_slot` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-kernel-arena/src/lock.rs:25`](crates/carrick-kernel-arena/src/lock.rs#L25) | `struct` | `LockOwner` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-kernel-arena/src/process.rs:432`](crates/carrick-kernel-arena/src/process.rs#L432) | `struct` | `ProcessSection` | pid/tgid | pid/tgid: ['ProcessRecord', 'ProcessSection'] |
| [`crates/carrick-kernel-arena/src/process.rs:437`](crates/carrick-kernel-arena/src/process.rs#L437) | `struct` | `ProcessRecord` | pid/tgid | pid/tgid: ['ProcessRecord'] |
| [`crates/carrick-kernel-arena/src/process.rs:482`](crates/carrick-kernel-arena/src/process.rs#L482) | `fn` | `claim` | pid/tgid | pid/tgid: ['pid', 'ProcessRecord'] |
| [`crates/carrick-kernel-arena/src/process.rs:533`](crates/carrick-kernel-arena/src/process.rs#L533) | `fn` | `publish_host_pid` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-kernel-arena/src/process.rs:588`](crates/carrick-kernel-arena/src/process.rs#L588) | `fn` | `with_record_transition` | pid/tgid | pid/tgid: ['ProcessRecord'] |

### `carrick-mem` (MIXED)

**Linux Items Count:** 109.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-mem/src/elf.rs:24`](crates/carrick-mem/src/elf.rs#L24) | `const` | `LINUX_PIE_DEFAULT_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_PIE_DEFAULT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:137`](crates/carrick-mem/src/memory.rs#L137) | `const` | `LINUX_EL0_CLOCK_STUB_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL0_CLOCK_STUB_BASE'] |
| [`crates/carrick-mem/src/memory.rs:138`](crates/carrick-mem/src/memory.rs#L138) | `const` | `LINUX_EL0_CLOCK_STUB_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL0_CLOCK_STUB_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:149`](crates/carrick-mem/src/memory.rs#L149) | `fn` | `clock_handler_layout` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_VECTORS_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:177`](crates/carrick-mem/src/memory.rs#L177) | `fn` | `is_carrick_el0_clock_stub_va` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL0_CLOCK_STUB_BASE', 'LINUX_EL0_CLOCK_STUB_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:222`](crates/carrick-mem/src/memory.rs#L222) | `const` | `LINUX_KERNEL_REGION_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_KERNEL_REGION_BASE'] |
| [`crates/carrick-mem/src/memory.rs:224`](crates/carrick-mem/src/memory.rs#L224) | `const` | `LINUX_KERNEL_REGION_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_KERNEL_REGION_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:231`](crates/carrick-mem/src/memory.rs#L231) | `const` | `LINUX_NULL_GUARD_END` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_NULL_GUARD_END'] |
| [`crates/carrick-mem/src/memory.rs:232`](crates/carrick-mem/src/memory.rs#L232) | `const` | `LINUX_EL0_TRAMPOLINE_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_KERNEL_REGION_BASE', 'LINUX_EL0_TRAMPOLINE_BASE'] |
| [`crates/carrick-mem/src/memory.rs:236`](crates/carrick-mem/src/memory.rs#L236) | `const` | `LINUX_EL0_TRAMPOLINE_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL0_TRAMPOLINE_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:241`](crates/carrick-mem/src/memory.rs#L241) | `const` | `LINUX_EL1_VECTORS_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_KERNEL_REGION_BASE', 'LINUX_EL1_VECTORS_BASE'] |
| [`crates/carrick-mem/src/memory.rs:242`](crates/carrick-mem/src/memory.rs#L242) | `const` | `LINUX_EL1_VECTORS_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_VECTORS_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:253`](crates/carrick-mem/src/memory.rs#L253) | `const` | `LINUX_PAGE_TABLES_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_PAGE_TABLES_BASE'] |
| [`crates/carrick-mem/src/memory.rs:267`](crates/carrick-mem/src/memory.rs#L267) | `const` | `LINUX_PAGE_TABLES_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_PAGE_TABLES_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:276`](crates/carrick-mem/src/memory.rs#L276) | `const` | `LINUX_EL1_MAINT_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_KERNEL_REGION_BASE', 'LINUX_EL1_MAINT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:277`](crates/carrick-mem/src/memory.rs#L277) | `const` | `LINUX_EL1_MAINT_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_MAINT_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:278`](crates/carrick-mem/src/memory.rs#L278) | `const` | `LINUX_EL1_ASID_MAINT_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_MAINT_BASE', 'LINUX_EL1_ASID_MAINT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:302`](crates/carrick-mem/src/memory.rs#L302) | `const` | `LINUX_IDENTITY_PAGE_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_MAINT_SIZE', 'LINUX_IDENTITY_PAGE_BASE', 'LINUX_EL1_MAINT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:303`](crates/carrick-mem/src/memory.rs#L303) | `const` | `LINUX_IDENTITY_PAGE_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IDENTITY_PAGE_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:304`](crates/carrick-mem/src/memory.rs#L304) | `const` | `LINUX_SYSCALL_MAILBOX_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IDENTITY_PAGE_SIZE', 'LINUX_SYSCALL_MAILBOX_BASE', 'LINUX_IDENTITY_PAGE_BASE'] |
| [`crates/carrick-mem/src/memory.rs:305`](crates/carrick-mem/src/memory.rs#L305) | `const` | `LINUX_SYSCALL_MAILBOX_ARENA_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SYSCALL_MAILBOX_ARENA_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:306`](crates/carrick-mem/src/memory.rs#L306) | `const` | `LINUX_SYSCALL_MAILBOX_SLOT_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SYSCALL_MAILBOX_SLOT_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:308`](crates/carrick-mem/src/memory.rs#L308) | `const` | `LINUX_SYSCALL_MAILBOX_SLOTS` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SYSCALL_MAILBOX_SLOTS'] |
| [`crates/carrick-mem/src/memory.rs:384`](crates/carrick-mem/src/memory.rs#L384) | `const` | `LINUX_CARRIER_MAINT_ROOT_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SYSCALL_MAILBOX_ARENA_SIZE', 'LINUX_SYSCALL_MAILBOX_BASE', 'LINUX_CARRIER_MAINT_ROOT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:386`](crates/carrick-mem/src/memory.rs#L386) | `const` | `LINUX_CARRIER_MAINT_ROOT_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_CARRIER_MAINT_ROOT_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:398`](crates/carrick-mem/src/memory.rs#L398) | `const` | `LINUX_FD_CEILING_CONTROL_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_FD_CEILING_CONTROL_BASE', 'LINUX_CARRIER_MAINT_ROOT_SIZE', 'LINUX_CARRIER_MAINT_ROOT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:400`](crates/carrick-mem/src/memory.rs#L400) | `const` | `LINUX_FD_CEILING_CONTROL_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_FD_CEILING_CONTROL_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:401`](crates/carrick-mem/src/memory.rs#L401) | `const` | `LINUX_FD_CEILING_OFF_CEILING` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_FD_CEILING_OFF_CEILING'] |
| [`crates/carrick-mem/src/memory.rs:402`](crates/carrick-mem/src/memory.rs#L402) | `const` | `LINUX_FD_CEILING_OFF_GATE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_FD_CEILING_OFF_GATE'] |
| [`crates/carrick-mem/src/memory.rs:465`](crates/carrick-mem/src/memory.rs#L465) | `const` | `LINUX_SIGRETURN_TRAMPOLINE_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SIGRETURN_TRAMPOLINE_BASE'] |
| [`crates/carrick-mem/src/memory.rs:466`](crates/carrick-mem/src/memory.rs#L466) | `const` | `LINUX_SIGRETURN_TRAMPOLINE_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SIGRETURN_TRAMPOLINE_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:473`](crates/carrick-mem/src/memory.rs#L473) | `const fn` | `is_carrick_kernel_only_range` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_KERNEL_REGION_BASE', 'LINUX_EL1_KERNEL_BASE', 'LINUX_KERNEL_REGION_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:494`](crates/carrick-mem/src/memory.rs#L494) | `fn` | `is_carrick_el1_vector_va` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_VECTORS_BASE', 'LINUX_EL1_VECTORS_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:593`](crates/carrick-mem/src/memory.rs#L593) | `const` | `LINUX_HEAP_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HEAP_BASE'] |
| [`crates/carrick-mem/src/memory.rs:594`](crates/carrick-mem/src/memory.rs#L594) | `const` | `LINUX_HEAP_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HEAP_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:595`](crates/carrick-mem/src/memory.rs#L595) | `const` | `LINUX_MMAP_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_MMAP_BASE'] |
| [`crates/carrick-mem/src/memory.rs:605`](crates/carrick-mem/src/memory.rs#L605) | `const` | `LINUX_MMAP_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_MMAP_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:613`](crates/carrick-mem/src/memory.rs#L613) | `const` | `LINUX_INTERPRETER_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_INTERPRETER_BASE'] |
| [`crates/carrick-mem/src/memory.rs:618`](crates/carrick-mem/src/memory.rs#L618) | `const` | `LINUX_MMAP_SIZE_MAX` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_PIE_DEFAULT_BASE', 'LINUX_MMAP_BASE', 'LINUX_MMAP_SIZE_MAX'] |
| [`crates/carrick-mem/src/memory.rs:661`](crates/carrick-mem/src/memory.rs#L661) | `fn` | `hvf_default` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HEAP_BASE', 'LINUX_MMAP_BASE', 'LINUX_HEAP_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:675`](crates/carrick-mem/src/memory.rs#L675) | `const` | `LINUX_SHARED_FILE_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SHARED_FILE_BASE'] |
| [`crates/carrick-mem/src/memory.rs:676`](crates/carrick-mem/src/memory.rs#L676) | `const` | `LINUX_SHARED_FILE_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SHARED_FILE_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:686`](crates/carrick-mem/src/memory.rs#L686) | `const` | `LINUX_PRIVATE_OVERLAY_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_PRIVATE_OVERLAY_BASE'] |
| [`crates/carrick-mem/src/memory.rs:687`](crates/carrick-mem/src/memory.rs#L687) | `const` | `LINUX_PRIVATE_OVERLAY_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_PRIVATE_OVERLAY_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:693`](crates/carrick-mem/src/memory.rs#L693) | `const` | `LINUX_HVPATCH_ROOT_SLOT_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HVPATCH_ROOT_SLOT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:694`](crates/carrick-mem/src/memory.rs#L694) | `const` | `LINUX_HVPATCH_ROOT_SLOT_ARENA_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HVPATCH_ROOT_SLOT_ARENA_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:695`](crates/carrick-mem/src/memory.rs#L695) | `const` | `LINUX_HVPATCH_GLOBAL_FRAME_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HVPATCH_ROOT_SLOT_ARENA_SIZE', 'LINUX_HVPATCH_GLOBAL_FRAME_BASE', 'LINUX_HVPATCH_ROOT_SLOT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:697`](crates/carrick-mem/src/memory.rs#L697) | `const` | `LINUX_HVPATCH_GLOBAL_FRAME_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HVPATCH_GLOBAL_FRAME_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:698`](crates/carrick-mem/src/memory.rs#L698) | `const` | `LINUX_HVPATCH_RESERVED_END` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HVPATCH_GLOBAL_FRAME_BASE', 'LINUX_HVPATCH_RESERVED_END', 'LINUX_HVPATCH_GLOBAL_FRAME_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:710`](crates/carrick-mem/src/memory.rs#L710) | `fn` | `va_in_shared_aperture` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SHARED_FILE_BASE', 'LINUX_SHARED_FILE_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:744`](crates/carrick-mem/src/memory.rs#L744) | `const` | `LINUX_STACK_TOP` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_STACK_TOP'] |
| [`crates/carrick-mem/src/memory.rs:757`](crates/carrick-mem/src/memory.rs#L757) | `const` | `LINUX_RLIMIT_STACK_SOFT` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_RLIMIT_STACK_SOFT'] |
| [`crates/carrick-mem/src/memory.rs:758`](crates/carrick-mem/src/memory.rs#L758) | `const` | `LINUX_STACK_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_STACK_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:768`](crates/carrick-mem/src/memory.rs#L768) | `const` | `LINUX_ROSETTA_VA_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_ROSETTA_VA_BASE'] |
| [`crates/carrick-mem/src/memory.rs:769`](crates/carrick-mem/src/memory.rs#L769) | `const` | `LINUX_ROSETTA_IPA_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_ROSETTA_IPA_BASE'] |
| [`crates/carrick-mem/src/memory.rs:770`](crates/carrick-mem/src/memory.rs#L770) | `const` | `LINUX_ROSETTA_WINDOW_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_ROSETTA_WINDOW_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:773`](crates/carrick-mem/src/memory.rs#L773) | `fn` | `is_rosetta_va` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_ROSETTA_WINDOW_SIZE', 'LINUX_ROSETTA_VA_BASE'] |
| [`crates/carrick-mem/src/memory.rs:785`](crates/carrick-mem/src/memory.rs#L785) | `const` | `LINUX_HIGH_VA_THRESHOLD` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HIGH_VA_THRESHOLD'] |
| [`crates/carrick-mem/src/memory.rs:788`](crates/carrick-mem/src/memory.rs#L788) | `const` | `LINUX_ALIAS_IPA_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_ALIAS_IPA_BASE'] |
| [`crates/carrick-mem/src/memory.rs:789`](crates/carrick-mem/src/memory.rs#L789) | `const` | `LINUX_ALIAS_IPA_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_ALIAS_IPA_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:791`](crates/carrick-mem/src/memory.rs#L791) | `const` | `LINUX_EL1_KERNEL_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_KERNEL_BASE'] |
| [`crates/carrick-mem/src/memory.rs:792`](crates/carrick-mem/src/memory.rs#L792) | `const` | `LINUX_EL1_KERNEL_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_KERNEL_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:793`](crates/carrick-mem/src/memory.rs#L793) | `const` | `LINUX_EL1_IMAGE_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_IMAGE_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:806`](crates/carrick-mem/src/memory.rs#L806) | `const` | `LINUX_GIC_WINDOW_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_GIC_WINDOW_BASE'] |
| [`crates/carrick-mem/src/memory.rs:807`](crates/carrick-mem/src/memory.rs#L807) | `const` | `LINUX_GIC_WINDOW_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_GIC_WINDOW_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:808`](crates/carrick-mem/src/memory.rs#L808) | `const` | `LINUX_GIC_DISTRIBUTOR_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_GIC_WINDOW_BASE', 'LINUX_GIC_DISTRIBUTOR_BASE'] |
| [`crates/carrick-mem/src/memory.rs:810`](crates/carrick-mem/src/memory.rs#L810) | `const` | `LINUX_GIC_DISTRIBUTOR_MAX` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_GIC_DISTRIBUTOR_MAX'] |
| [`crates/carrick-mem/src/memory.rs:811`](crates/carrick-mem/src/memory.rs#L811) | `const` | `LINUX_GIC_REDISTRIBUTOR_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_GIC_WINDOW_BASE', 'LINUX_GIC_REDISTRIBUTOR_BASE', 'LINUX_GIC_DISTRIBUTOR_MAX'] |
| [`crates/carrick-mem/src/memory.rs:813`](crates/carrick-mem/src/memory.rs#L813) | `const` | `LINUX_GIC_REDISTRIBUTOR_MAX` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_GIC_WINDOW_SIZE', 'LINUX_GIC_REDISTRIBUTOR_MAX', 'LINUX_GIC_DISTRIBUTOR_MAX'] |
| [`crates/carrick-mem/src/memory.rs:860`](crates/carrick-mem/src/memory.rs#L860) | `const fn` | `ipa_overlaps_gic_window` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_GIC_WINDOW_BASE', 'LINUX_GIC_WINDOW_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:865`](crates/carrick-mem/src/memory.rs#L865) | `const` | `AARCH64_LINUX_PAGE_TABLE_LAYOUT` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_GIC_WINDOW_BASE', 'LINUX_GIC_WINDOW_SIZE', 'LINUX_NULL_GUARD_END'] |
| [`crates/carrick-mem/src/memory.rs:1058`](crates/carrick-mem/src/memory.rs#L1058) | `fn` | `alloc_alias_ipa` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_ALIAS_IPA_BASE', 'LINUX_ALIAS_IPA_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:1096`](crates/carrick-mem/src/memory.rs#L1096) | `fn` | `is_high_va` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HIGH_VA_THRESHOLD'] |
| [`crates/carrick-mem/src/memory.rs:1105`](crates/carrick-mem/src/memory.rs#L1105) | `fn` | `ipa_for_va` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_ROSETTA_IPA_BASE', 'LINUX_ROSETTA_VA_BASE'] |
| [`crates/carrick-mem/src/memory.rs:1464`](crates/carrick-mem/src/memory.rs#L1464) | `fn` | `load_elf_bytes_with_reader_for` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_PIE_DEFAULT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:1744`](crates/carrick-mem/src/memory.rs#L1744) | `fn` | `with_vdso_auxv` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_AT_SYSINFO_EHDR'] |
| [`crates/carrick-mem/src/memory.rs:1754`](crates/carrick-mem/src/memory.rs#L1754) | `fn` | `without_auxv_hwcap` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_AT_HWCAP'] |
| [`crates/carrick-mem/src/memory.rs:1778`](crates/carrick-mem/src/memory.rs#L1778) | `fn` | `with_auxv_base` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_AT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:1945`](crates/carrick-mem/src/memory.rs#L1945) | `fn` | `with_el0_trampoline_bytes` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL0_TRAMPOLINE_SIZE', 'LINUX_EL0_TRAMPOLINE_BASE'] |
| [`crates/carrick-mem/src/memory.rs:2103`](crates/carrick-mem/src/memory.rs#L2103) | `fn` | `with_el1_region` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_KERNEL_BASE', 'LINUX_EL1_KERNEL_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:2212`](crates/carrick-mem/src/memory.rs#L2212) | `fn` | `with_identity_page` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_IDENTITY_PAGE_SIZE', 'LINUX_IDENTITY_PAGE_BASE'] |
| [`crates/carrick-mem/src/memory.rs:2259`](crates/carrick-mem/src/memory.rs#L2259) | `fn` | `with_syscall_mailbox_arena` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SYSCALL_MAILBOX_ARENA_SIZE', 'LINUX_SYSCALL_MAILBOX_BASE'] |
| [`crates/carrick-mem/src/memory.rs:2306`](crates/carrick-mem/src/memory.rs#L2306) | `fn` | `with_carrier_maintenance_root` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_CARRIER_MAINT_ROOT_SIZE', 'LINUX_CARRIER_MAINT_ROOT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:2353`](crates/carrick-mem/src/memory.rs#L2353) | `fn` | `with_fd_ceiling_control` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_FD_CEILING_CONTROL_BASE', 'LINUX_FD_CEILING_OFF_CEILING', 'LINUX_FD_CEILING_OFF_GATE'] |
| [`crates/carrick-mem/src/memory.rs:2536`](crates/carrick-mem/src/memory.rs#L2536) | `fn` | `with_vdso_bytes` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_VVAR_BASE', 'LINUX_VDSO_BASE'] |
| [`crates/carrick-mem/src/memory.rs:2554`](crates/carrick-mem/src/memory.rs#L2554) | `fn` | `with_vdso_bytes_at` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_VVAR_SIZE', 'LINUX_VDSO_SIZE', 'LINUX_AT_SYSINFO_EHDR'] |
| [`crates/carrick-mem/src/memory.rs:2616`](crates/carrick-mem/src/memory.rs#L2616) | `fn` | `with_linux_initial_stack` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_STACK_SIZE', 'LINUX_STACK_TOP'] |
| [`crates/carrick-mem/src/memory.rs:2626`](crates/carrick-mem/src/memory.rs#L2626) | `fn` | `with_linux_initial_stack_execfn` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_STACK_SIZE', 'LINUX_STACK_TOP'] |
| [`crates/carrick-mem/src/memory.rs:2749`](crates/carrick-mem/src/memory.rs#L2749) | `fn` | `build_linux_initial_stack` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_AT_NULL', 'LINUX_AT_EXECFN', 'LINUX_AT_PLATFORM'] |
| [`crates/carrick-mem/src/memory.rs:3324`](crates/carrick-mem/src/memory.rs#L3324) | `fn` | `stage1_identity_page_tables` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_NULL_GUARD_END', 'LINUX_KERNEL_REGION_BASE', 'LINUX_GIC_WINDOW_BASE'] |
| [`crates/carrick-mem/src/memory.rs:3557`](crates/carrick-mem/src/memory.rs#L3557) | `fn` | `apply_image_protections` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HIGH_VA_THRESHOLD', 'LINUX_MMAP_BASE'] |
| [`crates/carrick-mem/src/memory.rs:3691`](crates/carrick-mem/src/memory.rs#L3691) | `fn` | `seal_unowned_user_space` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_HVPATCH_RESERVED_END', 'LINUX_NULL_GUARD_END', 'LINUX_KERNEL_REGION_BASE'] |
| [`crates/carrick-mem/src/memory.rs:3757`](crates/carrick-mem/src/memory.rs#L3757) | `fn` | `stage1_hvpatch_page_tables` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_PAGE_TABLES_BASE'] |
| [`crates/carrick-mem/src/memory.rs:3833`](crates/carrick-mem/src/memory.rs#L3833) | `fn` | `stage1_carrier_maintenance_page_tables` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_CARRIER_MAINT_ROOT_BASE', 'LINUX_KERNEL_REGION_BASE', 'LINUX_CARRIER_MAINT_ROOT_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:3902`](crates/carrick-mem/src/memory.rs#L3902) | `fn` | `el0_trampoline_bytes` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL0_TRAMPOLINE_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:3945`](crates/carrick-mem/src/memory.rs#L3945) | `fn` | `el1_maintenance_bytes` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_MAINT_SIZE', 'LINUX_EL1_MAINT_BASE', 'LINUX_EL1_ASID_MAINT_BASE'] |
| [`crates/carrick-mem/src/memory.rs:3992`](crates/carrick-mem/src/memory.rs#L3992) | `fn` | `sigreturn_trampoline_bytes` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SIGRETURN_TRAMPOLINE_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:4018`](crates/carrick-mem/src/memory.rs#L4018) | `fn` | `el1_vectors_bytes` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_VECTORS_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:5168`](crates/carrick-mem/src/memory.rs#L5168) | `fn` | `el1_idle_entry_va` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EL1_VECTORS_BASE', 'LINUX_EL1_VECTORS_SIZE'] |
| [`crates/carrick-mem/src/memory.rs:5995`](crates/carrick-mem/src/memory.rs#L5995) | `fn` | `linux_auxv_from_load_plan_with_vdso` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_AT_EXECFN', 'LINUX_AT_PAGESZ', 'LINUX_VDSO_BASE'] |
| [`crates/carrick-mem/src/memory/el1_clock.rs:8`](crates/carrick-mem/src/memory/el1_clock.rs#L8) | `const` | `STUB_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_VDSO_BASE'] |
| [`crates/carrick-mem/src/page_geometry.rs:10`](crates/carrick-mem/src/page_geometry.rs#L10) | `const` | `DEFAULT_LINUX_PAGE_SIZE` | carrick-abi, LINUX_*/SYS_* | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_PAGE_SIZE'] |
| [`crates/carrick-mem/src/shared_aperture.rs:179`](crates/carrick-mem/src/shared_aperture.rs#L179) | `fn` | `new` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_SHARED_FILE_BASE', 'LINUX_SHARED_FILE_SIZE'] |
| [`crates/carrick-mem/src/vdso.rs:18`](crates/carrick-mem/src/vdso.rs#L18) | `const` | `LINUX_VVAR_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_VVAR_BASE'] |
| [`crates/carrick-mem/src/vdso.rs:21`](crates/carrick-mem/src/vdso.rs#L21) | `const` | `LINUX_VDSO_BASE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_VDSO_BASE'] |
| [`crates/carrick-mem/src/vdso.rs:23`](crates/carrick-mem/src/vdso.rs#L23) | `const` | `LINUX_VVAR_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_VVAR_SIZE'] |
| [`crates/carrick-mem/src/vdso.rs:24`](crates/carrick-mem/src/vdso.rs#L24) | `const` | `LINUX_VDSO_SIZE` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_VDSO_SIZE'] |
| [`crates/carrick-mem/src/vdso.rs:109`](crates/carrick-mem/src/vdso.rs#L109) | `const` | `VDSO_CLOCK_RESOLUTION_NS` | carrick-abi, LINUX_*/SYS_* | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_CLOCK_RESOLUTION_NSEC'] |
| [`crates/carrick-mem/src/vdso.rs:258`](crates/carrick-mem/src/vdso.rs#L258) | `fn` | `x8664_vdso_image_bytes` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_2', 'LINUX_2_6_HASH'] |

### `carrick-observability` (MIXED)

**Linux Items Count:** 68.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-observability/src/compat.rs:411`](crates/carrick-observability/src/compat.rs#L411) | `fn` | `snapshot` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-observability/src/probes.rs:88`](crates/carrick-observability/src/probes.rs#L88) | `struct` | `HostProcessBirth` | pid/tgid | pid/tgid: ['pid', 'HostProcessBirth'] |
| [`crates/carrick-observability/src/probes.rs:95`](crates/carrick-observability/src/probes.rs#L95) | `enum` | `HostProcessBirthError` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:116`](crates/carrick-observability/src/probes.rs#L116) | `fn` | `new` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:134`](crates/carrick-observability/src/probes.rs#L134) | `fn` | `query` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:170`](crates/carrick-observability/src/probes.rs#L170) | `const fn` | `pid` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:201`](crates/carrick-observability/src/probes.rs#L201) | `struct` | `EpollMaskedProbe` | epoll | epoll: ['EpollMaskedProbe'] |
| [`crates/carrick-observability/src/probes.rs:465`](crates/carrick-observability/src/probes.rs#L465) | `struct` | `HvpatchGuestLifecycle` | pid/tgid | pid/tgid: ['HvpatchGuestLifecycle', 'pid'] |
| [`crates/carrick-observability/src/probes.rs:487`](crates/carrick-observability/src/probes.rs#L487) | `enum` | `HvpatchGuestLifecycleError` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:509`](crates/carrick-observability/src/probes.rs#L509) | `struct` | `HvpatchGuestLifecycleArgs` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:522`](crates/carrick-observability/src/probes.rs#L522) | `fn` | `new` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:569`](crates/carrick-observability/src/probes.rs#L569) | `const fn` | `pid` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:607`](crates/carrick-observability/src/probes.rs#L607) | `struct` | `HvpatchSyscallService` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:616`](crates/carrick-observability/src/probes.rs#L616) | `fn` | `new` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:638`](crates/carrick-observability/src/probes.rs#L638) | `const fn` | `pid` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:772`](crates/carrick-observability/src/probes.rs#L772) | `struct` | `HvpatchGuestFault` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:782`](crates/carrick-observability/src/probes.rs#L782) | `fn` | `new` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:818`](crates/carrick-observability/src/probes.rs#L818) | `const fn` | `pid` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:901`](crates/carrick-observability/src/probes.rs#L901) | `struct` | `HvpatchFrameCowTrigger` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:914`](crates/carrick-observability/src/probes.rs#L914) | `struct` | `HvpatchFrameCowTriggerArgs` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:927`](crates/carrick-observability/src/probes.rs#L927) | `fn` | `new` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:964`](crates/carrick-observability/src/probes.rs#L964) | `const fn` | `pid` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:1004`](crates/carrick-observability/src/probes.rs#L1004) | `struct` | `HvpatchFrameCow` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:1019`](crates/carrick-observability/src/probes.rs#L1019) | `struct` | `HvpatchFrameCowArgs` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:1034`](crates/carrick-observability/src/probes.rs#L1034) | `fn` | `new` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:1075`](crates/carrick-observability/src/probes.rs#L1075) | `const fn` | `pid` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:1123`](crates/carrick-observability/src/probes.rs#L1123) | `struct` | `HvpatchForkFrameShare` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:1137`](crates/carrick-observability/src/probes.rs#L1137) | `struct` | `HvpatchForkFrameShareArgs` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:1151`](crates/carrick-observability/src/probes.rs#L1151) | `fn` | `new` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:1193`](crates/carrick-observability/src/probes.rs#L1193) | `const fn` | `pid` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:1295`](crates/carrick-observability/src/probes.rs#L1295) | `struct` | `HvpatchGuestAddressSpace` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:2258`](crates/carrick-observability/src/probes.rs#L2258) | `fn` | `new` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:2287`](crates/carrick-observability/src/probes.rs#L2287) | `const fn` | `pid` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:4965`](crates/carrick-observability/src/probes.rs#L4965) | `struct` | `PreparedHostImagePublication` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6104`](crates/carrick-observability/src/probes.rs#L6104) | `fn` | `host_process_birth` | pid/tgid | pid/tgid: ['pid', 'HostProcessBirth'] |
| [`crates/carrick-observability/src/probes.rs:6112`](crates/carrick-observability/src/probes.rs#L6112) | `fn` | `host_process_birth_current` | pid/tgid | pid/tgid: ['pid', 'HostProcessBirth'] |
| [`crates/carrick-observability/src/probes.rs:6232`](crates/carrick-observability/src/probes.rs#L6232) | `fn` | `futex_route` | futex ops | futex ops: ['futex__route', 'futex_route'] |
| [`crates/carrick-observability/src/probes.rs:6299`](crates/carrick-observability/src/probes.rs#L6299) | `fn` | `ulock_requeue` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6327`](crates/carrick-observability/src/probes.rs#L6327) | `fn` | `futex_unexpected_errno` | futex ops | futex ops: ['futex__unexpected__errno', 'futex_unexpected_errno'] |
| [`crates/carrick-observability/src/probes.rs:6436`](crates/carrick-observability/src/probes.rs#L6436) | `fn` | `hvpatch_thread_terminal` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6490`](crates/carrick-observability/src/probes.rs#L6490) | `fn` | `hvpatch_guest_lifecycle` | pid/tgid | pid/tgid: ['HvpatchGuestLifecycle', 'pid'] |
| [`crates/carrick-observability/src/probes.rs:6629`](crates/carrick-observability/src/probes.rs#L6629) | `fn` | `hvpatch_guest_fault` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6657`](crates/carrick-observability/src/probes.rs#L6657) | `fn` | `hvpatch_guest_fault_with` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6680`](crates/carrick-observability/src/probes.rs#L6680) | `fn` | `hvpatch_frame_cow` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6699`](crates/carrick-observability/src/probes.rs#L6699) | `fn` | `hvpatch_frame_cow_trigger` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6803`](crates/carrick-observability/src/probes.rs#L6803) | `fn` | `hvpatch_fork_frame_share` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6862`](crates/carrick-observability/src/probes.rs#L6862) | `fn` | `hvpatch_guest_address_space` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6965`](crates/carrick-observability/src/probes.rs#L6965) | `fn` | `hvpatch_syscall_service` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6976`](crates/carrick-observability/src/probes.rs#L6976) | `fn` | `hvpatch_syscall_service_clear` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:6986`](crates/carrick-observability/src/probes.rs#L6986) | `fn` | `hvpatch_core_lifecycle` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:7602`](crates/carrick-observability/src/probes.rs#L7602) | `fn` | `epoll_ctl` | epoll | epoll: ['epoll__ctl', 'epoll_ctl'] |
| [`crates/carrick-observability/src/probes.rs:7606`](crates/carrick-observability/src/probes.rs#L7606) | `fn` | `epoll_interest` | epoll | epoll: ['epoll__interest', 'epoll_interest'] |
| [`crates/carrick-observability/src/probes.rs:7647`](crates/carrick-observability/src/probes.rs#L7647) | `fn` | `epoll_masked` | epoll | epoll: ['epoll_masked', 'EPOLL_MASKED_PROBE', 'epoll__masked'] |
| [`crates/carrick-observability/src/probes.rs:7691`](crates/carrick-observability/src/probes.rs#L7691) | `fn` | `epoll_rebind` | epoll | epoll: ['EPOLL_REBIND_PROBE', 'epoll_rebind', 'epoll__rebind'] |
| [`crates/carrick-observability/src/probes.rs:7714`](crates/carrick-observability/src/probes.rs#L7714) | `fn` | `epoll_wait_fd` | epoll | epoll: ['epoll__wait__fd', 'epoll_wait_fd'] |
| [`crates/carrick-observability/src/probes.rs:7718`](crates/carrick-observability/src/probes.rs#L7718) | `fn` | `epoll_result` | epoll | epoll: ['epoll__result', 'epoll_result'] |
| [`crates/carrick-observability/src/probes.rs:7723`](crates/carrick-observability/src/probes.rs#L7723) | `fn` | `epoll_lookup` | epoll | epoll: ['epoll_lookup', 'epoll__lookup'] |
| [`crates/carrick-observability/src/probes.rs:7728`](crates/carrick-observability/src/probes.rs#L7728) | `fn` | `epoll_stale_edge` | epoll | epoll: ['epoll_stale_edge', 'epoll__stale__edge'] |
| [`crates/carrick-observability/src/probes.rs:7827`](crates/carrick-observability/src/probes.rs#L7827) | `fn` | `fork_post` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:7927`](crates/carrick-observability/src/probes.rs#L7927) | `fn` | `supervisor_child_exit` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:8338`](crates/carrick-observability/src/probes.rs#L8338) | `fn` | `native_x86_fault` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:8353`](crates/carrick-observability/src/probes.rs#L8353) | `fn` | `native_x86_fault_stack` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:8365`](crates/carrick-observability/src/probes.rs#L8365) | `fn` | `native_x86_fault_history` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:8372`](crates/carrick-observability/src/probes.rs#L8372) | `fn` | `native_x86_pc` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:8377`](crates/carrick-observability/src/probes.rs#L8377) | `fn` | `native_x86_resolve` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:8399`](crates/carrick-observability/src/probes.rs#L8399) | `fn` | `native_x86_xstate_edge` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:8411`](crates/carrick-observability/src/probes.rs#L8411) | `fn` | `native_x86_xstate` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-observability/src/probes.rs:8967`](crates/carrick-observability/src/probes.rs#L8967) | `fn` | `epoll_lookup` | epoll | epoll: ['epoll_lookup'] |

### `carrick-pipe-core` (MIXED)

**Linux Items Count:** 2.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-pipe-core/src/lib.rs:20`](crates/carrick-pipe-core/src/lib.rs#L20) | `const` | `EVENTFD_MAX` | fd tables/Fd | fd tables/Fd: ['eventfd', 'EVENTFD_MAX'] |
| [`crates/carrick-pipe-core/src/lib.rs:74`](crates/carrick-pipe-core/src/lib.rs#L74) | `fn` | `broken_pipe_signal` | signals/SigSet | signals/SigSet: ['SIGPIPE', 'BrokenPipe'] |

### `carrick-runtime` (MIXED)

**Linux Items Count:** 7.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-runtime/src/el1_census.rs:144`](crates/carrick-runtime/src/el1_census.rs#L144) | `struct` | `Census` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-runtime/src/el1_census.rs:211`](crates/carrick-runtime/src/el1_census.rs#L211) | `fn` | `write_at_teardown` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-runtime/src/host_process.rs:16`](crates/carrick-runtime/src/host_process.rs#L16) | `fn` | `prepare` | signals/SigSet | signals/SigSet: ['SIGPIPE'] |
| [`crates/carrick-runtime/src/hvpatch/mod.rs:334`](crates/carrick-runtime/src/hvpatch/mod.rs#L334) | `struct` | `PendingAddressSpaceRetirement` | pid/tgid | pid/tgid: ['HvpatchGuestLifecycle', 'pid'] |
| [`crates/carrick-runtime/src/lib.rs:423`](crates/carrick-runtime/src/lib.rs#L423) | `fn` | `rosetta_interpreter_path` | /proc | /proc: ['/proc'] |
| [`crates/carrick-runtime/src/runtime.rs:1030`](crates/carrick-runtime/src/runtime.rs#L1030) | `fn` | `run_combined_syscall_loop_with_dispatcher` | carrick-abi, LINUX_*/SYS_*, errno, signals/SigSet, pid/tgid | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_ENOMEM', 'LINUX_EINTR', 'LINUX_ENOSYS'], errno: ['LinuxErrno'], signals/SigSet: ['SigSet'], pid/tgid: ['pid'] |
| [`crates/carrick-runtime/src/threaded_loop.rs:40`](crates/carrick-runtime/src/threaded_loop.rs#L40) | `trait` | `HostBackend` | futex ops | futex ops: ['FutexTable', 'futex'] |

### `carrick-sched-core` (MIXED)

**Linux Items Count:** 8.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-sched-core/src/lib.rs:381`](crates/carrick-sched-core/src/lib.rs#L381) | `struct` | `ThreadCtx` | carrick-abi | carrick-abi: ['AArch64-shaped register context: x[31], pc, sp_el0, tpidr_el0, tpidrro_el0, v[32]'] |
| [`crates/carrick-sched-core/src/lib.rs:402`](crates/carrick-sched-core/src/lib.rs#L402) | `const` | `THREAD_CTX_V_OFFSET` | carrick-abi | carrick-abi: ['AArch64 FP/SIMD save area offset'] |
| [`crates/carrick-sched-core/src/lib.rs:404`](crates/carrick-sched-core/src/lib.rs#L404) | `const` | `THREAD_CTX_FPSR_OFFSET` | carrick-abi | carrick-abi: ['AArch64 FPSR/FPCR register offset'] |
| [`crates/carrick-sched-core/src/lib.rs:452`](crates/carrick-sched-core/src/lib.rs#L452) | `struct` | `ThreadIdentity` | pid/tgid, fd tables/Fd | pid/tgid: ['tid (Linux tid)'], fd tables/Fd: ['file_table (Linux file table pointer)'] |
| [`crates/carrick-sched-core/src/lib.rs:588`](crates/carrick-sched-core/src/lib.rs#L588) | `fn` | `identity` | pid/tgid | pid/tgid: ['Returns ThreadIdentity carrying Linux tid and file_table'] |
| [`crates/carrick-sched-core/src/lib.rs:698`](crates/carrick-sched-core/src/lib.rs#L698) | `unsafe fn` | `ctx_mut` | carrick-abi | carrick-abi: ['Mutable access to AArch64 ThreadCtx'] |
| [`crates/carrick-sched-core/src/lib.rs:1450`](crates/carrick-sched-core/src/lib.rs#L1450) | `fn` | `alloc_record` | pid/tgid | pid/tgid: ['Allocates zone record bound to Linux ThreadIdentity'] |
| [`crates/carrick-sched-core/src/lib.rs:1479`](crates/carrick-sched-core/src/lib.rs#L1479) | `fn` | `alloc_host_runnable` | pid/tgid | pid/tgid: ['Allocates host-runnable record bound to Linux ThreadIdentity'] |

### `carrick-spec` (MIXED)

**Linux Items Count:** 3.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-spec/src/lib.rs:230`](crates/carrick-spec/src/lib.rs#L230) | `struct` | `NamespaceConfig` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-spec/src/lib.rs:435`](crates/carrick-spec/src/lib.rs#L435) | `fn` | `anonymous` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-spec/src/lib.rs:884`](crates/carrick-spec/src/lib.rs#L884) | `struct` | `ProcessSpec` | carrick-abi, pid/tgid | carrick-abi: ['carrick_abi'], pid/tgid: ['pid'] |

### `carrick-thread` (MIXED)

**Linux Items Count:** 16.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-thread/src/platform_futex.rs:31`](crates/carrick-thread/src/platform_futex.rs#L31) | `struct` | `FutexTableFutex` | futex ops | futex ops: ['FutexTable'] |
| [`crates/carrick-thread/src/platform_futex.rs:38`](crates/carrick-thread/src/platform_futex.rs#L38) | `fn` | `new` | futex ops | futex ops: ['FutexTable'] |
| [`crates/carrick-thread/src/platform_futex.rs:50`](crates/carrick-thread/src/platform_futex.rs#L50) | `fn` | `carrier_shared_futex_table` | futex ops | futex ops: ['FutexTable'] |
| [`crates/carrick-thread/src/platform_futex.rs:269`](crates/carrick-thread/src/platform_futex.rs#L269) | `struct` | `FutexTableNativeFutex` | futex ops | futex ops: ['FutexTable'] |
| [`crates/carrick-thread/src/platform_futex.rs:278`](crates/carrick-thread/src/platform_futex.rs#L278) | `fn` | `new` | futex ops | futex ops: ['FutexTable'] |
| [`crates/carrick-thread/src/thread.rs:232`](crates/carrick-thread/src/thread.rs#L232) | `fn` | `register_container_runtime_endpoint` | futex ops | futex ops: ['FutexTable', 'futex'] |
| [`crates/carrick-thread/src/thread.rs:272`](crates/carrick-thread/src/thread.rs#L272) | `fn` | `notify_container_futex_signal_pending` | futex ops | futex ops: ['futex'] |
| [`crates/carrick-thread/src/thread.rs:690`](crates/carrick-thread/src/thread.rs#L690) | `fn` | `is_woken` | futex ops | futex ops: ['FUTEX_SLOT_WOKEN'] |
| [`crates/carrick-thread/src/thread.rs:1112`](crates/carrick-thread/src/thread.rs#L1112) | `struct` | `FutexTable` | futex ops | futex ops: ['FutexTable', 'FUTEX_SHARDS', 'FutexBucket'] |
| [`crates/carrick-thread/src/thread.rs:1188`](crates/carrick-thread/src/thread.rs#L1188) | `fn` | `subscribe_generation` | futex ops | futex ops: ['FUTEX_SLOT_QUEUED', 'futex_halt_poll_ns'] |
| [`crates/carrick-thread/src/thread.rs:1404`](crates/carrick-thread/src/thread.rs#L1404) | `fn` | `prepare_wait` | futex ops | futex ops: ['FUTEX_SLOT_QUEUED'] |
| [`crates/carrick-thread/src/thread.rs:1608`](crates/carrick-thread/src/thread.rs#L1608) | `unsafe fn` | `wait_while_word_equals` | futex ops | futex ops: ['FUTEX_SIGNAL_TOKEN', 'FUTEX_WAKE_TOKEN'] |
| [`crates/carrick-thread/src/thread.rs:1740`](crates/carrick-thread/src/thread.rs#L1740) | `fn` | `notify_signal_pending` | futex ops | futex ops: ['FUTEX_SIGNAL_TOKEN'] |
| [`crates/carrick-thread/src/thread.rs:1758`](crates/carrick-thread/src/thread.rs#L1758) | `fn` | `notify_signal_pending_for` | futex ops | futex ops: ['FUTEX_SIGNAL_TOKEN'] |
| [`crates/carrick-thread/src/thread.rs:1784`](crates/carrick-thread/src/thread.rs#L1784) | `fn` | `wake` | futex ops | futex ops: ['FUTEX_WAKE_TOKEN'] |
| [`crates/carrick-thread/src/thread.rs:1860`](crates/carrick-thread/src/thread.rs#L1860) | `fn` | `requeue` | futex ops | futex ops: ['FUTEX_WAKE_TOKEN'] |

### `carrick-timer-core` (MIXED)

**Linux Items Count:** 10.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-timer-core/src/itimer.rs:28`](crates/carrick-timer-core/src/itimer.rs#L28) | `const` | `ITIMER_COUNT` | carrick-abi | carrick-abi: ['ITIMER_REAL/VIRTUAL/PROF fixed slots'] |
| [`crates/carrick-timer-core/src/itimer.rs:34`](crates/carrick-timer-core/src/itimer.rs#L34) | `const` | `TIMER_IDENT_BASE` | carrick-abi | carrick-abi: ['BSD/Darwin kqueue EVFILT_TIMER ident range'] |
| [`crates/carrick-timer-core/src/itimer.rs:46`](crates/carrick-timer-core/src/itimer.rs#L46) | `const` | `TIMER_ARM_ADD` | carrick-abi | carrick-abi: ['BSD EV_ADD timer arm flag'] |
| [`crates/carrick-timer-core/src/itimer.rs:48`](crates/carrick-timer-core/src/itimer.rs#L48) | `const` | `TIMER_ARM_ONESHOT` | carrick-abi | carrick-abi: ['BSD EV_ONESHOT timer arm flag'] |
| [`crates/carrick-timer-core/src/itimer.rs:93`](crates/carrick-timer-core/src/itimer.rs#L93) | `fn` | `ident_for` | carrick-abi | carrick-abi: ['EVFILT_TIMER ident per itimer slot'] |
| [`crates/carrick-timer-core/src/itimer.rs:121`](crates/carrick-timer-core/src/itimer.rs#L121) | `fn` | `is_cpu_timer` | carrick-abi | carrick-abi: ['ITIMER_VIRTUAL / ITIMER_PROF CPU timer check'] |
| [`crates/carrick-timer-core/src/posix.rs:12`](crates/carrick-timer-core/src/posix.rs#L12) | `const` | `OVERRUN_MAX` | errno | errno: ['POSIX timer overrun saturation bound'] |
| [`crates/carrick-timer-core/src/posix.rs:18`](crates/carrick-timer-core/src/posix.rs#L18) | `struct` | `PosixTimerSpec` | signals/SigSet | signals/SigSet: ['signum: i32', 'si_value: i64'] |
| [`crates/carrick-timer-core/src/posix.rs:30`](crates/carrick-timer-core/src/posix.rs#L30) | `fn` | `remaining_time` | carrick-abi | carrick-abi: ['POSIX timer remaining time calculation'] |
| [`crates/carrick-timer-core/src/posix.rs:47`](crates/carrick-timer-core/src/posix.rs#L47) | `fn` | `next_overrun` | errno | errno: ['POSIX timer overrun saturation'] |

### `carrick-vfs` (MIXED)

**Linux Items Count:** 48.

| File:Line | Item Kind | Item Name | Named Linux Concept(s) | Description |
|---|---|---|---|---|
| [`crates/carrick-vfs/src/darwin_fs.rs:20`](crates/carrick-vfs/src/darwin_fs.rs#L20) | `fn` | `copyfile_clone_or_data` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/fs_backend.rs:60`](crates/carrick-vfs/src/fs_backend.rs#L60) | `enum` | `BackendError` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/fs_backend.rs:105`](crates/carrick-vfs/src/fs_backend.rs#L105) | `enum` | `HostFdOpen` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/fs_backend.rs:152`](crates/carrick-vfs/src/fs_backend.rs#L152) | `fn` | `lowerable` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/fs_backend.rs:162`](crates/carrick-vfs/src/fs_backend.rs#L162) | `fn` | `into_errno` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/fs_backend.rs:515`](crates/carrick-vfs/src/fs_backend.rs#L515) | `trait` | `FsBackend` | carrick-abi, LINUX_*/SYS_*, errno | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_ENOSYS', 'LINUX_ENOTSUP'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/dentry.rs:631`](crates/carrick-vfs/src/vfs/dentry.rs#L631) | `fn` | `lookup_path` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOTDIR', 'LINUX_ENAMETOOLONG', 'LINUX_ENOENT'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/dentry.rs:2484`](crates/carrick-vfs/src/vfs/dentry.rs#L2484) | `fn` | `stat` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOTDIR', 'LINUX_ENOENT'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/dentry.rs:2557`](crates/carrick-vfs/src/vfs/dentry.rs#L2557) | `fn` | `readlink` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_EINVAL'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/dentry.rs:2568`](crates/carrick-vfs/src/vfs/dentry.rs#L2568) | `fn` | `fast_open` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_EISDIR', 'LINUX_ENOSYS', 'LINUX_EXDEV'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/dentry.rs:2628`](crates/carrick-vfs/src/vfs/dentry.rs#L2628) | `fn` | `open_metadata_fd` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOENT'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/dentry.rs:2687`](crates/carrick-vfs/src/vfs/dentry.rs#L2687) | `fn` | `get_or_open_dir_fd` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOTDIR'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/dentry.rs:2803`](crates/carrick-vfs/src/vfs/dentry.rs#L2803) | `fn` | `get_or_refresh_inode` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/errno.rs:18`](crates/carrick-vfs/src/vfs/errno.rs#L18) | `struct` | `HostSyscallError` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/errno.rs:39`](crates/carrick-vfs/src/vfs/errno.rs#L39) | `fn` | `linux_errno` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/errno.rs:44`](crates/carrick-vfs/src/vfs/errno.rs#L44) | `trait` | `HostSyscallResult` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/errno.rs:83`](crates/carrick-vfs/src/vfs/errno.rs#L83) | `fn` | `rootfs_errno` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_E2BIG', 'LINUX_ENOENT', 'LINUX_EINVAL'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/mod.rs:115`](crates/carrick-vfs/src/vfs/mod.rs#L115) | `type` | `VfsError` | carrick-abi, errno | carrick-abi: ['carrick_abi'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/mod.rs:256`](crates/carrick-vfs/src/vfs/mod.rs#L256) | `fn` | `statfs` | carrick-abi, LINUX_*/SYS_* | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_PIPEFS_MAGIC', 'LINUX_SYSFS_MAGIC', 'LINUX_SECRETMEM_MAGIC'] |
| [`crates/carrick-vfs/src/vfs/mod.rs:396`](crates/carrick-vfs/src/vfs/mod.rs#L396) | `trait` | `VirtualConsoleDevice` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-vfs/src/vfs/mod.rs:782`](crates/carrick-vfs/src/vfs/mod.rs#L782) | `struct` | `SyntheticProcIdentity` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-vfs/src/vfs/mod.rs:823`](crates/carrick-vfs/src/vfs/mod.rs#L823) | `struct` | `SyntheticProcProcess` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-vfs/src/vfs/mod.rs:845`](crates/carrick-vfs/src/vfs/mod.rs#L845) | `struct` | `SyntheticProcZombie` | pid/tgid | pid/tgid: ['pid'] |
| [`crates/carrick-vfs/src/vfs/mod.rs:1062`](crates/carrick-vfs/src/vfs/mod.rs#L1062) | `trait` | `Vfs` | carrick-abi, LINUX_*/SYS_*, errno | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_ENOTDIR', 'LINUX_ENOTSUP', 'LINUX_EROFS'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:172`](crates/carrick-vfs/src/vfs/rootfs.rs#L172) | `fn` | `statfs` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:329`](crates/carrick-vfs/src/vfs/rootfs.rs#L329) | `fn` | `with_paths_topology_admission` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:374`](crates/carrick-vfs/src/vfs/rootfs.rs#L374) | `fn` | `dentry_stat` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOSYS'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:384`](crates/carrick-vfs/src/vfs/rootfs.rs#L384) | `fn` | `dentry_is_dir` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOSYS'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:394`](crates/carrick-vfs/src/vfs/rootfs.rs#L394) | `fn` | `dentry_readlink` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOSYS'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:403`](crates/carrick-vfs/src/vfs/rootfs.rs#L403) | `fn` | `dentry_fast_open` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOSYS'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:545`](crates/carrick-vfs/src/vfs/rootfs.rs#L545) | `fn` | `get_or_fill_host_inode` | carrick-abi, LINUX_*/SYS_* | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_S_IFMT', 'LINUX_S_IFCHR', 'LINUX_S_IFBLK'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:635`](crates/carrick-vfs/src/vfs/rootfs.rs#L635) | `fn` | `create_raw_fd` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:708`](crates/carrick-vfs/src/vfs/rootfs.rs#L708) | `fn` | `link` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:715`](crates/carrick-vfs/src/vfs/rootfs.rs#L715) | `fn` | `link_with_parent_check` | carrick-abi, LINUX_*/SYS_*, errno | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_EPERM', 'LINUX_EEXIST', 'LINUX_ENOENT'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:837`](crates/carrick-vfs/src/vfs/rootfs.rs#L837) | `fn` | `symlink` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_EROFS'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:852`](crates/carrick-vfs/src/vfs/rootfs.rs#L852) | `fn` | `truncate_path` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_EROFS'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:887`](crates/carrick-vfs/src/vfs/rootfs.rs#L887) | `fn` | `set_owner` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:912`](crates/carrick-vfs/src/vfs/rootfs.rs#L912) | `fn` | `fset_owner` | carrick-abi | carrick-abi: ['carrick_abi'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:943`](crates/carrick-vfs/src/vfs/rootfs.rs#L943) | `fn` | `open_metadata_fd` | LINUX_*/SYS_*, errno | LINUX_*/SYS_*: ['LINUX_ENOSYS'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:956`](crates/carrick-vfs/src/vfs/rootfs.rs#L956) | `fn` | `get_xattr` | carrick-abi, LINUX_*/SYS_*, errno | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_EXDEV', 'LINUX_EINVAL', 'LINUX_ENODATA'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:998`](crates/carrick-vfs/src/vfs/rootfs.rs#L998) | `fn` | `list_xattr` | carrick-abi, LINUX_*/SYS_*, errno | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_EXDEV', 'LINUX_ENODATA'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:1049`](crates/carrick-vfs/src/vfs/rootfs.rs#L1049) | `fn` | `remove_xattr` | carrick-abi, LINUX_*/SYS_*, errno | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_EINVAL', 'LINUX_ENOENT', 'LINUX_ENODATA'], errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:1081`](crates/carrick-vfs/src/vfs/rootfs.rs#L1081) | `fn` | `set_xattr` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:1135`](crates/carrick-vfs/src/vfs/rootfs.rs#L1135) | `fn` | `lookup_nofollow` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_ENOTDIR', 'LINUX_ENAMETOOLONG', 'LINUX_ELOOP'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:1293`](crates/carrick-vfs/src/vfs/rootfs.rs#L1293) | `fn` | `open_for_dispatch` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:1663`](crates/carrick-vfs/src/vfs/rootfs.rs#L1663) | `fn` | `rename_with_flags_and_publish` | LINUX_*/SYS_* | LINUX_*/SYS_*: ['LINUX_EINVAL'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:1971`](crates/carrick-vfs/src/vfs/rootfs.rs#L1971) | `fn` | `with_mkdir_transaction` | errno | errno: ['LinuxErrno'] |
| [`crates/carrick-vfs/src/vfs/rootfs.rs:1996`](crates/carrick-vfs/src/vfs/rootfs.rs#L1996) | `fn` | `mkdir_admitted` | carrick-abi, LINUX_*/SYS_* | carrick-abi: ['carrick_abi'], LINUX_*/SYS_*: ['LINUX_EEXIST', 'LINUX_EINVAL'] |

## NT pressure points

For each Linux-specific item family identified in the substrate and mixed crates, the table below maps the Linux concept to the corresponding Windows NT concept that requires a different architectural shape. Facts only, without recommendations beyond this structural mapping.

| Subsystem / Linux Concept Family | Audited Items / Symbols | Corresponding NT Concept | Architectural Mapping & Structural Shape Differences |
|---|---|---|---|
| **File Descriptors and Dense FD Tables (`carrick-fd-core`, `carrick-el1-abi`, `carrick-vfs`)** | ``Fd(i32)`, `TableId`, `BadFd`, `open`, `close`, `dup`, `dup2`, `dup3`, `close_range`, `install_pair`, `RawOfdPin`, open file descriptions shared via `CLONE_FILES`.` | **Handles and Object Manager (`HANDLE_TABLE`, `HANDLE`)** | NT uses 32/64-bit opaque `HANDLE`s that index a multi-level per-process handle table managed by the Object Manager (`OB`). Handles are table byte offsets (always multiples of 4), not contiguous zero-based integers. Kernel objects (`FILE_OBJECT`, `SECTION`, `EVENT`, etc.) have standardized `OBJECT_HEADER` structures with reference counts and security descriptors. Closing a handle uses `NtClose`, and handle duplication across or within processes uses `NtDuplicateObject`. NT does not have POSIX open file descriptions (OFDs) or fork/clone-style descriptor table sharing; handles are explicitly inheritable or non-inheritable. |
| **Epoll Multiplexing and Readiness Rings (`carrick-el1-abi`, `carrick-el1`, `carrick-observability`, `carrick-vfs`)** | ``EpollState`, `IpcEpollItem`, `create_epoll`, `epoll_add`, `epoll_modify`, `epoll_delete`, `epoll_harvest`, `EpollReadyMask`, `epoll_ctl`.` | **WaitForMultipleObjects and I/O Completion Ports (`IOCP`)** | NT asynchronous I/O and multiplexing operate on completion queues rather than readiness polls. Proactive asynchronous operations use I/O Completion Ports (`NtCreateIoCompletion`, `NtSetIoCompletion`, `NtRemoveIoCompletion`). Multi-wait synchronization across handles uses `NtWaitForMultipleObjects`, which can wait simultaneously on up to 64 kernel dispatcher objects (`MAXIMUM_WAIT_OBJECTS`) with wait-all or wait-any semantics. There is no edge-triggered or level-triggered poll ring; synchronization objects become signaled when ready. |
| **Asynchronous Signals and Frame Delivery (`carrick-signal-core`, `carrick-hal`, `carrick-runtime`)** | ``Signal` (KILL, CHLD, STOP, etc.), `SignalSet`, `SigBlockMask`, `sigaction`, `siginfo`, `build_sigframe`, `restore_sigframe`, `RestorerAddress`, `StandardSignalSlot`.` | **Alertable Waits, APCs, and Structured Exception Handling (SEH)** | NT has no POSIX asynchronous signal mechanism. Asynchronous notifications to user threads are delivered via Asynchronous Procedure Calls (User APCs) using `NtQueueApcThread` / `KiDeliverApc`. User APCs are only delivered when a thread enters an alertable wait state (`Alertable = TRUE` in `NtWaitForSingleObject` / `NtWaitForMultipleObjects` / `NtSleep`). Hardware faults and synchronous errors (access violations, illegal instructions, division by zero) are dispatched through Structured Exception Handling (`KiUserExceptionDispatcher`) in `ntdll.dll`, unwinding via static PE exception directory tables (`.pdata` and `.xdata`) rather than dynamic signal frames. |
| **Memory Mapping and Anonymous Allocations (`carrick-mem`, `carrick-vfs`, `carrick-embed`)** | ``mmap`, `munmap`, `mprotect`, `PROT_NONE`, `MAP_SHARED`, `MAP_PRIVATE`, `LINUX_MMAP_BASE`, arbitrary address range unmapping.` | **Sections and Views (`NtCreateSection`, `NtMapViewOfSection`, `NtAllocateVirtualMemory`)** | NT separates private address space reservation/commitment from file/shared-memory mapping. Anonymous memory is managed via `NtAllocateVirtualMemory` (state transition from Reserved to Committed). Shared memory and file mappings are Section objects (`SECTION`) created with `NtCreateSection` and mapped into virtual address spaces using `NtMapViewOfSection`. Partial range unmapping (punching holes in a view with `munmap`) is not supported by NT: views must be unmapped in their entirety using `NtUnmapViewOfSection`. |
| **Page Allocation Granularity (`carrick-guest-mem`, `carrick-mem`, `carrick-mmu-core`)** | `4 KiB and 16 KiB page boundary calculations (`HOST_PAGE_GRANULE = 0x4000`, `PIPE_BUF = 4096`, `PT_PAGE = 0x1000`), arbitrary page-aligned `mmap` placement.` | **64 KiB Allocation Granularity (`MM_ALLOCATION_GRANULARITY`)** | Although the underlying page size on x86_64 and AArch64 Windows is 4 KiB, the NT Virtual Memory Manager enforces a 64 KiB allocation granularity (`MM_ALLOCATION_GRANULARITY = 0x10000`). Base addresses for `VirtualAlloc` reservations, mapped section views, thread stacks, and PE image loads must be aligned to 64 KiB boundaries. Allocating at 4 KiB or 16 KiB boundaries violates NT memory manager alignment invariants. |
| **Guest Page Translation Granule (`carrick-mmu-core`, `carrick-mem`, `carrick-guest-mem`)** | `AArch64 stage-1 page tables (`PT_PAGE = 0x1000`, 4 KiB granule) over 16 KiB host page backing custody.` | **4 KiB Translation Granule (`PAGE_SIZE = 4096`) and Reservation Policy** | `carrick-mmu-core/src/aarch64.rs::PT_PAGE` is already 0x1000 (4 KiB stage-1 table page). Windows NT for AArch64 and x86_64 uses a 4 KiB page size exclusively (12-bit page offset, 4-level page tables). Apple Silicon macOS hosts run with a 16 KiB page size (14-bit page offset). The NT personality requires 64 KiB reservation and 4 KiB commit policy; the stage-1 page tables are already 4 KiB, while host 16 KiB backing custody remains a separate host-side memory management domain. |
| **Error Numbers and Return Codes (`carrick-vfs`, `carrick-inotify-core`, `carrick-el1`, `carrick-embed`)** | ``LinuxErrno`, `LINUX_EINVAL`, `LINUX_ENOSPC`, `ETIMEDOUT`, `EAGAIN`, `EFAULT`, `HostSyscallError`, `into_errno`.` | **NTSTATUS and Win32 Error Codes (`0xC0000000` / Win32 `DWORD`)** | NT kernel system services do not return negative errno integers. They return 32-bit `NTSTATUS` codes structured into Severity (2 bits), Customer flag (1 bit), Facility (12 bits), and Code (16 bits) (e.g., `STATUS_SUCCESS = 0x00000000`, `STATUS_INVALID_PARAMETER = 0xC000000D`, `STATUS_ACCESS_VIOLATION = 0xC0000005`, `STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034`). Win32 subsystems map `NTSTATUS` to Win32 error codes (`RtlNtStatusToDosError`), stored in the TEB's `LastErrorValue` (`GetLastError`). |
| **Synthetic Filesystems and Namespace Path Hierarchies (`carrick-vfs`, `carrick-runtime`)** | ``/proc`, `/proc/<tid>/stat`, `/proc/self`, synthetic process directories, `devpts`, `AF_UNIX` path endpoints.` | **NT Object Manager Namespace (`\Device`, `\DosDevices`) and PEB Information** | NT has no rootfs `/proc` or `/sys` mount points. Process inspection occurs via query system calls (`NtQuerySystemInformation`, `NtQueryInformationProcess`) and direct user-mode access to the Process Environment Block (`PEB`). Device and filesystem paths reside in the unified Object Manager namespace (`\Device\HarddiskVolume1\...`, `\DosDevices\C:\...`, `\Global??`). Inter-process communication uses Named Pipes (`\Device\NamedPipe\...`) and ALPC ports (`\RPC Control\...`) rather than POSIX domain sockets (`AF_UNIX`). |
| **Process, Thread, and Execution Graph (`carrick-thread`, `carrick-kernel-arena`, `carrick-spec`, `carrick-engine`, `carrick-sched-core`)** | ``pid`/`tgid`, `ThreadId(i32)`, `ThreadIdentity` (tid, file_table), `ThreadCtx` (AArch64 registers), `CLONE_VM`, `CLONE_THREAD`, `CLONE_FILES`, `CLONE_CHILD_CLEARTID`, `ProcessRecord`.` | **Executive Processes (`EPROCESS`), Threads (`ETHREAD`), Client ID, and TEB (Register x18 on ARM64)** | NT processes are created through `NtCreateUserProcess` / `NtCreateProcessEx` and threads through `NtCreateThreadEx`. Processes and threads are identified by `CLIENT_ID` (containing `UniqueProcessId` and `UniqueThreadId` handles). NT has no `fork()` primitive and no concept of thread-group IDs (`tgid`) separate from process IDs. Every NT thread has a Thread Environment Block (`TEB`). On Windows ARM64, the platform register **x18** is reserved by the OS to point to the user TEB (per Microsoft's ARM64 ABI), while x86_64 uses the `gs` segment base. `tpidr_el0` is Linux TLS and must not be confused with the NT TEB register contract. |
| **Userspace Synchronization and Futexes (`carrick-thread`, `carrick-sched-core`, `carrick-guest-mem`, `carrick-embed`)** | ``FutexTable`, `futex` wait/wake/requeue, `FUTEX_WAIT`, `FUTEX_WAKE`, `shared_futex_location`.` | **WaitOnAddress, Keyed Events, and Dispatcher Synchronization Objects** | Windows NT synchronization at the system call boundary uses handle-based dispatcher objects (`NtCreateEvent`, `NtSetEvent`, `NtCreateSemaphore`, `NtCreateMutant`). Modern NT userspace synchronization (SRW locks and condition variables) is built upon `RtlWaitOnAddress` / `RtlWakeAddressSingle`, which is implemented in kernel space via Keyed Events (`NtWaitForKeyedEvent` and `NtReleaseKeyedEvent`) keyed on virtual addresses, rather than Linux futex opcodes with requeue hashing. |
| **Directory Change Notifications (`carrick-inotify-core`, `carrick-el1-abi`)** | ``LinuxInotifyEventHeader`, `alloc_wd`, `INOTIFY_EVENT_HEADER_SIZE`, `LINUX_IN_MODIFY`, `LINUX_IN_Q_OVERFLOW`.` | **Directory Change Notifications (`ReadDirectoryChangesW` / `NtNotifyChangeDirectoryFile`)** | NT filesystem notification uses asynchronous directory change queries (`NtNotifyChangeDirectoryFile` / `ReadDirectoryChangesW`) operating on directory handles with completion routines or I/O completion ports. Results are returned into caller-supplied `FILE_NOTIFY_INFORMATION` buffers rather than a central inotify instance with watch descriptors (`wd`) and `struct inotify_event` wire headers. |
| **Inter-Task Pipes and Event Descriptors (`carrick-pipe-core`)** | ``EVENTFD_MAX`, `broken_pipe_signal` requesting SIGPIPE.` | **Anonymous Pipes (`NtCreatePipeFile`) and NT Events (`NtCreateEvent`)** | NT anonymous pipes are implemented via the Named Pipe File System (`NPFS`) driver via `NtCreatePipeFile` returning read and write handles. Broken pipes report `STATUS_PIPE_BROKEN` on subsequent read/write calls; NT never generates asynchronous signals (like SIGPIPE) on pipe disconnects. Event counters (Linux `eventfd`) correspond to NT Notification or Synchronization Event objects (`NtCreateEvent`). |
| **Interval and POSIX Timers (`carrick-timer-core`)** | ``ITIMER_COUNT = 3` (REAL, VIRTUAL, PROF), `PosixTimerSpec` with `signum` and `si_value`, `OVERRUN_MAX`, BSD kqueue timer-ident flags.` | **Waitable Timers (`NtCreateTimer`, `NtSetTimer`) and APC Delivery** | NT timers are kernel dispatcher objects created via `NtCreateTimer` and armed with `NtSetTimer` (100-nanosecond negative relative or positive absolute intervals). Timers can trigger optional completion APC routines (`PTIMERAPCROUTINE`) executed when the calling thread enters an alertable wait state, rather than generating POSIX signals (`SIGALRM`, `SIGVTALRM`, `SIGPROF`) or filling POSIX overrun counters. |
