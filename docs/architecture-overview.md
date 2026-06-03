# Carrick Architecture Overview

Carrick runs an unmodified Linux ELF binary as a **native macOS process**, not as a guest
inside a virtual machine. There is no Linux kernel, no init, no second scheduler, and no
separate hypervisor RAM pool. Each Linux process is one Darwin process: it forks with
`libc::fork`, it is scheduled by XNU, it is reaped with `wait4`, and its `getpid()` returns
the same number the host `ps` shows. What makes the Linux binary *think* it is on Linux is a
thin slice of hardware — one `Hypervisor.framework` (HVF) virtual CPU per guest thread,
running the guest's own instructions at EL0 with an identity-mapped MMU — plus a host-side
Rust translation layer that services every `svc #0` the guest issues.

The "process, not VM" thesis drives every design decision below. Because the guest pid *is*
the host pid, process-lifecycle syscalls map almost directly onto Darwin primitives
(`fork`→`fork`, `kill`→`kill` with signal-number translation, `wait4`→`wait4`). Because
there is no guest kernel, every Linux syscall is decoded and serviced in host userspace and
re-expressed as Darwin syscalls. And because the guest executes on real silicon at a real
exception level, carrick gets genuine hardware enforcement of the guest/host boundary — at
the cost of one EL0→EL1→EL2→host round-trip per trap, which the rest of this document
explains how carrick keeps cheap.

This page is the architectural deep-dive. For the syscall-by-syscall translation table see
[syscalls-emulation-map.md](syscalls-emulation-map.md); for how to observe any of the
machinery below at runtime see [diagnostics-and-debugging.md](diagnostics-and-debugging.md).

---

## 1. The HVF Trap Boundary & CPU Mode Switch

To run a Linux binary, carrick stands up a tiny VM per process via HVF and hands the guest's
own AArch64 instructions to the hardware. Carrick configures only what is needed to make EL0
execution and the syscall trap work; it never emulates instructions on the hot path.

1. **CPU state initialization.** The vCPU's EL0 state is seeded with the program counter
   pointing at the guest entry (the ELF `e_entry`, or the dynamic interpreter's `AT_BASE`)
   and `SP_EL0` pointing at the guest stack carrick has already populated with `argc`,
   `argv`, `envp`, and the auxiliary vector. HVF starts a vCPU at EL1h, so carrick installs
   a one-page **EL0 entry trampoline** whose first instruction is `eret`: it seeds
   `SPSR_EL1=EL0t` and `ELR_EL1=guest entry`, and the single `eret` drops the vCPU into EL0
   at the program's first instruction.

2. **Exception vectors.** `VBAR_EL1` is programmed to point at a host-built vector-table page
   (`el1_vectors_bytes`, `crates/carrick-mem/src/memory.rs:1506`). The AArch64 vector table
   is sixteen 0x80-byte slots; carrick fills the "Lower EL using AArch64, synchronous" slot
   at offset `0x400` (`AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET`) with a two-instruction stub and
   makes every other slot a bare `eret` so spurious exceptions just return. When the guest
   executes a Linux syscall via `svc #0`, the CPU vectors into that synchronous slot.

3. **Hypervisor exit.** The synchronous-slot stub is `hvc #2; eret`
   (`AARCH64_HVC_SYSCALL_OPCODE`, `crates/carrick-mem/src/memory.rs:133`). The `hvc` forces
   an immediate VM-exit to EL2, returning control to carrick in host userspace. (`hvc #0` is
   deliberately *avoided*: HVF can consume an `hvc #0` as an SMCCC hypercall before reporting
   the exit when `x0` looks like an SMCCC function ID — V8's mmap hints can. `hvc #1` is
   reserved for the EL1 stage-1 maintenance trampoline described in §2.)

4. **Register inspection & dispatch.** At the exit, carrick reads the exception class.
   A direct EL0 `svc` surfaces as `EC=0x15` (`AARCH64_SVC_EXCEPTION_CLASS`); the EL1 vector's
   `hvc` re-trap surfaces as `EC=0x16` (`AARCH64_HVC_EXCEPTION_CLASS`), in which case carrick
   reads `ESR_EL1` to confirm an underlying SVC and otherwise treats it as a fault
   (`run_until_syscall`, `crates/carrick-hvf/src/trap.rs:1956`). On a confirmed syscall it
   snapshots `x0..x5` and `x8` into an `Aarch64SyscallFrame` (`trap.rs:2068`) — `x8` is the
   syscall number, `x0..x5` the six arguments — dispatches to the matching Rust handler, and
   writes the return value back into `x0` (`complete_syscall`, `trap.rs:994`) before resuming
   the vCPU at the post-`svc` `ELR_EL1`.

```mermaid
sequenceDiagram
    participant Guest as Guest EL0 (Linux Process)
    participant Kern as Guest EL1 (VBAR_EL1 vectors)
    participant Host as Host EL2 → userspace (carrick runtime)

    Guest->>Kern: svc #0 (Linux syscall, nr in x8, args in x0..x5)
    Note over Kern: Lower-EL Synchronous slot (VBAR_EL1 + 0x400)
    Kern->>Host: hvc #2 (VM-exit to EL2)
    Note over Host: Read EC/ESR_EL1; decode x0..x5,x8;<br/>dispatch to Rust handler
    Host->>Guest: Write x0 (retval) + resume vCPU at post-svc PC
```

> [!NOTE]
> The trap path is also carrick's fault path. Any other lower-EL synchronous exception —
> an instruction abort (`EC=0x20`), a data abort (`EC=0x24`), an undefined instruction — lands
> in the same EL1 vector and re-traps via `hvc`; carrick reads `ESR_EL1`, declines to treat
> `x8` as a syscall number, and instead delivers the appropriate Linux signal (e.g. `SIGSEGV`,
> `SIGILL`) using the fault `ESR`/`FAR` captured at exit. A handful of EL0 system-register
> reads (`CTR_EL0`, feature-ID registers Apple Rosetta probes) are emulated inline here so the
> guest never sees a fatal undef.

---

## 2. Identity Mapping & the FEAT_PAN3 Workaround

ARMv8-A exclusive load/store primitives — `ldaxr`/`stlxr`, the backbone of every guest mutex,
futex fast-path, and atomic — are the load-bearing constraint on how carrick maps guest
memory.

### Why a page table is mandatory

If the guest ran with the stage-1 MMU disabled (`SCTLR_EL1.M=0`), the architecture forces
*every* data access to be treated as `Device-nGnRnE`. Exclusive instructions on Device memory
are architecturally prohibited; Apple's HVF raises an external abort rather than treating it
as implementation-defined. The very first `ldaxr` musl issues from `pthread_mutex_lock` then
aborts, and the guest spins forever. Carrick must therefore enable the MMU and tag guest
memory as **Normal Inner-Shareable Write-Back cacheable** before the guest ever runs.

### The identity map

`stage1_identity_page_tables` (`crates/carrick-mem/src/memory.rs:1250`) builds a coarse
**stage-1 identity map**: the guest virtual address *is* its intermediate physical address,
across the whole `0..1 TiB` window that M-series HVF's 40-bit IPA ceiling allows. The trap
engine programs `MAIR_EL1` slot 0 = Normal WB cacheable, points `TTBR0_EL1`/`TTBR1_EL1` at the
table root, configures `TCR_EL1` for two active 48-bit halves (4 KiB granule, 40-bit IPS,
top-byte-ignore for Rosetta pointer tags), and sets `SCTLR_EL1.M=1` on top of `C=1, I=1`
(caches) plus `UCI`/`UCT`/`DZE` so glibc's EL0 cache-maintenance, `CTR_EL0` read, and
`DC ZVA` work without trapping (`trap.rs:1377`–`1438`).

The table is mostly coarse blocks (1 GiB at L1, 2 MiB at L2) so it is small and cheap to walk,
but it is deliberately fine-grained where it must be:

* **The first 2 MiB is split to 4 KiB pages (L3).** `VA 0..0x10000` stays *invalid* as a
  null guard (matching Linux `mmap_min_addr`), so a guest NULL deref faults cleanly to
  `SIGSEGV` at stage 1 instead of crashing the vCPU thread on an unbacked stage-2 fault. From
  `0x10000` up the pages are user-accessible, which lets a low-loading static binary — Go's
  `go` toolchain links its first segment at `0x10000` — actually run.
* **A dedicated "kernel hole" at 180 GiB** (`LINUX_KERNEL_REGION_BASE = 0x2D_0000_0000`) holds
  carrick's EL1-only pages: the EL0 entry trampoline, the `VBAR_EL1` vector table, the page
  tables themselves, and the EL1 maintenance trampoline. It sits well above any guest image
  and below the heap/mmap/stack windows.

### The FEAT_PAN3 workaround

On Apple Silicon, HVF starts the vCPU with `PSTATE.PAN=1` (Privileged Access Never) and
*keeps* it set regardless of what the host writes to `CPSR` via `set_reg`. With FEAT_PAN3
(mandatory on ARMv8.3+), any EL1 instruction fetch from a page whose descriptor has `AP[1]=1`
(`AP=01`, user-accessible) raises a permission fault. Carrick never gets to clear PAN, so it
splits the identity map by *who fetches from each page*:

* **Kernel-only pages** (the entry trampoline, vectors, and page-table region — everything
  EL1 fetches): `AP=00` (RW at EL1, no EL0 access), `UXN=1` (EL0 can never fetch them). With
  `AP[1]=0` there is no user-accessible bit for FEAT_PAN3 to trip on. `PXN=0` so EL1 *can*
  fetch the trampoline/vectors. This is `KERNEL_BLOCK_FLAGS` (`memory.rs:1288`).
* **User pages** (guest text, interpreter, heap, mmap arena, stack — everything EL0 fetches):
  `AP=01` (RW at EL0+EL1), `UXN=0` (EL0 may execute), and crucially `PXN=1` — **privileged
  execute never**. `PXN=1` tells the CPU that EL1 is forbidden from fetching instructions
  here, so the FEAT_PAN3 check never fires on these otherwise-user-accessible pages. This is
  `USER_BLOCK_FLAGS`/`USER_PAGE_FLAGS` (`memory.rs:1296`).

A second consequence of the W^X discipline: the anonymous mmap arena's boot blocks default
`UXN=1` (non-executable), matching Linux's "a `mmap` without `PROT_EXEC` is not executable".
Only a rare `PROT_EXEC` mapping splits a block to clear `UXN`, so the common RW mmap is a
no-op in the runtime page-table manager.

> [!IMPORTANT]
> Carrick uses **stage-1 only**; it does not use HVF's stage-2 (IPA→PA) translation. That
> avoids stage-2 TLB pressure but means a runtime page-table edit (guest `mmap`/`mprotect`/
> `munmap`, which the host applies by editing the live stage-1 descriptors) needs explicit
> maintenance: arm64 public HVF exposes no stage-2 TLB shootdown. Carrick owns guest EL1, so
> it runs a tiny EL1 maintenance trampoline (`dsb sy; tlbi vmalle1is; dsb sy; isb; hvc #1`,
> closing with `hvc #1` as its completion marker) on its own vCPU to flush stage-1, gated by
> the Pause-Modify-Resume barrier in §3.

---

## 3. The BKL-free Concurrency Model

Carrick retired its Big Kernel Lock. A multithreaded guest — a web server, a build system,
CPython's thread pool, the Go runtime — runs every guest thread on its own native CPU,
concurrently, with no global serialization point.

### One pthread, one vCPU, one shared address space

Each guest thread maps to a native macOS `pthread`, and each pthread builds and owns its **own
HVF vCPU** for its whole lifetime. When the guest issues a thread-creating `clone`/`clone3`,
the runtime spawns a `guest-tid-N` thread (`crates/carrick-runtime/src/runtime.rs:1768`) which
calls `HvfTrapEngine::from_thread_spec` (`crates/carrick-hvf/src/trap.rs:3496`) to create a
fresh vCPU **in the same process VM**. `hv_vm_map` is VM-global on HVF, so the new vCPU
already sees every region the parent mapped — all sibling vCPUs translate the *same* guest
address space through the *same* page tables. The new vCPU is seeded at the EL0 trampoline
with `ELR_EL1` = the post-`clone` instruction so its first `eret` resumes the guest thread
exactly where Linux would.

> [!NOTE]
> HVF caps concurrent vCPUs (64 on current hardware). carrick binds one vCPU per guest thread,
> so a guest with more live threads than the cap (CPython `test_queue` spawns 100) blocks the
> new pthread in `wait_for_vcpu_slot` *after* `clone` already reported success to the guest —
> matching Linux, which has no such cap — and starts the thread the instant a sibling exits and
> frees a slot. Without this, a thread that silently failed to get a vCPU would deadlock any
> `join` on it.

### Subsystem-level locks, not one big lock

The runtime shares its kernel state as a plain `Arc<KernelState>`
(`runtime.rs:1289`) across every vCPU thread — no `SendKernel`, no `Rc<RefCell>`, no global
dispatch lock. `KernelState` wraps a single `SyscallDispatcher` whose subsystems are
*independently* lockable (`crates/carrick-runtime/src/dispatch/mod.rs:929`):

| Subsystem | State | Lock |
|---|---|---|
| memory | brk, mmap arena, shared-file IPA window, `/proc/self/maps` regions | `Mutex<mem::MemState>` |
| process | exe path, personality, dumpable flag, task comm | `Mutex<proc::ProcState>` |
| credentials | uids/gids, umask | `Mutex<creds::CredState>` |
| signals | handlers, mask, pending set, alt stack | `Mutex<signal::SignalState>` |
| filesystem / I/O | VFS mount table, open-fd table, cwd, stdio buffers | `fs::FsState` / `fs::IoState` |
| SysV IPC | host-file-backed shared-memory registry | `Mutex<sysv::SysvShmState>` |

Two vCPUs in unrelated subsystems run fully in parallel: thread A reading a socket
(`fs`/`io`) and thread B growing the heap (`mem`) never contend. The futex table and thread
registry are separate `Arc`-shared structures; a guest `FUTEX_WAIT` parks the host thread on a
Darwin `__ulock`/kqueue rather than spinning a lock.

### Narrow borrows via `SyscallCtx`

Each dispatched syscall is handed a transient `SyscallCtx<'a, M>`
(`dispatch/mod.rs:505`) — a scoped borrow of just the guest memory, the compat reporter, and,
on the threaded path, an optional `ThreadCtx` carrying this thread's Linux tid and the shared
thread/futex tables. A handler locks only the subsystem(s) it actually touches, for only as
long as the call runs. The borrow is dropped before the vCPU resumes, so locks are never held
across guest execution.

### Where the threads *do* synchronize

Two operations are genuinely process-global and use explicit stop-the-world barriers rather
than the per-subsystem locks (`crates/carrick-hvf/src/fork_quiesce.rs`):

* **`fork(2)`** must snapshot a coherent address space. The forking thread raises a quiesce
  flag and kicks every sibling vCPU out of `hv_vcpu_run`; each sibling parks at the lock-safe
  run-loop top (a Dekker handshake guarantees it either observes the quiesce or hasn't entered
  the guest yet). Only then does the parent `libc::fork`, after which both parent and child
  rebuild a fresh vCPU. The child is a real new host process; it inherits the COW'd address
  space and re-registers its host buffers via `hv_vm_map`.
* **A runtime page-table edit** (the §2 stage-1 mutation) uses `PtQuiesce`, a
  Pause-Modify-Resume barrier: pause siblings, edit the live descriptors from the host, run
  the EL1 maintenance trampoline to flush stage-1, then resume. This is distinct from the fork
  quiesce (which tears vCPUs down rather than resuming them).

---

## 4. Interactive PtyRelay & Terminal Bridging

`carrick run -t` gives the guest an interactive terminal: a real shell with job control,
line editing, and live window resizing. This needs clean byte propagation, terminal-state
save/restore, and reliable signal forwarding between the user's terminal and the guest.

### Host pty allocation

Carrick allocates a host pseudo-terminal pair via `posix_openpt` + `grantpt` + `unlockpt` +
`ptsname` (`HostPty::allocate` → `vfs::devpts::open_master`,
`crates/carrick-runtime/src/pty_relay.rs:110`). The slave fd is `dup2`'d onto host fds 0, 1,
and 2 (`crates/carrick-runtime/src/interactive_supervisor.rs:351`) and made the controlling
terminal with `ioctl(TIOCSCTTY)`; the guest process inherits these as its stdin/stdout/stderr,
so the guest's terminal *is* the pty slave and gets real line discipline (cooked mode,
`Ctrl-C`→`SIGINT`, `Ctrl-Z`→`SIGTSTP`).

### The relay thread

A dedicated `PtyRelay` thread (`pty_relay.rs`) runs a bidirectional `poll(2)` loop multiplexing
several fds:

* **real terminal `stdin` → pty master** — the user's keystrokes reach the guest.
* **pty master → real terminal `stdout`** — the guest's output reaches the screen.
* **a shutdown self-pipe** — lets `stop()` break the `poll` for a clean teardown, restoring the
  saved host-terminal termios.

### SIGWINCH via self-pipe

Window resizes are forwarded without calling unsafe functions in async-signal context. The
process-level `SIGWINCH` handler does the only async-signal-safe thing — it `write(2)`s a
single byte to a non-blocking self-pipe (`pty_relay.rs:26`). The `poll` loop sees that pipe
readable, drains it, reads the new size from the real terminal with `ioctl(TIOCGWINSZ)`, and
applies it to the pty master with `ioctl(TIOCSWINSZ)` (`propagate_winsize`, `pty_relay.rs:49`)
so the guest's slave observes the resize and the guest is delivered its own `SIGWINCH`.

> [!NOTE]
> Known limitations of the current interactive bridge: `ttyname(3)`, `tty(1)`, and `/dev/tty`
> do not resolve to the pty slave path, and a subset of concurrent shell + child writes can
> staircase (`\n` reaching the raw host terminal without `\r`) because the macOS pty slave
> termios is shared between the shell host-process and the forked child host-process during a
> raw/cooked transition. These are tracked, not fundamental.

---

## See also

* [../README.md](../README.md) — quickstart, the crate workspace, and the build/codesign gate.
* [syscalls-emulation-map.md](syscalls-emulation-map.md) — the ~150-syscall translation map
  (what each Linux syscall lowers to on Darwin).
* [diagnostics-and-debugging.md](diagnostics-and-debugging.md) — `carrick trace` (in-process
  libdtrace + USDT probes), the always-on event ring, the carrick-lldb plugin, and the
  diagnostic env vars used to crack the timing-sensitive bugs in §2–§3.
* [conformance-testing.md](conformance-testing.md) — running and interpreting the differential
  Docker-oracle suites and the compile-time no-panic gate.
* [conformance-coverage.md](conformance-coverage.md) — the active probe-gate map: every
  syscall-ABI invariant and its owning deterministic probe.
