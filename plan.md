# Carrick

A Linux binary compatibility layer for macOS on Apple Silicon. Unmodified Linux binaries run as native macOS processes, with syscalls trapped via Hypervisor.framework and serviced by a host-side translation library. No virtual machine in the traditional sense, no separate Linux kernel, no second memory pool. Inspired by illumos LX-branded zones, with the kernel-side work pushed into userspace because we don't own the kernel.

The name is a type of knot used to join two heavy ropes of different sizes.

## Goals

- Run unmodified Linux ELF binaries on macOS / Apple Silicon as ordinary macOS processes.
- Use OCI (Docker) images as the filesystem and distribution format.
- Real `fork(2)`, real `clone(2)`, real `splice(2)` — not snapshot-restore approximations.
- Tight feedback loop for discovering and implementing missing compatibility, via DTrace probes throughout the dispatch path.
- Host-path transparency: `/Users/you/code` on macOS is `/Users/you/code` inside Linux processes.

## Non-goals (v1)

- cgroups, namespaces, network isolation. The OCI runtime spec is out of scope initially; we use OCI images for filesystem and distribution only.
- GUI Linux applications (no Wayland/X surface).
- x86_64 binaries. Rosetta-for-Linux interop can come later; v1 is ARM64-native only.
- A Docker API socket. `carrick` is the primary surface; Docker CLI compatibility is a later layer.

## Architecture

### One-paragraph summary

Each Linux process is a real macOS process. The macOS host process owns the Linux process's address space directly (allocated via `mach_vm_allocate`), so address-space operations like `fork(2)` map onto Mach VM primitives and get COW for free. Hypervisor.framework is used as a *syscall trap mechanism only* — a tiny VM per process, no Linux kernel inside it, EL0 set up to execute the guest binary. On `svc #0` (or equivalent), the guest traps out and the host's translation library services the syscall against Darwin primitives. Filesystem comes from OCI image layers composed in a userspace VFS layer, mounted such that host paths appear at the same paths inside. DTrace USDT probes throughout the dispatch path provide structured compatibility discovery: any unhandled syscall, partial ioctl, or unimplemented `/proc` read fires a probe with full argument capture.

### Key architectural commitment: host process holds the address space

This is the single most important decision in the project, and it diverges from Noah.

Noah used Hypervisor.framework as a *process container* — the VM held the Linux process's address space and Noah implemented fork via VM snapshot + recreate, which was ~100× slower than native fork. This made fork-heavy workloads (shells, build systems, anything that exec's a lot) feel awful — exactly the workloads people run in WSL-likes.

Carrick inverts the relationship:

- The macOS host process owns the Linux process's address space as ordinary Mach VM regions.
- HVF stage-2 page tables map those host pages into the guest's view of memory (zero-copy).
- The VM is essentially empty — no kernel running inside it. It's a CPU-mode-switch trick that gives us a clean trap mechanism for `svc`.
- `fork(2)` becomes a real macOS `fork(2)`. Mach VM gives us COW. The child inherits the address space, FD table, and HVF context (recreated in the child).
- `clone(2)` with thread flags maps to `pthread_create`; with process flags maps to fork.
- `ptrace` becomes Mach task port operations.
- `splice(2)` plumbs between two host file descriptors via host primitives (`fcopyfile`, `sendfile`-equivalents). The strictest zero-copy semantics may degrade to read+write under the hood; we document the difference and most callers won't notice.

The cost of this inversion: we cannot lean on a Linux kernel inside the VM to do anything for us. Every syscall is ours. The VM is just a CPU-mode-switch trick. In exchange, we get real process semantics, real signals, real fork.

## Layered components

### Layer 0 — Trap mechanism

Hypervisor.framework, configured per-process. Each Linux process is a host process running a tiny HVF VM with EL0 set up to execute the Linux binary. `svc #0` traps to EL2; control returns to host. The VM contains no Linux kernel — just the guest's user-mode address space, mapped via stage-2 page tables backed by host Mach VM regions.

### Layer 1 — Address space and process lifecycle

Host-side process model.

- **ELF loader** runs in the host. Lays out the Linux process's memory in host address space. Handles static and dynamic binaries. Resolves `ld-linux-aarch64.so` and lets it do glibc/musl startup against our syscall surface.
- **`fork(2)`**: real macOS fork. Child inherits address space (COW via Mach VM), FD table, signal dispositions, HVF context (recreated in child).
- **`execve(2)`**: tear down address space, reload via ELF loader.
- **`clone(2)`**: `CLONE_VM | CLONE_THREAD` → `pthread_create`. Process-creation flags → fork-with-shared-resources.
- **`ptrace(2)`**: implemented over Mach task ports. Sufficient for `gdb`, `strace` (Linux strace running against a Linux child).

### Layer 2 — Syscall translation

The dispatch table. The bulk of the implementation.

- Per-syscall handlers in host code (Rust or Zig — see open question below).
- Organized by subsystem: fs, net, signal, mm, sched, time, ipc. Each subsystem is 50–200 syscalls of effort.
- DTrace probes at entry and exit of every handler. Additional `unhandled` and `partial` probes for unimplemented paths.
- Single source of truth for the syscall table generates dispatch code, probe definitions, and test scaffolding.

### Layer 3 — VFS

APFS as backing store. Userspace VFS layer composes:

- **Host passthrough**: `/Users`, `/Volumes`, `/private/tmp` visible at the same paths. UID/GID translation between macOS user (501) and Linux user.
- **OCI rootfs**: `/usr`, `/etc`, `/bin`, `/lib` from extracted image layers. Overlay semantics implemented in the VFS layer rather than on disk — no layer materialization, lower disk use, faster image switching.
- **Synthetic `/proc` and `/sys`**: generated on read against host process state. Not backed by files.

APFS case-insensitivity is handled by hosting the OCI rootfs on a case-sensitive disk image (sparsebundle), mounted at startup. Host directories ride on user's APFS volume directly — and case-conflict bugs there are real-world Linux bugs anyway.

### Layer 4 — Networking

BSD sockets directly for most things.

- **`epoll`** implemented over `kqueue`. Edge-triggered vs. level-triggered, `EPOLLONESHOT`, `EPOLLEXCLUSIVE`. `eventfd` and `timerfd` synthesized in userspace.
- **Netlink**: faked for common cases. Interface enumeration via `getifaddrs`, routing tables via `sysctl`, formatted as Linux-style netlink responses.
- **`AF_UNIX`** passes through directly.
- **Network namespaces** deferred to post-v1.

### Layer 5 — OCI image plumbing

Use OCI images as the filesystem and distribution format. We are *not* implementing the OCI runtime spec.

- **Registry client**: reuse an existing library (containerd's `remotes`, or `oras-go`).
- **Layer storage**: `~/.carrick/layers/`, content-addressed.
- **Layer composition**: in the VFS layer, not by extraction.
- **CLI**: `carrick pull image:tag`, `carrick run image:tag command`.

### Layer 6 — User-facing CLI

- `carrick run <image> [cmd]` — launch a binary from an image.
- `carrick shell` — drop into a default machine's shell.
- `carrick exec` — run in an existing context.
- `carrick pull <image>` — pull an image.
- `carrick compat-report -- <cmd>` — run with DTrace probes active, produce structured compatibility report.

## DTrace compatibility loop

A first-class feature, not just a development tool.

### Probe schema

USDT probes at every translation boundary, structured for aggregation:

| Probe | Args | Fires on |
|---|---|---|
| `carrick*:::syscall-entry` | nr, name, regs | every Linux syscall |
| `carrick*:::syscall-return` | nr, name, retval, errno | every return |
| `carrick*:::unhandled-syscall` | nr, name, regs | unimplemented syscall |
| `carrick*:::partial-syscall` | nr, name, regs, reason | implemented but with caveats (e.g., unknown flag bits) |
| `carrick*:::unhandled-ioctl` | fd, request, arg | ioctl we don't recognize |
| `carrick*:::proc-read-unimplemented` | path | read of `/proc/...` we don't synthesize |
| `carrick*:::sys-read-unimplemented` | path | same for `/sys/...` |
| `carrick*:::signal-unsupported` | signum, reason | signal semantics we don't fully model |

Cheap when disabled (DTrace's standard pitch). Structured arguments so `dtrace -n 'carrick*:::unhandled-syscall { printf("%s(%d, %d, ...)", arg1, arg2, arg3); }'` Just Works.

### Compatibility report

`carrick compat-report -- <command>` runs the command under DTrace, aggregates unhandled syscalls and ioctls, and emits a frequency-sorted report. This is the artifact people attach to bug reports. The format is stable and machine-parseable.

### Regression suite

Every unhandled syscall observed in the wild becomes a test case, with arguments captured from the real workload. New translation-layer code must keep these passing. The compatibility report from a known-broken workload becomes a fixture.

### SIP caveat

macOS DTrace is real but partially neutered by SIP. Probe-based modification of targets is restricted; read-only observation is fine. We document the `csrutil` interactions, and we ship a `--trace-compat` fallback flag on the runtime that writes the same data via internal hooks for users who can't or won't loosen SIP.

## Build vs. reuse

| Component | Decision |
|---|---|
| HVF trap mechanism | Reuse Hypervisor.framework |
| ELF loader | Build — straightforward, ~few thousand lines |
| Syscall dispatch + handlers | Build — this is the project |
| VFS layer | Build — overlay logic + Darwin VFS adapter |
| Synthetic `/proc`, `/sys` | Build |
| Network translation (epoll-on-kqueue, netlink) | Build |
| Signal translation | Build — Linux semantics on Mach exception ports |
| OCI registry client | Reuse — containerd `remotes` or `oras-go` |
| OCI image layer format | Reuse the spec; build our overlay reader |
| DTrace probes | Reuse USDT macros; build the schema and reports |
| CLI | Build |

## MVP scope

The v0 milestone is "Alpine bash works interactively."

1. ELF loader runs a static `hello-world` binary.
2. HVF trap mechanism: catch `write(2)` and `exit(2)`. Bring-up milestone.
3. Implement the first ~30 syscalls — static `busybox` runs `ls`, `cat`, `echo`.
4. Dynamic linking — `ld-linux-aarch64.so` loads, glibc/musl startup completes. Unlocks ~90% of real binaries.
5. VFS layer: read-only mount of an extracted OCI rootfs.
6. DTrace probe scaffolding throughout; `carrick compat-report` produces output.
7. `bash` from an Alpine image runs interactively.

Optimistic estimate: six engineer-months to v0. More likely nine.

After v0:

- v0.1 — fork(2) and clone(2)
- v0.2 — networking (epoll-on-kqueue, BSD sockets)
- v0.3 — `/proc` fidelity sufficient for Go runtime, glibc introspection
- v0.4 — `splice(2)`, `sendfile(2)`, `io_uring` (or explicit non-support with a clear error)
- v1.0 — `apt-get install` works inside a Debian image. That's the public bar.

## Hard parts to budget for

In rough order of cost:

1. **Signal semantics.** Linux signal delivery, `signalfd`, `sigaction` with `SA_RESTART`, signal masking around syscalls, signal-vs-syscall race conditions. Mach exception ports can model it but the mapping is intricate.
2. **`/proc` fidelity.** `/proc/self/maps` has to be byte-accurate or Go's runtime gets confused. `/proc/cpuinfo` parsing breaks in surprising ways. Strategy: implement the ~20 files real software touches, get those exactly right, return `ENOENT` for the rest with a DTrace probe firing so we discover the gaps.
3. **epoll-on-kqueue.** Edge-triggered semantics, `EPOLLONESHOT`, `EPOLLEXCLUSIVE`, interaction with synthesized `eventfd`/`timerfd`. Doable, tedious.
4. **Threading model edge cases.** `set_robust_list`, `set_tid_address`, glibc NPTL assumptions. Most threads "just work" via pthread; the futex implementation needs care.
5. **APFS case-insensitivity** for the OCI rootfs. Mitigated by hosting the rootfs on a case-sensitive sparsebundle, but the mount-management story needs to be clean.
6. **Sleep/wake and HVF context survival.** macOS suspending and resuming with Carrick processes in flight. HVF's behavior across system sleep is the open question.

## Open questions

These need answers before serious implementation, in roughly the order they'll bite us:

1. **Implementation language.** Rust vs. Zig vs. C. Rust gets us memory safety in the dispatch path, which matters when we're servicing syscalls in the host's address space. Zig has better ergonomics for low-level work and cleaner C interop. Plain C is fastest to start, hardest to maintain. Leaning Rust.
2. **HVF context per-process cost.** What's the actual memory and setup cost of an HVF context on M-series? If it's 50KB and 100µs, great. If it's 5MB and 50ms, we need to pool contexts or use a different trap mechanism for short-lived processes. Empirical question, answer it on hardware in week one.
3. **Mach exception port for `svc` vs. HVF VM-exit.** Two ways to trap the syscall instruction. HVF is the planned path; an alternative is registering a Mach exception handler on `EXC_BAD_INSTRUCTION` for `svc` in a regular macOS process. Likely slower per syscall but no HVF overhead. Worth benchmarking before committing.
4. **fork() inside an HVF-bearing process.** Real macOS fork is fine; the question is whether the HVF context can be re-attached cleanly in the child or must be recreated. If recreation, what's the cost, and does it dominate fork latency? This determines whether shell-heavy workloads are fast or merely correct.
5. **Threading: shared HVF context vs. per-thread.** Linux threads share an address space (and Linux's view of the process). Do we share one HVF context across threads with serialized vCPU access, or one per thread? Per-thread is cleaner; shared may be necessary for memory cost. Benchmark.
6. **APFS sparsebundle for OCI rootfs — mount lifecycle.** Auto-mount on `carrick run`? Per-machine sparsebundle or shared? How do we handle the user yanking the disk image manually? Operational question more than architectural.
7. **DTrace under SIP — what's the actual usability bar?** Can a typical developer run `carrick compat-report` without `csrutil disable`? If not, the `--trace-compat` fallback isn't a fallback, it's the primary path, and we should design it accordingly.
8. **`io_uring`.** Implementing it is a substantial subproject (~60 opcodes, deep ordering guarantees). Initial position: return `ENOSYS`, let callers fall back to `epoll`. Revisit when something important refuses to.
9. **Rosetta-for-Linux integration.** Apple's `rosettad` can run x86_64 Linux binaries inside a Linux VM. Can we invoke it as a translation layer for individual binaries, or does it require a full VM context? Defer to post-v1, but understanding the constraint shapes whether x86 support is ever feasible.

## Project shape

- Single repo, mixed Rust (or chosen lang) for the runtime + shell scripts for tooling.
- Public from day one. The DTrace-driven compatibility loop only works at scale if external users run it.
- Compatibility reports are first-class artifacts: a public dashboard of "what's the top unimplemented syscall by workload."
- No corporate sponsor required for v0; this is a research-grade systems project that earns adoption by being good.