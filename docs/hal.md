# Carrick HAL and Platform Architecture

Carrick's portability work is organized around three independent axes:

- **Runtime core:** ELF loading, VFS/rootfs, syscall dispatch, process model,
  signal state, timers, and conformance reporting.
- **Host primitives:** errno/signal translation, readiness multiplexing, futexes,
  host file/socket/timer mechanisms, and other OS services.
- **VMM backends and guest ISA:** HVF, KVM, bhyve, or NVMM driving AArch64 or
  x86_64 guest execution.

The goal is not a lowest-common-denominator VM abstraction. Each platform should
use the best host mechanism available while satisfying the same Linux ABI
contract at the runtime boundary.

> [!IMPORTANT]
> This document describes the current crate architecture. Historical plans under
> `docs/superpowers/specs/` and `docs/superpowers/plans/` are useful archaeology,
> but some still use old crate names such as `carrick-hvf`, `carrick-linux`, or
> `carrick-bhyve`. Treat current source and this document as authoritative.

---

## Current Platform Matrix

| Feature | Host | VMM crate | Host crate | Guest ISA status | Notes |
| --- | --- | --- | --- | --- | --- |
| `platform-macos` | macOS / Apple Silicon | `carrick-vmm-hvf` | `carrick-host`, `carrick-host-bsd` | AArch64 mature; amd64 via Rosetta path | Default feature; release path; requires codesign entitlement. |
| `platform-linux` | Linux | `carrick-vmm-kvm` | `carrick-host-linux` | AArch64 KVM path; x86_64 active lane | Build with `--no-default-features --features platform-linux`. |
| `platform-freebsd` | FreeBSD | `carrick-vmm-bhyve` | `carrick-host-bsd` | x86_64 active lane | Requires `vmm.ko` / `/dev/vmm`; target-host cleanup matters. |
| `platform-netbsd` | NetBSD | `carrick-vmm-nvmm` | `carrick-host-bsd` | x86_64 bring-up lane | Nested NVMM host behavior is a known blocker without target preparation. |

Each non-macOS build selects exactly one platform feature:

```sh
cargo build -p carrick-cli --no-default-features --features platform-linux
cargo build -p carrick-cli --no-default-features --features platform-freebsd
cargo build -p carrick-cli --no-default-features --features platform-netbsd
```

The default `platform-macos` feature pulls `carrick-vmm-hvf` and Apple
Hypervisor.framework bindings, so it is intentionally not used for non-macOS
target builds.

---

## Crate Boundaries

### Platform-neutral contracts

- `carrick-hal` is the traits-only leaf crate. It defines the runtime trap
  contract (`SyscallTrap`, `TrapError`, `RawSyscall`), raw hypervisor traits
  (`HvVm`, `HvVcpu`, `VcpuExit`), guest architecture traits, event and futex
  contracts, threaded-loop glue traits, signal/timer delivery surfaces, and
  shared error/register types. It has no OS or hypervisor dependency.
- `carrick-guest-mem` owns the guest-memory access trait and syscall frame hub
  types used by runtime handlers and live VMM engines.
- `carrick-mem` owns guest address-space construction: ELF layout, page tables,
  vector/trampoline pages, VDSO/vvar setup, and memory-region helpers.
- `carrick-thread`, `carrick-signal-core`, and `carrick-timer-core` hold
  platform-neutral thread/futex registry state, pending-signal bookkeeping, and
  interval/POSIX timer slot state.
- `carrick-observability` holds platform-neutral compat-reporting support.

### Host primitive crates

- `carrick-host` is Darwin-specific support used by the macOS path: host facts,
  guest CPU accounting, host process details, host mappings, and macOS futex
  helpers.
- `carrick-host-bsd` is the BSD-family host layer selected by macOS, FreeBSD,
  and NetBSD. It contains BSD errno translation, kqueue abstractions, BSD futex
  wrappers, and BSD-family signal-number translation.
- `carrick-host-linux` is the Linux host layer. It provides the native epoll
  multiplexer and Linux host errno identity hook.
- `carrick-portable` is a thin raw-`libc` shim for symbols and constants that
  differ or are missing across supported host OSes.

### VMM backend crates

- `carrick-vmm-hvf` is the mature macOS Hypervisor.framework backend. It owns
  the HVF trap engine, vCPU coordination, fork/exec address-space management,
  signal injection/restoration glue, and USDT probe provider.
- `carrick-vmm-kvm` is the Linux/KVM backend. It contains KVM machine/vCPU
  wrappers, aarch64 KVM support, x86_64 KVM support, kick/futex/fork/timer
  backend glue, and standalone `run-elf` surfaces for target-host bring-up.
- `carrick-vmm-bhyve` is the FreeBSD/bhyve backend. On x86_64 it uses bhyve
  through the shared `carrick-x86` engine and supplies FreeBSD-specific
  kick/futex/fork/timer/signal glue.
- `carrick-vmm-nvmm` is the NetBSD/NVMM backend. It mirrors the x86_64 backend
  shape and contains NVMM machine/vCPU wrappers plus the NetBSD-specific glue.
- `carrick-x86` is the shared x86_64 VMM engine. It owns long-mode bring-up,
  register/snapshot abstractions, fault tables, x86 VDSO helpers, and the
  generic `X86EngineCore<V>` over a backend-provided `X86Vmm`/`X86Vcpu`.

### Runtime and product layers

- `carrick-runtime` owns Linux behavior: ELF execution, syscall dispatch, VFS,
  fs backends, process model, credentials, namespaces, `/proc`, sockets, IPC,
  and the platform-selected execution loop.
- `carrick-image` owns OCI image acquisition and local content storage.
- `carrick-engine` lowers docker-shaped CLI requests and image config into a
  resolved `RunSpec`.
- `carrick-cli` is the `carrick` binary: docker-compatible command surface,
  diagnostic commands, lifecycle commands, and the final call into
  `Runtime::execute`.
- `carrick-conformance` shells out to built carrick binaries and Docker oracles
  to run differential suites and render the support matrix.

See [../crates/README.md](../crates/README.md) for a compact workspace map.

---

## Runtime Dependency Shape

The product path remains:

```text
carrick-cli -> carrick-engine -> { carrick-image, carrick-runtime } -> carrick-spec
```

Platform code is selected below `carrick-runtime` and `carrick-cli`:

```text
platform-macos
  -> carrick-vmm-hvf
  -> carrick-host + carrick-host-bsd

platform-linux
  -> carrick-vmm-kvm
  -> carrick-host-linux

platform-freebsd
  -> carrick-vmm-bhyve
  -> carrick-host-bsd

platform-netbsd
  -> carrick-vmm-nvmm
  -> carrick-host-bsd
```

The VMM crates do not own the Linux syscall semantics. They provide engines,
register access, guest memory access, signal/timer delivery, and vCPU
coordination. The runtime owns the dispatcher and calls through the trait
surfaces exposed by `carrick-hal`.

---

## Guest ISA Split

### AArch64

The macOS/HVF path is the reference implementation. A guest executes Linux
AArch64 instructions at EL0. Carrick owns guest EL1 enough to install vectors,
trampolines, page tables, and maintenance paths; an `svc #0` enters the EL1
vector and then exits to the host through `hvc`.

The syscall metadata table for this path is currently in
`crates/carrick-vmm-hvf/src/syscall.rs`; guest-architecture table abstractions
also live in `carrick-hal`.

### x86_64

x86_64 guests are handled by the shared `carrick-x86` engine plus thin backend
adapters in KVM, bhyve, and NVMM. The shared engine owns:

- long-mode page-table and descriptor setup;
- syscall doorbell and fault-doorbell handling;
- register snapshot/restore;
- fork RAM strategy hooks;
- common run-ELF service-loop plumbing;
- x86 VDSO helpers.

Backend crates supply the raw VMM operations and platform glue. This avoids
copying the same long-mode/trap-loop logic separately into KVM, bhyve, and
NVMM.

---

## Conformance Lanes

The conformance harness is platform-neutral: it shells out to a built `carrick`
binary and compares against Docker oracle results or cached oracle verdicts.

- Local macOS/HVF is the default lane.
- `--lane kvm-local` runs a platform-linux binary on Linux with `/dev/kvm`.
- `--lane bhyve-local` runs a platform-freebsd binary on FreeBSD with bhyve.
- `--lane nvmm-local` runs a platform-netbsd binary on NetBSD with NVMM.

The local x86 lanes inject `--platform linux/amd64` and need the platform binary
built on the target host. x86-lane expected gaps belong in backend-specific
baseline overlays, not in the main HVF baseline.

See [conformance-testing.md](conformance-testing.md) and
[../AGENTS.md](../AGENTS.md) for the operational rules: do not run carrick and
Docker oracle phases concurrently, stamp `CARRICK_RUN_ID`, and verify target
host claims with the exact lane command before treating a status note as current
truth.

---

## Adding a Platform or Backend

Use this checklist before writing backend code:

1. Decide the host feature name and make sure it does not pull another platform's
   VMM dependency closure.
2. Put OS primitives in a host crate (`carrick-host-*` or `carrick-portable`),
   not in the runtime dispatcher.
3. Put hypervisor operations in a `carrick-vmm-*` crate.
4. Reuse `carrick-x86` for x86_64 VMM backends unless the host VMM cannot
   support the required engine contract.
5. Keep Linux ABI constants and wire structs in `carrick-abi`; do not add local
   ad hoc `LINUX_*`/`SYS_*` constants in dispatch files.
6. Add or update target-host conformance lanes only after the platform binary
   can be built and the local host prerequisites are documented.
7. Record target-host caveats in active docs only after verifying them with the
   exact command that future agents should run.

---

## Historical Name Map

Several older design docs used names that no longer exist. Translate them as:

| Historical name | Current name |
| --- | --- |
| `carrick-hvf` | `carrick-vmm-hvf` |
| `carrick-linux` as KVM backend | `carrick-vmm-kvm` |
| `carrick-linux` as host glue | `carrick-host-linux` |
| `carrick-bhyve` | `carrick-vmm-bhyve` |
| `carrick-nvmm` | `carrick-vmm-nvmm` |
| `carrick-bsd` | `carrick-host-bsd` |

Do not rename historical files just to remove old names; update active docs and
current code comments where they would mislead an implementation or debug pass.
