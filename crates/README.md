# Carrick Crate Map

Carrick is a 51-crate Cargo workspace. The product path is:

```text
carrick-cli   -> carrick-engine -> { carrick-image, carrick-runtime -> carrick-kernel -> carrick-vfs } -> carrick-spec
carrick-embed -> { carrick-engine, carrick-runtime -> carrick-kernel -> carrick-vfs }                  -> carrick-spec
```

`carrick-embed` is the library front door and takes the runtime directly. Its
builder exposes syscall observers and policy presets, VFS mounts, resource
budgets, time control, network interposition, and shared buffers; the CLI
reaches the runtime only through the engine. Tty sessions and concurrent
containers in one host process are not yet public embed features.

Platform code is selected by Cargo features. The default feature is
`platform-macos`; non-macOS builds use `--no-default-features` plus exactly one
`platform-*` feature.

## Product and Runtime

| Crate | Role |
| --- | --- |
| `carrick-cli` | The `carrick` binary: docker-compatible command surface, lifecycle commands, diagnostics, and final runtime execution. |
| `carrick-engine` | Docker-style request merge layer: image config + CLI flags -> `RunSpec`. |
| `carrick-embed` | Library embedding surface: `ContainerBuilder` -> `RunRequest` -> `Engine::resolve` -> `Runtime::prepare`/`PreparedRun::execute`, with captured, inherited or piped stdio and the `testing` helpers (`TestContainer`, `run_in_container`, `ResultAssert`). The dog-food consumer for Carrick's own guest tests; guest-running tests need the signed `just test-embed` recipe. |
| `carrick-image` | OCI reference parsing, pull/cache, config and layer resolution. |
| `carrick-runtime` | The execution lane: the HVPatch VM carrier, the vCPU and threaded loops, image preparation and the run lifecycle, the interactive/pty supervisors, and the `carrick-hal` bridge implementations. It no longer contains the kernel or the retired 1:1 backend driver bins. |
| `carrick-kernel` | The Carrick kernel: the kernel object graph, syscall dispatch and its subsystems, namespaces, credentials, sockets, IPC, the in-zone network, the file authority, the kernel-view filesystems (procfs/sysfs/`/dev`/devpts) and the container/run state. Names no carrier and no VMM crate; reaches the execution lane only through `carrick-hal` traits. |
| `carrick-kernel-example` | The VM-free kernel conformance harness and bring-your-own-execution-backend template (`just test-kernel`): runs scripted Linux tasks on host threads over `Vec`-backed guest memory against `carrick-kernel`'s public surface alone (Null `carrick-hal` bridges, its own `CarrierProcess`/`MmBackend`/`Stage1MmProjection`). Not on the product path: the root `default-members` keeps the product build to `carrick-cli`'s closure (its `test-support` dependency would otherwise unify into `carrick`), and `just check-layering` keeps `carrick-runtime` and every VMM crate out of its closure and `test-support` out of the product selection. |
| `carrick-vfs` | The filesystem model below the kernel: the `Vfs` trait and mount table, dentry cache, host and in-memory backends, the OCI rootfs with its overlay and layer cache, the path codec, and the bind/resolv.conf/services mounts. Names no kernel, carrier or VMM type. |
| `carrick-spec` | Shared vocabulary types: `RunSpec`, `ContainerSpec`, `ImageConfig`, mounts, namespace config, platform requests. |

## ABI, Memory, and Neutral Core

| Crate | Role |
| --- | --- |
| `carrick-abi` | `no_std` Linux ABI constants and wire structs shared by host and ring code, with compile-time layout/constant assertions. |
| `carrick-core` | Neutral MM, fork, COW, and wait/lifecycle substrate for Carrick (shared owner algorithms; hardware and Linux lowering stay with clients). |
| `carrick-core-abi` | Neutral owner identities and transport, shared by both ISA images. |
| `carrick-el1-abi` | Contracts, memory layouts, and definitions shared between the host runtime and the bare-metal in-guest EL1 kernel (`carrick-el1`). |
| `carrick-fatal` | Single fatal sink for carrier invariant violations (`carrick_fatal!`) with non-allocating stack formatting and `CARRICK_LAST_FATAL` recording. |
| `carrick-fd-core` | Allocation-free descriptor and OFD authority as shared atomic records across host and EL1. |
| `carrick-guest-arch` | The no_std hardware boundary and sealed `Arch` traits for Carrick's in-guest kernel. |
| `carrick-guest-mem` | Guest-memory trait, memory error type, and syscall-frame hub types shared by handlers and VMM engines. |
| `carrick-hal` | OS/VMM-neutral traits and shared types: trap contract, hypervisor traits, guest-arch tables, event/futex/threaded-loop/signal/timer surfaces. Depends on the platform-neutral `no_std` `carrick-el1-abi` for exact owner Fork completion receipts; it takes no EL1 implementation or VMM dependency. |
| `carrick-inotify-core` | Platform-neutral inotify queue ring buffer, coalescing, and watch descriptor bookkeeping. |
| `carrick-kernel-arena` | The per-run kernel arena: a file-backed `MAP_SHARED` region holding the Linux-visible cross-process delta (identity, leases, shared kernel objects) the host kernel cannot express, with no authority daemon -- processes operate on it via atomics and robust bucket locks. |
| `carrick-mem` | Guest address-space construction: ELF layout, boot identity/hvpatch tables, trampolines, VDSO/vvar, region helpers. |
| `carrick-mmu-core` | `no_std` + `alloc` MMU management substrate and stage-1 page-table manipulation algorithms (AArch64 `PageTableManager`). |
| `carrick-observability` | Platform-neutral compat-reporting support. |
| `carrick-personality-linux` | Linux interpretation of neutral owner records, shared by host and EL1. |
| `carrick-pipe-core` | Allocation-free pipe and event counter substrate over shared or local records. |
| `carrick-sched-core` | `no_std` in-guest scheduling core shared by guest EL1 and the host: the zone of futex-parked threads (records whose claim word names their one owner, hash-bucket wait queues, per-vCPU-slot run queues), laid out `repr(C)` in the shared EL1 region. |
| `carrick-signal-core` | Platform-neutral pending-signal bookkeeping. |
| `carrick-signal-linux` | Linux signal policy and host-venue pending bookkeeping shared across backends. |
| `carrick-syscall-abi` | Guest-safe Linux syscall numbering, canonical tables, and wait-option domains. |
| `carrick-thread` | Thread registry, private-futex park table, and fork/page-table quiesce barriers. |
| `carrick-timer-core` | Platform-neutral interval/POSIX timer slot bookkeeping and timer due-time decisions. |

## Host Primitive Layers

| Crate | Role |
| --- | --- |
| `carrick-host` | Darwin host helpers for the macOS path: host facts, guest CPU accounting, host process info, host mappings, macOS futex helpers. |
| `carrick-host-bsd` | BSD-family host glue selected by macOS/FreeBSD/NetBSD: errno translation, kqueue, BSD futex, signal-number translation. |
| `carrick-host-linux` | Linux host glue selected by `platform-linux`: epoll multiplexer and Linux errno identity hook. |
| `carrick-portable` | Thin raw-`libc` shim for symbols/constants that differ or are absent across hosts. |

## VMM Backends and Guest ISA

The VMM crates execute guest instructions and project Carrick's kernel state
onto host virtualization APIs. They do not own Linux process identity or
lifecycle semantics.

| Crate | Role |
| --- | --- |
| `carrick-aarch64` | Shared AArch64 engine (`Aarch64EngineCore`) used by the HVF AArch64 path (and shared with the KVM AArch64 lane). |
| `carrick-el1` | Carrick guest EL1 kernel image body: neutral mechanisms and Linux personality compiled into AArch64 EL1 and x86_64 CPL0 images. |
| `carrick-el1-image` | Precompiled in-guest EL1 kernel binary image embedded into the host runtime. |
| `carrick-vmm-bhyve` | FreeBSD/bhyve backend; x86_64 lane through the shared x86 engine plus bhyve-specific host/VMM glue. |
| `carrick-vmm-hvf` | macOS Hypervisor.framework backend; mature AArch64 stage-1/stage-2 projection, vCPU execution and coordination, fault/syscall exits, and observability probes. |
| `carrick-vmm-kvm` | Linux/KVM backend; AArch64 KVM support, x86_64 lane, KVM kick/futex/fork/timer/signal glue, standalone target-host runners. |
| `carrick-vmm-nvmm` | NetBSD/NVMM backend; x86_64 lane through the shared x86 engine plus NVMM-specific host/VMM glue. |
| `carrick-x86` | Shared x86_64 engine: long-mode bring-up, register/snapshot model, fault tables, VDSO helpers, generic `X86EngineCore<V>`. |
| `carrick-x86-cpl0` | Bare-metal x86_64 CPL0 image and fixture runner. |

## Test and Harness Support

| Crate | Role |
| --- | --- |
| `carrick-conformance` | Differential conformance harness; shells out to built carrick binaries and Docker oracles, classifies baselines, renders support matrix. |
| `carrick-conformance-contract` | Typed, fail-closed conformance-contract registry, work/timing observations, structural/affine budget models, and 463-syscall coverage inventory. |
| `carrick-conformance-next` | In-process conformance framework using `carrick-embed` (Phase J): `TestContainer` + `AuditObserver` `#[test]` ports of LTP/probe cases, semantic probe observers, fuzzing, and golden traces. `carrick-conformance` stays the verdict authority until the new framework reproduces every historical false-green rejection. |
| `carrick-coordinator` | Host-wide resource coordinator enforcing mutual exclusion between Carrick guest execution and Docker oracle phases across checkouts, quiet timing windows, and campaign budgets. |
| `carrick-investigation` | Durable event-sourced investigation engine driving validated stage transitions, experiment planning, and review-package assembly for contract-driven conformance investigations. |
| `carrick-test-support` | Shared test helpers: synthetic rootfs tar/gzip assembly and aligned EL1 region backing for VM-free ABI tests. |
| `carrick-xtask` | Repository maintenance, gate drivers, facts ledger verification, baseline recording/comparison, assembly diffs, and test lane checks. |

## Feature Closure Rules

- `platform-macos` pulls `carrick-vmm-hvf`, `carrick-host`, and
  `carrick-host-bsd`; it needs macOS codesigning before running guests.
- `platform-linux` pulls `carrick-vmm-kvm` and `carrick-host-linux`; it must not
  pull HVF/applevisor.
- `platform-freebsd` pulls `carrick-vmm-bhyve` and `carrick-host-bsd`; it must
  not pull HVF/applevisor.
- `platform-netbsd` pulls `carrick-vmm-nvmm` and `carrick-host-bsd`; it must not
  pull HVF/applevisor.
- `carrick-embed` and `carrick-conformance-next` forward `platform-*` and
  `syscall-shim` (default `["platform-macos", "syscall-shim"]`), so an embedded
  guest runs with the same EL1 shim as the shipped binary. `scripts/closure-assert-no-hvf.sh`
  walks `carrick-cli` only; check the embed closure with
  `cargo tree -p carrick-embed --no-default-features --features platform-linux
  --target aarch64-unknown-linux-gnu --edges normal | grep -Ei
  'carrick-vmm-hvf|applevisor'` (expect no output).

Use `cargo metadata --no-deps` and `scripts/closure-assert-no-hvf.sh` when
changing feature wiring.
