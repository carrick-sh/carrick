# Carrick Crate Map

Carrick is a 31-crate Cargo workspace. The product path is:

```text
carrick-cli   -> carrick-engine -> { carrick-image, carrick-runtime } -> carrick-spec
carrick-embed -> { carrick-engine, carrick-runtime }                   -> carrick-spec
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
| `carrick-runtime` | Carrick kernel implementation: ELF execution, syscall dispatch, VFS/rootfs, kernel-owned process and memory models, namespaces, credentials, sockets, IPC, procfs/sysfs, scheduling integration, and platform-selected execution loops. |
| `carrick-spec` | Shared vocabulary types: `RunSpec`, `ContainerSpec`, `ImageConfig`, mounts, namespace config, platform requests. |

## ABI, Memory, and Neutral Core

| Crate | Role |
| --- | --- |
| `carrick-abi` | Linux ABI constants and wire structs, with compile-time layout/constant assertions. |
| `carrick-guest-mem` | Guest-memory trait, memory error type, and syscall-frame hub types shared by handlers and VMM engines. |
| `carrick-kernel` | Kernel-graph foundations: carrier/container objects, arenas, typed process/task/thread/mm identity, lifecycle transactions, and shared registries. |
| `carrick-mem` | Guest address-space construction: ELF layout, page tables, trampolines, VDSO/vvar, region helpers. |
| `carrick-hal` | OS/VMM-neutral traits and shared types: trap contract, hypervisor traits, guest-arch tables, event/futex/threaded-loop/signal/timer surfaces. |
| `carrick-thread` | Thread registry, private-futex park table, and fork/page-table quiesce barriers. |
| `carrick-signal-core` | Platform-neutral pending-signal bookkeeping. |
| `carrick-timer-core` | Platform-neutral interval/POSIX timer slot bookkeeping and timer due-time decisions. |
| `carrick-observability` | Platform-neutral compat-reporting support. |

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
| `carrick-vmm-hvf` | macOS Hypervisor.framework backend; mature AArch64 stage-1/stage-2 projection, vCPU execution and coordination, fault/syscall exits, and observability probes. |
| `carrick-vmm-kvm` | Linux/KVM backend; AArch64 KVM support, x86_64 lane, KVM kick/futex/fork/timer/signal glue, standalone target-host runners. |
| `carrick-vmm-bhyve` | FreeBSD/bhyve backend; x86_64 lane through the shared x86 engine plus bhyve-specific host/VMM glue. |
| `carrick-vmm-nvmm` | NetBSD/NVMM backend; x86_64 lane through the shared x86 engine plus NVMM-specific host/VMM glue. |
| `carrick-x86` | Shared x86_64 engine: long-mode bring-up, register/snapshot model, fault tables, VDSO helpers, generic `X86EngineCore<V>`. |
| `carrick-aarch64` | Shared AArch64 engine (`Aarch64EngineCore`) used by the HVF AArch64 path (and shared with the KVM AArch64 lane). |

## Binary Patching & Translation Core (DSR)

| Crate | Role |
| --- | --- |
| `carrick-dsr` | Platform-neutral DSR core: the `NativeLane`/`GuestIsa`/`NativeHost` seam traits, translation cache + publication behind the `NativeHostJit` seam, `prepared_image`, profiling census, page-geometry vocabulary, probe-sink seam, test hooks. |
| `carrick-dsr-aarch64` | AArch64 guest-ISA lane: bad64/dynasmrt decode + emit, block planner + exclusive fusion, gateway (`gateway_aarch64.S`), counter virtualization, artifact store, mapped memory + translator. |
| `carrick-dsr-x86` | x86_64 guest-ISA lane: `iced-x86` decode/classify, block planning + control-flow lowering, a hand-rolled byte-level block emitter (no dynasmrt dependency), gateway (`gateway_x86_64.S`) + x87/SSE/AVX state transfer. |
| `carrick-native-darwin` | **Preserved for future OS-level optimisation.** Darwin host primitives: Apple Silicon `MAP_JIT` W^X JIT backend (`DarwinHostJit`, implementing `NativeHostJit`), Tier-D binary patching (svc island generation, x18/TLS virtualisation), persistent AOT cache. Not actively wired into the HVPatch execution path. |

## Test and Harness Support

| Crate | Role |
| --- | --- |
| `carrick-conformance` | Differential conformance harness; shells out to built carrick binaries and Docker oracles, classifies baselines, renders support matrix. |
| `carrick-conformance-next` | In-process conformance framework using `carrick-embed` (Phase J): `TestContainer` + `AuditObserver` `#[test]` ports of LTP/probe cases, semantic probe observers, fuzzing, and golden traces. `carrick-conformance` stays the verdict authority until the new framework reproduces every historical false-green rejection. |
| `carrick-test-support` | Shared integration/CLI test helpers, mainly synthetic rootfs tar/gzip assembly. |

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
