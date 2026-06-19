# Carrick Crate Map

Carrick is a 24-crate Cargo workspace. The product path is:

```text
carrick-cli -> carrick-engine -> { carrick-image, carrick-runtime } -> carrick-spec
```

Platform code is selected by Cargo features. The default feature is
`platform-macos`; non-macOS builds use `--no-default-features` plus exactly one
`platform-*` feature.

## Product and Runtime

| Crate | Role |
| --- | --- |
| `carrick-cli` | The `carrick` binary: docker-compatible command surface, lifecycle commands, diagnostics, and final runtime execution. |
| `carrick-engine` | Docker-style request merge layer: image config + CLI flags -> `RunSpec`. |
| `carrick-image` | OCI reference parsing, pull/cache, config and layer resolution. |
| `carrick-runtime` | Linux behavior core: ELF execution, syscall dispatch, VFS/rootfs, process model, namespaces, credentials, sockets, IPC, procfs/sysfs, and platform-selected execution loops. |
| `carrick-spec` | Shared vocabulary types: `RunSpec`, `ContainerSpec`, `ImageConfig`, mounts, namespace config, platform requests. |

## ABI, Memory, and Neutral Core

| Crate | Role |
| --- | --- |
| `carrick-abi` | Linux ABI constants and wire structs, with compile-time layout/constant assertions. |
| `carrick-guest-mem` | Guest-memory trait, memory error type, and syscall-frame hub types shared by handlers and VMM engines. |
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

| Crate | Role |
| --- | --- |
| `carrick-vmm-hvf` | macOS Hypervisor.framework backend; mature AArch64 trap loop, vCPU coordination, fork/exec VM management, probes. |
| `carrick-vmm-kvm` | Linux/KVM backend; AArch64 KVM support, x86_64 lane, KVM kick/futex/fork/timer/signal glue, standalone target-host runners. |
| `carrick-vmm-bhyve` | FreeBSD/bhyve backend; x86_64 lane through the shared x86 engine plus bhyve-specific host/VMM glue. |
| `carrick-vmm-nvmm` | NetBSD/NVMM backend; x86_64 lane through the shared x86 engine plus NVMM-specific host/VMM glue. |
| `carrick-x86` | Shared x86_64 engine: long-mode bring-up, register/snapshot model, fault tables, VDSO helpers, generic `X86EngineCore<V>`. |

## Test and Harness Support

| Crate | Role |
| --- | --- |
| `carrick-conformance` | Differential conformance harness; shells out to built carrick binaries and Docker oracles, classifies baselines, renders support matrix. |
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

Use `cargo metadata --no-deps` and `scripts/closure-assert-no-hvf.sh` when
changing feature wiring.
