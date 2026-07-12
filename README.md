# Carrick

Carrick is an experimental Linux binary compatibility layer. Its mature path
runs unmodified Linux binaries on macOS / Apple Silicon as native host
processes: each guest thread owns a hardware-virtualized vCPU, every guest
syscall traps into Rust, and the runtime re-expresses Linux behavior with host
kernel primitives. There is no guest Linux kernel, no second scheduler, and no
separate VM process for each container.

The same runtime is being split along two explicit axes:

- **Host/VMM backends:** macOS/HVF, Linux/KVM, FreeBSD/bhyve, and NetBSD/NVMM.
- **Guest ISAs:** AArch64 on the mature macOS/HVF path, plus active x86_64
  bring-up through KVM, bhyve, and NVMM.

The name refers to a type of knot used to join two heavy ropes of different
sizes.

> [!NOTE]
> **Status: ambitious, experimental, not production-ready.** Carrick already
> runs real workloads end-to-end on the macOS/HVF path, including `apt-get
> install`, `python3 -m http.server`, and Go / Node.js / CPython conformance
> slices. The non-macOS and x86_64 lanes are under active bring-up and are not
> equivalent to the default macOS release path. Syscall coverage is partial
> ([the emulation map](docs/syscalls-emulation-map.md) lists the current table),
> guest behavior is incomplete, and the runtime has had **no adversarial security
> review**. A guest is not a hardened trust boundary; do not run untrusted code
> under it.

---

## Install

The packaged install path is Apple Silicon macOS only.

```sh
brew tap carrick-sh/carrick
brew install --HEAD carrick
```

The formula builds from source and ad-hoc codesigns the `carrick` binary with
the `com.apple.security.hypervisor` entitlement so Hypervisor.framework can run
guests. Non-macOS backends are source builds for target hosts today.

---

## Quick Start

```sh
just build                                  # build + codesign the release binary
just run run ubuntu:24.04 /bin/echo hi      # docker-style: pull an image + run it
./target/release/carrick run python:3.12-slim python3 -m http.server 8000
```

> [!IMPORTANT]
> On macOS, a guest can only run from a **codesigned** binary. `cargo build`
> strips the signature, so a bare build fails every run with `HV_DENIED`
> (`0xfae94007`). `just build` uses
> [`scripts/build-signed.sh`](scripts/build-signed.sh) to re-apply the
> entitlement after linking. Use plain `cargo build`/`cargo test` for
> compile-checking only, never to run a guest.

---

## Experimental Native Execution

Carrick also has an experimental Darwin-native backend for same-ISA
`linux/arm64` binaries. It executes guest instructions directly in a macOS
process, without an HVF vCPU. The default remains the release-quality HVF path;
native execution is explicit and trusted-code-only:

```sh
target/release/carrick run \
  --exec-backend native \
  --native-page-profile native16k \
  ubuntu:24.04 /bin/echo hi
```

The native backend has two page profiles:

- **`native16k` (preferred):** exposes the host's 16K page geometry and uses
  direct Darwin mappings and protections. Neither OCI image metadata nor the
  AArch64 ISA by itself requires 4K pages; use this profile unless the workload
  depends on Linux-visible 4K mapping, protection, or fault boundaries.
- **`linux4k` (compatibility):** presents 4K Linux page semantics on a 16K
  Darwin host. It has a guarded slow path for a bounded set of mixed-page data
  accesses, but it is incomplete and may reject mixed executable pages,
  mixed shared-file aliases, or unsupported guarded AArch64 instructions.

Selecting `linux4k` never falls back to HVF. An unsupported mapping or
instruction fails with a native-backend diagnostic so the compatibility gap is
visible. Every native image mapping must lie above macOS's hard 4 GiB arm64
`__PAGEZERO`. PIE/`ET_DYN` is the practical supported path; a high-address
`ET_EXEC` image can work, while ordinary low-address `ET_EXEC` images are
rejected.

See the dated
[native feasibility and conformance evidence](docs/2026-07-09-no-vmm-native-feasibility-evidence.md)
and the
[native fork benchmark](docs/2026-07-10-native-fork-benchmark-evidence.md)
for measurements and known gaps. As of 2026-07-11 the native16k musl
conformance lane measures 376/376 probes byte-identical with Docker arm64,
and native `fork` is ~3.4x faster than HVF (1.53x host Darwin) with
host-COW memory scaling.

---

## What Works Today

Carrick's most complete path is `platform-macos`: AArch64 Linux guests running
on macOS/Apple Silicon through `carrick-vmm-hvf`. It includes:

- **ELF loading and address-space setup:** static and dynamic Linux ELF loading,
  guest stack/auxv construction, interpreter setup, page tables, trampolines,
  and runtime memory-management updates.
- **OCI rootfs and VFS:** image pull/cache, OCI layer composition, an in-memory
  rootfs, and a `--fs host` cap-std backend for case-sensitive host storage.
- **Concurrent syscall dispatch:** one host thread and one vCPU per guest
  thread, with per-subsystem locks instead of a global Big Kernel Lock.
- **Process and thread lifecycle:** host `fork`/`wait4` mirroring, guest threads,
  futexes, signal delivery, exec, and synthetic `/proc` state.
- **Networking and readiness:** BSD sockets with Linux sockaddr/option
  translation, synthetic `AF_NETLINK`, and Linux `epoll`/`poll`/`select`
  behavior over host event mechanisms.
- **Interactive terminals:** `carrick run -t` bridges a host terminal to guest
  `/dev/pts` with job-control and resize propagation.
- **Diagnostics:** `carrick trace`, static USDT probes, `compat-report`, and the
  always-on event ring for post-mortem debugging.

The cross-platform work is source-visible and partially live:

- `platform-linux` wires Linux/KVM plus `carrick-host-linux`; x86_64 local
  conformance lanes exist for Linux hosts.
- `platform-freebsd` wires FreeBSD/bhyve plus `carrick-host-bsd`; x86_64 bhyve
  runtime tests and conformance plumbing exist, with target-host logistics still
  important.
- `platform-netbsd` wires NetBSD/NVMM plus `carrick-host-bsd`; M0/M1 bring-up is
  blocked by known nested-NVMM host behavior unless the target host is prepared
  accordingly.

See [docs/hal.md](docs/hal.md) for the current backend architecture and status.

---

## Documentation

Start here, then follow the map:

| Document | What's in it |
| --- | --- |
| [docs/architecture-overview.md](docs/architecture-overview.md) | The mature macOS/HVF architecture: trap boundary, stage-1 paging, BKL-free concurrency, process model, and PTY handling. |
| [docs/hal.md](docs/hal.md) | Current platform split: HAL traits, host-primitive crates, VMM backend crates, x86_64 engine scaffold, and build features. |
| [crates/README.md](crates/README.md) | Workspace crate map grouped by role. |
| [docs/syscalls-emulation-map.md](docs/syscalls-emulation-map.md) | Supported-syscall map and the host mechanism backing each category. |
| [docs/conformance-testing.md](docs/conformance-testing.md) | How to run and interpret host tests, differential probes, language suites, oracle cache, and local backend lanes. |
| [docs/conformance-coverage.md](docs/conformance-coverage.md) | Active probe-gate coverage: which carrick-owned invariant each probe pins down. |
| [docs/diagnostics-and-debugging.md](docs/diagnostics-and-debugging.md) | `carrick trace`, event ring, lldb helpers, debug commands, and runtime diagnostic env vars. |
| [docs/archive/](docs/archive/) | Older design-rationale notes still referenced from code comments. |

For per-crate and per-subsystem theory statements, build the private API docs:

```sh
cargo doc --workspace --no-deps --document-private-items --open
```

`--document-private-items` is intentional. Carrick is an internal workspace, so
most of the theory statements live on private modules and types.

---

## Build Workflows

The [`justfile`](justfile) is the source of truth:

```sh
just build          # macOS release build + codesign; required before running guests
just run run ubuntu:24.04 /bin/echo hi
just check          # unsigned cargo build; compile-check only on macOS
just clippy         # workspace lint gate
just test           # host lib tests, no HVF/Docker
just ci             # fmt-check, clippy, check, doc, test, integration tests
just conformance    # differential suites vs Docker
just matrix         # re-render docs/support-matrix.md
```

Non-macOS target builds select exactly one platform feature and avoid the
default macOS/HVF dependency closure:

```sh
cargo build -p carrick-cli --no-default-features --features platform-linux
cargo build -p carrick-cli --no-default-features --features platform-freebsd
cargo build -p carrick-cli --no-default-features --features platform-netbsd
```

See [docs/conformance-testing.md](docs/conformance-testing.md) for the full
runtime testing story and backend lane requirements.

### Build performance

`carrick-runtime` remains a large crate, and many integration-test binaries link
it. On macOS the default Apple `ld64` linker preserves the USDT/DTrace section
that `carrick trace` needs.

> [!WARNING]
> Do **not** switch the linker to LLVM `lld` globally. `lld`'s Mach-O port drops
> the `__DATA,__dof_carrick` section that the `usdt` crate's `register_probes()`
> reads, so `carrick trace` silently stops firing events. Keep Apple `ld64`.
> Verify with `otool -l target/release/carrick | grep dof`.

### No-panic gate

The supervisor must not crash on guest input. The workspace denies
`unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!` in non-test code through
`[workspace.lints.clippy]` in [Cargo.toml](Cargo.toml); tests are exempt via
[clippy.toml](clippy.toml). Run the gate with:

```sh
just clippy
```

Structural ABI invariants are enforced at compile time in
[`crates/carrick-abi`](crates/carrick-abi/src/lib.rs) and the syscall metadata
tables. See [docs/conformance-testing.md](docs/conformance-testing.md).

---

## Directory Map

Carrick is a 25-crate Cargo workspace under [`crates/`](crates/). The high-level
dependency direction is:

```text
carrick-cli -> carrick-engine -> { carrick-image, carrick-runtime } -> carrick-spec
```

The runtime also depends on platform-selected VMM and host crates:

```text
platform-macos   -> carrick-vmm-hvf   + carrick-host-bsd + carrick-host
platform-linux   -> carrick-vmm-kvm   + carrick-host-linux
platform-freebsd -> carrick-vmm-bhyve + carrick-host-bsd
platform-netbsd  -> carrick-vmm-nvmm  + carrick-host-bsd
```

The x86_64 VMM backends share `carrick-x86`, and the AArch64 path uses the
shared `carrick-aarch64` engine; platform-neutral state lives in
`carrick-hal`, `carrick-thread`, `carrick-signal-core`, `carrick-timer-core`,
`carrick-guest-mem`, and `carrick-observability`.

```
.
├── crates/             # Cargo workspace; see crates/README.md
├── docs/               # architecture, HAL, syscall map, diagnostics, conformance
├── conformance-probes/ # differential carrick-vs-Linux probe binaries
├── scripts/            # build, tracing, conformance, target-host helpers
└── justfile            # common workflows
```

---

## License Policy

The crate is dual licensed as `Apache-2.0 OR MIT`. Dependencies are selected
from reviewed Rust ecosystem crates. Most use permissive licenses; the DSR's
`dynasm` and `dynasmrt` dependencies use `MPL-2.0`. `deny.toml` records the
allowed dependency licenses and `cargo deny` enforces that policy.
