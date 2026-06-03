# Carrick

Carrick is a high-performance, fully concurrent Linux binary compatibility layer for macOS on Apple Silicon. Unmodified Linux processes run as native macOS processes, with syscalls trapped via `Hypervisor.framework` and translated directly to Darwin host primitives. Unlike traditional virtual machines, Carrick requires no guest Linux kernel, no separate hypervisor memory pool, and no slow snapshot-restore loops for process lifecycle management.

The name refers to a type of knot used to join two heavy ropes of different sizes.

> [!IMPORTANT]
> **Carrick is fully functional and production-ready.** The runtime has successfully retired the Big Kernel Lock (BKL), supports fully multi-threaded guest execution, implements a robust socket translation layer, serves pseudo-terminals (`/dev/pts`), and runs complex workloads like `apt-get install` and `python3 -m http.server` entirely end-to-end.

---

## Quick Start

```sh
just build                                  # build + codesign the release binary (required to run a guest)
just run run ubuntu:24.04 /bin/echo hi      # docker-style: pull an image + run a command in it
./target/release/carrick run python:3.12-slim python3 -m http.server 8000
```

> [!IMPORTANT]
> A guest can only run from a **codesigned** binary. `cargo build` strips the
> signature on macOS, so a bare build fails every run with `HV_DENIED`
> (`0xfae94007`). `just build` (i.e. [`scripts/build-signed.sh`](scripts/build-signed.sh))
> re-applies the `com.apple.security.hypervisor` entitlement after linking.
> Use plain `cargo build`/`cargo test` only for compile-checking, never to run.

---

## Implemented Now

Carrick provides a robust translation layer and lifecycle supervisor covering the following features:

* **ELF Loading & Address-Space Mapping:** Parses static and dynamic AArch64 Linux ELF binaries (`goblin`), layouts the memory regions, and populates the initial guest stack with `argc`, `argv`, `envp`, and target auxiliary vectors (e.g., `AT_BASE` for dynamic interpreters).
* **VFS & Rootfs Composition:** Merges OCI container layers in-memory at runtime to provide a virtual root filesystem (supporting Whiteouts, symlinks, and opaque directories) without physical disk extraction.
* **Fully Concurrent Dispatcher (BKL Retired):** Decodes and services guest syscalls in host Rust code. Since the Big Kernel Lock (BKL) retirement, vCPU threads run concurrently against per-subsystem thread-safe locks (`Mutex`/`RwLock` over `fs`, `creds`, `proc`, `signal`, and `mem`), avoiding global serialization.
* **Socket Networking Subsystem:** Translates Linux socket calls (`socket`, `bind`, `connect`, `listen`, `accept`, `sendto`/`recvfrom`, `setsockopt`/`getsockopt`, `shutdown`) directly onto native Darwin sockets, and synthesizes `AF_NETLINK` sockets locally to satisfy routing table audits (like glibc's `__check_pf`).
* **kqueue-Backed Event Multiplexing:** Maps Linux `epoll` boundaries (`epoll_create1`, `epoll_ctl`, `epoll_pwait`) onto native Darwin `kqueue` descriptors, alongside custom userspace implementations of `eventfd2` and `timerfd`.
* **Interactive Pseudo-Terminals (`carrick run -t`):** Bridges the host terminal and guest `/dev/pts/N` using a dedicated poll-based thread multiplexing terminal inputs and PTY master events, enabling job control (Ctrl-C, Ctrl-Z) and live size resize (`SIGWINCH`) propagation.
* **Synthetic procfs & sysfs:** Populates expected nodes like `/proc/self/maps`, `/proc/cpuinfo`, `/proc/version`, and `/sys/devices/system/cpu/...` to fulfill assertions made during Musl/Glibc and language runtime (e.g., Go, Rust) startup sequences.
* **DTrace Loop (USDT Probes):** Wires static USDT probes at translation boundaries. Running `carrick compat-report -- <cmd>` uses these probes to collect and aggregate unhandled or partially-implemented syscalls or `/proc` paths.

---

## Documentation

Start here, then follow the map:

| Document | What's in it |
| --- | --- |
| [docs/architecture-overview.md](docs/architecture-overview.md) | The architectural deep-dive: the HVF trap boundary & CPU mode switch, the stage-1 identity mapping & `FEAT_PAN3` workaround, the BKL-free concurrency model, and the interactive `PtyRelay`. |
| [docs/syscalls-emulation-map.md](docs/syscalls-emulation-map.md) | The supported-syscall map — categorized, with each call's emulation quality and the Darwin host mechanism backing it (`kqueue`, `os_sync_wait_on_address`, `parking_lot`, native BSD sockets, `sendfile`, …). |
| [docs/diagnostics-and-debugging.md](docs/diagnostics-and-debugging.md) | The diagnostic toolbox: `carrick trace` (USDT + custom DTrace scripts), the always-on in-memory event ring + the `carrick_lldb.py` plugin, the `carrick debug` subcommands, and the host `CARRICK_*` debug environment variables. |
| [docs/conformance-testing.md](docs/conformance-testing.md) | How to run and interpret the host, differential-probe, and language-runtime (Go/Node/CPython) suites; the local registry setup; and the **compile-time** ABI conformance checks. |
| [docs/conformance-coverage.md](docs/conformance-coverage.md) | The active probe-gate coverage map — which carrick-owned invariant each probe pins down. |
| [docs/archive/](docs/archive/) | Historical session handoffs, code reviews, and superseded design/spec notes, kept out of the active tree. |

---

## Build Workflows

A [`justfile`](justfile) wraps the common workflows (`just --list` to see them all):

```sh
just build          # build + codesign the release binary (the only runnable build)
just run run ubuntu:24.04 /bin/echo hi
just clippy         # the no-panic lint gate
just test           # host unit/integration tests (no HVF/Docker needed)
just conformance    # differential suite vs Docker
```

See [docs/conformance-testing.md](docs/conformance-testing.md) for the full testing
story (host tests, the differential probe gate, the language-runtime suites, and the
compile-time ABI checks).

### Build performance

`carrick-runtime` is a single large crate (~41k lines), and the workspace links
27 integration-test binaries plus the cli, each statically linking its rlib.
With macOS's default `ld64`, an incremental rebuild after a one-line runtime
edit spends ~37s of its ~57s wall time in the linker.

> [!WARNING]
> Do **not** switch the linker to LLVM `lld` globally. `lld`'s Mach-O port
> drops the `__DATA,__dof_carrick` section that the `usdt` crate's
> `register_probes()` reads, so `carrick trace`'s USDT probes silently stop
> firing (the provider registers empty; `dtrace -l` shows nothing). `ld64`
> preserves the section. A faster linker can be re-introduced only if it keeps
> `__dof_carrick` — verify with `otool -l target/release/carrick | grep dof`
> and confirm `carrick trace` still emits syscall events.

The remaining incremental cost is rustc recompiling the monolithic runtime
crate; that is inherent to keeping the runtime as one crate (its
dispatch/memory/trap internals are too coupled to split cheaply).

### No-panic gate

The supervisor must never crash on guest input, so `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!` are denied crate-wide via `[lints.clippy]` in `Cargo.toml` (test code is exempt via `clippy.toml`). A handful of audited, provably-infallible sites carry a targeted `#[allow(...)]` with an `// INVARIANT:` comment. Run the gate with:

```sh
cargo clippy --all-targets
```

This exits non-zero on any *new* unguarded panic/unwrap. (Do **not** add `-D warnings`: that promotes unrelated pre-existing style lints to errors; the `Cargo.toml` deny levels are what enforce the no-panic gate.) Structural ABI invariants are enforced separately, at **compile time** — see the `const _: () = assert!(…)` / `assert_layout!` blocks in `crates/carrick-abi/src/lib.rs` and [docs/conformance-testing.md](docs/conformance-testing.md).

---

## Directory Map

Carrick is a Cargo workspace:

| Crate | Responsibility |
| --- | --- |
| `carrick-spec` | Pure vocabulary types (`RunSpec`, `ContainerSpec`, `ImageConfig`, `Mount`, `NamespaceConfig`) shared across layers. |
| `carrick-abi` | Linux AArch64 ABI constants and wire-format structs, with their compile-time size/offset/uniqueness assertions. |
| `carrick-image` | OCI image references, pull/store, image-config parsing, layer + config resolution. |
| `carrick-runtime` | The HVF runtime: ELF loading, syscall dispatch, VFS, fs backends, and the `execute(&RunSpec)` seam. |
| `carrick-engine` | The container layer: docker `run` merge semantics, lowering a `CliRunRequest` into a `RunSpec`. |
| `carrick-cli` | The `carrick` binary (docker-compatible `run` + diagnostic subcommands). |

The dependency direction is `cli → engine → {image, runtime} → spec`; `runtime` and `image` never depend on each other or on `engine`.

```
.
├── crates/            # the Cargo workspace (see table above)
├── docs/              # architecture, syscall map, diagnostics, conformance (+ archive/)
├── conformance-probes/# differential carrick-vs-Linux probe binaries
├── scripts/           # build-signed.sh, carrick_lldb.py, *.d DTrace scripts, suite drivers
└── justfile           # common workflows
```

---

## License Policy

The crate is dual licensed as `Apache-2.0 OR MIT`. Dependencies are selected from permissive Rust ecosystem crates. `deny.toml` records the allowed dependency licenses for `cargo-deny`; the current resolved dependency graph uses permissive licenses such as MIT, Apache-2.0, BSD, ISC, Unicode-3.0, Zlib, Unlicense, 0BSD, BSL-1.0, and CDLA-Permissive-2.0.
