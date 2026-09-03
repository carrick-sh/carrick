# Carrick

Carrick is an experimental, embeddable hybrid Linux kernel written in Rust. It
runs unmodified Linux user-space binaries without booting a guest Linux kernel
and without making each Linux process a host process.

Linux software depends on a kernel contract, but providing that contract does
not have to mean carrying an entire second operating system. Carrick
reimplements Linux tasks, memory, files, signals, waits, namespaces, and other
kernel semantics in Rust, while deliberately using the best mechanisms of the
host OS for execution, storage, networking, events, timers, and memory. The
host provides capabilities; Carrick remains the authority for Linux behavior.

That split is what makes Carrick a hybrid kernel—and what makes it useful as a
library. A Rust program can resolve an OCI image and run Linux software through
`carrick-embed`, while the `carrick` command provides a familiar
Docker-compatible interface for humans and scripts.

The name refers to a type of knot used to join two heavy ropes of different
sizes.

> [!NOTE]
> **Status: ambitious, experimental, not production-ready.** Carrick already
> runs real workloads end-to-end on the macOS/HVF path, including `apt-get
> install`, `python3 -m http.server`, and Go / Node.js / CPython conformance
> slices. The non-macOS and x86_64 lanes are under active bring-up and are not
> equivalent to the mature macOS/HVF compatibility path. Syscall coverage is
> partial ([the emulation map](docs/syscalls-emulation-map.md) lists the current
> table), guest behavior is incomplete, and the runtime has had **no adversarial
> security review**. A guest is not a hardened trust boundary; do not run
> untrusted code under it.

---

## Embed Linux in seven lines

Inside a function returning `Result<_, carrick_embed::EmbedError>`, the core
embedding path is seven lines:

```rust
use carrick_embed::ContainerBuilder;
let result = ContainerBuilder::from_image("ubuntu:24.04")
    .command(["/bin/sh", "-c", "echo hello from $GREETING"])
    .env("GREETING", "Carrick")
    .run_blocking()?
    .ensure_success()?;
print!("{}", result.stdout_utf8());
```

This resolves the OCI image, starts the workload on Carrick's kernel, captures
its output, and turns an unsuccessful Linux process into a Rust error. The same
builder also accepts Docker-shaped configuration including entrypoints,
environment, working directory, user, hostname, mounts, platform, pull policy,
and stdio. See [`carrick-embed`](crates/carrick-embed/README.md) for the complete
blocking, async, result, and test APIs.

## Docker-compatible CLI

The CLI exposes the same engine with a Docker-shaped `run` surface:

```sh
carrick run ubuntu:24.04 /bin/echo hello
carrick run python:3.12-slim python3 -m http.server 8000
```

It understands OCI image references and familiar container configuration, but
it does not start Docker or boot Linux behind the scenes. The Linux process
tree belongs to Carrick's kernel; the CLI is simply one client of the same
engine available to embedded programs.

## Install

The packaged install path is Apple Silicon macOS only.

```sh
brew tap carrick-sh/carrick
brew install --HEAD carrick
```

The formula builds from source and ad-hoc codesigns the `carrick` binary with
the `com.apple.security.hypervisor` entitlement required for
`Hypervisor.framework`. Non-macOS backends are source builds for target hosts
today.

---

> [!IMPORTANT]
> On macOS, Carrick runs via `Hypervisor.framework` and must execute from a
> codesigned binary. `cargo build` strips the signature, resulting in
> `HV_DENIED` (`0xfae94007`). Always build with `just build` or
> [`scripts/build-signed.sh`](scripts/build-signed.sh) to apply the entitlement
> after linking. Use plain `cargo build`/`cargo test` for compile-checking only.

---

## How the hybrid kernel works

```text
Linux ELF at guest EL0
  -> syscall or fault trap through the selected VMM
  -> Carrick kernel graph and subsystem dispatch
  -> typed host capabilities
```

- The carrier owns one VM and one kernel graph. That graph models multiple
  container roots and Linux process trees explicitly; PID identity is scoped
  to the calling container rather than to the host process. The public
  [`Carrier`](crates/carrick-embed/src/carrier.rs) API admits independent,
  concurrent non-interactive containers into that shared kernel.
- `fork`, `clone`, `exec`, exit, wait, signals, credentials, file descriptions,
  and `/proc` state are Carrick kernel operations. Host process identity is not
  guest identity.
- Each logical guest thread has a host pthread, while a bounded, reclaimable
  set of vCPU leases is multiplexed across those threads. A blocking guest wait
  can release its lease for another runnable thread.
- Guest virtual addresses, stage-1 IPAs, reusable global-frame IPAs, and host
  owner generations are distinct memory domains authenticated through live
  translation and generation state.
- The runtime is BKL-free: independently locked subsystems coordinate through
  typed kernel objects and explicit lifecycle transactions.
- Interactive `-t` sessions use process-wide host terminal facilities, so the
  embedded shared-carrier interface deliberately does not expose a TTY yet.

Hardware-assisted execution is supplied per host:

- **Host/VMM backends:** macOS/HVF (`Hypervisor.framework`), Linux/KVM,
  FreeBSD/bhyve, and NetBSD/NVMM.
- **Guest ISAs:** AArch64 on the reference macOS/HVF path, plus active x86_64
  bring-up through KVM, bhyve, and NVMM.
- **Preserved optimization primitives:** `carrick-native-darwin`,
  `carrick-dsr`, `carrick-dsr-aarch64`, and `carrick-dsr-x86` provide JIT
  translation, `MAP_JIT` W^X primitives, and Tier-D direct binary patching for
  future OS-level optimizations. They are not selectable shipped execution
  backends.

---

## Advanced embedding: compose the kernel boundary

Because Carrick owns the syscall, filesystem, clock, network, and lifecycle
paths, an embedding program can compose behavior inside the kernel instead of
wrapping a host process from outside. The compiled advanced example creates
one carrier, runs two containers concurrently in its single VM, gives each a
different read-only in-memory filesystem, and changes only alpha's `getuid`
result and stdout route:

```rust
use std::sync::Arc;

use carrick_embed::{
    Carrier, EmbedError, FilterVfs, InMemoryFileVfs, InterceptAction,
    InterceptedSyscall, ProcessInfo, SyscallInterceptor,
};

struct AlphaPolicy;

impl SyscallInterceptor for AlphaPolicy {
    fn intercept(&self, _: &ProcessInfo<'_>, call: &InterceptedSyscall<'_>) -> InterceptAction {
        match call.name() {
            "getuid" => InterceptAction::Return(4242),
            "write" if call.effective_args().get(0) == Some(1) => {
                match call.effective_args().with_arg(0, 2) {
                    Ok(args) => InterceptAction::RewriteArgs(args),
                    Err(_) => InterceptAction::Continue,
                }
            }
            _ => InterceptAction::Continue,
        }
    }
}

fn role_files(role: &'static [u8]) -> Result<FilterVfs, EmbedError> {
    let files = InMemoryFileVfs::new();
    files
        .add_file("/config/role", role)
        .map_err(|errno| EmbedError::Config(format!("VFS errno {}", errno.get())))?;
    Ok(FilterVfs::new(Box::new(files)).readonly(true))
}

#[tokio::main]
async fn main() -> Result<(), EmbedError> {
    let carrier = Carrier::new()?;
    let alpha = carrier
        .container("ubuntu:24.04")
        .command(["/bin/sh", "-c", "/usr/bin/id -ru; cat /config/role"])
        .vfs_mount("/config", Box::new(role_files(b"alpha\n")?))
        .interceptor(Arc::new(AlphaPolicy));
    let beta = carrier
        .container("ubuntu:24.04")
        .command(["/bin/sh", "-c", "/usr/bin/id -ru; cat /config/role"])
        .vfs_mount("/config", Box::new(role_files(b"beta\n")?));

    let (alpha, beta) = tokio::join!(alpha.run(), beta.run());
    carrier.shutdown().await?;
    alpha?.ensure_success()?;
    beta?.ensure_success()?;
    Ok(())
}
```

The [complete compiled example](crates/carrick-embed/examples/advanced_embed.rs)
also verifies the isolated outputs. Its policy is container-local; sharing the
same `Arc` policy or VFS object is an explicit application choice.

| Interface | What an embedder can do | Current boundary |
| --- | --- | --- |
| Stdio | Capture, inherit, or provide independent stdout/stderr writers | no interactive embedded TTY |
| Observers | Inspect effective syscalls and apply allow, errno, signal, or short-I/O actions | observation/filtering, not arbitrary result replacement |
| Interceptors | Rewrite six scalar arguments or propose a return value/Linux errno | no syscall-number change, guest-pointer dereference, or guest-memory mutation |
| VFS | Mount in-memory, layered, filtered, recording, or custom filesystems | behavior below the mount only; no private-page access |
| Time | Use system, offset, frozen, scaled, or deterministic container clocks | Carrick-modeled clocks and waits, not host time |
| Faults and budgets | Inject ordered faults/delays and limit modeled resources | only the documented actions and counters |
| Network | Mock or refuse selected outbound targets and record connections | not a raw-packet or general packet-filter API |
| Shared buffers | Expose generation-checked host-backed `MAP_SHARED` pages | callers coordinate access; leases fail after retirement |
| Carrier concurrency | Run independent non-interactive containers concurrently in one kernel graph and VM | exactly one carrier/VM per host process; explicit shutdown required |

## Project status

The most complete path is AArch64 Linux user space on Apple Silicon macOS via
`Hypervisor.framework`. It runs dynamically linked programs, OCI filesystems,
multi-process workloads, networking, terminals, package installation, and
substantial Go, Node.js, CPython, and LTP conformance suites.

Linux/KVM, FreeBSD/bhyve, and NetBSD/NVMM backends share the kernel architecture
but remain under active x86_64 bring-up. They are not yet equivalent to the
macOS/HVF reference path. See the [platform architecture and status](docs/hal.md)
and [current syscall map](docs/syscalls-emulation-map.md) for the precise edges.

## Learn more

- [`carrick-embed`](crates/carrick-embed/README.md) — embedding APIs and
  extension seams.
- [Architecture](docs/architecture-overview.md) — the kernel, trap boundary,
  memory model, concurrency, and process lifecycle.
- [Platform layer](docs/hal.md) — host capabilities and VMM backends.
- [Syscall coverage](docs/syscalls-emulation-map.md) — current Linux ABI
  support.
- [Conformance testing](docs/conformance-testing.md) — differential testing
  against Linux and the hardware-runner evidence boundary.
- [Workspace map](crates/README.md) — crate ownership and dependency direction.

## Build from source

The [`justfile`](justfile) is the source of truth. On Apple Silicon macOS:

```sh
just build
just run run ubuntu:24.04 /bin/echo hello
just ci
```

`just build` applies the required hypervisor entitlement. Other hosts select
their platform backend explicitly; see the [platform guide](docs/hal.md).

## License

Carrick is dual-licensed under Apache-2.0 or MIT.
