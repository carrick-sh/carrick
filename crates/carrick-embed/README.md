# carrick-embed

Run an unmodified Linux container image from a Rust program, on Carrick's own
kernel (no guest Linux kernel, no Docker daemon). Experimental, like the rest of
Carrick: syscall coverage is partial and a guest is not a hardened trust
boundary — do not run untrusted code under it.

An embedded workload enters the same carrier architecture as the CLI: one VM
and one Carrick kernel graph can contain multiple Linux process and namespace
trees. The embedding process does not become the Linux process, and guest
`fork`/`clone` remain Carrick kernel operations.

## Quick start

```rust
use carrick_embed::{ContainerBuilder, EmbedError};

fn main() -> Result<(), EmbedError> {
    let result = ContainerBuilder::from_image("ubuntu:24.04")
        .command(["/bin/sh", "-c", "echo hello from $GREETING"])
        .env("GREETING", "carrick-embed")
        .run_blocking()?
        .ensure_success()?;
    print!("{}", result.stdout_utf8());
    Ok(())
}
```

Inside tokio, use `.run().await` (it resolves the image on your runtime and
executes on the blocking pool); `run_blocking()` refuses to run inside a runtime.

## What you get

- Docker-shaped inputs: `command`, `entrypoint`, `env`, `workdir`, `user`
  (numeric `uid[:gid]` only), `hostname`, `mount`/`mount_readonly` (absolute
  paths), `platform`, `pull_policy`, `image_store`, `max_traps`.
- Stdio per stream: `StdioConfig::Captured` (default; bytes land in
  `ContainerResult::{stdout, stderr}`), `Inherit` (your process's fd 1/2), or
  `Piped(Box<dyn Write + Send>)`.
- `ContainerResult { exit_code, signal, stdout, stderr, trap_limit_hit, traps,
  compat }`, `success()`, `ensure_success()` (turns a failed guest into
  `EmbedError::Guest`).
- `EmbedError`: `Image`, `Config`, `Prepare`, `Entitlement`, `Guest`,
  `TrapLimit`, `Runtime`, `InterceptorPanicked`, `ExecutePanicked`. Linux errnos
  delivered to the guest are never errors here.
- `carrick_embed::testing`: `TestContainer` (one image, many commands),
  `run_in_container(image, cmd)`, and the `ResultAssert` chain.
- Kernel extension seams are summarized below. They are installed per
  container and sealed by `prepare`.
- `Carrier` explicitly owns one VM and kernel graph for concurrent containers.
  The convenience `from_image` path instead creates and deterministically
  retires an implicit single-use carrier.
- Every request lowers into `carrick_engine::RunRequest`, so image-vs-request
  precedence (entrypoint/cmd, env layering, cwd, user) is decided by the same
  code as `carrick run`.

## Kernel extension seams

| Interface | Supported behavior | Current boundary |
| --- | --- | --- |
| Stdio | `StdioConfig::{Captured, Inherit, Piped}` configures stdout and stderr independently; captured bytes are returned in `ContainerResult` | an interactive embedded TTY is not exposed yet |
| Observers | `.observer(...)` inspects effective syscall arguments, filters with allow/deny/kill/short-I/O actions, and receives lifecycle and terminal-return callbacks | observation/filtering only; observers do not replace arbitrary results |
| Interceptors | `.interceptor(...)` rewrites all six opaque scalar argument words or proposes a return value/Linux errno; repeated calls run in registration order and the first terminal proposal stops the chain | cannot change the syscall number, dereference guest pointers, or mutate guest memory |
| VFS | `.vfs_mount(...)` installs an in-memory, layered, filtered, recording, or custom `Vfs` implementation at an absolute guest path | controls filesystem behavior below that mount; it is not arbitrary private-page access |
| Time | `.time(TimeControl)` selects `System`, `Offset`, `Frozen`, `Scaled`, or `Deterministic` time for the container's `ClockDomain`; the last call wins | controls Carrick-modeled guest clocks and waits for this container, not host time |
| Faults and budgets | `.fault_injector(FaultInjector)` adds ordered errno, kill, short-I/O, or container clock-domain delay rules; `.resource_budget(ResourceBudget)` limits processes, syscalls, CPU time, committed memory, or bytes written with `ExceedAction` | the first matching fault rule wins; a pure delay returns `Allow`, so later observers and the handler continue, while later rules in that injector are not evaluated; budgets cover only the shipped counters and actions |
| Network | `.network_interposer(NetworkInterposer)` installs outbound target rules that mock with `MockService`/`HttpMock` or refuse with a Linux errno, with bounded ordered `ConnectionRecord` history | one interposer per container (the last call wins); this is not a general packet-filter or raw-packet API |
| Shared buffers | `.shared_buffer(name, &SharedBuffer)` exposes host-backed pages at `/dev/carrick/shm/<name>` for guest `MAP_SHARED`; `PreparedContainer::shared_buffer_lease` returns a generation-stamped `SharedBufferLease` | no arbitrary private-page access; lease operations fail with `SharedBufferError` after retirement or generation drift, and callers coordinate concurrent access |
| Carrier concurrency | `Carrier::new()` owns one VM/kernel graph; `.container(image)` binds builders to it and `.shutdown().await` drains exact retirement | one carrier/VM per host process; non-interactive workloads only |

Repeated `.observer(...)` and `.interceptor(...)` calls preserve registration
order and are sealed by `prepare`. Resource-budget enforcement runs before user
observers. Launch policy and guest seccomp evaluate an interceptor's effective
call before its proposed result is honored; policy outcomes combine
monotonically, so a later errno cannot downgrade an established signal death.
Installing an interceptor also disables accelerated syscall blind spots for
that container: identity and time calls are routed through ordinary visible
traps. If trusted interceptor code panics, the run returns
`EmbedError::InterceptorPanicked { container_id }`; the panic does not unwind
through Carrick's executor. Builder/setup failures use `EmbedError::Config` or
`Prepare`, while post-prepare infrastructure failures use `Runtime`.

[`examples/intercept_getuid.rs`](examples/intercept_getuid.rs) is a compiled
single-container example. It replaces canonical `getuid` with uid 1000, leaves
all other syscalls unchanged, and runs `/usr/bin/id -ru` (`-r` requests the
real uid):

```sh
cargo run -p carrick-embed --example intercept_getuid
```

On macOS the example binary must be built and signed with the hypervisor
entitlement before it can run a guest; ordinary `cargo check` only proves the
public interface compiles.

## Explicit carrier concurrency

Use an explicit carrier when runs should overlap or deliberately share a host
object:

```rust
use carrick_embed::{Carrier, EmbedError};

#[tokio::main]
async fn main() -> Result<(), EmbedError> {
    let carrier = Carrier::new()?;
    let a = carrier.container("ubuntu:24.04").command(["sleep", "1"]);
    let b = carrier.container("ubuntu:24.04").command(["uname", "-a"]);
    let (a, b) = tokio::join!(a.run(), b.run());
    carrier.shutdown().await?;
    a?.ensure_success()?;
    b?.ensure_success()?;
    Ok(())
}
```

Async `.run()` gives each execution a blocking-pool worker. Blocking callers
that want overlap must use separate host threads. `ContainerBuilder::from_image`
is intentionally single-use and refuses while an explicit carrier exists; use
`carrier.container(image)` for every run in that generation.

Containers receive distinct kernel identities, root process trees, UTS/network
namespace state, extension chains, filesystems, stdio, clocks, and lifecycle.
Passing the same `Arc<dyn SyscallObserver>`, interceptor, or other shared host
object to multiple builders deliberately shares that object; Carrick does not
clone away the application's synchronization contract.

Call `carrier.shutdown().await` after every run future has settled. It closes
admission, cancels live guests if necessary, joins workers, destroys the VM,
and waits for lifecycle publication. Dropping the last handle requests the same
close asynchronously as a safety fallback, but is not a deterministic join.
Admission and lifecycle failures are typed as `CarrierAlreadyActive`,
`CarrierClosing`, `CarrierClosed`, or `CarrierFailed`. A contained trusted
interceptor panic becomes `InterceptorPanicked`; a blocking worker panic
becomes `ExecutePanicked`.

See [`examples/advanced_embed.rs`](examples/advanced_embed.rs) for a compiled
two-container example with isolated VFS mounts, syscall interception, and
stdio routing.

## Entitlement (macOS)

The executable that calls this crate — your application, or the cargo test
binary — must carry the hypervisor entitlement (`scripts/entitlements.plist`).
An unsigned binary gets `EmbedError::Entitlement` (`HV_DENIED`, `0xfae94007`)
from every run. For Carrick's own tests the signed `just test-embed` recipe
codesigns each test executable and runs it serialized; `Entitlement` there is a
failure, never a skip. See AGENTS.md Rule 0.

The entitlement authorizes HVF on a physical Apple Silicon host; it cannot add
nested-virtualization support to a hosted VM. Guest-running embed tests
therefore require a supported hardware runner in addition to signing. Ordinary
compile and host-only tests do not.

## Not in this version

Interactive embedded TTY sessions, syscall-number replacement, guest-pointer
dereference, arbitrary guest-memory mutation, and raw packet filtering are not
public interfaces.

## Features

Default `["platform-macos", "syscall-shim"]`, forwarded to `carrick-runtime`
and `carrick-engine` exactly like `carrick-cli`. Off macOS build with
`--no-default-features --features platform-<linux|freebsd|netbsd>` (optionally
plus `syscall-shim`).
