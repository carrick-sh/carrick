# carrick-embed

Run an unmodified Linux container image from a Rust program, on Carrick's own
kernel (no guest Linux kernel, no Docker daemon). Experimental, like the rest of
Carrick: syscall coverage is partial and a guest is not a hardened trust
boundary — do not run untrusted code under it.

## Quick start

```rust
use carrick_embed::testing::ResultAssert;
use carrick_embed::{ContainerBuilder, EmbedError};

fn main() -> Result<(), EmbedError> {
    let result = ContainerBuilder::from_image("ubuntu:24.04")
        .command(["/bin/sh", "-c", "echo hello from $GREETING"])
        .env("GREETING", "carrick-embed")
        .run_blocking()?;                      // resolve image, run guest, return
    result.assert_success().assert_stdout_contains("hello from carrick-embed");
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
  `TrapLimit`, `Runtime`, `ExecutePanicked`. Linux errnos delivered to the guest
  are never errors here.
- `carrick_embed::testing`: `TestContainer` (one image, many commands),
  `run_in_container(image, cmd)`, and the `ResultAssert` chain.
- Every request lowers into `carrick_engine::RunRequest`, so image-vs-request
  precedence (entrypoint/cmd, env layering, cwd, user) is decided by the same
  code as `carrick run`.

## Entitlement (macOS)

The executable that calls this crate — your application, or the cargo test
binary — must carry the hypervisor entitlement (`scripts/entitlements.plist`).
An unsigned binary gets `EmbedError::Entitlement` (`HV_DENIED`, `0xfae94007`)
from every run. For Carrick's own tests the signed `just test-embed` recipe
codesigns each test executable and runs it serialized; `Entitlement` there is a
failure, never a skip. See AGENTS.md Rule 0.

## Not in this version

tty/interactive sessions, VFS injection, syscall observers, time control,
fault injection, shared memory, network mocking and resource budgets are
later phases of the embed program
(`docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md`); running
two containers in one host process depends on Phase B (container objects on the
kernel graph).

## Features

Default `["platform-macos", "syscall-shim"]`, forwarded to `carrick-runtime`
and `carrick-engine` exactly like `carrick-cli`. Off macOS build with
`--no-default-features --features platform-<linux|freebsd|netbsd>` (optionally
plus `syscall-shim`).
