# Docker-compatible frontend & workspace layering — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split carrick into a Cargo workspace (`carrick-spec`, `carrick-image`, `carrick-runtime`, `carrick-engine`, `carrick-cli`) and add a docker-compatible `run` frontend that honors image OCI config, core flags, and bind mounts — host namespaces only.

**Architecture:** A leaf `carrick-spec` crate holds pure vocabulary types (`RunSpec`, `ContainerSpec`, `ImageConfig`, `Mount`, `NamespaceConfig`, `FsBackendKind`). `carrick-runtime` (the bulk of today's `src/`) consumes a `RunSpec` via a new `execute()` seam. `carrick-image` resolves an image reference to layers + parsed `ImageConfig`. `carrick-engine` is the only crate that knows both image and runtime: it merges CLI overrides with image config (docker `run` semantics) into a `RunSpec` and executes it. `carrick-cli` is the binary (output name stays `carrick`).

**Tech Stack:** Rust 2024 edition, Cargo workspace + `[workspace.lints]`, clap, oci-client, applevisor/HVF, thiserror, camino, serde.

**Spec:** `docs/superpowers/specs/2026-05-24-docker-frontend-layering-design.md`

**Refinements from spec (deliberate):**
1. `ImageReference` stays in `carrick-image` (wraps `oci_client::Reference`; moving it would pull `oci_client` into the leaf crate). `ContainerSpec.image` is the canonical ref `String`.
2. The runtime's existing `RunResult` (embeds `CompatReport`) stays in `carrick-runtime` as the outbound type; spec defines the inbound `RunSpec` only. Engine returns `carrick_runtime::RunResult`.

**Hard constraints (do not regress):**
- Output binary MUST stay named `carrick` so `target/release/carrick` (the codesign/entitlements path) is unchanged. `scripts/build-signed.sh` and `scripts/entitlements.plist` depend on it; regressing yields HV_DENIED.
- The no-panic gate (`deny unwrap/expect/panic/todo/unimplemented`) must remain active across all crates.

---

## File Structure (target)

```
Cargo.toml                       # virtual workspace manifest
clippy.toml                      # unchanged (test-code exemptions)
crates/
  carrick-spec/
    Cargo.toml
    src/lib.rs                   # re-exports
    src/image.rs                 # ImageConfig
    src/container.rs             # Mount, NamespaceMode/Config, ContainerSpec
    src/run.rs                   # FsBackendKind, RunSpec
  carrick-image/
    Cargo.toml
    src/lib.rs                   # was src/oci.rs + ImageConfig parsing + resolve()
  carrick-runtime/
    Cargo.toml
    src/lib.rs                   # was src/lib.rs minus oci
    src/*.rs                     # all other current src/ modules
    src/execute.rs               # NEW: Runtime::execute(&RunSpec) seam
    tests/*                      # re-homed lib-level integration tests
  carrick-engine/
    Cargo.toml
    src/lib.rs
    src/resolve.rs               # CliRunRequest, resolve_run_spec (docker merge)
    src/engine.rs                # Engine::run
  carrick-cli/
    Cargo.toml                   # [[bin]] name = "carrick"
    src/main.rs                  # was src/main.rs, run arm rewired to engine
    tests/*                      # cli.rs, conformance.rs (bin-level tests)
```

---

## Task 1: Workspace scaffold + relocate crate into `carrick-runtime` + `carrick-cli`

This is a mechanical relocation. No logic changes. Verified by a green build with the binary still named `carrick`.

**Files:**
- Create: `Cargo.toml` (workspace), `crates/carrick-runtime/Cargo.toml`, `crates/carrick-cli/Cargo.toml`
- Move: `src/*.rs` (except `main.rs`) → `crates/carrick-runtime/src/`; `src/main.rs` → `crates/carrick-cli/src/main.rs`

- [ ] **Step 1: Create the crate directories and move sources with git**

```bash
cd /Volumes/CaseSensitive/carrick
mkdir -p crates/carrick-runtime/src crates/carrick-cli/src
git mv src/main.rs crates/carrick-cli/src/main.rs
git mv src/* crates/carrick-runtime/src/        # moves remaining modules incl. lib.rs and oci.rs (oci split out in Task 5)
```

- [ ] **Step 2: Write the workspace root `Cargo.toml`**

Replace the entire root `Cargo.toml` with a virtual manifest. Move the `[lints.clippy]`, `[profile]`, and shared dependency version pins to `[workspace.lints]` / `[workspace.dependencies]`.

```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "Apache-2.0 OR MIT"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"

[workspace.dependencies]
anyhow = "1.0.100"
bitflags = "2.10.0"
libc = "0.2"
camino = { version = "1.2.1", features = ["serde1"] }
cap-std = "4"
clap = { version = "4.5.51", features = ["derive", "env"] }
fd-lock = "4"
flate2 = { version = "1.1.9", default-features = false, features = ["rust_backend"] }
getrandom = "0.3.4"
goblin = { version = "0.10.5", default-features = false, features = ["elf32", "elf64", "endian_fd", "std"] }
oci-client = { version = "0.15", default-features = false, features = ["rustls-tls"] }
parking_lot = "0.12"
parking_lot_core = "0.9"
serde = { version = "1.0.228", features = ["derive"] }
serde_json = "1.0.145"
sha2 = "0.10.9"
tar = { version = "0.4.45", default-features = false }
tempfile = "3.23.0"
thiserror = "2.0.17"
tokio = { version = "1.48.0", features = ["fs", "io-util", "macros", "rt"] }
tracing = "0.1.43"
tracing-subscriber = { version = "0.3.22", features = ["env-filter", "fmt"] }
usdt = "0.6.0"
zerocopy = { version = "0.8.48", features = ["derive"] }
applevisor = { version = "1.0.0", default-features = false, features = ["macos-13-0"] }
applevisor-sys = { version = "1.0.0", default-features = false, features = ["macos-13-0"] }
# dev
assert_cmd = "2.1.1"
predicates = "3.1.3"
bollard = "0.18"
futures-util = "0.3"
base64 = "0.22"
```

- [ ] **Step 3: Write `crates/carrick-runtime/Cargo.toml`**

The lib crate name is `carrick_runtime` (Rust identifier) via `name = "carrick-runtime"`. Include every dependency the current crate used as a library (all non-dev deps above). Dev-deps re-homed in Task 2.

```toml
[package]
name = "carrick-runtime"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "carrick_runtime"
path = "src/lib.rs"

[lints]
workspace = true

[dependencies]
anyhow.workspace = true
bitflags.workspace = true
libc.workspace = true
camino.workspace = true
cap-std.workspace = true
fd-lock.workspace = true
flate2.workspace = true
getrandom.workspace = true
goblin.workspace = true
oci-client.workspace = true
parking_lot.workspace = true
parking_lot_core.workspace = true
serde.workspace = true
serde_json.workspace = true
sha2.workspace = true
tar.workspace = true
tempfile.workspace = true
thiserror.workspace = true
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
usdt.workspace = true
zerocopy.workspace = true

[target.'cfg(all(target_os = "macos", target_arch = "aarch64"))'.dependencies]
applevisor.workspace = true
applevisor-sys.workspace = true
```

- [ ] **Step 4: Write `crates/carrick-cli/Cargo.toml`** — the binary, output name `carrick`

```toml
[package]
name = "carrick-cli"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "carrick"
path = "src/main.rs"

[lints]
workspace = true

[dependencies]
carrick-runtime = { path = "../carrick-runtime" }
anyhow.workspace = true
clap.workspace = true
camino.workspace = true
libc.workspace = true
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

- [ ] **Step 5: Fix the import root in `main.rs`**

`main.rs` referenced the lib as `carrick::`. Rewrite to `carrick_runtime::`.

Run: `cd /Volumes/CaseSensitive/carrick && grep -rl 'carrick::' crates/carrick-cli/src | xargs sed -i '' 's/\bcarrick::/carrick_runtime::/g'`

Then audit the diff: `git diff crates/carrick-cli/src/main.rs | grep carrick_runtime | head`.

- [ ] **Step 6: Build the whole workspace**

Run: `cargo build`
Expected: PASS. Binary at `target/debug/carrick`.

Run: `ls target/debug/carrick && echo OK`
Expected: prints the path and `OK`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(workspace): split into carrick-runtime lib + carrick-cli bin"
```

---

## Task 2: Re-home integration tests + dev-dependencies; restore green test suite

The `tests/` directory was attached to the old single crate. Lib-level tests (`carrick::runtime`, `carrick::*`) belong with `carrick-runtime`; binary-level tests (`cli.rs`, `conformance.rs`) belong with `carrick-cli`.

**Files:**
- Move: most of `tests/*` → `crates/carrick-runtime/tests/`; `tests/cli.rs`, `tests/conformance.rs`, `tests/common/` (if used by cli tests) → `crates/carrick-cli/tests/`
- Modify: dev-deps in both crate manifests; `tests/*` import roots (`carrick::` → `carrick_runtime::`)

- [ ] **Step 1: Classify each test file**

Run: `cd /Volumes/CaseSensitive/carrick && for f in tests/*.rs; do echo "== $f =="; grep -l 'cargo_bin\|assert_cmd\|bollard' "$f" >/dev/null 2>&1 && echo "BIN-LEVEL" || echo "lib-level"; done`
Expected: `cli.rs`, `conformance.rs`, `interactive_*` and any using `assert_cmd`/`bollard` flagged BIN-LEVEL; the rest lib-level.

- [ ] **Step 2: Move lib-level tests**

```bash
cd /Volumes/CaseSensitive/carrick
mkdir -p crates/carrick-runtime/tests crates/carrick-cli/tests
# lib-level (adjust list per Step 1 output):
for f in address_space compat_report concurrency_contracts elf_inspector io_blocking_guard io_wait linux_fixture nested_pipe oci_layout rootfs_overlay rootfs_streaming runtime_loop syscall_creds syscall_fs syscall_mem syscall_net syscall_process syscall_signal syscall_table syscall_thread syscall_time thread_stress_harness trap_hvf; do
  [ -f "tests/$f.rs" ] && git mv "tests/$f.rs" crates/carrick-runtime/tests/
done
# bin-level:
for f in cli conformance interactive_supervisor interactive_tty; do
  [ -f "tests/$f.rs" ] && git mv "tests/$f.rs" crates/carrick-cli/tests/
done
[ -d tests/common ] && git mv tests/common crates/carrick-runtime/tests/common
```

(If `tests/common` is used by bin-level tests, duplicate or move accordingly; verify with `grep -rn "mod common\|common::" tests crates/*/tests`.)

- [ ] **Step 3: Fix test import roots**

```bash
cd /Volumes/CaseSensitive/carrick
grep -rl '\bcarrick::' crates/carrick-runtime/tests crates/carrick-cli/tests | xargs sed -i '' 's/\bcarrick::/carrick_runtime::/g'
```

- [ ] **Step 4: Add dev-dependencies to the crate manifests**

To `crates/carrick-runtime/Cargo.toml`:
```toml
[dev-dependencies]
tempfile.workspace = true
```
To `crates/carrick-cli/Cargo.toml`:
```toml
[dev-dependencies]
assert_cmd.workspace = true
predicates.workspace = true
tempfile.workspace = true
bollard.workspace = true
futures-util.workspace = true
base64.workspace = true
tokio.workspace = true
```

- [ ] **Step 5: Run the full test suite**

Run: `cargo test --workspace`
Expected: PASS (same count as before the split; ~113 lib tests + integration tests). If a moved test fails to compile due to a `pub(crate)` item it reached through the old crate, mark it `#[ignore]` ONLY as a last resort and note it; prefer widening visibility in `carrick-runtime` or moving the test.

- [ ] **Step 6: Checkpoint — codesign + smoke a real run (HVF gate)**

Run: `./scripts/build-signed.sh`
Expected: `built + signed: target/release/carrick`.

Run: `./target/release/carrick run --raw alpine:latest /bin/echo hello`
Expected: prints `hello` (proves HVF still works post-split; this is the HV_DENIED early-warning).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(workspace): re-home integration tests and dev-deps"
```

---

## Task 3: Create `carrick-spec` with vocabulary types

Pure value types, light deps. TDD the small constructors/helpers.

**Files:**
- Create: `crates/carrick-spec/Cargo.toml`, `crates/carrick-spec/src/lib.rs`, `src/image.rs`, `src/container.rs`, `src/run.rs`

- [ ] **Step 1: Write `crates/carrick-spec/Cargo.toml`**

```toml
[package]
name = "carrick-spec"
version.workspace = true
edition.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
camino.workspace = true
serde.workspace = true
```

- [ ] **Step 2: Write the failing test for `NamespaceConfig::host()` and `RunSpec` construction**

Create `crates/carrick-spec/src/run.rs` test module first (implementation stubs to follow):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{NamespaceConfig, NamespaceMode};

    #[test]
    fn namespace_config_host_is_all_host() {
        let ns = NamespaceConfig::host();
        assert_eq!(ns.network, NamespaceMode::Host);
        assert_eq!(ns.pid, NamespaceMode::Host);
        assert_eq!(ns.mount, NamespaceMode::Host);
        assert_eq!(ns.uts, NamespaceMode::Host);
        assert_eq!(ns.ipc, NamespaceMode::Host);
        assert_eq!(ns.user, NamespaceMode::Host);
    }
}
```

- [ ] **Step 3: Run the test (expect compile failure)**

Run: `cargo test -p carrick-spec`
Expected: FAIL — types not defined.

- [ ] **Step 4: Implement the types**

`crates/carrick-spec/src/container.rs`:
```rust
use camino::Utf8PathBuf;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Host path (bind source).
    pub source: Utf8PathBuf,
    /// Guest path (mount target).
    pub target: Utf8PathBuf,
    pub readonly: bool,
}

/// Isolation mode for a namespace. Only `Host` exists today; this enum is the
/// seam where real isolation (private network/pid/mount/...) drops in later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceMode {
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceConfig {
    pub network: NamespaceMode,
    pub pid: NamespaceMode,
    pub mount: NamespaceMode,
    pub uts: NamespaceMode,
    pub ipc: NamespaceMode,
    pub user: NamespaceMode,
}

impl NamespaceConfig {
    /// Every namespace shared with the host. The only configuration today.
    pub fn host() -> Self {
        Self {
            network: NamespaceMode::Host,
            pid: NamespaceMode::Host,
            mount: NamespaceMode::Host,
            uts: NamespaceMode::Host,
            ipc: NamespaceMode::Host,
            user: NamespaceMode::Host,
        }
    }
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self::host()
    }
}

/// A resolved container request: identity + config, independent of how the
/// rootfs layers are sourced. The engine lowers this into a `RunSpec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSpec {
    /// Canonical image reference string (e.g. `docker.io/library/alpine:latest`).
    pub image: String,
    pub name: Option<String>,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: Option<Utf8PathBuf>,
    pub user: Option<String>,
    pub mounts: Vec<Mount>,
    pub tty: bool,
    pub interactive: bool,
    pub rm: bool,
    pub namespaces: NamespaceConfig,
    pub labels: BTreeMap<String, String>,
}
```

`crates/carrick-spec/src/image.rs`:
```rust
use camino::Utf8PathBuf;
use std::collections::BTreeMap;

/// Parsed OCI image config (the `config` field of an image config blob).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageConfig {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: Vec<String>,
    pub working_dir: Option<Utf8PathBuf>,
    pub user: Option<String>,
    pub exposed_ports: Vec<String>,
    pub labels: BTreeMap<String, String>,
}
```

`crates/carrick-spec/src/run.rs` (above the test module):
```rust
use camino::Utf8PathBuf;
use crate::container::{Mount, NamespaceConfig};

/// Which writable-layer backend the runtime should install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsBackendKind {
    Memory,
    Host,
}

/// The fully-resolved low-level execution request the runtime consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSpec {
    pub executable: String,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
    pub cwd: Option<Utf8PathBuf>,
    pub rootfs_layers: Vec<Utf8PathBuf>,
    pub fs_backend: FsBackendKind,
    pub mounts: Vec<Mount>,
    pub tty: bool,
    pub raw: bool,
    pub interactive: bool,
    pub max_traps: usize,
    pub debug_state_path: Option<Utf8PathBuf>,
    pub namespaces: NamespaceConfig,
    pub user: Option<String>,
}
```

`crates/carrick-spec/src/lib.rs`:
```rust
pub mod container;
pub mod image;
pub mod run;

pub use container::{ContainerSpec, Mount, NamespaceConfig, NamespaceMode};
pub use image::ImageConfig;
pub use run::{FsBackendKind, RunSpec};
```

- [ ] **Step 5: Run the test (expect pass)**

Run: `cargo test -p carrick-spec`
Expected: PASS.

- [ ] **Step 6: Add `carrick-spec` to `carrick-runtime` deps and re-export `FsBackendKind` use**

In `crates/carrick-runtime/Cargo.toml` `[dependencies]` add:
```toml
carrick-spec = { path = "../carrick-spec" }
```

Run: `cargo build -p carrick-runtime`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(spec): add carrick-spec vocabulary crate (RunSpec, ContainerSpec, ImageConfig)"
```

---

## Task 4: Add `Runtime::execute(&RunSpec)` seam to `carrick-runtime`

Consolidate the host/memory branching that currently lives in the CLI `Run` arm (`crates/carrick-cli/src/main.rs`, the `Commands::Run` block) into a single runtime entry point. Move the helpers `seed_guest_baseline`, `install_fs_backend`, and `setup_interactive_stdio` from `main.rs` into the runtime crate. The interactive (tty) path returns a `RunResult` instead of calling `std::process::exit`, leaving exit-code/process control to the CLI.

**Files:**
- Create: `crates/carrick-runtime/src/execute.rs`
- Modify: `crates/carrick-runtime/src/lib.rs` (add `pub mod execute;`); move helpers out of `crates/carrick-cli/src/main.rs`

- [ ] **Step 1: Move the three helpers into the runtime crate**

Cut `setup_interactive_stdio` (main.rs:278), `install_fs_backend` (main.rs:1022), and `seed_guest_baseline` (main.rs:1083) from `crates/carrick-cli/src/main.rs` and paste them into `crates/carrick-runtime/src/execute.rs`, making each `pub`. Adjust their bodies to use `crate::` paths (they were `carrick::` from the bin). The interactive supervisor return type is unchanged.

- [ ] **Step 2: Write `Runtime::execute` in `crates/carrick-runtime/src/execute.rs`**

This mirrors the existing `Run` arm logic (today's `main.rs` lines ~590–664), parameterized by `RunSpec`. It returns `RunResult`; for the interactive case it relays and waits, then synthesizes a `RunResult` carrying the relayed exit code (empty stdout/stderr, as the relay path streams directly).

Module paths matter here: `SyscallDispatcher` lives in `crate::dispatch`, `HostFsBackend` in `crate::fs_backend`, `RootFs` in `crate::rootfs` (the crate root has no re-exports). The run entry functions live in `crate::runtime`.

```rust
use crate::compat::CompatReport;
use crate::dispatch::SyscallDispatcher;
use crate::fs_backend::HostFsBackend;
use crate::rootfs::RootFs;
use crate::runtime::{
    RunResult, RuntimeError, run_elf_from_dispatcher_debug,
    run_rootfs_elf_with_hvf_args_and_dispatcher_debug,
};
use carrick_spec::{FsBackendKind, RunSpec};

/// Execute a fully-resolved `RunSpec`: build the writable-layer backend from
/// the OCI layers, apply bind mounts, seed the guest baseline, wire stdio/tty,
/// run the vCPU, and return the outcome. This is the single seam the engine
/// layer drives.
pub fn execute(spec: &RunSpec) -> Result<RunResult, RuntimeError> {
    let layers: Vec<std::path::PathBuf> =
        spec.rootfs_layers.iter().map(|p| p.as_std_path().to_path_buf()).collect();

    match spec.fs_backend {
        FsBackendKind::Host => {
            let mut host = HostFsBackend::new()
                .map_err(|e| RuntimeError::FsBackend(e.to_string()))?;
            host.extract_layers(&layers)
                .map_err(|e| RuntimeError::FsBackend(e.to_string()))?;
            apply_mounts(&mut host, spec)?;
            let mut dispatcher = SyscallDispatcher::new();
            dispatcher.set_executable_path(spec.executable.clone());
            seed_guest_baseline(&mut host);
            let _ = dispatcher.set_fs_backend(Box::new(host));
            run_with_stdio(dispatcher, spec, /*memory_rootfs=*/ None)
        }
        FsBackendKind::Memory => {
            let rootfs = RootFs::from_layer_paths(&layers)
                .map_err(|e| RuntimeError::FsBackend(e.to_string()))?;
            let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(
                rootfs.clone(),
                spec.executable.clone(),
            );
            install_fs_backend(&mut dispatcher, Some(FsBackendKind::Memory))
                .map_err(|e| RuntimeError::FsBackend(e.to_string()))?;
            run_with_stdio(dispatcher, spec, Some(rootfs))
        }
    }
}

fn run_with_stdio(
    mut dispatcher: SyscallDispatcher,
    spec: &RunSpec,
    memory_rootfs: Option<RootFs>,
) -> Result<RunResult, RuntimeError> {
    if let Some(parent) = setup_interactive_stdio(&mut dispatcher, spec.tty, spec.raw)
        .map_err(|e| RuntimeError::FsBackend(e.to_string()))?
    {
        let code = parent
            .relay_and_wait()
            .map_err(|e| RuntimeError::FsBackend(e.to_string()))?;
        return Ok(RunResult {
            exit_code: code,
            stdout: Vec::new(),
            stderr: Vec::new(),
            traps: 0,
            report: CompatReport::default(),
            trap_limit_hit: false,
        });
    }
    let dbg = spec.debug_state_path.as_ref().map(|p| p.as_std_path().to_path_buf());
    match memory_rootfs {
        Some(rootfs) => run_rootfs_elf_with_hvf_args_and_dispatcher_debug(
            spec.executable.as_str(),
            &rootfs,
            dispatcher,
            spec.argv.clone(),
            spec.envp.clone(),
            spec.max_traps,
            dbg.as_ref(),
        ),
        None => run_elf_from_dispatcher_debug(
            spec.executable.as_str(),
            dispatcher,
            spec.argv.clone(),
            spec.envp.clone(),
            spec.max_traps,
            dbg.as_ref(),
        ),
    }
}

/// Apply `spec.mounts` to the host backend's VFS mount table. With host
/// namespaces this is a bind into the guest path space.
fn apply_mounts(_host: &mut HostFsBackend, spec: &RunSpec) -> Result<(), RuntimeError> {
    for m in &spec.mounts {
        // VFS bind-mount wiring. Use the existing mount-table API in
        // src/vfs/mount.rs. If no public bind API exists yet, add a
        // `pub fn bind_host_path(&mut self, source: &Utf8Path, target: &Utf8Path, ro: bool)`
        // to the mount table and call it here.
        let _ = m;
    }
    Ok(())
}
```

NOTE FOR IMPLEMENTER: `apply_mounts` is the one genuinely new runtime capability. Before writing it, read `crates/carrick-runtime/src/vfs/mount.rs` to find the existing mount-table type and whether a bind entry already exists (the VFS refactor added a mount table — see memory `plan_vfs_refactor`). Wire mounts through that API; do not invent a parallel mechanism. If the host backend needs the mounts before `set_fs_backend`, thread them in at construction instead. Memory-backend mounts may be deferred (return `Ok` and log) — bind mounts are primarily meaningful for `--fs host`.

- [ ] **Step 2a: Ensure `CompatReport` derives `Default`**

The interactive path synthesizes a `RunResult` with `CompatReport::default()`. Check `crates/carrick-runtime/src/compat.rs`: if the `pub struct CompatReport` derive line does not already include `Default`, add it (it is plain data — all fields are `Default`-able). Example:
```rust
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatReport { /* … */ }
```

- [ ] **Step 3: Add `RuntimeError::FsBackend(String)` variant if absent**

Check `crates/carrick-runtime/src/runtime.rs` for the `RuntimeError` enum. If there is no general string/backend variant, add:
```rust
#[error("fs backend error: {0}")]
FsBackend(String),
```

- [ ] **Step 4: Export the seam**

In `crates/carrick-runtime/src/lib.rs` add `pub mod execute;`. Ensure `HostFsBackend`, `SyscallDispatcher`, `RootFs` are reachable as referenced (they already are via existing `pub use`/modules; adjust paths to match).

- [ ] **Step 5: Build**

Run: `cargo build -p carrick-runtime`
Expected: PASS.

- [ ] **Step 6: Rewire the CLI `Run` arm to call `execute` (temporary, pre-engine)**

In `crates/carrick-cli/src/main.rs` `Commands::Run`, replace the inline host/memory branches with: build a `RunSpec` inline (using the same image-load + default `/bin/sh` behavior as today, env unchanged for now), call `carrick_runtime::execute::execute(&spec)`, then keep the existing tty/raw/json output handling using the returned `RunResult`. (Full docker semantics arrive in Tasks 5–7; this step only proves the seam end-to-end.)

- [ ] **Step 7: Build, smoke, codesign**

Run: `cargo build && ./scripts/build-signed.sh && ./target/release/carrick run --raw alpine:latest /bin/echo via-execute`
Expected: prints `via-execute`.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(runtime): add execute(&RunSpec) seam; CLI run uses it"
```

---

## Task 5: Create `carrick-image` — move `oci.rs`, add `ImageConfig` parsing + `resolve()`

**Files:**
- Create: `crates/carrick-image/Cargo.toml`, `crates/carrick-image/src/lib.rs`
- Move: `crates/carrick-runtime/src/oci.rs` → `crates/carrick-image/src/lib.rs`
- Modify: remove `pub mod oci;` from `crates/carrick-runtime/src/lib.rs`; update `carrick-cli` to use `carrick_image::`

- [ ] **Step 1: Move the file and create the manifest**

```bash
cd /Volumes/CaseSensitive/carrick
mkdir -p crates/carrick-image/src
git mv crates/carrick-runtime/src/oci.rs crates/carrick-image/src/lib.rs
```

`crates/carrick-image/Cargo.toml`:
```toml
[package]
name = "carrick-image"
version.workspace = true
edition.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
carrick-spec = { path = "../carrick-spec" }
oci-client.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio.workspace = true
camino.workspace = true
tar.workspace = true
flate2.workspace = true
sha2.workspace = true

[dev-dependencies]
tempfile.workspace = true
tokio = { workspace = true, features = ["rt", "macros", "fs"] }
```

Remove `pub mod oci;` from `crates/carrick-runtime/src/lib.rs`. The `pull_image` free function and any other items previously in `oci.rs` move with it. Update `carrick-cli` imports from `carrick_runtime::oci::` to `carrick_image::`.

- [ ] **Step 2: Build (expect errors pointing at remaining `oci::` references)**

Run: `cargo build`
Expected: FAIL listing references to the moved module. Fix each by importing from `carrick_image`. Repeat until green.

- [ ] **Step 3: Write the failing test for `ImageConfig` parsing**

Add to the bottom of `crates/carrick-image/src/lib.rs`:
```rust
#[cfg(test)]
mod image_config_tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "architecture": "arm64",
      "os": "linux",
      "config": {
        "Env": ["PATH=/usr/bin", "FOO=bar"],
        "Entrypoint": ["/entry"],
        "Cmd": ["--flag"],
        "WorkingDir": "/app",
        "User": "1000:1000",
        "ExposedPorts": {"8080/tcp": {}},
        "Labels": {"maintainer": "x"}
      }
    }"#;

    #[test]
    fn parses_oci_config_blob() {
        let cfg = parse_image_config(SAMPLE.as_bytes()).unwrap();
        assert_eq!(cfg.entrypoint.as_deref(), Some(&["/entry".to_string()][..]));
        assert_eq!(cfg.cmd.as_deref(), Some(&["--flag".to_string()][..]));
        assert_eq!(cfg.env, vec!["PATH=/usr/bin", "FOO=bar"]);
        assert_eq!(cfg.working_dir.as_deref().map(|p| p.as_str()), Some("/app"));
        assert_eq!(cfg.user.as_deref(), Some("1000:1000"));
        assert!(cfg.exposed_ports.contains(&"8080/tcp".to_string()));
        assert_eq!(cfg.labels.get("maintainer").map(String::as_str), Some("x"));
    }

    #[test]
    fn missing_config_section_is_default() {
        let cfg = parse_image_config(br#"{"architecture":"arm64","os":"linux"}"#).unwrap();
        assert_eq!(cfg, carrick_spec::ImageConfig::default());
    }
}
```

- [ ] **Step 4: Run the test (expect failure)**

Run: `cargo test -p carrick-image image_config`
Expected: FAIL — `parse_image_config` not found.

- [ ] **Step 5: Implement `parse_image_config` + `ResolvedImage` + `resolve()`**

Add to `crates/carrick-image/src/lib.rs`:
```rust
use camino::Utf8PathBuf;
use carrick_spec::ImageConfig;

/// The layers + parsed config the engine needs to run an image.
#[derive(Debug, Clone)]
pub struct ResolvedImage {
    pub layers: Vec<Utf8PathBuf>,
    pub config: ImageConfig,
}

#[derive(serde::Deserialize)]
struct RawImageBlob {
    #[serde(default)]
    config: RawConfigSection,
}

#[derive(serde::Deserialize, Default)]
struct RawConfigSection {
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(rename = "Env", default)]
    env: Vec<String>,
    #[serde(rename = "WorkingDir")]
    working_dir: Option<String>,
    #[serde(rename = "User")]
    user: Option<String>,
    #[serde(rename = "ExposedPorts", default)]
    exposed_ports: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(rename = "Labels", default)]
    labels: std::collections::BTreeMap<String, String>,
}

/// Parse an OCI image config blob into the spec's `ImageConfig`.
pub fn parse_image_config(bytes: &[u8]) -> Result<ImageConfig, OciBootstrapError> {
    let raw: RawImageBlob = serde_json::from_slice(bytes)?;
    let c = raw.config;
    Ok(ImageConfig {
        entrypoint: c.entrypoint,
        cmd: c.cmd,
        env: c.env,
        working_dir: c.working_dir.map(Utf8PathBuf::from),
        user: c.user.filter(|u| !u.is_empty()),
        exposed_ports: c.exposed_ports.into_keys().collect(),
        labels: c.labels,
    })
}
```

Add a `resolve` method on `ImageStore` that loads the stored pull summary, reads the config blob from the store (the config digest is recorded during pull; if `PullSummary` does not yet carry the config digest, extend it to store `config_digest: Option<String>` and populate it in `pull_image`), parses it, and returns layer paths + config:
```rust
impl ImageStore {
    pub async fn resolve(
        &self,
        image: &ImageReference,
    ) -> Result<ResolvedImage, OciBootstrapError> {
        let summary = self.load_pull_summary(image).await?;
        let config = match summary.config_digest.as_deref() {
            Some(digest) => {
                let bytes = tokio::fs::read(self.blob_path(digest)?).await?;
                parse_image_config(&bytes)?
            }
            None => ImageConfig::default(),
        };
        let layers = summary
            .layers
            .iter()
            .map(|l| Utf8PathBuf::from_path_buf(l.path.clone())
                .unwrap_or_else(|p| Utf8PathBuf::from(p.to_string_lossy().into_owned())))
            .collect();
        Ok(ResolvedImage { layers, config })
    }
}
```

NOTE FOR IMPLEMENTER: inspect `pull_image` in this file. It already downloads the config blob (`config_size` is recorded). Add `config_digest: Option<String>` to `PullSummary`, set it where the config is fetched, and persist the config blob to `blob_path(config_digest)` if it is not already stored. Keep `#[serde(default)]` on the new field so old on-disk summaries still deserialize.

- [ ] **Step 6: Run the tests**

Run: `cargo test -p carrick-image`
Expected: PASS (parse tests + existing oci tests).

- [ ] **Step 7: Build the workspace + smoke**

Run: `cargo build && ./scripts/build-signed.sh && ./target/release/carrick run --raw alpine:latest /bin/echo image-crate-ok`
Expected: prints `image-crate-ok`.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(image): extract carrick-image crate; parse OCI ImageConfig + resolve()"
```

---

## Task 6: Create `carrick-engine` — docker `run` merge semantics + facade

This is the behavioral heart. The merge function is pure and fully TDD'd.

**Files:**
- Create: `crates/carrick-engine/Cargo.toml`, `src/lib.rs`, `src/resolve.rs`, `src/engine.rs`

- [ ] **Step 1: Write `crates/carrick-engine/Cargo.toml`**

```toml
[package]
name = "carrick-engine"
version.workspace = true
edition.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
carrick-spec = { path = "../carrick-spec" }
carrick-image = { path = "../carrick-image" }
carrick-runtime = { path = "../carrick-runtime" }
camino.workspace = true
thiserror.workspace = true
tokio.workspace = true
```

- [ ] **Step 2: Write the failing merge tests**

`crates/carrick-engine/src/resolve.rs`:
```rust
use camino::Utf8PathBuf;
use carrick_image::ResolvedImage;
use carrick_spec::{FsBackendKind, ImageConfig, Mount, NamespaceConfig, RunSpec};

#[derive(Debug, Clone, Default)]
pub struct CliRunRequest {
    pub image: String,
    pub args: Vec<String>,
    pub env_overrides: Vec<String>,
    pub entrypoint_override: Option<Vec<String>>,
    pub workdir: Option<Utf8PathBuf>,
    pub user: Option<String>,
    pub mounts: Vec<Mount>,
    pub name: Option<String>,
    pub tty: bool,
    pub interactive: bool,
    pub rm: bool,
    pub raw: bool,
    pub fs_backend: FsBackendKind,
    pub max_traps: usize,
    pub debug_state_path: Option<Utf8PathBuf>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EngineError {
    #[error("no command specified")]
    NoCommand,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img(config: ImageConfig) -> ResolvedImage {
        ResolvedImage { layers: vec![Utf8PathBuf::from("/blob/l1")], config }
    }
    fn req() -> CliRunRequest {
        CliRunRequest { image: "alpine:latest".into(), max_traps: 100_000, ..Default::default() }
    }

    #[test]
    fn args_replace_image_cmd_and_join_entrypoint() {
        let cfg = ImageConfig {
            entrypoint: Some(vec!["/ep".into()]),
            cmd: Some(vec!["default".into()]),
            ..Default::default()
        };
        let mut r = req();
        r.args = vec!["override".into()];
        let spec = resolve_run_spec(&r, &img(cfg)).unwrap();
        assert_eq!(spec.argv, vec!["/ep", "override"]);
        assert_eq!(spec.executable, "/ep");
    }

    #[test]
    fn falls_back_to_image_cmd_when_no_args() {
        let cfg = ImageConfig { cmd: Some(vec!["/bin/cmd".into()]), ..Default::default() };
        let spec = resolve_run_spec(&req(), &img(cfg)).unwrap();
        assert_eq!(spec.argv, vec!["/bin/cmd"]);
    }

    #[test]
    fn entrypoint_override_wins() {
        let cfg = ImageConfig {
            entrypoint: Some(vec!["/ep".into()]),
            cmd: Some(vec!["c".into()]),
            ..Default::default()
        };
        let mut r = req();
        r.entrypoint_override = Some(vec!["/new-ep".into()]);
        let spec = resolve_run_spec(&r, &img(cfg)).unwrap();
        assert_eq!(spec.argv, vec!["/new-ep", "c"]);
    }

    #[test]
    fn empty_command_is_error() {
        let err = resolve_run_spec(&req(), &img(ImageConfig::default())).unwrap_err();
        assert_eq!(err, EngineError::NoCommand);
    }

    #[test]
    fn env_image_then_baseline_then_overrides() {
        let cfg = ImageConfig {
            cmd: Some(vec!["/c".into()]),
            env: vec!["PATH=/img/bin".into(), "FOO=image".into()],
            ..Default::default()
        };
        let mut r = req();
        r.env_overrides = vec!["FOO=cli".into(), "EXTRA=1".into()];
        let spec = resolve_run_spec(&r, &img(cfg)).unwrap();
        // image PATH wins over baseline default:
        assert!(spec.envp.contains(&"PATH=/img/bin".to_string()));
        // baseline HOME added because image didn't set it:
        assert!(spec.envp.contains(&"HOME=/root".to_string()));
        // override replaces image value:
        assert!(spec.envp.contains(&"FOO=cli".to_string()));
        assert!(!spec.envp.contains(&"FOO=image".to_string()));
        // brand-new override appended:
        assert!(spec.envp.contains(&"EXTRA=1".to_string()));
    }

    #[test]
    fn workdir_and_user_precedence() {
        let cfg = ImageConfig {
            cmd: Some(vec!["/c".into()]),
            working_dir: Some(Utf8PathBuf::from("/img-wd")),
            user: Some("imguser".into()),
            ..Default::default()
        };
        let mut r = req();
        r.workdir = Some(Utf8PathBuf::from("/cli-wd"));
        let spec = resolve_run_spec(&r, &img(cfg.clone())).unwrap();
        assert_eq!(spec.cwd.as_deref().map(|p| p.as_str()), Some("/cli-wd"));
        assert_eq!(spec.user.as_deref(), Some("imguser")); // no -u override → image User
    }

    #[test]
    fn namespaces_are_all_host() {
        let cfg = ImageConfig { cmd: Some(vec!["/c".into()]), ..Default::default() };
        let spec = resolve_run_spec(&req(), &img(cfg)).unwrap();
        assert_eq!(spec.namespaces, NamespaceConfig::host());
    }
}
```

- [ ] **Step 3: Run the tests (expect failure)**

Run: `cargo test -p carrick-engine`
Expected: FAIL — `resolve_run_spec` not defined.

- [ ] **Step 4: Implement `resolve_run_spec` + `merge_env`**

Add to `crates/carrick-engine/src/resolve.rs` (above the test module):
```rust
/// Baseline env applied for keys the image config did not set. Mirrors the
/// values carrick injected pre-split, preserving apt/glibc behavior.
const BASELINE_ENV: &[(&str, &str)] = &[
    ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    ("HOME", "/root"),
    ("TERM", "xterm-256color"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("DEBIAN_FRONTEND", "noninteractive"),
    ("PAGER", "cat"),
];

fn env_key(entry: &str) -> &str {
    entry.split_once('=').map(|(k, _)| k).unwrap_or(entry)
}

/// image ENV, then baseline defaults for missing keys, then CLI overrides
/// (last-wins / replace-in-place).
fn merge_env(image_env: &[String], overrides: &[String]) -> Vec<String> {
    let mut out: Vec<String> = image_env.to_vec();
    let has = |out: &[String], k: &str| out.iter().any(|e| env_key(e) == k);
    for (k, v) in BASELINE_ENV {
        if !has(&out, k) {
            out.push(format!("{k}={v}"));
        }
    }
    for ov in overrides {
        let k = env_key(ov).to_string();
        match out.iter_mut().find(|e| env_key(e) == k) {
            Some(slot) => *slot = ov.clone(),
            None => out.push(ov.clone()),
        }
    }
    out
}

/// Lower a CLI run request + resolved image into a `RunSpec` using docker
/// `run` merge semantics. Pure: no I/O, no HVF.
pub fn resolve_run_spec(
    req: &CliRunRequest,
    image: &ResolvedImage,
) -> Result<RunSpec, EngineError> {
    let cfg = &image.config;

    let entrypoint = req
        .entrypoint_override
        .clone()
        .or_else(|| cfg.entrypoint.clone())
        .unwrap_or_default();
    let cmd = if !req.args.is_empty() {
        req.args.clone()
    } else {
        cfg.cmd.clone().unwrap_or_default()
    };
    let mut argv = entrypoint;
    argv.extend(cmd);
    if argv.is_empty() {
        return Err(EngineError::NoCommand);
    }
    let executable = argv[0].clone();

    let envp = merge_env(&cfg.env, &req.env_overrides);
    let cwd = req.workdir.clone().or_else(|| cfg.working_dir.clone());
    let user = req.user.clone().or_else(|| cfg.user.clone());

    Ok(RunSpec {
        executable,
        argv,
        envp,
        cwd,
        rootfs_layers: image.layers.clone(),
        fs_backend: req.fs_backend,
        mounts: req.mounts.clone(),
        tty: req.tty,
        raw: req.raw,
        interactive: req.interactive,
        max_traps: req.max_traps,
        debug_state_path: req.debug_state_path.clone(),
        namespaces: NamespaceConfig::host(),
        user,
    })
}
```

- [ ] **Step 5: Run the tests (expect pass)**

Run: `cargo test -p carrick-engine`
Expected: PASS (all 7 tests).

- [ ] **Step 6: Implement the `Engine::run` facade**

`crates/carrick-engine/src/engine.rs`:
```rust
use carrick_image::{ImageReference, ImageStore};
use carrick_runtime::runtime::{RunResult, RuntimeError};
use crate::resolve::{CliRunRequest, EngineError, resolve_run_spec};

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Image(#[from] carrick_image::OciBootstrapError),
    #[error(transparent)]
    Resolve(#[from] EngineError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
}

pub struct Engine {
    store: ImageStore,
}

impl Engine {
    pub fn new(store: ImageStore) -> Self {
        Self { store }
    }

    /// Resolve the image (the caller is responsible for pull-on-demand before
    /// this point, matching today's CLI flow), merge config, and execute.
    pub async fn resolve_spec(
        &self,
        req: &CliRunRequest,
        image_ref: &ImageReference,
    ) -> Result<carrick_spec::RunSpec, RunError> {
        let resolved = self.store.resolve(image_ref).await?;
        Ok(resolve_run_spec(req, &resolved)?)
    }

    /// Execute a previously-resolved spec on the runtime.
    pub fn execute(&self, spec: &carrick_spec::RunSpec) -> Result<RunResult, RunError> {
        Ok(carrick_runtime::execute::execute(spec)?)
    }
}
```

NOTE FOR IMPLEMENTER: keep image *pull-on-demand* in the CLI (Task 7) so the engine stays I/O-light and the pull progress messages stay where users expect them. `resolve_spec` assumes the image is already in the store. Adjust `carrick_runtime::runtime::{RunResult, RuntimeError}` paths to match the crate's actual `pub` surface.

`crates/carrick-engine/src/lib.rs`:
```rust
pub mod engine;
pub mod resolve;

pub use engine::{Engine, RunError};
pub use resolve::{CliRunRequest, EngineError, resolve_run_spec};
```

- [ ] **Step 7: Build**

Run: `cargo build -p carrick-engine`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(engine): docker run merge semantics + Engine facade"
```

---

## Task 7: Wire the CLI `run` command to the engine with docker flags

Replace the temporary inline `RunSpec` (Task 4 Step 6) with a real docker-compatible flag surface mapped into `CliRunRequest`.

**Files:**
- Modify: `crates/carrick-cli/Cargo.toml` (add engine/image/spec deps), `crates/carrick-cli/src/main.rs` (the `Run` command definition + arm)
- Create: `crates/carrick-cli/src/run_args.rs` (flag → request mapping + `-v`/`-e` parse helpers)

- [ ] **Step 1: Add deps to `crates/carrick-cli/Cargo.toml`**

```toml
carrick-engine = { path = "../carrick-engine" }
carrick-image = { path = "../carrick-image" }
carrick-spec = { path = "../carrick-spec" }
```

- [ ] **Step 2: Write failing tests for the `-v` and `--env-file` parse helpers**

`crates/carrick-cli/src/run_args.rs`:
```rust
use camino::Utf8PathBuf;
use carrick_spec::Mount;

/// Parse a docker `-v host:guest[:ro]` spec.
pub fn parse_volume(spec: &str) -> Result<Mount, String> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        [src, dst] => Ok(Mount {
            source: Utf8PathBuf::from(*src),
            target: Utf8PathBuf::from(*dst),
            readonly: false,
        }),
        [src, dst, mode] => Ok(Mount {
            source: Utf8PathBuf::from(*src),
            target: Utf8PathBuf::from(*dst),
            readonly: *mode == "ro",
        }),
        _ => Err(format!("invalid -v value: {spec}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_two_parts_rw() {
        let m = parse_volume("/h:/g").unwrap();
        assert_eq!(m.source.as_str(), "/h");
        assert_eq!(m.target.as_str(), "/g");
        assert!(!m.readonly);
    }
    #[test]
    fn volume_ro_mode() {
        let m = parse_volume("/h:/g:ro").unwrap();
        assert!(m.readonly);
    }
    #[test]
    fn volume_invalid() {
        assert!(parse_volume("/only-one").is_err());
    }
}
```

- [ ] **Step 3: Run helper tests (expect fail then pass)**

Run: `cargo test -p carrick-cli parse_volume` (after adding `mod run_args;` to `main.rs`)
Expected: FAIL → after the code above compiles, PASS.

- [ ] **Step 4: Extend the `Run` clap command with docker flags**

In `crates/carrick-cli/src/main.rs`, add to the `Run` variant (keep existing `max_traps`, `debug_state_path`, `raw`, `tty`, `fs`, `command`):
```rust
        /// Set environment variables (repeatable): -e KEY=VAL
        #[arg(short = 'e', long = "env", value_name = "KEY=VAL")]
        env: Vec<String>,
        /// Read environment variables from a file (KEY=VAL per line).
        #[arg(long = "env-file", value_name = "FILE")]
        env_file: Vec<PathBuf>,
        /// Working directory inside the container.
        #[arg(short = 'w', long = "workdir", value_name = "DIR")]
        workdir: Option<String>,
        /// Username or UID[:GID].
        #[arg(short = 'u', long = "user", value_name = "USER")]
        user: Option<String>,
        /// Override the image ENTRYPOINT.
        #[arg(long = "entrypoint", value_name = "CMD")]
        entrypoint: Option<String>,
        /// Bind-mount a host path: -v host:guest[:ro] (repeatable).
        #[arg(short = 'v', long = "volume", value_name = "SPEC")]
        volume: Vec<String>,
        /// Keep STDIN open (accepted; combine with -t for interactive).
        #[arg(short = 'i', long = "interactive")]
        interactive: bool,
        /// Assign a name to the container (recorded; no store yet).
        #[arg(long = "name", value_name = "NAME")]
        name: Option<String>,
        /// Remove on exit (accepted; no-op without a persistent store).
        #[arg(long = "rm")]
        rm: bool,
        /// Publish a port (parsed/recorded; no-op under host networking).
        #[arg(short = 'p', long = "publish", value_name = "SPEC")]
        publish: Vec<String>,
```

- [ ] **Step 5: Rewrite the `Commands::Run` arm to build `CliRunRequest` and drive the engine**

Replace the arm body with: parse the image ref; pull-on-demand exactly as today (`store.load_pull_summary` else `pull_image`); set the host process name from the resolved executable (compute after `resolve_spec`, or from the first arg); build `CliRunRequest`:
```rust
let mut env_overrides: Vec<String> = Vec::new();
for f in &env_file {
    let text = std::fs::read_to_string(f)
        .with_context(|| format!("reading --env-file {}", f.display()))?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        env_overrides.push(line.to_owned());
    }
}
env_overrides.extend(env);
// forward host diagnostic vars (preserves pre-split behavior)
for key in ["GODEBUG", "GOMAXPROCS", "GOTRACEBACK", "GOGC", "GODEBUGFLAGS"] {
    if let Ok(val) = std::env::var(key) {
        env_overrides.push(format!("{key}={val}"));
    }
}
let mut mounts = Vec::new();
for v in &volume {
    mounts.push(run_args::parse_volume(v).map_err(|e| anyhow::anyhow!(e))?);
}
let req = carrick_engine::CliRunRequest {
    image: image.canonical(),
    args: command.clone(),
    env_overrides,
    entrypoint_override: entrypoint.map(|e| vec![e]),
    workdir: workdir.map(camino::Utf8PathBuf::from),
    user,
    mounts,
    name,
    tty,
    interactive,
    rm,
    raw,
    fs_backend: match fs.unwrap_or_else(default_fs_backend_kind) {
        FsBackendKind::Host => carrick_spec::FsBackendKind::Host,
        FsBackendKind::Memory => carrick_spec::FsBackendKind::Memory,
    },
    max_traps,
    debug_state_path: debug_state_path.map(camino::Utf8PathBuf::from),
};
let engine = carrick_engine::Engine::new(store);
let spec = block_on_oci(engine.resolve_spec(&req, &image))?;
// host process name from resolved executable
{
    let base = spec.executable.rsplit('/').next().unwrap_or(&spec.executable);
    carrick_runtime::dispatch::set_host_process_name(base.as_bytes());
}
let result = engine.execute(&spec)?;
```
Then keep the existing tty/raw/json output + exit-code logic, operating on `result` (a `RunResult`). Note: the `Run` arm no longer defaults to `/bin/sh` — an empty command with no image CMD/ENTRYPOINT now errors via `EngineError::NoCommand`. The `Shell` normalization (which injects `/bin/sh`) is unchanged and still provides the interactive-shell default.

NOTE FOR IMPLEMENTER: `block_on_oci` is the existing tokio block-on helper in `main.rs`; reuse it for the async `resolve_spec`. `Engine::new` consumes `store`; if `store` is needed later in the arm, clone it (it is `Clone`).

- [ ] **Step 6: Build + helper tests**

Run: `cargo test -p carrick-cli && cargo build`
Expected: PASS.

- [ ] **Step 7: End-to-end docker-semantics smoke**

Run: `./scripts/build-signed.sh`
```bash
# image CMD honored (no command given):
./target/release/carrick run --raw alpine:latest
# entrypoint+args join + env override:
./target/release/carrick run --raw -e GREETING=hi alpine:latest /bin/sh -c 'echo $GREETING'
# workdir:
./target/release/carrick run --raw -w /tmp alpine:latest /bin/pwd
```
Expected: first prints the alpine default cmd output (`/bin/sh` is alpine's CMD, so it starts a shell reading EOF and exits 0); second prints `hi`; third prints `/tmp`.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(cli): docker-compatible run flags wired through carrick-engine"
```

---

## Task 8: Re-home remaining dev/diagnostic subcommands & finalize crate boundaries

The CLI still has `Pull`, `Exec`, `CompatReport`, `DispatchSyscall`, `Rootfs`, `Syscalls`, `TrapCapabilities`, `Debug`, `Trace`, `TraceChild`, `Volume`, `InspectElf`, `PlanElfLoad`, `LoadElf`, `RunElf`. These must compile against the new crate layout.

**Files:**
- Modify: `crates/carrick-cli/src/main.rs` (import fixes), possibly `crates/carrick-runtime/src/lib.rs` (visibility)

- [ ] **Step 1: Build and fix all remaining import errors**

Run: `cargo build`
Expected: errors listing `carrick_runtime::` / `carrick_image::` items that the dev subcommands reference. Fix each import. `Pull` uses `carrick_image::{ImageReference, ImageStore, pull_image}`. `RunElf` builds a dispatcher + calls `run_elf_from_dispatcher_debug` — keep using the runtime crate directly, or route through `carrick_runtime::execute::execute` with a hand-built `RunSpec` (prefer the latter for consistency, but direct use is acceptable for dev tooling).

- [ ] **Step 2: Verify the full CLI surface still parses**

Run: `./target/release/carrick --help` (after `cargo build`)
Expected: lists all subcommands without panics.

- [ ] **Step 3: Run the bin-level integration tests**

Run: `cargo test -p carrick-cli`
Expected: PASS (cli.rs, conformance.rs — conformance may require Docker; if Docker is unavailable in this environment it will skip/ignore as designed).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor(cli): re-home dev/diagnostic subcommands onto workspace crates"
```

---

## Task 9: Verify workspace lints (no-panic gate) across all crates

- [ ] **Step 1: Confirm each crate inherits `[lints] workspace = true`**

Run: `grep -L 'workspace = true' crates/*/Cargo.toml`
Expected: prints nothing under a `[lints]` context — every crate has the inheritance. (Manually confirm each crate manifest contains the `[lints]\nworkspace = true` block.)

- [ ] **Step 2: Run the no-panic gate**

Run: `cargo clippy --all-targets`
Expected: no NEW `unwrap_used`/`expect_used`/`panic`/`todo`/`unimplemented` errors. If a moved file trips the gate because an audited `#[allow(...)]` lost context, restore the targeted allow with its `// INVARIANT:` comment.

- [ ] **Step 3: Confirm `clippy.toml` still exempts test code**

Run: `cat clippy.toml`
Expected: unchanged from before the split; lives at the workspace root and applies workspace-wide.

- [ ] **Step 4: Commit (only if any allows/lints were adjusted)**

```bash
git add -A
git commit -m "chore(workspace): restore no-panic gate allows after crate split"
```

---

## Task 10: Final acceptance — full suite, codesign, Docker differential demos

- [ ] **Step 1: Full workspace test + build**

Run: `cargo test --workspace && cargo build --release`
Expected: PASS, same test count as the pre-split baseline (plus the new spec/image/engine/cli unit tests).

- [ ] **Step 2: Codesign and verify HVF**

Run: `./scripts/build-signed.sh`
Expected: `built + signed: target/release/carrick`.

- [ ] **Step 3: North-star demos (behavior-preserving check)**

```bash
./target/release/carrick run --raw python:3.12-slim /usr/local/bin/python3 --version
```
Expected: prints `Python 3.12.x` (proves image-config + run path + HVF end-to-end).

If Docker is available, cross-check one demo against the oracle (see memory `reference_docker_cross_check`):
```bash
docker run --rm python:3.12-slim python3 --version
```
Expected: same version string.

- [ ] **Step 4: Update scripts/docs referencing the old layout**

Run: `grep -rn 'src/main.rs\|src/oci.rs\|carrick::' scripts docs README.md 2>/dev/null | grep -v superpowers/specs | grep -v superpowers/plans`
Expected: review each hit. `build-signed.sh` should be unchanged (still `target/release/carrick`). Update any stale path references in README "Development" section to mention the workspace (`cargo test --workspace`).

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "docs(workspace): note workspace layout; final acceptance for docker run frontend"
```

---

## Verification Summary

When all tasks are complete:
- `cargo test --workspace` is green (lib + spec/image/engine/cli unit tests + integration tests).
- `cargo clippy --all-targets` shows no new panic-gate violations.
- `./scripts/build-signed.sh` produces a signed `target/release/carrick`.
- `carrick run` honors image ENTRYPOINT/CMD/ENV/WORKDIR/USER, accepts `-e/--env-file/-w/-u/--entrypoint/-v/-i/--name/--rm/-p`, and bind-mounts `-v` host paths (for `--fs host`).
- The five-crate DAG holds: `cli → engine → {image, runtime} → spec`, with `runtime`/`image` not depending on each other or on `engine`.
- Binary name unchanged (`carrick`); HVF/codesigning intact.

## Out of scope (do not implement here)
- Lifecycle commands (`ps`/`stop`/`rm`/`logs`/`create`/`start`/`-d`), persistent container store/daemon.
- Real namespace isolation (the `NamespaceConfig` seam exists for it).
- Port publishing as a real feature.
