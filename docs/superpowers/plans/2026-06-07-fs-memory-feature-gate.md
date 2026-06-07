# `fs-memory` Feature Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the in-memory filesystem backend (`--fs memory` / `FsBackendKind::Memory`) behind a default-off `fs-memory` Cargo feature, so a stock build only ever runs on the host-APFS backend.

**Architecture:** A Cargo feature `fs-memory` (default OFF) declared in `carrick-spec` and propagated to `carrick-runtime`, `carrick-engine`, `carrick-cli`. The `FsBackendKind::Memory` enum variant is `#[cfg(feature = "fs-memory")]`, so when off it does not exist: `clap` rejects `--fs memory` natively and the compiler forces every selection site to be feature-gated. Default/fallback resolution becomes "host, then error" (host everywhere; hard-error instead of the silent memory fallback). The internal `MemoryBackend` struct stays compiled unconditionally as the VFS's transient init overlay.

**Tech Stack:** Rust, Cargo features, `clap` (ValueEnum), `anyhow`, `tracing`, `assert_cmd` (integration tests).

**Spec:** `docs/superpowers/specs/2026-06-07-fs-memory-feature-gate-design.md`

---

## File Structure

Files modified (no new source files; one new test file):

- `crates/carrick-spec/Cargo.toml` — declare `fs-memory` feature.
- `crates/carrick-runtime/Cargo.toml` — `fs-memory = ["carrick-spec/fs-memory"]`.
- `crates/carrick-engine/Cargo.toml` — add `[features]` + `fs-memory` propagation.
- `crates/carrick-cli/Cargo.toml` — `fs-memory` propagation (NOT in `default`).
- `crates/carrick-spec/src/lib.rs` — `#[cfg]` the `FsBackendKind::Memory` variant.
- `crates/carrick-runtime/src/apfs.rs` — new shared `default_writable_backend_kind()` helper (cfg-split).
- `crates/carrick-runtime/src/execute.rs` — gate the execute Memory arm + `install_fs_backend` Memory arm; add `host_failure_fallback`; gate import.
- `crates/carrick-engine/src/lib.rs` — route default through the shared helper; fix 6 unit tests.
- `crates/carrick-cli/src/fs_setup.rs` — gate install Memory arm; add `host_failure_fallback`; delete the duplicate `default_fs_backend_kind`; gate import; update module doc.
- `crates/carrick-cli/src/lifecycle.rs` — gate the "start requires --fs host" guard.
- `crates/carrick-cli/src/args.rs` — update the three `--fs` doc comments.
- `crates/carrick-cli/tests/fs_backend_flag.rs` — NEW: CLI-rejection + feature-on parity tests.
- `crates/carrick-cli/tests/perf_runner.rs` — filter the memory perf case when feature off.

---

## Task 1: Declare the `fs-memory` feature across the workspace (default OFF)

This task only edits `Cargo.toml`s. The feature is unused by code yet, so the workspace must still build both with and without it.

**Files:**
- Modify: `crates/carrick-spec/Cargo.toml`
- Modify: `crates/carrick-runtime/Cargo.toml`
- Modify: `crates/carrick-engine/Cargo.toml`
- Modify: `crates/carrick-cli/Cargo.toml`

- [ ] **Step 1: Add the feature to carrick-spec**

In `crates/carrick-spec/Cargo.toml`, change the `[features]` block from:

```toml
[features]
default = []
clap = ["dep:clap"]
```

to:

```toml
[features]
default = []
clap = ["dep:clap"]
# In-memory filesystem backend selection (`--fs memory` / FsBackendKind::Memory).
# Default OFF: a stock build runs only on the host-APFS backend, which is the
# only fork-coherent option (see docs/superpowers/specs/2026-06-07-fs-memory-feature-gate-design.md).
fs-memory = []
```

- [ ] **Step 2: Add + propagate the feature in carrick-runtime**

In `crates/carrick-runtime/Cargo.toml`, the `[features]` block currently contains only `syscall-shim = []`. Add the `fs-memory` line so it enables the spec feature:

```toml
[features]
# Guest-side syscall shim (docs/syscall-shim-design.md). NO default here on
# purpose: the binary (carrick-cli) is the single control point. carrick-cli's
# default enables it for normal builds; dependents that use carrick-runtime as a
# library do not re-enable it through feature unification.
syscall-shim = []
# In-memory fs backend selection (default OFF; control point is carrick-cli).
fs-memory = ["carrick-spec/fs-memory"]
```

- [ ] **Step 3: Add a `[features]` section to carrick-engine**

`crates/carrick-engine/Cargo.toml` has no `[features]` section. Add one immediately before its `[dependencies]` line (line 14):

```toml
[features]
# In-memory fs backend selection (default OFF; control point is carrick-cli).
fs-memory = ["carrick-spec/fs-memory", "carrick-runtime/fs-memory"]

```

- [ ] **Step 4: Propagate the feature in carrick-cli (NOT default)**

In `crates/carrick-cli/Cargo.toml`, the `[features]` block currently is:

```toml
default = ["syscall-shim"]
syscall-shim = ["carrick-runtime/syscall-shim"]
```

Add the `fs-memory` line **without** adding it to `default`:

```toml
default = ["syscall-shim"]
syscall-shim = ["carrick-runtime/syscall-shim"]
# In-memory fs backend selection (`--fs memory`). Default OFF on purpose; opt in
# with `cargo build -p carrick-cli --features fs-memory`.
fs-memory = ["carrick-spec/fs-memory", "carrick-engine/fs-memory", "carrick-runtime/fs-memory"]
```

- [ ] **Step 5: Verify the workspace still builds both ways**

Run: `cargo build --workspace`
Expected: builds clean (feature off; code unchanged).

Run: `cargo build -p carrick-cli --features fs-memory`
Expected: builds clean (feature on; code still references `Memory` unconditionally, which is fine because the variant is not gated yet).

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-spec/Cargo.toml crates/carrick-runtime/Cargo.toml crates/carrick-engine/Cargo.toml crates/carrick-cli/Cargo.toml
git commit -m "build(fs): declare default-off fs-memory feature across the workspace"
```

---

## Task 2: Centralize the default-backend choice in a cfg-split helper

Today the case-sensitivity probe that picks the default backend is **duplicated** in `carrick-engine::resolve_run_spec` and `carrick-cli::fs_setup::default_fs_backend_kind`. Replace both with one shared helper in `carrick-runtime::apfs` whose feature-off branch always returns `Host`. This is the single place the "default" cfg lives.

**Files:**
- Modify: `crates/carrick-runtime/src/apfs.rs`
- Modify: `crates/carrick-engine/src/lib.rs:225-237`
- Modify: `crates/carrick-cli/src/fs_setup.rs:74` and delete `default_fs_backend_kind` (`:205-233`)

- [ ] **Step 1: Add a unit test for the helper (feature OFF returns Host)**

Append to `crates/carrick-runtime/src/apfs.rs` (inside its existing `#[cfg(test)] mod tests`, or add one if absent):

```rust
#[cfg(test)]
mod fs_default_tests {
    use super::*;

    #[test]
    fn default_backend_is_host_without_feature() {
        // With the fs-memory feature off (the default build), the default
        // writable backend is always Host regardless of volume case-sensitivity.
        if cfg!(not(feature = "fs-memory")) {
            assert_eq!(
                default_writable_backend_kind(),
                carrick_spec::FsBackendKind::Host
            );
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails to compile (helper missing)**

Run: `cargo test -p carrick-runtime --lib apfs::fs_default_tests 2>&1 | head -20`
Expected: FAIL — `cannot find function default_writable_backend_kind`.

- [ ] **Step 3: Implement the shared helper**

Add to `crates/carrick-runtime/src/apfs.rs` (near `preferred_scratch_root`/`probe_case_sensitive`):

```rust
/// The default writable-layer backend when the user passes no `--fs`.
///
/// With the `fs-memory` feature enabled, prefer `Host` on case-sensitive
/// volumes (where Linux fs semantics survive) and fall back to the in-memory
/// backend on case-insensitive ones. Without the feature, always `Host` — the
/// in-memory backend is not selectable and is silently incoherent across guest
/// `fork` anyway (see the fs-memory design spec).
pub fn default_writable_backend_kind() -> carrick_spec::FsBackendKind {
    #[cfg(not(feature = "fs-memory"))]
    {
        carrick_spec::FsBackendKind::Host
    }
    #[cfg(feature = "fs-memory")]
    {
        let probe = preferred_scratch_root()
            .unwrap_or_else(|_| std::env::temp_dir().join("carrick-scratch"));
        if std::fs::create_dir_all(&probe).is_err() {
            return carrick_spec::FsBackendKind::Memory;
        }
        if probe_case_sensitive(&probe) {
            carrick_spec::FsBackendKind::Host
        } else {
            tracing::warn!(
                "carrick: {} is case-insensitive; defaulting --fs to memory. \
                 Pass `--fs host` to force the cap-std backend (some Linux tools may misbehave).",
                probe.display()
            );
            carrick_spec::FsBackendKind::Memory
        }
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p carrick-runtime --lib apfs::fs_default_tests`
Expected: PASS.

- [ ] **Step 5: Route carrick-engine through the helper**

In `crates/carrick-engine/src/lib.rs`, replace the duplicated probe (lines 225-237):

```rust
    // 5. Select fs backend (fall back to case sensitivity probe)
    let fs_backend = req.fs.unwrap_or_else(|| {
        let probe = carrick_runtime::apfs::preferred_scratch_root()
            .unwrap_or_else(|_| std::env::temp_dir().join("carrick-scratch"));
        if std::fs::create_dir_all(&probe).is_err() {
            FsBackendKind::Memory
        } else if carrick_runtime::apfs::probe_case_sensitive(&probe) {
            FsBackendKind::Host
        } else {
            FsBackendKind::Memory
        }
    });
```

with:

```rust
    // 5. Select fs backend: caller's `--fs`, else the shared default
    //    (host-only unless the fs-memory feature is compiled in).
    let fs_backend = req
        .fs
        .unwrap_or_else(carrick_runtime::apfs::default_writable_backend_kind);
```

- [ ] **Step 6: Route carrick-cli through the helper and delete the duplicate**

In `crates/carrick-cli/src/fs_setup.rs`, line 74, change:

```rust
    let kind = fs.unwrap_or_else(default_fs_backend_kind);
```

to:

```rust
    let kind = fs.unwrap_or_else(carrick_runtime::apfs::default_writable_backend_kind);
```

Then **delete** the now-unused `default_fs_backend_kind` function (the whole `fn default_fs_backend_kind() -> FsBackendKind { ... }` block, currently lines ~205-233, including its doc comment).

- [ ] **Step 7: Verify build + existing tests (feature off)**

Run: `cargo build --workspace 2>&1 | tail -5`
Expected: clean (the engine/cli now compile against `Host` default; `FsBackendKind::Memory` is still a valid variant so nothing else breaks yet).

Run: `cargo build -p carrick-cli --features fs-memory 2>&1 | tail -5`
Expected: clean (helper's memory branch compiles).

- [ ] **Step 8: Commit**

```bash
git add crates/carrick-runtime/src/apfs.rs crates/carrick-engine/src/lib.rs crates/carrick-cli/src/fs_setup.rs
git commit -m "refactor(fs): centralize default-backend choice in apfs::default_writable_backend_kind"
```

---

## Task 3: Red test — `--fs memory` must be rejected on a default build

Write the failing acceptance test first. It runs `carrick run --help` (no guest boot) and asserts the `--fs` arg no longer offers `memory` as a possible value. Currently `memory` is offered, so this fails — the proof that gating is needed.

**Files:**
- Create: `crates/carrick-cli/tests/fs_backend_flag.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/carrick-cli/tests/fs_backend_flag.rs`:

```rust
//! `--fs memory` is gated behind the default-off `fs-memory` Cargo feature.
//! On a stock build, `host` is the only accepted `--fs` value.
#![allow(clippy::unwrap_used, clippy::panic)]

use assert_cmd::Command;

/// `carrick run --help` lists the `--fs` possible values. Without the
/// `fs-memory` feature, `memory` must not appear among them. Uses `--help`
/// (no guest boot) so it is fast and deterministic in both the red and green
/// phases.
#[cfg(not(feature = "fs-memory"))]
#[test]
fn run_help_does_not_offer_fs_memory() {
    let out = Command::cargo_bin("carrick")
        .unwrap()
        .args(["run", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("possible values: memory"),
        "--fs must not offer 'memory' when fs-memory is off; help was:\n{stdout}"
    );
}
```

> NOTE: the `--fs memory` *invocation* test (asserting a clap exit-2 usage
> error) is deliberately added later, in Task 4 Step 5 — after gating, clap
> rejects the value before any guest work, so it runs instantly. Adding it here
> (red phase) would actually boot/pull a guest because the value is still
> accepted, which is slow and flaky. The `--help` test above is the red-first
> acceptance check.

- [ ] **Step 2: Run the test to verify it FAILS**

Run: `cargo test -p carrick-cli --test fs_backend_flag 2>&1 | tail -25`
Expected: `run_help_does_not_offer_fs_memory` FAILS — `memory` is currently a valid `--fs` value, so the help contains `possible values: memory, host`.

- [ ] **Step 3: Commit the red test**

```bash
git add crates/carrick-cli/tests/fs_backend_flag.rs
git commit -m "test(fs): red — assert --fs memory is rejected without the feature"
```

---

## Task 4: Gate the `Memory` variant and every selection site

This is the atomic core: gating the variant removes it from the type when the feature is off, so all references must be gated simultaneously or the crate will not compile. After this task, the Task 3 tests go green and the default build accepts only `--fs host`.

**Files:**
- Modify: `crates/carrick-spec/src/lib.rs:220-225`
- Modify: `crates/carrick-cli/src/fs_setup.rs` (import `:54`, install body `:75-118`)
- Modify: `crates/carrick-runtime/src/execute.rs` (import `:5`, execute arm `:331`, install body `:430-446`)
- Modify: `crates/carrick-cli/src/lifecycle.rs:374-376`

- [ ] **Step 1: Gate the enum variant**

In `crates/carrick-spec/src/lib.rs`, change:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum FsBackendKind {
    Memory,
    Host,
}
```

to:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum FsBackendKind {
    /// In-memory writable overlay. Gated behind the default-off `fs-memory`
    /// feature: silently incoherent across guest `fork` (separate host
    /// processes get private copy-on-write copies), so it is opt-in only.
    #[cfg(feature = "fs-memory")]
    Memory,
    /// Host-APFS passthrough via cap-std: the kernel is the single fork-coherent
    /// source of truth. The only backend in a default build.
    Host,
}
```

- [ ] **Step 2: Gate the carrick-cli `fs_setup` import + install body**

In `crates/carrick-cli/src/fs_setup.rs`, line 54, split the import so `MemoryBackend` is only imported when the feature is on (else it is an unused-import error under `-D warnings`):

```rust
use carrick_runtime::fs_backend::{FsBackend, HostFsBackend, MemoryBackend};
```

becomes:

```rust
use carrick_runtime::fs_backend::{FsBackend, HostFsBackend};
#[cfg(feature = "fs-memory")]
use carrick_runtime::fs_backend::MemoryBackend;
```

Add a `host_failure_fallback` helper just above `install_fs_backend` (after the imports):

```rust
/// On a `--fs host` failure, fall back to the in-memory backend when the
/// `fs-memory` feature is compiled in, or hard-error with an actionable message
/// when it isn't (the "host, then error" rule).
#[cfg(feature = "fs-memory")]
fn host_failure_fallback(reason: &str) -> Result<(Box<dyn FsBackend>, FsBackendKind)> {
    tracing::warn!("carrick: {reason}; falling back to in-memory backend");
    Ok((Box::new(MemoryBackend::new()), FsBackendKind::Memory))
}

#[cfg(not(feature = "fs-memory"))]
fn host_failure_fallback(reason: &str) -> Result<(Box<dyn FsBackend>, FsBackendKind)> {
    anyhow::bail!(
        "carrick: {reason}; the in-memory fallback is not compiled in. \
         Rebuild with `--features fs-memory`, or run on a writable case-sensitive scratch volume."
    )
}
```

Now rewrite the `match kind { ... }` inside `install_fs_backend`. Replace the existing block (the `let mut backend: Box<dyn FsBackend> = match kind { FsBackendKind::Memory => ...; FsBackendKind::Host => match HostFsBackend::new() { Ok(...) => { ... seed-fail returns Ok(Memory) ... }, Err(err) => { warn; Box::new(MemoryBackend::new()) } } };`) with:

```rust
    let mut backend: Box<dyn FsBackend> = match kind {
        #[cfg(feature = "fs-memory")]
        FsBackendKind::Memory => Box::new(MemoryBackend::new()),
        FsBackendKind::Host => match HostFsBackend::new() {
            Ok(mut host) => {
                // SEED THE BACKEND WITH THE FULL ROOTFS. ("rootfs as APFS, throw
                // away when done": materialise every rootfs file/dir/symlink onto
                // the cap-std scratch dir so all fs syscalls flow through real
                // host syscalls against a real filesystem.)
                if let Some(rootfs) = dispatcher.rootfs() {
                    if let Err(err) = host.seed_from_rootfs(rootfs) {
                        let (mut mem, kind) = host_failure_fallback(&format!(
                            "--fs host seed-from-rootfs failed ({err})"
                        ))?;
                        seed_guest_baseline(&mut *mem);
                        let _ = dispatcher.set_fs_backend(mem);
                        return Ok(kind);
                    }
                    host_seeded = true;
                }
                Box::new(host)
            }
            Err(err) => host_failure_fallback(&format!("--fs host failed ({err})"))?.0,
        },
    };
```

(Everything after this `match` — `seed_guest_baseline`, `set_fs_backend`, the `if host_seeded` drop, `Ok(kind)` — is unchanged.)

- [ ] **Step 3: Gate the carrick-runtime `execute` import, execute arm, and install body**

In `crates/carrick-runtime/src/execute.rs`, line 5, split the import:

```rust
use crate::fs_backend::{FsBackend, HostFsBackend, MemoryBackend};
```

becomes:

```rust
use crate::fs_backend::{FsBackend, HostFsBackend};
#[cfg(feature = "fs-memory")]
use crate::fs_backend::MemoryBackend;
```

Gate the execute match's Memory arm. At `execute.rs:331`, the arm `FsBackendKind::Memory => {` (inside `match spec.fs_backend` at line 206) gets a `#[cfg]` attribute immediately above it:

```rust
            #[cfg(feature = "fs-memory")]
            FsBackendKind::Memory => {
                // ... unchanged arm body ...
            }
```

Add a `host_failure_fallback` helper just above `fn install_fs_backend` (this crate's install uses `eprintln!`, no `tracing`, and returns only a `Box`):

```rust
#[cfg(feature = "fs-memory")]
fn host_failure_fallback(reason: &str) -> anyhow::Result<Box<dyn FsBackend>> {
    eprintln!("carrick: {reason}; falling back to in-memory backend");
    Ok(Box::new(MemoryBackend::new()))
}

#[cfg(not(feature = "fs-memory"))]
fn host_failure_fallback(reason: &str) -> anyhow::Result<Box<dyn FsBackend>> {
    anyhow::bail!(
        "carrick: {reason}; the in-memory fallback is not compiled in. \
         Rebuild with `--features fs-memory`, or run on a writable case-sensitive scratch volume."
    )
}
```

Rewrite the `match kind` inside this `install_fs_backend` (lines ~430-446):

```rust
    let mut backend: Box<dyn FsBackend> = match kind {
        #[cfg(feature = "fs-memory")]
        FsBackendKind::Memory => Box::new(MemoryBackend::new()),
        FsBackendKind::Host => match HostFsBackend::new() {
            Ok(mut host) => {
                if let Some(rootfs) = dispatcher.rootfs() {
                    host.seed_from_rootfs(rootfs)?;
                    host_seeded = true;
                }
                Box::new(host)
            }
            Err(err) => host_failure_fallback(&format!("--fs host failed ({err})"))?,
        },
    };
```

- [ ] **Step 4: Gate the lifecycle guard**

In `crates/carrick-cli/src/lifecycle.rs`, the guard at lines 374-376 names the `Memory` variant, which won't compile when off. Gate the whole `if`:

```rust
    if matches!(state.config.fs, Some(carrick_spec::FsBackendKind::Memory)) {
        bail!("start requires a container created with --fs host");
    }
```

becomes:

```rust
    // A memory-backed container is not joinable/startable. When the fs-memory
    // feature is off, the variant cannot exist, so the guard is vacuous and is
    // compiled out.
    #[cfg(feature = "fs-memory")]
    if matches!(state.config.fs, Some(carrick_spec::FsBackendKind::Memory)) {
        bail!("start requires a container created with --fs host");
    }
```

- [ ] **Step 5: Build feature-off, add the now-fast invocation test, and run (GREEN)**

Run: `cargo build --workspace 2>&1 | tail -8`
Expected: clean. No reference to `FsBackendKind::Memory` survives in default-feature code.

Now that gating is in place, `--fs memory` is rejected by clap before any guest work, so the invocation test runs instantly. Append it to `crates/carrick-cli/tests/fs_backend_flag.rs`:

```rust
/// On a default build, passing `--fs memory` is a clap usage error (exit 2),
/// rejected before any guest boot. Fast because clap fails at parse time.
#[cfg(not(feature = "fs-memory"))]
#[test]
fn run_with_fs_memory_is_a_usage_error() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["run", "--fs", "memory", "ubuntu:24.04", "/bin/true"])
        .assert()
        .failure()
        .code(2);
}
```

Run: `cargo test -p carrick-cli --test fs_backend_flag 2>&1 | tail -15`
Expected: PASS — `run_help_does_not_offer_fs_memory` and `run_with_fs_memory_is_a_usage_error`.

- [ ] **Step 6: Build feature-on to confirm the opt-in path still compiles**

Run: `cargo build -p carrick-cli --features fs-memory 2>&1 | tail -8`
Expected: clean — every gated arm/import re-appears and compiles.

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-spec/src/lib.rs crates/carrick-cli/src/fs_setup.rs crates/carrick-runtime/src/execute.rs crates/carrick-cli/src/lifecycle.rs
git commit -m "feat(fs): gate FsBackendKind::Memory behind the fs-memory feature (host, then error)"
```

---

## Task 5: Fix existing tests that name `FsBackendKind::Memory`

Two test sites reference the variant directly and must compile with the feature off. The engine unit tests use `fs: Some(Memory)` only as incidental input (none assert on `.fs`), so switch them to `Host` for determinism. The one perf case that runs `--fs memory` gets filtered out when the feature is off.

**Files:**
- Modify: `crates/carrick-engine/src/lib.rs` (lines 357, 445, 478, 510, 542, 583)
- Modify: `crates/carrick-cli/tests/perf_runner.rs`

- [ ] **Step 1: Switch the engine test inputs to `Host`**

In `crates/carrick-engine/src/lib.rs`, every occurrence of:

```rust
            fs: Some(FsBackendKind::Memory),
```

(6 of them, in the `#[cfg(test)] mod tests` request literals) becomes:

```rust
            fs: Some(FsBackendKind::Host),
```

Use a single replace-all; none of these tests assert on the resolved `fs_backend`, so this is behavior-neutral and removes the dependency on the gated variant.

- [ ] **Step 2: Verify the engine tests compile + pass (feature off)**

Run: `cargo test -p carrick-engine --lib 2>&1 | tail -12`
Expected: PASS (all engine unit tests green; no reference to `FsBackendKind::Memory`).

- [ ] **Step 3: Filter the memory perf case when the feature is off**

In `crates/carrick-cli/tests/perf_runner.rs`, the harness iterates `CASES` (imported from `perf_support::cases`). One case sets `carrick_fs_mode: "memory"` (`cases.rs:266`), which would run `carrick run-elf --fs memory` and fail on a default build. At every point `perf_runner.rs` selects cases to run, skip the memory case unless the feature is on. Add this helper near the top of `perf_runner.rs`:

```rust
/// The in-memory fs backend is opt-in (`--features fs-memory`); skip perf cases
/// that require it on a default build so the harness never invokes `--fs memory`.
fn case_runnable(case: &perf_support::cases::PerfCase) -> bool {
    cfg!(feature = "fs-memory") || case.carrick_fs_mode != "memory"
}
```

and guard the per-case execution with it (wherever the runner loops over `CASES` and dispatches a carrick run), e.g.:

```rust
    for case in CASES {
        if !case_runnable(case) {
            continue;
        }
        // ... existing per-case body ...
    }
```

- [ ] **Step 4: Verify perf harness compiles (feature off)**

Run: `cargo test -p carrick-cli --test perf_runner --no-run 2>&1 | tail -6`
Expected: compiles clean (perf tests are typically `#[ignore]`; we only need compilation here).

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-engine/src/lib.rs crates/carrick-cli/tests/perf_runner.rs
git commit -m "test(fs): drop default-build test reliance on FsBackendKind::Memory"
```

---

## Task 6: Feature-on parity smoke test + documentation

Add a smoke test that proves the opt-in path still exposes `--fs memory`, and update the docs/help text that still advertises memory as a default.

**Files:**
- Modify: `crates/carrick-cli/tests/fs_backend_flag.rs`
- Modify: `crates/carrick-cli/src/args.rs` (lines ~81-85, ~251-254, ~320-321)
- Modify: `crates/carrick-cli/src/fs_setup.rs` (module doc, if it mentions memory default)

- [ ] **Step 1: Add a feature-on parity test**

Append to `crates/carrick-cli/tests/fs_backend_flag.rs`:

```rust
/// With the feature on, `--fs memory` is offered again (parity with pre-gate
/// behavior). This test only compiles/runs under `--features fs-memory`.
#[cfg(feature = "fs-memory")]
#[test]
fn run_help_offers_fs_memory_with_feature() {
    let out = assert_cmd::Command::cargo_bin("carrick")
        .unwrap()
        .args(["run", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("possible values:") && stdout.contains("memory"),
        "--fs should offer 'memory' when fs-memory is on; help was:\n{stdout}"
    );
}
```

- [ ] **Step 2: Verify it passes under the feature**

Run: `cargo test -p carrick-cli --features fs-memory --test fs_backend_flag 2>&1 | tail -15`
Expected: PASS — all three tests (the two `#[cfg(not)]` ones are compiled out; the parity one runs).

- [ ] **Step 3: Update the three `--fs` doc comments in args.rs**

`RunElf` (lines ~81-83):

```rust
        /// Which writable-layer backend to use. Defaults to `host` on
        /// case-sensitive volumes (APFS scratch dir + cap-std sandbox)
        /// and `memory` elsewhere (in-memory tmpfs).
```

becomes:

```rust
        /// Which writable-layer backend to use. Defaults to `host`. The
        /// in-memory backend (`memory`) is opt-in: build with
        /// `--features fs-memory`. It is incoherent across guest `fork`.
```

`Run` (lines ~251-252):

```rust
        /// Which writable-layer backend to use. Defaults to `host` on
        /// case-sensitive volumes and `memory` elsewhere.
```

becomes:

```rust
        /// Which writable-layer backend to use. Defaults to `host`. The
        /// in-memory backend (`memory`) is opt-in (`--features fs-memory`).
```

`Create` (line ~320) has no doc comment; add one above its `#[arg(long, value_enum)]`:

```rust
        /// Which writable-layer backend to use. Defaults to `host`. The
        /// in-memory backend (`memory`) is opt-in (`--features fs-memory`).
        #[arg(long, value_enum)]
        fs: Option<FsBackendKind>,
```

- [ ] **Step 4: Update the fs_setup module doc + any prose mentioning a memory default**

Run: `grep -rn "memory" crates/carrick-cli/src/fs_setup.rs | grep -iE "default|elsewhere|case-insensitive"`
For any comment that says the default is memory on case-insensitive volumes, update it to state the default is `host` and that memory is opt-in behind `fs-memory`. (The `install_fs_backend` doc comment at the top of the function and the module-level `//!` block are the likely spots.)

Also scan user-facing docs:

Run: `grep -rln "fs memory\|--fs memory\|FsBackendKind::Memory" docs/ README.md 2>/dev/null`
For each hit that presents `--fs memory` as a generally-available option, add a note that it now requires `--features fs-memory`. (Do not rewrite the design/plan specs themselves.)

- [ ] **Step 5: Verify formatting, lint, and the full default test suite**

Run: `cargo fmt --check`
Expected: clean (exit 0).

Run: `cargo clippy --workspace --all-targets 2>&1 | grep -E "warning|error" | head`
Expected: no output (no warnings/errors; CI denies warnings).

Run: `cargo test --workspace 2>&1 | tail -20`
Expected: green, with **no** test exercising the in-memory backend (default features).

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-cli/tests/fs_backend_flag.rs crates/carrick-cli/src/args.rs crates/carrick-cli/src/fs_setup.rs docs/ README.md
git commit -m "docs(fs): document --fs memory as opt-in; add feature-on parity smoke test"
```

---

## Final Verification

- [ ] **Default build is host-only and green**

Run: `cargo build --workspace && cargo test --workspace 2>&1 | tail -20`
Expected: builds + tests green; `fs_backend_flag` proves `--fs memory` is rejected; no memory test runs.

- [ ] **Opt-in build restores memory with parity**

Run: `cargo build -p carrick-cli --features fs-memory && cargo test -p carrick-cli --features fs-memory --test fs_backend_flag 2>&1 | tail -10`
Expected: builds; the parity test passes; `--fs memory` is offered again.

- [ ] **Lint + format clean**

Run: `cargo clippy --workspace --all-targets && cargo fmt --check`
Expected: no warnings; formatting clean.

- [ ] **Acceptance criteria (from the spec) all met**

1. Default `cargo test --workspace` green with `fs-memory` off; no test touches the in-memory backend. ✅ (Task 5, Final)
2. `carrick run --fs memory …` fails at parse with `host` the only value. ✅ (Task 3/4)
3. Default resolution is always `Host`; `--fs host` scratch/seed failure is a hard error naming `--features fs-memory`. ✅ (Task 2/4)
4. `--features fs-memory` restores `--fs memory` with today's behavior, proven by a smoke test. ✅ (Task 6)
5. No change to host-backend behavior or syscall emulation; `MemoryBackend` still compiles unconditionally as the VFS init overlay. ✅ (untouched)

---

## Self-Review notes (resolved)

- **Spec coverage:** §4 host-then-error → Tasks 2+4; §5 feature + variant gating → Tasks 1+4; §5.3 dedup probe → Task 2; §6 tests → Tasks 3+5+6; §7 acceptance → Final. No gaps.
- **Type consistency:** the helper is `carrick_runtime::apfs::default_writable_backend_kind() -> carrick_spec::FsBackendKind` everywhere; `host_failure_fallback` returns `(Box<dyn FsBackend>, FsBackendKind)` in `fs_setup` (needs the kind for the early return) and `Box<dyn FsBackend>` in `execute` (does not). Intentional, documented at each definition.
- **Imports:** `MemoryBackend` import is `#[cfg(feature = "fs-memory")]`-gated in both `fs_setup.rs` and `execute.rs` to avoid an unused-import error under `-D warnings`.
