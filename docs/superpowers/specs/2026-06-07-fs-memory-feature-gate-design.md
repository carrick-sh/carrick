# Gate `--fs memory` behind a default-off `fs-memory` Cargo feature

**Status:** design approved (2026-06-07); not yet executed.

**Date:** 2026-06-07.

**Scope:** make the in-memory filesystem backend (`--fs memory` /
`FsBackendKind::Memory`) opt-in at compile time. A stock `cargo build` produces
a binary where `--fs memory` does not exist and the host-APFS backend is the
only selectable writable layer. The in-memory code is still *compiled* (it
remains the VFS's transient init overlay — see §3) but is never *selectable* as
a container's live filesystem without the feature.

This does **not** touch the internal `MemoryBackend` struct's role as the
writable-overlay primitive, the host backend, or any syscall emulation.

---

## 1. Motivation: the in-memory backend is silently incoherent across `fork`

carrick runs each guest *process* as a real host process: guest
`fork`/`clone(CLONE_NEWPID)` is implemented by `libc::fork()`-ing the host
runtime (`crates/carrick-runtime/src/dispatch/proc.rs:2303`,
`crates/carrick-runtime/src/runtime.rs:720`, around the vCPU
release/rebuild dance).

`MemoryBackend` stores the writable filesystem in ordinary process heap:
`RwLock<MemoryBackendState>`, file bytes as `Arc<[u8]>` + a dirty-page
`BTreeMap` (`crates/carrick-runtime/src/fs_backend.rs`). There is no
`MAP_SHARED` segment and no kernel-backed inode.

Consequently, under `--fs memory`:

- **Threads of one guest process** share the filesystem (one address space, one
  `RwLock`) — coherent.
- **Separate guest processes** (anything that forks) do **not**. At `fork()` the
  child inherits a copy-on-write snapshot of the parent's heap, including the
  entire in-memory filesystem. From that point the two diverge: a file the child
  writes lands in the child's private `MemoryBackendState`; the parent never
  sees it, and vice-versa. Nothing reconciles them — the filesystem forks along
  with the process.

This breaks every multi-process workload (apt's fork-storm, dpkg, a shell
spawning subprocesses, build tools). `--fs host` avoids it by moving the source
of truth out of the address space and into the host kernel: the writable overlay
is materialized on a real cap-std scratch dir (APFS), both forked host processes
hold real fds/inodes, and the kernel makes writes immediately visible across
them. Metadata the host fs can't natively represent (guest file mode, socket
identity) lives in fork-coherent xattrs (`user.carrick.mode`,
`user.carrick.socket`).

`--fs host` is already the default on case-sensitive volumes and at parity with
memory for the workloads we care about. Removing `--fs memory` from the default
build removes a backend that is correct only for a single-process guest and is
silently wrong the instant anything forks.

## 2. Goal / non-goals

**Goal.** A `fs-memory` Cargo feature, **default OFF**, such that:

1. A default build rejects `--fs memory` at the CLI (`clap` reports an invalid
   value; `host` is the only accepted value).
2. No resolution path ever selects `FsBackendKind::Memory` in a default build —
   defaults and `--fs host` fallbacks resolve to `Host`, hard-erroring rather
   than silently degrading (the "host, then error" rule, §4).
3. `cargo build --features fs-memory` restores `--fs memory` exactly as it
   behaves today.
4. The default `cargo test` (feature off) is fully green **without** any test
   that relies on the in-memory backend; memory tests are `#[cfg]`-gated and
   opt-in only (§6).

**Non-goals.**

- Removing or refactoring the `MemoryBackend` struct itself. It stays compiled
  unconditionally as the VFS's transient init overlay (§3).
- Changing the host backend, the VFS overlay/whiteout semantics, or any syscall
  handler.
- Deprecating `--fs memory` for feature-enabled builds: with `fs-memory` on,
  behavior is unchanged.

## 3. Why `MemoryBackend` must stay compiled

`RootFsVfs::new()` / `with_rootfs()` initialize the `overlay` field to
`Box::new(MemoryBackend::new())` before any backend is chosen
(`crates/carrick-runtime/src/vfs/rootfs.rs:105,112`). `overlay.rs` re-exports it
as `WritableOverlay`. The chosen backend is installed later via
`set_fs_backend → set_overlay` (`crates/carrick-runtime/src/dispatch/mod.rs:1792`),
which *swaps* the overlay:

- `--fs host`: the overlay is replaced by the disk-backed `HostFsBackend`; the
  in-memory overlay is dropped. The live filesystem is the kernel-mediated
  scratch dir.
- `--fs memory`: the overlay stays the `MemoryBackend`.

So `MemoryBackend` is (a) the transient init default that always exists for a
moment, and (b) the live overlay only under `--fs memory`. The feature gates
**(b)** — the selection — not the type. The type is compiled unconditionally.

## 4. Behavior when the feature is OFF (default)

Per the approved "host, then error" rule:

- **CLI:** `--fs memory` is not a valid value (the enum variant is absent, so
  `clap::ValueEnum` rejects it: `invalid value 'memory' for '--fs <FS>'
  [possible values: host]`).
- **Default selection** (`carrick-engine::resolve_run_spec` and
  `carrick-cli::fs_setup::default_fs_backend_kind`): always resolve to `Host`.
  The case-insensitive-volume → memory downgrade is dropped (a `#[cfg(not)]`
  path). A case-insensitive scratch volume no longer silently changes backend;
  it just runs on host (with the existing "some Linux tools may misbehave"
  caveat applying to the volume, surfaced via a warning if we keep one).
- **`--fs host` scratch/seed failure** (`fs_setup.rs:99`, `execute.rs:443`): a
  hard error with an actionable message instead of the silent fallback to
  `MemoryBackend`. Example: `carrick: --fs host failed (<err>); the in-memory
  fallback is not compiled in (rebuild with --features fs-memory or use a
  writable case-sensitive scratch volume)`.

When the feature is ON, all of the above behave exactly as today.

## 5. Approach A — `#[cfg]` the enum variant

Chosen over a runtime-rejection approach because it is the most literal
"remove": the variant is genuinely absent from the default build, `clap` rejects
the value natively, and the compiler forces every `Memory` site to be addressed
(no silent miss).

### 5.1 Feature declaration & propagation

Follow the existing `syscall-shim` convention (kebab-case; lib crates declare the
feature, the binary is the control point) — but **default off** everywhere.

- `crates/carrick-spec/Cargo.toml`: add `fs-memory = []` (owns `FsBackendKind`).
- `crates/carrick-runtime/Cargo.toml`: `fs-memory = ["carrick-spec/fs-memory"]`.
- `crates/carrick-engine/Cargo.toml`: `fs-memory = ["carrick-spec/fs-memory",
  "carrick-runtime/fs-memory"]`.
- `crates/carrick-cli/Cargo.toml`: `fs-memory = ["carrick-spec/fs-memory",
  "carrick-engine/fs-memory", "carrick-runtime/fs-memory"]`. **Not** added to
  `default`.

Feature unification note: because no crate puts `fs-memory` in `default`, a
normal `cargo build`/`cargo test` of the workspace leaves it off. Enabling it on
`carrick-cli` (`-p carrick-cli --features fs-memory`) turns it on across the
graph via the propagation above.

### 5.2 The variant

`crates/carrick-spec/src/lib.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum FsBackendKind {
    #[cfg(feature = "fs-memory")]
    Memory,
    Host,
}
```

When off, the enum is `{ Host }`. `clap::ValueEnum` lists only `host`. Serde of a
persisted `"Memory"` spec errors when off — acceptable: a memory container can't
run in a default build anyway (a clear deserialize error is the correct outcome).

### 5.3 Selection / match sites (compiler-enforced)

Every `FsBackendKind::Memory` arm or producer gets `#[cfg(feature = "fs-memory")]`,
and each default/fallback producer gets a `#[cfg(not(feature = "fs-memory"))]`
host-or-error counterpart. With the variant absent, a `match kind { Host => ... }`
is exhaustive, so the gated arms simply disappear. Sites (from the audit):

- `carrick-spec/src/lib.rs` — the variant (§5.2).
- `carrick-cli/src/fs_setup.rs`
  - `:76` install `Memory => MemoryBackend` arm → `#[cfg(feature)]`.
  - `:99` `--fs host` seed-fail returns `Memory` → replace with hard error when
    off (§4); keep memory fallback when on.
  - `:212-233` `default_fs_backend_kind` → when off, return `Host`
    unconditionally (no case-sensitivity probe needed for the choice; a warning
    may still note a case-insensitive volume). When on, today's probe logic.
- `carrick-engine/src/lib.rs:229-235` — `resolve_run_spec` fs default. When off,
  `req.fs.unwrap_or(FsBackendKind::Host)`. When on, today's probe.
- `carrick-runtime/src/execute.rs`
  - `:331` execute match `Memory => { ... }` arm → `#[cfg(feature)]`.
  - `:432`/`:443` runtime `install_fs_backend` `Memory => MemoryBackend` arm and
    host-fail fallback → `#[cfg(feature)]` arm + host-then-error when off.
- `carrick-cli/src/lifecycle.rs:374` — the `matches!(state.config.fs,
  Some(Memory))` guard ("start requires --fs host"). When off the variant is
  absent, so this `matches!` can't name it; gate the whole guard with
  `#[cfg(feature = "fs-memory")]` (when off, a memory container can't exist, so
  the guard is vacuous).

Deduplication opportunity (in scope, since we're editing both): the
case-sensitivity probe is duplicated in `resolve_run_spec` and
`default_fs_backend_kind`. When the feature is on, factor the probe into one
shared helper (e.g. `carrick_runtime::apfs::default_fs_backend_kind()` or a
`carrick-engine` helper) and call it from both, rather than maintaining two
copies. When off, both reduce to "Host".

### 5.4 `--fs` argument

`crates/carrick-cli/src/args.rs` carries `fs: Option<FsBackendKind>` on `RunElf`
(`:85`), `Run` (`:254`), and `Create` (`:321`). No structural change: with the
variant gone, `value_enum` accepts only `host`. Update the three doc comments
("Defaults to `host` on case-sensitive volumes and `memory` elsewhere") to
reflect the feature-off reality (memory only `--features fs-memory`).

## 6. Testing

The default `cargo test` (feature off) must be green with **no** dependency on
the in-memory backend. Memory-exercising tests are gated and opt-in only.

- `crates/carrick-runtime/tests/integration/syscall_fs.rs` and
  `.../common/syscall_support.rs` — gate the memory-backed cases with
  `#[cfg(feature = "fs-memory")]` (or route them through host). The default run
  must still cover the same syscalls via the host backend; if a case is
  memory-only, it becomes feature-gated.
- `crates/carrick-engine/src/lib.rs` unit tests asserting `fs:
  Some(FsBackendKind::Memory)` (`:357,445,478,510,542,583`) — gate with
  `#[cfg(feature = "fs-memory")]`; add/adjust host-default equivalents so the
  default build still asserts the resolution logic.
- `crates/carrick-cli/tests/perf_*` (`perf_runner.rs`, `perf_support/cases.rs`,
  `perf_support/invoke.rs`) — gate the memory cases; perf is not a default gate,
  but it must compile with the feature off.

New coverage:

- A default-build test asserting `--fs memory` is rejected (CLI returns a
  non-zero exit / clap error naming `host` as the only value).
- A default-build test asserting the default backend resolves to `Host` and that
  a `--fs host` construction failure is a hard error, not a memory fallback
  (can be a unit test on the resolution helper).
- A `#[cfg(feature = "fs-memory")]` smoke test that `--fs memory` still works
  when the feature is on (parity with today), so the opt-in path is exercised
  when someone builds with it.

CI: **no** standing job depends on the memory path. The existing gates run with
default features (memory off) and must stay green. Building/testing
`--features fs-memory` is available for anyone exercising the opt-in but is not a
required gate. (Optional, low-priority: a non-blocking `--features fs-memory`
compile check to catch bit-rot; not required by this spec.)

## 7. Acceptance criteria

1. Default `cargo build` + `cargo test --workspace` are green with `fs-memory`
   off, and no test in that run touches the in-memory backend.
2. `carrick run --fs memory …` on a default build fails at argument parsing with
   `host` as the only listed value.
3. On a default build, the resolved backend is always `Host`; a `--fs host`
   scratch/seed failure is a hard error with an actionable message (names
   `--features fs-memory` and the case-sensitive-volume remedy).
4. `cargo build -p carrick-cli --features fs-memory` restores `--fs memory` with
   behavior identical to today, proven by a feature-gated smoke test.
5. No change to host-backend behavior or syscall emulation; `MemoryBackend`
   still compiles unconditionally as the VFS init overlay.

## 8. Risks & notes

- **Missed `Memory` site →** compile error in the default build (variant
  absent). This is a feature of Approach A: the failure is loud and at compile
  time, not silent. The audit in §5.3 is believed complete; the compiler is the
  backstop.
- **Persisted-spec deserialize:** an on-disk `ContainerState`/`RunSpec` with
  `fs_backend: "Memory"` fails to load on a default build. Acceptable — such a
  container can't run without the feature; the error is clear. Worth a one-line
  note in the error path so the message is actionable.
- **Doc/help drift:** the three `--fs` doc comments and any user docs mentioning
  `--fs memory` as a default option must be updated to reflect "opt-in via
  `--features fs-memory`."

## Appendix — code anchors (verified 2026-06-07)

- Guest fork = host fork: `dispatch/proc.rs:2303`, `runtime.rs:720`.
- `MemoryBackend` heap storage: `fs_backend.rs` (`RwLock<MemoryBackendState>`,
  `SharedFileContents { base: Arc<[u8]>, dirty: BTreeMap, len }`).
- Overlay init + swap: `vfs/rootfs.rs:105,112,118`,
  `dispatch/mod.rs:1792-1793,1804`; re-export `overlay.rs`.
- Selection/default/fallback sites: `fs_setup.rs:76,99,212-233`,
  `engine/lib.rs:229-235`, `execute.rs:331,432,443`, `lifecycle.rs:374`.
- `--fs` args: `args.rs:85` (RunElf), `:254` (Run), `:321` (Create).
- Feature convention: `syscall-shim` in `carrick-cli`/`carrick-runtime`
  `Cargo.toml`; `clap` optional feature in `carrick-spec/Cargo.toml`.
