# Docker-compatible frontend & workspace layering

**Date:** 2026-05-24
**Status:** Approved design, pending implementation plan

## Goal

Restructure carrick into a Cargo workspace whose layering supports a drop-in
Docker-style CLI frontend for running containers. The immediate deliverable is
the **layering** plus a docker-compatible `run` command. Full lifecycle
commands (`ps`/`stop`/`rm`/`logs`, detached containers, persistent container
state) are explicitly **out of scope** for this phase but the layer boundaries
are chosen so they can attach later without reshaping the design.

Host namespaces only: the container shares the host's network and PID
namespaces (no isolation implemented). The abstraction carries a
`NamespaceConfig` whose only mode today is `Host`; that enum is the seam where
real isolation drops in later.

## Scope decisions (from brainstorming)

- **Compatibility depth:** layering-first, `run`-focused. Not a literal
  `alias docker=carrick`; not a daemon; no persistent multi-container store yet.
- **Physical structure:** Cargo workspace (compiler-enforced crate boundaries).
- **`run` features for v1:** honor image OCI config (ENTRYPOINT/CMD/ENV/
  WORKDIR/USER), core flags (`-e`/`--env-file`, `-w`, `-u`, `--entrypoint`,
  `--name`, `-t`/`-i`, `--rm`), volume bind mounts (`-v`/`--mount`).
  Network + PID namespaces = host (recorded, not enforced). `-p` parsed and
  recorded but a no-op under host networking.

## Architecture: crate DAG

```
        carrick-cli  (bin, output name stays "carrick")
              │   docker-compatible `run` + dev subcommands
              ▼
        carrick-engine          ← NEW: the container layer
          │        │   ContainerSpec, docker run semantics,
          │        │   host-only NamespaceConfig, builds RunSpec
          ▼        ▼
  carrick-image   carrick-runtime
   pull/store/     HVF + dispatch + vfs + fs_backend
   OCI config      execute(RunSpec) -> RunOutcome
          │        │
          ▼        ▼
            carrick-spec         ← NEW: leaf, types only
```

**Dependency rules:**
- `carrick-spec` is a leaf: pure vocabulary types, light deps (serde, camino,
  bitflags). No HVF, no libc-heavy logic. Lets runtime and engine share
  `RunSpec`/`RunOutcome` without depending on each other.
- `carrick-runtime` and `carrick-image` are siblings; neither knows the other
  or `carrick-engine`.
- `carrick-engine` is the only crate that knows both image and runtime; it
  orchestrates resolve → merge → build RunSpec → execute.
- `carrick-cli` depends on engine for `run`; may reach runtime/image directly
  for dev/diagnostic subcommands (trace, debug, rootfs, inspect-elf,
  dispatch-syscall, volume).
- `[workspace.lints]` carries the no-panic gate (deny `unwrap`/`expect`/
  `panic`/`todo`/`unimplemented`) to every crate; `clippy.toml` keeps test
  code exempt.

**Hard constraints:**
- Output binary stays named `carrick` (`[[bin]] name = "carrick"`), so
  `target/release/carrick` — the codesign/entitlements path that HVF depends
  on — is unchanged. Regressing this yields HV_DENIED.
- The deeply-coupled runtime internals (dispatch ↔ memory ↔ trap ↔ thread)
  stay together in `carrick-runtime`. We are not splitting those.

## Crate responsibilities & key types

### carrick-spec (vocabulary only)
- `ImageReference` (moved from `oci.rs`).
- `ImageConfig` — parsed OCI image config: `entrypoint: Option<Vec<String>>`,
  `cmd: Option<Vec<String>>`, `env: Vec<String>`,
  `working_dir: Option<Utf8PathBuf>`, `user: Option<String>`,
  `exposed_ports`, `labels`.
- `Mount { source: Utf8PathBuf /* host */, target: Utf8PathBuf /* guest */, readonly: bool }`.
- `NamespaceMode` — `enum { Host }` (only variant today; the isolation seam).
  `NamespaceConfig { network, pid, mount, uts, ipc, user }`, all `Host`.
- `ContainerSpec` — resolved container request: image ref, `argv`, `env`,
  `cwd`, `user`, `tty`, `interactive`, `rm`, `name`, `mounts: Vec<Mount>`,
  `namespaces`, `labels`.
- `RunSpec` — low-level execution request the runtime consumes: `executable`,
  `argv`, `envp`, `cwd`, `rootfs_layers: Vec<Utf8PathBuf>`,
  `fs_backend: FsBackendKind`, `mounts`, `tty`/`raw`/`interactive`,
  `max_traps`, `debug_state_path`. (`FsBackendKind` moves here as a plain enum.)
- `RunOutcome` — `exit_code`, `stdout`, `stderr`, `traps`, `trap_limit_hit`,
  `report`.

### carrick-image
- `ImageStore`, `pull(ImageRef)`, and new `resolve(ImageRef) -> ResolvedImage
  { layers: Vec<Utf8PathBuf>, config: ImageConfig }`.
- Now also fetches/parses the **image config blob** (today carrick only reads
  layers). rootfs *composition* stays in runtime; image hands over layer paths
  + config.
- `OciBootstrapError` moves here.

### carrick-runtime
- Current `src/` minus `oci.rs` and minus CLI glue.
- New public seam: `Runtime::execute(spec: &RunSpec) -> Result<RunOutcome>` —
  wraps what the `Run` arm does today: pick fs backend from
  `(layers, fs_backend)`, apply `mounts` to the VFS mount table, seed baseline,
  set up stdio/tty, run the vCPU, collect the outcome.
- Existing lower-level entries (`run_elf_from_dispatcher_debug`,
  `run_rootfs_elf_with_hvf_args_and_dispatcher_debug`) stay `pub` for dev
  subcommands.

### carrick-engine
- `resolve_container(req: CliRunRequest, image: ResolvedImage) -> ContainerSpec`
  then `-> RunSpec` — where docker `run` semantics live (pure, HVF-free,
  unit-testable).
- `Engine::run(req) -> RunOutcome` — facade: `image.resolve` → merge →
  `runtime.execute`. No persistent container store yet; `Engine` is the seam
  where one would attach.

### carrick-cli
- clap frontend: docker-compatible `run` flag parsing → `CliRunRequest` →
  engine; plus existing dev/diagnostic subcommands. Output binary stays
  `carrick`.

## Data flow & docker `run` semantics

End-to-end for `carrick run -e FOO=bar -v /h:/g -w /app image cmd...`:
1. **cli** parses → `CliRunRequest { image_ref, args, env_overrides, mounts,
   workdir, user, entrypoint_override, tty, interactive, rm, name }`.
2. **engine** `image.resolve(ref)` → `ResolvedImage { layers, config }`
   (pull-on-demand if absent, as today).
3. **engine** merges into `ContainerSpec`, lowers to `RunSpec`.
4. **runtime** `execute(RunSpec)`: builds fs backend, applies mounts to the VFS
   mount table, seeds baseline, sets up stdio/tty, runs the vCPU, returns
   `RunOutcome`.
5. **cli** renders output (tty / raw / json) and sets the exit code.

**Merge rules (in `carrick-engine`):**
- **argv** = effective_entrypoint ++ effective_cmd:
  - effective_entrypoint = `--entrypoint` else image `ENTRYPOINT` (may be empty).
  - effective_cmd = positional args after image if any, else image `CMD`
    (args *replace* CMD, not append — docker rule).
  - empty result → error `"no command specified"` (matches docker). The
    `shell` subcommand keeps its `/bin/sh` default and bypasses this.
- **env** = image `ENV`, then carrick baseline defaults (PATH/HOME/TERM/LANG/
  LC_ALL) **only for keys not already set**, then `-e`/`--env-file` overrides
  (last-wins). Behavior change: image ENV now wins over today's fixed
  injection — closer to docker.
- **workdir** = `-w` else image `WorkingDir` else `/`.
- **user** = `-u` else image `User`. Best-effort under host namespaces (existing
  creds handling); no failure if it can't fully apply.
- **mounts** = `-v host:guest[:ro]` → `Mount`, passed through `RunSpec` to the
  runtime VFS mount table.
- **namespaces** = all `Host` (recorded, not enforced). `-p` parsed/recorded,
  no-op under host networking.

The docker-semantics logic is a pure function (`CliRunRequest` + `ImageConfig`
→ `RunSpec`), unit-testable without HVF — a testability win over today's
main.rs glue.

## Error handling

- Each crate owns a `thiserror` enum (`SpecError`, `ImageError`,
  `RuntimeError`, `EngineError`). `OciBootstrapError` moves with `carrick-image`.
- `carrick-engine` wraps image/runtime errors with context. The cli boundary
  uses `anyhow` for top-level reporting, as today.
- No-panic gate enforced workspace-wide via `[workspace.lints]`; test code
  exempt via `clippy.toml`.

## Testing

- `carrick-spec` / `carrick-engine`: **new** table-driven unit tests for the
  merge rules (entrypoint+cmd precedence, env layering, workdir/user defaults,
  mount parsing) — pure, fast, no HVF.
- `carrick-runtime`: existing ~113 lib tests move with the code.
- `carrick-image`: existing oci tests move with it.
- Integration: `tests/` (incl. the bollard differential conformance harness)
  stays at the workspace root, driving the `carrick` binary through the new
  `run` path. Conformance probes unchanged.
- Acceptance: `carrick run python:3.12-slim python3 --version` and the existing
  demos (apt-get install, python http.server) still pass — proving the new
  layering is behavior-preserving for `run`.

## Migration strategy (incremental, `cargo check` green at each step)

1. Convert root `Cargo.toml` to a workspace; create the 5 crate skeletons. Keep
   `[[bin]] name = "carrick"` so `target/release/carrick` is unchanged.
2. Land `carrick-spec`: move `ImageReference`, add new types.
3. Land `carrick-image`: move `oci.rs`, add image-config fetch/parse +
   `resolve()`.
4. Land `carrick-runtime`: move the bulk of `src/` (mechanical `crate::`
   re-rooting); add the `execute(RunSpec)` seam wrapping existing `run_*`
   entries.
5. Land `carrick-engine`: merge logic + `Engine::run`.
6. Land `carrick-cli`: docker `run` flag parsing → engine; re-home dev
   subcommands.
7. Verify: build-signed.sh, clippy no-panic gate, lib tests, one Docker
   differential demo.

## Risks

- The runtime move (step 4) is large and mechanical — biggest churn, no logic
  change.
- Codesigning/entitlements must be re-verified after the bin moves; HV_DENIED
  is the failure mode if it regresses.

## Out of scope (future phases)

- Lifecycle commands: `ps`, `stop`, `rm`, `logs`, `create`/`start` split,
  detached (`-d`) execution.
- Persistent container state store / daemon.
- Real namespace isolation (network/pid/mount/user). The `NamespaceConfig`
  seam is in place for it.
- Port publishing as a real feature (host networking makes it identity today).
