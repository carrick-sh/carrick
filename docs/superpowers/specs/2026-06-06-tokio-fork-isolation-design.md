# Isolate tokio so it is never alive across a fork

**Date:** 2026-06-06
**Status:** Approved (brainstorming) — ready for implementation plan
**Repo:** `carrick` (`/Volumes/CaseSensitive/carrick`)

**Goal:** Fix `carrick run -t …` (and any `--pid private` / interactive run) hanging
at teardown by ensuring **no tokio runtime/threads are alive when carrick forks**.
Keep tokio (the OCI pull and `carrick serve` legitimately need async); isolate it.

## Root cause (confirmed via lldb)

`carrick run -t hello-world` prints output, then hangs; it leaks orphaned
`carrick:…` watcher processes. The supervisor's stuck stack:

```
__psynch_cvwait → tokio::runtime::blocking::shutdown::Receiver::wait
  → tokio::runtime::blocking::pool::BlockingPool::shutdown
  → drop_in_place<BlockingPool> → carrick::runtime_util::block_on_oci
```

`run_cli` runs `block_on_oci(async { engine.run(req).await })` (commands.rs:566).
`Engine::run` (carrick-engine/src/lib.rs:283) does the async pull **and then calls
`Runtime::execute(&spec)` — the fork — inside the tokio runtime.** `libc::fork()`
copies only the calling thread, so the forked supervisor/runtime children inherit
a tokio runtime whose blocking-pool worker threads don't exist. When a child drops
that runtime, `BlockingPool::shutdown` blocks forever joining absent threads →
the supervisor never exits → the launcher's `wait4` hangs → `carrick run -t` hangs.

Non-`-t` runs don't fork carrick processes, so they exit fine. `carrick serve` /
`carrick build` already honor a "no-tokio-before-fork" rule by spawning `carrick`
**subprocesses** (see serve/build.rs, serve/mod.rs comments). Only the direct
`run`/lifecycle path violates the invariant.

## The invariant

**No tokio runtime or tokio-spawned threads may be live at the moment carrick
forks** (the interactive supervisor fork, the `--pid private` NsSupervisor fork,
guest `fork(2)`, or `exec`). Async work (OCI pull, login, the serve daemon) must
complete and its runtime be **dropped** before any fork.

## Design

### 1. Split async resolve from sync execute (`carrick-engine`)

Replace `Engine::run` (which mixes pull + execute) with an async resolver that
returns the spec and does **not** fork:

```rust
// carrick-engine/src/lib.rs
impl Engine {
    /// Async: parse the ref, pull/resolve the image for the target platform,
    /// and build the RunSpec. Does NOT execute — no fork happens here, so it is
    /// safe to run inside a tokio runtime.
    pub async fn resolve(&self, req: CliRunRequest) -> Result<RunSpec, anyhow::Error> {
        let image_ref = carrick_spec::ImageReference::parse(&req.image_ref)
            .map_err(|e| anyhow::anyhow!("invalid image reference: {}", e))?;
        let platform = request_platform(&req);
        let target = carrick_image::PlatformTarget {
            os: "linux".to_string(),
            arch: platform.oci_arch().to_string(),
            variant: None,
        };
        let resolved = self.store
            .resolve_with_platform(&image_ref, &target)
            .await
            .map_err(|e| anyhow::anyhow!("failed to resolve image: {}", e))?;
        resolve_run_spec(req, resolved).map_err(anyhow::Error::msg)
    }
}
```

Remove `Engine::run` (or keep it only if a non-forking caller needs it — none do;
both current callers fork). `RunSpec` is already `carrick_spec::RunSpec`.

### 2. Run resolve under tokio, execute outside (`carrick-cli`)

Both call sites change from "block_on(engine.run)" to "block_on(resolve), then
execute":

- **`commands.rs` `run_cli` (~L560–582):**
```rust
let engine = carrick_engine::Engine::new(store.clone());
let spec = match block_on_oci(engine.resolve(req.clone())) {
    Ok(s) => s,                       // tokio runtime is now DROPPED (pool joined in parent)
    // resolve runs in the PARENT, before any fork → normal exit is safe.
    Err(e) => { eprintln!("carrick: {e:#}"); std::process::exit(125); }
};
let result = match carrick_runtime::Runtime::execute(&spec) {   // no tokio alive → fork is safe
    Ok(r) => r,
    // execute() forks (interactive supervisor / `--pid private` NsSupervisor); a
    // setup failure can surface in a FORKED CHILD, so this arm keeps the
    // async-signal-safe `_exit` (std::process::exit's atexit/Drop is unsafe
    // post-fork and double-closes inherited fds → SIGABRT). stderr is flushed.
    Err(e) => { eprintln!("carrick: {e:#}"); unsafe { libc::_exit(125) }; }
};
```
  The split means the *resolve* error is now in the parent (normal exit); the
  *execute* error keeps `_exit` because it may run in a forked child. Keep
  `Runtime::execute`'s own internal forked-child `_exit` handling unchanged.
  Update the comments (commands.rs L21/L35/L45) that say "supervisor fork happens
  inside engine.run" → it now happens inside `Runtime::execute`.

- **`lifecycle.rs:249`:** apply the same split (`block_on_oci(engine.resolve(req))`
  then `Runtime::execute(&spec)` outside the block_on). This path forks the
  detached NsSupervisor, so it has the same hazard.

### 3. Pre-fork guardrail (regression fence)

Add a cheap check that no tokio runtime is active immediately before the carrick
forks, so this can't silently regress:

```rust
// just before fork_interactive_session() in execute.rs setup_interactive_stdio,
// and before the NsSupervisor/guest fork:
debug_assert!(
    tokio::runtime::Handle::try_current().is_err(),
    "tokio runtime must not be live across a carrick fork (see tokio-fork-isolation spec)"
);
```
`carrick-runtime` already depends on tokio, so the assert compiles there. (If a
non-debug fence is preferred, log+continue rather than panic — but debug_assert is
enough to catch it in CI/tests.)

## Testing

- **Red→green e2e:** `carrick run -t hello-world` (and `carrick run -t hello-world
  </dev/null`) must exit promptly (rc=0), print the message, and leave **no**
  orphaned `carrick:…` processes. Before the fix this hangs (124); after, exits.
  Verify `carrick run -it ubuntu:24.04 bash` still works (run a command, `exit`
  returns) — the interactive path itself is fine; only teardown was broken.
- **Unit:** a test in carrick-cli (or engine) asserting `Engine::resolve` returns a
  `RunSpec` without executing (no fork), and that after `block_on_oci(resolve)`
  returns, `tokio::runtime::Handle::try_current().is_err()` holds.
- **No leak check:** after a `-t` run, `ps | grep 'carrick:'` is empty.
- **Gate:** `just ci` green (fmt/clippy/build/docs/tests/integration). Re-run the
  carrick-cli serve tests (they spawn subprocesses — unaffected).

## Out of scope
- Removing tokio entirely (rewriting the OCI pull + serve server in blocking I/O).
- The interactive **job-control** gaps (`cannot set terminal process group` / `no
  job control`, `ttyname`/`/dev/tty`) — real but separate; tracked elsewhere.
- The `-t`-without-a-real-tty 0-output behavior beyond not-hanging (the relay with
  a non-tty stdin is a separate UX question).
