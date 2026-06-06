# Tokio Fork-Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `carrick run -t …` (and `--pid private`) exit cleanly instead of hanging, by ensuring no tokio runtime is alive when carrick forks.

**Architecture:** Split the async OCI resolve from the sync fork+execute: `Engine::resolve(req)→RunSpec` runs under `block_on_oci` (runtime then dropped, blocking pool joined in the parent); `Runtime::execute(&spec)` runs after, with no tokio alive. Add a `debug_assert` guardrail before the forks.

**Tech Stack:** Rust, tokio (current-thread), carrick-engine / carrick-cli / carrick-runtime crates.

**Spec:** `docs/superpowers/specs/2026-06-06-tokio-fork-isolation-design.md`

**Conventions:** run from `/Volumes/CaseSensitive/carrick`. Build the runnable binary with `./scripts/build-signed.sh` (a bare `cargo build` is unsigned → HV_DENIED). `CK=./target/release/carrick`. Use `CARRICK_RUN_ID=plan-$$` and reap with `pkill -9 -f "carrick:"` only after confirming no other carrick lanes run.

---

### Task 1: Reproduce the hang (RED baseline)

**Files:** none (capture the failing behavior before changing code).

- [ ] **Step 1: Build the signed binary**

```sh
./scripts/build-signed.sh 2>&1 | tail -3
```
Expected: `built + signed: target/release/carrick`.

- [ ] **Step 2: Confirm `-t` hangs (non-tty stdin reproduces reliably)**

```sh
pkill -9 -f "carrick:" 2>/dev/null
timeout 25 ./target/release/carrick run -t hello-world </dev/null >/tmp/red.out 2>&1; echo "EXIT=$? (124=hang)"
ps -A -o command= | grep -c 'carrick:'   # leaked watchers
pkill -9 -f "carrick:" 2>/dev/null
```
Expected (RED): `EXIT=124`, ≥1 leaked `carrick:` process. This is the bug. (Non-`-t` `./target/release/carrick run hello-world </dev/null` exits 0 — control.)

---

### Task 2: Add `Engine::resolve` (async, no fork) and retire `Engine::run`

**Files:**
- Modify: `crates/carrick-engine/src/lib.rs` (the `impl Engine` around L283)

- [ ] **Step 1: Replace `Engine::run` with `Engine::resolve`**

Replace the whole `pub async fn run(&self, req: CliRunRequest) -> Result<RunResult, anyhow::Error>` method (L283–306) with:
```rust
    /// Resolve a run request to a `RunSpec`: parse the image ref, pull/resolve
    /// the image for the target platform, and build the spec. This is the ONLY
    /// async part of a run — it does NOT execute, so no fork happens here and it
    /// is safe to drive inside a tokio runtime. The caller drops the runtime
    /// before calling `carrick_runtime::Runtime::execute` (see the
    /// tokio-fork-isolation spec).
    pub async fn resolve(&self, req: CliRunRequest) -> Result<carrick_spec::RunSpec, anyhow::Error> {
        let image_ref = carrick_spec::ImageReference::parse(&req.image_ref)
            .map_err(|e| anyhow::anyhow!("invalid image reference: {}", e))?;
        let platform = request_platform(&req);
        let target = carrick_image::PlatformTarget {
            os: "linux".to_string(),
            arch: platform.oci_arch().to_string(),
            variant: None,
        };
        let resolved = self
            .store
            .resolve_with_platform(&image_ref, &target)
            .await
            .map_err(|e| anyhow::anyhow!("failed to resolve image: {}", e))?;
        resolve_run_spec(req, resolved).map_err(anyhow::Error::msg)
    }
```
(If `carrick_spec::RunSpec` isn't already the return type of `resolve_run_spec`, match its exact type — confirm with `grep -n "fn resolve_run_spec" crates/carrick-engine/src/lib.rs`.)

- [ ] **Step 2: Find every caller of the old `engine.run`**

```sh
grep -rn "\.run(\|engine\.run\|Engine::run" crates/*/src crates/*/tests | grep -i engine
```
Expected callers to update in Task 3: `crates/carrick-cli/src/commands.rs:566`, `crates/carrick-cli/src/lifecycle.rs:249`. Note any test callers and update them to `resolve` + `Runtime::execute` too.

- [ ] **Step 3: Compile-check the engine crate**

```sh
cargo build -p carrick-engine 2>&1 | tail -5
```
Expected: compiles (callers in carrick-cli will be fixed in Task 3 — `cargo build -p carrick-engine` alone should still build).

---

### Task 3: Update the two call sites to resolve→execute

**Files:**
- Modify: `crates/carrick-cli/src/commands.rs` (run_cli, ~L560–582 + the doc comments at L21/L35/L45)
- Modify: `crates/carrick-cli/src/lifecycle.rs` (~L249)

- [ ] **Step 1: `run_cli` (commands.rs ~L566)** — replace the `match block_on_oci(async { engine.run(req.clone()).await })` block with:
```rust
            let spec = match block_on_oci(engine.resolve(req.clone())) {
                Ok(s) => s,
                // resolve runs in the PARENT (no fork yet) → normal exit is safe.
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    std::process::exit(125);
                }
            };
            let result = match carrick_runtime::Runtime::execute(&spec) {
                Ok(r) => r,
                // execute() forks (interactive supervisor / `--pid private`
                // NsSupervisor); a setup failure can surface in a FORKED CHILD,
                // so use async-signal-safe `_exit` (std::process::exit's
                // atexit/Drop is unsafe post-fork → double-close → SIGABRT).
                // SAFETY: _exit is async-signal-safe; stderr already flushed.
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    unsafe { libc::_exit(125) };
                }
            };
```
Keep the existing post-`result` code (the `status`/`trap_limit_hit` handling) unchanged.

- [ ] **Step 2: Fix the now-stale comments** in commands.rs (L21, L35, L45) that say the supervisor fork happens "inside `engine.run`" — change to "inside `Runtime::execute` (after the tokio runtime is dropped)".

- [ ] **Step 3: `lifecycle.rs` (~L249)** — replace `match crate::runtime_util::block_on_oci(async { engine.run(req).await }) {` with the same split:
```rust
    let spec = match crate::runtime_util::block_on_oci(engine.resolve(req)) {
        Ok(s) => s,
        Err(e) => { /* keep this arm's existing error handling, operating on `e` */ }
    };
    match carrick_runtime::Runtime::execute(&spec) {
        // keep the existing Ok/Err handling that the old `engine.run` match had,
        // operating on the RunResult / error
    }
```
Read `lifecycle.rs:240–300` first and preserve its exact Ok/Err handling (it differs from run_cli — it's the detached/lifecycle path); only the call shape changes (resolve under block_on, execute outside). If its Err arm runs in a forked child, keep `_exit`; otherwise normal return.

- [ ] **Step 4: Build the workspace**

```sh
./scripts/build-signed.sh 2>&1 | tail -3
```
Expected: builds + signs.

---

### Task 4: Pre-fork guardrail (regression fence)

**Files:**
- Modify: `crates/carrick-runtime/src/execute.rs` (before `fork_interactive_session`, ~L268/L356) and the `--pid private` NsSupervisor fork site.

- [ ] **Step 1: Add the assert before the interactive fork**

In `setup_interactive_stdio` (execute.rs ~L588), right before the `fork_interactive_session()` call, add:
```rust
    debug_assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "tokio runtime must not be live across a carrick fork (tokio-fork-isolation spec)"
    );
```
- [ ] **Step 2: Add the same assert at the `--pid private` NsSupervisor fork**

```sh
grep -rn "NsSupervisor\|fork()\|prepare_host_fork\|setsid\|libc::fork" crates/carrick-runtime/src/execute.rs crates/carrick-runtime/src/namespace 2>/dev/null | head
```
Add the same `debug_assert!(tokio::runtime::Handle::try_current().is_err(), …)` immediately before the NsSupervisor process fork (the detached `--pid private` path). If carrick-runtime lacks a `use tokio;` import, reference it fully-qualified as above (the crate already depends on tokio).

- [ ] **Step 3: Build**

```sh
./scripts/build-signed.sh 2>&1 | tail -3
```
Expected: builds.

---

### Task 5: Verify GREEN (e2e + unit) 

**Files:**
- Create test: `crates/carrick-cli/src/runtime_util.rs` (add a `#[cfg(test)]` unit test)

- [ ] **Step 1: e2e — the hang is gone**

```sh
pkill -9 -f "carrick:" 2>/dev/null
timeout 25 ./target/release/carrick run -t hello-world </dev/null >/tmp/green.out 2>&1; echo "EXIT=$? (expect 0)"
grep -c "Hello from Docker" /tmp/green.out
sleep 1; echo "leaked carrick: procs: $(ps -A -o command= | grep -c 'carrick:')"   # expect 0
```
Expected (GREEN): `EXIT=0`, the hello message present, **0 leaked** processes.

- [ ] **Step 2: e2e — interactive bash still works** (drive via tmux real tty; do NOT grep the pane for a sentinel that appears in the typed command — read actual command output or check the process exited):

```sh
tmux kill-session -t ck 2>/dev/null; tmux new-session -d -s ck -x 120 -y 40
tmux send-keys -t ck './target/release/carrick run -it ubuntu:24.04 bash' Enter; sleep 12
tmux send-keys -t ck 'uname -m > /tmp/guest_uname; exit' Enter; sleep 6
tmux capture-pane -t ck -p | tail -4; tmux kill-session -t ck 2>/dev/null
# distinguish completion by a side effect, not the echoed command line:
ps -A -o command= | grep -c 'carrick:'   # expect 0 (session torn down)
```
Expected: bash ran, `exit` returned, 0 leftover `carrick:` procs. (Job-control warnings are OK — out of scope.)

- [ ] **Step 3: Unit test — `block_on_oci` leaves no live runtime**

Add to `crates/carrick-cli/src/runtime_util.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::block_on_oci;

    #[test]
    fn block_on_oci_drops_runtime_so_nothing_is_live_after() {
        block_on_oci(async {});
        // After block_on_oci returns, no tokio runtime may be current — this is
        // the invariant that makes a subsequent fork safe.
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "a tokio runtime is still current after block_on_oci returned"
        );
    }
}
```

- [ ] **Step 4: Run the unit test**

```sh
cargo test -p carrick-cli block_on_oci_drops_runtime 2>&1 | tail -8
```
Expected: PASS.

- [ ] **Step 5: Commit the implementation**

```sh
git add crates/carrick-engine/src/lib.rs crates/carrick-cli/src/commands.rs crates/carrick-cli/src/lifecycle.rs crates/carrick-runtime/src/execute.rs crates/carrick-cli/src/runtime_util.rs
git commit -m "fix(run): isolate tokio from fork — split Engine::resolve from execute

carrick run -t hung: execute()/fork ran inside block_on_oci's tokio runtime;
the forked child's BlockingPool::shutdown joined absent threads. Resolve the
image under tokio, drop the runtime, then execute (fork) with no tokio alive.
Pre-fork debug_assert fences it. Fixes the hang + leaked carrick: watchers."
```

---

### Task 6: Full gate

- [ ] **Step 1: `just ci`** (fmt/clippy/build/docs/test/test-integration)

```sh
just ci 2>&1 | tail -15; echo "JUST_CI_EXIT=${PIPESTATUS[0]}"
```
Expected: exit 0, all suites ok. (The carrick-cli serve tests spawn subprocesses — unaffected. If clippy flags the `debug_assert`/`_exit` changes, fix per the no-panic gate.)

- [ ] **Step 2: Commit any gate fixes**, then the work is ready for finishing-a-development-branch.

---

## Self-review notes
- Spec coverage: invariant (Task 4 guardrail), resolve/execute split (Tasks 2–3), error-arm nuance — resolve=`exit`, execute=`_exit` (Task 3 Step 1), tests (Task 5: e2e hang-gone + bash-works + unit no-live-runtime), gate (Task 6). All mapped.
- No placeholders: real code + exact commands. lifecycle.rs Step 3 says "preserve exact existing Ok/Err handling" — the engineer must read 240–300 first (its handling differs from run_cli and isn't duplicated here to avoid guessing it wrong); the *call-shape* change is fully specified.
- Type consistency: `Engine::resolve → carrick_spec::RunSpec`; `Runtime::execute(&spec) → RunResult`; both call sites use the same names.
- HVF note: the e2e steps need HVF (local dev machine), not CI — that's why the CI-gated test (Step 3) is the runtime-drop invariant, which needs no HVF/network.
