# Unified Conformance Harness — Design Spec

**Status:** Approved. Implementation contract.
**Date:** 2026-06-03
**Crate:** `crates/carrick-conformance` (new host workspace member)
**Supersedes the orchestration of:** `scripts/cpython-parity.py`, `scripts/go-conformance.sh`, `scripts/nodejs-conformance-image.sh`, and `.claude/skills/ltp-conformance/scripts/ltp-sweep.sh`.
**Complements (does not replace):** `crates/carrick-cli/tests/conformance.rs` — the deterministic, line-exact ABI probe gate.

---

## 1. Problem & motivation

Carrick is a Linux-binary-on-macOS runtime built on Hypervisor.framework. The only way we know whether a given Linux program behaves correctly under carrick is to run it and compare the result against real Linux. We do that today, but the apparatus that does it has accreted into four independent, mutually-inconsistent drivers — a Python script for CPython, two shell scripts for Go, a Bash/native-entrypoint pair for Node, and a skill's shell sweep for LTP — each with its own notion of what an "image", a "run", a "verdict", and a "baseline" are. This spec replaces the *orchestration* of all four with one declarative, manifest-driven Rust binary, and makes the resulting verdict data the single committed source of truth.

The motivation is not tidiness. It is three specific recurring failures that the scattered apparatus keeps producing, each of which has cost real debugging hours and each of which a unified harness is designed to make structurally impossible.

### 1.1 The stale-binary trap

Every conformance run shells out to `target/release/carrick`. That binary must carry the `com.apple.security.hypervisor` entitlement (via `./scripts/build-signed.sh`); a plain `cargo build` strips the codesignature and every guest launch then fails with `HV_DENIED` (`0xfae94007`). Worse than the signing problem is the *staleness* problem: it is trivially easy to edit a syscall handler, forget to rebuild, run the suite, and read a green result that describes the binary from twenty minutes ago. The verdicts look authoritative. They are lies. This is the single most expensive class of false signal in the whole apparatus, because it inverts the developer's trust: a passing run is supposed to be evidence, and here it is anti-evidence.

The harness closes this two ways, belt and suspenders. **(a)** Every `just` conformance recipe **depends on `build`** (`./scripts/build-signed.sh`) so the signed binary is built before the suite can run — this is the load-bearing guard on the normal path. **(b)** The runner itself, at startup, performs a **best-effort freshness sanity check** (§4.5) that is *belt to (a)'s suspenders*: it warns (not aborts) when the binary looks stale, and is the only freshness signal a developer gets when they bypass `just` and run `cargo run -p carrick-conformance` directly. The two are not redundant-and-equal: (a) is the real guard; (b) is a backstop for the off-path invocation. §4.5 specifies exactly why (b) must *warn* rather than *abort* (incremental cargo legitimately does not touch an unchanged artifact's mtime, so a strict "newer than every crate file" abort would spuriously fire right after a successful `just build`).

### 1.2 False environmental walls (the noise we just hit)

The apparatus repeatedly produces walls of `TBROK`/`TIMEOUT` rows that look like mass regressions but are environmental artifacts. We hit one minutes before writing this spec: a curated LTP sweep came back with a uniform `broken`/`TIMEOUT` wall across entire areas. The cause was **§1.1 in action — a stale binary**: the sweep shelled out to a `target/release/carrick` that predated `HEAD` by a day, so the verdicts described a binary that no longer existed. That is the dominant false-wall source, and the build-first guard (§1.1) is its fix.

A second, subtler environmental wall comes from the *filesystem backend*, and it is worth stating precisely because the obvious mental model is wrong. carrick's `--fs` selects the **writable-layer** backend over the image's read-only rootfs; it does **not** decide whether the image files exist:

- `--fs memory` is the in-memory CoW overlay over the composed OCI layers — carrick's closest analog to docker's overlayfs. It presents the image rootfs and is fast.
- `--fs host` *also* presents the image rootfs: `fs_setup.rs` **materializes the entire rootfs onto a cap-std scratch via `seed_from_rootfs`** (`crates/carrick-cli/src/fs_setup.rs`). But it is **slow** — the cap-std per-component re-resolution amplifies every guest `open` into many host opens (documented in `docs/fs-host-capstd-amplification.md`; `test_glob` can take ~140s and trip a timeout).

Both backends run *with the image* — `ltp-check.sh:57` already passes `localhost:5050/ltp:arm64`, so `/opt/ltp` is present either way. The difference is speed and writable-layer semantics, **not** missing framework files. (The truly empty scratch — *no image at all* — is the probe-gate / `run-elf` path, where emptiness is a feature; the language/LTP suites never use it.)

The harness makes both walls structurally hard: it always runs the **full image under both engines** (the drop-in insight, §3); it standardizes coherent suites on the **fast `--fs memory`** writable layer (avoiding the cap-std amplification and the volume-dependent default below); and it can never test a stale binary (§1.1).

> **Case-sensitive-volume default surprise (load-bearing).** `--fs` is `Option<FsBackendKind>`; when omitted, carrick **defaults to `host` on case-sensitive volumes** and `memory` elsewhere (`args.rs` doc comment, lines 81–84; the runtime decision is in `fs_setup.rs`, which logs `"<dir> is case-insensitive; defaulting --fs to memory"`). This repo lives on `/Volumes/CaseSensitive`, so the *default here is the slow `--fs host` cap-std backend* — correct (the rootfs is seeded), but amplifying, and it makes a suite's wall-clock depend on which volume it runs from. To keep runs fast and **volume-independent**, every coherent-rootfs suite pins its `--fs` **explicitly** in `carrick_flags` (`--fs memory` for the language/LTP suites); the manifest validator (§4.1) rejects a coherent suite that leaves `--fs` to the volume-dependent default. A suite may still opt into `--fs host` explicitly where it genuinely wants the cap-std real-fs path.

### 1.3 Scattered, un-diffable status

Carrick's "where are we" lives in at least five places that drift independently: `docs/conformance-coverage.md` (a language-runtime snapshot), `docs/cpython-baseline/TRIAGE.md`, `docs/nodejs-baseline/TRIAGE.md`, `docs/ltp-baseline/BASELINE.md`, plus assorted `.jsonl` baselines. Each was generated by a different driver with a different verdict vocabulary. There is no single artifact you can `git diff` to answer "did this commit regress anything", and no single table a newcomer can read to understand what works.

The harness generates one committed artifact — **`docs/support-matrix.md`** — from run results, grouped by ecosystem, with a uniform verdict vocabulary. That matrix *is* the baseline (together with `scripts/conformance/baseline.jsonl`). The scattered docs get a pointer to it. Both `docs/support-matrix.md` and the `scripts/conformance/` directory are **outputs the harness creates** — neither exists in the repo today; §8 specifies the first-run (absent-baseline) bootstrap behavior so the classifier never reads a file that is not yet there.

---

## 2. Goals / Non-goals

### Goals

- **One declarative manifest** (`scripts/conformance/suites.toml`) describes every suite. Adding a suite is a manifest edit, not a new script.
- **One Rust binary** (`crates/carrick-conformance`) orchestrates everything: select, run both engines, parse, classify, write results, render the matrix.
- **Drop-in symmetry.** The same image and the same trailing argv go to both `carrick run` and `docker run`. The oracle and the subject differ only in the engine and an explicitly-declared, schema-encoded set of per-engine flags/env (§4.1, §5.1) — never in an undeclared way.
- **Tiered execution.** A `smoke` tier is a fast regression gate (minutes). A `full` tier runs everything.
- **Generated, committed support matrix.** `docs/support-matrix.md` is rendered from results and checked in; it is the human-readable baseline.
- **A real regression gate.** A test that was MATCH and is now DIFF, and is not a known gap, fails the build with a non-zero exit.
- **Build-first.** Never test a stale or unsigned binary (the `just build` dependency is the guard; §1.1, §4.5).
- **Scoped process isolation** so the harness can run concurrently with other lanes, worktrees, CI agents, and the user's own processes without ever reaping one of them (§6).

### Non-goals

- **Not** a replacement for `crates/carrick-cli/tests/conformance.rs`. That probe gate is a deterministic, line-exact ABI oracle (byte-diff of static-musl ELF probes). It stays. The matrix *links* it. The two answer different questions: the probe gate proves *a specific syscall's bytes are right*; this harness proves *a real program behaves like Linux*.
- **Not** full LTP discovery. The harness runs a curated handful of LTP tests per area as a regression signal; whole-suite LTP discovery (~1436 tests) stays in `ltp-sweep.sh`, which the harness does **not** subsume.
- **Not** a new parallelism dependency. No rayon / num_cpus / crossbeam (none are in the lockfile). Concurrency is a hand-rolled `std::thread::scope` + `AtomicUsize` work-stealing pool, mirroring `conformance.rs::fan_out_indexed`.
- **Not** a security review, a performance benchmark, or a perf gate. `perf_*` probes are out of scope for the correctness diff.
- **Not** a cross-process resource governor. Run-id scoping (§6) makes two harness invocations *safe to reap independently*, but it does **not** bound their *combined* HVF/CPU load; running two full-tier harness invocations in two worktrees simultaneously will oversubscribe the host. §7.4 states this limit explicitly.

---

## 3. The drop-in insight

`carrick run <image> <cmd>` is, by construction, a drop-in for `docker run <image> <cmd>`. The CLI accepts the same image refs, the same `-v` / `-w` / `-e` / `--entrypoint` flags, the same command override. This is the whole leverage of the harness:

> **The harness runs both engines as subprocesses with identical trailing argv.**
> Oracle: `docker run --platform linux/arm64 --rm <image> <cmd>`
> Subject: `./target/release/carrick run <image> <carrick-envelope-flags> <cmd>`
> The only differences are the engine and an **explicitly-declared, schema-encoded** envelope (carrick's `--raw`/`--fs`/`CARRICK_RUN_ID`; docker's `--name`/`--platform`; and a small set of per-engine flags/env declared per suite, §4.1).

Two consequences shape the design:

1. **Full image under both engines; fast writable layer.** Suites run the *full image* (the composed OCI rootfs as the guest filesystem) under both engines, so the program sees the same files under carrick as under docker — the drop-in core. The carrick writable-layer backend is pinned to `--fs memory` (the fast in-memory overlay, docker's closest analog); `--fs host` would *also* present the image but via the slow cap-std seed-and-amplify path (§1.2), so coherent suites pin `--fs memory` **explicitly** rather than inherit the volume-dependent default. The failure mode to avoid for PATH-lookup / relative-name-exec tests (Go's `os/exec` TestString, LTP framework setup) is running with **no image** — the bare `run-elf` scratch — not the choice of writable backend; the harness always supplies an image. The genuinely empty scratch is reserved for the probe gate's `run-elf` discovery, where emptiness is the point.

2. **Docker is driven by the `docker` CLI as a subprocess — bollard is not used.** Both engines are `std::process::Command` subprocesses (`carrick run ...` and `docker run ...`), launched the same way, captured to **files** under `target/conformance/raw/`, never pipes. **This harness does not depend on bollard, futures-util, or tokio.** The entire docker side is CLI subprocess: `docker run --name conf-<run-id> ...` for the run, `docker inspect` for the authoritative exit code, and `docker kill` / `docker rm -f` for scoped cleanup (§4.2, §6.2). This is a deliberate departure from `crates/carrick-cli/tests/conformance.rs`, which mixes bollard (for its in-test container lifecycle) with raw `docker run -i`; the standalone harness has no in-test lifecycle needs that bollard simplifies, so it drops all three async deps as dead weight.

The pipe rule is load-bearing, not hygiene theater: a wedged guest holding a stdout pipe survives the parent's `timeout` reaping — the pipe keeps the parent alive and the whole run hangs. Capture to a file; the file is closed independently of the guest's fate.

---

## 4. Architecture

One binary crate, `crates/carrick-conformance`, that shells out to the signed `target/release/carrick` and to the `docker` CLI. It links **none** of the guest stack (no `carrick-runtime`, no `applevisor`/HVF) — it is a pure orchestrator. The workspace glob `members = ["crates/*"]` auto-discovers it; **no root `Cargo.toml` edit is needed** and it must **not** be added to `exclude` (that list is only for the standalone `conformance-probes` crate, which has its own `Cargo.lock` and cross-compiles to musl).

The crate decomposes into six modules, each with exactly one job. The dependency arrows point downward: `main` orchestrates; `engine`, `parsers`, `verdict`, `matrix` are leaves it composes; `manifest` is the shared vocabulary everything reads.

```
                         ┌────────────┐
                         │  main.rs   │  orchestrator: select, two-phase exec,
                         │            │  write JSONL, set exit code, --bless,
                         └─────┬──────┘  --dry-run, --render-matrix
            ┌──────────────┬───┴────┬───────────────┬──────────────┐
            ▼              ▼        ▼                ▼              ▼
      ┌──────────┐  ┌───────────┐ ┌──────────┐ ┌──────────┐  ┌──────────┐
      │manifest.rs│  │ engine.rs │ │parsers/  │ │verdict.rs│  │ matrix.rs│
      └──────────┘  └───────────┘ └──────────┘ └──────────┘  └──────────┘
       suites.toml   run_carrick/   one Verdict-  MATCH/DIFF/   render
       serde structs  run_docker     Parser per   REGRESSION/   support-
                      -> RunOutput    ecosystem    ORACLE_FAIL/  matrix.md
                                      -> Suite-    TIMEOUT vs    from results
                                       Result      baseline
```

### 4.1 `manifest.rs` — the shared vocabulary

**Job:** define the serde structs that mirror `scripts/conformance/suites.toml`, and validate them.

**Interface:**
```rust
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Manifest { pub suite: Vec<Suite> }

#[derive(Debug, Clone, serde::Deserialize)]
pub struct EnvKv { pub key: String, pub val: String }

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Suite {
    pub name: String,
    pub ecosystem: Ecosystem,        // cpython | go | node | ltp
    pub image: String,               // registry ref handed to BOTH engines
    pub cmd: Vec<String>,            // trailing argv handed to BOTH engines
    pub verdict: VerdictParser,      // regrtest | gotest | tap | ltp | shell
    pub tier: Tier,                  // smoke | full
    pub weight: Weight,              // heavy | light
    pub timeout_s: u64,
    #[serde(default)] pub known_gaps: Vec<String>,   // test-ids or signatures
    #[serde(default)] pub entrypoint: Option<EnginePair<String>>, // see below
    #[serde(default)] pub carrick_flags: Vec<String>,// e.g. ["--fs","memory"]
    #[serde(default)] pub docker_flags: Vec<String>, // e.g. ["--user","65534"]
    #[serde(default)] pub bind_mounts: Vec<String>,  // -v specs, applied to BOTH
    #[serde(default)] pub env: Vec<EnvKv>,           // -e specs, applied to BOTH
    #[serde(default)] pub env_carrick: Vec<EnvKv>,   // -e specs, carrick side only
    #[serde(default)] pub env_docker: Vec<EnvKv>,    // -e specs, docker side only
    #[serde(default)] pub workdir: Option<String>,   // -w, applied to BOTH
}
```

**TOML shape — env is a table-array of `{key, val}`, NOT a tuple.** TOML has no tuple type and the `toml` crate maps an array-of-2-element-arrays to `Vec<Vec<String>>`, *not* `Vec<(String, String)>`. So `env` (and `env_carrick`/`env_docker`) deserialize from an array of inline tables:
```toml
env = [ { key = "NODEJS_CONFORMANCE_IN_IMAGE", val = "1" } ]
```
The `EnvKv` struct exists precisely so the interface type and the on-disk shape agree. The §5.2 examples use this form.

**Per-engine entrypoint and env.** Two fields *may* differ per engine, via `EnginePair<T> { both: Option<T>, carrick: Option<T>, docker: Option<T> }`:
- `entrypoint: Option<EnginePair<String>>`. For Node, **both** engines run the image's native conformance entrypoint, so `entrypoint = { both = "/usr/local/bin/nodejs-conformance" }` — the harness passes `--entrypoint /usr/local/bin/nodejs-conformance` to carrick *and* docker. carrick honors a native/`#!` entrypoint (the shebang-entrypoint support already landed), and docker accepts `--entrypoint` identically. The legacy `--entrypoint /bin/bash <image> /usr/local/bin/nodejs-conformance …` carrick workaround is **not** needed and is intentionally dropped — pinning the *same* entrypoint on both sides is what keeps the run symmetric and the `cmd` literally identical. The per-engine `carrick`/`docker` arms exist only for a hypothetical future suite that needs an asymmetric entrypoint; Node does not use them.
- `env_carrick` / `env_docker` carry the one var that *must* differ: `NODEJS_CONFORMANCE_EFFECTIVE_RUNNER=carrick` vs `=docker` (verified in `docker/nodejs-conformance/nodejs-conformance:119,138`). `env` carries the shared `NODEJS_CONFORMANCE_IN_IMAGE=1`.

**Trailing argv is identical — no exception.** With the entrypoint pinned the same on both engines, the `cmd` is byte-for-byte identical on both sides. For Node, `cmd = ["--runner","docker","--suite",<s>,"--line",<n>,"--timeout",<t>]` — the conformance flags only; the entrypoint binary is supplied by `--entrypoint`, never repeated in `cmd` (repeating it would double the entrypoint on the docker side). The drop-in invariant (Goals, §3, §14) is therefore literal: **identical trailing `cmd` argv on both engines**, the *only* per-engine difference being the `EFFECTIVE_RUNNER` env value. The harness records the full resolved argv for both engines in the JSONL so a reviewer can confirm the match.

**Dependencies:** `serde` (derive), and the `toml` crate. **`toml` is NOT currently a workspace dependency** — it must be added to the root `[workspace.dependencies]` (`toml = "0.8"`) first, then pulled in here as `toml = { workspace = true }`. This is the only new workspace dependency this crate introduces.

**Validation (unit-tested):** `Manifest::validate()` rejects:
- an empty `cmd`, a `timeout_s == 0`, a duplicate `name`, an empty `known_gap` string;
- an `image` with no registry host for any ecosystem that requires a pull (the "n=0 trap": carrick can't pull a bare daemon ref, every test reads as n=0, looks like a mass regression);
- **a coherent-rootfs suite (`ecosystem ∈ {cpython, go, node}`, or any `ltp` suite) that does not pin `--fs` to a backend in `carrick_flags`** (the case-sensitive-volume default surprise, §1.2): it must list **`--fs memory`** (the standardized fast overlay) — or explicitly opt into `--fs host` if it genuinely wants the cap-std real-fs path. A suite that pins neither is rejected with a message naming the volume-dependent-default hazard, so no suite's writable-layer backend (and wall-clock) silently depends on which volume it runs from.
Validation is a pure function so it can be a unit test fixture.

### 4.2 `engine.rs` — symmetric subprocess execution

**Job:** run one suite on one engine, capture to files, enforce timeout, clean up scoped.

**Interface:**
```rust
pub struct RunOutput {
    pub stdout_path: PathBuf,   // target/conformance/raw/<run_id>.out
    pub stderr_path: PathBuf,   // target/conformance/raw/<run_id>.err
    pub exit_code: i32,         // authoritative; docker via `docker inspect`
    pub duration: Duration,
    pub timed_out: bool,        // hit timeout_s -> scoped kill fired
    pub run_id: String,         // the unique per-run id (§6), recorded in results
    pub argv: Vec<String>,      // full resolved argv, recorded in JSONL for audit
}

pub fn run_carrick(suite: &Suite, run_id: &str) -> anyhow::Result<RunOutput>;
pub fn run_docker (suite: &Suite, run_id: &str) -> anyhow::Result<RunOutput>;
```

**`run_carrick`** builds:
```
./target/release/carrick run
    <docker-compatible flags: -v, -w, -e, --entrypoint(carrick-or-both)>
    <image>
    <carrick_flags: e.g. --raw, --fs memory>
    <cmd...>
```
**Flag-ordering — the real, code-enforced constraint.** In `crates/carrick-cli/src/args.rs` the `Run` variant declares `image: String` as a positional and `command: Vec<String>` with `#[arg(trailing_var_arg = true, allow_hyphen_values = true)]`; `--raw` and `--fs` are *ordinary* clap optional flags. `trailing_var_arg` captures the **first bare positional token and everything after it** into `command`. Therefore the only hard rule clap enforces is: **the carrick envelope flags (`--raw`, `--fs ...`) and the image must precede the first `cmd` token.** It is *not* a hard image-relative ordering — `carrick run --raw --fs memory <image> <cmd>` and `carrick run <image> --raw --fs memory <cmd>` parse identically. The harness adopts the convention **`<image>` then `<carrick_flags>` then `<cmd>`** (envelope flags after the image, before the command) because that is how every existing driver writes it; the implementer must understand the convention is for consistency, and the *enforced* constraint is "envelope flags before the first command token." The docker-compatible flags (`-v`/`-w`/`-e`/`--entrypoint`) are conventionally placed before the image (mirroring `docker run`); this front/back asymmetry is cosmetic, not semantic.

Env: `CARRICK_RUN_ID=<run_id>` (always); `CARRICK_INSECURE_REGISTRIES=<inferred from image host>` (always, when the image ref has a `localhost:<port>/` prefix); plus `env` ∪ `env_carrick` from the manifest. The child is spawned with `.process_group(0)` so the whole guest tree can be group-killed.

**`run_docker`** builds:
```
docker run --name conf-<run_id> --rm --platform linux/arm64
    <docker_flags> <-v, -w, -e (env ∪ env_docker), --entrypoint(docker-or-both)>
    <image> <cmd...>
```
No carrick env. `--name conf-<run_id>` is load-bearing for scoped cleanup (§6.2). **Pre-run idempotent cleanup (resolves the deterministic-name collision hole):** because run-ids are deterministic `conf-<pid>-<seq>` (§6.1) and a pid is reused by the OS over time, a previous crashed run may have left a container named `conf-<run_id>`; `docker run --name` would then fail with a name conflict. So `run_docker` issues `docker rm -f conf-<run_id>` **before** the `docker run` (idempotent — succeeds whether or not such a container exists), guaranteeing the `--name` is free. The authoritative exit code comes from `docker inspect --format '{{.State.ExitCode}}' conf-<run_id>` **before** the `--rm` auto-removal races it; the harness inspects, then `docker rm -f` to be certain.

**Timeout & cleanup:** each run is bracketed by a watcher (200ms poll, mirroring `conformance.rs`). On `elapsed > timeout_s`:
- carrick: `libc::kill(-pid, SIGKILL)` on the process group, **then** `sudo -n scripts/sudo/kill.sh <run_id>` as the belt for any guest that escaped the group via `setpgid`/`setsid`.
- docker: `docker kill conf-<run_id>` then `docker rm -f conf-<run_id>`.
`timed_out = true` is recorded; the captured-so-far output stays on disk for triage.

**Registry inference:** from the image host. `localhost:5050/...` → `export CARRICK_INSECURE_REGISTRIES=localhost:5050`; `localhost:5005/...` → `localhost:5005`. (cpython + ltp images live on `:5050`; go + node images on `:5005`. Neither is `:5000` — macOS ControlCenter holds `:5000`.) A bare daemon ref with no registry host is a validation error (§4.1) for any ecosystem that requires a pull.

**Dependencies:** `std::process`, `libc`, `anyhow`. **No bollard, no futures-util, no tokio** — the docker side is pure `docker` CLI subprocess (§3). Capture-to-file means the ~96MB failure dumps (e.g. `runtime.test`) land on disk, never in the harness's own stdout.

### 4.3 `parsers/` — one `VerdictParser` per ecosystem

**Job:** map an engine's raw captured output into a normalized per-test outcome map. Each parser is a small, pure, **independently unit-testable** function over checked-in fixtures. This is where the parse logic of the four legacy drivers is *lifted into Rust* (the relationship; §13).

**Interface:**
```rust
pub struct SuiteResult {
    pub totals: Totals,                  // n, passed, failed, broken, skipped...
    pub result: SuiteOutcome,            // SUCCESS | FAILURE | NONE (mid-run crash) | EMPTY
    pub ids: BTreeMap<String, Outcome>,  // test-id -> ok|fail|error|skipped|xfail|...
}
pub trait VerdictParser { fn parse(&self, raw: &Raw) -> SuiteResult; }
```
where `Raw { stdout: String, stderr: String, exit_code: i32, timed_out: bool }`.

The five parsers, each reproducing the exact logic of its legacy driver:

- **`regrtest`** (CPython, from `cpython-parity.py:33-70`). Per-test line regex `^(\S+) \(([\w.]+)\)(?: \[\d+\])? \.\.\. (.*)$` — group 2 (dotted id) is the key. Classify the trailing rest by prefix: `ok`→ok, `FAIL`→FAIL, `ERROR`→ERROR, `skipped`→skipped, `expected failure`→xfail, `unexpected success`→uxsuccess, else→other. **First-occurrence-wins per id** (`setdefault`): a later subtest line for the same id is ignored. Summary: `^Result:\s*(\w+)` → result (absent ⇒ `NONE`, signalling a mid-run crash/hang, distinct from a clean FAILURE); `Total tests:\s*run=(\d+)`. **Strip carrick advisory lines** (`case-insensitive`, `Pass --fs`, ``Pass `--fs``) before parsing or they pollute the parse. **This regex is non-trivial** (optional `[N]` group, dotted-id `[\w.]+` char class) — see the parser-dependency note below: it is implemented with the `regex` crate, not hand-rolled.

- **`gotest`** (Go, from `go-conformance.sh`). Plain `go test -test.v` text, **not** test2json. Extract `^--- (PASS|FAIL): <Test>` lines, normalize to `PASS <Test>` / `FAIL <Test>`, sort -u. **CRASH guard first:** if the carrick log contains any of `failed to run static ELF | fault not handled by trap path | UnexpectedException | trap engine failed`, treat as a guest abort (one root-cause gap = the test after the last PASS, plus the `esr=0x...`), suppressing false "absent" downstream tests — do **not** count post-crash absences as N gaps. **This crash-guard pattern is generalized at the classifier level too** (see §4.4 and the *missing-side* rule), so any parser that yields `result == NONE` is treated as a single crash verdict, not a per-id diff storm.

- **`tap`** (Node, libuv + node-core). Parse the TAP stream the underlying runners already emit: `ok N - <name>`, `not ok N - <name>`, `# SKIP`/`# TODO` directives, and the `1..N` plan; honor `Bail out!`. **This is a genuinely new parser, not a lift of the legacy logic, and is scoped as its own milestone (§13, §14):** the legacy Node harness recorded only a coarse PASS/TIMEOUT/FAIL suite verdict (from the `timeout -s KILL` exit code: 0→PASS, 124/137→TIMEOUT, else→FAIL) plus one signature line. The harness ships in two stages for Node: **(stage 1)** reproduce that exact coarse verdict — `SuiteResult.ids` carries a single synthetic id whose outcome is PASS/TIMEOUT/FAIL plus the signature; this matches the other ecosystems' initial fidelity and is enough to gate v24-green / v26-red. **(stage 2)** add the real per-test TAP parse (`ok`/`not ok`/`1..N`/`# SKIP`/`# TODO`/`Bail out!`) so the matrix shows true per-test granularity (node-core ~5304 tests, libuv ~507). The first deliverable is stage 1; stage 2 is a follow-up milestone. The manifest does not change between stages — only the `tap` parser deepens.

- **`ltp`** (LTP, from `ltp-check.sh`/`ltp-full-sweep.sh`). Two-tier extraction over combined stdout+stderr:
  - **Tier 1** (new-API): the `Summary:` block — `grep -oE "passed +[0-9]+|failed +[0-9]+|broken +[0-9]+"`, joined → e.g. `passed 5 failed 1 broken 0`. (`skipped`/`warnings` deliberately **excluded** from the verdict key so a differing skip count doesn't split a MATCH.) If non-empty, this *is* the verdict.
  - **Tier 2** (old-API fallback): count per-line tokens `p=TPASS, fa=TFAIL, b=TBROK, c=TCONF`. All-zero (`0000`) → empty verdict (crashed before any token). Else literal `P<p> F<fa> B<b> C<c>`.
  - rc 124/137 → prepend `TIMEOUT/` to the verdict. Strip carrick banners (`case-insensitive|Pass .--fs`) before counting. **TBROK is a hidden test** (framework setup broke), not a fail; **TCONF on both sides verifies nothing**.

- **`shell`** (deterministic shell snippets, the probe-gate vocabulary). Concatenate stdout+stderr, `normalize()` (drop carrick scratch notices, trim), byte-compare. Used for any small deterministic suite that does not need a richer parser.

**Dependencies:** `serde`/`serde_json` (for fixtures), `std`, and **`regex`** (workspace dep). *Decision (was deferred):* the `regrtest` line regex (optional `[N]` group, dotted-id char class) and the Go `--- (PASS|FAIL):` extraction are error-prone to hand-roll faithfully, and a subtly wrong hand-rolled matcher is exactly the kind of silent parse bug this harness exists to eliminate. We therefore **add `regex = "1"` to the root `[workspace.dependencies]`** and use it in the parsers. (This is the second and final new workspace dependency, alongside `toml`; both are listed in §14 step 1.) The LTP token counting and the `tap` line classification are simple enough for `str` matching, but may use `regex` for consistency.

### 4.4 `verdict.rs` — the classifier

**Job:** given a carrick `SuiteResult`, a docker `SuiteResult`, the suite's `known_gaps`, and the committed baseline (which may be absent on the first run, §8), produce one verdict per suite.

**Single source of truth for "is a divergence acceptable" (resolves the known_gaps-vs-baseline ambiguity).** A per-id divergence is **excused** if and only if it satisfies **either** of two independent excusers, evaluated in this order:
1. **`known_gaps` (static, authored):** the id (or a signature substring) is listed in the suite's `known_gaps`. This is the *authored* statement "this divergence is expected and tracked." Always-on; works on the first run when there is no baseline.
2. **baseline (dynamic, observed):** the id's `(carrick, docker)` outcome pair is **identical** to the pair recorded in `baseline.jsonl` for the same id (an *unchanged* divergence). This catches divergences that predate any authored gap.

They are an **OR**, not an AND: a divergence excused by *either* is green. The combined rule is therefore exactly:
> **REGRESSION** iff an id diverges AND it is **not** in `known_gaps` AND its `(carrick, docker)` pair **differs from** the baseline pair (i.e. it was MATCH-or-differently-divergent before and is a *new or worse* break now).

This makes the two §-cross-references consistent: a test that DIFFs, is not in `known_gaps`, but was already that-exact-DIFF in the baseline → **DIFF (green)**, because excuser 2 fires. A test that DIFFs, is not in `known_gaps`, and was MATCH (or a different divergence) in the baseline → **REGRESSION (red)**.

**Algorithm.** Take the union of test-ids. For each id, compare **outcome categories only** (never timings, tracebacks, or skip reasons — those are non-deterministic and would split MATCHes), using `<absent>` for an id missing on one side. Apply the excuser rule above. Then classify the suite:

| Verdict | Condition |
|---|---|
| `ORACLE_FAIL` | docker timed out **or** docker produced zero comparable tests (oracle hung/broke). Excluded from the regression denominator — never counted against carrick. |
| `TIMEOUT` | carrick timed out (a hang = a blocked syscall = a real gap). |
| `CARRICK_CRASH` | **carrick `result == NONE`** (mid-run crash/hang: no `Result:` tail / Go crash-guard hit / TAP `Bail out!`). Classified as **one** crash verdict for the whole suite, **not** a per-id diff storm — see the missing-side rule below. Gating: treated like `REGRESSION` (non-zero exit) **unless** the whole suite is itself a `known_gap` (e.g. `cpython-smoke`'s `test_subprocess`). |
| `MATCH` | every comparable id agrees (after applying the excuser rule). |
| `DIFF` | some comparable id diverges, but **every** diverging id is excused (excuser 1 or 2). Green. |
| `REGRESSION` | at least one diverging id is excused by **neither** rule (per the boxed iff above). **Non-zero exit.** |

**The missing-side / crash rule (resolves the diff-storm hole).** A carrick mid-run crash makes *every downstream id* `<absent>` on the carrick side. Against a fully-passing docker side that would explode into hundreds of spurious `REGRESSION`s. So the classifier **special-cases `carrick.result == NONE` (or `timed_out`) as a single `CARRICK_CRASH`/`TIMEOUT` suite verdict and does NOT run the per-id diff** — the suite reports one root-cause verdict, exactly as the Go `gotest` crash-guard does for its own parser, now generalized to the classifier so it applies to every ecosystem. Symmetrically, `docker.result == NONE`/`timed_out` → `ORACLE_FAIL`, also short-circuiting the per-id diff. Only when *both* sides produced comparable per-test output does the id-union diff run.

The asymmetry between `DIFF` (green) and `REGRESSION` (red) is the entire point: we accept a known, tracked, or unchanged divergence; we reject a *new* break. `ORACLE_FAIL` is its own class precisely because the LinuxKit oracle is imperfect (it hangs on some node-core tests, fails 14 libuv tests carrick passes, times out on `test_threading`) — letting an oracle hang count against carrick would make carrick look worse than it is.

**Dependencies:** `manifest`, `parsers`, `serde_json` (read baseline). Pure function; unit-testable with synthetic `SuiteResult` pairs, including the absent-baseline (§8) and crash-storm cases.

### 4.5 `main.rs` — the orchestrator

**Job:** parse args, sanity-check the binary, select suites, run the two-phase execution, classify, write JSONL, render the matrix on demand, set the exit code.

**CLI (clap):**
```
carrick-conformance
  --tier <smoke|full>        select by tier (default: full)
  --ecosystem <cpython|go|node|ltp>   filter (repeatable)
  --suite <name>             filter to named suites (repeatable)
  --manifest <path>          default scripts/conformance/suites.toml
  --baseline <path>          default scripts/conformance/baseline.jsonl
  --jsonl <path>             results output (default target/conformance/results.jsonl)
  --bless                    rewrite baseline + matrix from this run's results (guarded; see below)
  --render-matrix            render docs/support-matrix.md from latest results and exit
  --dry-run                  print the planned carrick + docker argv for each suite, no exec
```

**Freshness sanity check (the stale-binary backstop, §1.1b).** Before any run, stat `target/release/carrick`. If it is **missing**, **abort** with a message telling the developer to `just build` (`std::process::exit(2)`) — a missing binary cannot be tested. If it is **present but its mtime is older than the newest file under the *runtime* crates** (`crates/carrick-runtime`, `crates/carrick-hvf`, `crates/carrick-host`, `crates/carrick-abi`, `crates/carrick-mem`, `crates/carrick-guest-mem`, `crates/carrick-cli` — *not* all of `crates/`), **emit a loud stderr warning and continue**. It is a **warning, not an abort**, for two concrete reasons:
1. On the normal `just` path the `build` dependency already rebuilt the signed binary, so this check is *belt to that suspenders* — it must not veto a run `just` already vouched for.
2. **Incremental cargo does not bump the artifact mtime when nothing changed.** A strict "binary newer than every crate file" *abort* would spuriously fire immediately after a successful `just build` (cargo left the unchanged `target/release/carrick` untouched, so its mtime predates a freshly-`touch`ed or git-checkout-updated source file). Scoping the comparison to the runtime crates and downgrading to a warning removes the false-abort while preserving the off-`just`-path signal a developer needs.

This is deliberately *narrower and softer* than an all-of-`crates/` abort: it will not misfire on an unrelated crate file, a git checkout that bumps mtimes, or cargo's no-op rebuild.

**Signed-binary check.** Mirror `conformance.rs::ensure_signed`: run `codesign -d --entitlements -` and grep for `com.apple.security.hypervisor`. *Decision (was a choice-menu):* **the harness does NOT auto-re-sign. If the entitlement is absent it ABORTS** (`std::process::exit(2)`) with the exact instruction `run 'just build' (or ./scripts/build-signed.sh) — the binary is unsigned and every guest run will be HV_DENIED`. Rationale: the `just` recipes already depend on `build`, which signs; an unsigned binary at this point means the developer bypassed `just`, and the correct response is to tell them to use the build path, not to silently re-sign behind their back (which would also race a concurrent test re-signing the same file). `scripts/entitlements.plist` is referenced only in the abort message as the manual recovery command *(present in the repo — confirmed)*; the harness itself never invokes `codesign --force`.

**Dependencies:** all of the above modules, `clap`, `anyhow`.

**`--bless` safety (resolves the bless-safety gap).** `--bless` rewrites `baseline.jsonl` and `docs/support-matrix.md` from the current run. It is **guarded**:
- **Refuses a filtered run.** `--bless` is rejected (non-zero exit, no write) if combined with `--suite` or `--ecosystem`, or with `--tier smoke` — blessing a partial run would wipe baseline rows for the unrun suites. `--bless` requires a **full-tier, unfiltered** run (`--tier full`, no `--suite`/`--ecosystem`).
- **Refuses to bless a broken oracle or a carrick hang.** If the run contains **any** `ORACLE_FAIL`, `TIMEOUT`, or `CARRICK_CRASH` verdict, `--bless` aborts (non-zero exit, no write) and lists the offending suites — blessing a hung oracle or a carrick hang as the new baseline would permanently hide a real gap. The developer must resolve or explicitly `known_gap`-annotate those suites first. (A suite that is *intentionally* red and tracked via a whole-suite `known_gap`, e.g. `cpython-smoke`, classifies as `DIFF`/excused, not `CARRICK_CRASH`, so it does not block bless.)

### 4.6 `matrix.rs` — the support-matrix renderer

**Job:** render `docs/support-matrix.md` from the results JSONL. Deterministic output (stable sort), so the committed file diffs cleanly. See §9 for columns and grouping.

**Dependencies:** `serde_json` (read results), `std::fmt`.

---

## 5. The manifest schema (`scripts/conformance/suites.toml`)

One `[[suite]]` table per suite. The same `image` and the same trailing `cmd` are handed to **both** engines; engine-specific differences live only in the schema-declared `carrick_flags` / `docker_flags` / `env_carrick` / `env_docker` / per-engine `entrypoint` (§4.1). Below are four real seed entries using the grounded image refs, argv, and known-gaps from the research. (Full first-manifest scope in §10.)

### 5.1 Field reference

| Field | Type | Meaning |
|---|---|---|
| `name` | string | unique suite id (matrix row key) |
| `ecosystem` | enum | `cpython` \| `go` \| `node` \| `ltp` (matrix grouping) |
| `image` | string | registry ref handed to both engines; host → registry inference |
| `cmd` | string[] | trailing argv handed to both engines (byte-identical) |
| `verdict` | enum | `regrtest` \| `gotest` \| `tap` \| `ltp` \| `shell` |
| `tier` | enum | `smoke` \| `full` |
| `weight` | enum | `heavy` (serial within phase) \| `light` (pooled) |
| `timeout_s` | int | per-run hard kill |
| `known_gaps` | string[] | test-ids / signatures excluded from the regression verdict (excuser 1, §4.4) |
| `entrypoint` | table? | per-engine `--entrypoint`: `{ both = ".." }` or `{ carrick = ".." }` / `{ docker = ".." }` |
| `carrick_flags` | string[] | carrick-only envelope flags (after image, before cmd); coherent suites MUST pin `--fs` (`--fs memory` — the fast overlay), never leave it to the volume default |
| `docker_flags` | string[] | docker-only flags (e.g. `--user 65534`) |
| `bind_mounts` | string[] | `-v` specs applied to both |
| `env` | `{key,val}`[] | `-e` specs applied to both (table-array, §4.1) |
| `env_carrick` | `{key,val}`[] | `-e` specs, carrick side only |
| `env_docker` | `{key,val}`[] | `-e` specs, docker side only |
| `workdir` | string? | `-w` applied to both |

### 5.2 Example entries (real, grounded)

```toml
# ---- CPython: smoke representative (multithreaded-fork cluster) ----
[[suite]]
name        = "cpython-smoke"
ecosystem   = "cpython"
image       = "localhost:5050/cpython-test:3.12.13"
cmd         = ["/usr/local/bin/python3", "-m", "test", "-v", "--randseed", "0",
               "test_subprocess", "test_threading"]
verdict     = "regrtest"
tier        = "smoke"
weight      = "heavy"
timeout_s   = 180
carrick_flags = ["--raw", "--fs", "memory"]   # COHERENT rootfs; envelope flags before cmd
known_gaps  = [
  "test_subprocess",   # DIFF: cluster-1 nested-fork HVF wedge (HV_BUSY/leaked-vCPU)
  "test_threading",    # ORACLE_FAIL: oracle hung ~200s in LinuxKit VM, not a carrick gap
]
# image baked with Lib/test (--bundled form): NO bind-mount; python3 is the ABSOLUTE path.

# ---- Go: smoke health-check package ----
[[suite]]
name        = "go-runtime"
ecosystem   = "go"
image       = "localhost:5005/carrick-go-conformance:1.24"
cmd         = ["/conformance/runtime.test", "-test.run", "Test", "-test.short"]
verdict     = "gotest"
tier        = "smoke"
weight      = "heavy"
timeout_s   = 120
carrick_flags = ["--raw", "--fs", "memory"]
workdir     = "/usr/local/go/src/runtime"
known_gaps  = [
  "TestGdb", "TestLldb", "TestCgo", "TestTracebackSystem",  # SKIPPED both sides
]
# fully green 341/341 after the BRK->SIGTRAP fix; CAUTION: failures dump ~96MB — cap output.

# ---- Node: libuv (must run as non-root) ----
[[suite]]
name        = "node-libuv"
ecosystem   = "node"
image       = "localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0"
entrypoint  = { both = "/usr/local/bin/nodejs-conformance" }  # native entrypoint on BOTH engines
cmd         = ["--runner", "docker", "--suite", "libuv", "--line", "24", "--timeout", "120"]
verdict     = "tap"
tier        = "full"
weight      = "heavy"
timeout_s   = 180   # OUTER host wall-clock on top of the in-image timeout
carrick_flags = ["--raw", "--fs", "memory"]
docker_flags  = ["--user", "65534"]
env         = [ { key = "NODEJS_CONFORMANCE_IN_IMAGE", val = "1" } ]   # shared
env_carrick = [ { key = "NODEJS_CONFORMANCE_EFFECTIVE_RUNNER", val = "carrick" } ]
env_docker  = [ { key = "NODEJS_CONFORMANCE_EFFECTIVE_RUNNER", val = "docker"  } ]
known_gaps  = [
  "kill", "spawn_exercise_sigchld_issue", "tcp_reuseport", "udp_reuseport",
  "udp_multicast_interface6", "udp_recvmsg_unreachable_error",
  "udp_recvmsg_unreachable_error6", "tty_pty_partial", "platform_output",
  # eintr_handling is a CONTENTION false-positive (passes solo) -> NOT a gap
]
# carrick 498/507 solo as uid 65534 (98.2%); EFFECTIVE_RUNNER (env_carrick/env_docker) carries the tag.
# Both engines run the native entrypoint via --entrypoint /usr/local/bin/nodejs-conformance, so the
# trailing `cmd` argv is byte-identical on both sides; only EFFECTIVE_RUNNER differs.

# ---- LTP: curated signals smoke, in the FULL coherent image ----
[[suite]]
name        = "ltp-signals-smoke-rt_sigaction01"
ecosystem   = "ltp"
image       = "localhost:5050/ltp:arm64"
cmd         = ["/opt/ltp/testcases/bin/rt_sigaction01"]   # one [[suite]] per binary
verdict     = "ltp"
tier        = "smoke"
weight      = "light"
timeout_s   = 40
carrick_flags = ["--fs", "memory"]   # fast overlay; pinned, not the slow cap-std host default
known_gaps  = []
# run the test binary DIRECTLY (no /bin/sh -c) to mirror docker. /opt/ltp is present under
# EITHER backend (the ltp image is the rootfs); --fs memory is pinned for SPEED + volume-
# independence — the volume default here is the slow cap-std `host` backend (§1.2), NOT because
# host lacks the files. --raw omitted (no-op alias for the default envelope).
```

Notes that the schema encodes:

- **CPython** passes `--raw --fs memory` (coherent rootfs) with the envelope flags before the `cmd`; entrypoint is the **absolute** `/usr/local/bin/python3`; the `--bundled` (baked-in `Lib/test`) form needs **no** bind-mount. Wrong registry ref (bare daemon tag, no `localhost:5050/`) → carrick can't pull → every module n=0 (the n=0 trap, rejected by validation).
- **Go** uses the prebaked image driver (true carrick verdicts, no bind-mount artifacts) with `-w` at the package's GOROOT src dir. The `runtime` package is the designated smoke package.
- **Node** runs the image's native `nodejs-conformance` entrypoint on **both** engines (`--entrypoint /usr/local/bin/nodejs-conformance`), with `--runner docker` *inside* the image; the carrick/docker distinction is carried **only** by `NODEJS_CONFORMANCE_EFFECTIVE_RUNNER` (`env_carrick`/`env_docker`). The trailing `cmd` is byte-identical on both sides — there is no entrypoint exception (the legacy `--entrypoint /bin/bash` carrick workaround is dropped now that carrick honors `#!` entrypoints; §4.1). libuv needs an unprivileged run (`--user 65534`) plus the in-entrypoint `setuid(1000)` drop. An **outer** host timeout is required *in addition to* the in-image `timeout -s KILL`.
- **LTP** uses one `[[suite]]` per test binary, run **directly** as argv (no `/bin/sh -c`), under `--fs memory` (the fast overlay) rather than the slow cap-std `--fs host` default. `/opt/ltp` is present under **either** backend (the ltp image is the rootfs); `--fs memory` is pinned for speed + volume-independence (§1.2), **not** because host lacks the files — and never left to the volume default. `--raw` is a no-op alias for the default envelope. (The Node v26 line is a separate Node suite, §10.3 — not LTP.)

---

## 6. Scoped process isolation (run-id) — the load-bearing invariant

> **This is an explicit, non-negotiable user requirement.** It is given its own section because it is the single invariant that lets the harness coexist with other lanes, worktrees, CI agents, and the user's own carrick/docker processes — and because violating it reintroduces the exact bug that forced every existing gate to run serially.

### 6.1 The requirement

**Every individual suite-run, on each engine, gets its own unique run-id.** The id is `conf-<orchestrator-pid>-<monotonic-seq>` where the seq is an `AtomicUsize::fetch_add` — **deterministic within a single harness invocation** (no random salt *inside* a run), so the JSONL is reproducible and traceable. Across *separate* invocations the pid varies; the **collision case that matters** — two invocations that happen to reuse the same pid (after a crash/restart) running concurrently in two worktrees — is handled not by salting the id but by the **idempotent pre-run `docker rm -f conf-<run_id>`** on the docker side (§4.2) and by the fact that the carrick scoped-kill matches only *live* `carrick:<run-id>` proctitles owned by guests this invocation spawned. The reviewer's collision concern is therefore real but is closed at the *mechanism* (pre-clean the name; scope to live procs) rather than by reintroducing nondeterminism into the id. Every cleanup or timeout-kill the runner performs is **scoped to exactly that one run-id** and can never reap an unrelated process — not a concurrent suite in the same run, not a parallel lane, not another git worktree's run, not a CI agent, not the user's own carrick or docker processes. The run-id is recorded per suite in the results JSONL.

### 6.2 Concrete mechanism

**(a) carrick lane.** Pass `CARRICK_RUN_ID=<run-id>` in the child env. carrick stamps it into the guest's process title — `carrick:<run-id>` (`proctitle.rs`), inherited across guest forks. Timeout/cleanup invokes:
```
sudo -n scripts/sudo/kill.sh <run-id>
```
`kill.sh` **requires** a run-id (`$1`); a bare invocation `exit 2`s. It matches only `ps` args containing `carrick:<run-id>` and SIGKILLs them in up to 3 passes. It **refuses a global reap.** As suspenders, the per-run watcher also does `libc::kill(-pid, SIGKILL)` on the process group (child spawned with `.process_group(0)`); the scoped `kill.sh` is the belt for a guest that escaped its group via `setpgid`/`setsid`.

**(b) docker lane.** Launch with `docker run --name conf-<run-id> ...`. **Pre-run:** `docker rm -f conf-<run-id>` (idempotent — clears any stale container of the same deterministic name from a prior crashed invocation, so `--name` can never collide, §4.2). Timeout/cleanup is:
```
docker kill conf-<run-id>   &&   docker rm -f conf-<run-id>
```
scoped to that exact container name. **Never** `docker kill $(docker ps -q)`, never an ancestor- or image-pattern reap, never touching a container the runner did not itself name.

### 6.3 The hard invariant

**The runner issues NO unscoped kill, EVER.**

- No bare `pkill -f carrick`.
- No `kill`-by-image or by ancestor.
- No `docker kill $(docker ps -q)`, no kill-by-image, no global reap.
- `kill.sh --all` (the global sledgehammer) is **manual recovery only** — the runner never calls it.

Every kill the runner performs names exactly one run-id (carrick) or one container name (docker). That is the whole invariant. The only `docker rm -f` that touches a name the runner is *about* to own is the idempotent pre-clean of that exact `conf-<run-id>` — still a single, named container, never a pattern reap.

### 6.4 Why (the bug this prevents)

An unscoped reap mid-run reaps sibling lanes, sibling worktrees, sub-agents, CI agents, and the developer's own running `carrick`/`docker` processes — and it looks, to all of them, like an unrelated flake. This is precisely the hazard that historically forced the conformance gate and the LTP sweeps to run **serially**: nobody could run two lanes at once without one reaping the other. Run-id scoping removes the *reaping* constraint. With it, `carrick‖carrick` and `docker‖docker` and lane‖lane and worktree‖worktree all coexist *without reaping each other*. (Reaping safety is **not** resource safety — see §7.4 for the separate, unsolved-by-this-spec concurrency-budget limit. And `carrick‖docker` remains forbidden for the resource-starvation reason of §7.1, distinct from reaping.)

---

## 7. Execution model

### 7.1 Two-phase, never carrick‖docker

The HVF guest and the Docker LinuxKit VM **starve each other** when run concurrently — they contend for the same CPU and the same arm64 virtualization resources, producing slow runs and *false* TIMEOUTs on timing-sensitive cases. The gate is therefore strictly two-phase:

1. **Phase 1 — all carrick.** Fan every carrick run across the worker pool. `carrick‖carrick` is fine and is the speed win.
2. **Phase 2 — all docker.** *Strictly after* phase 1 returns, fan every docker run across the pool. `docker‖docker` is fine.
3. **Phase 3 — pure classification.** Run neither engine; zip carrick results with docker results, classify (§4.4).

carrick and docker are **disjoint in time** — they never overlap. Do **not** collapse the phases into a carrick-then-docker-per-item loop inside the pool; that reintroduces overlap across workers. This mirrors `conformance.rs::conformance_probes` exactly.

### 7.2 Weight-aware concurrency (pinned scheduling contract)

The worker pool size is `available_parallelism().get().saturating_sub(2).clamp(1, 8)` (i.e. `min(cores-2, 8)`, floored at 1, default 4 if `available_parallelism` fails) — std only, **no** num_cpus/rayon. The fan-out is the hand-rolled work-stealing pool from `conformance.rs::fan_out_indexed` (`Vec<Mutex<Option<T>>>` slots + `AtomicUsize` cursor, `std::thread::scope`; poisoned mutexes handled with `.unwrap_or_else(|e| e.into_inner())`, never `.unwrap()` — the no-panic gate).

The scheduling rule is pinned to be deterministic to implement (resolving the heavy/light ambiguity). **Within a phase, AT MOST ONE `heavy` suite runs at a time. `light` suites pool freely up to the worker-count, concurrently WITH the single in-flight heavy suite.** Concretely:

- A single phase-wide `heavy_lock: Mutex<()>` (a token, count 1). A worker about to run a `heavy` suite acquires `heavy_lock`; it holds the lock for the duration of that one suite and releases it before taking another work item. So **two heavy suites never overlap** (not even two of the *same* engine/ecosystem) — they serialize against each other via the single token.
- `light` suites do **not** touch `heavy_lock`; they pool up to the worker count regardless of whether a heavy suite is in flight. So **light runs concurrently with the one heavy** and with other light suites.
- Net: at any instant, ≤ 1 heavy + up to `(worker_count − 1)` light. The rationale ("two heavy suites concurrently starve each other even on the same engine") is exactly the heavy-vs-heavy exclusion the single token enforces; heavy-vs-light is permitted because a light suite (e.g. one LTP binary) is cheap enough not to starve the heavy one.

### 7.3 Hygiene

- **Capture to files, never pipes.** A wedged guest holding a stdout pipe survives the parent's `timeout` reaping. Both engines write to `target/conformance/raw/<run_id>.{out,err}`.
- **Normalize before diff.** Strip carrick's host-only scratch notices (`case-insensitive; defaulting`, ``Pass `--fs host` ``) so its output lines up with docker's. Snippets/probes must emit no timestamps, pids, or hashes.
- **Oracle cancels, never blames.** A docker timeout or zero-comparable-test result → `ORACLE_FAIL`, excluded from the regression verdict. The oracle is imperfect (hangs on some node-core, fails 14 libuv tests carrick passes, times out `test_threading`); never let an oracle hang count against carrick.
- **Append-vs-truncate is explicit.** `results.jsonl` and `baseline.jsonl` are **truncate-and-rewrite per harness invocation**, not append. (The *legacy* drivers opened their `--jsonl` in append mode with last-wins-per-module dedupe-on-read; this harness owns the whole file each run, so it writes the complete current result set fresh and the matrix renderer reads it without a dedupe pass.) `--bless` copies the just-written `results.jsonl` to `baseline.jsonl` (subject to the §4.5 guards). The per-run raw `*.out`/`*.err` files are likewise overwritten by run-id, not appended.

### 7.4 Cross-invocation resource budget (a known, unenforced limit)

Run-id scoping (§6) makes two harness invocations *reaping-safe*, **not** *resource-safe*. Two full-tier invocations in two worktrees each spin up their own `min(cores-2, 8)` pool of HVF guests; together they oversubscribe the host CPU and the HVF budget the single-process pool was sized to respect, producing slow runs and false TIMEOUTs (the same starvation §7.1 avoids between engines). **This spec does NOT add a cross-process governor** (a host-wide semaphore/file-lock is out of scope for the first deliverable). The operational rule is documentary: **run at most one full-tier harness invocation at a time per host**; `--tier smoke` (a handful of suites) is cheap enough to overlap. A cross-process concurrency lock is noted here as a possible follow-up, explicitly out of the first deliverable's scope, so the "lanes coexist" claim of §6.4 is not over-read as "any number of full sweeps coexist."

---

## 8. Regression model

The baseline is two committed artifacts read together: **`scripts/conformance/baseline.jsonl`** (per-suite, per-test-id verdict data) and **`docs/support-matrix.md`** (the rendered headline). Together they answer "what did this commit change". **Neither exists in the repo today; both are first created by the first blessed run** (§10's scope-concern resolution: *baseline = first blessed run*, not hand-transcribed).

**First-run / empty-baseline bootstrap (resolves the bootstrap gap, and the npm-smoke placeholder).** On a run where `baseline.jsonl` is **absent** (or a suite/id has no baseline entry):
- Excuser 2 (baseline match, §4.4) is simply unavailable for that id — there is nothing to compare against.
- The classifier therefore **cannot emit `REGRESSION`** for an id with no baseline entry: a divergence excused by neither `known_gaps` nor a (nonexistent) baseline entry is classified as **`NEW` (non-gating)**, not `REGRESSION`. `NEW` is a green, write-only verdict meaning "first observation of this id/suite; recorded, nothing to regress against."
- Consequently the **first run is write-only and cannot fail the gate on a missing baseline** — it populates `baseline.jsonl` (via `--bless`, subject to §4.5 guards) and renders the matrix. Only the *second* and later runs, now with a baseline, can emit `REGRESSION`.

This is exactly the rule for **`npm-smoke`**, whose reviewer-flagged placeholder is hereby resolved: on the first run, `npm-smoke` has no baseline entry and (per §10.3) no `known_gaps`, so it is classified **`NEW` (non-gating)** — it is recorded and surfaced in the matrix, and **does not fail `just conformance-quick`** even if carrick ≠ docker. It becomes gateable only after a human blesses a baseline for it. There is no "untracked-suite spurious failure" on the first run.

With a baseline present:
- A test that diverges, is **not** excused by `known_gaps`, and whose `(carrick, docker)` pair **differs from** the baseline pair → **REGRESSION** → the run exits **non-zero** (the boxed iff, §4.4).
- A divergence covered by `known_gaps`, **or** unchanged vs the baseline pair, is **green** (`DIFF`).
- A test that was failing/divergent in the baseline and now **MATCHes** is an **improvement** — flagged in the report, blessed into the baseline with **`--bless`** (which, under the §4.5 guards, rewrites both `baseline.jsonl` and the matrix from the current run).
- `just conformance-quick` runs `--tier smoke` and exits non-zero on **any** `REGRESSION` (or unexcused `CARRICK_CRASH`/`TIMEOUT`). This is the fast pre-merge gate (minutes).

`known_gaps` entries should cite their root cause (the seed list in §10 does). An entry's job is to say "this divergence is expected and tracked"; when the underlying fix lands, the gap is removed in the *same* commit, and a now-MATCHing test that was a known gap is surfaced as an improvement to bless. This mirrors the probe gate's `KNOWN_PROBE_GAPS` discipline (an unexpectedly-passing known gap is surfaced so the stale entry gets deleted).

---

## 9. The support matrix output

`matrix.rs` renders **`docs/support-matrix.md`**, committed, grouped by ecosystem, with a per-ecosystem headline line and a uniform verdict vocabulary.

**Columns:** `Ecosystem | Suite | tier | carrick | oracle | verdict | gaps`

**Headline format per side (resolves the fraction-vs-status ambiguity).** The `carrick` and `oracle` columns each render with a **single, deterministic rule keyed off the side's `SuiteResult`**, never an ad-hoc mix:
- If the side **timed out** → the literal `TIMEOUT`.
- Else if the side **crashed mid-run** (`result == NONE`) → the literal `CRASH`.
- Else if the side **produced comparable per-test ids** (`n > 0`, the `regrtest`/`gotest`/`tap`/`ltp`-tier-2 case) → the fraction **`<passed>/<n>`** (e.g. `498/507`, `341/341`). For LTP tier-1 (`Summary:` block), `passed` and `n = passed+failed+broken`, so the same `<passed>/<n>` rule applies (e.g. `5/6`).
- Else if the side produced **only a coarse suite outcome** (no per-test ids — e.g. the Node `tap` stage-1 coarse verdict, or a `shell` suite) → the status word from `SuiteOutcome` (`SUCCESS` / `FAILURE` / `EMPTY`).

So the column is a fraction exactly when there are per-test counts, and a status word exactly when there are not — the choice is determined by the parser's output shape, not left to the renderer. The rule is identical for both `carrick` and `oracle`.

- `verdict` — `MATCH` / `DIFF` / `REGRESSION` / `NEW` / `CARRICK_CRASH` / `TIMEOUT` / `ORACLE_FAIL`.
- `gaps` — count + short pointer to the known_gaps cluster.

**Per-ecosystem headline** example: `Go: 876/880 (4 known carrick-only: os/exec TestExplicitPWD, net raw-IP ×3)`.

**What it replaces.** This matrix becomes the single status source. The scattered docs get a one-line pointer to it: `docs/conformance-coverage.md` (the language-runtime snapshot), `docs/cpython-baseline/TRIAGE.md`, `docs/nodejs-baseline/TRIAGE.md`, and `docs/ltp-baseline/BASELINE.md`. The matrix also **links** the two things it does not subsume: `crates/carrick-cli/tests/conformance.rs` (the probe gate) and `ltp-sweep.sh` (full LTP discovery).

---

## 10. First-manifest scope

The first `suites.toml` seeds the four ecosystems below. **Seeding strategy (resolves the hand-transcription scope concern):** the `known_gaps` lists below are the *curation targets* drawn from the research, but the **`baseline.jsonl` itself is produced by the first blessed run, not hand-transcribed** (§8). The first run records every suite as `NEW` (no prior baseline), the human reviews it against the seeded `known_gaps` and the §10 narrative, and `--bless` captures it. This is lower-risk than hand-seeding every per-id verdict (which would have to *exactly* match the first run or produce a wall of spurious REGRESSION/improvement noise). The `known_gaps` strings below are still authored up front (they are the static excuser-1 list), but the dynamic per-id baseline is captured, not typed.

### 10.1 CPython — 41 baseline modules (`regrtest`, heavy, `--raw --fs memory`, abs `/usr/local/bin/python3`)

Smoke: `cpython-smoke` = `test_subprocess test_threading` (representative cluster-1). Full: the 41-module set driven module-by-module.

Seeded known_gaps (root-caused):
- **multiprocessing cluster** — deterministic guest SIGSEGV at `Pool(3)` creation (cluster-1 nested-fork HVF wedge, Bug B; verify via `forksleepfork` flake-rate, **not** `carrick trace` which Heisenbugs it). Modules: `test_concurrent_futures.*`, `test_multiprocessing_{spawn,fork,forkserver}.{processes,threads,manager,misc}`.
- **`test_subprocess`** — DIFF, cluster-1 nested-fork wedge (hundreds of forks; low flake rate breaks at n=1).
- **`test_socket`** — CARRICK_TIMEOUT in baseline; 40 SCTP skips are **out of scope** (macOS has no SCTP) → accepted DIFF.
- **`test_os`** — CARRICK_TIMEOUT (hangs partway via cluster-1 fork).
- **cluster-3 inode-identity** (`samestat(lstat,fstat)` false → `shutil.rmtree` refuses → tempdir cascade): `test_glob` (ndiff=15), `test_posixpath` (5), `test_tempfile` (32), `test_stat` (2).
- **cluster-4 fcntl** (`F_SETPIPE_SZ`/`F_GETPIPE_SZ` EINVAL; `F_NOTIFY`+`DN_MULTISHOT` — no macOS equivalent): `test_fcntl` (ndiff=4).
- **non-UTF8 filename handling** (hypothesis: `to_string_lossy`/`from_utf8_lossy` drops bytes): `test_sqlite3, test_httpservers, test_zipimport, test_import, test_cmd_line_script, test_ntpath, test_capi, test_cgi`.
- **asyncio** (likely cluster-1 fork-exec): `test_asyncio.test_{subprocess,events,sock_lowlevel,sendfile,unix_events}`.
- **single-test punch-list** (ndiff=1, triage individually): `test_time, test_resource, test_pty, test_thread, test_wait3, test_select, test_struct, test_itertools`.
- **`test_threading`** — ORACLE_FAIL (oracle hang, exclude). **`test_pipe`** — BOTH_EMPTY (not a real 3.12 module — harness artifact, not a gap).

Baseline target (`baseline.jsonl`, captured by the first run; the 2026-05-30 reference was 16 MATCH / 21 DIFF / 2 CARRICK_TIMEOUT / 1 ORACLE_FAIL / 1 BOTH_EMPTY; full 492-module sweep snapshot 2026-06-02: 425 MATCH / 18 DIFF, 86.4%).

### 10.2 Go — 9 default packages (`gotest`, prebaked image driver, `--fs memory`)

Smoke: `runtime` (fully green 341/341 after BRK→SIGTRAP). Full: `sync, sync/atomic, context, time, os/signal, os/exec, runtime, net, cgo-smoke`.

Seeded known_gaps — the **4 known carrick-only fails** plus the both-sides skips:
- `os/exec` **`TestExplicitPWD`** — cross-mount symlink/`$PWD` resolution gap.
- `net` **`TestInterfaceMulticastAddrs`**, **`TestIPConnRemoteName`**, **`TestIPConnSpecificMethods`** — raw-IP/multicast, need `CAP_NET_RAW` (`CARRICK_SUDO=1`).
- Both-sides SKIP (keep the diff fair): `TestGdb, TestLldb, TestCgo, TestTracebackSystem, TestGoLookupIPCNAMEOrderHostsAliasesFilesDNSMode`.
- `os/signal` `TestTerminalSignal` — environmental (needs controlling TTY), fails identically under plain docker.

Aggregate ~876/880; `os/exec`, `runtime`, `net` are **heavy** (concurrent fork+exec, 96MB dumps, DNS). `os/signal`+`os/exec` need a **coherent image rootfs** (`carrick run <image>` — e.g. `debian:stable-slim`) for PATH lookup / relative-name exec; the failure mode being avoided is running test binaries with **no image** (the bare `run-elf` scratch), not the writable-backend choice. Within an image they pin `--fs memory` for speed + volume-independence like every coherent suite (§1.2).

### 10.3 Node — app-smoke / v8-smoke / libuv / node-core (`tap`)

Smoke: `app-smoke`, `v8-smoke` (line 24). Full: `libuv`, `node-core`, `npm-smoke`.

Seeded known_gaps:
- **libuv (9 carrick-only, 498/507 = 98.2% solo as uid 65534):** `kill`, `spawn_exercise_sigchld_issue`, `tcp_reuseport`, `udp_reuseport`, `udp_multicast_interface6`, `udp_recvmsg_unreachable_error` (+`...6`), `tty_pty_partial`, `platform_output` (cosmetic, `UV_ENOENT` after numeric setuid). **`eintr_handling` is a contention false-positive** (passes solo) — exclude. carrick *passes* 14 tests the LinuxKit/root docker oracle fails (`fs_*`, `pipe_*` EOPNOTSUPP, iouring) — do not expect oracle parity on those (whitelist them as `ORACLE_FAIL`).
- **node-core (3 cosmetic, 5301/5304 = 99.9%):** `test-node-output-v8-warning`, `test-node-output-eval`, `test-node-output-errors` — exact-stderr snapshot mismatches; the oracle also fails `v8-warning` and hung mid-suite → accepted cosmetic, not regressions.
- **v26 known-red** (a **separate Node suite**, gated to `--line 24` green; this is a NODE fact, recorded here only): V8 init `Check failed: 0 == munmap(address, size)` and v26 app-smoke `Error: write EPIPE`. docker passes both. v24 is the working line.
- **npm-smoke — first-run behavior is now SPECIFIED (no placeholder):** there is no recorded carrick-vs-oracle baseline for npm-smoke and no `known_gaps` for it. Per §8, on the **first run it is classified `NEW` (non-gating)** — recorded and shown in the matrix, but it **cannot fail the gate**, even if carrick ≠ docker, because there is no baseline to regress against. It becomes gateable only once a human blesses a baseline for it. So the first `just conformance-quick` does **not** fail spuriously on npm-smoke.

libuv runs **unprivileged** (`--user 65534`) with an in-entrypoint `setuid(1000)` drop. An **outer host timeout** is required on top of the in-image `timeout -s KILL` (broad carrick suites can strand process trees past the in-guest timeout and block JSONL append).

### 10.4 LTP — a curated handful per area, in the FULL coherent image (`ltp`, `--fs memory`)

Smoke handful (deterministic both-MATCH rows, one `[[suite]]` per binary, run **directly** as argv, `--fs memory` mandatory):
- **signals:** `rt_sigaction01, rt_sigprocmask01, sigaction01, sigpending02, tgkill01, kill09`.
- **epoll:** `epoll_create01, epoll_ctl01, epoll_wait02, eventfd01, pipe01, poll01`.
- **timers:** `clock_gettime01, clock_getres01, gettimeofday01, time01, timer_create01, timerfd_create01`.
- **sched:** `gettid01, getcpu01, sched_getaffinity01, sched_yield01, sched_get_priority_max01, sched_get_priority_min01`.

Seeded known_gaps / exclusions (the dangerous traps):
- **EXCLUDE blocking/timeout-prone rows:** `pause01/02/03` (`__ulock` zombie-wake race), `abort01` (raises SIGABRT, different verdict shape), `select03/pselect02` (TBROK cluster), `clock_settime/clock_adjtime` (privileged → frequently `NO_ORACLE`).
- **EXCLUDE every `tst_timer_test.c` THRESHOLD test** ("slept too long"/"slept too short") — the LinuxKit arm64 VM has real timing jitter, so the *oracle* fails them while carrick passes (a timing-jitter **inversion**, not a carrick win).
- **Inversions are NOT automatic wins.** "carrick passes, docker fails" is produced by *either* (a) genuine oracle timing jitter (carrick more correct — exclude) *or* (b) carrick *under-enforcing* a check docker enforces (a **false pass** masquerading as superiority). **Verify each inversion individually** (read the failing docker assertion); never auto-exclude by signature.
- **futex_wait/futex_wake counts** are `__ulock`-zombie-wake-sensitive — keep out of the deterministic handful; they belong in the `futexshare` probe (the precise gate), not the count-based LTP row.
- **`clone` family** is fork/thread-creating and timing-sensitive — run 3× before believing a verdict; not in smoke.

Full LTP discovery (~1436 tests) stays in `ltp-sweep.sh` — the harness runs only the curated handful. **Note on the historical wall:** the uniform TBROK/TIMEOUT runs came from the **stale binary** (§1.1) and, for fs-heavy tests, the slow cap-std `--fs host` default (false *timeouts*) — **not** from missing framework files (`ltp-check.sh:57` already runs inside the ltp image, so `/opt/ltp` was present). Re-baseline under the fresh-binary + `--fs memory` configuration. Per-area reference (older runs): signals 73%, epoll 65%, timers 74%, sched 76%, overall 63% verified-MATCH of oracle-valid.

---

## 11. `just` recipes (build-first + freshness sanity check)

Mirror the existing `conformance: build` pattern. Every recipe depends on `build` (`./scripts/build-signed.sh`) so the signed binary the harness shells out to exists; this is the load-bearing freshness guard on the normal path. The runner *additionally* does the soft freshness sanity check (§4.5) as a backstop for off-`just` invocations.

```make
# Full unified conformance harness (needs Docker + signed binary; self-skips on absence).
conformance TIER="full" *ARGS: build
    cargo run -p carrick-conformance -- --tier {{TIER}} {{ARGS}}

# Fast pre-merge regression gate: smoke tier, non-zero exit on any regression.
conformance-quick: build
    cargo run -p carrick-conformance -- --tier smoke

# Render the committed support matrix from the latest results (no run).
matrix:
    cargo run -p carrick-conformance -- --render-matrix
```

`build` → `./scripts/build-signed.sh {{ARGS}}` (the signing path; a bare `cargo build` strips the codesignature → `HV_DENIED`). Because `just conformance` always rebuilds via the `build` dependency, the runner's freshness sanity check (§4.5) never fires on the `just` path — by design it is a *warning-only* backstop for the `cargo run -p carrick-conformance` direct invocation. `just clippy` (`cargo clippy --workspace --all-targets -- -D warnings`) and `just ci` already cover the new crate via `--workspace` — **no edit needed**.

---

## 12. Testing strategy

- **Per-parser unit tests vs checked-in fixtures.** Each of `regrtest`/`gotest`/`tap`/`ltp`/`shell` gets a `tests/fixtures/<ecosystem>/` directory holding real captured `*.out`/`*.err` pairs (one passing, one DIFF, one mid-run-crash/`NONE`, one TIMEOUT, one TBROK-wall for LTP). The parser is a pure function `Raw -> SuiteResult`, so the tests are fast, hermetic, and need neither carrick nor docker.
- **Classifier unit tests for the hard cases.** `verdict.rs` is exercised over synthetic `SuiteResult` pairs covering: a clean MATCH; a `known_gaps`-excused DIFF; a baseline-excused (unchanged) DIFF; a true REGRESSION (unexcused, baseline-was-MATCH); a `carrick.result == NONE` **crash storm** (assert it yields one `CARRICK_CRASH`, not N REGRESSIONs); an **absent-baseline first run** (assert every id is `NEW`, the run is write-only, no REGRESSION); and an `ORACLE_FAIL` short-circuit.
- **Manifest-validation test.** `Manifest::validate()` is exercised against a good manifest and against each rejection case (empty cmd, zero timeout, duplicate name, bare-daemon image ref, empty known_gap, **and a coherent suite missing `--fs memory`** — the case-sensitive-volume guard).
- **`--bless` guard tests.** Assert `--bless` is rejected on a filtered/smoke run, and rejected when the run contains any `ORACLE_FAIL`/`TIMEOUT`/`CARRICK_CRASH`.
- **`--dry-run`.** Prints the planned carrick **and** docker argv for every selected suite without executing either engine — the primary buildability check and the first thing to run after wiring the manifest. A reviewer can read the dry-run output and confirm the trailing `cmd` argv is identical on both sides (and that the only per-engine differences are the schema-declared entrypoint/flags/env).
- **Acceptance = the first full run.** The first `just conformance --bless` populates `scripts/conformance/baseline.jsonl` and `docs/support-matrix.md`. Those committed artifacts *are* the acceptance criterion: from then on, a regression is a real, diffable change to them.
- **No-panic gate.** `main.rs` is production code — `unwrap`/`expect`/`panic`/`todo`/`unimplemented` are **denied** (`[workspace.lints.clippy]`). Use `?`+anyhow, `let-else { return }`, `unwrap_or_else(|e| e.into_inner())` for poisoned mutexes, `checked_*`/`saturating_*` for size math (release builds have `overflow-checks = true`). A targeted `#[allow(clippy::panic)]` is sanctioned only where a hard abort is genuinely correct. `clippy.toml`'s `allow-*-in-tests` covers `#[cfg(test)]` only — **not** the bin's main path.

---

## 13. Relationship to the existing apparatus

- **Supersedes the orchestration of** `scripts/cpython-parity.py`, `scripts/go-conformance.sh` (+`go-conformance-image.sh`), `scripts/nodejs-conformance-image.sh`, and `ltp-sweep.sh`. Their **parse logic is lifted into the Rust parsers** (§4.3); the scripts are kept for **one release** (cross-check the harness against them) and then archived.
- **Parser-fidelity is phased, not promised all-up-front (resolves the four-parser scope concern).** The first deliverable lands the **coarsest faithful parse per ecosystem** that still gates correctly: `regrtest` and `ltp` are lifted faithfully from day one (their legacy logic *is* per-id and is the gate); `gotest` lands with its `--- PASS/FAIL` extraction and CRASH guard; **`tap` lands as the coarse PASS/TIMEOUT/FAIL stage-1 verdict** (§4.3), matching the legacy Node fidelity, with the true per-test TAP parse as a named **stage-2 follow-up milestone**. The one-release cross-check against the four originals validates the coarse parses first; deepening `tap` (and any per-id refinement) is a subsequent milestone, not a precondition of the first landing. This keeps the first deliverable bounded.
- **Complements (does not replace)** `crates/carrick-cli/tests/conformance.rs` — the deterministic, line-exact ABI probe gate over static-musl ELF probes. That gate stays as the *precise* durable guard (a count-based MATCH proves the same *number* of assertions passed, not the same *assertions* — only a probe pins the exact bytes). The matrix **links** it.
- **Does not subsume** full LTP discovery (`ltp-sweep.sh`); the harness runs only a curated handful per area as a regression signal. The matrix links the sweep.

The division of labor is deliberate: **probes** are the line-exact gate (a fix lands with its probe); the **harness** is the broad behavioral signal (does a real program behave like Linux) and the committed, diffable status of the project; the **sweep** is discovery (find the next gap). All three are referenced from one place — the support matrix.

---

## 14. Implementation checklist (buildable order)

1. Add **`toml = "0.8"`** and **`regex = "1"`** to root `[workspace.dependencies]` (the only two new workspace deps). `mkdir -p crates/carrick-conformance/src`; write `Cargo.toml` (inherit `version/edition/license.workspace`; `[lints] workspace = true`; deps `anyhow`, `libc`, `serde` {derive}, `serde_json`, `toml`, `regex`). **No bollard/futures-util/tokio** — the docker side is pure `docker` CLI subprocess (§3, §4.2).
2. `manifest.rs` + the `EnvKv` / per-engine `entrypoint`/`env` shape (§4.1) + `Manifest::validate()` (incl. the **`--fs memory` coherent-suite guard** and the n=0 bare-ref guard) + validation unit tests.
3. `scripts/conformance/suites.toml` with the §10 seed entries; run `--dry-run` and confirm identical trailing `cmd` argv on both engines (and the only per-engine differences are the declared entrypoint/flags/env).
4. `parsers/{regrtest,gotest,ltp,shell}.rs` + the **stage-1 coarse `tap`** parser + fixtures + unit tests (build the fixtures by capturing one real run per ecosystem). Stage-2 per-test TAP is a follow-up.
5. `engine.rs` (subprocess symmetry, capture-to-file, registry inference, per-run watcher, the **idempotent pre-run `docker rm -f`**, **run-id scoping §6**).
6. `verdict.rs` (classifier: the boxed REGRESSION iff, the **crash-storm short-circuit**, the **absent-baseline `NEW`** rule) + unit tests over synthetic `SuiteResult` pairs (§12).
7. `main.rs` (freshness *warning* + signed-binary *abort* §4.5, two-phase fan-out mirroring `fan_out_indexed` with the **single heavy-token** §7.2, truncate-rewrite JSONL §7.3, guarded `--bless` §4.5, `--render-matrix`, exit code).
8. `matrix.rs` (deterministic render, the **headline fraction-vs-status rule** §9).
9. `just conformance` / `conformance-quick` / `matrix` recipes.
10. First full run (`--bless`) → commit `baseline.jsonl` + `support-matrix.md`; add pointers from the four scattered status docs.

---

**Invariants a reviewer must check on every change to this harness:**
1. Both engines receive **identical trailing `cmd` argv** *and* the same `--entrypoint`; the only per-engine differences are the schema-declared `carrick_flags`/`docker_flags`/`env_carrick`/`env_docker` (e.g. `EFFECTIVE_RUNNER=carrick|docker`). The `EnginePair` `carrick`/`docker` entrypoint arms exist for a hypothetical future asymmetric suite, but no current suite uses them — Node pins the native entrypoint on both sides.
2. carrick and docker are **disjoint in time** (two-phase; never overlapping); at most one **heavy** suite runs at a time within a phase.
3. **Every** kill names exactly one run-id (carrick) or one container name (docker); the runner issues **no unscoped kill, ever**; the docker `--name` is pre-cleaned idempotently to survive deterministic-id reuse.
4. The runner **aborts on an unsigned binary** and **warns on a stale-looking one** (it never tests an unsigned binary; the soft freshness check never false-aborts after a no-op cargo rebuild).
5. Every **coherent-rootfs suite pins `--fs` explicitly** (`--fs memory` for language/LTP — the fast overlay; the case-sensitive-volume default is the slow cap-std `host` backend); validation rejects a coherent suite that leaves it to the volume default.
6. Output is captured to **files, never pipes**; `results.jsonl`/`baseline.jsonl` are **truncate-rewritten** (not appended); the matrix and baseline are **deterministic** and diff cleanly.
7. On an **absent baseline** the first run is **write-only** (`NEW`, non-gating); `--bless` is **guarded** (full-tier, unfiltered, no ORACLE_FAIL/TIMEOUT/CARRICK_CRASH).
