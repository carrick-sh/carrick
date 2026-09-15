# Conformance budget kill, serial confirmation and probe wedge watchdog — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Stop the harness reporting its own diagnostic budget as a carrick hang, confirm every load-killed row serially before it gets a verdict, bound every probe carrier with artifacts on breach, and let one Docker container populate both oracle parser profiles.

**Architecture:** The deadline that fired becomes a typed fact on the run output; transcript growth becomes positive progress evidence; a budget kill becomes its own non-gating, bless-blocking verdict resolved by a bounded serial Phase 1b; the existing opt-in `TestContainer::deadline` becomes default-ON and escalates to an external lldb capture only when the in-process abort sink cannot be consumed; Docker fills both profile rows from one captured transcript.

**Tech Stack:** Rust under `-D warnings`, `carrick-conformance` (bin-only), `carrick-embed`, `carrick-runtime`, `carrick-conformance-next`, signed HVF probe lane, Docker arm64 oracle.

**Spec:** docs/superpowers/specs/2026-09-15-conformance-budget-kill-and-wedge-watchdog-design.md

## Global Constraints

- `RUSTC_WRAPPER=""` prefixes every `cargo`/`just` invocation in this environment. Runtime lib tests need `RUST_TEST_THREADS=1`.
- **Never run carrick and Docker concurrently.** Every verification below is carrick-only or Docker-only, never both.
- No new shell script and no Python. New capability is a Rust module in an existing crate, or a `carrick debug` subcommand.
- `crates/carrick-conformance-next/**/*.rs` may not contain `Command::new(` — `scripts/conformance/check-next-strategy.py` (run by `just lint-domains`) rejects it.
- Opt-OUT, not opt-in: every new behaviour defaults ON with an exact `=0` hatch.
- `just check-matrix` must stay green: any render change is accompanied by a deterministic re-render in the same commit.
- Every new behaviour gets a red-first test that a gate executes. `carrick-conformance` and `carrick-conformance-next` in-file `mod tests` run under `just test` (`--lib --bins`); `tests/` targets do not unless listed in `just test-integration`.
- Reap by `CARRICK_RUN_ID` with `scripts/sudo/kill.sh`; never `pkill -f carrick`.

## Task 1: Deadline provenance and progress evidence

Files: `crates/carrick-conformance/src/engine.rs`.

Interfaces:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineOrigin { Declared, Fast, AdaptiveOracle, Cap }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CarrickDeadline { pub declared_s: u64, pub effective_s: u64, pub origin: DeadlineOrigin }

impl CarrickDeadline { pub fn is_diagnostic(self) -> bool; } // effective_s < declared_s

pub struct TimeoutEvidence { /* existing */ pub stdout_bytes: u64, pub stderr_bytes: u64,
                             pub ms_since_last_growth: Option<u64> }

pub fn classify_timeout_with_progress(
    evidence: &TimeoutEvidence, wall_ms: u64, progress_window_ms: u64,
) -> TimeoutKind; // Progressing wins over the duty/load ladder
```

- [ ] Write failing unit tests in `engine.rs::tests`: `budget_kill_is_named_by_the_deadline_that_fired` (an effective 14 s deadline against a declared 300 s one is `is_diagnostic()`; equal values are not), and `a_growing_transcript_is_never_blocked` (growth 500 ms before the kill with duty 0.02 and load 1.0 on 10 cores yields `Progressing`, where `classify_timeout` yields `Blocked`). Pin the exact sep14 rows in the test comments: `go-go_types` 14181 ms on a 2x5883+2000 budget, MATCH serially in 14672 ms.
- [ ] Run them red and keep the receipt: `RUSTC_WRAPPER="" cargo test -p carrick-conformance --bins budget_kill -- --nocapture`.
- [ ] Make `effective_carrick_timeout_s` return `CarrickDeadline` (keep its existing arithmetic and its existing test `carrick_timeout_is_fast_unless_the_oracle_proves_the_case_is_slow` passing unchanged), thread it through `run_carrick`/`run_one`, and store it on `RunOutput`.
- [ ] Sample `stdout_path`/`stderr_path` lengths in the existing 200 ms poll loop; keep the last growth instant; fill the new `TimeoutEvidence` fields at the kill, before `kill_scoped`. No new syscalls outside the existing poll cadence.
- [ ] Add `TimeoutKind::Progressing` (`as_str() == "progressing"`, `is_measurement_failure() == false`) and implement `classify_timeout_with_progress`. Keep `classify_timeout` pure and exported; the new function delegates to it when there is no growth evidence.
- [ ] Verify: `RUSTC_WRAPPER="" cargo test -p carrick-conformance --bins` green; `RUSTC_WRAPPER="" just clippy`.

## Task 2: BudgetKill verdict, report plumbing, matrix exhaustiveness

Files: `crates/carrick-conformance/src/verdict.rs`, `crates/carrick-conformance/src/main.rs`, `crates/carrick-conformance/src/matrix.rs`, `docs/support-matrix.md`.

Interfaces:
```rust
pub enum Verdict { /* existing */ BudgetKill }            // as_str() == "BUDGET_KILL"

pub struct CarrickRunFacts<'a> {
    pub timed_out: bool,
    pub deadline: Option<crate::engine::CarrickDeadline>,
    pub timeout_kind: Option<crate::engine::TimeoutKind>,
    pub result: &'a SuiteResult,
}
pub fn classify(suite: &Suite, facts: CarrickRunFacts<'_>, docker: &SuiteResult, baseline: &Baseline) -> Classification;
```

- [ ] Write failing tests in `verdict.rs::tests`: a diagnostic-deadline kill yields `Verdict::BudgetKill` with `gating == false`; a declared-deadline kill still yields `Verdict::Timeout` with `gating` per the existing baseline rule; a `Progressing` declared-budget timeout stays gating.
- [ ] Write a failing test in `main.rs::tests`: `budget_kill_blocks_bless_and_is_not_a_measurement_waiver` — `bless_gate` puts a `BudgetKill` row in `blocking` (not in `starved`, not in `carried` unless `--allow-hang` names it).
- [ ] Write a failing test in `matrix.rs::tests`: `every_verdict_appears_in_the_headline_order` — an exhaustive `match` over `Verdict` asserting each variant is present in `headline`'s `order` array, so a future variant cannot silently vanish from the counts.
- [ ] Run all three red; keep the receipts.
- [ ] Implement: the new variant, `CarrickRunFacts` replacing the bare `carrick_timed_out: bool` at both call sites (`classify`, `classify_closure`), `bless_blocks(_, Verdict::BudgetKill) == true`, and the `order`/legend update.
- [ ] Add `deadline`, `timeout_kind` (already present) and `confirmation` (Task 3) to `SuiteReport` with `#[serde(default, skip_serializing_if = "Option::is_none")]` so committed baselines and prior results files still parse.
- [ ] Re-render the matrix deterministically (no conformance run): `RUSTC_WRAPPER="" cargo run -p carrick-conformance -- --render-matrix --jsonl scripts/conformance/baseline.jsonl`.
- [ ] Verify: `RUSTC_WRAPPER="" just check-matrix` green; `RUSTC_WRAPPER="" cargo test -p carrick-conformance --bins` green; confirm `git diff scripts/conformance/baseline.jsonl` is empty (no re-bless).

## Task 3: Phase 1b — bounded serial confirmation

Files: `crates/carrick-conformance/src/main.rs`.

Interfaces:
```rust
/// Total wall-clock seconds for the whole confirmation pass. 0 disables (bisection hatch).
#[arg(long, default_value_t = 900, env = "CARRICK_CONFORMANCE_SERIAL_CONFIRM_BUDGET_S")]
carrick_serial_confirm_budget_s: u64,

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerialConfirmation {
    pub reason: ConfirmReason,          // BudgetKill | Starved
    pub load_ms: u64, pub load_budget_ms: u64,
    pub load_timeout_kind: Option<TimeoutKind>,
    pub serial_ms: Option<u64>, pub serial_timed_out: bool,
    pub skipped: Option<&'static str>,  // "budget pool exhausted" | "disabled"
}

fn needs_serial_confirmation(out: &engine::RunOutput, kind: Option<TimeoutKind>) -> Option<ConfirmReason>;
fn binary_identity(path: &Path) -> anyhow::Result<String>; // sha2, recorded at preflight
```

- [ ] Write failing tests in `main.rs::tests`: `needs_serial_confirmation_selects_only_budget_kills_and_starvation` (a declared-budget timeout, a MATCH and a CRASH are all excluded); `serial_confirmation_pool_stops_and_names_the_remainder` (a pure scheduling function over `(row, declared_s)` and a pool, returning the ran/skipped split deterministically by suite index); `serial_confirmation_adopts_the_serial_verdict_even_when_worse` (adopting a REGRESSION over a phase-1 `BudgetKill`, proving this is not retry-until-green).
- [ ] Run red; keep receipts.
- [ ] Implement Phase 1b strictly between Phase 1 and Phase 2, on the main thread, no fan-out, `timeout_cap_s = Some(0)`, run id `conf-<pid>-s{i:02}`, one attempt per row. Log `phase 1b/4: serial confirmation — N row(s), pool <budget>s (workers=1, declared budgets)` and one line per row with its outcome.
- [ ] Record the binary sha256 at preflight; re-verify before Phase 1b and bail by name on drift (`just build` can replace `target/release/carrick` under a live gate).
- [ ] Use the confirmation run's `RunOutput` for classification in Phase 3 for those rows; set `perf.carrick_ms` from the serial run; put the load run's timing in `confirmation`.
- [ ] Rows left unconfirmed by pool exhaustion keep `BudgetKill`, are named individually in the summary, and still block bless.
- [ ] Update the phase banners (`phase 1/4 … 4/4`) and confirm the fail-fast counter is unaffected (`BudgetKill` is non-gating, so it cannot trip `--max-gating`).
- [ ] Verify: `RUSTC_WRAPPER="" cargo test -p carrick-conformance --bins` green; `RUSTC_WRAPPER="" just clippy`; dry-run sanity `RUSTC_WRAPPER="" cargo run -p carrick-conformance -- --dry-run --suite go-go_types`.

## Task 4: Oracle dual-profile population

Files: `crates/carrick-conformance/src/main.rs` (Phase 2 fold and `oracle_fill`), `crates/carrick-conformance/src/oracle.rs`.

Interfaces:
```rust
impl OracleCache {
    /// Insert BOTH parser-profile rows from one completed Docker run. Each row
    /// is admitted only if its own profile's cacheability rule accepts it.
    pub fn insert_fresh_both_profiles(
        &mut self, suite: &Suite, platform: DockerPlatform,
        regression: SuiteResult, closure: SuiteResult,
        elapsed_ms: Option<u64>, timed_out: bool,
    ) -> (bool, bool);
}
```

- [ ] Write a failing test in `oracle.rs::tests`: `one_docker_run_populates_both_profile_rows` — after `insert_fresh_both_profiles`, both `get(...)` and `get_for_profile(..., ClosureV3)` hit, and a result that fails `is_strict_closure_success` stores the regression row only. Assert the regression key bytes are byte-identical to `oracle_key` today (the golden-key test `regression_profile_keeps_golden_key_bytes_and_closure_is_distinct` must remain green).
- [ ] Run red; keep the receipt.
- [ ] Implement: parse the same `RunOutput::raw()` under both `ParseMode`s in the Phase 2 fold and in `oracle_fill`, insert both rows, keep the profile-free timing sidecar untouched, and keep the "timed-out Docker inserts nothing" rule.
- [ ] Update `--oracle-fill-profile`'s help to state that a fill now writes both rows and that the flag only selects which parse the *report* uses.
- [ ] Verify: `RUSTC_WRAPPER="" cargo test -p carrick-conformance --bins oracle` green; confirm `git diff scripts/conformance/oracle-cache.jsonl` is empty until a Docker phase actually runs (the change is additive at fill time, not at load time).
- [ ] Note in the commit body that the 438 already-committed cpython closure rows are NOT back-filled by this change; the one-time repair is `--oracle-fill --oracle-fill-profile regression` on the canonical box, Docker-only, never alongside carrick.

## Task 5: Default-ON probe carrier budget

Files: `crates/carrick-embed/src/testing.rs`, `crates/carrick-embed/src/deadline.rs`, `crates/carrick-conformance-next/src/lib.rs`, `crates/carrick-conformance-next/tests/common/mod.rs`.

Interfaces:
```rust
// carrick-embed
impl TestContainer {
    pub fn carrier_budget(self, budget: Duration) -> Self;     // replaces `deadline`
    pub fn label(self, label: impl Into<String>) -> Self;      // names the artifact directory
}
pub(crate) fn effective_carrier_budget(requested: Option<Duration>, first_in_process: bool) -> Option<Duration>;
// 0 from CARRICK_PROBE_CARRIER_BUDGET_MS => None (hatch); absent => the default.

// carrick-conformance-next (lib target, so `just test` runs its tests)
pub const PROBE_CARRIER_BUDGET_MS: u64;
pub const PROBE_COLD_START_ALLOWANCE_MS: u64;
pub fn probe_carrier_budget(probe: &str, first_in_process: bool) -> std::time::Duration;
```

- [ ] **Measure before choosing constants.** Add per-probe elapsed printing to the shard loop (`eprintln!("RUN … elapsed_ms=…")`), run one green gate on a quiet box with nothing else alive, and derive the p99 from the log:
  `RUSTC_WRAPPER="" just conformance-probes 2>&1 | tee target/conformance/logs/probe-timing-$(date +%F).log`
  Record the distribution in the commit body; set `PROBE_CARRIER_BUDGET_MS` from it, not from intuition.
- [ ] Write failing tests in `carrick-embed`'s lib tests: `carrier_budget_is_armed_by_default` (a `TestContainer` built with no explicit budget reports `Some(_)`); `zero_is_the_exact_hatch` (`CARRICK_PROBE_CARRIER_BUDGET_MS=0` ⇒ `None`, any other value overrides); `run_with_audit_is_bounded_too` (the audit path applies the same budget — it currently calls `run_blocking` directly and is unbounded).
- [ ] Write a failing test in `carrick-conformance-next/src/lib.rs::tests`: `every_generic_probe_has_a_carrier_budget` and `cold_start_allowance_exceeds_the_steady_budget`.
- [ ] Run all red; keep receipts.
- [ ] Implement, renaming `deadline` to `carrier_budget` (no second spelling, no deprecated alias — AGENTS.md forbids a shim) and updating every existing caller.
- [ ] Wire `generic_probe_container` to set `.label(probe_name)` and the budget; wire `case_`/workload containers the same way.
- [ ] Verify: `RUSTC_WRAPPER="" just test` green; `RUSTC_WRAPPER="" just lint-domains` green (proves no `Command::new` crept into the probe crate); `RUSTC_WRAPPER="" just test-integration` green.

## Task 6: Wedge capture and the named failure

Files: `crates/carrick-runtime/src/deadlock_watchdog.rs` (promote the private capture helpers into a reusable `capture` module), `crates/carrick-embed/src/deadline.rs`, `crates/carrick-embed/src/error.rs`.

Interfaces:
```rust
// carrick-runtime
pub struct WedgeCaptureRequest {
    pub label: String, pub pid: i32, pub run_id: Option<String>,
    pub budget_ms: u64, pub elapsed_ms: u64, pub out_root: PathBuf, // target/postmortem
}
pub struct WedgeCapture { pub dir: PathBuf, pub backtrace: PathBuf, pub core: Option<PathBuf> }
/// Spawns a DETACHED capture child, waits for it under its own hard timeout,
/// and returns the artifacts. Never returns Ok with an empty backtrace.
pub fn capture_wedged_carrier(request: WedgeCaptureRequest) -> Result<WedgeCapture, WedgeCaptureError>;

// carrick-embed
pub enum EmbedError { /* existing */
    ProbeWedged { label: String, budget_ms: u64, elapsed_ms: u64, artifacts: PathBuf },
    ProbeWedgeCaptureFailed { label: String, reason: String, artifacts: Option<PathBuf> },
}
```

- [ ] Write failing host-only tests: `capture_directory_is_private_owned_and_unpredictable` (reuse the existing `capture_request_uses_private_unpredictable_directory` shape); `empty_backtrace_is_an_error_not_a_capture` (a stub capture runner producing zero bytes ⇒ `WedgeCaptureError::NoEvidence`); `capture_child_timeout_still_kills_and_names` ; `probe_wedged_error_names_the_directory`.
- [ ] Run red; keep receipts.
- [ ] Implement `capture_wedged_carrier` by lifting `ensure_private_directory` / `fresh_capture_directory` out of `deadlock_watchdog` (do not duplicate them) and executing, in order: `manifest.json`, `sudo -n lldb -p <pid> --batch -o "thread backtrace all"` → `backtrace.txt`, `process save-core --style modified-memory` → `carrier.core`, then SIGKILL of the carrier pid. The child enforces its own hard timeout and kills even when the capture failed.
- [ ] Wire it into `deadline.rs`'s `RecvTimeoutError::Timeout` → `ABORT_GRACE` expiry arm, replacing today's prose-only `CarrierFailed`. Keep the deliberate non-join of the wedged worker and document why.
- [ ] Generalize `deadlock_watchdog::arm()` to accept an explicit window from the caller so the probe budget arms it (keeping the `CARRICK_DEADLOCK_WATCHDOG_MS` override as the operator hatch), and make the published request consistent with the new directory layout.
- [ ] Verify (carrick-only, no Docker): `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib deadlock` green; `RUSTC_WRAPPER="" just test` green.
- [ ] Live red-first proof: run `forkstackstorm` alone with a deliberately tiny budget and confirm `target/postmortem/forkstackstorm-<pid>/` contains a non-empty `backtrace.txt` and `carrier.core`, that the probe fails by name, and that `scripts/test-signed.sh` publishes no receipt:
  `RUSTC_WRAPPER="" CARRICK_PROBE_CARRIER_BUDGET_MS=2000 CARRICK_RUN_ID=sep15-wedge ./scripts/test-signed.sh carrick-conformance-next generic_probe_shard_1 --nocapture; echo EXIT=$?; bash scripts/sudo/kill.sh sep15-wedge`
  Then the same with the production budget to prove a green gate is unaffected.

## Task 7: Live acceptance on one exact artifact

- [ ] Freeze a signed binary and record its provenance: source HEAD, binary SHA-256, CDHash, LC_UUID, hypervisor entitlement, non-empty `__dof_carrick`.
- [ ] Carrick-only, nothing else alive (`pgrep -fl 'carrick run|carrick-conformance|docker run'` empty). Reproduce the four rows at 8 workers and confirm `BUDGET_KILL … [progressing]` followed by serial confirmation to their real verdicts:
  `RUSTC_WRAPPER="" CARRICK_RUN_ID=sep15-budget just --no-deps conformance full --ecosystem go --suite go-go_types --suite go-net --suite go-net_http --suite cpython-tarfile --require-cached-oracle --jsonl target/conformance/sep15-budget/results.jsonl; bash scripts/sudo/kill.sh sep15-budget`
- [ ] Prove the mislabel is gone by running the same selection on the pre-change binary (`git checkout <base> -- crates/carrick-conformance`, rebuild, rerun) and recording `TIMEOUT … [blocked]` as the red receipt.
- [ ] Docker-only phase for the profile fix: one `--oracle-fill --oracle-fill-profile regression --ecosystem cpython` pass on the canonical box, then a carrick-only `--require-cached-oracle` run proving zero misses.
- [ ] `RUSTC_WRAPPER="" just ci` green (includes `check-matrix`, `lint-domains`, `test`, `test-integration`).
- [ ] `RUSTC_WRAPPER="" just conformance-probes` green on the frozen binary with the watchdog armed at production constants; scoped cleanup proven after each rung.
- [ ] Stop promotion at the first red. Do not raise a budget, waive a row, or flip a default off to reach green.

## Rulings

- The verdict is `BUDGET_KILL`, not `PERF`: a truncated run's ratio is the number AGENTS.md calls meaningless, so the verdict states the kill and the perf axis carries the serial measurement.
- Serial confirmation is single-shot and adopts the serial verdict unconditionally. It is not `--flake-retries` and must never become retry-until-green.
- Under embed the carrier is the signed test process; killing it kills the shard, and that is the fail-closed outcome (`test-signed.sh` publishes no receipt). The design says so explicitly rather than implying surgical isolation.
- `deadline` is renamed to `carrier_budget` with no compatibility alias: no second spelling, no shim.
- The profile fix is additive and not retroactive; the one-time repair of the existing 438 closure-only rows is a separate, Docker-only step.

## Director rulings on the planner's open questions (2026-09-15)

1. `BUDGET_KILL` is non-gating and bless-blocking for now; a confirmed over-2x row becomes gating
   only once a declared perf baseline exists (separate work).
2. The 900 s serial-confirmation pool may truncate; unconfirmed rows stay `BUDGET_KILL`, are named
   individually and block bless. Exact `=0` disables.
3. Probe carrier budget constants are measured on this Mac (the canonical HVF box) from a green
   `just conformance-probes`; one global budget plus a typed per-probe override table for the known
   heavy probes is acceptable.
4. The 438 closure-only cpython rows were already repaired by the Sep 14 `--refresh-oracle` run
   and committed as 0745386ef; no further back-fill.
5. `forkstackstorm`'s spin attribution is a separate brief (Group B fork-planning family); this
   plan only makes the wedge visible and fatal.
6. `CARRICK_DEADLOCK_WATCHDOG_MS` is deleted; the window becomes a typed parameter everywhere. One
   spelling, no second path.
