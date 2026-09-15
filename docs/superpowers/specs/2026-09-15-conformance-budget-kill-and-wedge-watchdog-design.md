# Conformance budget kills, serial confirmation, probe wedge watchdog, oracle profile unification: proposed change, not implemented

## Problem and evidence

Four measured defects in the gate itself, all on disk today.

**1. The harness reports its own diagnostic budget as a carrick hang.** The 8-worker ecosystem run in `target/conformance/sep14-ecosystem/` produced 22 TIMEOUT lines, 21 of them annotated `[blocked]` and zero `[starved]` (`grep -o '\[blocked\]' run.log | wc -l` = 21). `[blocked]` is defined in `crates/carrick-conformance/src/engine.rs::classify_timeout` as "CPU duty < 0.5 and 1-minute load < 1.5x ncpu" — which is exactly what an I/O-bound or `sleep`-heavy suite looks like while it is making progress. The serial rerun at declared budgets (`--workers 1 --carrick-timeout-cap-s 0`, `target/conformance/sep14-ecosystem/serial/*.jsonl`) shows 5 of the first 10 were plain MATCH: `go-go_types` 14672 ms, `go-os` 5556 ms, `go-syscall` 6549 ms, `go-go_internal_srcimporter` 7381 ms, `cpython-compile` 5796 ms. Only `cpython-asyncio` (300260 ms against a 300 s declared budget, `blocked`) was a confirmed hang; `go-net` and `go-net_http` completed serially with REGRESSION verdicts.

**2. The kill point is the 2x-Docker bar, by construction.** `effective_carrick_timeout_s` (engine.rs) sets the Carrick deadline to `min(declared, max(fast_timeout_s, ceil(2 x oracle_ms / 1000) + 2))`. Every budget-killed row in `target/conformance/sep15-ecosystem-postA/regressed.txt` sits on that number: `go-go_types` carrick 14181 ms vs budget 2x5883+2000 = 13766 ms; `go-net_http` 11265 ms vs 11 s; `cpython-tarfile` 13086 ms vs 13 s; `go-net` 8229 ms vs 7 s (the excess is the 200 ms poll step plus the scoped-cleanup call, which runs inside the timed region). `go-go_types` finished serially in 14672 ms against a 5883 ms oracle — a real 2.49x ratio. The adaptive budget IS the project's second gate expressed as a deadline: a kill at it is a perf observation by construction and can never, on its own, be evidence of a hang. Reporting it as TIMEOUT/`[blocked]` inverts AGENTS.md's own rule that a row sitting exactly on its budget has a meaningless ratio.

**3. The probe gate has no watchdog.** `/Volumes/CaseSensitive/carrick/.worktrees/sep14-tcp-dualstack/target/postmortem/README-forkstackstorm-spin.md`: during `just conformance-probes`, carrier `carrick:embed-signed-48761` pid 49776 spun 29m45s at 104% CPU on the `forkstackstorm` probe, executor `carrick-executor-5` looping in `HvpatchRuntimeDirectory::continuation_services` under `vcpu_loop::quiesce`. It ended only when the director noticed, attached lldb by hand, saved `forkstackstorm-spin-49776.bt.txt` (26 threads) and a 70 MB core, and killed it. The bound the probes DO have (each probe caps its own waits at 5 s) is inside guest code and cannot see a carrier wedge outside it.

**4. A closure run's oracle rows do not satisfy a regression run.** `crates/carrick-conformance/src/oracle.rs` keys each row by `OracleKey`, whose `parser_profile` determinant is `None` for regression and `"closure-v3"` for closure. The Sep 14 full run was `--closure`, so a filtered `--ecosystem cpython --require-cached-oracle` run refused up front with 438 uncached rows; commit `0745386ef` paid for that with a full fresh Docker pass of 438 cpython rows plus 193 go/node refreshes.

## What the current source actually does (corrections to the brief)

Verified by reading, not assumed:

- **A per-probe carrier bound already exists and is opt-in.** `crates/carrick-embed/src/testing.rs::TestContainer::deadline` → `crates/carrick-embed/src/deadline.rs::run_with_deadline` already latches `AbortReason::ContainerDeadline`, freezes the scheduler, captures a `PostMortem` in-process and returns `EmbedError::KernelAborted`. It defaults to `None` and no probe sets it. `crates/carrick-conformance-next/tests/common/mod.rs::generic_probe_container` builds every generic probe without one. This is a default-off mechanism, which AGENTS.md classifies as abandoned rather than shipped — the fix is to make it default-ON with an exact `=0` hatch, not to write a new watchdog.
- **`TestContainer::run_with_audit` bypasses `deadline` entirely** (it calls `builder.run_blocking()` directly). Any budget that is not applied there leaves every audit-based case unbounded.
- **The spin case is already a named failure, but with no artifacts.** When the abort latch is not consumed within `ABORT_GRACE` (30 s) — precisely a spinning executor that never reaches a supervised wait, i.e. forkstackstorm — `run_with_deadline` returns `EmbedError::CarrierFailed` with prose, deliberately does **not** join the worker, and captures nothing. The wedged thread then keeps spinning inside the test process.
- **`carrick-conformance-next` may not spawn anything.** `scripts/conformance/check-next-strategy.py::check_next_has_no_subprocesses` rejects `Command::new(` in **every** `.rs` under that crate, tests included, and `just lint-domains` runs it. The capture step therefore cannot live in the probe crate; it must live in `carrick-embed`/`carrick-runtime`.
- **"Kill only that carrier" has no separate process to kill.** Under embed the carrier is in-process (`crates/carrick-embed/src/carrier.rs`, `CarrierRuntime` in the host process); pid 49776 in the postmortem is the signed libtest executable itself, with its proctitle rewritten to `carrick:<run-id>:`. Killing the carrier kills the shard. That is acceptable and already fail-closed — `scripts/test-signed.sh` requires the executable to exit 0 **and** validates a receipt containing one `execution` row per selected test, so a killed shard cannot publish a receipt — but the design must say so rather than imply surgical isolation.
- **Most of the capture already exists in Rust.** `crates/carrick-runtime/src/deadlock_watchdog.rs` publishes an authenticated capture request (private 0700 dir, unpredictable name, `sudo -n lldb -p <pid> -b -o 'process save-core --style modified-memory …'`) and SIGSTOPs the carrier — but it is gated on `CARRICK_DEADLOCK_WATCHDOG_MS`, is keyed on syscall-dispatch progress only, and **nothing consumes the request**: it lands in `/tmp` and the carrier stays stopped until a human notices. `carrick debug lldb-snapshot` / `lldb-run` (`crates/carrick-cli/src/debug.rs`, `args.rs:1040-1100`) already implement attach + `thread backtrace all` + `process save-core` + census. The gap is an executor, not a capability.
- **The elapsed-time evidence is already profile-independent.** `oracle.rs` carries an `OracleExecutionKey` sidecar (`oracle-cache.timings.jsonl`) deliberately excluding parsing policy. Only the parsed *result* row is profile-keyed. This is the precedent the profile fix should follow.
- **`classify` cannot see which budget fired.** `verdict.rs::classify(suite, carrick, carrick_timed_out: bool, docker, baseline)` receives a bare bool, so "missed the suite's declared budget" and "was cut off by the operator's diagnostic budget" are indistinguishable at the only place a verdict is decided.

## Alternatives and decisions

### Budget-kill classification

1. Tune `classify_timeout` thresholds. Rejected: no threshold on CPU duty separates "waiting on a socket while passing tests" from "waiting forever"; the discriminator is progress, not duty.
2. New `TimeoutKind::Progressing` only. Rejected alone: it fixes the label but leaves the verdict TIMEOUT, so the row still reads as a hang in the summary, the matrix and the bless gate.
3. **Selected:** make the *deadline that fired* a typed, reported fact, add `TimeoutKind::Progressing` from positive transcript-growth evidence, and mint a distinct verdict for a kill at a budget below the suite's declaration.

**Naming decision, against the brief.** The brief asks for a `PERF` verdict. A verdict named PERF asserts a measurement, and a truncated run's ratio is exactly the number AGENTS.md says is meaningless ("a row sitting exactly on its budget … its 'ratio' is meaningless"). The verdict is therefore `Verdict::BudgetKill` (`BUDGET_KILL`): it states what happened (cut off at the diagnostic budget while progressing) and nothing it cannot prove. The perf signal the brief wants is not lost — it is carried on the axis that already exists (`PerfSummary`), sourced from the serial confirmation, which is a controlled single-variable measurement on a quiet box and therefore citable.

### Serial confirmation

1. Reuse `--flake-retries`. Rejected: retry-on-flake adopts the *first non-gating* attempt — retry-until-green, which this project forbids. Confirmation runs **once** and adopts the serial verdict whatever it is, including a worse one.
2. Leave it to the operator (the Sep 14 procedure in `brief-serial-remeasure.md`). Rejected: a manual step that must be remembered is not a gate.
3. **Selected:** an automatic Phase 1b between the carrick phase and the docker phase, default ON, bounded by a total wall-clock pool with an exact `=0` hatch.

### Probe wedge watchdog

1. A shell watchdog around `scripts/test-signed.sh`. Rejected by AGENTS.md ("Rust first; extend ourselves") and by the history in `deadline.rs`, which records that exactly this shape produced `rc=137` and no evidence.
2. A watchdog inside `carrick-conformance-next`. Impossible: the strategy checker forbids `Command::new` there.
3. **Selected:** default-ON budget in `carrick-embed`, escalating through the existing in-process abort sink, and — only when that sink cannot be consumed — an external capture performed by a detached child spawned from `carrick-runtime`'s healthy watchdog thread.

### Oracle profile unification

1. Make the key profile-free and cache the raw Docker transcript, parsing at read time. Semantically cleanest (the oracle IS the container's bytes) but it invalidates **every** committed key at once, forces a full fresh Docker pass of 2,127 rows, and grows the committed cache by megabytes of LTP/regrtest transcript. Rejected.
2. Derive the regression result from the closure result. Unsound: the two parsers extract different id sets from the same bytes (`parsers/mod.rs::parse_transcript`), and one is not a subset of the other.
3. **Selected:** dual-profile population at fill time. One Docker container, two parses of the same captured `Raw`, two rows inserted under two keys, each subject to its own cacheability rule. Additive: no existing key changes bytes (regression omits the determinant), no re-bless of existing rows, the cache-key invariant "the key is the suite declaration (plus the parser that reads it)" is preserved exactly.

**Trade-off, stated:** the cache file grows by one row per regrtest suite (the other verdict kinds parse identically under both modes but are still keyed separately, so they also gain a row on a closure run), and the fix is **not retroactive** — the 438 cpython closure rows already committed cannot be back-filled without the bytes, so the one-time repair remains `--oracle-fill --oracle-fill-profile regression` or `--refresh-oracle` on the canonical box.

## Contract

### C1 — Deadline provenance is a recorded fact

`engine::run_carrick` computes the effective deadline and must report it. `RunOutput` gains `deadline: CarrickDeadline { declared_s, effective_s, origin }` where `origin ∈ {Declared, Fast, AdaptiveOracle, Cap}`. A run is a **budget kill** iff `timed_out && effective_s < declared_s`. This is decided by construction, never inferred from elapsed-vs-budget arithmetic.

### C2 — Progress is positive evidence only

`run_one` already captures to files, so the poll loop stats both transcripts every 200 ms at negligible cost. `TimeoutEvidence` gains `stdout_bytes`, `stderr_bytes` and `ms_since_last_growth` (time between the last observed byte growth and the kill). Classification order becomes: growth within `progress_window_ms` (default 2000, and always < the effective deadline) ⇒ `TimeoutKind::Progressing`; otherwise the existing duty/load ladder. Absence of growth is **not** evidence of a hang — an old-API LTP test block-buffers stdout and flushes only in `tst_exit()` — so no-growth falls through to the existing classification and the serial confirmation remains the authority. `Progressing` must never be reported as `Blocked`.

### C3 — A budget kill is never a hang verdict

`classify` takes a typed `CarrickRunFacts { timed_out, deadline, timeout_kind }` in place of the bare bool. A budget kill classifies as `Verdict::BudgetKill`: `gating = false` (it proves nothing about correctness) and **bless-blocking** (there is no measured result to bless). A kill at the *declared* budget stays `Verdict::Timeout`, carrying its `TimeoutKind` — including `Progressing`, which there means "cannot finish its own declared budget" and is a genuine defect. `TimeoutKind::Progressing` is **not** a `is_measurement_failure`: a progressing budget kill is resolved by confirmation, not waived.

### C4 — Serial confirmation is default-ON, bounded, single-shot

After Phase 1 joins every worker and before Phase 2 starts Docker, Phase 1b re-runs, on the main thread with no fan-out, every row whose Phase-1 run was a budget kill or was classified `Starved`. Each re-run uses the same `carrick_bin` with `timeout_cap_s = Some(0)` (the declared budget) and its own scoped run id. Constraints:

- **Budget pool.** `--carrick-serial-confirm-budget-s` (env `CARRICK_CONFORMANCE_SERIAL_CONFIRM_BUDGET_S`), default 900, exact `0` disables. The pass stops when the pool is exhausted and names every unconfirmed row; unconfirmed rows keep `BudgetKill` and block bless. Silent truncation is forbidden.
- **Deterministic order** by suite index, so the pass is reproducible.
- **Same artifact.** The binary's SHA-256 is recorded at preflight and re-verified before Phase 1b; a change is a named error (`just build` replaces `target/release/carrick` underneath a running gate — AGENTS.md).
- **Single shot.** Exactly one re-run per row; the serial verdict is adopted unconditionally. This is not a retry.
- **No Docker overlap.** Phase 1b runs carrick only, strictly before Phase 2.
- **Evidence retention.** The report keeps `confirmation: Option<SerialConfirmation { reason, load_ms, load_budget_ms, load_timeout_kind, serial_ms, serial_timed_out }>`. `perf.carrick_ms` becomes the **serial** measurement (the only citable one); the load run's timing is retained inside `confirmation`, labelled as a kill observation, never as a ratio.

### C5 — Baseline and matrix determinism are unchanged

`BudgetKill` blocks bless, so it can never enter `scripts/conformance/baseline.jsonl`. `matrix::render`'s `headline` currently filters over a hand-written `order` array; a verdict missing from it silently vanishes from the counts. The new variant is added to that array and to the legend prose, and `docs/support-matrix.md` is re-rendered deterministically in the same commit (`--render-matrix --jsonl scripts/conformance/baseline.jsonl`), so `just check-matrix` stays green with no conformance run. A unit test must exhaustively match `Verdict` against the `order` array so the next variant cannot vanish.

### C6 — Every probe carrier is bounded by default

`TestContainer` gains `carrier_budget: Duration` defaulting to a measured constant rather than `None`, applied by `run`, `run_with_audit` and every other run entry point. Hatch: `CARRICK_PROBE_CARRIER_BUDGET_MS=0` disables for one bisection run; any other value overrides. The carrier wedge bound is `CARRICK_PROBE_CARRIER_MULTIPLE` (default 3) x the probe's budget. The first container in a process carries a separate cold-start allowance (image resolution plus a cold guest already broke a 10 s exit budget — see the `exit_budget` docs in `testing.rs`). Constants are derived from a measured distribution of a green `just conformance-probes` run, not chosen by intuition.

### C7 — Escalation ladder, fail-closed at every rung

1. Budget breach ⇒ existing `request_abort(AbortReason::ContainerDeadline)` ⇒ in-process `PostMortem` ⇒ `EmbedError::KernelAborted` ⇒ the probe FAILS with a named error naming the probe, the budget and the artifact path.
2. Abort not consumed within `ABORT_GRACE` ⇒ wedge capture. A detached capture child is spawned by the runtime's watchdog thread (which is healthy; only executor threads are wedged) and: creates `target/postmortem/<probe>-<pid>/` with 0700 permissions and an owned-directory check (reuse `deadlock_watchdog::ensure_private_directory`), writes `manifest.json` (probe label, `CARRICK_RUN_ID`, pid, budget, multiple, elapsed, binary sha256/CDHash), runs `sudo -n lldb -p <pid> --batch -o "thread backtrace all"` into `backtrace.txt`, then `process save-core --style modified-memory` into `carrier.core`, enforces its own hard timeout, and only then SIGKILLs the carrier pid.
3. **Zero events is an error.** An empty or absent `backtrace.txt`, a zero-length core, an unavailable `lldb`, or a capture-child timeout produces a distinct named error (`ProbeWedgeCaptureFailed`) that still fails the probe and still names the directory. No rung may produce an empty pass. A watchdog that fires without the carrier ever having dispatched a guest syscall is still a failure, never a skip (the `trap_hvf.rs` self-skip pattern is explicitly not to be copied).
4. Killing the carrier kills the shard. That is the intended, fail-closed outcome: `scripts/test-signed.sh` then records `failed=1`, publishes no receipt, and `just conformance-probes` exits non-zero with the artifact path in the log.

### C8 — Oracle rows are populated for both profiles from one container

When Phase 2 (or `--oracle-fill`) completes a Docker run, the captured `Raw` is parsed under both `ParseMode::Regression` and `ParseMode::Closure`, and both rows are inserted via `insert_fresh_for_profile`. Each insertion honours its own cacheability rule independently (`is_cacheable` vs `is_closure_cacheable`), so a suite that fails strict closure still yields a valid regression row and vice versa. A timed-out Docker run inserts neither. The timing sidecar keeps its existing profile-free key. No existing key's bytes change.

## Red-first proof and acceptance

Every behaviour gets a test that a gate executes. `carrick-conformance` is bin-only, so its in-file `mod tests` run under `just test`'s `--lib --bins` — the same pattern that already carries `allow_hang_reports_stale_entries_and_leaves_starved_unblocking`. `carrick-embed`'s host-only tests run under `just test`. Probe-side invariants go in `crates/carrick-conformance-next/src/lib.rs` (a lib target, therefore `just test`), not in a `tests/` target that would need adding to `just test-integration` to be executed at all.

Red-first is mandatory and mechanical: each unit test must be shown failing against the current tree before the implementing change, and the red output recorded in the commit body. The classifier tests need no guest — they are pure functions over recorded evidence, which is why `classify_timeout` was written pure in the first place.

Live acceptance, in order, never concurrent with Docker:

1. Reproduce the mislabel: a filtered run of the four known rows (`go-go_types`, `go-net`, `go-net_http`, `cpython-tarfile`) at 8 workers must, on the candidate, report `BUDGET_KILL … [progressing]` and then confirm serially to their real verdicts; on the pre-change binary the same run reports `TIMEOUT … [blocked]`.
2. `forkstackstorm` alone on a quiet box under an artificially small budget must produce a populated `target/postmortem/forkstackstorm-<pid>/` with a non-empty backtrace and a non-empty core, and fail the probe by name.
3. A filtered `--ecosystem cpython --require-cached-oracle` run after one dual-population Docker pass must find its rows cached.
4. `just check-matrix` green with the re-rendered matrix; `just ci` green; `just conformance-probes` green on a binary with the watchdog armed at production constants.

No retries-until-green, no new `known_gaps`, no deadline raised to make a row pass, no default flipped off to hide a breach.

## Review status

Source-reviewed against `crates/carrick-conformance/src/{engine,main,oracle,verdict,matrix}.rs`, `crates/carrick-embed/src/{testing,deadline,carrier,builder}.rs`, `crates/carrick-runtime/src/deadlock_watchdog.rs`, `crates/carrick-runtime/src/kernel/debug/post_mortem.rs`, `crates/carrick-cli/src/{args,debug}.rs`, `scripts/test-signed.sh`, `scripts/conformance/check-next-strategy.py` and the `justfile`. Feasible with no new scripts and no new crate. No implementation and no default change has been made.
