# Native Compiler Budget: Attribution of the Unaccounted CPU Term

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the additive native CPU model reconcile by attributing the
measured 57-77 percent unaccounted CPU residual to typed profile terms, then
repair whichever attributed term the committed decision ladder selects, and
re-run the Task 3 measurement campaign to a green typed decision row.

**Architecture:** Extend `NATIVEPERF1` with three attribution surfaces —
per-process startup CPU, an on-CPU/off-CPU split inside the blocked wait
segment, and host helper-thread CPU — then re-run the frozen W1/W2 campaign
so `analyze` either reconciles within 2 percent and emits a typed decision
row or fails closed on a now-nameable term.

**Tech Stack:** Rust (carrick-runtime native_darwin DSR profiler), Python
(scripts/perf harness), signed live W1/W2 workloads, Docker oracle.

## Global Constraints

- Never raise `max_traps`, timeouts, or weaken AArch64 exclusive or signal
  semantics; never weaken the 2 percent additive gate or the 10 percent ABBA
  tax gate.
- Never overlap Carrick and Docker phases; every Carrick run carries a unique
  `CARRICK_RUN_ID` and is reaped with `sudo -n scripts/sudo/kill.sh <run-id>`.
- Rebuild and sign with `just build` before every guest run; measured runs
  require a clean tree.
- Untraced signed runs are the only absolute wall/CPU authority; DTrace
  magnitudes stay proportional-shape evidence.
- Profile-off builds must keep the specialized no-timer path (no new locks or
  timer reads when `PROFILE` is false).

## The measured facts this plan answers (2026-07-14 campaign, `docs/perf-results/`)

- Untraced authority: W2 completes at p50 3.520 s vs Docker 0.220 s
  (**16.00x**); W1 is ceiling-truncated (all five runs typed `max-traps` at
  p50 19.360 s vs Docker 1.600 s).
- ABBA profile tax is 1.13 percent, yet the committed analyzer FAILS CLOSED:
  `additive CPU reconciliation differs by more than 2%: 0.653181`. Exclusive
  DSR phases cover 23-43 percent of measured user+system CPU.
- The residual tracks blocked wall (one-thread: exclusive 1.46 s + blocked
  1.66 s vs cpu 3.41 s; W1 ceiling: exclusive 21.2 s + blocked 42.1 s vs cpu
  69.0 s) and is system-time dominated (untraced W2: user 1.44 s /
  sys 2.31 s).
- Two candidate explanations fit W2 equally and the current profile cannot
  distinguish them: (a) per-syscall wait machinery — only 3,860 syscalls per
  W2 run but ~500-650 us unprofiled CPU and ~544-601 us sys per syscall, with
  every syscall passing a blocked segment (blocked_count == exit_syscall);
  (b) per-process startup — 23 guest processes at ~85-110 ms residual each.
  The retained W1 ceiling profile (72 PIDs, 42 s blocked wall) fits neither
  alone.
- Count scopes also fail closed: hottest-thread exclusive 47.1 percent
  selects `sensitive-exclusive`; aggregate-threads exclusive 21.7 percent
  selects nothing (aggregate resolver share 58.4 percent, recurrence
  unproven).
- Blocked wall is 55.0 percent of untraced wall — above the design's
  30 percent blocked-residual rung — but the rung may not be selected while
  the additive model cannot say how much of that wall burns CPU.

No slice is selected by this plan. It makes the term nameable, then lets the
committed ladder select.

---

### Task 1: Typed attribution frames in the native profiler

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/profile.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs` (blocked measurement
  at `measure_native_blocked`, dispatch loop `dispatch_native_syscall_inner`,
  process/thread bring-up and helper-thread spawn sites)
- Test: profiler unit tests alongside `profile.rs`; hermetic parser tests in
  `scripts/perf/test_native_compiler_budget.py`

**Interfaces:**
- Consumes: existing `NATIVEPERF1|thread|...` nine-frame protocol and
  `Phase::Blocked` accounting (`phase_blocked_ns`/`phase_blocked_count`,
  invariant `phase_blocked_count == exit_syscall`).
- Produces: three new fields/frames, exact names consumed by Task 2:
  - `phases-b` gains `phase_blocked_cpu_ns` — thread CPU time consumed inside
    the blocked segment (measured via per-thread usage, e.g.
    `thread_selfusage(2)`/`thread_info(THREAD_BASIC_INFO)` deltas around the
    wait closure), so `blocked_idle_ns = phase_blocked_ns -
    phase_blocked_cpu_ns` is derivable and `phase_blocked_cpu_ns <=
    phase_blocked_ns` is a parser invariant.
  - a new one-per-process `startup` frame: `startup_wall_ns`,
    `startup_cpu_ns` — from process entry (post-exec runtime init, including
    prepared-image build/map and rootfs/cache init) to the first gateway
    entry of the first guest thread.
  - a new one-per-process `host-threads` frame: `helper_cpu_ns` — aggregate
    CPU of non-guest helper threads (pumps, watchers) sampled at process
    profile flush.

- [ ] **Step 1: Red-first profiler unit tests** for the three surfaces:
  blocked-cpu never exceeds blocked wall; startup frame emitted exactly once
  per process; helper CPU monotonic; profile-off monomorph contains no new
  timer/usage calls (compile-time `PROFILE=false` path unchanged — assert via
  the existing no-timer test pattern).
- [ ] **Step 2: Implement the frames** behind the existing `PROFILE` const
  generic; extend the frame writer to stay within the `PIPE_BUF`-bounded
  framing contract (new fields ride the existing `phases-b` frame; the two
  new frames use the established `NATIVEPERF1|thread|...|frame=<name>`
  encoding with `pid/tid/era` identity).
- [ ] **Step 3: Extend the Python parser strictly**: add the new fields to
  `FRAME_FIELDS`, extend `validate_profile` with
  `phase_blocked_cpu_ns <= phase_blocked_ns` and exactly-one-startup-frame
  per pid, and red-first hermetic tests (mutation-rejection style, matching
  the existing suite).
- [ ] **Step 4: Signed live reducer proof**: rebuild/sign, run one profiled
  W2 and one profiled `forkexecpthread` reducer; require complete unique
  frames, zero invalid records, scoped cleanup clean.
- [ ] **Step 5: Commit** (`fix(native): attribute blocked/startup/helper CPU
  in NATIVEPERF1`).

### Task 2: Extend the additive model and analyzer to consume attribution

**Files:**
- Modify: `scripts/perf/native_compiler_budget.py`
  (`derive_additive_cpu_evidence`, `analyze`, `ON_CPU_PHASES`)
- Test: `scripts/perf/test_native_compiler_budget.py`

**Interfaces:**
- Consumes: Task 1's `phase_blocked_cpu_ns`, `startup` frame
  (`startup_wall_ns`, `startup_cpu_ns`), `host-threads` frame
  (`helper_cpu_ns`).
- Produces: `AdditiveCpuEvidence` gains `blocked_cpu_ns`, `startup_cpu_ns`,
  `helper_cpu_ns`; the reconciliation becomes
  `residual = cpu - (exclusive_sum + blocked_cpu + startup_cpu +
  helper_cpu)` with the unchanged 2 percent gate; the decision ladder's
  blocked rung uses measured `blocked_cpu` share of untraced CPU (denominator
  now explicit and on-CPU) while the existing wall-based trigger is retained
  as a diagnostic; a `startup` rung analog is added only as a term available
  to the existing >=30 percent / two-term rules — no new thresholds.

- [ ] **Step 1: Red-first analyzer tests**: synthetic profiles where the
  residual is explained by blocked-cpu, by startup-cpu, and by neither
  (fail-closed stays); ladder tests that the >=30 percent rung can select
  `blocked-cpu` or `startup-cpu` under both thread scopes agreeing.
- [ ] **Step 2: Implement**, keeping count/CPU denominators unmixed and the
  fail-closed scope reconciliation exactly as-is.
- [ ] **Step 3: Full hermetic suite + `just fmt-check` + commit**
  (`diagnostics(native): reconcile additive budget with attribution terms`).

### Task 3: Re-run the measurement campaign to a typed decision row

**Files:**
- Create: `docs/perf-results/native-compiler-budget-v2.jsonl`
- Modify: `docs/native-default-conformance-campaign.md`

- [ ] **Step 1:** Freeze provenance (clean tree, `just build`, host
  metadata); Docker-only preflights for W1/W2/one-thread.
- [ ] **Step 2:** Plane A baseline (`baseline --samples 5`), Plane B W2
  ABBA (`run --schedule abba-5`), one-thread controls (warmup+3 per plane),
  one Plane C dtrace shape — exactly the 2026-07-14 procedure.
- [ ] **Step 3:** `analyze --input docs/perf-results/native-compiler-budget-v2.jsonl --check`
  must now either emit exactly one typed decision row (append it to the
  evidence) or fail closed on a *named* term; either outcome is recorded
  verbatim in the campaign ledger. Do not proceed to any optimization if the
  model still does not reconcile — iterate attribution first.

### Task 4: Repair the selected term (gated on Task 3's decision row)

**Files:** named by the decision row; candidates, with their design-committed
prescriptions:
- `blocked-cpu` (parking/wake machinery): make the per-wait host path cheap —
  persistent kqueue registrations instead of per-wait register/deregister
  churn, narrower `native_wait_should_interrupt` predicate work, no polling
  backstop on hot paths (`crates/carrick-vmm-hvf/src/io_wait.rs`,
  `crates/carrick-runtime/src/native_darwin.rs` wait functions). Do not
  replace Linux blocking semantics with spinning.
- `startup-cpu` (per-process bring-up): reuse/persist per-process prepared
  state across the run's processes where the prepared-image design already
  permits it; never weaken image identity or signing checks.
- `sensitive-exclusive` (if the reconciled ladder selects it with scopes
  agreeing): faithful translated exclusive regions or typed atomic lowering;
  explicitly no coarse lock.
- `resolver-recurrence` / `cold-translation-aot`: only with the recurring-PC
  and first-resolution proof the design demands.

- [ ] Red-first against the selected metric; require the reduced
  compiler/import workload to complete naturally below 20x Docker (target
  10x); keep every correctness gate (probe suite, exact reducers, `just ci`)
  green; then resume Task 8 at exact c94.

## Self-Review Results

- Spec coverage: the design's Plane B item "blocked/off-CPU time where it can
  be measured without polling" and "process/self-reexec startup count and
  time" — previously unimplemented, the proximate cause of the fail-closed
  additive gate — are Task 1; the decision-rule rungs stay untouched except
  for gaining honestly measured on-CPU denominators (Task 2); the campaign
  re-run and the no-discretion-drift decision are Task 3; every repair
  candidate in Task 4 carries the design's own prescription and gates.
- Placeholder scan: none; the only deliberately open item is which term the
  typed decision row names, which is the point of the plan.
- Type consistency: field names (`phase_blocked_cpu_ns`, `startup_wall_ns`,
  `startup_cpu_ns`, `helper_cpu_ns`) are used identically in Tasks 1-2.
