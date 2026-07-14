# Native Compiler Performance Measurement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a reproducible, reconciled native compiler performance budget whose untraced timings select the first optimization slice without prematurely choosing AOT caching or sensitive-instruction lowering.

**Architecture:** Add a profiling-gated `NATIVEPERF1` record emitted once per native DSR thread, with exact exit-kind counts and exclusive loop-phase durations. A standard-library Python runner validates immutable W1/W2 workload manifests, executes Carrick and Docker in separate phases, validates every profile record, and writes deterministic JSONL evidence. The tranche ends with a measured decision and a separate implementation plan for the selected optimization; it does not implement that optimization.

**Tech Stack:** Rust 1.96.0, macOS `mach_absolute_time`, serde/serde_json, Python 3 standard library, Go `-toolexec`, signed Carrick native backend, Docker arm64 oracle, DTrace/USDT.

## Global Constraints

- DTrace overhead is acceptable and expected to be proportional; DTrace counts, ordering, exit mix, and relative distribution are evidence, while absolute wall-time authority comes only from signed untraced runs.
- W1 is `/conformance/go_types.test -test.v -test.run '^TestImplicitsInfo$' -test.short` with its existing page profile and `max_traps`; do not raise the ceiling.
- W2 is an exact captured `linux_arm64/compile` or `cgo` child with hashed executable, inputs, argv, environment, and output contract. `GOMAXPROCS=1` is a diagnostic variant only.
- Carrick and Docker phases never overlap. Every Carrick run has a unique `CARRICK_RUN_ID` and a successful scoped cleanup receipt from `sudo -n scripts/sudo/kill.sh <run-id>`.
- Profile-off code follows the existing const-specialized path and takes no new subsystem lock solely for measurement.
- Profile timings are usable for proportions only when the fixed ABBA profile-on/profile-off p50 tax is at most 10%; exact counts remain usable above that threshold.
- Every gateway iteration reconciles to exactly one typed exit kind. Missing, duplicate, overflowed, incomplete, dirty-provenance, failed-work, or greater-than-2% CPU reconciliation records invalidate a run.
- Do not raise timeouts or `max_traps`, reduce workload work, weaken AArch64 exclusive/signal semantics, or implement persistence/AOT before the evidence decision.
- Do not read Linux kernel or other GPL implementation source.
- Use `just build` before live execution and confirm the signed binary contains the new `NATIVEPERF1` marker.

## File Structure

- Create `crates/carrick-runtime/src/native_darwin/dsr/profile.rs`: typed profile mode, exit/sensitive/phase enums, overflow-detecting counters, monotonic timers, reconciliation, and `NATIVEPERF1` serialization.
- Modify `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`: own the per-thread budget, feed translation/cache facts into it, and emit one completion record on thread teardown.
- Modify `crates/carrick-runtime/src/native_darwin/dsr/types.rs`: expose stable typed classifications for `NativeDsrExit` and `SensitiveKind`; never serialize debug strings or raw ordinals chosen at call sites.
- Modify `crates/carrick-runtime/src/native_darwin.rs`: const-specialized exclusive loop-phase timing and exact accounting around prepare/run, finish/recovery, sensitive emulation, syscall dispatch, loop/quiesce, and blocked syscall outcomes.
- Create `scripts/perf/native_compiler_budget.py`: manifest validation, provenance hashing, isolated Carrick/Docker execution, `/usr/bin/time -l` parsing, `NATIVEPERF1` parsing/reconciliation, ABBA and baseline orchestration, and deterministic JSONL analysis.
- Create `scripts/perf/test_native_compiler_budget.py`: hermetic parser, manifest, reconciliation, statistics, scheduling, and invalid-run tests.
- Create `scripts/perf/native-compiler-toolexec.sh`: Docker-only Go `-toolexec` capture wrapper that records NUL-delimited tool argv before tail-calling the real tool.
- Create `scripts/perf/manifests/native-compiler-w1-v1.json`: immutable W1 command and environment declaration.
- Create `scripts/perf/manifests/native-compiler-w2-v1.json`: generated and then checked-in exact W2 command/input manifest.
- Create `scripts/perf/fixtures/native-compiler-w2-v1/`: the smallest hashed input bundle required to replay W2 directly.
- Create `docs/perf-results/native-compiler-budget-v1.jsonl`: measured Plane A/B/C rows and the selected decision, added only after live evidence exists.
- Modify `docs/native-default-conformance-campaign.md`: record measured results separately from the selected next implementation.
- Modify `.superpowers/sdd/progress.md`: record the measurement tranche and review state without claiming Task 8 complete.
- Create `docs/superpowers/plans/2026-07-14-native-compiler-selected-slice.md`: follow-on plan whose contents come from the measured decision rule and whose first section records the concrete selected slice.

---

### Task 1: Reconciled Low-Tax Native DSR Budget

**Files:**
- Create: `crates/carrick-runtime/src/native_darwin/dsr/profile.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs:119-300,865-1060`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/types.rs:178-260`
- Modify: `crates/carrick-runtime/src/native_darwin.rs:1480-2090`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/profile.rs`
- Test: `crates/carrick-runtime/src/native_darwin.rs` native DSR unit-test module

**Interfaces:**
- Consumes: `CARRICK_DSR_PROFILE`, `ThreadTranslator`, `NativeDsrExit`, `SensitiveKind`, `prepare_and_enter_dsr::<PROFILE>`, and `dispatch_native_syscall`.
- Produces: `profile::ThreadBudget`, `profile::ExitClass`, `profile::SensitiveClass`, `profile::Phase`, `profile::PhaseTimer`, `PreparedExit::profile_class()`, and one `NATIVEPERF1|thread|...` record per profiled thread.
- Invariant: `gateway_entries == syscall + resolve_direct + resolve_indirect + sensitive + fault + kick + stale_generation + unsupported` using checked arithmetic; `complete=1` appears only after reconciliation succeeds.

- [ ] **Step 1: Add red-first protocol and reconciliation tests**

Add tests in the new module before adding the implementation:

```rust
#[test]
fn thread_budget_reconciles_every_gateway_exit() {
    let mut budget = ThreadBudget::enabled_for_test(41, 42);
    for class in ExitClass::ALL {
        budget.record_exit(class).expect("count exit");
    }
    let record = budget.complete_record().expect("reconciled record");
    assert_eq!(record.gateway_entries, ExitClass::ALL.len() as u64);
    assert_eq!(record.reconciled_exits, record.gateway_entries);
    assert!(record.to_protocol_line().starts_with("NATIVEPERF1|thread|"));
    assert!(record.to_protocol_line().contains("complete=1"));
}

#[test]
fn thread_budget_rejects_missing_exit_and_overflow() {
    let mut missing = ThreadBudget::enabled_for_test(41, 42);
    missing.record_gateway_entry().expect("gateway");
    assert!(matches!(missing.complete_record(), Err(ProfileError::ExitMismatch { .. })));

    let mut overflow = ThreadBudget::enabled_for_test(41, 42);
    overflow.set_gateway_entries_for_test(u64::MAX);
    assert!(matches!(overflow.record_gateway_entry(), Err(ProfileError::CounterOverflow("gateway_entries"))));
}

#[test]
fn sensitive_classes_have_stable_protocol_names() {
    assert_eq!(SensitiveClass::from(SensitiveKind::Exclusive(0)).as_str(), "exclusive");
    assert_eq!(SensitiveClass::from(SensitiveKind::DcZva).as_str(), "dc-zva");
    assert_eq!(SensitiveClass::ALL.len(), 8);
}
```

- [ ] **Step 2: Run the focused tests and prove RED**

Run:

```bash
cargo test -p carrick-runtime native_darwin::dsr::profile::tests -- --nocapture
```

Expected: compilation fails because `profile`, `ThreadBudget`, and the typed classes do not exist.

- [ ] **Step 3: Implement typed classes, checked counters, and monotonic timing**

Implement `profile.rs` around these exact public-to-module contracts:

```rust
pub(super) const PROTOCOL_PREFIX: &str = "NATIVEPERF1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExitClass {
    Syscall, ResolveDirect, ResolveIndirect, Sensitive,
    Fault, Kick, StaleGeneration, Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SensitiveClass {
    Exclusive, ReadTpidr, WriteTpidr, ReadCtr,
    ReadDczid, DcZva, DcCvau, IcIvau,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    PrepareIndex, Translate, TranslatedRun, FinishExit,
    SensitiveEmulation, SyscallDispatch, LoopQuiesce, Blocked,
}

pub(super) struct ThreadBudget {
    enabled: bool,
    pid: libc::pid_t,
    tid: i32,
    gateway_entries: u64,
    exits: [u64; ExitClass::COUNT],
    sensitive: [u64; SensitiveClass::COUNT],
    phase_ns: [u64; Phase::COUNT],
    phase_counts: [u64; Phase::COUNT],
    overflowed: bool,
}

impl ThreadBudget {
    pub(super) fn from_environment(tid: i32) -> Self;
    pub(super) fn enabled(&self) -> bool;
    pub(super) fn record_gateway_entry(&mut self) -> Result<(), ProfileError>;
    pub(super) fn record_exit(&mut self, class: ExitClass) -> Result<(), ProfileError>;
    pub(super) fn record_sensitive(&mut self, class: SensitiveClass) -> Result<(), ProfileError>;
    pub(super) fn add_phase(&mut self, phase: Phase, elapsed_ns: u64) -> Result<(), ProfileError>;
    pub(super) fn complete_record(&self) -> Result<CompleteThreadRecord, ProfileError>;
}
```

Use `mach_absolute_time` plus one cached `mach_timebase_info` conversion on macOS. `PhaseTimer::disabled()` performs no clock read. All increments use `checked_add`; never encode saturation as valid evidence. Protocol output uses stable kebab-case names and decimal integers, not `Debug` formatting.

- [ ] **Step 4: Classify exits and sensitive kinds without raw call-site numbering**

Add methods to `types.rs`:

```rust
impl NativeDsrExit {
    pub(super) const fn profile_class(&self) -> profile::ExitClass { /* exhaustive match */ }
}

impl SensitiveKind {
    pub(super) const fn profile_class(self) -> profile::SensitiveClass { /* exhaustive match */ }
}
```

The match must name every variant; do not use `_`. `Kick` and `KickAtEntry` share `ExitClass::Kick`. Any future enum variant must fail compilation until classified.

- [ ] **Step 5: Split prepare from translated execution and wire exact exclusive timings**

Replace the boolean-only `profiling` field with a `ThreadBudget`. Split `prepare_and_enter_dsr` into `prepare_dsr_entry::<PROFILE>` and `enter_dsr_prepared::<PROFILE>` so translated guest execution is not charged to preparation. Select the two const-specialized function pointers once before the loop, preserving the `<false>` production path when disabled. Add `PreparedExit::profile_class()` inside `dsr::mod` rather than exposing its private `NativeDsrExit` field. Wire the loop with the following ownership:

```rust
let loop_timer = profile::PhaseTimer::start_if::<PROFILE>();
thread_runtime.park_for_fork_quiesce();
translator.add_profile_phase(profile::Phase::LoopQuiesce, loop_timer)?;

let prepare_timer = profile::PhaseTimer::start_if::<PROFILE>();
let prepared = prepare(&mut translator, &memory, &snapshot)?;
translator.add_profile_phase(profile::Phase::PrepareIndex, prepare_timer)?;

let run_timer = profile::PhaseTimer::start_if::<PROFILE>();
let raw_exit = enter(&mut translator, prepared, &mut snapshot)?;
translator.add_profile_phase(profile::Phase::TranslatedRun, run_timer)?;

let finish_timer = profile::PhaseTimer::start_if::<PROFILE>();
let exit_class = raw_exit.profile_class();
let exit = translator.finish_exit(&memory.lock(), &mut snapshot, prepared, raw_exit)?;
translator.record_profile_exit(exit_class)?;
translator.add_profile_phase(profile::Phase::FinishExit, finish_timer)?;
```

Keep translation subphase timings already collected in `ResolverStats`; export them as nested diagnostics and exclude them from the exclusive sum. Time sensitive emulation around the existing exhaustive `SensitiveKind` match.

Make `dispatch_native_syscall` const-generic and return `TimedDispatchOutcome { outcome, blocked_ns }`. Around each existing blocking helper, read the clock only for `<true>` and checked-add the interval to `blocked_ns`. After return, charge `Phase::Blocked = blocked_ns` and `Phase::SyscallDispatch = total_dispatch_ns.checked_sub(blocked_ns)`; an underflow invalidates the record. This makes blocking and active dispatch mutually exclusive without polling or a new lock.

- [ ] **Step 6: Emit exactly one complete record and test malformed completion**

On `ThreadTranslator::drop`, call `complete_record`. Emit a successful line only when complete:

```text
NATIVEPERF1|thread|complete=1|pid=41|tid=42|gateway_entries=8|exit_syscall=1|...|phase_syscall_dispatch_ns=123
```

On overflow or mismatch emit:

```text
NATIVEPERF1|invalid|complete=0|pid=41|tid=42|reason=exit-mismatch
```

Never emit both for one translator. Add a test that a fork-child reset terminates the parent-era budget before resetting counters, so one record never combines two process identities.

- [ ] **Step 7: Run focused, runtime, formatting, and compile gates**

Run:

```bash
cargo test -p carrick-runtime native_darwin::dsr::profile::tests -- --nocapture
cargo test -p carrick-runtime native_darwin::tests::dsr_sensitive_flow_runtime_reuses_native_system_register_semantics -- --nocapture
cargo test -p carrick-runtime --lib
just fmt-check
cargo clippy -p carrick-runtime --all-targets -- -D warnings
```

Expected: all pass; the profile protocol tests prove exhaustive reconciliation and overflow rejection.

- [ ] **Step 8: Build, sign, and prove profile-off/profile-on behavior live**

Run:

```bash
just build
strings target/release/carrick | grep NATIVEPERF1
codesign -d --entitlements :- target/release/carrick
```

Run one signed bounded W1 control without `CARRICK_DSR_PROFILE` and one with it, using distinct `CARRICK_RUN_ID`s. Expected: no `NATIVEPERF1` line when off; one complete line per native thread when on; both preserve the same workload result or same existing trap-limit result; both cleanup receipts succeed.

- [ ] **Step 9: Commit the independently reviewable profiler**

```bash
git add crates/carrick-runtime/src/native_darwin.rs \
  crates/carrick-runtime/src/native_darwin/dsr/mod.rs \
  crates/carrick-runtime/src/native_darwin/dsr/profile.rs \
  crates/carrick-runtime/src/native_darwin/dsr/types.rs
git commit -m "diagnostics(native): reconcile compiler DSR budgets" -m "Record exact native gateway exit classes and exclusive loop-phase durations behind the existing profiling switch. Reject overflowed or unreconciled thread records so compiler attribution cannot silently bless partial evidence.\n\nVerified with focused profile protocol tests, the DSR sensitive runtime reducer, the runtime library suite, clippy, and signed profile-off/profile-on W1 controls.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 2: Immutable Compiler Workloads and Evidence Analyzer

**Files:**
- Create: `scripts/perf/native_compiler_budget.py`
- Create: `scripts/perf/test_native_compiler_budget.py`
- Create: `scripts/perf/native-compiler-toolexec.sh`
- Create: `scripts/perf/manifests/native-compiler-w1-v1.json`
- Create: `scripts/perf/manifests/native-compiler-w2-v1.json`
- Create: `scripts/perf/fixtures/native-compiler-w2-v1/`

**Interfaces:**
- Consumes: `NATIVEPERF1` stderr records, signed `target/release/carrick`, `/usr/bin/time -l`, Docker arm64, and Task 1's exact field names.
- Produces: `load_manifest(path) -> WorkloadManifest`, `parse_nativeperf(lines) -> ProfileRun`, `validate_profile(run)`, `run_phase(...) -> RunRecord`, and `analyze(records) -> DecisionRecord`.
- Manifest schema: `carrick.native-compiler-workload.v1`; result schema: `carrick.native-compiler-budget.v1`.

**Review reconciliation:** The implemented result wire uses strict tagged
`run`/`decision` variants and a typed outcome (`completed`, `max-traps`, or
`failed`). Non-completing W1 rows, including the fixed status-125 trap ceiling,
are retained as baseline evidence but are deliberately rejected by decision
analysis. Docker identity and replay checks run once in an explicit Docker-only
preflight that writes a hashed receipt; Carrick measurement consumes that
receipt without invoking Docker. Baseline execution is engine-major (all
Carrick W1/W2 samples and scoped cleanup, then all Docker W1/W2 samples), while
the Plane B comparison uses the exact warmup-inclusive ABBA order.

- [ ] **Step 1: Write red-first manifest and protocol parser tests**

Add hermetic tests using temporary files and synthetic records:

```python
def test_manifest_rejects_changed_input_hash(self):
    manifest, root = fixture_manifest(self.tmp)
    (root / "input.go").write_text("package changed\n", encoding="utf-8")
    with self.assertRaisesRegex(BudgetError, "sha256 mismatch"):
        load_manifest(manifest)

def test_profile_requires_complete_unique_threads_and_exact_exits(self):
    lines = [
        "NATIVEPERF1|thread|complete=1|pid=10|tid=11|gateway_entries=2|"
        "exit_syscall=1|exit_resolve_direct=1|exit_resolve_indirect=0|"
        "exit_sensitive=0|exit_fault=0|exit_kick=0|"
        "exit_stale_generation=0|exit_unsupported=0|overflowed=0"
    ]
    profile = parse_nativeperf(lines)
    validate_profile(profile)
    with self.assertRaisesRegex(BudgetError, "duplicate thread"):
        validate_profile(parse_nativeperf(lines + lines))

def test_decision_uses_untraced_cpu_not_dtrace_wall(self):
    record = synthetic_budget(translation_cpu_share=.12, sensitive_exit_share=.46)
    self.assertEqual(analyze([record]).selected_slice, "sensitive-exclusive")
```

- [ ] **Step 2: Run tests and prove RED**

Run:

```bash
python3 -m unittest -v scripts/perf/test_native_compiler_budget.py
```

Expected: import failure because `native_compiler_budget.py` does not exist.

- [ ] **Step 3: Implement strict schemas, hashing, parser, and decision rules**

Implement frozen dataclasses:

```python
@dataclasses.dataclass(frozen=True)
class WorkloadManifest:
    schema: str
    name: str
    image: str
    workdir: str
    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    files: tuple[HashedFile, ...]
    expected_exit: int
    expected_stdout_sha256: str
    max_traps: int
    native_page_profile: str

@dataclasses.dataclass(frozen=True)
class RunRecord:
    schema: str
    workload: str
    plane: str
    repetition: int
    run_id: str
    binary_sha256: str
    wall_ns: int
    user_ns: int
    system_ns: int
    peak_rss_bytes: int
    exit_status: int
    work_units: int
    cleanup_ok: bool
    profile: ProfileRun | None
```

Reject unknown schema, unknown fields, duplicate keys, non-absolute guest argv[0], unordered environment, missing hashes, changed binary/hash, dirty Git state, malformed time output, duplicate `(pid, tid)` records, any `complete=0`, any overflow, and any exit reconciliation mismatch. Implement all 30%/60% decision rules from the design with fixed tie order: sensitive, resolver recurrence, cold translation, syscall, blocked/residual, then smallest two-term slice.

- [ ] **Step 4: Implement Docker-only `-toolexec` capture and W2 materialization**

The POSIX wrapper must append NUL-delimited records atomically to a mounted path and then exec the real tool:

```sh
#!/bin/sh
set -eu
tool=$1
shift
{
  printf 'TOOLEXEC1\0'
  printf '%s\0' "$tool" "$@"
  printf '\0'
} >>"${CARRICK_TOOLEXEC_LOG:?}"
exec "$tool" "$@"
```

Run the exact c94/W1 Docker command with `GOFLAGS=-toolexec=/capture/native-compiler-toolexec.sh` in a Docker-only phase. The Python `capture-w2` subcommand selects the smallest naturally successful `linux_arm64/compile` or `cgo` child, copies every absolute input file named by the captured command from the container into `scripts/perf/fixtures/native-compiler-w2-v1/`, records executable/input SHA-256 values and relevant sorted environment, then replays the direct command under Docker. Reject the capture unless direct replay has the same exit status and output digest twice.

- [ ] **Step 5: Add the immutable W1 declaration and generated W2 declaration**

W1 JSON must pin:

```json
{
  "schema": "carrick.native-compiler-workload.v1",
  "name": "w1-test-implicits-info",
  "image": "localhost:5005/carrick-go-conformance:1.24",
  "workdir": "/usr/local/go/src/go/types",
  "argv": ["/conformance/go_types.test", "-test.v", "-test.run", "^TestImplicitsInfo$", "-test.short"],
  "env": [],
  "max_traps": 1000000,
  "native_page_profile": "native16k"
}
```

Populate all provenance/hash fields required by the schema from live files; do not invent missing values in the plan. Generate W2 solely through `capture-w2`, then inspect and check in the manifest plus minimal fixture bundle.

- [ ] **Step 6: Implement phase isolation, fixed schedules, and cleanup receipts**

Provide subcommands `validate`, `capture-w2`, `run`, and `analyze`. `run` accepts `--plane untraced|profiled|dtrace` and a complete explicit schedule. The ABBA schedule is `off-1,on-1,on-2,off-2` repeated until each mode has five measured samples after one discarded warm-up. Baseline schedules interleave workloads but never Carrick and Docker. After every Carrick invocation, call:

```python
subprocess.run(
    ["sudo", "-n", "scripts/sudo/kill.sh", run_id],
    cwd=repo,
    check=True,
    timeout=30,
)
```

Before Docker, prove there are zero scoped Carrick descendants. Use `/usr/bin/time -l` for wall/user/system/RSS and parse under `LC_ALL=C`. Store stdout, stderr, time, cleanup, manifest, and provenance beside each run before appending its JSONL record atomically.

- [ ] **Step 7: Run all hermetic tests and dry-run validation**

Run:

```bash
python3 -m unittest -v scripts/perf/test_native_compiler_budget.py
python3 scripts/perf/native_compiler_budget.py validate \
  scripts/perf/manifests/native-compiler-w1-v1.json \
  scripts/perf/manifests/native-compiler-w2-v1.json
shellcheck scripts/perf/native-compiler-toolexec.sh
just fmt-check
```

Expected: tests pass; both manifests validate; shellcheck and formatting pass. If `shellcheck` is unavailable, record that absence and run `sh -n` plus the wrapper's hermetic exec test instead.

- [ ] **Step 8: Commit the independently reviewable workload tool**

```bash
git add scripts/perf/native_compiler_budget.py \
  scripts/perf/test_native_compiler_budget.py \
  scripts/perf/native-compiler-toolexec.sh \
  scripts/perf/manifests/native-compiler-w1-v1.json \
  scripts/perf/manifests/native-compiler-w2-v1.json \
  scripts/perf/fixtures/native-compiler-w2-v1
git commit -m "diagnostics(native): freeze compiler performance workloads" -m "Capture an exact Go compiler child through the supported toolexec boundary, hash its replay inputs, and add strict isolated runners for untraced, in-process-profiled, and DTrace evidence. Invalid or unreconciled records fail closed.\n\nVerified with hermetic parser and scheduling tests, manifest validation, two Docker W2 replays, shell validation, and formatting.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 3: Measure the Budget and Select the Dominant Slice

**Files:**
- Create: `docs/perf-results/native-compiler-budget-v1.jsonl`
- Modify: `docs/native-default-conformance-campaign.md`
- Modify: `.superpowers/sdd/progress.md`
- Create: `docs/superpowers/plans/2026-07-14-native-compiler-selected-slice.md`

**Interfaces:**
- Consumes: signed Task 1 binary, Task 2 manifests/runner, W1/W2 output contracts, existing `carrick trace --profile dsr`, and the committed decision rules.
- Produces: validated Plane A/B/C records, a single `decision` JSONL row naming the measured dominant slice, and a separate reviewed implementation plan for that slice.
- Does not produce: runtime optimization code, a timeout change, a `max_traps` change, an AOT artifact, or a conformance bless.

- [ ] **Step 1: Freeze live provenance before measurement**

Run `just build`, verify codesign/marker, and record Git SHA/dirty state, binary SHA-256/CDHash, workload manifest hashes, image identity, macOS version, host model, CPU count, and power state. Abort if tracked files are dirty or if the signed binary hash differs from the run declaration.

- [ ] **Step 2: Establish untraced Plane A authority**

For W1 and W2, discard one warm-up and collect at least five signed Carrick repetitions in fixed interleaved order with profiling absent. W1 may hit the existing one-million ceiling before the fix; W2 must use its frozen direct replay. Only after all Carrick processes and scoped cleanup are complete, collect at least five Docker repetitions. Require exact output/status/work units and write every raw receipt before generating JSONL.

Expected pre-fix result: measured wall/user/system/RSS and Carrick/Docker p50 ratios; W1's ceiling is recorded as a failure outcome, never reclassified as completion.

- [ ] **Step 3: Measure Plane B tax with fixed ABBA**

Run W2 in `off,on,on,off` blocks until each mode has five measured samples plus its discarded warm-up. Analyze p50 tax:

```text
tax = profiled_p50 / unprofiled_p50 - 1
```

If tax is at most 10%, accept profile durations and counts. If tax is above 10%, accept exact counts only and mark all duration-based shares `diagnostic_only=true`; do not weaken the threshold.

- [ ] **Step 4: Reconcile Plane B and compute the additive budget**

For every profiled run require unique complete `(pid,tid)` records and exact exit reconciliation. For W2-one-thread compare exclusive on-CPU phase sum against measured user+system CPU, compute an explicit residual, and reject negative residual or absolute reconciliation difference above 2%. For multithreaded W1/W2 report per-thread terms, aggregate CPU, and process wall separately; never sum thread wall against process wall.

- [ ] **Step 5: Collect one bounded Plane C DTrace shape**

Run `carrick trace --profile dsr` only after Plane A/B Carrick processes are gone. Require natural/bounded completion metadata, zero drops, zero incomplete pairs, and per-PID reconciliation. State explicitly in the output row that DTrace wall magnitude is inflated and excluded from absolute timing/decision inputs; retain its counts, ordering, exit mix, and relative shape.

- [ ] **Step 6: Apply the decision rules without discretion drift**

Run `analyze` to emit exactly one decision row. Selection order is the design's measured rule: dominant sensitive kind by exit share; recurrent resolution; cold translation/first-resolution by untraced CPU; syscall; blocked/residual; otherwise the smallest independently verified two-term slice reaching 60%. AOT is selectable only if cold translation plus first resolution is at least 30% of untraced CPU and the analyzer cites the supporting run IDs. No selection may use DTrace wall magnitude.

- [ ] **Step 7: Record evidence and update the campaign honestly**

Append the exact measured ratios, profile tax, reconciled count mix, accepted/diagnostic timing status, residual, DTrace completeness, and selected slice to `docs/native-default-conformance-campaign.md`. Update `.superpowers/sdd/progress.md` to `performance measurement complete; optimization pending`. Keep Task 8 incomplete and do not change the bless checklist.

- [ ] **Step 8: Write the selected optimization's separate implementation plan**

Use the writing-plans skill again. The new plan must cite the exact decision row and preserve every correctness/promotion gate from the design. If the selected slice is `sensitive-exclusive`, plan faithful translated exclusive regions or typed atomic lowering and explicitly reject a coarse lock. If it is `resolver-recurrence`, plan link/cache repair before persistence. If it is `cold-translation-aot`, first write and approve a relocatable artifact design keyed by guest content, page profile, translator ABI, host ISA/features, and relocation assumptions.

- [ ] **Step 9: Run final measurement-tranche gates**

Run:

```bash
python3 -m unittest -v scripts/perf/test_native_compiler_budget.py
python3 scripts/perf/native_compiler_budget.py analyze \
  --input docs/perf-results/native-compiler-budget-v1.jsonl \
  --check
just ci
```

Expected: evidence validates deterministically, the decision is reproducible, and `just ci` passes. Live signed W1/W2 results are cited in the ledger; no performance-fix claim is made yet.

- [ ] **Step 10: Commit evidence, ledger, and follow-on plan**

Use the measured slice in the subject/body; do not use the literal placeholder:

```bash
git add docs/perf-results/native-compiler-budget-v1.jsonl \
  docs/native-default-conformance-campaign.md \
  docs/superpowers/plans/2026-07-14-native-compiler-selected-slice.md
git commit -m "docs(native): select measured compiler performance slice" -m "Record the untraced W1/W2 authority, the reconciled low-tax native budget, and the bounded DTrace exit shape. Apply the committed decision rule without treating inflated DTrace wall time as absolute authority; the checked-in follow-on plan names the selected slice and its evidence.\n\nVerified with deterministic evidence analysis, signed workload runs and scoped cleanup receipts, complete DTrace reconciliation, and just ci.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

`.superpowers/sdd/progress.md` is ignored controller state and remains uncommitted unless repository policy changes.

## Self-Review Results

- Spec coverage: W1/W2 freezing, Plane A authority, Plane B reconciliation/tax, Plane C proportional evidence, additive residual, decision rules, failure handling, and correctness gates all map to explicit tasks. W3 and the optimization/promotion gates deliberately belong to the follow-on optimization plan because W3 is forbidden until W2 completes naturally.
- Placeholder scan: no deferred filename, symbol, error-handling, or test placeholders remain. The fixed `native-compiler-selected-slice.md` filename records the analyzer's concrete choice in its content.
- Type consistency: Task 1's `NATIVEPERF1`, typed classifications, and completion rules exactly match Task 2's parser contract; Task 2's `RunRecord` is the input to Task 3's analyzer and decision row.
- Scope check: this plan delivers one testable subsystem—the performance measurement and decision mechanism. The selected optimization is intentionally a separate plan because its architecture cannot be known before measurement.
