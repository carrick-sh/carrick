# Atomic Exec-to-Terminal Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the split exec/exit ownership protocol with one atomic gate transition, prove the previously reachable race red-first, and bind its cost to paired release-mode observations.

**Architecture:** `CloneAdmissionGate` becomes the sole terminal-owner authority by storing `Exit { owner }` and consuming an exact `ExecCloneAdmission` directly into that state. A typed `ExecTerminalHandoff` keeps the exec close alive across pending-resume errors, while a release reducer measures the exact production claim helpers before and after the fix without adding instrumentation to shipped code.

**Tech Stack:** Rust 2024, `parking_lot::{Mutex, Condvar}`, Carrick HVPatch runtime state machines, serialized Rust tests, Python 3 standard library, Mach-O `dwarfdump`, SHA-256, paired ABBA measurements.

**Spec:** `docs/superpowers/specs/2026-09-01-atomic-exec-terminal-handoff-design.md`

## Global Constraints

- `CloneAdmissionGate` is the single authority for admission closure and process-terminal ownership; remove `KernelState::persistent_exit_owner`.
- The only destructive handoff is exact `Exec { owner, generation } -> Exit { owner }` under the existing gate mutex; never expose `None`.
- Preserve the original pending-exec error and publish no fabricated guest or compatibility return.
- Production claim paths add no allocation, clock read, probe, event-ring write, blocking wait, second mutex, second atomic, or extra lock acquisition.
- Deterministic concurrency proof uses channels/barriers, never sleeps or scheduler probability.
- Performance evidence uses release-mode ABBA order `baseline A -> fixed B -> fixed B -> baseline A`, at least five warmups and thirty samples of at least 100,000 transitions.
- Accept only when fixed generic-claim median is at most `1.05x` baseline and p95 is at most `1.10x` baseline, with zero competing-exec admissions.
- Bind evidence to source commit, executable SHA-256 and Mach-O UUID, toolchain, host identity, exact command, process census, raw samples, median, and p95.
- Host reducer results are not signed guest, Docker-oracle, conformance, or shipped `<=2x` workload proof.
- Run runtime tests with `RUST_TEST_THREADS=1`; never use a parallel bare workspace library test.

---

## File Structure

- `crates/carrick-runtime/src/vcpu_loop/mod.rs` — clone-admission state/authority, terminal entry, deterministic race tests, and the ignored release reducer.
- `crates/carrick-runtime/src/vcpu_loop/exec.rs` — consuming conversion from `PreparedExecveDrain` to `ExecTerminalHandoff`.
- `scripts/perf/atomic_exec_terminal_handoff_abba.py` — isolated-ref build, executable identification, quiet-host census, ABBA orchestration, sample validation, and threshold decision.
- `scripts/perf/test_atomic_exec_terminal_handoff_abba.py` — deterministic parser, ordering, identity, and threshold tests for the runner.
- `docs/perf-results/2026-09-01-atomic-exec-terminal-handoff.json` — machine-readable raw receipt.
- `docs/perf-results/2026-09-01-atomic-exec-terminal-handoff.md` — human-readable scope, result, and non-claims.

### Task 1: Install the Exact Baseline Reducer

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:1915-1935`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs` test module near the clone-admission tests
- Create: `scripts/perf/atomic_exec_terminal_handoff_abba.py`
- Create: `scripts/perf/test_atomic_exec_terminal_handoff_abba.py`

**Interfaces:**
- Consumes: current split `persistent_exit_owner` plus `CloneAdmissionGate::try_claim_process_exit()` and current destructor-driven exec-error sequence.
- Produces: `try_claim_persistent_process_exit_with(...)`, ignored test `clone_admission_terminal_claim_cost_receipt`, receipt prefix `CARRICK_EXEC_TERMINAL_PERF|`, and runner CLI `--single`/`--baseline`/`--candidate`/`--output`.

- [ ] **Step 1: Extract the exact current generic-claim helper without changing semantics**

Add beside `KernelState::try_claim_persistent_process_exit`:

```rust
fn try_claim_persistent_process_exit_with(
    persistent_exit_owner: &std::sync::atomic::AtomicI32,
    clone_admission: &CloneAdmissionGate,
    owner: ThreadId,
) -> Result<ProcessExitClaim, RuntimeError> {
    let owner_raw = owner.raw();
    match persistent_exit_owner.compare_exchange(
        0,
        owner_raw,
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Acquire,
    ) {
        Ok(_) => {}
        Err(current) if current == owner_raw => {}
        Err(_) => return Ok(ProcessExitClaim::AlreadyOwned),
    }
    clone_admission.try_claim_process_exit()
}
```

Make the production method delegate to it and retain the existing
`begin_process_exit()` call only for `ProcessExitClaim::Owner`. This extraction
must produce no semantic diff beyond the helper call.

- [ ] **Step 2: Add the ignored release reducer over exact production operations**

Add test-only sample types and the exact ignored test:

```rust
#[derive(serde::Serialize)]
struct ExecTerminalPerfSample {
    operation: &'static str,
    sample: usize,
    iterations: usize,
    elapsed_ns: u128,
    ns_per_transition: f64,
    contender_admissions: usize,
}

#[test]
#[ignore = "manual release-mode performance receipt"]
fn clone_admission_terminal_claim_cost_receipt() {
    let iterations = std::env::var("CARRICK_HANDOFF_PERF_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000_usize);
    let warmups = std::env::var("CARRICK_HANDOFF_PERF_WARMUPS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(5_usize);
    let samples = std::env::var("CARRICK_HANDOFF_PERF_SAMPLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(30_usize);
    assert!(iterations >= 100_000);
    assert!(warmups >= 5);
    assert!(samples >= 30);
    run_exec_terminal_perf_samples(iterations, warmups, samples);
}
```

`run_exec_terminal_perf_samples` prepares every gate, atomic, owner, and exec
guard before `Instant::now()`. The generic case times only
`try_claim_persistent_process_exit_with`. The handoff case times the current
production-shaped `drop(exec_guard)` followed by that helper. Each measured
sample prints exactly one line:

```rust
println!(
    "CARRICK_EXEC_TERMINAL_PERF|{}",
    serde_json::to_string(&sample).expect("serialize perf sample")
);
```

Use a fresh vector of `iterations` prebuilt cases per sample, so reset,
allocation, owner construction, `close_for_exec`, and teardown remain outside
the timed interval.

- [ ] **Step 3: Run the reducer once and verify its sample contract**

Run:

```bash
RUST_TEST_THREADS=1 \
CARRICK_HANDOFF_PERF_ITERATIONS=100000 \
CARRICK_HANDOFF_PERF_WARMUPS=5 \
CARRICK_HANDOFF_PERF_SAMPLES=30 \
cargo test --release -p carrick-runtime --lib \
  clone_admission_terminal_claim_cost_receipt -- --ignored --nocapture
```

Expected: 60 prefixed measured JSON lines after unreported warmups: 30
`generic_exit_claim` and 30 `exec_error_to_terminal`; every row has 100,000
iterations and zero contender admissions.

- [ ] **Step 4: Implement the isolated-ref ABBA runner**

Create a standard-library-only Python runner with this public CLI:

```python
parser.add_argument("--repo", type=Path, default=Path.cwd())
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument("--single")
mode.add_argument("--baseline")
parser.add_argument("--candidate")
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--iterations", type=int, default=100_000)
parser.add_argument("--warmups", type=int, default=5)
parser.add_argument("--samples", type=int, default=30)
```

Require `--candidate` with `--baseline`. Resolve refs with `git rev-parse`,
create detached temporary worktrees, and build with:

```python
[
    "cargo", "test", "--release", "-p", "carrick-runtime", "--lib",
    "--no-run", "--message-format=json",
]
```

Parse the `compiler-artifact` whose target name is `carrick_runtime` and whose
`profile.test` is true. Record `sha256_file(executable)` and parse
`dwarfdump --uuid executable`. Invoke the test executable directly:

```python
env = {
    **os.environ,
    "CARRICK_HANDOFF_PERF_ITERATIONS": str(iterations),
    "CARRICK_HANDOFF_PERF_WARMUPS": str(warmups),
    "CARRICK_HANDOFF_PERF_SAMPLES": str(samples),
    "RUST_TEST_THREADS": "1",
}
cmd = [
    str(executable),
    "clone_admission_terminal_claim_cost_receipt",
    "--ignored",
    "--nocapture",
    "--exact",
]
```

Discover the full exact test name from `executable --list` rather than assuming
the module path. In paired mode run labels exactly `A1`, `B1`, `B2`, `A2` with
refs `[baseline, candidate, candidate, baseline]`. Reject missing/duplicate
samples, wrong iteration/sample cardinality, nonzero contender admissions,
changed executable identity for the same ref, and foreign processes matching
`carrick run`, `carrick-conformance`, `docker build`, or another reducer
instance. Exclude the runner's own PID and only its currently awaited build/test
child; any unrelated matching process invalidates the arm.

Aggregate median and nearest-rank p95 per ref/operation. Set `accepted` only
when:

```python
generic_median_ratio = candidate_median / baseline_median
generic_p95_ratio = candidate_p95 / baseline_p95
accepted = (
    generic_median_ratio <= 1.05
    and generic_p95_ratio <= 1.10
    and contender_admissions == 0
)
```

Write one deterministic JSON object containing schema version, exact commands,
host/toolchain identity, arm order, executable identities, raw rows, aggregates,
ratios, and `accepted`. Exit 1 when a paired receipt is valid but not accepted;
exit 2 when the receipt itself is invalid.

- [ ] **Step 5: Test runner parsing, ordering, identity, and thresholds**

Create `unittest.TestCase` coverage using synthetic prefixed rows. Include:

```python
def test_abba_order_is_exact(self):
    self.assertEqual(abba_refs("base", "fixed"), [
        ("A1", "base"), ("B1", "fixed"),
        ("B2", "fixed"), ("A2", "base"),
    ])

def test_threshold_rejects_slow_median(self):
    verdict = performance_verdict(
        baseline_median=10.0, baseline_p95=12.0,
        candidate_median=10.6, candidate_p95=12.0,
        contender_admissions=0,
    )
    self.assertFalse(verdict["accepted"])

def test_threshold_accepts_boundary(self):
    verdict = performance_verdict(
        baseline_median=10.0, baseline_p95=12.0,
        candidate_median=10.5, candidate_p95=13.2,
        contender_admissions=0,
    )
    self.assertTrue(verdict["accepted"])
```

Run:

```bash
python3 -m unittest scripts.perf.test_atomic_exec_terminal_handoff_abba -v
```

Expected: all parser/threshold tests pass.

- [ ] **Step 6: Commit the measurement seam and capture the baseline receipt**

Run:

```bash
git add crates/carrick-runtime/src/vcpu_loop/mod.rs \
  scripts/perf/atomic_exec_terminal_handoff_abba.py \
  scripts/perf/test_atomic_exec_terminal_handoff_abba.py
git commit -m "perf: measure exec terminal ownership handoff"
python3 scripts/perf/atomic_exec_terminal_handoff_abba.py \
  --single HEAD \
  --iterations 100000 --warmups 5 --samples 30 \
  --output .superpowers/sdd/2026-09-01-atomic-exec-terminal-handoff/baseline.json
```

Expected: commit succeeds; baseline JSON records both operations, exact source
and executable identity, 30 measured samples per operation, and zero contender
admissions. The SDD baseline artifact remains untracked but is named in the
task report and ledger.

### Task 2: Make Exec-to-Terminal Ownership Atomic

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:1263-1658`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:1694-1745`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:1910-1951`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:4441-4545`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:6959-7016`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs` clone-admission and pending-exec tests
- Modify: `crates/carrick-runtime/src/vcpu_loop/exec.rs:109-149`
- Modify: `crates/carrick-runtime/src/vcpu_loop/exec.rs:1844-1897`

**Interfaces:**
- Consumes: Task 1 reducer and exact current helper.
- Produces: `CloneAdmissionClose::Exit { owner }`, `ProcessExitClaimReceipt`, `ExecTerminalHandoff`, `PendingExecTerminal`, `PreparedExecveDrain::into_terminal_handoff`, and atomic `begin_persistent_process_terminal_from_exec`.

- [ ] **Step 1: Write the deterministic failing gate race test**

Add a test whose synchronization is entirely channel-driven:

```rust
#[test]
fn exec_terminal_handoff_never_reopens_admission_to_competing_exec() {
    let gate = Arc::new(CloneAdmissionGate::default());
    let owner = ThreadId::synthetic_for_tests(74_100);
    let contender = ThreadId::synthetic_for_tests(74_101);
    let admission = gate.close_for_exec(owner).expect("close for exec");
    let (validated_tx, validated_rx) = std::sync::mpsc::channel();
    let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();

    std::thread::scope(|scope| {
        let contender_gate = Arc::clone(&gate);
        let contender_thread = scope.spawn(move || {
            validated_rx.recv().expect("handoff validation");
            attempt_tx.send(()).expect("record contender attempt");
            contender_gate.close_for_exec(contender)
        });

        let claim = admission.claim_process_exit_with(|| {
            validated_tx.send(()).expect("release contender");
            attempt_rx.recv().expect("contender reached gate");
        });

        assert_eq!(claim.expect("exact handoff").claim, ProcessExitClaim::Owner);
        assert!(contender_thread.join().expect("contender join").is_err());
    });
    assert!(gate.try_enroll_thread_clone().is_none());
    assert!(gate.try_enroll_process_fork(contender).is_none());
    assert_eq!(
        gate.try_claim_process_exit(contender).expect("losing exit").claim,
        ProcessExitClaim::AlreadyOwned,
    );
}
```

Run before implementation:

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib \
  exec_terminal_handoff_never_reopens_admission_to_competing_exec -- --nocapture
```

Expected: compile failure because `claim_process_exit_with`, owner-bearing
`try_claim_process_exit`, and `ProcessExitClaimReceipt` do not exist. Record the
exact red receipt in the task report.

- [ ] **Step 2: Move exit-owner identity into the gate**

Implement:

```rust
enum CloneAdmissionClose {
    Exec { owner: ThreadId, generation: u64 },
    Fork { owner: ThreadId, generation: u64 },
    Exit { owner: ThreadId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessExitClaimReceipt {
    claim: ProcessExitClaim,
    change_epoch: u64,
}
```

Change `CloneAdmissionGate::try_claim_process_exit(owner)` so the match occurs
under its one existing mutex:

```rust
match state.closing {
    Some(CloneAdmissionClose::Exec { .. }) => ProcessExitClaim::LostToExec,
    Some(CloneAdmissionClose::Exit { owner: current }) if current != owner => {
        ProcessExitClaim::AlreadyOwned
    }
    Some(CloneAdmissionClose::Exit { .. }) => claim_from_in_flight(state.in_flight),
    Some(CloneAdmissionClose::Fork { .. }) | None => {
        state.closing = Some(CloneAdmissionClose::Exit { owner });
        state.change_epoch = state.change_epoch.checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        self.changed.notify_all();
        claim_from_in_flight(state.in_flight)
    }
}
```

Return the current `change_epoch` with the claim. Update every `Exit` pattern in
permit cancellation, tests, and diagnostics to `Exit { .. }`.

Remove `persistent_exit_owner` from `KernelState`, its initializer, and its
helper. Make `KernelState::try_claim_persistent_process_exit(owner)` delegate
only to `clone_admission.try_claim_process_exit(owner)` and set
`process_exiting` only for `Owner`.

- [ ] **Step 3: Add the consuming exact-owner transition**

Implement on `ExecCloneAdmission`:

```rust
fn claim_process_exit(self) -> Result<ProcessExitClaimReceipt, RuntimeError> {
    self.claim_process_exit_with(|| {})
}

fn claim_process_exit_with(
    self,
    after_validate: impl FnOnce(),
) -> Result<ProcessExitClaimReceipt, RuntimeError> {
    let expected = CloneAdmissionClose::Exec {
        owner: self.owner,
        generation: self.generation,
    };
    let mut state = self.gate.state.lock();
    if state.closing != Some(expected) {
        return Err(RuntimeError::Configuration(
            "exec terminal handoff lost exact clone-admission owner".to_owned(),
        ));
    }
    after_validate();
    state.closing = Some(CloneAdmissionClose::Exit { owner: self.owner });
    state.change_epoch = state.change_epoch.checked_add(1)
        .unwrap_or_else(|| std::process::abort());
    let change_epoch = state.change_epoch;
    let claim = claim_from_in_flight(state.in_flight);
    let callbacks = std::mem::take(&mut state.listeners);
    self.gate.changed.notify_all();
    drop(state);
    for (_, callback) in callbacks.into_values() {
        callback();
    }
    Ok(ProcessExitClaimReceipt { claim, change_epoch })
}
```

The consumed guard drops after `closing` is `Exit { owner }`, so its existing
`Drop` comparison cannot reopen admission. Ensure the closure is invoked only
after exact validation and while the gate mutex is held. The production call's
zero-sized closure must inline away in release builds.

- [ ] **Step 4: Transfer pending exec resources into a typed handoff**

Define in `vcpu_loop/mod.rs`:

```rust
pub(super) struct ExecTerminalHandoff {
    clone_admission: ExecCloneAdmission,
}

impl ExecTerminalHandoff {
    fn claim_process_exit(self) -> Result<ProcessExitClaimReceipt, RuntimeError> {
        self.clone_admission.claim_process_exit()
    }
}

struct PendingExecTerminal {
    context: crate::kernel::KernelContext,
    handoff: ExecTerminalHandoff,
}
```

In `exec.rs`, add consuming methods:

```rust
impl PreparedExecve {
    fn into_terminal_handoff(self) -> super::ExecTerminalHandoff {
        let Self { _clone_admission, .. } = self;
        super::ExecTerminalHandoff { clone_admission: _clone_admission }
    }
}

impl PreparedExecveDrain {
    pub(super) fn into_terminal_handoff(self) -> super::ExecTerminalHandoff {
        let Self { prepared, drain, completion_ownership } = self;
        drop(drain);
        drop(completion_ownership);
        prepared.into_terminal_handoff()
    }
}
```

`take_pending_exec_terminal_context` becomes `take_pending_exec_terminal` and
returns `PendingExecTerminal` without dropping the exec close.

- [ ] **Step 5: Route exec failure through a preclaimed terminal suffix**

Refactor terminal entry into:

```rust
fn begin_persistent_process_terminal_with_claim(
    &mut self,
    engine: &mut E,
    terminal: PersistentTerminal,
    context: crate::kernel::KernelContext,
    receipt: ProcessExitClaimReceipt,
) -> executor::ExecutorExit;

fn begin_persistent_process_terminal_from_exec(
    &mut self,
    engine: &mut E,
    terminal: PersistentTerminal,
    pending: PendingExecTerminal,
) -> executor::ExecutorExit;
```

The generic function obtains its receipt from
`try_claim_persistent_process_exit(self.state.this_tid)`. The exec function
claims through `pending.handoff`, restores
`service_kernel_context = Some(pending.context.retain_exact())`, calls
`begin_process_exit()` for `Owner`, and enters the common suffix with the exact
receipt. `Pending` subscribes against `receipt.change_epoch`, not an epoch read
before the state transition.

In `ProductionHvpatchLoopPoll::poll`, preserve the original error:

```rust
Err(error) => match self.take_pending_exec_terminal() {
    Some(pending) => self.begin_persistent_process_terminal_from_exec(
        engine,
        PersistentTerminal::Error(error),
        pending,
    ),
    None => {
        let context = self.state.service_kernel_context.as_ref()
            .unwrap_or_else(|| std::process::abort())
            .retain_exact();
        self.begin_persistent_process_terminal(
            engine,
            PersistentTerminal::Error(error),
            context,
        )
    }
}
```

If exact handoff validation fails, log both errors and abort; do not lower it to
`ThreadDone` or replace the original terminal error with a guessed owner.

- [ ] **Step 6: Add production-path error and ownership regressions**

Extend the existing pending-exec fixture for both
`ExecCompletionOrigin::GuestSyscall` and `InternalControl`. Assert:

```rust
assert_pending_exec_terminal_error(
    &case.job,
    "carrier logical exec lost exact root Kernel context",
);
assert!(case.job.state.syscall_completion.is_idle());
assert_no_exec_return_publication(
    &case.kernel, &case.engine, &case.returns, &case.events,
);
assert_eq!(
    case.kernel.clone_admission
        .try_claim_process_exit(case.job.state.this_tid)
        .expect("same-owner retry").claim,
    ProcessExitClaim::Owner,
);
assert!(case.kernel.clone_admission
    .close_for_exec(ThreadId::synthetic_for_tests(74_102))
    .is_err());
```

Also cover generic exit during an active exec: it must return `LostToExec`
without installing an exit owner; after ordinary guard drop a later unrelated
exit must become `Owner` rather than `AlreadyOwned`.

- [ ] **Step 7: Turn the red test green and run focused ownership suites**

Run:

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib \
  exec_terminal_handoff_never_reopens_admission_to_competing_exec -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib \
  persistent_terminal_claim -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib \
  pending_exec_completion_ownership -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib \
  typed_completion_ownership -- --nocapture
```

Expected: all focused tests pass serially; the deterministic contender is
rejected; both exec origins retain the exact original terminal error; no return
publication occurs.

- [ ] **Step 8: Adapt the release reducer to the fixed exact operations**

Keep the sample schema and runner unchanged. Update generic cases to time the
new exact production helper and exec cases to time only
`ExecCloneAdmission::claim_process_exit`. No setup, reset, clock read, or JSON
serialization belongs inside the measured loop.

Run the ignored reducer with the Task 1 command. Expected: 60 valid measured
rows and zero contender admissions.

- [ ] **Step 9: Verify formatting and commit the atomic handoff**

Run:

```bash
just fmt-check
git diff --check
git add crates/carrick-runtime/src/vcpu_loop/mod.rs \
  crates/carrick-runtime/src/vcpu_loop/exec.rs
git commit -m "fix: atomically hand exec ownership to terminal exit"
```

Expected: formatting/diff checks pass and the commit contains only the runtime,
tests, and reducer adaptation.

### Task 3: Bind Performance and Correctness Closure to Evidence

**Files:**
- Modify if runner defects are exposed: `scripts/perf/atomic_exec_terminal_handoff_abba.py`
- Modify if runner defects are exposed: `scripts/perf/test_atomic_exec_terminal_handoff_abba.py`
- Create: `docs/perf-results/2026-09-01-atomic-exec-terminal-handoff.json`
- Create: `docs/perf-results/2026-09-01-atomic-exec-terminal-handoff.md`
- Modify: `.superpowers/sdd/2026-09-01-atomic-exec-terminal-handoff/progress.md` (ignored controller ledger)

**Interfaces:**
- Consumes: Task 1 baseline commit/reducer and Task 2 fixed commit.
- Produces: accepted ABBA receipt, human-readable non-claim, full validation receipts, and a reviewed remediation range that unblocks original Task 5.

- [ ] **Step 1: Verify a quiet host and run exact ABBA arms**

Record the Task 1 and Task 2 commit ids as `BASELINE_REF` and `CANDIDATE_REF` in
the task report. Confirm no `carrick run`, conformance, Docker build, or sibling
benchmark process is active. Then run:

```bash
python3 scripts/perf/atomic_exec_terminal_handoff_abba.py \
  --baseline "$BASELINE_REF" \
  --candidate "$CANDIDATE_REF" \
  --iterations 100000 --warmups 5 --samples 30 \
  --output docs/perf-results/2026-09-01-atomic-exec-terminal-handoff.json
```

Expected: arm order is A1/B1/B2/A2; every ref has one stable executable
identity; every operation has 120 total paired rows split evenly across arms;
zero contender admissions; `accepted: true`; median ratio `<= 1.05`; p95 ratio
`<= 1.10`.

- [ ] **Step 2: Write the human-readable evidence boundary**

Create the Markdown receipt with these exact sections:

```markdown
# Atomic Exec-to-Terminal Handoff Performance Receipt

## Artifact identity
## Method
## Correctness observations
## Timing result
## Acceptance
## Non-claims
```

Copy commit ids, binary SHA-256/UUID, host/toolchain identity, commands, sample
counts, medians, p95s, ratios, and verdict from the JSON. State explicitly that
this is a release host state-machine micro-reducer and is not signed guest,
Docker-oracle, conformance, ecosystem, or shipped `<=2x` proof.

- [ ] **Step 3: Validate the evidence and runner tests**

Run:

```bash
python3 -m json.tool \
  docs/perf-results/2026-09-01-atomic-exec-terminal-handoff.json >/dev/null
python3 -m unittest scripts.perf.test_atomic_exec_terminal_handoff_abba -v
```

Expected: JSON parses and all runner unit tests pass.

- [ ] **Step 4: Run the complete serialized runtime library suite**

Run exactly the runtime portion in the repository-supported serial mode:

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib
```

Expected: all runtime library tests pass except explicitly named existing
ignored tests; no hang and no child-reaping cross-test failure.

- [ ] **Step 5: Run repository quality and integration gates**

Run:

```bash
just fmt-check
just clippy
just lint-domains
just ci
```

Expected: all gates pass. If a gate fails, reduce and attribute it against
current `main`; do not describe the remediation as complete or waive a failure
as unrelated without a reproducible base comparison in the task report.

- [ ] **Step 6: Commit the accepted evidence**

Run:

```bash
git add docs/perf-results/2026-09-01-atomic-exec-terminal-handoff.json \
  docs/perf-results/2026-09-01-atomic-exec-terminal-handoff.md \
  scripts/perf/atomic_exec_terminal_handoff_abba.py \
  scripts/perf/test_atomic_exec_terminal_handoff_abba.py
git commit -m "perf: bind atomic exec terminal handoff evidence"
```

Expected: only accepted evidence and any runner corrections are committed.

- [ ] **Step 7: Package the complete remediation for independent review**

Generate the SDD review package from the Task 1 base through Task 3 HEAD. The
reviewer must check the spec's single-authority invariant, exact-owner transfer,
original-error preservation, no fabricated return, deterministic contention
proof, absence of production instrumentation, ABBA identities/cardinality,
threshold math, and non-claims. Task 5 of the original interception plan remains
blocked until the review is clean or every capped finding is adjudicated under
the SDD ledger rules.
