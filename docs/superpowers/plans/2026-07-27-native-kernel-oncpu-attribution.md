# Darwin/AArch64 Kernel On-CPU Attribution Implementation Plan

> **RESEARCH RECORD — SUPERSEDED 2026-07-28.** This five-round review artifact
> is preserved for its detailed requirements and rejected alternatives, but it
> is not the execution controller. The user approved a compact reset after the
> round-5 breaker. Execute
> [`2026-07-28-native-kernel-attribution-compact-execution.md`](2026-07-28-native-kernel-attribution-compact-execution.md);
> its TDD tests incorporate every remaining load-bearing breaker finding.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the accepted but undifferentiated Darwin-kernel CPU bucket into stable whole-process-tree kernel stack evidence and one exact measurement-selection result without creating a causal hypothesis or changing guest execution.

**Architecture:** Extend the existing `native-wall` DTrace sample at the same `profile-499` firing that records a kernel PC, so every new kernel sample contributes to exactly one aggregated kernel stack. Generalize the existing multi-line stack protocol without changing voluntary off-CPU rows, rank symbolized kernel leaves with exact count reconciliation and exact rational decisions, and collect two cold-Go captures through one fail-closed receipt runner. This plan stops with a selectable candidate package, a disconfirmed kernel-family selection question, or a measurement-repair result outside the hypothesis ledger; a causal hypothesis and runtime spike require a separate approved design, a mechanism-specific traced counter, and untraced wall evidence.

**Tech Stack:** DTrace kernel/profile/proc providers, Carrick's in-process libdtrace profile runner, Rust/Serde JSONL profile parsing, Python 3 attribution and receipt tooling, Darwin/AArch64 signed release builds.

## Global Constraints

- The reference workload is the cold-`GOCACHE` Go build used by official `C0=19,375 ms`; traced elapsed time is diagnostic and never a performance result.
- Preserve the accepted untraced baseline artifact `scripts/perf/evidence/native-go-build-wall-baseline-v1.json` (SHA-256 `9c9e25f8c7e4f40feb8a86293a2dbd71e3406db3a22a6aeaa9b0dfff23958e13`) and accepted attribution artifact `scripts/perf/evidence/native-go-build-wall-attribution-v1.json` (SHA-256 `fdb73ea7880fb2cf957bcbbc9c122ad57d739377eecf0e8e90da0bccb0ad67d8`); do not rewrite or re-bless either.
- The fixed image is `localhost:5005/carrick-go-conformance:1.24`, native `arm64`, image ID `sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`, and repo digest `localhost:5005/carrick-go-conformance@sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
- Track only `$target` and descendants admitted by `proc:::create`; unrelated Carrick processes must contribute zero samples.
- Never run Carrick and the Docker oracle concurrently. Registry-only containers do not count as Docker oracles.
- `profile-499` is the sole on-CPU sample clock. A kernel sample must increment both the existing PC aggregate and exactly one stack aggregate in the same predicate firing.
- Reject principal, aggregation, dynamic, or other DTrace drops; interruption; timeout; bounded termination; non-natural target exit; incomplete records; live tracked processes at end; exact-run-ID cleanup failure; or kernel-stack/sample mismatch.
- Preserve old voluntary off-CPU `value_ns` stack rows and default analysis of historical profiles that contain no kernel stack rows.
- Do not read Linux kernel or other GPL source. Kernel names come only from DTrace's `%k` stack formatter; this plan does not depend on `/System/Library/Kernels/kernel`.
- Do not time per-event probes or use traced wall time to estimate a wall-time ceiling.
- H001 indirect-return work remains `PROPOSED`, not rejected: the current AArch64 lane already has a two-way indirect cache and accepted whole-tree profiles put the gateway bucket below 1%, so the 34% undifferentiated kernel bucket has higher first-measurement value.
- The implementation branch starts at clean `7c98887c2bcdc6615be83ebaf2a0255994e519cf` plus the reviewed plan commit below. Each task makes exactly one commit, and both live captures use the unchanged Task 3 commit and one unchanged signed binary.
- A later separate H006 causal design, if proposed and approved, starts from clean pre-sidecar commit `7131c12bde03991c0c913a527d6b6a727924daba`. It may cherry-pick only the three literal attribution-tooling commit SHAs recorded by Task 4; it must not import sidecar experiment commits or current-branch-only `native_go_build.py` helpers.
- This plan is measurement-only: no guest-execution behavior, translation-cache size, sidecar policy, syscall semantics, or default backend changes are authorized.
- In required-live mode, zero kernel samples or an unresolved top kernel leaf are measurement rejection. Rejection leaves the derived output absent. Task 4 records exactly one measurement-selection result outside the hypothesis backlog; selectable, diffuse, and rejected evidence all leave H006 absent and make no hypothesis-ledger mutation.

---

## Pre-execution gate: commit the reviewed plan

The plan must be a clean provenance ancestor, not an untracked controller file.

- [ ] **Step 1: Verify the exact starting point and single plan change**

Run:

```bash
test "$(git rev-parse HEAD)" = \
  "7c98887c2bcdc6615be83ebaf2a0255994e519cf"
git status --short --untracked-files=all
git diff --check
cargo test -p carrick-cli --bin carrick trace_profile
```

Expected: `HEAD` matches exactly, all 19 existing `trace_profile` unit tests
pass, and the only non-ignored status row is:

```text
?? docs/superpowers/plans/2026-07-27-native-kernel-oncpu-attribution.md
```

`git diff --check` covers the empty tracked diff only; it does not validate the
untracked plan. The staged check in Step 2 validates the plan itself.

- [ ] **Step 2: Commit the reviewed plan with provenance**

Run:

```bash
git add docs/superpowers/plans/2026-07-27-native-kernel-oncpu-attribution.md
git diff --cached --check
git commit -F - <<'EOF'
docs(perf): plan kernel on-CPU attribution

The accepted native-wall pair leaves about one third of sampled CPU in an
undifferentiated Darwin-kernel bucket, so it cannot yet select a bounded host
mechanism.

Define exact kernel stack reconciliation, receipt-bound cold-Go captures, and
CPU-work opportunity evidence without treating traced time as wall time.

Verified against the attribution artifact accepted by 34ce4c3c from the
688357ef A/B profile pair and the 7c98887c campaign controller state.

Co-Authored-By: Codex <codex@openai.com>
EOF
```

Expected: `git diff --cached --check` validates the staged plan and passes,
then the plan commit succeeds with no tooling or runtime file staged.

- [ ] **Step 3: Freeze the plan ancestry**

Run:

```bash
PLAN_SHA=$(git rev-parse HEAD)
test "$(git rev-parse "$PLAN_SHA^")" = \
  "7c98887c2bcdc6615be83ebaf2a0255994e519cf"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
printf 'PLAN_SHA=%s\n' "$PLAN_SHA"
```

Expected: both tests pass. Record the printed 40-character `PLAN_SHA`; Tasks
1-3 must remain the next three commits with no intervening changes.

---

### Task 1: Emit and parse exact kernel on-CPU stack samples

**Files:**
- Modify: `scripts/dtrace/native-wall.d` at the existing kernel `profile-499` clause and `dtrace:::END`
- Modify: `crates/carrick-cli/src/trace_profile.rs` at `StackTraceRecord`, `ProfileMetric::StackTrace`, `validate_native_wall_metrics`, and stack-to-metric conversion

**Interfaces:**
- Consumes: existing `profile-499`, `track_pid`, `@cpu_kernel`, `NWSTACK1`, and `TraceProfileKind::NativeWall`.
- Produces: `NWSTACK1|begin|state=kernel-oncpu|value=<samples>` records and backward-compatible stack-trace JSON metrics with exactly one of `count` or `value_ns`.
- Compatibility: historical `native-wall` raw streams with no kernel stacks still parse; a profile with zero kernel samples and no kernel stacks still parses; any present kernel stack population must reconcile exactly.

- [ ] **Step 1: Write failing parser and serialization tests**

Add behavior-level unit tests in `crates/carrick-cli/src/trace_profile.rs`.
The accepted fixture is:

```text
DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1
DSRPROF1|count|phase=wall-samples|value=1
DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=3
DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0
DSRPROF1|total|phase=elapsed|value_ns=1000000
NWSTACK1|begin|state=kernel-oncpu|value=2
kernel`foo
NWSTACK1|end
NWSTACK1|begin|state=kernel-oncpu|value=1
kernel`bar
NWSTACK1|end
DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1
```

Assert the public JSON rows, not private source text:

```rust
let rows: Vec<serde_json::Value> = summary
    .json_rows()
    .into_iter()
    .map(|row| serde_json::to_value(row).expect("serialize row"))
    .collect();
let kernel: Vec<_> = rows
    .iter()
    .filter(|row| row["scope"]["phase"] == "cpu-kernel-stack")
    .collect();
assert_eq!(kernel.len(), 2);
assert_eq!(kernel[0]["scope"].get("pid"), None);
assert_eq!(kernel[0]["metric"].get("pid"), None);
assert_eq!(kernel[0]["metric"]["count"], 2);
assert_eq!(kernel[0]["metric"].get("value_ns"), None);
assert_eq!(kernel[1]["metric"]["count"], 1);
```

Add separate tests with literal fixtures for these mutations:

```text
kernel stack total 2 != kernel PC total 3
both value=1 and value_ns=1 on one stack header
neither value nor value_ns on one stack header
kernel-oncpu row with pid=42
kernel-oncpu row with unknown=1
voluntary row without pid
voluntary row with count instead of value_ns
kernel-oncpu row with value=0
voluntary row with value_ns=0
empty kernel stack frame list
historical profile with three kernel PC samples and no kernel stack rows
profile with user CPU samples, zero kernel samples, and no kernel stack rows
```

The first ten cases must fail. The historical and zero-kernel cases must
parse and must emit no `cpu-kernel-stack` rows. Keep the existing voluntary
serialization assertion and additionally prove that it still has both scope
`pid` and metric `pid`, `value_ns`, and no `count`.

- [ ] **Step 2: Run the focused parser tests and prove RED**

Run:

```bash
cargo test -p carrick-cli --bin carrick trace_profile
```

Expected: the new accepted count-valued fixture fails because `NWSTACK1`
currently requires `pid` plus `value_ns`; the malformed/compatibility
expectations must not fail from fixture syntax errors.

- [ ] **Step 3: Generalize the stack value domain**

Use these exact internal shapes:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StackTraceValue {
    Count(u64),
    DurationNs(u64),
}

#[derive(Debug)]
struct StackTraceRecord {
    state: String,
    pid: Option<u64>,
    value: StackTraceValue,
    frames: Vec<String>,
}
```

After parsing fields, enforce exact state-specific key sets and values:

```rust
let state = required("state")?.to_owned();
let (pid, value) = match state.as_str() {
    "kernel-oncpu" if fields.keys().map(String::as_str).eq(
        ["state", "value"].into_iter()
    ) => (
        None,
        StackTraceValue::Count(
            parse_u64(required("value")?).context("invalid stack count")?,
        ),
    ),
    "voluntary" if fields.keys().map(String::as_str).eq(
        ["pid", "state", "value_ns"].into_iter()
    ) => (
        Some(parse_u64(required("pid")?).context("invalid stack pid")?),
        StackTraceValue::DurationNs(
            parse_u64(required("value_ns")?)
                .context("invalid stack duration")?,
        ),
    ),
    _ => bail!("stack record has an invalid state/field/value contract"),
};
```

`BTreeMap` key order makes the two literal key sequences deterministic. Reject
zero `Count` and zero `DurationNs` values. Do not accept unknown stack states,
extra fields, a `pid` on `kernel-oncpu`, or a count-valued `voluntary` row.

- [ ] **Step 4: Complete the serialized conversion shape**

Change the public metric to:

```rust
StackTrace {
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_ns: Option<u64>,
    frames: Vec<String>,
},
```

Convert every parsed record with one exhaustive match:

```rust
let (phase, scope_pid, metric_pid, count, value_ns) = match stack.value {
    StackTraceValue::Count(samples) => (
        "cpu-kernel-stack",
        None,
        None,
        Some(samples),
        None,
    ),
    StackTraceValue::DurationNs(duration_ns) => {
        let pid = stack
            .pid
            .ok_or_else(|| anyhow!("voluntary stack lost its pid"))?;
        (
            "offcpu-voluntary-stack",
            Some(pid),
            Some(pid),
            None,
            Some(duration_ns),
        )
    }
};
```

Use `phase`, `scope_pid`, `metric_pid`, `count`, and `value_ns` directly in
`ProfileScope` and `ProfileMetric::StackTrace`. `kind` remains
`Some(stack.state.clone())`. This guarantees both serialized `pid` locations
are absent for kernel rows and preserved for voluntary rows.

- [ ] **Step 5: Collect stacks at the existing kernel sample firing**

Change only the existing kernel `profile-499` clause:

```d
profile-499
/track_pid[pid] && arg0 != 0/
{
	@cpu_kernel[arg0] = count();
	@cpu_kernel_stack[stack(24)] = count();
}
```

In `dtrace:::END`, immediately after printing `@cpu_kernel`, print every
kernel stack without truncation:

```d
printa("NWSTACK1|begin|state=kernel-oncpu|value=%@d\n%kNWSTACK1|end\n",
    @cpu_kernel_stack);
```

Do not add a timer, per-event USDT probe, `trunc(@cpu_kernel_stack, ...)`, or
kernel-file lookup. Keep the existing `aggsize=32m`, `bufsize=32m`, and
zero-drop gate for the first live capture. Task 4 is the behavior-level DTrace
gate: the script must compile, run, and reconcile every kernel PC sample to a
stack sample before evidence can be accepted.

- [ ] **Step 6: Reconcile kernel and voluntary populations independently**

In `validate_native_wall_metrics`, use:

```rust
let kernel_samples =
    summed_count(grouped, "cpu-kernel-pc", None).unwrap_or(0);
let kernel_stack_samples = stack_traces
    .iter()
    .filter_map(|stack| match stack.value {
        StackTraceValue::Count(value) => Some(value),
        StackTraceValue::DurationNs(_) => None,
    })
    .sum::<u64>();
let has_kernel_stacks = stack_traces
    .iter()
    .any(|stack| matches!(stack.value, StackTraceValue::Count(_)));
if has_kernel_stacks && kernel_stack_samples != kernel_samples {
    bail!(
        "native-wall kernel stack samples total {kernel_stack_samples}, \
         expected {kernel_samples}"
    );
}

let voluntary_stack_ns = stack_traces
    .iter()
    .filter_map(|stack| match stack.value {
        StackTraceValue::DurationNs(value) => Some(value),
        StackTraceValue::Count(_) => None,
    })
    .sum::<u64>();
let voluntary_ns =
    summed_total_ns(grouped, "offcpu-voluntary-total").unwrap_or(0);
if voluntary_ns != 0 && voluntary_stack_ns == 0 {
    bail!("native-wall profile has voluntary off-CPU time but no blocking stacks");
}
```

Every row still requires at least one frame at `NWSTACK1|end`. Completely
absent kernel stacks remain compatible even when historical kernel PC rows
exist. A zero-kernel profile with no kernel stack rows is valid. A present
kernel stack population when `kernel_samples == 0` is rejected by the same
exact mismatch.

- [ ] **Step 7: Run GREEN gates**

Run:

```bash
cargo test -p carrick-cli --bin carrick trace_profile
cargo test -p carrick-cli --test trace_profile
just fmt-check
git diff --check
```

Expected: all pass. No new test may grep `native-wall.d`; live receipt
reconciliation in Task 4 tests the DTrace behavior.

- [ ] **Step 8: Commit the profile protocol**

Run:

```bash
git add \
  scripts/dtrace/native-wall.d \
  crates/carrick-cli/src/trace_profile.rs
git commit -F - <<'EOF'
diagnostics(native): capture kernel CPU stacks

The accepted native-wall profile records Darwin kernel PCs but cannot name the
kernel mechanisms consuming that CPU.

Capture one kernel stack at the same 499 Hz firing as each kernel PC and extend
the stack protocol with count-valued rows while preserving voluntary durations
and historical streams without kernel stacks.

Verified with carrick-cli parser and serialization tests, including malformed,
historical-absence, zero-kernel, and exact-reconciliation cases.

Co-Authored-By: Codex <codex@openai.com>
EOF
```

Expected: this is the first commit after `PLAN_SHA`.

---

### Task 2: Rank kernel leaves and compare accepted-baseline drift

**Files:**
- Modify: `scripts/perf/native_wall_attribution.py`
- Modify: `scripts/perf/test_native_wall_attribution.py`
- Modify: `scripts/perf/README.md`

**Interfaces:**
- Consumes: `cpu-kernel-pc` exact counts and optional `cpu-kernel-stack` stack-trace metrics from Task 1.
- Produces: a `kernel` object with exact samples, CPU seconds at 499 Hz, deterministic ranked raw stacks, normalized four-frame stack families, leaves, leaf-symbolization coverage, compatibility state, and two-run stability/baseline-drift failures.
- Produces: an accepted comparison with a deterministic `kernel_stack_family` measurement-selection object. Family instability is measurement rejection; a stable-but-diffuse accepted family distribution emits `selection_outcome="diffuse"` rather than requiring Task 4 to infer a decision.
- Decision authority: every threshold, two-share delta, dominant-category choice, and selected-family ordering uses integer counts/totals or `fractions.Fraction`. Emitted floats are diagnostics only and are never read back for accept/reject/select/order decisions.
- Produces: `build_artifact(profile_paths, binary, *, require_kernel_stacks)` for Task 3 receipt analysis. It returns an accepted artifact or raises `ValueError`; it never writes a rejected output.

- [ ] **Step 1: Write failing kernel contract and zero-case tests**

Extend the literal `profile_rows` fixture with:

```python
row(
    "cpu-kernel-stack",
    {
        "type": "stack-trace",
        "state": "kernel-oncpu",
        "count": 40,
        "frames": ["kernel`vm_fault+0x10", "kernel`arm_fast_fault"],
    },
    kind="kernel-oncpu",
),
row(
    "cpu-kernel-stack",
    {
        "type": "stack-trace",
        "state": "kernel-oncpu",
        "count": 9,
        "frames": ["kernel`unix_syscall", "kernel`read_nocancel"],
    },
    kind="kernel-oncpu",
),
```

Assert these literal outcomes:

```python
self.assertEqual(summary["kernel"]["samples"], 49)
self.assertEqual(summary["kernel"]["stack_samples"], 49)
self.assertEqual(summary["kernel"]["cpu_seconds"], 49 / 499)
self.assertEqual(summary["kernel"]["stack_coverage"], 1.0)
self.assertEqual(summary["kernel"]["symbolized_leaf_coverage"], 1.0)
self.assertEqual(summary["kernel"]["top_stacks"][0]["samples"], 40)
self.assertEqual(
    summary["kernel"]["stack_families"][0]["frames"],
    ["kernel`vm_fault", "kernel`arm_fast_fault"],
)
self.assertEqual(summary["kernel"]["stack_families"][0]["rank"], 1)
self.assertEqual(summary["kernel"]["stack_families"][0]["samples"], 40)
self.assertEqual(summary["kernel"]["stack_families"][0]["share"], 40 / 49)
self.assertEqual(summary["kernel"]["top_frames"][0]["frame"], "kernel`vm_fault")
self.assertEqual(summary["kernel"]["top_frames"][0]["samples"], 40)
self.assertEqual(summary["kernel"]["top_frames"][0]["cpu_seconds"], 40 / 499)
self.assertEqual(summary["kernel"]["top_frames"][0]["share"], 40 / 49)
self.assertIs(summary["kernel"]["top_frames"][0]["symbolized"], True)
```

Add separate tests for:

```text
kernel count mismatch
empty kernel frames
duration-valued kernel row
kernel metric pid present
kernel scope pid present
count-valued voluntary row
voluntary scope/metric pid mismatch
historical kernel samples with no stacks and require_kernel_stacks=false
historical kernel samples with no stacks and require_kernel_stacks=true
zero kernel samples with no stacks and require_kernel_stacks=true
zero kernel samples with a positive stack row
95% and just-below-95% leaf-symbolization boundaries
symbolized caller above an unresolved leaf
unresolved top leaf despite at least 95% aggregate leaf coverage
two raw stacks whose first four frames differ only by terminal +0xHEX offsets coalesce into one normalized family
two raw stacks with the same normalized first four frames but different deeper callers coalesce into one normalized family
two raw stacks with the same leaf but different callers in the first four frames remain different families
```

The exact compatibility expectations are:

```python
# Historical absence, default mode.
kernel == {
    "samples": 49,
    "stack_samples": 0,
    "cpu_seconds": 49 / 499,
    "stack_coverage": 0.0,
    "symbolized_leaf_coverage": 0.0,
    "top_stacks": [],
    "stack_families": [],
    "top_frames": [],
    "top_5_stack_share": 0.0,
    "top_10_stack_family_share": 0.0,
    "top_10_frame_share": 0.0,
    "stacks_present": False,
}
# Zero kernel samples, required-live mode.
kernel == {
    "samples": 0,
    "stack_samples": 0,
    "cpu_seconds": 0.0,
    "stack_coverage": 1.0,
    "symbolized_leaf_coverage": 1.0,
    "top_stacks": [],
    "stack_families": [],
    "top_frames": [],
    "top_5_stack_share": 0.0,
    "top_10_stack_family_share": 0.0,
    "top_10_frame_share": 0.0,
    "stacks_present": False,
}
```

Historical absence remains accepted only when the live-evidence flag is false.
Required mode rejects kernel samples without stacks. Required mode also adds
the exact failure `kernel samples are zero` for the zero shape above; the shape
is deterministic and non-dividing, but its containing summary is not accepted.
Default historical mode may still accept the same zero shape. This is the first
zero/unresolved precedence gate: required-live zero evidence cannot reach an
accepted pair comparison or measurement-selection object.

- [ ] **Step 2: Run the analyzer suite and prove RED**

Run:

```bash
python3 -m unittest scripts.perf.test_native_wall_attribution -v
```

Expected: failures because count-valued kernel stacks are currently routed
through the voluntary-duration loop and no `kernel` object exists.

- [ ] **Step 3: Parse kernel and voluntary stack contracts separately**

Add the missing standard-library imports, integer percentage constants, exact
ratio helpers, and kernel frame normalizer:

```python
import re
from fractions import Fraction


KERNEL_OFFSET_SUFFIX = re.compile(r"\+0x[0-9a-fA-F]+$")
KERNEL_STACK_FAMILY_PREFIX_FRAMES = 4
MIN_WALL_COVERAGE_PERCENT = 99
MIN_CPU_COVERAGE_PERCENT = 85
MIN_VOLUNTARY_STACK_COVERAGE_PERCENT = 80
MIN_KERNEL_SYMBOLIZED_LEAF_COVERAGE_PERCENT = 95
MIN_COMPARED_CPU_CATEGORY_SHARE_PERCENT = 10
MAX_CPU_CATEGORY_DELTA_PERCENTAGE_POINTS = 5
MIN_STABLE_KERNEL_FRAME_SHARE_PERCENT = 5
MAX_KERNEL_FRAME_DELTA_PERCENTAGE_POINTS = 5
KERNEL_STACK_FAMILY_TOP_LIMIT = 10
MIN_COMPARED_KERNEL_STACK_FAMILY_SHARE_PERCENT = 5
MAX_KERNEL_STACK_FAMILY_DELTA_PERCENTAGE_POINTS = 5
MIN_SELECTED_KERNEL_STACK_FAMILY_SHARE_PERCENT = 10
MIN_STABLE_TOP_10_KERNEL_STACK_FAMILY_COVERAGE_PERCENT = 60
MAX_KERNEL_BASELINE_DELTA_PERCENTAGE_POINTS = 5


def ratio_at_least(numerator: int, denominator: int, percent: int) -> bool:
    if numerator < 0 or denominator <= 0 or not 0 <= percent <= 100:
        raise ValueError("invalid exact ratio comparison")
    return 100 * numerator >= percent * denominator


def share_delta_at_most(
    a: int,
    a_total: int,
    b: int,
    b_total: int,
    percentage_points: int,
) -> bool:
    if (
        min(a, b) < 0
        or min(a_total, b_total) <= 0
        or percentage_points < 0
    ):
        raise ValueError("invalid exact share delta")
    return (
        100 * abs(a * b_total - b * a_total)
        <= percentage_points * a_total * b_total
    )


def exact_share(numerator: int, denominator: int) -> Fraction:
    if numerator < 0 or denominator <= 0:
        raise ValueError("invalid exact share")
    return Fraction(numerator, denominator)


def normalize_kernel_frame(frame: str) -> str:
    return KERNEL_OFFSET_SUFFIX.sub("", frame)


def normalize_kernel_stack_family(frames: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        normalize_kernel_frame(frame)
        for frame in frames[:KERNEL_STACK_FAMILY_PREFIX_FRAMES]
    )


def kernel_stack_rows(profile: Profile) -> tuple[ProfileRow, ...]:
    rows: list[ProfileRow] = []
    for row in profile.rows:
        if row.phase != "cpu-kernel-stack":
            continue
        metric = row.metric
        if (
            row.metric_type != "stack-trace"
            or metric.get("state") != "kernel-oncpu"
            or row.kind != "kernel-oncpu"
            or row.pid is not None
            or "pid" in metric
            or "value_ns" in metric
        ):
            raise ValueError("invalid kernel on-CPU stack contract")
        count = _require_int(metric.get("count"), "kernel stack count")
        frames = metric.get("frames")
        if count <= 0 or not isinstance(frames, list) or not frames:
            raise ValueError("kernel stack has no positive count or frames")
        if not all(isinstance(frame, str) and frame for frame in frames):
            raise ValueError("kernel stack contains an invalid frame")
        rows.append(row)
    return tuple(rows)
```

Replace the broad stack loop with a voluntary-only loop:

```python
for row in rows:
    if row.phase != "offcpu-voluntary-stack":
        continue
    metric = row.metric
    if (
        row.metric_type != "stack-trace"
        or metric.get("state") != "voluntary"
        or row.kind != "voluntary"
        or row.pid is None
        or metric.get("pid") != row.pid
        or "count" in metric
    ):
        raise ValueError("invalid voluntary off-CPU stack contract")
    value_ns = _require_int(metric.get("value_ns"), "stack value_ns")
    if value_ns <= 0:
        raise ValueError("voluntary stack duration must be positive")
```

Only this loop reads `value_ns`. Kernel rows never enter voluntary-duration
coverage or host-address symbolication.

- [ ] **Step 4: Summarize exact kernel CPU opportunity**

Implement:

```python
def summarize_kernel_stacks(
    rows: tuple[ProfileRow, ...],
    kernel_samples: int,
    *,
    require_kernel_stacks: bool,
) -> tuple[dict[str, object], list[str]]:
    failures: list[str] = []
    if not rows:
        if require_kernel_stacks:
            if kernel_samples == 0:
                failures.append("kernel samples are zero")
            else:
                failures.append("kernel samples exist but kernel stacks are absent")
        vacuous = kernel_samples == 0
        return {
            "samples": kernel_samples,
            "stack_samples": 0,
            "cpu_seconds": kernel_samples / CPU_HZ,
            "stack_coverage": 1.0 if vacuous else 0.0,
            "symbolized_leaf_coverage": 1.0 if vacuous else 0.0,
            "top_stacks": [],
            "stack_families": [],
            "top_frames": [],
            "top_5_stack_share": 0.0,
            "top_10_stack_family_share": 0.0,
            "top_10_frame_share": 0.0,
            "stacks_present": False,
        }, failures

    stack_rows: list[dict[str, object]] = []
    family_counts: Counter[tuple[str, ...]] = Counter()
    frame_counts: Counter[str] = Counter()
    frame_symbolized: dict[str, bool] = {}
    stack_samples = 0
    symbolized_leaf_samples = 0
    for row in rows:
        count = _require_int(row.metric["count"], "kernel stack count")
        frames = tuple(row.metric["frames"])
        leaf = normalize_kernel_frame(frames[0])
        family = normalize_kernel_stack_family(frames)
        symbolized = "`" in frames[0]
        stack_samples += count
        symbolized_leaf_samples += count if symbolized else 0
        frame_counts[leaf] += count
        family_counts[family] += count
        frame_symbolized[leaf] = symbolized
        stack_rows.append(
            {
                "samples": count,
                "cpu_seconds": count / CPU_HZ,
                "frames": list(frames),
            }
        )
    if stack_samples != kernel_samples:
        raise ValueError(
            f"kernel stack samples {stack_samples} != "
            f"kernel PC samples {kernel_samples}"
        )
    stack_rows.sort(key=lambda item: (-int(item["samples"]), item["frames"]))
    for item in stack_rows:
        item["share"] = int(item["samples"]) / kernel_samples
    stack_families = [
        {
            "rank": rank,
            "frames": list(family),
            "samples": samples,
            "cpu_seconds": samples / CPU_HZ,
            "share": samples / kernel_samples,
            "leaf_symbolized": "`" in family[0],
        }
        for rank, (family, samples) in enumerate(
            sorted(
                family_counts.items(),
                key=lambda item: (-item[1], item[0]),
            ),
            start=1,
        )
    ]
    top_frames = [
        {
            "frame": frame,
            "samples": samples,
            "cpu_seconds": samples / CPU_HZ,
            "share": samples / kernel_samples,
            "symbolized": frame_symbolized[frame],
        }
        for frame, samples in sorted(
            frame_counts.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    symbolized_coverage = symbolized_leaf_samples / kernel_samples
    if require_kernel_stacks and not ratio_at_least(
        symbolized_leaf_samples,
        kernel_samples,
        MIN_KERNEL_SYMBOLIZED_LEAF_COVERAGE_PERCENT,
    ):
        failures.append(
            "kernel symbolized leaf coverage "
            f"{symbolized_coverage:.3%} is below 95%"
        )
    if (
        require_kernel_stacks
        and top_frames
        and top_frames[0]["symbolized"] is not True
    ):
        failures.append("kernel top leaf is unresolved")
    return {
        "samples": kernel_samples,
        "stack_samples": stack_samples,
        "cpu_seconds": kernel_samples / CPU_HZ,
        "stack_coverage": stack_samples / kernel_samples,
        "symbolized_leaf_coverage": symbolized_coverage,
        "top_stacks": stack_rows,
        "stack_families": stack_families,
        "top_frames": top_frames,
        "top_5_stack_share": (
            sum(int(item["samples"]) for item in stack_rows[:5])
            / kernel_samples
        ),
        "top_10_stack_family_share": (
            sum(int(item["samples"]) for item in stack_families[:10])
            / kernel_samples
        ),
        "top_10_frame_share": (
            sum(int(item["samples"]) for item in top_frames[:10])
            / kernel_samples
        ),
        "stacks_present": True,
    }, failures
```

The non-empty path cannot divide by zero because positive rows must reconcile
to `kernel_samples`; a positive row against zero samples raises before any
division. A stack is symbolized only when its leaf `frames[0]` contains a
backtick. A symbolized caller never substitutes for an unresolved leaf.
Family identity is exactly the ordered first four frames after stripping only
a terminal `+0xHEX` suffix from each; shorter stacks retain their exact shorter
length, deeper frames are deliberately outside the family key, and module,
symbol spelling, unresolved addresses, frame order, and every other character
remain unchanged. Counts from raw stacks with the same family key are summed
before ranking by descending samples and then lexicographic frame tuple.

At the same time, replace every existing single-run ratio decision with the
same exact-count authority while preserving its mathematical threshold and
scope:

```python
# Wall timer coverage >= 99%; the expected-sample denominator is kept exact.
wall_coverage_ok = elapsed_ns > 0 and ratio_at_least(
    wall_samples * 1_000_000_000,
    elapsed_ns * WALL_HZ,
    MIN_WALL_COVERAGE_PERCENT,
)

# Resolved CPU coverage >= 85%.
cpu_coverage_ok = total_cpu_samples > 0 and ratio_at_least(
    resolved_cpu_samples,
    total_cpu_samples,
    MIN_CPU_COVERAGE_PERCENT,
)

# Voluntary blocking-stack coverage >= 80%; zero voluntary time remains
# vacuously covered exactly as before.
stack_coverage_ok = voluntary_ns == 0 or ratio_at_least(
    stack_total_ns,
    voluntary_ns,
    MIN_VOLUNTARY_STACK_COVERAGE_PERCENT,
)
```

Keep the existing zero-denominator failure/compatibility branches before these
helpers, so this does not broaden historical acceptance. Compute
`wall_timer_coverage`, `resolved_cpu_coverage`, `top_stack_coverage`,
`symbolized_leaf_coverage`, and every per-row `share` as emitted floats only
after the exact boolean is known. No float, rounded string, epsilon, or emitted
diagnostic may be read back as decision authority.

Remove the replaced float threshold constants. Update the existing
`test_accepts_stable_cpu_classification_above_eighty_five_percent` diagnostic
assertion to compare with `MIN_CPU_COVERAGE_PERCENT / 100` while separately
asserting the exact count predicate; no stale `MIN_CPU_COVERAGE`,
`MIN_WALL_COVERAGE`, `MIN_STACK_COVERAGE`, or `MAX_CATEGORY_DELTA` reference
may remain.

Call this from:

```python
def summarize(
    profile: Profile,
    binary: pathlib.Path,
    *,
    require_kernel_stacks: bool = False,
) -> dict[str, object]:
```

Use the exact `cpu_counts["darwin-kernel"]` total as `kernel_samples`, add the
returned failures to the run's failure list, and add the returned object under
`result["kernel"]`.

- [ ] **Step 5: Add deterministic two-run leaf, family, and baseline stability**

Before adding any constants or comparison logic below, add every pair-level
fixture and assertion listed at the end of this step, then run:

```bash
python3 -m unittest scripts.perf.test_native_wall_attribution -v
```

Expected: assertion `FAIL` results for absent `stack_families` /
`kernel_stack_family` fields, the zero/unresolved precedence, caller-drift
rejection, the selectable boundary, and accepted diffuse outcome. An import,
fixture parse, or discovery `ERROR` is not accepted RED. Only after observing
those failures add the following implementation.

Add these fixed accepted-baseline counts. The producer SHA names the source
commit used for the accepted A/B profiles; the acceptance SHA names the later
commit that committed the derived attribution artifact. Do not call either one
the other:

```python
ACCEPTED_KERNEL_PROFILE_PRODUCER_SHA = (
    "688357ef6b72b299daf5990d494fff7d1a7a7805"
)
ACCEPTED_ATTRIBUTION_ACCEPTANCE_SHA = (
    "34ce4c3c40bec2bd408612efcba66226fa2793f9"
)
ACCEPTED_KERNEL_SHARE_COUNTS = (
    (9750, 28255),
    (9748, 28385),
)
ACCEPTED_KERNEL_SHARE_MEAN_NUM = 9750 * 28385 + 9748 * 28255
ACCEPTED_KERNEL_SHARE_MEAN_DEN = 2 * 28255 * 28385
ACCEPTED_KERNEL_SHARES = tuple(
    samples / total for samples, total in ACCEPTED_KERNEL_SHARE_COUNTS
)
ACCEPTED_KERNEL_SHARE_MEAN = (
    ACCEPTED_KERNEL_SHARE_MEAN_NUM / ACCEPTED_KERNEL_SHARE_MEAN_DEN
)
```

The unsimplified exact mean is therefore
`mean_num=552183490`, `mean_den=1604036350`; the equivalent reduced fraction
is `55218349/160403635`. `ACCEPTED_KERNEL_SHARES` and
`ACCEPTED_KERNEL_SHARE_MEAN` reproduce the existing emitted diagnostics
`[0.34507166873119804, 0.34342082085608594]` and
`0.34424624479364196`, but neither float is decision authority.

Change:

```python
def compare(
    a: dict[str, object],
    b: dict[str, object],
    *,
    require_kernel_stacks: bool = False,
) -> dict[str, object]:
```

For every two-profile comparison, including historical default mode, take each
category's numerator from `cpu[category]["samples"]` and its denominator from
`reconciliation["cpu_samples"]`. Choose the dominant category by the largest
integer sample count, retaining `CPU_CATEGORIES` order as the deterministic
tie-break exactly as the current implementation does. A category is eligible
for the existing stability gate iff:

```python
ratio_at_least(a, a_total, MIN_COMPARED_CPU_CATEGORY_SHARE_PERCENT) or (
    ratio_at_least(b, b_total, MIN_COMPARED_CPU_CATEGORY_SHARE_PERCENT)
)
```

An eligible category is stable iff:

```python
share_delta_at_most(
    a,
    a_total,
    b,
    b_total,
    MAX_CPU_CATEGORY_DELTA_PERCENTAGE_POINTS,
)
```

Thus category eligibility at 10% is inclusive and an exact five-percentage-
point delta is accepted. Preserve the existing categories, failure text, and
default-mode scope. Emit `category_absolute_deltas` as
`float(abs(exact_share(a, a_total) - exact_share(b, b_total)))`; that float is
diagnostic only.

In required-live mode, apply this exact precedence:

1. If either `kernel["samples"]` is zero, return a rejected comparison with
   `kernel samples are zero`; do not evaluate top-leaf, family, or
   measurement-selection fields.
2. Otherwise, if either top leaf is absent or has `symbolized is not True`,
   return a rejected comparison with `kernel top leaf is unresolved`; do not
   evaluate family or measurement-selection fields. A symbolized caller still
   cannot satisfy this gate.
3. Require the two resolved `top_frames[0]["frame"]` values to be identical.
4. For the union of leaves satisfying `100 * samples >= 5 * kernel_samples` in
   either run, use zero samples when a leaf is absent and accept its delta iff
   `100 * abs(a * B - b * A) <= 5 * A * B`, where `a/A` and `b/B` are
   that leaf's exact run shares.
5. Compare each run's exact Darwin-kernel count `a/A` to the accepted exact
   mean. Accept iff
   `100 * abs(a * ACCEPTED_KERNEL_SHARE_MEAN_DEN -
   ACCEPTED_KERNEL_SHARE_MEAN_NUM * A) <=
   5 * A * ACCEPTED_KERNEL_SHARE_MEAN_DEN`.
6. Compare normalized stack families as specified below. A family-stability
   failure rejects the comparison. Low stable-family concentration does not
   reject otherwise complete evidence; it emits the accepted
   `selection_outcome="diffuse"`.

The zero and unresolved returns dominate every later rule. Because
`build_artifact` raises on the rejected summary/comparison and `main` writes
only after acceptance, neither state can publish an attribution artifact.
Task 4 therefore has exactly one result for both states: preserve every
published receipt, record `MEASUREMENT_REPAIR_REQUIRED` outside the hypothesis
backlog, and leave H006 absent.

For stack-family comparison, build maps keyed by the exact
`tuple(item["frames"])` values from each run's complete, ranked
`kernel["stack_families"]` list:

1. Let `A` and `B` be the two exact kernel-sample totals. For the union of
   every family satisfying `100 * a >= 5 * A` or `100 * b >= 5 * B`, use zero
   samples for a missing family and accept its delta iff
   `100 * abs(a * B - b * A) <= 5 * A * B`. This gate catches a common leaf
   whose caller chain changes between runs.
2. Define each run's top 10 as ranks 1 through 10 from its deterministic family
   list. Emit `members` for the union of the two top-10 identity sets and every
   identity compared by rule 1, so every accepted comparison delta remains
   auditable. A row is a `stable_top_10_member` only when its identity occurs
   in both top 10s and the same exact cross-product delta predicate passes.
3. For each pair row construct `share_a = Fraction(a, A)` and
   `share_b = Fraction(b, B)`. Sort pair rows and stable members by descending
   `min(share_a, share_b)`, then descending `share_a + share_b`, then
   lexicographic frame tuple. Missing samples are zero. Exact `Fraction`
   values—not emitted `shares` floats—are the ordering authority that chooses
   the first member.
4. For each run, sum the exact samples of every stable member. Emit
   `stable_top_10_coverage` as the two diagnostic float shares, but test each
   coverage with `100 * stable_samples >= 60 * kernel_samples`. Do not use the
   union, either run alone, or `top_10_frame_share`.
5. `selected_family` is the first stable member whose normalized leaf
   `frames[0]` contains a backtick, or JSON `null` when none exists.
   When non-null, look that leaf up in each run's complete `top_frames` map and
   copy its per-run aggregate leaf samples and shares into the selected object;
   Task 4 must not repeat that lookup.
6. Emit `selection_outcome="selectable"` only when `selected_family` is
   non-null, `100 * selected_samples >= 10 * kernel_samples` in each run, and
   `100 * stable_samples >= 60 * kernel_samples` in each run. All four
   predicates are required; both boundaries are inclusive.
7. Otherwise emit `selection_outcome="diffuse"` plus every applicable exact
   reason in this order: `no symbolized normalized family occurs in both top
   10s`; `selected family minimum share <share> is below 10%`; `stable top-10
   family coverage <coverage> is below 60%`. This is an accepted,
   kernel-family-selection-question-disconfirming measurement result only
   after all measurement-rejection gates above pass. It does not create or
   reject a hypothesis.

Every two-element `ranks`, `samples`, `shares`, coverage, leaf-sample, and
leaf-share array is ordered `[run_a, run_b]`, matching the two input profile
paths. A family present outside one run's top 10 keeps its actual samples/share
but has JSON `null` rank for that run; a family absent from a run has `null`
rank and numeric zero samples/share. `stable_top_10_members` preserves the same
deterministic ordering as the filtered `members` rows. All emitted `shares`,
`absolute_delta`, `minimum_share`, coverage, and
`minimum_stable_top_10_coverage_observed` values are computed with
`float(Fraction(...))` only after exact predicates and ordering have been
decided. Tests must fail if any implementation reads those floats back for
authority.

Emit:

```json
{
  "kernel_top_frame": "kernel`vm_fault",
  "kernel_frame_absolute_deltas": {"kernel`vm_fault": 0.01},
  "kernel_stack_family": {
    "normalization": {
      "terminal_offset_pattern": "\\+0x[0-9a-fA-F]+$",
      "prefix_frames": 4
    },
    "top_limit": 10,
    "minimum_compared_share": 0.05,
    "maximum_absolute_delta": 0.05,
    "minimum_selected_share": 0.10,
    "minimum_stable_top_10_coverage": 0.60,
    "kernel_sample_totals": [100, 100],
    "members": [
      {
        "frames": ["kernel`vm_fault", "kernel`arm_fast_fault"],
        "ranks": [1, 1],
        "samples": [40, 38],
        "shares": [0.40, 0.38],
        "absolute_delta": 0.02,
        "stable_top_10_member": true,
        "leaf_symbolized": true
      },
      {
        "frames": ["kernel`pmap_enter", "kernel`vm_fault"],
        "ranks": [2, 2],
        "samples": [28, 28],
        "shares": [0.28, 0.28],
        "absolute_delta": 0.0,
        "stable_top_10_member": true,
        "leaf_symbolized": true
      }
    ],
    "stable_top_10_members": [
      ["kernel`vm_fault", "kernel`arm_fast_fault"],
      ["kernel`pmap_enter", "kernel`vm_fault"]
    ],
    "stable_top_10_samples": [68, 66],
    "stable_top_10_coverage": [0.68, 0.66],
    "minimum_stable_top_10_coverage_observed": 0.66,
    "selected_family": {
      "frames": ["kernel`vm_fault", "kernel`arm_fast_fault"],
      "ranks": [1, 1],
      "samples": [40, 38],
      "shares": [0.40, 0.38],
      "minimum_share": 0.38,
      "absolute_delta": 0.02,
      "leaf": "kernel`vm_fault",
      "leaf_samples": [46, 44],
      "leaf_shares": [0.46, 0.44]
    },
    "selection_outcome": "selectable",
    "selection_reasons": []
  },
  "measurement_selection": {
    "result": "SELECTABLE_CANDIDATE_PACKAGE",
    "hypothesis_ledger_mutation": "none"
  },
  "accepted_kernel_baseline": {
    "artifact": "scripts/perf/evidence/native-go-build-wall-attribution-v1.json",
    "profile_producer_sha": "688357ef6b72b299daf5990d494fff7d1a7a7805",
    "artifact_acceptance_sha": "34ce4c3c40bec2bd408612efcba66226fa2793f9",
    "sample_counts": [[9750, 28255], [9748, 28385]],
    "shares": [0.34507166873119804, 0.34342082085608594],
    "mean_fraction": {
      "numerator": 552183490,
      "denominator": 1604036350
    },
    "mean": 0.34424624479364196,
    "maximum_absolute_delta": 0.05,
    "new_sample_counts": [[100, 290], [100, 291]],
    "new_shares": [0.3448275862068966, 0.3436426116838488],
    "absolute_deltas_from_mean": [0.0005813414132545623, 0.0006036331097931922]
  }
}
```

The comparison-level `measurement_selection` object is outside the hypothesis
ledger and contains no hypothesis ID or status. Map the family result exactly:

```text
selection_outcome="selectable"
  -> result="SELECTABLE_CANDIDATE_PACKAGE"
  -> hypothesis_ledger_mutation="none"

selection_outcome="diffuse"
  -> result="KERNEL_FAMILY_SELECTION_DISCONFIRMED"
  -> hypothesis_ledger_mutation="none"
```

The selectable object packages the emitted selected family/leaf and CPU-work
observation for a later causal design; it does not assert that the family
causes wall time. The diffuse object disconfirms only the measurement question
“does a stable, significant kernel family exist to select?” It does not reject
an undefined mechanism. Rejected evidence produces no comparison or
`measurement_selection` object because the analyzer publishes no artifact;
Task 4 records `MEASUREMENT_REPAIR_REQUIRED`.

Emit `kernel_stack_family` and `measurement_selection` only for an accepted
`require_kernel_stacks=True` pair. Default historical two-profile analysis
retains its existing category-comparison shape and emits neither field;
one-profile analysis still has `comparison=null`.

Use failure text:

```text
kernel top frame differs between profiles
kernel top leaf is unresolved
kernel frame <name> share delta <delta> exceeds 5%
kernel stack family <compact-json-frames> share delta <delta> exceeds 5%
Darwin kernel share <share> differs from accepted mean by <delta>, exceeds 5%
```

Render `<compact-json-frames>` with
`json.dumps(list(family), separators=(",", ":"))`, and format every reported
share/delta with `.3%`. The required RED fixtures and GREEN assertions are:

- `test_required_pair_zero_rejects_before_family_decision` covers both
  zero/zero and zero/valid orderings. Direct `compare(...,
  require_kernel_stacks=True)` returns `accepted is False`, has exactly the
  first failure `kernel samples are zero`, and has no `kernel_stack_family`
  or `measurement_selection` key; `build_artifact` raises with that reason and
  an absent CLI output remains absent.
- `test_required_pair_unresolved_leaf_rejects_before_family_decision` uses a
  nonzero raw-address leaf with a symbolized caller. Direct comparison returns
  `accepted is False`, has exactly the first failure `kernel top leaf is
  unresolved`, and has no `kernel_stack_family` or `measurement_selection` key;
  `build_artifact` raises with that reason and output remains absent.
- `test_stack_family_normalization_ignores_offsets_and_deep_tail`: run A has
  two 20-sample raw stacks whose first four frames differ from run B's
  40-sample stack only by terminal offsets and frames after depth four. The
  accepted comparison emits one 40-sample family with identical normalized
  first-four-frame identity in both runs.
- `test_same_leaf_different_caller_family_rejects_output`: run A gives 40 of
  100 kernel samples to
  ``["kernel`vm_fault+0x10", "kernel`caller_a+0x4"]``; run B gives 40 of
  100 to ``["kernel`vm_fault+0x20", "kernel`caller_b+0x8"]``; the remaining
  60 samples use identical families. The leaf gate passes, but family
  comparison rejects the two 40% identities, and CLI output remains absent.
- `test_hostile_exact_five_point_leaf_family_and_category_delta_is_accepted`
  uses literal shares `40/100` and `35/100`. It asserts the authoritative
  predicate exactly:

  ```python
  self.assertEqual(
      100 * abs(40 * 100 - 35 * 100),
      5 * 100 * 100,
  )
  self.assertTrue(share_delta_at_most(40, 100, 35, 100, 5))
  ```

  Separate full comparison fixtures use those counts for the same leaf and
  normalized family, and for one eligible CPU category. Each comparison is
  accepted even though `40 / 100 - 35 / 100` is not an exact binary float.
  Repeat every full comparison with the A/B operands reversed (`35/100`
  versus `40/100`) and require the same acceptance, so omitting `abs()` cannot
  pass.
- `test_just_over_five_point_leaf_family_and_category_delta_rejects` uses
  literal shares `400/1000` and `349/1000`. It asserts
  `100 * abs(400 * 1000 - 349 * 1000) >
  5 * 1000 * 1000`; separate leaf, family, and eligible-category variants each
  reject for their existing exact reason, and CLI output remains absent.
  Repeat every variant with the A/B operands reversed (`349/1000` versus
  `400/1000`) and require the same rejection.
- `test_exact_five_percent_membership_boundary_and_just_below` asserts
  `100 * 5 == 5 * 100` and `100 * 499 < 5 * 10000`. Full leaf and family
  fixtures prove `5/100` is included in the threshold-driven delta set while
  `499/10000` is not. Put **both** the exact-boundary family and the
  just-below family outside both top-10 sets; assert that only the `5/100`
  family enters emitted `members`. This isolates inclusive threshold
  membership from top-10 membership. No emitted float decides membership.
- `test_family_selection_accepts_inclusive_ten_and_sixty_percent_boundaries`
  uses 90 kernel and 171 user samples in each profile, with normalized counts
  `[9] + [5] * 9 + [3] * 12`. It asserts
  `100 * 9 == 10 * 90` and `100 * 54 == 60 * 90`, emits selected minimum
  share `0.10`, stable coverage `[0.60, 0.60]`,
  `selection_outcome="selectable"`, and comparison-level
  `measurement_selection` exactly
  `{"result": "SELECTABLE_CANDIDATE_PACKAGE",
  "hypothesis_ledger_mutation": "none"}`.
- `test_ten_percent_share_with_below_sixty_coverage_reports_coverage_only`
  uses 100 kernel and 190 user samples in each run. The identical stable top-10
  counts are `[10, 6, 6, 6, 6, 5, 5, 5, 5, 5]`, totaling 59; all remaining
  families have at most four samples. Exact selected share passes at `10/100`,
  exact coverage fails at `59/100`, and the accepted diffuse decision contains
  only `stable top-10 family coverage 59.000% is below 60%`.
- `test_below_ten_share_with_exact_sixty_coverage_reports_share_only` uses
  10,000 kernel and 19,000 user samples in each run. The identical stable
  top-10 counts are `[999, 556, 556, 556, 556, 556, 556, 556, 556, 553]`,
  totaling 6,000; remaining families have at most 400 samples. Exact coverage
  passes at `6000/10000`, selected share fails at `999/10000`, and the accepted
  diffuse decision contains only
  `selected family minimum share 9.990% is below 10%`.
- `test_selection_requires_share_and_coverage_conjunction` runs the four exact
  boolean cases `(share_ok, coverage_ok)` = `(true,true)`, `(true,false)`,
  `(false,true)`, and `(false,false)` through the real family-decision path.
  Only `(true,true)` is selectable; the other cases emit respectively the
  coverage reason, share reason, and both reasons in the fixed order. This
  fails an erroneous `or` implementation.
- `test_stable_diffuse_family_distribution_is_accepted_decision` uses 100
  kernel and 190 user samples in each profile with 20 lexicographically named,
  symbolized families of five samples each.
  It passes measurement gates and publishes an accepted artifact with stable
  top-10 coverage `[0.50, 0.50]`, selected minimum share `0.05`,
  `selection_outcome="diffuse"`, both ordered reasons for the 10% and 60%
  thresholds, and comparison-level `measurement_selection` exactly
  `{"result": "KERNEL_FAMILY_SELECTION_DISCONFIRMED",
  "hypothesis_ledger_mutation": "none"}`.
- `test_family_comparison_is_input_order_deterministic` reverses raw stack-row
  order in both boundary fixtures and asserts the complete
  `kernel_stack_family` object is byte-for-byte equal after JSON serialization
  with `sort_keys=True`.
- `test_exact_fraction_family_ordering_beats_float_tie` uses
  `N = 1 << 60`. Family
  ``["kernel`leaf", "kernel`aaa"]`` has counts
  `[N // 2, N // 2 - 2]`; family
  ``["kernel`leaf", "kernel`zzz"]`` has
  `[N // 2 - 1, N // 2 - 1]`. Their shared normalized leaf aggregates to the
  identical top leaf in both runs, so the top-leaf gate passes. Each run's
  remaining counts are a lower family, and each profile has `2 * N` user
  samples so accepted-baseline drift remains in range. The four emitted family
  shares round to the same binary float near `0.5`, but exact minimum share
  ranks the ``kernel`zzz`` caller family first. Assert it is the selected family
  and that reversing source rows changes no output.
- `test_exact_accepted_baseline_mean_boundary` constructs
  `mean_num = 9750 * 28385 + 9748 * 28255`,
  `mean_den = 2 * 28255 * 28385`, then a new exact share with
  `new_total = 20 * mean_den` and
  `new_samples = 20 * mean_num + mean_den`. The delta is exactly five
  percentage points and passes. Incrementing `new_samples` by one is
  mathematically just over five points and rejects. Repeat on the other side
  with `new_samples = 20 * mean_num - mean_den`, which is exactly five points
  below and passes, then decrement it by one and require rejection. Neither
  assertion compares with `0.34424624479364196`.
- `test_exact_existing_and_kernel_coverage_boundaries` exercises exact and
  just-below values for the unchanged 99% wall, 85% resolved CPU, 80%
  voluntary-stack, and 95% symbolized-leaf gates. In particular, `95/100`
  symbolized leaf samples pass and `9499/10000` reject. The test asserts the
  emitted float diagnostics but proves the decisions from integer predicates.
- `test_exact_category_eligibility_boundary` proves `10/100` enters the
  existing category stability gate and `999/10000` does not. It preserves the
  current category set, dominant-rank contract, and default two-profile scope.
- `test_dominant_category_uses_integer_counts_not_float_share` uses a total
  above `1 << 60` with the two leading categories one sample apart but rounded
  to the same emitted float share. The larger integer count must be dominant;
  an exact count tie must retain `CPU_CATEGORIES` order.

Also retain tests for different top leaves and missing leaves treated as zero.
Default historical analysis does not apply the new baseline, leaf, family,
zero, or unresolved gates and emits no pair decision for a one-profile
artifact. Historical single-run acceptance still applies its existing
99%/85%/80% gates, now with mathematically exact predicates.

- [ ] **Step 6: Expose one no-output-on-rejection API**

Add:

```python
def build_artifact(
    profile_paths: tuple[pathlib.Path, ...],
    binary: pathlib.Path,
    *,
    require_kernel_stacks: bool,
) -> dict[str, object]:
    if len(profile_paths) not in {1, 2}:
        raise ValueError("one or two profiles are required")
    summaries = tuple(
        summarize(
            load_profile(path),
            binary,
            require_kernel_stacks=require_kernel_stacks,
        )
        for path in profile_paths
    )
    comparison = (
        compare(
            summaries[0],
            summaries[1],
            require_kernel_stacks=require_kernel_stacks,
        )
        if len(summaries) == 2
        else None
    )
    accepted = all(bool(summary["accepted"]) for summary in summaries)
    if comparison is not None:
        accepted = accepted and bool(comparison["accepted"])
    if not accepted:
        reasons = [
            str(reason)
            for summary in summaries
            for reason in summary["failures"]
        ]
        if comparison is not None:
            reasons.extend(str(reason) for reason in comparison["failures"])
        raise ValueError("; ".join(dict.fromkeys(reasons)))
    return {
        "schema": OUTPUT_SCHEMA,
        "profiles": list(summaries),
        "comparison": comparison,
        "accepted": True,
    }
```

Keep the existing direct `--profile`/`--binary` CLI for historical use and add
`--require-kernel-stacks`. `main` calls `build_artifact`; only after it returns
does `_write_atomic` create `--output`. Add a test with an absent output path
that remains absent when `build_artifact` or `main` rejects.

- [ ] **Step 7: Document the evidence units**

In `scripts/perf/README.md`, state:

```text
Kernel PCs and kernel stacks are sampled at the same 499 Hz event.
`samples / 499` is sampled CPU-work opportunity in CPU seconds.
It is not elapsed time, a critical-path measure, or a wall-time ceiling.
Historical profiles may omit kernel stacks; new campaign evidence must set
`--require-kernel-stacks`.
```

Document the 95% symbolized-leaf gate, exact reconciliation, four-frame
offset-normalized family identity, deterministic stable-top-10 intersection,
5% family comparison, 10% selected-family and 60% stable-coverage thresholds,
and fixed accepted-kernel-share drift comparison. State that every decision
uses counts/totals or exact `Fraction` ordering, while emitted floats are
diagnostics only. Include accepted counts `9750/28255` and `9748/28385` plus
exact mean fraction `552183490/1604036350`. State that required-live zero or
unresolved-top-leaf evidence is rejected as
`MEASUREMENT_REPAIR_REQUIRED`; selectable evidence emits
`SELECTABLE_CANDIDATE_PACKAGE`; stable-but-diffuse evidence emits
`KERNEL_FAMILY_SELECTION_DISCONFIRMED`; all three are outside the hypothesis
ledger and leave H006 absent.
Name `688357ef6b72b299daf5990d494fff7d1a7a7805` as the accepted profiles'
producer and `34ce4c3c40bec2bd408612efcba66226fa2793f9` as the artifact's
acceptance commit.

- [ ] **Step 8: Run GREEN gates**

Run:

```bash
python3 -m unittest scripts.perf.test_native_wall_attribution -v
python3 -m py_compile \
  scripts/perf/native_wall_attribution.py \
  scripts/perf/test_native_wall_attribution.py
just fmt-check
git diff --check
```

Expected: all pass.

- [ ] **Step 9: Commit the analyzer**

Run:

```bash
git add \
  scripts/perf/native_wall_attribution.py \
  scripts/perf/test_native_wall_attribution.py \
  scripts/perf/README.md
git commit -F - <<'EOF'
diagnostics(native): rank kernel CPU stacks

Kernel PC samples identify a large Darwin bucket but cannot distinguish a
stable mechanism or quantify its sampled CPU work.

Reconcile count-valued kernel stacks, rank normalized caller families and their
actual leaves, preserve historical zero/absent cases, and compare new captures
with the accepted kernel-share baseline.

Verified with malformed-unit, zero-kernel, unresolved-leaf, deterministic
family-membership/coverage, two-run stability, baseline-drift, and
rejected-output tests.

Co-Authored-By: Codex <codex@openai.com>
EOF
```

Expected: this is the second commit after `PLAN_SHA`.

---

### Task 3: Build a fail-closed receipt capture and analysis runner

**Files:**
- Create: `scripts/perf/native_kernel_capture.py`
- Create: `scripts/perf/test_native_kernel_capture.py`
- Modify: `scripts/perf/README.md`

**Interfaces:**
- Consumes: only the stable `native_go_build.guest_script()` workload API, signed `carrick trace --profile native-wall`, `native_wall_attribution.build_artifact`, and `scripts/sudo/kill.sh <exact-run-id>`.
- Does not consume: `PERFORMANCE_CONTROL_KEYS`, `fixed_variant_overlay`, `reject_ambient_carrick`, `foreign_workload_census`, `sample_provenance`, or any sidecar experiment helper. Those APIs do not exist at pinned base `7131c12b`.
- Produces: one single-use directory containing `trace.raw`, `summary.jsonl`, `stdout.log`, `stderr.log`, `command-status.json`, `cleanup.stdout.log`, `cleanup.stderr.log`, and an atomic exclusive `carrick.native-kernel-capture.v1` `receipt.json`.
- Produces: `capture` and `analyze` CLI modes. `analyze` accepts only two validated accepted receipts and delegates summary math to Task 2; Task 4 never supplies raw profile paths.

- [ ] **Step 1: Write failing environment, lifecycle, and receipt tests**

Use real temporary files/directories for hashing, status, atomic publication,
and receipt validation. Use a small injected subprocess executor only at the
external `git`, `ps`, `docker`, trace, and cleanup boundary. Each fake response
must match the complete real `CompletedProcess` fields used by production.

Do not import the not-yet-created module at test-module scope. Use:

```python
def subject(self):
    try:
        return importlib.import_module("native_kernel_capture")
    except ModuleNotFoundError as error:
        self.fail(f"native_kernel_capture module must exist: {error}")
```

Add
`test_module_exposes_capture_census_and_analysis_entrypoints` first. It calls
`self.subject()` and asserts that `capture_one`,
`validate_run_id`, `classify_process_snapshot`, `analyze_receipts`, and `main`
are callable. A missing module is therefore an assertion failure inside a
test, not a discovery/import error.

Use the following as the complete behavior-test backlog. Before Step 2, add
only the module-entrypoint test plus the named parent-shell/independent-runner
test, ambient-control test, and two named run-ID tests used in Step 4. After
their intended RED, add each remaining test one at a time and run it RED before
its implementation:

```text
existing artifact directory rejects before any subprocess and is unchanged
ambient CARRICK_DSR_SHARED_TRANSLATION rejects before trace launch
test_run_id_allowlist_accepts_only_conservative_ascii
test_invalid_run_ids_reject_before_artifact_or_subprocess
host trace environment contains exactly the selected CARRICK_RUN_ID among CARRICK_* keys
guest argv contains -e CARRICK_RUN_ID=<the-same-id>
timeout writes status=124 and timed_out=true, then runs exact kill.sh <run-id>
trace exception writes status=125 and still runs exact cleanup
cleanup nonzero makes accepted=false
exact post-cleanup census containing carrick:<run-id>: makes accepted=false
prefix run ID and regex metacharacters do not match a different stamped token
own process plus every ancestor is excluded from foreign census even when the parent shell command contains scripts/perf/native_kernel_capture.py
a separate concurrent runner outside that ancestor chain remains foreign in the same ps snapshot
the same process graph in different ps row order yields identical canonical ancestry/foreign evidence
an ancestor PID/PPID/command change between pre/post snapshots is provenance drift
pre/post git, binary, host, image, environment, or foreign census drift makes accepted=false
nonzero trace status or stdout without exactly one BUILD_OK makes accepted=false
incomplete, bounded, dropped, interrupted, wrong-run-id, dirty, or wrong-command summary makes accepted=false through the real attribution loader
accepted and rejected receipts bind all seven non-receipt artifacts by absolute path, size, and SHA-256
receipt publication is exclusive and cannot replace an existing receipt
analyze rejects a modified bound artifact and leaves output absent
analyze rejects an accepted=false receipt and leaves output absent
analyze accepts two determinant-equal, distinct-run receipts and passes only their bound summary paths to build_artifact
analyze accepts different A/B ancestry PIDs when ordered normalized commands and chain shape match
analyze rejects a different launcher command or extra/missing ancestor and leaves output absent
```

Every failure after successful directory creation must leave one parseable,
atomic, immutable `accepted=false` receipt and return nonzero. Directory
collision is the only expected failure with no new receipt because the runner
must not mutate an existing evidence path.

- [ ] **Step 2: Prove the bootstrap RED is a test failure**

Run:

```bash
python3 -m unittest \
  scripts.perf.test_native_kernel_capture.NativeKernelCaptureTest.test_module_exposes_capture_census_and_analysis_entrypoints \
  -v
```

Expected: `FAIL`, not `ERROR`, with
`native_kernel_capture module must exist`. Fix test syntax until unittest
reports an assertion failure; an import/discovery error is not accepted RED
evidence.

- [ ] **Step 3: Make only the module bootstrap GREEN**

Create `scripts/perf/native_kernel_capture.py` with the smallest importable
surface:

```python
#!/usr/bin/env python3
"""Capture receipt-bound Darwin kernel on-CPU evidence."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Sequence


@dataclasses.dataclass(frozen=True)
class ProcessRow:
    pid: int
    ppid: int
    command: str


@dataclasses.dataclass(frozen=True)
class ProcessCensus:
    ancestry: tuple[ProcessRow, ...]
    foreign: tuple[str, ...]


def classify_process_snapshot(
    ps_output: str,
    *,
    own_pid: int,
) -> ProcessCensus:
    return ProcessCensus(ancestry=(), foreign=())


def validate_run_id(_run_id: str) -> None:
    return None


def capture_one(*_args, **_kwargs):
    return None


def analyze_receipts(*_args, **_kwargs):
    return None


def main(_argv: Sequence[str] | None = None) -> int:
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

Run the focused bootstrap test again. Expected: `PASS`.

- [ ] **Step 4: Prove behavior RED after the module imports**

Use this literal process snapshot in the ancestry behavior test, with the rows
deliberately out of PID order:

```text
41 40 python3 scripts/perf/native_kernel_capture.py capture --run-id other
20 10 zsh -lc python3 scripts/perf/native_kernel_capture.py capture --run-id ours
1 0 /sbin/launchd
30 20 python3 scripts/perf/native_kernel_capture.py capture --run-id ours
40 10 zsh -lc python3 scripts/perf/native_kernel_capture.py capture --run-id other
10 1 /Applications/Codex.app/Contents/MacOS/Codex
```

Call `classify_process_snapshot(snapshot, own_pid=30)`. Hand-derived expected
evidence is:

```python
self.assertEqual(
    [row.pid for row in census.ancestry],
    [30, 20, 10, 1],
)
self.assertEqual(
    census.foreign,
    (
        "pid=40 ppid=10 command=zsh -lc python3 "
        "scripts/perf/native_kernel_capture.py capture --run-id other",
        "pid=41 ppid=40 command=python3 "
        "scripts/perf/native_kernel_capture.py capture --run-id other",
    ),
)
```

The parent PID 20 contains the runner path but is absent from `foreign`; the
independent runner PID 41 and its shell PID 40 remain foreign. Also run the
ambient-control capture test, whose first assertion requires a non-`None`
receipt before inspecting it.

Run:

```bash
python3 -m unittest \
  scripts.perf.test_native_kernel_capture.NativeKernelCaptureTest.test_parent_shell_is_excluded_but_independent_runner_is_foreign \
  scripts.perf.test_native_kernel_capture.NativeKernelCaptureTest.test_ambient_control_publishes_rejected_receipt_without_trace \
  scripts.perf.test_native_kernel_capture.NativeKernelCaptureTest.test_run_id_allowlist_accepts_only_conservative_ascii \
  scripts.perf.test_native_kernel_capture.NativeKernelCaptureTest.test_invalid_run_ids_reject_before_artifact_or_subprocess \
  -v
```

Expected: all four are `FAIL`, not `ERROR`: the census returns empty evidence,
`capture_one` returns `None`, and the no-op validator accepts rejected run IDs.
These are the intended missing behaviors. Only after observing these failures
continue with implementation. Add the remaining lifecycle tests one behavior
at a time, observe the focused assertion failure, then make the smallest
implementation change that passes it.

- [ ] **Step 5: Define self-contained capture types and fixed inputs**

Use:

```python
SCHEMA = "carrick.native-kernel-capture.v1"
SUMMARY_SCHEMA = "carrick.dsr-profile.v1"
PROFILE = "native-wall"
DEFAULT_TIMEOUT_SECONDS = 180
DEFAULT_IMAGE = "localhost:5005/carrick-go-conformance:1.24"
REFERENCE_IMAGE_ID = (
    "sha256:6199806814040f05f24d1845b3198f82"
    "a2bb982d336ffb04aa4470861cb214d6"
)
REFERENCE_IMAGE_DIGEST = (
    "localhost:5005/carrick-go-conformance@"
    "sha256:6199806814040f05f24d1845b3198f82"
    "a2bb982d336ffb04aa4470861cb214d6"
)


@dataclasses.dataclass(frozen=True)
class CaptureConfig:
    repo: pathlib.Path
    binary: pathlib.Path
    image: str
    run_id: str
    artifact_dir: pathlib.Path
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


@dataclasses.dataclass(frozen=True)
class CommandStatus:
    status: int
    timed_out: bool


@dataclasses.dataclass(frozen=True)
class CleanupEvidence:
    status: int
    stdout: str
    stderr: str
    descendants: tuple[str, ...]
```

Define and use this exact conservative validator before directory creation or
any subprocess:

```python
RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,96}", re.ASCII)


def validate_run_id(run_id: str) -> None:
    if run_id == "--all" or RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise ValueError(
            "run ID must be 1-96 ASCII letters, digits, dot, underscore, "
            "or hyphen, and must not equal --all"
        )
```

The accepted fixtures are `"a"`, `"native-kernel-stack-a-v1"`, and
`"A.Z_9-"`. The rejected fixtures are exactly:

```python
(
    "",
    "--all",
    r"bad\t",
    "bad name",
    "bad\tname",
    "bad\nname",
    "bad\rname",
    "bad/name",
    "bad:name",
    "é",
    "'quoted'",
    '"quoted"',
    "$HOME",
    "`id`",
    "bad;name",
    "x" * 97,
)
```

For every rejected fixture assert that no subprocess executor call occurred
and the requested artifact path is still absent. This test proves that a run ID
accepted by the runner reaches `scripts/sudo/kill.sh` and its `awk -v`
assignments without backslash, shell, whitespace, control, or non-ASCII
reinterpretation.

Resolve `repo` after run-ID validation; resolve relative `binary` and
`artifact_dir` against that repository. Require the binary inside the
repository and the artifact directory inside `repo/target/perf`. Create the
directory once with `mkdir(parents=True, exist_ok=False)`.

Define exactly:

```python
{
    "raw_trace": artifact_dir / "trace.raw",
    "summary_jsonl": artifact_dir / "summary.jsonl",
    "command_stdout": artifact_dir / "stdout.log",
    "command_stderr": artifact_dir / "stderr.log",
    "command_status": artifact_dir / "command-status.json",
    "cleanup_stdout": artifact_dir / "cleanup.stdout.log",
    "cleanup_stderr": artifact_dir / "cleanup.stderr.log",
    "receipt": artifact_dir / "receipt.json",
}
```

Never delete, truncate, rename, or reuse an existing artifact directory.

- [ ] **Step 6: Build the fixed default path without current-only helpers**

Import only:

```python
from native_go_build import guest_script
```

Reject every inherited environment key beginning with `CARRICK_`. Then copy
`os.environ` and add only:

```python
environment["CARRICK_RUN_ID"] = config.run_id
```

Build the guest command locally:

```python
guest_command = [
    str(config.binary),
    "run",
    "--exec-backend",
    "native",
    "-e",
    f"CARRICK_RUN_ID={config.run_id}",
    "-w",
    "/tmp",
    config.image,
    "/bin/sh",
    "-c",
    guest_script(),
]
trace_command = [
    str(config.binary),
    "trace",
    "--profile",
    PROFILE,
    "--trace-out",
    str(paths["raw_trace"]),
    "--summary-jsonl",
    str(paths["summary_jsonl"]),
    "--",
    *guest_command[1:],
]
```

No `sudo`, `gtimeout`, pipeline, `tee`, manual DTrace command, sidecar
environment, or mutable workload command is supported.

- [ ] **Step 7: Implement self-contained provenance and ancestry-safe census**

The pre/post snapshot must contain:

```text
git_commit
git_status
repository
binary_path
binary_sha256
host = {platform, machine, node}
image_ref
image = {architecture, id, repo_digests}
controlled_environment = {CARRICK_RUN_ID: <run-id>}
process_ancestry = [{pid, ppid, command}, ...] from runner to PID 1
foreign_processes
docker_oracles
```

Implement these with the Python standard library and read-only subprocesses:

```text
git rev-parse HEAD
git status --porcelain=v1
sha256(binary)
platform.platform(), platform.machine(), platform.node()
docker image inspect --format \
  '{{json .Architecture}}\n{{json .Id}}\n{{json .RepoDigests}}' \
  localhost:5005/carrick-go-conformance:1.24
ps -axww -o pid= -o ppid= -o command=
docker ps --format {{.ID}} {{.Names}} {{.Image}}
```

Require the exact reference image identity above and allow only `registry` or
`registry:*` running containers. Parse the one `ps` result into `ProcessRow`
values with `split(maxsplit=2)`, reject malformed/non-numeric rows and duplicate
PIDs, and build one `pid -> ProcessRow` map. Starting at `os.getpid()`, follow
`ppid` in that same immutable map through PID 1 to PPID 0. Reject a missing
runner row, missing ancestor row, or ancestry cycle. Do not issue a second
`ps` call to discover parents.

Set `excluded_pids` to exactly the runner PID plus every derived ancestor PID.
Only the general foreign-workload scan excludes those PIDs. For every other
row, reject an executable named `cargo` or `rustc`, any command containing
`target/release/carrick`, `scripts/perf/native_go_build.py`,
`scripts/perf/native_wall_attribution.py`,
`scripts/perf/native_kernel_capture.py`, or
`scripts.perf.test_native_kernel_capture`. Do not reject an arbitrary process
merely because its command contains the word `test`. Sort foreign evidence by
PID and render each row exactly as:

```text
pid=<pid> ppid=<ppid> command=<complete command>
```

Serialize `process_ancestry` in runner-to-root order. A parent `zsh -lc`
command containing the runner path is therefore auditable but not foreign; a
sibling or otherwise independent runner is not in `excluded_pids` and remains
foreign.

Both pre and post snapshots derive their ancestry from their own single `ps`
snapshot. Canonical PID ordering makes input row order irrelevant.
`process_ancestry` is part of exact pre/post provenance equality: a changed
ancestor PID, PPID, or command rejects the capture. Keep those literal values
bound in each receipt. Do not directly compare literal ancestry PID/PPID values
between serial A/B captures; Step 10 defines the only allowed cross-run
projection.

Implement `scoped_process_census(run_id)` with literal, delimiter-aware
matching equivalent to `scripts/sudo/kill.sh`:

```text
carrick:<run-id>:
CARRICK_RUN_ID=<run-id>
--name <run-id>
run_id=<run-id>
```

The last three match only on `carrick trace` command lines and require the next
character to be end-of-string, space, tab, backslash, single quote, or double
quote. Do not use a regex or an unanchored `run_id in command` test. Unlike the
general foreign census, this post-cleanup census does **not** exclude ancestors:
its narrow guest/trace predicate must still expose a surviving trace wrapper.
The Task 4 parent contains `native_kernel_capture.py` and `--run-id`, not
`carrick trace` or any of the accepted `key=value`/`--name` tokens, so it does
not match the cleanup census.

- [ ] **Step 8: Implement total capture ordering and immutable status**

The lifecycle is exactly:

```text
validate collision without subprocess
exclusive directory creation
ambient-environment validation
pre-provenance snapshot
trace subprocess with timeout_seconds=180 for campaign runs
materialize stdout, stderr, status, absent raw, and absent summary
exact run-ID cleanup in finally
materialize cleanup stdout and stderr
exact post-cleanup descendant census
post-cleanup provenance snapshot
load and summarize the profile through native_wall_attribution
bind every non-receipt artifact
publish receipt atomically and exclusively
return zero only when receipt accepted=true
```

Cleanup is always:

```python
subprocess.run(
    [str(config.repo / "scripts/sudo/kill.sh"), config.run_id],
    cwd=config.repo,
    capture_output=True,
    text=True,
    timeout=30,
    check=False,
)
```

Write `command-status.json` atomically as:

```json
{"status": 0, "timed_out": false}
```

Use status `124` for `TimeoutExpired` and `125` for launch/internal exceptions.
After directory creation, exceptions become rejection reasons; they do not
bypass cleanup or receipt publication. The post snapshot occurs only after
cleanup and the descendant census.

- [ ] **Step 9: Validate the summary through the real attribution loader**

Do not add a first-row-only or parallel JSONL validator. Call the Task 2
production path:

```python
profile = native_wall_attribution.load_profile(paths["summary_jsonl"])
single_run = native_wall_attribution.summarize(
    profile,
    config.binary,
    require_kernel_stacks=True,
)
if not single_run["accepted"]:
    raise EvidenceError(
        "; ".join(str(reason) for reason in single_run["failures"])
    )
```

`load_profile` is authoritative for every-row schema/profile/provenance/
completion invariance, the one completion row, and all completion/drop gates.
`summarize` is authoritative for wall, CPU, voluntary-stack, kernel-stack, and
symbolization reconciliation. Compare the returned `Profile.provenance` and
`Profile.completion` to frozen preflight rather than re-reading only the first
row. Require:

```text
schema=carrick.dsr-profile.v1
profile=native-wall
run_id equals config.run_id
git_sha equals frozen pre.git_commit
git_dirty=false
binary_sha256 equals frozen pre.binary_sha256
host equals frozen pre.host.node
command equals guest_command[1:]
exactly one metric.type=completion row
completion.complete=true
completion.bounded=false
completion.target_exit_reason=1
completion.high_cardinality_overflow=false
completion.incomplete_pairs=0
all four drop counts zero
completion.drops.interrupted=false
single_run.accepted=true
```

The receipt is accepted only when:

```text
no preflight or exception reason
command status == 0 and timed_out == false
stdout has exactly one line equal to BUILD_OK
cleanup status == 0
cleanup descendants is empty
pre snapshot == post snapshot
summary contract passes
```

The receipt contains exact `inputs`, `argv`, `workload`, `provenance`,
`command`, `cleanup`, `summary`, `accepted`, `rejection_reasons`, and
`artifacts`. `summary` copies the loader's complete provenance/completion plus
the single-run accepted flag and failures; it is not a weaker replacement for
the bound JSONL. Its exact unavailable form is:

```python
{
    "available": False,
    "provenance": None,
    "completion": None,
    "accepted": False,
    "failures": [str(error)],
}
```

The available form sets `available=true`, copies `profile.provenance` and
`profile.completion`, and copies `single_run["accepted"]` plus its failures.
The failure string is the actual caught exception, not fixed wording. Bind all
seven non-receipt artifacts by absolute path, size, and SHA-256. Publish
`receipt.json` with a temporary fsynced file plus `os.link`; never use
`os.replace` for the final exclusive receipt.

Implement `parse_receipt(path)` and
`validate_receipt(receipt, *, require_accepted)` to re-check schema, duplicate
keys, directory confinement, exact artifact set, distinct paths, sizes,
hashes, fixed inputs, host/guest/summary run-ID equality, snapshots, command,
cleanup, loader-derived completion, and acceptance consistency. Receipt
validation reloads the bound profile through `load_profile`/`summarize` when
the capture claims acceptance. A rejected receipt is valid evidence when
`require_accepted=False`, but cannot feed analysis.

- [ ] **Step 10: Make receipt analysis the only new live analysis path**

Implement the CLI with subparsers:

```text
capture
  --repo PATH                 required
  --binary PATH               required
  --image STRING              default fixed image; any other value rejects
  --run-id STRING             required
  --artifact-dir PATH         required
  --timeout-seconds INTEGER   default 180; must be positive

analyze
  --receipt PATH              required exactly twice
  --output PATH               required and absent
```

`capture` returns zero only for an accepted receipt and one for a published
rejected receipt or collision. Argument errors return two. `analyze` returns
zero only after exclusive accepted output publication and one for evidence
rejection.

Implement:

```python
def analyze_receipts(
    receipt_paths: tuple[pathlib.Path, pathlib.Path],
    output: pathlib.Path,
) -> dict[str, object]:
```

Keep exact ancestry rows in each receipt and define a separate non-serialized
pair projection:

```python
@dataclasses.dataclass(frozen=True)
class AncestryProjectionRow:
    depth: int
    role: str
    parent_depth: int | None
    command: str


def project_ancestry(
    rows: tuple[ProcessRow, ...],
    *,
    run_id: str,
) -> tuple[AncestryProjectionRow, ...]:
    if len(rows) < 2:
        raise EvidenceError("process ancestry has no launcher")
    projected: list[AncestryProjectionRow] = []
    for depth, row in enumerate(rows):
        if depth == 0:
            role = "runner"
        elif depth == len(rows) - 1:
            role = "root"
        else:
            role = "ancestor"
        if depth + 1 < len(rows):
            parent = rows[depth + 1]
            if row.ppid != parent.pid:
                raise EvidenceError("process ancestry edge is broken")
            parent_depth: int | None = depth + 1
        else:
            if row.pid != 1 or row.ppid != 0:
                raise EvidenceError("process ancestry does not end at PID 1")
            parent_depth = None
        projected.append(
            AncestryProjectionRow(
                depth=depth,
                role=role,
                parent_depth=parent_depth,
                command=re.sub(
                    rf"(?<![A-Za-z0-9._-]){re.escape(run_id)}"
                    r"(?![A-Za-z0-9._-])",
                    "<RUN_ID>",
                    row.command,
                ),
            )
        )
    return tuple(projected)
```

Import `re` at module scope. The negative lookarounds make replacement
delimiter-bounded: a run ID is replaced only when neither adjacent character
belongs to the allowed run-ID alphabet `[A-Za-z0-9._-]`.

The projection intentionally omits literal `pid` and `ppid`. `depth`,
`parent_depth`, and ordered rows preserve chain length and edges; `role`
preserves runner/intermediate/root positions; the normalized command preserves
launch context. Do not remove other decimal strings or normalize arbitrary PID
text inside commands. Exact numeric ancestry remains receipt-bound and exact
within each run's pre/post equality.

Add two real receipt-pair tests using complete bound summary/artifact fixtures.
The accepting test uses:

```text
Run A:
310 210 python3 scripts/perf/native_kernel_capture.py capture --run-id native-kernel-stack-a-v1 --artifact-dir target/perf/native-kernel-stack-a-v1
210 10 zsh -lc python3 scripts/perf/native_kernel_capture.py capture --run-id native-kernel-stack-a-v1 --artifact-dir target/perf/native-kernel-stack-a-v1
10 1 /Applications/Codex.app/Contents/MacOS/Codex
1 0 /sbin/launchd

Run B:
511 411 python3 scripts/perf/native_kernel_capture.py capture --run-id native-kernel-stack-b-v1 --artifact-dir target/perf/native-kernel-stack-b-v1
411 12 zsh -lc python3 scripts/perf/native_kernel_capture.py capture --run-id native-kernel-stack-b-v1 --artifact-dir target/perf/native-kernel-stack-b-v1
12 1 /Applications/Codex.app/Contents/MacOS/Codex
1 0 /sbin/launchd
```

`test_analyze_accepts_different_pid_chains_with_equivalent_launch_projection`
must publish an accepted output: replacing each exact run ID yields equal
four-row projections despite different runner, shell, and Codex PIDs.

`test_project_ancestry_short_run_id_is_delimiter_bounded` uses `run_id="a"`
and command
`bash -lc 'capture --run-id a --artifact-dir target/perf/a'`. Assert the
projected command is exactly
`bash -lc 'capture --run-id <RUN_ID> --artifact-dir target/perf/<RUN_ID>'`;
in particular, the `a` inside `bash` remains unchanged.

For
`test_analyze_rejects_different_launcher_shape_or_command`, run two subcases:

```text
same four-row chain but Run B depth 1 command begins bash -lc instead of zsh -lc
Run B inserts /usr/bin/env between the runner and zsh, producing five rows
```

Both must return nonzero with `launch ancestry differs between receipts` and
leave an absent output absent. Use the real `analyze_receipts`,
`validate_receipt`, profile loader, and artifact hashing; do not assert only on
`project_ancestry` or a mock.

Validate both receipts with `require_accepted=True`; require distinct run IDs,
receipt paths, and artifact directories. Require equal pair determinants for
git commit, binary hash, host, image, and controlled environment after
replacing each exact run ID with `<RUN_ID>`. Compare
`project_ancestry(receipt_a.pre.process_ancestry, run_id=a)` with the B
projection; if they differ, raise
`EvidenceError("launch ancestry differs between receipts")`. Never compare raw
cross-run PID/PPID identity. Each receipt has already required exact raw
pre/post ancestry equality and an empty foreign census. Resolve only the two
receipt-bound `summary_jsonl` paths and the receipt-bound binary path. Call:

```python
artifact = native_wall_attribution.build_artifact(
    (summary_a, summary_b),
    binary,
    require_kernel_stacks=True,
)
```

Reject before receipt loading if `output` already exists, and never replace it.
Write `output` atomically and exclusively only after `build_artifact` returns
accepted. On any receipt or attribution rejection, return nonzero and leave a
previously absent output absent. The rejected capture receipts remain the
complete evidence; do not publish a second rejected-analysis format.

- [ ] **Step 11: Run GREEN runner gates**

Run:

```bash
python3 -m unittest scripts.perf.test_native_kernel_capture -v
python3 -m unittest scripts.perf.test_native_wall_attribution -v
python3 -m py_compile \
  scripts/perf/native_kernel_capture.py \
  scripts/perf/test_native_kernel_capture.py \
  scripts/perf/native_wall_attribution.py
git diff --check
```

Expected: all pass.

- [ ] **Step 12: Commit the runner**

Run:

```bash
git add \
  scripts/perf/native_kernel_capture.py \
  scripts/perf/test_native_kernel_capture.py \
  scripts/perf/README.md
git diff --cached --check
test "$(git diff --cached --name-only)" = \
"scripts/perf/README.md
scripts/perf/native_kernel_capture.py
scripts/perf/test_native_kernel_capture.py"
git commit -F - <<'EOF'
diagnostics(native): bind kernel profile receipts

Direct shell capture can lose status, cleanup, provenance, and rejected
evidence, making a natural-looking profile unsafe to promote.

Bind host and guest run IDs, exact cleanup, post-cleanup provenance, seven
single-use artifacts, ancestry-safe census, and receipt-only analysis without
sidecar helper APIs.

Verified with lifecycle, timeout, drift, summary, hash, collision, exact-run-ID,
ancestor/independent-runner, rejected-output, and two-receipt analysis tests.

Co-Authored-By: Codex <codex@openai.com>
EOF
```

Expected: the staged whitespace check passes, the exact three-path staged scope
matches, and this is the third commit after `PLAN_SHA`. The earlier plain
`git diff --check` does not substitute for this staged check because the two
new Python files were untracked before `git add`.

- [ ] **Step 13: Prove the three tooling commits transplant onto the clean base**

Run from the campaign worktree:

```bash
set -euo pipefail
TASK3_SHA=$(git rev-parse HEAD)
TASK2_SHA=$(git rev-parse HEAD^)
TASK1_SHA=$(git rev-parse HEAD^^)
PLAN_SHA=$(git rev-parse HEAD^^^)
test "$(git rev-parse "$PLAN_SHA^")" = \
  "7c98887c2bcdc6615be83ebaf2a0255994e519cf"

COMPAT_PARENT=$(mktemp -d /tmp/carrick-kernel-tooling-compat.XXXXXX)
COMPAT_PARENT=$(cd "$COMPAT_PARENT" && pwd -P)
COMPAT_WORKTREE="$COMPAT_PARENT/worktree"
cleanup_compat() {
  if git worktree list --porcelain | grep -Fqx "worktree $COMPAT_WORKTREE"; then
    git worktree remove --force "$COMPAT_WORKTREE"
  fi
  rmdir "$COMPAT_PARENT"
}
trap cleanup_compat EXIT

git worktree add --detach "$COMPAT_WORKTREE" \
  7131c12bde03991c0c913a527d6b6a727924daba
git -C "$COMPAT_WORKTREE" cherry-pick \
  "$TASK1_SHA" "$TASK2_SHA" "$TASK3_SHA"
(
  cd "$COMPAT_WORKTREE"
  python3 -m unittest \
    scripts.perf.test_native_wall_attribution \
    scripts.perf.test_native_kernel_capture -v
  cargo test -p carrick-cli --bin carrick trace_profile
  just fmt-check
  test -z "$(git status --porcelain=v1 --untracked-files=all)"
)
```

Expected: all tests pass inside the transplanted worktree and its status is
empty. Canonicalizing the temporary parent prevents macOS `/tmp` versus
`/private/tmp` spelling from bypassing the exact worktree-list match. The trap
removes only that canonical exact temporary worktree and parent. Record the
three printed/resolved 40-character SHAs for Task 4; these are the complete
later-worktree allowlist.

---

### Task 4: Capture two receipt-bound profiles and record measurement selection

**Files:**
- Modify after accepted or rejected measurement: `docs/perf-results/native-wall-time-campaign.md`
- Modify after accepted or rejected measurement: `handoff.md`

**Interfaces:**
- Consumes: only Task 3 `capture`/`analyze` commands and their immutable receipts. It does not invoke `carrick trace`, redirect capture stdout/stderr, call cleanup, read an unbound JSONL path, or duplicate the raw lifecycle.
- Produces: zero, one, or two published single-use receipt directories according to the conditional controller schema below and, only when both receipts plus attribution gates pass, `target/perf/native-kernel-stack-attribution-v1.json` plus its SHA-256.
- Produces: exactly one result outside the hypothesis backlog—`SELECTABLE_CANDIDATE_PACKAGE`, `KERNEL_FAMILY_SELECTION_DISCONFIRMED`, or `MEASUREMENT_REPAIR_REQUIRED`—and the literal three-commit transplant allowlist. No result creates, advances, defers, retains, or rejects H006; runtime code remains out of scope.

- [ ] **Step 1: Run structural and final source gates**

Run:

```bash
cargo test -p carrick-cli --bin carrick trace_profile
cargo test -p carrick-cli --test trace_profile
python3 -m unittest scripts.perf.test_native_wall_attribution -v
python3 -m unittest scripts.perf.test_native_kernel_capture -v
just fmt-check
git diff --check
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

Expected: all pass and the tree is clean.

- [ ] **Step 2: Build once and freeze exact source/binary provenance**

Run:

```bash
just build
codesign --verify --verbose=2 target/release/carrick
otool -l target/release/carrick | grep -A2 __dof_carrick
SOURCE_SHA=$(git rev-parse HEAD)
BINARY_SHA=$(shasum -a 256 target/release/carrick | awk '{print $1}')
TASK3_SHA=$(git rev-parse HEAD)
TASK2_SHA=$(git rev-parse HEAD^)
TASK1_SHA=$(git rev-parse HEAD^^)
PLAN_SHA=$(git rev-parse HEAD^^^)
printf 'SOURCE_SHA=%s\nBINARY_SHA=%s\n' "$SOURCE_SHA" "$BINARY_SHA"
printf 'ATTRIBUTION_SHAS=%s %s %s\n' \
  "$TASK1_SHA" "$TASK2_SHA" "$TASK3_SHA"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

Expected: codesign succeeds, `__dof_carrick` is present, all SHAs print, and
the tree is clean. Do not rebuild between captures.

- [ ] **Step 3: Verify all single-use outputs are absent**

Run:

```bash
NATIVE_KERNEL_COLLISION_FOUND=0
for path in \
  target/perf/native-kernel-stack-a-v1 \
  target/perf/native-kernel-stack-b-v1 \
  target/perf/native-kernel-stack-attribution-v1.json
do
  if test -e "$path"; then
    printf 'single-use evidence already exists: %s\n' "$path" >&2
    NATIVE_KERNEL_COLLISION_FOUND=1
  fi
done
test "$NATIVE_KERNEL_COLLISION_FOUND" -eq 0
```

Expected: success. The loop enumerates all three paths before its single
failure, so every collision is recorded independently. It does not read, hash,
or adopt any pre-existing bytes. Never delete or recycle one of these paths.
If any exists, stop after recording every reported collision before assigning
a new evidence version.

Use this conditional controller schema for both planned captures. The two
documents must record every field that is applicable and must omit every
field marked conditional:

```yaml
run_a_or_b:
  planned_artifact_directory: <fixed planned path>
  attempt_state: attempted | not-attempted | collision-before-directory
  capture_state: accepted | rejected | not-evaluated
  receipt:
    publication_state: published | not-produced
    # The next fields exist only when publication_state=published:
    path: <receipt path>
    sha256: <64 lowercase hex>
    bound_artifacts:
      <all seven names>: {path: <absolute path>, size: <integer>, sha256: <hex>}

analysis:
  attempt_state: attempted | not-attempted
  outcome: accepted | rejected | not-evaluated

derived_attribution:
  planned_path: target/perf/native-kernel-stack-attribution-v1.json
  production_state: produced | not-produced
  # sha256 exists only when production_state=produced
```

The transitions are exact:

- A preflight or runner collision sets that run's
  `attempt_state=collision-before-directory`,
  `capture_state=not-evaluated`, and `receipt.publication_state=not-produced`.
  Do not read, hash, or adopt any pre-existing path. If only A collides, B is
  `not-attempted`; if both planned run directories collide, both runs are
  `collision-before-directory`. If preflight finds only B's planned directory, B is
  `collision-before-directory` and A is `not-attempted`; if it finds only the
  derived path, both runs are `not-attempted` and the derived state is
  `not-produced` for this measurement. Record one literal
  `Preflight collision path: <path>` per path printed by Step 3; multiple
  collisions are recorded independently before stopping. A later runner
  collision has no preflight-collision line: an A runner collision leaves B
  `not-attempted`, while a B runner collision follows an accepted A.
- Invoking a capture sets `attempt_state=attempted`. A published receipt sets
  `capture_state` from its literal `accepted` boolean and requires receipt
  path/SHA-256 plus all seven bound path/size/SHA-256 records. An attempted
  command that violates Task 3 by publishing no receipt is
  `capture_state=rejected`, `publication_state=not-produced`, with the contract
  failure recorded and no invented path or hash.
- If A is rejected, B is
  `attempt_state=not-attempted`, `capture_state=not-evaluated`,
  `publication_state=not-produced`; its planned directory is recorded, but no
  B receipt path, SHA-256, or bound artifact field exists.
- Two-receipt fields may appear only after A is accepted and B is attempted;
  receipt-pair determinants and analysis fields may be evaluated only when both
  published receipts are accepted. A B collision has no B receipt/hash and no
  pair evaluation.
- `derived_attribution.production_state=not-produced` on every collision,
  capture rejection, receipt rejection, pair rejection, or analysis rejection.
  Never attach a SHA-256 to `not-produced`, and never adopt a pre-existing
  derived file. It is `produced` with a fresh SHA-256 only after accepted
  two-receipt analysis.

- [ ] **Step 4: Capture run A only through Task 3**

Run:

```bash
python3 scripts/perf/native_kernel_capture.py capture \
  --repo "$PWD" \
  --binary target/release/carrick \
  --image localhost:5005/carrick-go-conformance:1.24 \
  --run-id native-kernel-stack-a-v1 \
  --artifact-dir target/perf/native-kernel-stack-a-v1 \
  --timeout-seconds 180
```

Expected: status zero and
`target/perf/native-kernel-stack-a-v1/receipt.json` has `accepted=true`. If it
returns nonzero, do not run B. If the command published a receipt, preserve the
directory unchanged, record A as `attempted/rejected`, and record its receipt
hash, all bound artifacts, and rejection reasons. If it reports a directory
collision before publication, record A as `collision-before-directory` with no
receipt/hash. If it attempted a newly created directory but no receipt exists,
record A as `attempted/rejected` with a Task 3 receipt-contract failure and no
receipt/hash. In every nonzero case record B as `not-attempted/not-produced`
with its planned path and no SHA-256.

- [ ] **Step 5: Capture run B serially through Task 3**

Only after A's published receipt validates with `accepted=true`, and without
rebuilding or changing the tree, run:

```bash
python3 scripts/perf/native_kernel_capture.py capture \
  --repo "$PWD" \
  --binary target/release/carrick \
  --image localhost:5005/carrick-go-conformance:1.24 \
  --run-id native-kernel-stack-b-v1 \
  --artifact-dir target/perf/native-kernel-stack-b-v1 \
  --timeout-seconds 180
```

Expected: status zero and
`target/perf/native-kernel-stack-b-v1/receipt.json` has `accepted=true`. If it
returns nonzero, preserve every published directory unchanged. Record B as
`attempted/rejected` with its published receipt/hash/bound artifacts, or as
`collision-before-directory` with no receipt/hash; an attempted no-receipt
contract breach is rejected with no invented hash. A remains
`attempted/accepted`. Never run A and B concurrently.

- [ ] **Step 6: Analyze only the immutable receipts**

Only after both published receipts independently validate with
`accepted=true`, run:

```bash
python3 scripts/perf/native_kernel_capture.py analyze \
  --receipt target/perf/native-kernel-stack-a-v1/receipt.json \
  --receipt target/perf/native-kernel-stack-b-v1/receipt.json \
  --output target/perf/native-kernel-stack-attribution-v1.json
```

Expected on acceptance: status zero and one accepted output. The runner proves:

```text
both receipts and all bound hashes valid
same source, binary, host, image, and controlled environment
equivalent projected runner-to-root launch command chain despite nondeterministic PIDs
exact raw runner-to-root ancestry matched pre/post within each receipt
distinct exact run IDs and artifact directories
natural target exit, exact BUILD_OK, exact cleanup, no descendants
zero drops, no interruption, no incomplete pairs
kernel PC/stack count equality
100% kernel stack coverage by exact count equality
symbolized leaf count satisfies 100 * symbolized >= 95 * kernel samples
symbolized identical top leaf
all leaves satisfying exact 5% membership pass the exact 5pp cross-product delta
all normalized families satisfying exact 5% membership pass the exact 5pp cross-product delta
exact-Fraction cross-run top-10 ordering plus exact 10% selected-share and 60% coverage predicates
both exact kernel counts/totals are within 5pp of mean 552183490/1604036350
existing wall/CPU/category gates use exact count predicates
```

On acceptance, hash the exact ignored derived bytes without modifying them:

```bash
DERIVED_ATTRIBUTION=target/perf/native-kernel-stack-attribution-v1.json
test -f "$DERIVED_ATTRIBUTION"
DERIVED_ATTRIBUTION_SHA=$(
  shasum -a 256 "$DERIVED_ATTRIBUTION" | awk '{print $1}'
)
test "${#DERIVED_ATTRIBUTION_SHA}" -eq 64
case "$DERIVED_ATTRIBUTION_SHA" in
  *[!0-9a-f]*) exit 1 ;;
esac
printf 'DERIVED_ATTRIBUTION=%s\nDERIVED_ATTRIBUTION_SHA256=%s\n' \
  "$DERIVED_ATTRIBUTION" "$DERIVED_ATTRIBUTION_SHA"
```

Record the printed path and hash in both controller documents. On this or any
earlier rejection, if the current measurement's output path was absent at
preflight, it remains absent: record `production_state=not-produced`, retain
the planned path, and omit the SHA-256 field. If preflight instead found a
derived-path collision, leave those pre-existing bytes unadopted and unhashed,
record `production_state=not-produced`, retain the planned path, and omit the
SHA-256 field. Never hash a substitute or adopt a pre-existing file. Preserve
every published receipt and do not hand-run the analyzer against its JSONL
files.

- [ ] **Step 7: Read accepted decision fields and calculate CPU-work opportunity**

First require top-level `accepted=true`, `comparison.accepted=true`, and
`comparison.kernel_stack_family.selection_outcome` equal to exactly
`selectable` or `diffuse` in the accepted derived artifact. Also require the
exact consistent comparison-level `measurement_selection`: selectable maps
only to `SELECTABLE_CANDIDATE_PACKAGE`, diffuse maps only to
`KERNEL_FAMILY_SELECTION_DISCONFIRMED`, and
`hypothesis_ledger_mutation` is `none`. Reject an artifact containing a
hypothesis ID/status or an inconsistent mapping. Do not reconstruct top-10
membership, coverage, a selected family, or any causal result from receipt
summaries, raw `top_stacks`, per-run `top_frames`, or either run alone.

For `selection_outcome="selectable"`, require
`measurement_selection.result="SELECTABLE_CANDIDATE_PACKAGE"`, require
non-null `selected_family`, and, for each accepted run, consume its emitted
`samples`, `shares`, `leaf_samples`, and `leaf_shares` arrays. Record:

```text
kernel_cpu_seconds = kernel.samples / 499
selected_family_cpu_seconds = selected_family.samples[run] / 499
selected_leaf_cpu_seconds = selected_family.leaf_samples[run] / 499
```

Also calculate this optional baseline-normalized diagnostic proxy:

```text
C0_seconds = 19.375
baseline_normalized_selected_cpu_seconds =
    C0_seconds
    * average_cpu_parallelism
    * darwin_kernel_share
    * selected_family.leaf_shares[run]
```

The accepted earlier pair had `average_cpu_parallelism` 2.3158423136879414 and
2.3398933525138266, so neither formula is a single-CPU wall ceiling.
`selected_family_cpu_seconds` and `selected_leaf_cpu_seconds` are sampled
CPU-work opportunities. The normalized value answers only “how much selected
leaf CPU work would scale to a `C0`-length run at traced parallelism?” It is not
critical-path overlap, recoverable wall time, or a reason by itself to retain
or reject a mechanism.

For `selection_outcome="diffuse"`, require
`measurement_selection.result="KERNEL_FAMILY_SELECTION_DISCONFIRMED"`. There
is no authorized selected CPU opportunity: record the emitted
stable-membership rows, coverage, and ordered selection reasons, and record
selected family/leaf CPU opportunity as `not evaluated`, never zero and never
an executor-selected fallback.

- [ ] **Step 8: Record the exact measurement-selection result**

Write exactly one of these records in a dedicated measurement-selection
section in both controller documents, outside the hypothesis backlog.

Rejected receipt, pair, or attribution evidence:

```text
Measurement-selection result: MEASUREMENT_REPAIR_REQUIRED
Measurement evidence state: rejected
Kernel-family selection question: not evaluated
Candidate package: not evaluated
Hypothesis-ledger mutation: none
H006: not created
Next gate: repair the rejected measurement before any causal design
```

This includes zero kernel samples, an unresolved top leaf, capture collision,
receipt-contract failure, or any other rejection. Preserve every published
receipt, leave the derived output `not-produced`, and quote only actual
rejection evidence.

Accepted diffuse evidence:

```text
Measurement-selection result: KERNEL_FAMILY_SELECTION_DISCONFIRMED
Measurement evidence state: accepted
Kernel-family selection question: disconfirmed by emitted stable-but-diffuse reasons
Candidate package: not selected
Hypothesis-ledger mutation: none
H006: not created
Next gate: translated-guest instruction-mix measurement
```

Quote only emitted `selection_reasons`, members, exact counts/totals, and
coverage diagnostics. This disconfirms the kernel-family *selection question*,
not a causal mechanism. Do not implement a kernel-path optimization.

Accepted selectable evidence:

```text
Measurement-selection result: SELECTABLE_CANDIDATE_PACKAGE
Measurement evidence state: accepted
Kernel-family selection question: selectable
Candidate package: emitted selected family, leaf, counts, and CPU-work observations
Candidate package state: awaiting a separate approved causal design
Causal claim: none
Hypothesis-ledger mutation: none
H006: not created
Next gate: write and obtain approval for a separate causal mechanism design
```

Name only the emitted `selected_family.leaf` and
`selected_family.frames`; record raw and baseline-normalized CPU-work
observations with the explicit non-wall qualification. A stack family is an
observation, not a causal hypothesis.

No other input or outcome may change those records. In particular, Task 4 does
not inspect per-run top-10 lists to override `selection_outcome`, choose a
different member, infer causality from a symbol, apply a 3%-of-`C0` cutoff, or
create/update an H006 row.

Only a later separate causal-mechanism design may create H006. Before H006
enters the hypothesis backlog, that design must supply one complete ledger row
with every governing-spec field:

```text
observation and receipt-bound evidence
measured share or exact event count
calculated upper-bound wall-time win if the cost vanished
proposed structural host mechanism
bounded spike, variant/time bound, and stop condition
correctness risks and the focused proof that covers them
mechanism-specific traced diagnostic counter/direction and result field
untraced alternating-screen and five-plus-five promotion result fields
status: PROPOSED | SPIKING | RETAIN | REJECT | DEFER
```

If the candidate package cannot support a defensible calculated wall-time
upper bound, H006 remains uncreated. Gather receipt-bound critical-path or
other bound evidence first; a non-wall CPU-work observation is not an escape
from the governing ledger requirement.

The row is created as `PROPOSED`; pending diagnostic/screen result fields say
`not run` rather than zero. It moves to `SPIKING` only after the separate design
is explicitly approved. Measurement acceptance alone cannot make that
transition.

That later approved design must use this exact evaluation sequence:

1. **Mechanism design and approval.** Create the complete `PROPOSED` H006 row,
   predeclare one structural mechanism, counter movement, wall-time direction,
   variant/time bound, stop conditions, risks, and proof. Pin a clean worktree
   at `7131c12bde03991c0c913a527d6b6a727924daba`, cherry-pick only the literal
   Task 1/2/3 SHAs recorded here after their transplant gate, obtain design
   approval, and only then mark H006 `SPIKING`.
2. **Focused proof.** Add and run the smallest focused red/green correctness
   proof for the mechanism. A missing red or green result stops the spike.
3. **Receipt-bound traced control/spike.** Run the predeclared
   mechanism-specific traced control and spike through immutable receipts.
   Proceed only when the counter and selected-leaf sampled CPU work move in
   their predeclared directions; traced elapsed time is ignored.
4. **One candidate feasibility run for correctness only.** Run exactly one
   clean candidate feasibility sample to prove the workload and marker. Its
   elapsed time is not a performance screen, may not be compared with frozen
   `C0`, and cannot promote or retain the candidate.
5. **Contemporaneous alternating untraced screen.** On an accepted idle-host
   preflight, run exactly `control-1`, `candidate-1`, `control-2`,
   `candidate-2`, serially and untraced. Apply only the screening
   direction/credible-signal rule predeclared by the approved design. No
   frozen-`C0` comparison has promotion authority.
6. **Five control plus five candidate retention campaign.** Only a credible
   alternating screen may promote to five untraced control and five untraced
   candidate samples. Retention requires candidate/control median ratio
   `<=0.97`, bootstrap 95% upper bound `<1.0`, and every guardrail below. Only
   these contemporaneous untraced measurements can prove a wall-time win.

No candidate is retained until every governing retained-wave guardrail passes:

- focused red/green tests for the changed mechanism;
- a signed native AArch64 runtime demo that compiles and runs the Go marker;
- `just conformance-native smoke --workers 4`;
- explicit review of `go-sync`, `cpython-threading`, and
  `cpython-subprocess` results;
- an untraced Node V8 and CPython guardrail when the change touches translated
  execution, fork/exec, signals, atomics, or shared cache authority;
- `just ci`;
- clean DOF presence and scoped process cleanup.

- [ ] **Step 9: Run the full local gate before documenting**

Run:

```bash
just ci
```

Expected: the complete local gate passes. Record the command, source SHA, and
result in both controller documents. If it fails, do not claim the measurement
milestone closed.

- [ ] **Step 10: Update controller evidence**

In `docs/perf-results/native-wall-time-campaign.md` and `handoff.md`, record:

```text
dedicated native-kernel measurement-selection section bounded by:
  <!-- native-kernel-selection:start -->
  <!-- native-kernel-selection:end -->
exactly one `Preflight collision state: clear | collided`; when collided, one
  `Preflight collision path: <fixed planned path>` for every path Step 3
  reported, with no duplicates; when clear, no collision-path line
both planned A/B directories plus these literal conditional lines:
  Run A planned artifact directory: target/perf/native-kernel-stack-a-v1
  Run A attempt state: attempted | not-attempted | collision-before-directory
  Run A capture state: accepted | rejected | not-evaluated
  Run A receipt publication state: published | not-produced
  Run B planned artifact directory: target/perf/native-kernel-stack-b-v1
  Run B attempt state: attempted | not-attempted | collision-before-directory
  Run B capture state: accepted | rejected | not-evaluated
  Run B receipt publication state: published | not-produced
for each published Run X receipt, exactly one:
  Run X receipt path: target/perf/native-kernel-stack-{a|b}-v1/receipt.json
  Run X receipt SHA-256: <64 lowercase hex>
  Run X bound artifact count: 7
and exactly one record for each of trace.raw, summary.jsonl, stdout.log, stderr.log, command-status.json, cleanup.stdout.log, and cleanup.stderr.log:
  Run X bound artifact <name>: path=<absolute path>; size=<integer>; sha256=<64 lowercase hex>
no receipt/hash/bound-artifact fields for not-attempted, collision-before-directory, or attempted-no-receipt states
only when both receipts are accepted, exactly one each:
  Receipt-pair determinant state: matched | rejected
  Pair comparison state: accepted | rejected | not-evaluated
omit both receipt-pair lines unless both receipts are accepted; `rejected` determinant requires pair comparison `not-evaluated`
always include exactly one each:
  Analysis attempt state: attempted | not-attempted
  Analysis outcome: accepted | rejected | not-evaluated
  Derived attribution planned path: target/perf/native-kernel-stack-attribution-v1.json
  Derived attribution production state: produced | not-produced
derived SHA-256 only when production_state=produced; not-produced on every rejection path
analyzer source SHA (the literal Task 2 commit), binary, host, fixed image, and command provenance
for each published receipt: exact raw ancestry pre/post equality, host/guest run ID, timeout, command status, BUILD_OK count, cleanup status/log hashes, descendants, completion/drop state, and reconciliation
for an accepted pair only: equivalent projected ancestry plus exact normalized family definition, member ranks/counts/diagnostic shares, exact-rational ordering, deltas, stable samples/coverage, and selection fields
for accepted analysis only: emitted candidate family/leaf or diffuse reasons, top stacks/leaves, and symbolized-leaf coverage
accepted-baseline exact counts 9750/28255 and 9748/28385, mean fraction 552183490/1604036350, 5pp cross-product threshold, and new-run exact counts/deltas
accepted baseline profile producer 688357ef6b72b299daf5990d494fff7d1a7a7805 and artifact acceptance commit 34ce4c3c40bec2bd408612efcba66226fa2793f9
for SELECTABLE_CANDIDATE_PACKAGE only: raw selected family and leaf samples / 499 CPU seconds plus baseline-normalized diagnostic CPU opportunity for each run
explicit statement that neither CPU-work observation is a wall ceiling
the exact applicable measurement-selection record from Step 8, outside the hypothesis backlog
explicit statement that the hypothesis backlog is unchanged and H006 was not created
the later separate-design ledger schema, approval boundary, alternating screen, retention thresholds, and complete retained-wave guardrails
literal Task 1/2/3 40-character transplant SHAs and base 7131c12b...
final just ci receipt
```

If capture or analysis rejected, record only fields actually measured by each
published receipt and use `not evaluated` for downstream evidence, never zero.
Record the derived planned path with `production_state=not-produced` and omit
its SHA field. If analysis is accepted, both documents must contain the exact
derived path and freshly printed SHA-256 even though the file is ignored.
Also correct the stale handoff claim that every AArch64 return exits: the
current default has a two-way 32,768-set indirect target cache.

After editing both documents, set `RESULT` to the one actual literal result and
run this controller-output test. The mapping contains assertions for all three
legal outputs; the chosen branch must appear exactly once in each bounded
section:

```bash
RESULT=SELECTABLE_CANDIDATE_PACKAGE python3 - <<'PY'
import os
import pathlib
import re

result = os.environ["RESULT"]
expected = {
    "SELECTABLE_CANDIDATE_PACKAGE": (
        "Measurement-selection result: SELECTABLE_CANDIDATE_PACKAGE",
        "Measurement evidence state: accepted",
        "Kernel-family selection question: selectable",
        "Candidate package: emitted selected family, leaf, counts, and CPU-work observations",
        "Candidate package state: awaiting a separate approved causal design",
        "Causal claim: none",
        "Hypothesis-ledger mutation: none",
        "H006: not created",
        "Next gate: write and obtain approval for a separate causal mechanism design",
    ),
    "KERNEL_FAMILY_SELECTION_DISCONFIRMED": (
        "Measurement-selection result: KERNEL_FAMILY_SELECTION_DISCONFIRMED",
        "Measurement evidence state: accepted",
        "Kernel-family selection question: disconfirmed by emitted stable-but-diffuse reasons",
        "Candidate package: not selected",
        "Hypothesis-ledger mutation: none",
        "H006: not created",
        "Next gate: translated-guest instruction-mix measurement",
    ),
    "MEASUREMENT_REPAIR_REQUIRED": (
        "Measurement-selection result: MEASUREMENT_REPAIR_REQUIRED",
        "Measurement evidence state: rejected",
        "Kernel-family selection question: not evaluated",
        "Candidate package: not evaluated",
        "Hypothesis-ledger mutation: none",
        "H006: not created",
        "Next gate: repair the rejected measurement before any causal design",
    ),
}
if result not in expected:
    raise SystemExit(f"invalid RESULT={result!r}")

paths = (
    pathlib.Path("docs/perf-results/native-wall-time-campaign.md"),
    pathlib.Path("handoff.md"),
)
artifact_names = (
    "trace.raw",
    "summary.jsonl",
    "stdout.log",
    "stderr.log",
    "command-status.json",
    "cleanup.stdout.log",
    "cleanup.stderr.log",
)
planned_directories = {
    "A": "target/perf/native-kernel-stack-a-v1",
    "B": "target/perf/native-kernel-stack-b-v1",
}
derived_planned_path = "target/perf/native-kernel-stack-attribution-v1.json"
allowed_collision_paths = frozenset(
    (*planned_directories.values(), derived_planned_path)
)


def exact_line_count(section, line):
    return len(re.findall(rf"^{re.escape(line)}$", section, re.MULTILINE))


for path in paths:
    text = path.read_text()
    start = "<!-- native-kernel-selection:start -->"
    end = "<!-- native-kernel-selection:end -->"
    if text.count(start) != 1 or text.count(end) != 1:
        raise SystemExit(f"{path}: selection markers are not unique")
    section = text.split(start, 1)[1].split(end, 1)[0]
    for line in expected[result]:
        if exact_line_count(section, line) != 1:
            raise SystemExit(f"{path}: expected once: {line}")
    outcome_labels = {
        line.split(":", 1)[0]
        for outcome_lines in expected.values()
        for line in outcome_lines
    }
    chosen_lines_by_label = {
        line.split(":", 1)[0]: line for line in expected[result]
    }
    for label in outcome_labels:
        actual_lines = re.findall(
            rf"^{re.escape(label)}:.*$", section, re.MULTILINE
        )
        wanted_lines = (
            [chosen_lines_by_label[label]]
            if label in chosen_lines_by_label
            else []
        )
        if actual_lines != wanted_lines:
            raise SystemExit(
                f"{path}: {label} records {actual_lines!r}, "
                f"expected {wanted_lines!r}"
            )
    present = [
        name
        for name in expected
        if exact_line_count(section, f"Measurement-selection result: {name}")
    ]
    if present != [result]:
        raise SystemExit(f"{path}: result set {present!r}")

    def field(label, choices):
        choice_pattern = "|".join(re.escape(choice) for choice in choices)
        all_lines = re.findall(
            rf"^{re.escape(label)}:.*$", section, re.MULTILINE
        )
        matches = re.findall(
            rf"^{re.escape(label)}: ({choice_pattern})$",
            section,
            re.MULTILINE,
        )
        if len(all_lines) != 1 or len(matches) != 1:
            raise SystemExit(
                f"{path}: {label} has {len(all_lines)} total/"
                f"{len(matches)} canonical lines"
            )
        return matches[0]

    preflight_state = field("Preflight collision state", ("clear", "collided"))
    collision_paths = re.findall(
        r"^Preflight collision path: (.+)$", section, re.MULTILINE
    )
    if (
        len(collision_paths) != len(set(collision_paths))
        or any(item not in allowed_collision_paths for item in collision_paths)
    ):
        raise SystemExit(f"{path}: invalid or duplicate preflight collision path")
    if preflight_state == "clear" and collision_paths:
        raise SystemExit(f"{path}: clear preflight has collision paths")
    if preflight_state == "collided" and not collision_paths:
        raise SystemExit(f"{path}: collided preflight has no collision path")

    run_states = {}
    for run in ("A", "B"):
        planned = planned_directories[run]
        planned_label = f"Run {run} planned artifact directory"
        planned_lines = re.findall(
            rf"^{re.escape(planned_label)}:.*$", section, re.MULTILINE
        )
        if (
            len(planned_lines) != 1
            or exact_line_count(section, f"{planned_label}: {planned}") != 1
        ):
            raise SystemExit(f"{path}: Run {run} planned directory")
        attempt = field(
            f"Run {run} attempt state",
            ("attempted", "not-attempted", "collision-before-directory"),
        )
        capture = field(
            f"Run {run} capture state",
            ("accepted", "rejected", "not-evaluated"),
        )
        publication = field(
            f"Run {run} receipt publication state",
            ("published", "not-produced"),
        )
        run_states[run] = (attempt, capture, publication)

        conditional_lines = re.findall(
            rf"^Run {run} (?:receipt path|receipt SHA-256|"
            r"bound artifact count|bound artifact ).*$",
            section,
            re.MULTILINE,
        )
        receipt_path = re.findall(
            rf"^Run {run} receipt path: {re.escape(planned)}/receipt\.json$",
            section,
            re.MULTILINE,
        )
        receipt_sha = re.findall(
            rf"^Run {run} receipt SHA-256: [0-9a-f]{{64}}$",
            section,
            re.MULTILINE,
        )
        bound_count = exact_line_count(
            section, f"Run {run} bound artifact count: 7"
        )
        name_pattern = "|".join(re.escape(name) for name in artifact_names)
        artifact_rows = re.findall(
            rf"^Run {run} bound artifact ({name_pattern}): "
            r"path=(/[^;\n]+); size=(0|[1-9][0-9]*); "
            r"sha256=([0-9a-f]{64})$",
            section,
            re.MULTILINE,
        )

        if publication == "published":
            if attempt != "attempted" or capture not in {"accepted", "rejected"}:
                raise SystemExit(f"{path}: Run {run} published-state mismatch")
            if len(receipt_path) != 1 or len(receipt_sha) != 1:
                raise SystemExit(f"{path}: Run {run} receipt path/hash")
            if bound_count != 1:
                raise SystemExit(f"{path}: Run {run} bound artifact count")
            if sorted(row[0] for row in artifact_rows) != sorted(artifact_names):
                raise SystemExit(f"{path}: Run {run} seven bound artifacts")
            if len(conditional_lines) != 10:
                raise SystemExit(f"{path}: Run {run} stale conditional receipt line")
        else:
            if conditional_lines:
                raise SystemExit(f"{path}: Run {run} stale unproduced receipt field")
            if attempt == "attempted" and capture != "rejected":
                raise SystemExit(f"{path}: Run {run} attempted no-receipt mismatch")
            if attempt != "attempted" and capture != "not-evaluated":
                raise SystemExit(f"{path}: Run {run} unevaluated mismatch")

    a_accepted = run_states["A"] == ("attempted", "accepted", "published")
    b_accepted = run_states["B"] == ("attempted", "accepted", "published")
    both_accepted = a_accepted and b_accepted
    if preflight_state == "collided":
        for run in ("A", "B"):
            expected_attempt = (
                "collision-before-directory"
                if planned_directories[run] in collision_paths
                else "not-attempted"
            )
            if run_states[run][0] != expected_attempt:
                raise SystemExit(f"{path}: Run {run} preflight collision state")
    elif run_states["A"][0] == "not-attempted":
        raise SystemExit(f"{path}: clear preflight must attempt A")
    if not a_accepted and run_states["B"][0] == "attempted":
        raise SystemExit(f"{path}: B attempted without accepted A")
    if (
        preflight_state == "clear"
        and run_states["A"][0] == "collision-before-directory"
        and run_states["B"][0] != "not-attempted"
    ):
        raise SystemExit(f"{path}: A runner collision must stop B")
    if run_states["A"][1] == "rejected" and run_states["B"][0] != "not-attempted":
        raise SystemExit(f"{path}: rejected A must leave B not attempted")
    if a_accepted and run_states["B"][0] == "not-attempted":
        raise SystemExit(f"{path}: accepted A must attempt B or record B collision")

    pair_determinant_lines = re.findall(
        r"^Receipt-pair determinant state: (matched|rejected)$",
        section,
        re.MULTILINE,
    )
    pair_comparison_lines = re.findall(
        r"^Pair comparison state: (accepted|rejected|not-evaluated)$",
        section,
        re.MULTILINE,
    )
    all_pair_determinant_lines = re.findall(
        r"^Receipt-pair determinant state:.*$", section, re.MULTILINE
    )
    all_pair_comparison_lines = re.findall(
        r"^Pair comparison state:.*$", section, re.MULTILINE
    )
    analysis_attempt = field(
        "Analysis attempt state", ("attempted", "not-attempted")
    )
    analysis_outcome = field(
        "Analysis outcome", ("accepted", "rejected", "not-evaluated")
    )
    if both_accepted:
        if (
            len(all_pair_determinant_lines) != 1
            or len(pair_determinant_lines) != 1
            or len(all_pair_comparison_lines) != 1
            or len(pair_comparison_lines) != 1
        ):
            raise SystemExit(f"{path}: accepted receipts require pair states")
        determinant = pair_determinant_lines[0]
        comparison = pair_comparison_lines[0]
        if analysis_attempt != "attempted":
            raise SystemExit(f"{path}: accepted receipts require analysis attempt")
        if determinant == "rejected":
            if comparison != "not-evaluated" or analysis_outcome != "rejected":
                raise SystemExit(f"{path}: rejected determinant transition")
        elif comparison == "accepted":
            if analysis_outcome != "accepted":
                raise SystemExit(f"{path}: accepted comparison transition")
        elif comparison == "rejected":
            if analysis_outcome != "rejected":
                raise SystemExit(f"{path}: rejected comparison transition")
        else:
            raise SystemExit(f"{path}: matched determinant must compare")
    else:
        if all_pair_determinant_lines or all_pair_comparison_lines:
            raise SystemExit(f"{path}: pair states without two accepted receipts")
        if analysis_attempt != "not-attempted" or analysis_outcome != "not-evaluated":
            raise SystemExit(f"{path}: unevaluated analysis transition")

    derived_path = f"Derived attribution planned path: {derived_planned_path}"
    all_derived_path_lines = re.findall(
        r"^Derived attribution planned path:.*$", section, re.MULTILINE
    )
    if len(all_derived_path_lines) != 1 or exact_line_count(section, derived_path) != 1:
        raise SystemExit(f"{path}: derived planned path")
    production = field(
        "Derived attribution production state", ("produced", "not-produced")
    )
    derived_hash_lines = re.findall(
        r"^Derived attribution SHA-256:.*$",
        section,
        re.MULTILINE,
    )
    valid_derived_hashes = re.findall(
        r"^Derived attribution SHA-256: [0-9a-f]{64}$",
        section,
        re.MULTILINE,
    )
    if production == "produced":
        if len(derived_hash_lines) != 1 or len(valid_derived_hashes) != 1:
            raise SystemExit(f"{path}: produced derived hash")
    elif derived_hash_lines:
        raise SystemExit(f"{path}: stale not-produced derived hash")
    if preflight_state == "collided" and production != "not-produced":
        raise SystemExit(f"{path}: collided preflight produced derived output")

    if result == "MEASUREMENT_REPAIR_REQUIRED":
        if analysis_outcome == "accepted" or production != "not-produced":
            raise SystemExit(f"{path}: rejected result transition")
    else:
        if not both_accepted:
            raise SystemExit(f"{path}: accepted result requires both receipts")
        if (
            pair_determinant_lines != ["matched"]
            or pair_comparison_lines != ["accepted"]
            or analysis_outcome != "accepted"
            or production != "produced"
        ):
            raise SystemExit(f"{path}: accepted result transition")

ledger = paths[0].read_text()
backlog = ledger.split("## Hypothesis backlog", 1)[1]
backlog = backlog.split("\n## ", 1)[0]
if re.search(r"^\| H006 \|", backlog, re.MULTILINE):
    raise SystemExit("H006 must not exist in the hypothesis backlog")
PY
```

For diffuse or rejected evidence, change only the shell `RESULT=` value to its
literal enum. Expected: the script exits zero. These are the literal controller
tests for selectable, diffuse, and rejected measurement results; none can pass
with an H006 backlog row.

- [ ] **Step 11: Check docs and commit the measurement record**

Run:

```bash
just fmt-check
git diff --check
git status --short
git add docs/perf-results/native-wall-time-campaign.md handoff.md
git diff --cached --check
git commit -F - <<'EOF'
docs(perf): record kernel stack selection

The accepted native-wall pair leaves Darwin kernel CPU undifferentiated, so a
host mechanism cannot be selected from CPU-category shares alone.

Record receipt-bound replicated kernel stack families, accepted-baseline drift,
sampled CPU-work observations, and an exact measurement-selection result
without creating a causal hypothesis.

Verified with two exact-run-ID receipts, receipt-only attribution, and the full
local `just ci` gate. Traced elapsed time is not a performance result and H006
was not created.

Co-Authored-By: Codex <codex@openai.com>
EOF
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

For a rejected measurement, replace only the `git commit` command above with:

```bash
git commit -F - <<'EOF'
docs(perf): record kernel attribution rejection

The planned receipt-bound native-wall measurement failed before or during its
collision, completeness, cleanup, provenance, stack, symbolization, stability,
or baseline-drift gate.

Preserve every published receipt and hash, leave downstream CPU opportunity
unevaluated, record `MEASUREMENT_REPAIR_REQUIRED`, and leave H006 absent.

Verified with the applicable immutable published receipts, conditional
controller-output test, and full local `just ci` gate. Traced elapsed time is
not a performance result.

Co-Authored-By: Codex <codex@openai.com>
EOF
```

Use the accepted template for either accepted `selectable` or accepted
`diffuse` analysis, with the actual emitted measurement-selection result
recorded outside the hypothesis backlog. Use the rejected template only for
rejected evidence, including zero/unresolved required-live evidence or a
collision with no receipt. Expected: the staged whitespace check passes,
commit succeeds, and the tracked/untracked status is empty.

---

## Plan Self-Review Checklist

- [ ] The reviewed plan is committed before any tooling source change.
- [ ] Kernel PC and stack counts come from the same `profile-499` firing.
- [ ] New count-valued stacks do not change voluntary duration rows.
- [ ] Rust and Python reject malformed and zero-valued units, both serialized kernel `pid` locations, and count mismatches.
- [ ] Historical absent-kernel-stack and zero-kernel cases have explicit non-dividing behavior.
- [ ] The selected leaf is `frames[0]`, must itself be symbolized, and never borrows a caller symbol.
- [ ] Required-live zero samples and an unresolved top leaf reject the artifact as `MEASUREMENT_REPAIR_REQUIRED`; no later rule reinterprets them.
- [ ] Stack families strip only terminal `+0xHEX`, preserve ordered first-four-frame identity, compare all exact at-least-5% families, and emit deterministic top-10 membership, coverage, selection, thresholds, and reasons.
- [ ] Every decision-bearing ratio/delta uses counts and cross multiplication, exact family ordering uses `Fraction`, and floats are emitted diagnostics only.
- [ ] Literal tests cover hostile exact `40/100` versus `35/100`, just-over-five, exact/just-below 5% membership, independent 10%/60% failures, the conjunction, exact baseline drift, and float-tied family ordering.
- [ ] New pair stability uses accepted counts `9750/28255` and `9748/28385`, exact mean `552183490/1604036350`, and the exact 5pp predicate while distinguishing profile producer `688357ef...` from artifact acceptance `34ce4c3c...`.
- [ ] Task 4 records only `SELECTABLE_CANDIDATE_PACKAGE`, `KERNEL_FAMILY_SELECTION_DISCONFIRMED`, or `MEASUREMENT_REPAIR_REQUIRED` outside the hypothesis backlog; all leave H006 absent.
- [ ] Only a later separate approved design may create a complete H006 row as `PROPOSED`, and only approval may move it to `SPIKING`.
- [ ] Task 3 owns timeout, status, stdout/stderr, finally cleanup, exact descendant census, post-cleanup provenance, hashes, and immutable accepted/rejected receipts.
- [ ] Task 3 bootstrap and behavior RED runs are assertion failures, never accepted import/discovery errors.
- [ ] Task 3 stages exactly its two new Python files plus `scripts/perf/README.md` and runs `git diff --cached --check` before commit.
- [ ] Run IDs match only `[A-Za-z0-9._-]{1,96}`, reject `--all`, and have literal backslash, shell/control, and non-ASCII rejection tests before subprocess launch.
- [ ] The general census excludes the runner's complete same-snapshot ancestry but still rejects an independent concurrent runner; the narrow cleanup census hides no ancestor.
- [ ] Each receipt binds exact raw ancestry with exact pre/post equality; A/B compares only depth, role, parent-depth, and normalized-command projections, never numeric PID identity.
- [ ] Task 4 invokes no raw `carrick trace`, shell redirection, cleanup, or unbound JSONL analysis.
- [ ] Every evidence path is single-use and every cleanup uses one exact run ID.
- [ ] Every planned A/B run records attempted/not-attempted/collision and accepted/rejected/not-evaluated state; only attempted published receipts carry receipt and bound-artifact hashes.
- [ ] If A rejects, B is not attempted with no receipt/hash; two-receipt fields exist only after A succeeds and B is attempted.
- [ ] Both controller documents record the derived planned path in every branch, a SHA-256 only on production, and `not-produced` on every rejection path.
- [ ] The runner depends only on `native_go_build.guest_script()` and passes a real cherry-pick/test gate on `7131c12b`.
- [ ] Every compatibility Python, Cargo, formatting, and cleanliness proof runs inside a subshell after `cd "$COMPAT_WORKTREE"`; no compatibility test command escapes to the campaign worktree.
- [ ] Selectable CPU opportunities use emitted family samples / 499 and aggregate leaf samples / 499; the optional `C0 * parallelism * kernel share * leaf share` value is explicitly not a wall bound.
- [ ] The later sequence is approved mechanism design, focused red/green proof, receipt-bound traced control/spike, one correctness-only candidate feasibility run, alternating untraced C1/K1/C2/K2, then five control plus five candidate.
- [ ] No frozen-`C0` comparison can promote a candidate; retention requires median ratio `<=0.97`, bootstrap upper `<1.0`, and every governing focused/demo/native-smoke/review/Node-CPython/CI/DOF/cleanup guardrail.
- [ ] No guest runtime optimization, cache-size change, sidecar experiment import, or baseline re-bless is included.
- [ ] Final verification uses `just fmt-check`, `git diff --check`, staged checks for new files, the literal controller-output test, and `just ci`.
