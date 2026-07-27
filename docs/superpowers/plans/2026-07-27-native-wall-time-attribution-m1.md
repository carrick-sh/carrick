# Native Wall-Time Attribution M1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a fresh paired cold-Go-build baseline and two reconciled,
whole-process-tree DTrace attributions that select the first bounded
optimization spike.

**Architecture:** Extend the existing Python workload runner so Carrick and
native-arm64 Docker execute the identical cold-cache script in separate phases.
Add a built-in `native-wall` DTrace profile so libdtrace drop status, target
completion, provenance, process-tree state, sampled PCs, and off-CPU callsites
flow through Carrick's fail-closed JSONL publisher. A focused Python summarizer
classifies the PC rows, enforces reconciliation thresholds, compares two runs,
and emits the campaign evidence consumed by the ledger.

**Tech Stack:** Rust/clap/serde, libdtrace D language, Python 3 standard library,
Darwin `atos`/`otool`, Docker, Carrick's signed native AArch64 runner.

## Global Constraints

- Scope is Darwin/AArch64 `--exec-backend native` only.
- The primary workload is `scripts/perf/native_go_build.py` with a unique empty
  `GOCACHE` per sample.
- Carrick and Docker never run concurrently.
- Untraced five-sample medians are the only wall-time authority.
- DTrace timing is diagnostic; sampling proportions and exact counts select
  work.
- The trace population is seeded by `$target` and extended by process creation;
  `execname == "carrick"` is not a scope boundary.
- Wall-state occupancy, CPU resource shares, and off-CPU resource time remain
  separate quantities.
- No high-frequency phase bracketing is introduced.
- No Linux kernel or other GPL implementation source is consulted.
- Every run has a unique `CARRICK_RUN_ID` and cleanup uses only
  `scripts/sudo/kill.sh <run-id>`.

---

### Task 1: Paired Carrick and Docker benchmark runner

**Files:**
- Modify: `scripts/perf/native_go_build.py`
- Modify: `scripts/perf/test_native_go_build.py`

**Interfaces:**
- Produces:
  `build_command(repo: pathlib.Path, engine: str, run_id: str) -> list[str]`,
  `run_phase(repo: pathlib.Path, engine: str, samples: int,
  timeout_seconds: int) -> list[dict[str, object]]`, and schema
  `carrick.native-go-build.v2`.
- The JSON object contains `phases.carrick`, `phases.docker`, each phase's
  ordered samples and median, plus `ratio.carrick_over_docker`.
- Preserves `build_carrick_command()` as a compatibility wrapper for existing
  callers.

- [x] **Step 1: Add red tests for identical guest scripts and separate engines**

Add these tests to `scripts/perf/test_native_go_build.py`:

```python
    def test_carrick_and_docker_use_identical_guest_script(self):
        repo = pathlib.Path("/repo")
        carrick = native_go_build.build_command(repo, "carrick", "run-c")
        docker = native_go_build.build_command(repo, "docker", "run-d")
        self.assertEqual(carrick[-1], docker[-1])
        self.assertIn("--exec-backend", carrick)
        self.assertIn("--platform", docker)
        self.assertIn("linux/arm64", docker)

    def test_both_mode_is_two_ordered_phases(self):
        self.assertEqual(
            native_go_build.requested_engines("both"),
            ("carrick", "docker"),
        )

    def test_ratio_uses_phase_medians(self):
        self.assertAlmostEqual(
            native_go_build.carrick_over_docker_ratio([20, 19, 21], [2, 1, 3]),
            10.0,
        )
```

- [x] **Step 2: Run the focused test and verify red**

Run:

```bash
python3 -m unittest scripts/perf/test_native_go_build.py -v
```

Expected: failures because `build_command`, `requested_engines`, and
`carrick_over_docker_ratio` do not exist.

- [x] **Step 3: Extract one guest script and add Docker command construction**

Implement these exact public helpers in `scripts/perf/native_go_build.py`:

```python
ENGINE_CARRICK = "carrick"
ENGINE_DOCKER = "docker"
ENGINE_BOTH = "both"


def guest_script() -> str:
    return (
        'set -eu; cd /tmp; rm -rf "gc-$CARRICK_RUN_ID"; '
        'printf "package main\\nfunc main(){println(\\"ok\\")}\\n" > h.go; '
        'GOCACHE="/tmp/gc-$CARRICK_RUN_ID" '
        "/usr/local/go/bin/go build -o h ./h.go; "
        "./h; echo BUILD_OK"
    )


def requested_engines(value: str) -> tuple[str, ...]:
    if value == ENGINE_BOTH:
        return (ENGINE_CARRICK, ENGINE_DOCKER)
    if value in {ENGINE_CARRICK, ENGINE_DOCKER}:
        return (value,)
    raise ValueError(f"unknown engine: {value}")


def build_command(repo: pathlib.Path, engine: str, run_id: str) -> list[str]:
    if engine == ENGINE_CARRICK:
        return [
            str(repo / "target/release/carrick"),
            "run", "--exec-backend", "native",
            "-e", f"CARRICK_RUN_ID={run_id}",
            "-w", "/tmp", DEFAULT_IMAGE,
            "/bin/sh", "-c", guest_script(),
        ]
    if engine == ENGINE_DOCKER:
        return [
            "docker", "run", "--name", run_id,
            "--platform", "linux/arm64",
            "-e", f"CARRICK_RUN_ID={run_id}",
            "-w", "/tmp", DEFAULT_IMAGE,
            "/bin/sh", "-c", guest_script(),
        ]
    raise ValueError(f"unknown engine: {engine}")
```

Make `build_carrick_command()` call `build_command(..., ENGINE_CARRICK, ...)`.
Docker cleanup must use `docker rm -f <run-id>` in a `finally` block; Carrick
cleanup retains `scripts/sudo/kill.sh <run-id>`.

- [x] **Step 4: Add phase execution and the v2 artifact**

Add `--engine {carrick,docker,both}` with default `carrick`. Run all requested
Carrick samples before any Docker sample. Populate:

```python
{
    "schema": "carrick.native-go-build.v2",
    "phases": {
        engine: {
            "samples": rows,
            "median_ms": median_ms([int(row["elapsed_ms"]) for row in rows]),
        }
    },
    "ratio": {
        "carrick_over_docker": carrick_median / docker_median
    }
}
```

Record `docker image inspect --format '{{json .Architecture}}'` and reject a
Docker phase unless it returns `"arm64"`. Retain commit, binary hash, dirty
state, host load, and busy-host preflight fields.

- [x] **Step 5: Run focused tests and a command-only inspection**

Run:

```bash
python3 -m unittest scripts/perf/test_native_go_build.py -v
python3 scripts/perf/native_go_build.py --help
```

Expected: all tests pass; help lists `--engine`.

- [x] **Step 6: Commit**

```bash
git add scripts/perf/native_go_build.py scripts/perf/test_native_go_build.py
git commit -m "perf(native): pair Go-build oracle timing"
```

The commit body records why the historical 942 ms datum is insufficient, that
the phases are deliberately serial, and the focused Python test command.

---

### Task 2: Built-in launch-scoped `native-wall` DTrace profile

**Files:**
- Create: `scripts/dtrace/native-wall.d`
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/dtrace_consumer.rs`
- Modify: `crates/carrick-cli/src/trace_profile.rs`

**Interfaces:**
- Produces CLI value `--profile native-wall`.
- Produces a once-per-process `host-jit-range(pid,start,end)` USDT
  announcement so anonymous translated code is not conflated with system
  dylibs.
- Produces `carrick.dsr-profile.v1` JSONL rows with profile `native-wall` and
  phases `wall-state`, `cpu-user-pc`, `cpu-kernel-pc`,
  `offcpu-voluntary-pc`, `offcpu-runnable-pc`, `process-lifecycle`, and
  `image-base`, plus structured `NWSTACK1` records for the heaviest voluntary
  blocking stacks.
- Reuses `ProfileCaptureStatus` so any principal, aggregation, dynamic, or
  other drop makes completion false.
- Does not enable `CARRICK_DSR_PROFILE`; it samples normal production code.

- [x] **Step 1: Add red enum, protocol, and stack-parser tests**

Extend the unit tests in `trace_profile.rs` with a complete synthetic stream:

```rust
#[test]
fn native_wall_profile_parses_reconciled_samples_and_blocking_stack() {
    assert!(!TraceProfileKind::NativeWall.requires_runtime_profile());
    let summary = ProfileSummary::from_lines(
        [
            "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=120",
            "DSRPROF1|count|phase=wall-samples|value=120",
            "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=499",
            "NWSTACK1|begin|state=voluntary|pid=42|value_ns=900",
            "0x2000",
            "NWSTACK1|end",
            "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
            "DSRPROF1|total|phase=elapsed|value_ns=1000000000",
            "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
        ],
        ProfileCaptureStatus::default(),
    )
    .expect("complete native wall profile");
    assert!(summary.completion.complete);
}
```

Add a table-driven rejection test for missing elapsed time, mismatched wall
buckets, live processes, missing CPU samples, and voluntary time without a
stack. Launch scoping is proved live in Task 4 rather than by grepping D source.

- [x] **Step 2: Add a red JIT-range announcement test**

Add a `ProcessTranslator` unit test that asserts
`cache_host_range()` is nonempty and its size equals the configured cache
capacity using a real anonymous test mapping. The live smoke in Task 4 verifies
that the runtime announcement reaches JSONL.

- [x] **Step 3: Run the focused Rust tests and verify red**

Run:

```bash
cargo test -p carrick-cli trace_profile -- --nocapture
cargo test -p carrick-dsr-aarch64 cache_host_range -- --nocapture
```

Expected: compile failure because `TraceProfileKind::NativeWall` does not
exist and `cache_host_range()` is absent.

- [x] **Step 4: Add the bundled profile kind**

Add `NativeWall` to `TraceProfileKind`, `as_str`, `parse_protocol`, and
`bundled_script`. Export:

```rust
pub const BUNDLED_NATIVE_WALL_D: &str =
    include_str!("../../../scripts/dtrace/native-wall.d");
```

from `carrick-runtime/src/dtrace_consumer.rs`. Leave
`requires_runtime_profile()` false for this variant.

- [x] **Step 5: Add explicit JIT-range observability**

Add `host__jit__range(pid: u32, start: u64, end: u64)` to the USDT provider and
the public wrapper:

```rust
pub fn host_jit_range(start: u64, end: u64) {
    carrick_usdt::host__jit__range!(|| (std::process::id(), start, end));
}
```

Expose the cache range without raw pointer domains leaking into the runtime:

```rust
pub fn cache_host_range(&self) -> std::ops::Range<u64> {
    let range = self.state.read().cache.host_range();
    range.start as u64..range.end as u64
}
```

Immediately after `dsr_process_translator()` in the Darwin loop, fire the
range probe. In the D program, admit only tracked PIDs and emit only the first
announcement per PID as two `image-base` rows with kinds `jit-start` and
`jit-end`.

- [x] **Step 6: Implement launch-owned process and thread state**

In `scripts/dtrace/native-wall.d`, use:

```d
dtrace:::BEGIN
{
    started = timestamp;
    target_reason = 0;
    track_pid[$target] = 1;
    live_pids = 1;
    wall_samples = 0;
}

proc:::create
/track_pid[pid]/
{
    track_pid[args[0]->pr_pid] = 1;
    live_pids++;
    @process_events["create"] = count();
}

proc:::exit
/track_pid[pid] && pid != $target/
{
    track_pid[pid] = 0;
    live_pids--;
    @process_events["exit"] = count();
}

proc:::exit
/pid == $target/
{
    track_pid[pid] = 0;
    live_pids--;
    target_reason = arg0;
    exit(0);
}
```

Adopt a tracked LWP on its first `sched:::on-cpu`. Maintain one state per
`pid,tid`: `1=on-cpu`, `2=runnable`, `3=sleeping`. Update aggregate counts on
every transition. On `proc:::lwp-exit`, remove that LWP's current contribution
from the global state counts and clear its state. Never use `progenyof()` or an
`execname` predicate.

- [x] **Step 7: Add wall, CPU, and off-CPU sampling**

Use `tick-197hz` as the single wall sampler:

```d
tick-197hz
{
    wall_samples++;
    @wall_state[on_cpu_threads > 0 ? "on-cpu" :
        runnable_threads > 0 ? "runnable-descheduled" :
        sleeping_threads > 0 ? "all-sleeping" : "transition"] = count();
}
```

Use `profile-499` for CPU PCs:

```d
profile-499
/track_pid[pid] && arg1 != 0/
{
    @cpu_user[pid, arg1] = count();
}

profile-499
/track_pid[pid] && arg0 != 0/
{
    @cpu_kernel[arg0] = count();
}
```

On `sched:::off-cpu`, save timestamp, user PC and whether
`curlwpsinfo->pr_state == SSLEEP`. On the matching `sched:::on-cpu`, aggregate
duration and count separately for voluntary and runnable-descheduled waits,
keyed by PID and saved PC. For voluntary waits, also aggregate
`@voluntary_stack[pid, ustack(24)] = sum(duration)`. Clear the thread-local
timestamp after consumption.

- [x] **Step 8: Emit only machine-protocol rows from `END`**

Print every aggregation as `DSRPROF1` records. Examples:

```d
printa("DSRPROF1|count|phase=wall-state|kind=%s|value=%@d\n", @wall_state);
printa("DSRPROF1|count|phase=cpu-user-pc|pid=%d|source_pc=0x%x|value=%@d\n",
    @cpu_user);
printa("DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0x%x|value=%@d\n",
    @cpu_kernel);
printa("DSRPROF1|count|phase=offcpu-voluntary-pc|pid=%d|source_pc=0x%x|value=%@d\n",
    @voluntary_count);
printa("DSRPROF1|total|phase=offcpu-voluntary-pc|pid=%d|source_pc=0x%x|value_ns=%@d\n",
    @voluntary_ns);
printf("DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=%d\n",
    live_pids);
printf("DSRPROF1|total|phase=elapsed|value_ns=%d\n", timestamp - started);
printf("DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=%d\n",
    target_reason);
```

Use the existing `host-image-base` and `guest-image-base` probes to emit PID
and base as `image-base` exact rows, admitted only when `track_pid[pid]` is set.
Truncate `@voluntary_stack` to the heaviest 32 stacks and emit each one between
machine-readable delimiters:

```d
trunc(@voluntary_stack, 32);
printa("NWSTACK1|begin|state=voluntary|pid=%d|value_ns=%@d\n%kNWSTACK1|end\n",
    @voluntary_stack);
```

Do not print human headings or unversioned aggregations.

- [x] **Step 9: Enforce native-wall-specific completion invariants**

Extend `ProfileSummary::from_lines` with a small state machine that accepts
`NWSTACK1|begin`, stack-frame lines, and `NWSTACK1|end` only for a
`NativeWall` stream. Publish each block as:

```rust
ProfileMetric::StackTrace {
    state: String,
    pid: u64,
    value_ns: u64,
    frames: Vec<String>,
}
```

Reject nesting, an empty frame list, an unterminated block, a nonnumeric PID or
duration, or any `NWSTACK1` block in another profile. After grouping a
`NativeWall` profile, reject:

- missing `elapsed`;
- zero total wall samples;
- any `process-lifecycle/live-at-end` value other than zero;
- wall bucket sum not equal to the recorded wall-sample total;
- a profile with neither user nor kernel CPU samples.
- no voluntary stack records when voluntary off-CPU duration is nonzero.

Keep the existing drop, interruption, target-reason, duplicate-completion, and
post-completion failures.

- [x] **Step 10: Run tests, build signed, and verify DOF**

Run:

```bash
cargo test -p carrick-cli trace_profile -- --nocapture
cargo test -p carrick-dsr-aarch64 cache_host_range -- --nocapture
just build
otool -l target/release/carrick | grep -A2 __dof_carrick
```

Expected: focused tests pass; signed binary builds; `__dof_carrick` is present.

- [x] **Step 11: Commit**

```bash
git add scripts/dtrace/native-wall.d \
  crates/carrick-observability/src/probes.rs \
  crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-runtime/src/native_darwin.rs \
  crates/carrick-runtime/src/dtrace_consumer.rs \
  crates/carrick-cli/src/trace_profile.rs
git commit -m "diagnostics(native): add whole-tree wall profile"
```

The body records launch scoping, the wall/resource separation, sampling rates,
and the focused tests.

---

### Task 3: Fail-closed attribution summarizer

**Files:**
- Create: `scripts/perf/native_wall_attribution.py`
- Create: `scripts/perf/test_native_wall_attribution.py`
- Modify: `scripts/symbolicate.py`

**Interfaces:**
- Consumes one or two `carrick.dsr-profile.v1` JSONL files whose profile is
  `native-wall`.
- Produces schema `carrick.native-wall-attribution.v1`.
- Exposes:
  `load_profile(path: pathlib.Path) -> Profile`,
  `classify_host_symbol(symbol: str) -> str`,
  `summarize(profile: Profile, binary: pathlib.Path) -> dict[str, object]`,
  and `compare(a: Summary, b: Summary) -> dict[str, object]`.
- Exits nonzero instead of publishing when reconciliation or coverage fails.

- [x] **Step 1: Add red tests with a complete synthetic profile**

Create a fixture inline in `test_native_wall_attribution.py` with:

- 197 wall samples split 120 on-CPU, 40 runnable, 35 sleeping, 2 transition;
- 499 CPU samples split between a host PC and a JIT PC;
- voluntary and runnable off-CPU rows;
- two `StackTrace` metrics whose durations cover at least 80% of voluntary
  off-CPU duration;
- zero live processes, natural completion, and zero drops.

Assert:

```python
self.assertAlmostEqual(summary["wall_state"]["on-cpu"]["share"], 120 / 197)
self.assertEqual(summary["reconciliation"]["wall_samples"], 197)
self.assertLessEqual(summary["cpu"]["unresolved"]["share"], 0.10)
self.assertGreaterEqual(summary["offcpu"]["top_stack_coverage"], 0.80)
self.assertTrue(summary["accepted"])
```

Add negative tests for nonzero drops, 98% wall reconciliation, 11% unresolved
CPU, stack coverage below 80%, a live process at end, and a dominant category
moving more than five percentage points between comparison inputs.

- [x] **Step 2: Run the focused Python tests and verify red**

Run:

```bash
python3 -m unittest scripts/perf/test_native_wall_attribution.py -v
```

Expected: import failure because `native_wall_attribution.py` does not exist.

- [x] **Step 3: Implement JSONL loading and completion checks**

Parse every line independently. Require one completion row and identical
`run_id`, `git_sha`, `binary_sha256`, `profile`, and completion state across
rows. Require profile `native-wall`, `complete=true`, all drop counts zero, and
`target_exit_reason=1`.

Use dataclasses for immutable parsed rows and summaries. Reject duplicate
`(phase,pid,kind,source_pc,type)` keys instead of silently adding independent
publisher rows.

- [x] **Step 4: Classify sampled PCs**

Refactor reusable address helpers from `scripts/symbolicate.py` without
changing its CLI output. Resolve host PCs in one `atos` batch per image/base.
Classify symbols by these ordered rules:

```python
CATEGORY_RULES = (
    ("translation", ("carrick_dsr_aarch64", "dynasm", "translate", "emit")),
    ("gateway", ("native_darwin", "prepare", "resolve", "recover_rewrite_state")),
    ("dispatch", ("dispatch", "syscall", "carrick_host")),
    ("process-setup", ("capsule", "prepared_image", "clap", "serde", "sha2")),
)
```

A PC outside the announced Carrick text range is `translated-guest` only when
it is also outside the announced guest ELF range and has no resolvable host
image. Otherwise classify it `unresolved`; do not relabel every unknown dylib
as JIT.

Kernel PCs group by symbol when the JSON row contains a name and otherwise by
raw PC under `darwin-kernel`.

- [x] **Step 5: Enforce campaign reconciliation**

Publish only when:

- wall buckets equal total wall samples and cover at least 99% of expected
  `elapsed_ns * 197 / 1e9` within timer quantization;
- resolved CPU categories cover at least 90% of user plus kernel samples;
- voluntary top stacks cover at least 80% of voluntary duration;
- process live-at-end is zero.

For two profiles, require the dominant-category order to agree and each
category above 10% to stay within five percentage points. Report a failed
stability result without overwriting an earlier accepted single-run summary.

- [x] **Step 6: Add atomic JSON publication and human output**

Support:

```bash
python3 scripts/perf/native_wall_attribution.py \
  --profile run-a.jsonl --profile run-b.jsonl \
  --binary target/release/carrick \
  --output target/perf/native-wall-attribution.json
```

Write to a sibling temporary file, `fsync`, and `os.replace`. Human output
prints elapsed wall, average CPU parallelism, wall-state shares, CPU shares,
off-CPU top stacks, unresolved coverage, and stability.

- [x] **Step 7: Run tests**

Run:

```bash
python3 -m unittest \
  scripts/perf/test_native_go_build.py \
  scripts/perf/test_native_wall_attribution.py -v
```

Expected: all tests pass.

- [x] **Step 8: Commit**

```bash
git add scripts/perf/native_wall_attribution.py \
  scripts/perf/test_native_wall_attribution.py scripts/symbolicate.py
git commit -m "diagnostics(native): reconcile wall attribution"
```

The body names the 99%, 90%, 80%, and five-percentage-point gates.

---

### Task 4: Live profile validation and profiler correction

**Files:**
- Modify as evidence requires:
  `scripts/dtrace/native-wall.d`,
  `crates/carrick-cli/src/trace_profile.rs`,
  `scripts/perf/native_wall_attribution.py`
- Modify corresponding focused tests.

**Interfaces:**
- Consumes the signed binary from Task 2.
- Produces one accepted short-workload profile before Go-build tracing is
  allowed.

- [ ] **Step 1: Check host and trace prerequisites**

Run:

```bash
ps -eo pid=,args= | rg 'while :|cargo|rustc|target/release/carrick' || true
uptime
docker info >/dev/null
docker start vt-ferry-registry
otool -l target/release/carrick | grep -A2 __dof_carrick
```

Do not use `--allow-busy` for evidence.

- [ ] **Step 2: Run a bounded native smoke trace**

Use a unique run ID:

```bash
CARRICK_RUN_ID=native-wall-smoke-<stamp> \
  target/release/carrick trace --profile native-wall \
  --trace-out target/perf/native-wall-smoke.raw \
  --summary-jsonl target/perf/native-wall-smoke.jsonl -- \
  run --exec-backend native \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c 'echo TRACE_OK'
```

Expected: natural completion, `TRACE_OK`, zero drops, nonzero wall and CPU
samples, zero live processes.

- [ ] **Step 3: Run the summarizer**

Run:

```bash
python3 scripts/perf/native_wall_attribution.py \
  --profile target/perf/native-wall-smoke.jsonl \
  --binary target/release/carrick \
  --output target/perf/native-wall-smoke-summary.json
```

Expected: accepted reconciliation. If it fails, record the exact failed
invariant in the ledger before modifying the profile; do not weaken a threshold
to force green.

- [ ] **Step 4: Validate population scoping adversarially**

Start an unrelated stamped Carrick `/bin/sleep 15` run, then repeat the short
trace. Assert the unrelated PID appears nowhere in `cpu-user-pc`,
`offcpu-*`, or `image-base` rows. Clean each run by its own run ID.

- [ ] **Step 5: Commit any profiler correction**

If Tasks 4.2–4.4 required code changes, rerun focused tests and commit:

```bash
git add scripts/dtrace/native-wall.d \
  crates/carrick-cli/src/trace_profile.rs \
  scripts/perf/native_wall_attribution.py \
  scripts/perf/test_native_wall_attribution.py
git commit -m "fix(native): make wall profile reconcile"
```

If no correction was required, record the live receipt in the ledger with no
empty commit.

---

### Task 5: Fresh official baseline and replicated Go-build attribution

**Files:**
- Create: `scripts/perf/evidence/native-go-build-wall-baseline-v1.json`
- Create: `scripts/perf/evidence/native-go-build-wall-profile-a-v1.jsonl`
- Create: `scripts/perf/evidence/native-go-build-wall-profile-b-v1.jsonl`
- Create: `scripts/perf/evidence/native-go-build-wall-attribution-v1.json`
- Modify: `docs/perf-results/native-wall-time-campaign.md`
- Modify: `handoff.md`

**Interfaces:**
- Produces official `C0`, `D0`, and `R0`.
- Produces replicated wall-state, CPU, and off-CPU attribution satisfying M1.
- Changes one hypothesis from `PROPOSED` to `SPIKING` and records its measured
  ceiling.

- [ ] **Step 1: Rebuild the exact signed evidence binary**

Run:

```bash
just build
otool -l target/release/carrick | grep -A2 __dof_carrick
git status --short
```

Record the commit, dirty state, binary SHA-256, codesign result, and host
preflight. A dirty tree may be profiled diagnostically but cannot establish
official `C0`.

- [ ] **Step 2: Collect the paired untraced baseline**

On an accepted idle host:

```bash
python3 scripts/perf/native_go_build.py \
  --engine both --samples 5 \
  --output scripts/perf/evidence/native-go-build-wall-baseline-v1.json
```

Expected: five successful Carrick samples, then five successful Docker samples,
all printing `BUILD_OK`; the artifact contains medians and `C0 / D0`.

- [ ] **Step 3: Collect trace A**

Construct the command using `build_command(..., "carrick", run_id)` and place it
after `carrick trace --profile native-wall`. Write raw output under
`target/perf/` and JSONL to
`scripts/perf/evidence/native-go-build-wall-profile-a-v1.jsonl`.

Expected: natural build completion, zero drops, zero live processes, accepted
single-profile summary.

- [ ] **Step 4: Return the host to idle and collect trace B**

Repeat with a new run ID and
`native-go-build-wall-profile-b-v1.jsonl`. Do not run Docker, compilation, CI,
or another Carrick workload concurrently.

- [ ] **Step 5: Reconcile and compare**

Run:

```bash
python3 scripts/perf/native_wall_attribution.py \
  --profile scripts/perf/evidence/native-go-build-wall-profile-a-v1.jsonl \
  --profile scripts/perf/evidence/native-go-build-wall-profile-b-v1.jsonl \
  --binary target/release/carrick \
  --output scripts/perf/evidence/native-go-build-wall-attribution-v1.json
```

Expected: wall accounting at least 99%, CPU classification at least 90%,
off-CPU top-stack coverage at least 80%, and stable dominant categories.

- [ ] **Step 6: Select and size the first spike**

Update H001–H005 from the measured shares. For the dominant actionable category:

1. calculate the maximum wall or CPU reduction if it vanished;
2. state the expected counter or category movement;
3. choose one structural variant bounded to one implementation session;
4. name its red-first correctness proof;
5. predeclare the two-sample screen and five-plus-five retention gate.

Mark only that row `SPIKING`. Do not select translated guest execution merely
because it is the largest category; select Carrick-owned amplification.

- [ ] **Step 7: Update the ledger and handoff**

Replace every M1 `pending` field with an evidence-backed number or an explicit
failed gate. Set current milestone to M1 only if every M1 acceptance criterion
is met. Make the handoff's next action the selected hypothesis and bounded
spike.

- [ ] **Step 8: Validate evidence and documentation**

Run:

```bash
python3 -m unittest \
  scripts/perf/test_native_go_build.py \
  scripts/perf/test_native_wall_attribution.py -v
python3 -m json.tool \
  scripts/perf/evidence/native-go-build-wall-baseline-v1.json >/dev/null
python3 -m json.tool \
  scripts/perf/evidence/native-go-build-wall-attribution-v1.json >/dev/null
git diff --check
```

- [ ] **Step 9: Commit M1 evidence**

```bash
git add scripts/perf/evidence/native-go-build-wall-baseline-v1.json \
  scripts/perf/evidence/native-go-build-wall-profile-a-v1.jsonl \
  scripts/perf/evidence/native-go-build-wall-profile-b-v1.jsonl \
  scripts/perf/evidence/native-go-build-wall-attribution-v1.json \
  docs/perf-results/native-wall-time-campaign.md handoff.md
git commit -m "diagnostics(native): establish wall-time baseline"
```

The commit body records `C0`, `D0`, `R0`, attribution shares, trace stability,
the selected hypothesis and its calculated ceiling.

---

## Plan self-review

- Spec coverage: Tasks 1–5 cover the fresh paired baseline, launch scoping,
  wall/CPU/off-CPU separation, drop and completion failures, classification,
  replicated attribution, ledger update, and first-spike selection.
- Scope: this plan ends at M1. The selected optimization receives a separate
  TDD implementation plan because its files and correctness obligations cannot
  be known honestly before attribution.
- Type consistency: `native-wall`, the phase names, v2 benchmark schema, and v1
  attribution schema are identical across producers, tests, commands, and
  consumers.
- Completeness scan: every task names files, commands, expected outcomes, and
  stop behavior; no unspecified implementation work is delegated.
