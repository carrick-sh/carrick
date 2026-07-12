# Durable DSR DTrace Profiling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable, versioned `carrick trace` profiling surface that uses
allocation-free DSR USDT probes and DTrace timestamps to attribute all DSR
exits, resolver sites, cache activity, and fork/exec lifecycle without a
measurable disabled-probe performance regression.

**Architecture:** Define a stable typed probe ABI in `carrick-observability`,
fire it only at existing DSR semantic seams, and let three bounded embedded D
programs perform timing, sampling, and process-tree aggregation. The CLI parses
a versioned line protocol into atomically written JSONL; existing Rust counters,
syscall probes, and fork probes remain independent cross-checks.

**Tech Stack:** Rust 1.96.0, `usdt`, in-process libdtrace, `clap`,
`serde`/`serde_json`, `tempfile`, signed Carrick builds, and the native DSR
performance harness.

## Global Constraints

- Use `carrick trace`; do not add a standalone `dtrace` driver.
- Every D clause follows `pid == $target || progenyof($target)`.
- Probe wrappers accept copied scalars only. No allocation, formatting, locks,
  environment reads, clock reads, or runtime traversal occurs in closures.
- DTrace owns timestamps, pairing, aggregation, and duration sampling.
- Reuse existing syscall and fork probes instead of duplicating their seams.
- `--profile` and `--script` are mutually exclusive;
  `--summary-jsonl` requires `--profile`.
- Scripts live under `scripts/dtrace/` and are embedded with `include_str!`.
- Every D script exits on natural completion of the tracked process tree and
  also has a tick fallback; the driver bound is longer so `END` flushes.
- Machine output uses `DSRPROF1`; JSONL uses `carrick.dsr-profile.v1`.
- Unknown protocol versions, malformed records, missing completion, and
  truncated streams are hard errors. Unmatched phase pairs are explicit data,
  not parser failures.
- Traced timing never replaces untraced performance evidence.
- This work changes only DSR diagnostics. It does not preserve, compare, or
  modify `brk`, and it does not optimize DSR in the same change.
- Linux remains the semantic oracle; this macOS DTrace surface does not replace
  differential Linux proof and does not add a Linux host-profiler design.
- Disabled-probe ABBA gates use 30 syscall-floor and 10 V8 samples per binary,
  with practical p50 non-inferiority bounds of 2% and 1% respectively.
- Build runnable binaries with `just build`; retain Apple `ld64`; verify
  `__DATA,__dof_carrick` before live tracing.
- Stamp `CARRICK_RUN_ID`; reap only with `scripts/sudo/kill.sh <run-id>`.

## File structure

| File | Responsibility |
| --- | --- |
| `crates/carrick-observability/src/probes.rs` | Stable DSR enums, USDT wrappers, target stubs |
| `crates/carrick-runtime/src/native_darwin/dsr/mod.rs` | DSR phase and lifecycle probe calls |
| `crates/carrick-runtime/src/native_darwin.rs` | Guest tid and process role context |
| `crates/carrick-runtime/src/dtrace_consumer.rs` | Embedded D programs |
| `crates/carrick-cli/src/{args,commands,trace_profile}.rs` | CLI, parser, JSONL publication |
| `scripts/dtrace/dsr-{profile,indirect,fork}.d` | Broad, site, and fork profiles |
| `crates/carrick-cli/tests/trace_profile.rs` | CLI/parser/script tests |
| `docs/diagnostics-and-debugging.md` | Operator documentation |
| `docs/native-dsr-dtrace-profile.md` | Probe ABI, schema, and measured conclusions |
| `docs/perf-results/native-dsr-dtrace-{disabled,enabled}-overhead.jsonl` | Raw performance evidence |

---

### Task 1: Define and pin the DSR probe ABI

**Files:**

- Modify: `crates/carrick-observability/src/probes.rs`

**Interfaces:**

- Produces `DsrExitKind`, `DsrPrepareOutcome`, `DsrResolveKind`,
  `DsrOperationOutcome`, `DsrCacheEventKind`, `DsrCacheRole`, and
  `DsrCacheLifecyclePhase`.
- Produces ten matching real and stub wrappers for prepare, run, translate,
  resolve, cache event, and cache lifecycle begin/end surfaces.

- [ ] **Step 1: Write red ordinal tests**

```rust
#[test]
fn dsr_exit_kind_values_match_gateway_status() {
    assert_eq!(DsrExitKind::Syscall.raw(), 1);
    assert_eq!(DsrExitKind::DirectResolver.raw(), 2);
    assert_eq!(DsrExitKind::IndirectResolver.raw(), 3);
    assert_eq!(DsrExitKind::Fault.raw(), 4);
    assert_eq!(DsrExitKind::Kick.raw(), 5);
    assert_eq!(DsrExitKind::Sensitive.raw(), 6);
    assert_eq!(DsrExitKind::Unsupported.raw(), 7);
}

#[test]
fn dsr_probe_ordinals_are_unique() {
    fn unique(values: &[u32]) {
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), values.len());
    }
    unique(&DsrPrepareOutcome::ALL.map(DsrPrepareOutcome::raw));
    unique(&DsrResolveKind::ALL.map(DsrResolveKind::raw));
    unique(&DsrOperationOutcome::ALL.map(DsrOperationOutcome::raw));
    unique(&DsrCacheEventKind::ALL.map(DsrCacheEventKind::raw));
    unique(&DsrCacheLifecyclePhase::ALL.map(DsrCacheLifecyclePhase::raw));
}
```

- [ ] **Step 2: Verify red**

Run: `cargo test -p carrick-observability dsr_probe_abi --lib`

Expected: compilation fails because the enums do not exist.

- [ ] **Step 3: Add ordinal enums**

Use this exact pattern:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DsrExitKind {
    Syscall = 1,
    DirectResolver = 2,
    IndirectResolver = 3,
    Fault = 4,
    Kick = 5,
    Sensitive = 6,
    Unsupported = 7,
}
impl DsrExitKind {
    pub const ALL: [Self; 7] = [Self::Syscall, Self::DirectResolver,
        Self::IndirectResolver, Self::Fault, Self::Kick, Self::Sensitive,
        Self::Unsupported];
    pub const fn raw(self) -> u32 { self as u32 }
}
```

Remaining variants are:

```rust
DsrPrepareOutcome::{ResumeEntryHit = 1, BlockIndexHit = 2,
    Translated = 3, Failed = 4}
DsrResolveKind::{Direct = 1, Indirect = 2}
DsrOperationOutcome::{Success = 0, PcOverflow = 1, Decode = 2,
    Malformed = 3, BlockPolicy = 4, MemoryRead = 5,
    UnsupportedBlockAction = 6, Assembler = 7, Gateway = 8,
    CachePolicy = 9, GenerationChanged = 10, Host = 11}
DsrCacheEventKind::{BlockHit = 1, BlockMiss = 2, TargetPublish = 3,
    Invalidate = 4, BlockPublish = 5, CapacityFailure = 6}
DsrCacheRole::{Common = 0, Parent = 1, Child = 2}
DsrCacheLifecyclePhase::{ForkChildRepairBegin = 1,
    ForkChildRepairEnd = 2, ExecResetBegin = 3, ExecResetEnd = 4}
```

- [ ] **Step 4: Add scalar USDT definitions and wrappers**

```rust
fn dsr__prepare__begin(_: i32, _: u64) {}
fn dsr__prepare__end(_: i32, _: u64, _: u64, _: u64, _: u32) {}
fn dsr__run__begin(_: i32, _: u64, _: u64, _: u64) {}
fn dsr__run__end(_: i32, _: u32, _: u64, _: u64, _: i32) {}
fn dsr__translate__begin(_: i32, _: u64, _: u64) {}
fn dsr__translate__end(_: i32, _: u64, _: u64, _: u64, _: u64, _: u32) {}
fn dsr__resolve__begin(_: i32, _: u32, _: u64, _: u64) {}
fn dsr__resolve__end(_: i32, _: u32, _: u64, _: u64, _: u32) {}
fn dsr__cache__event(_: i32, _: u32, _: u64, _: u64, _: u64, _: u64) {}
fn dsr__cache__lifecycle(_: u32, _: u32, _: u64, _: u64, _: u64) {}
```

Every wrapper is `#[inline(always)]`; conversions happen inside the closure:

```rust
#[inline(always)]
pub fn dsr_run_end(tid: i32, kind: super::DsrExitKind,
    guest_pc: u64, target_pc: u64, status: i32) {
    carrick_usdt::dsr__run__end!(||
        (tid, kind.raw(), guest_pc, target_pc, status));
}
```

No wrapper creates `String`, `Vec`, or an eager tuple, reads a clock, or calls
`std::process::id`. Add identical `stub!` signatures.

- [ ] **Step 5: Verify and commit**

```bash
cargo test -p carrick-observability dsr_probe_abi --lib
cargo clippy -p carrick-observability --all-targets -- -D warnings
just fmt-check
git add crates/carrick-observability/src/probes.rs
git commit -m "diagnostics(native): define the DSR probe ABI" \
  -m "Pin typed scalar-only USDT events for DSR phases, exits, cache activity, and lifecycle. Mirror the surface with no-op target stubs."
```

---

### Task 2: Instrument every DSR semantic seam

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**

- Consumes Task 1 enums and wrappers.
- Produces `TranslationOutcome`, structured translation results, and complete
  begin/end pairing at the DSR runtime seams.

- [ ] **Step 1: Write a red translation-outcome test**

```rust
#[test]
fn dsr_translation_result_distinguishes_publish_and_index_hit() {
    let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001]);
    let mut process = ProcessState::for_test(16 * 1024).expect("state");
    let first = process.translate(&memory, guest).expect("first");
    let second = process.translate(&memory, guest).expect("second");
    assert_eq!(first.outcome, TranslationOutcome::Translated);
    assert_eq!(second.outcome, TranslationOutcome::BlockIndexHit);
    assert_eq!(first.entry, second.entry);
}
```

Move an existing oracle memory-helper body into `mapped_dsr_test_memory`; do not
duplicate an ELF or mapping builder.

- [ ] **Step 2: Verify red**

Run: `cargo test -p carrick-runtime dsr_translation_result_distinguishes --lib`

Expected: missing `TranslationOutcome` and structured result fields.

- [ ] **Step 3: Return typed outcomes**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TranslationOutcome { BlockIndexHit, Translated }

#[derive(Clone, Copy, Debug)]
struct TranslationResult {
    entry: types::CacheVa,
    generation: types::CodeGeneration,
    outcome: TranslationOutcome,
}
```

Change `ProcessState::translate` and `ThreadTranslator::translate` to return the
struct. The block-index early return is `BlockIndexHit`; a publication is
`Translated`.

- [ ] **Step 4: Store the guest tid**

Change the constructor to
`ThreadTranslator::for_process(process: Arc<ProcessTranslator>, tid: i32)` and
store `tid`. Unit tests pass `0`; the live loop passes the existing raw guest
tid accessor, never a host pthread ID.

- [ ] **Step 5: Fire prepare, translation, and cache probes**

At `prepare_entry`, fire begin before lookup and end on every outcome:

```rust
probes::dsr_prepare_begin(self.tid, guest.raw());
// existing resume-entry or translation selection
probes::dsr_prepare_end(self.tid, guest.raw(), entry.host().raw() as u64,
    generation.get(), outcome);
```

Before a returned error, emit `Failed` with cache PC and generation zero.
Inside `ProcessState::translate`, bracket decode/emission only after a miss.
Fire `BlockHit`, `BlockMiss`, `Invalidate`, `BlockPublish`, and
`CapacityFailure` at exact branches. Read cache used/capacity under the existing
process lock; add no atomics.

- [ ] **Step 6: Classify every gateway return**

Add a total `NativeDsrExit::probe_fields` match returning
`(DsrExitKind, guest_pc, target_pc, status)` for all seven variants. Fire
`dsr_run_begin` immediately before the exception-free gateway and
`dsr_run_end` immediately after it returns, before resolver or dispatcher work.
On gateway error, emit an `Unsupported` end with nonzero status.

- [ ] **Step 7: Bracket resolution and lifecycle**

Fire resolve begin/end around direct and indirect resolver arms; `outcome=0`
means `DsrOperationOutcome::Success`, and every `DsrError` variant maps totally
to the matching stable outcome, never a Darwin errno. Use the same mapping for
translation end. Fire `TargetPublish` after indirect-cache publication.

Wrap `after_fork_child` and `reset_for_exec` with lifecycle begin/end. Capture
cache bytes, published-block count, and dependency-page count under the existing
lock; add read-only `len()` accessors instead of duplicate counters.

- [ ] **Step 8: Verify and commit**

```bash
cargo test -p carrick-runtime native_darwin::dsr --lib
cargo clippy -p carrick-runtime --lib -- -D warnings
just fmt-check
git add crates/carrick-runtime/src/native_darwin.rs \
  crates/carrick-runtime/src/native_darwin/dsr
git commit -m "diagnostics(native): instrument typed DSR phases" \
  -m "Fire allocation-free USDT pairs at prepare, translated-run, translation, resolver, cache, fork-repair, and exec-reset seams."
```

---

### Task 3: Parse the versioned protocol into JSONL

**Files:**

- Create: `crates/carrick-cli/src/perf_stats.rs`
- Create: `crates/carrick-cli/src/trace_profile.rs`
- Modify: `crates/carrick-cli/src/main.rs`
- Modify: `crates/carrick-cli/tests/perf_support/stats.rs`

**Interfaces:**

- Produces `ProfileRecord::parse`,
  `ProfileSummary::from_lines(lines, capture_status)`, and
  `write_summary_atomic(path, summary, owner)`.
- Produces `TraceProfileKind::{Dsr,DsrIndirect,DsrFork}` with Clap and Serde
  derives so later CLI work consumes one typed vocabulary.
- Protocol prefix `DSRPROF1`; JSON schema `carrick.dsr-profile.v1`.

- [ ] **Step 1: Write red parser tests**

```rust
#[test]
fn parses_sample_and_completion() {
    let sample = ProfileRecord::parse(
        "DSRPROF1|sample|phase=run|pid=42|tid=7|kind=3|duration_ns=9000|interval=1024"
    ).expect("sample");
    assert_eq!(sample.record_type, RecordType::Sample);
    assert_eq!(sample.required_u64("duration_ns").expect("duration"), 9000);
    ProfileRecord::parse(
        "DSRPROF1|complete|profile=dsr|bounded=0"
    ).expect("complete");
}

#[test]
fn rejects_unknown_duplicate_and_truncated_protocol() {
    assert!(ProfileRecord::parse("DSRPROF2|complete").is_err());
    assert!(ProfileRecord::parse("DSRPROF1|count|kind=1|kind=2").is_err());
    assert!(ProfileSummary::from_lines([
        "DSRPROF1|count|phase=run|pid=1|kind=3|value=9"
    ], ProfileCaptureStatus::default()).is_err());
}
```

- [ ] **Step 2: Verify red**

Run: `cargo test -p carrick-cli --bin carrick trace_profile`

Expected: missing module and parser types.

- [ ] **Step 3: Implement strict parsing**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordType {
    Count, Total, Minimum, Maximum, Sample, Incomplete, HighWater,
    Complete,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TraceProfileKind { Dsr, DsrIndirect, DsrFork }

struct ProfileRecord {
    record_type: RecordType,
    fields: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Default)]
struct ProfileCaptureStatus {
    principal_drops: u64,
    aggregation_drops: u64,
    dynamic_drops: u64,
    other_drops: u64,
}
```

Reject unknown prefix/type, fields without `=`, empty or duplicate keys,
invalid integers, more than one completion, missing completion, and protocol
records after completion.

- [ ] **Step 4: Aggregate deterministically**

Group by present `(phase,pid,tid,kind,source_pc,target_pc)` fields. Merge exact
count/total/min/max rows. Move the existing nearest-rank `Summary`,
`summarize`, and `is_noisy` implementation into `src/perf_stats.rs`; have the
existing integration-test module re-export that file with `#[path]`, so the
profile parser and performance gate share one implementation. Publish
incomplete-pair rows separately and exclude them from duration samples.

- [ ] **Step 5: Write provenance-rich JSONL atomically**

```rust
#[derive(serde::Serialize)]
struct ProfileJsonRow {
    schema: &'static str,
    profile: TraceProfileKind,
    run_id: String,
    git_sha: String,
    binary_sha256: String,
    command: Vec<String>,
    scope: ProfileScope,
    metric: ProfileMetric,
    sampling_interval: Option<u64>,
    completion: CompletionState,
}
```

Write with `NamedTempFile::new_in(parent)`, `flush`, `sync_all`, optional
`fchown`, and `persist`. Any failure leaves the requested path unchanged.

- [ ] **Step 6: Verify and commit**

```bash
cargo test -p carrick-cli --bin carrick trace_profile
cargo clippy -p carrick-cli --all-targets -- -D warnings
just fmt-check
git add crates/carrick-cli/src/main.rs crates/carrick-cli/src/perf_stats.rs \
  crates/carrick-cli/src/trace_profile.rs \
  crates/carrick-cli/tests/perf_support/stats.rs
git commit -m "feat(trace): parse versioned DSR profiles" \
  -m "Reject malformed or incomplete streams and atomically publish deterministic, provenance-rich JSONL."
```

---

### Task 4: Add the durable trace profile CLI

**Files:**

- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Modify: `crates/carrick-runtime/src/dtrace_consumer.rs`
- Create: `crates/carrick-cli/tests/trace_profile.rs`
- Create: `scripts/dtrace/dsr-profile.d`
- Create: `scripts/dtrace/dsr-indirect.d`
- Create: `scripts/dtrace/dsr-fork.d`

**Interfaces:**

- Exposes the Task 3 `TraceProfileKind` through
  `carrick trace --profile PROFILE --summary-jsonl PATH -- COMMAND...`.
- Changes `run_child_under_dtrace` to return a `DTraceRunReport` containing
  per-kind libdtrace drop totals, so aggregation loss cannot be mistaken for a
  complete profile.
- Adds `TraceOptions::print_remaining_aggregates`; built-in profiles disable
  the consumer's final default aggregation dump because their `END` clauses
  already emit the complete machine protocol.

- [ ] **Step 1: Write red clap tests**

```rust
#[test]
fn trace_profile_argument_relationships_are_enforced() {
    cli().args(["trace", "--summary-jsonl", "/tmp/s.jsonl", "--",
        "run-elf", "/tmp/p"])
        .assert().failure().stderr(predicate::str::contains("profile"));
    cli().args(["trace", "--profile", "dsr", "--summary-jsonl",
        "/tmp/s.jsonl", "--script", "x.d", "--", "run-elf", "/tmp/p"])
        .assert().failure().stderr(predicate::str::contains("cannot be used"));
}
```

- [ ] **Step 2: Add typed clap arguments**

Import the Task 3 `TraceProfileKind` into `args.rs`. Add
`profile: Option<TraceProfileKind>` with `conflicts_with="script"`, and
`summary_jsonl: Option<PathBuf>` with `requires="profile"`. A profile may be
used without `--summary-jsonl` when the operator wants only raw output or the
human summary.

- [ ] **Step 3: Embed valid smoke programs**

Add `BUNDLED_DSR_PROFILE_D`, `BUNDLED_DSR_INDIRECT_D`, and
`BUNDLED_DSR_FORK_D` constants via `include_str!`. Until Tasks 5–7 replace them,
each script contains:

```d
#pragma D option quiet
tick-1s { secs++; }
tick-1s /secs >= 1/ { bounded = 1; exit(0); }
END { printf("DSRPROF1|complete|profile=dsr|bounded=%d\n", bounded); }
```

Use the matching profile name in each file. Add a shared stanza in all three
scripts that starts with `$target` active, observes `proc:::create` for the
selected tree, removes tracked PIDs at `proc:::exit`, and exits naturally when
the active count reaches zero. Pin the macOS proc-provider child-PID argument
shape with a signed one-fork smoke before relying on it; the tick remains the
fallback for an escaped or unobservable child.

Add and test `TraceOptions::print_remaining_aggregates`. Preserve `true` for
the default and user-supplied scripts; use `false` for the three built-in
profiles so libdtrace cannot append an unversioned duplicate aggregation dump
after the completion record.

- [ ] **Step 4: Surface libdtrace drops**

Mirror the public `dtrace_dropdata_t` layout and register
`dtrace_handle_drop` before `dtrace_go`. The callback only increments fixed
per-kind `u64` counters in driver state. Return them in:

```rust
pub struct DTraceRunReport {
    pub principal_drops: u64,
    pub aggregation_drops: u64,
    pub dynamic_drops: u64,
    pub other_drops: u64,
}
```

Pin the macOS `DTRACEDROP_*` ordinal mapping in unit tests. Principal-buffer
drops are a truncated-stream hard error. Other nonzero drops are recorded in
the JSONL completion state and make the profile incomplete; aggregation or
dynamic drops additionally set the high-cardinality overflow flag. The parser
computes cardinality from the emitted source/pair rows instead of asking D to
maintain a second aggregation over the same keys.

- [ ] **Step 5: Forward profile arguments through auto-sudo**

Extract sudo argv reconstruction into a pure tested helper. Forward `--profile`,
`--summary-jsonl`, and `--trace-out` exactly. Select the embedded script. If
`--trace-out` is absent, create an internal `NamedTempFile`; never mix protocol
records with guest output.

- [ ] **Step 6: Parse and publish after tracing**

After DTrace returns, read the raw stream, parse it, attach command/git/binary/
host/run provenance plus the `DTraceRunReport`, atomically write the summary
with caller uid/gid when requested, render a concise human summary to stderr,
and delete only an internal raw file. A parser error preserves any existing
summary.

- [ ] **Step 7: Verify and commit**

```bash
cargo test -p carrick-cli --test trace_profile --no-fail-fast
cargo test -p carrick-cli --bin carrick trace_profile
cargo clippy -p carrick-cli -p carrick-runtime --all-targets -- -D warnings
just fmt-check
git add crates/carrick-cli crates/carrick-runtime/src/dtrace_consumer.rs \
  scripts/dtrace/dsr-profile.d scripts/dtrace/dsr-indirect.d \
  scripts/dtrace/dsr-fork.d
git commit -m "feat(trace): add built-in DSR profile selection" \
  -m "Embed bounded DTrace profiles, preserve options through auto-sudo, and atomically convert the protocol to caller-owned JSONL."
```

---

### Task 5: Implement the broad DSR phase profiler

**Files:**

- Modify: `scripts/dtrace/dsr-profile.d`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`

**Interfaces:**

- Produces exact count/total/min/max, sampled duration, incomplete-pair, and
  cache high-water records for prepare, run, translate, resolve, dispatcher,
  cache, and lifecycle phases.

- [ ] **Step 1: Add a red complete-shape fixture**

```text
DSRPROF1|count|phase=run|pid=10|kind=3|value=9
DSRPROF1|total|phase=run|pid=10|kind=3|value_ns=90000
DSRPROF1|minimum|phase=run|pid=10|kind=3|value_ns=7000
DSRPROF1|maximum|phase=run|pid=10|kind=3|value_ns=15000
DSRPROF1|sample|phase=run|pid=10|tid=4|kind=3|duration_ns=9000|interval=1024
DSRPROF1|incomplete|phase=prepare|pid=10|kind=overwrite|value=1
DSRPROF1|high-water|metric=cache-bytes|pid=10|used=4096|capacity=67108864
DSRPROF1|complete|profile=dsr|bounded=0
```

Assert exact run, incomplete, and high-water JSON rows.

- [ ] **Step 2: Pair every low-cardinality phase**

Use this pattern for run slices and repeat it for prepare, translate, resolve,
and existing syscall entry/return:

```d
carrick*:::dsr-run-begin
/pid == $target || progenyof($target)/
{
    self->run_active = 1;
    self->run_started = timestamp;
    self->run_seq++;
}

carrick*:::dsr-run-end
/(pid == $target || progenyof($target)) && self->run_active/
{
    this->ns = timestamp - self->run_started;
    @run_count[pid, arg1] = count();
    @run_total[pid, arg1] = sum(this->ns);
    @run_min[pid, arg1] = min(this->ns);
    @run_max[pid, arg1] = max(this->ns);
    self->run_active = 0;
}

carrick*:::dsr-run-end
/(pid == $target || progenyof($target)) && !self->run_active/
{ @run_missing_begin[pid] = count(); }
```

Add a separate sampled end clause gated by
`self->run_active && ((self->run_seq & 1023) == 1)` that prints a
`DSRPROF1|sample` record before the aggregate clause clears the state. A begin
while active increments an overwrite aggregation before replacing the timestamp.

- [ ] **Step 3: Aggregate events and emit stable END records**

Count every exit kind, cache event, lifecycle event, and prepare outcome. Track
cache high-water with `max(arg4)` and capacity with `max(arg5)`. Emit every
aggregation through fully specified `printa` formats:

```d
printa("DSRPROF1|count|phase=run|pid=%d|kind=%d|value=%@d\n", @run_count);
printa("DSRPROF1|total|phase=run|pid=%d|kind=%d|value_ns=%@d\n", @run_total);
printa("DSRPROF1|minimum|phase=run|pid=%d|kind=%d|value_ns=%@d\n", @run_min);
printa("DSRPROF1|maximum|phase=run|pid=%d|kind=%d|value_ns=%@d\n", @run_max);
printf("DSRPROF1|complete|profile=dsr|bounded=%d\n", bounded);
```

Reuse the tested process-tree tracker from Task 4. A normal foreground workload
must end with `bounded=0`; `bounded=1` is explicit incomplete evidence, not a
successful natural profile.

- [ ] **Step 4: Compile and run the signed smoke**

```bash
just build
otool -l target/release/carrick | grep -q __dof_carrick
CARRICK_RUN_ID=dsr-profile-smoke timeout 20 target/release/carrick trace \
  --profile dsr --summary-jsonl target/conformance/dsr-profile-smoke.jsonl -- \
  run-elf --raw --exec-backend native --native-page-profile native16k \
  --native-code-mode dsr \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_trap_floor
```

Expected: guest exits zero; JSONL contains every phase class exercised by the
fixture, represents optional absent classes explicitly, has one completion,
and reports zero required incomplete pairs and zero libdtrace drops.

- [ ] **Step 5: Cross-check and commit**

Repeat with `CARRICK_DSR_PROFILE=1`. Exact DTrace exit totals must reconcile
with Rust totals; any lifecycle-boundary delta is documented, and unexplained
differences fail the task.

```bash
git add scripts/dtrace/dsr-profile.d crates/carrick-cli/tests/trace_profile.rs
git commit -m "feat(trace): profile complete DSR phase timing" \
  -m "Pair DSR and dispatcher phases in DTrace, publish exact counts and bounded samples, and expose incomplete pairs."
```

---

### Task 6: Implement the focused indirect-site profiler

**Files:**

- Modify: `scripts/dtrace/dsr-indirect.d`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`

**Interfaces:**

- Produces source and `(source,target)` resolver counts, aggregation
  cardinality, and overflow status.

- [ ] **Step 1: Add a red high-cardinality fixture**

```text
DSRPROF1|count|phase=indirect-source|pid=10|source_pc=0x4000|value=12
DSRPROF1|count|phase=indirect-pair|pid=10|source_pc=0x4000|target_pc=0x8000|value=7
DSRPROF1|complete|profile=dsr-indirect|bounded=0
```

Assert guest PCs become numeric JSON fields, cardinality is derived as one,
and a supplied nonzero aggregation-drop report marks the profile incomplete.

- [ ] **Step 2: Implement the bounded D program**

```d
carrick*:::dsr-resolve-begin
/(pid == $target || progenyof($target)) && arg1 == 2/
{
    @source[pid, arg2] = count();
    @pair[pid, arg2, arg3] = count();
}
```

Reuse the process-tree tracker and use a 15-second fallback tick. Emit source,
pair, an exact indirect total, and one completion record. The Rust parser
derives source/pair cardinality and combines it with the libdtrace drop report.
Do not attach to `dsr-run-end`, which would duplicate the resolver stream.

- [ ] **Step 3: Run direct V8**

```bash
CARRICK_DSR_PROFILE=1 CARRICK_RUN_ID=dsr-indirect-v8 timeout 30 \
  target/release/carrick trace \
  --profile dsr-indirect \
  --summary-jsonl target/conformance/dsr-indirect-v8.jsonl -- \
  run --name dsr-indirect-v8 --max-traps 18446744073709551615 \
  --raw --fs host --entrypoint /opt/nodejs-conformance/bin/node24 \
  --exec-backend native --native-page-profile native16k \
  --native-code-mode dsr \
  localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 \
  /opt/nodejs-conformance/fixtures/v8-smoke.js
```

Expected: `v8-smoke ok`; source counts sum to the script's exact indirect total
and reconcile with the Rust profile's indirect resolver count from the same
run; top pairs are present with zero aggregation/dynamic drops.

- [ ] **Step 4: Commit**

```bash
git add scripts/dtrace/dsr-indirect.d crates/carrick-cli/tests/trace_profile.rs
git commit -m "feat(trace): attribute indirect DSR resolver sites" \
  -m "Keep high-cardinality source/target aggregation out of the broad profiler and report cardinality and overflow explicitly."
```

---

### Task 7: Implement the DSR fork and exec lifecycle profiler

**Files:**

- Modify: `scripts/dtrace/dsr-fork.d`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`

**Interfaces:**

- Reuses the stable DSR cache-lifecycle probes plus existing fork and syscall
  probes; it does not add fork-only runtime instrumentation.
- Reports repair/reset duration and the time from each lifecycle boundary to
  the child's next DSR prepare.

- [ ] **Step 1: Add a red lifecycle fixture**

```text
DSRPROF1|sample|phase=fork-child-repair|pid=21|tid=21|duration_ns=1200
DSRPROF1|sample|phase=first-prepare-after-fork|pid=21|tid=21|duration_ns=800
DSRPROF1|sample|phase=exec-reset|pid=21|tid=21|duration_ns=900
DSRPROF1|sample|phase=first-prepare-after-exec|pid=21|tid=21|duration_ns=700
DSRPROF1|complete|profile=dsr-fork|bounded=0
```

Assert all four samples survive parsing and that a lifecycle start without its
matching end is published as an incomplete pair.

- [ ] **Step 2: Implement process-tree lifecycle pairing**

In `scripts/dtrace/dsr-fork.d`, key associative state by process and guest
thread. Pair cache-lifecycle phases `1/2` for fork-child repair and `3/4` for
exec reset. After each repair/reset end, arm a one-shot timestamp consumed by
the next `dsr-prepare-begin` in that process.

Use `pid == $target || progenyof($target)` on Carrick probes. Reuse the existing
host `syscall::fork:entry`, `syscall::fork:return`, and Carrick `fork-*` probes
to distinguish parent and child transitions. Clear all per-process state at
`proc:::exit`; emit any still-open pair as incomplete before deletion.
Reuse the tested process-tree tracker and use a 30-second fallback tick; the
200-iteration proof must complete naturally with `bounded=0`.

- [ ] **Step 3: Exercise static PIE fork plus exec**

Build and sign the current binary, then run the existing Rust static-PIE fork
fixture for 200 iterations:

```bash
just build
otool -l target/release/carrick | grep -A2 __dof_carrick
CARRICK_RUN_ID=dsr-fork-profile timeout 60 target/release/carrick trace \
  --profile dsr-fork \
  --summary-jsonl target/conformance/dsr-fork-profile.jsonl -- \
  run-elf --raw --exec-backend native \
  --native-page-profile native16k --native-code-mode dsr \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork_exec
```

Expected: guest exits zero; every completed child has one repair interval and
one first-prepare-after-fork interval; execing children have the corresponding
reset and first-prepare-after-exec intervals; required incomplete counts are
zero.

- [ ] **Step 4: Commit**

```bash
git add scripts/dtrace/dsr-fork.d crates/carrick-cli/tests/trace_profile.rs
git commit -m "feat(trace): profile DSR fork and exec repair" \
  -m "Follow the full Carrick process tree and measure cache repair, exec reset, and first-use latency without adding fork-specific runtime state."
```

---

### Task 8: Prove disabled-probe cost and publish profiling evidence

**Files:**

- Modify: `Cargo.toml`
- Modify: `crates/carrick-cli/Cargo.toml`
- Modify: `crates/carrick-cli/src/perf_stats.rs`
- Create: `crates/carrick-cli/tests/dsr_trace_overhead.rs`
- Create: `docs/native-dsr-dtrace-profile.md`
- Create: `docs/perf-results/native-dsr-dtrace-disabled-overhead.jsonl`
- Create: `docs/perf-results/native-dsr-dtrace-enabled-overhead.jsonl`
- Modify: `docs/diagnostics-and-debugging.md`
- Modify: `docs/dynamic-syscall-rewriter.md`

- [ ] **Step 1: Add the reusable Rust measurement gate**

Add workspace `rand = "0.9.4"` and a Carrick CLI dev-dependency. Extend the
existing perf statistics module with a seeded bootstrap median-ratio interval;
pin its output with deterministic unit tests. Add an ignored
`dsr_trace_overhead` integration test with two ignored entry points. The
disabled-probe entry point requires distinct `CARRICK_DSR_BASELINE_BIN` and
`CARRICK_DSR_CANDIDATE_BIN` paths, verifies their SHA-256 values differ, and
runs the fixed ABBA schedule. The enabled-profile entry point holds the
candidate binary fixed and alternates untraced/profiled runs. Both atomically
write raw samples, provenance, summaries, confidence intervals, and the
pass/fail or report-only decision as JSONL.

```bash
cargo test -p carrick-cli --test dsr_trace_overhead bootstrap_ratio
cargo test -p carrick-cli --test dsr_trace_overhead --no-run
git add Cargo.toml Cargo.lock crates/carrick-cli/Cargo.toml \
  crates/carrick-cli/src/perf_stats.rs \
  crates/carrick-cli/tests/dsr_trace_overhead.rs
git commit -m "test(native): automate DSR probe overhead gate" \
  -m "Reuse the Rust performance harness for deterministic ABBA collection and bootstrap non-inferiority decisions across distinct signed binaries."
```

- [ ] **Step 2: Freeze distinct signed binaries**

Build the signed pre-instrumentation binary from approved design commit
`fcd17c14` in a detached temporary worktree and the signed candidate from the
completed branch. Freeze copies outside either Cargo target path:

```bash
baseline_dir="$(mktemp -d /tmp/carrick-dsr-dtrace-baseline.XXXXXX)"
git worktree add --detach "$baseline_dir" fcd17c14
(cd "$baseline_dir" && just build)
just build
mkdir -p target/perf/dsr-dtrace
cp "$baseline_dir/target/release/carrick" \
  target/perf/dsr-dtrace/baseline-carrick
cp target/release/carrick target/perf/dsr-dtrace/candidate-carrick
codesign -dv --verbose=4 target/perf/dsr-dtrace/baseline-carrick
codesign -dv --verbose=4 target/perf/dsr-dtrace/candidate-carrick
shasum -a 256 target/perf/dsr-dtrace/{baseline,candidate}-carrick
```

Record the commit, SHA-256, codesign identity, machine/OS, workload command,
and build command for each. Do not compare two paths that resolve to the same
inode or hash. Remove the detached worktree only after its frozen binary hash
is present in the evidence.

- [ ] **Step 3: Run the disabled-probe ABBA gate**

With no DTrace consumer attached, alternate binaries in ABBA order to reduce
thermal and scheduler bias:

- 30 syscall-floor samples per binary.
- 10 direct V8 samples per binary.
- identical environment, guest image, backend, page profile, code mode, and
  CPU/power conditions.

Invoke the ignored Rust gate with the two frozen binary paths and the checked-in
evidence path; do not transcribe samples by hand.

```bash
CARRICK_DSR_BASELINE_BIN=target/perf/dsr-dtrace/baseline-carrick \
CARRICK_DSR_CANDIDATE_BIN=target/perf/dsr-dtrace/candidate-carrick \
CARRICK_DSR_OVERHEAD_OUT=docs/perf-results/native-dsr-dtrace-disabled-overhead.jsonl \
  cargo test -p carrick-cli --test dsr_trace_overhead \
  disabled_probe_overhead -- --ignored --nocapture --test-threads=1
```

Write every raw sample plus run order to
`docs/perf-results/native-dsr-dtrace-disabled-overhead.jsonl`. Compute medians
and deterministic bootstrap confidence intervals. Pass only when the post/pre
median-ratio interval either includes 1.0 or lies wholly below 1.0, and its
upper bound is at most 1.02 for syscall-floor and 1.01 for direct V8. A failure
blocks landing and requires revisiting the probe closure or call-site shape; it
is not waived as expected USDT overhead.

- [ ] **Step 4: Measure enabled-profiler cost separately**

Keeping the instrumented binary fixed, measure each built-in profile against
its identical untraced workload: syscall-floor for `dsr`, direct V8 for
`dsr-indirect`, and static-PIE fork/exec for `dsr-fork`. Store raw samples and
summaries in
`docs/perf-results/native-dsr-dtrace-enabled-overhead.jsonl`. Report these as
the cost of opting into observability, not as runtime cost when probes are
disabled.

```bash
CARRICK_DSR_CANDIDATE_BIN=target/perf/dsr-dtrace/candidate-carrick \
CARRICK_DSR_ENABLED_OUT=docs/perf-results/native-dsr-dtrace-enabled-overhead.jsonl \
  cargo test -p carrick-cli --test dsr_trace_overhead \
  enabled_profile_overhead -- --ignored --nocapture --test-threads=1
```

- [ ] **Step 5: Verify hard failure behavior**

Feed malformed, truncated, duplicate-completion, and incomplete-pair streams to
the parser tests. Interrupt a live profile with SIGINT and verify the raw trace
is retained, no successful completion is invented, and no partial summary is
atomically published as complete.

- [ ] **Step 6: Document measured conclusions only**

In `docs/native-dsr-dtrace-profile.md`, document:

- CLI examples for all three profiles.
- The probe ABI and `DSRPROF1`/`carrick.dsr-profile.v1` schema versions.
- Cardinality, duration, and incomplete-pair behavior.
- Disabled and enabled overhead results with direct evidence links.
- How broad DTrace totals reconcile with `CARRICK_DSR_PROFILE=1`.
- Known measurement limitations and the exact machine/workload context.

Add a short operator-facing profile section to
`docs/diagnostics-and-debugging.md`. Update
`docs/dynamic-syscall-rewriter.md` with links to the profiler and only the
results actually measured. Do not convert projections or one-off samples into
official performance claims.

- [ ] **Step 7: Run the final repository and runtime gates**

```bash
just build
otool -l target/release/carrick | grep -A2 __dof_carrick
just ci
jq -e . docs/perf-results/native-dsr-dtrace-disabled-overhead.jsonl >/dev/null
jq -e . docs/perf-results/native-dsr-dtrace-enabled-overhead.jsonl >/dev/null
test -s target/conformance/dsr-profile-v8.jsonl
test -s target/conformance/dsr-indirect-v8.jsonl
test -s target/conformance/dsr-fork-profile.jsonl
git diff --check
git status --short
```

Expected: the full local gate passes, the signed binary retains the DOF
section, all three live profiles complete with valid summaries, evidence JSONL
parses line-by-line, and the worktree contains only intentional artifacts.

- [ ] **Step 8: Commit**

```bash
git add docs/native-dsr-dtrace-profile.md \
  docs/perf-results/native-dsr-dtrace-disabled-overhead.jsonl \
  docs/perf-results/native-dsr-dtrace-enabled-overhead.jsonl \
  docs/diagnostics-and-debugging.md docs/dynamic-syscall-rewriter.md
git commit -m "docs(native): publish DSR profiling evidence" \
  -m "Record reproducible disabled- and enabled-probe measurements, document the supported profiling interface, and keep DSR performance claims tied to checked-in evidence."
```

---

## Completion criteria

The work is complete only when all of the following are true:

- The three supported `--profile` modes work through auto-sudo and follow the
  complete Carrick process tree.
- The runtime exposes only stable scalar probe arguments, and disabled probe
  closures perform no allocation, formatting, locking, environment lookup, or
  clock read.
- Raw DTrace output remains available for diagnosis while the CLI publishes a
  deterministic, versioned JSONL summary atomically.
- Broad phase totals reconcile with `CARRICK_DSR_PROFILE=1`; indirect and fork
  profiles prove their narrower invariants on direct V8 and static-PIE
  fork/exec workloads.
- Disabled probes meet the predeclared statistical bounds; enabled overhead is
  measured and reported separately.
- `just ci`, the DOF-section check, and all three signed live runs pass from the
  repository root.
