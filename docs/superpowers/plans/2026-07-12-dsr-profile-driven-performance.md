# DSR Profile-Driven Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert every currently measured DSR long pole into either a correctness-preserving performance improvement with before/after proof or an evidence-backed stop record.

**Architecture:** Execute an ordered optimization ladder: indirect target cache, repeated preparation lookup, exec replacement, gateway transitions, then translation/publication. Freeze a signed baseline before each area, make one attributable structural change, and promote it only when fixed-order ABBA statistics and the relevant DTrace profile pass the predeclared gate.

**Tech Stack:** Rust 1.96.0, typed DSR address/generation domains, `dynasmrt` AArch64 emission, `bad64` decode oracles, `parking_lot`, `rand` deterministic bootstrap statistics, `signal-hook`, macOS libdtrace/USDT, signed native execution, and the native arm64 Docker Linux oracle for semantics only.

## Global Constraints

- Scope is Darwin-native AArch64 DSR; do not preserve or modify the legacy `brk` executor.
- Per-thread indirect target-cache storage must not exceed 256 KiB.
- Never consult Linux kernel or other GPL implementation source.
- Never run Carrick and the Docker oracle concurrently.
- Every implementation starts red, passes focused correctness tests, and ends with a signed live workload.
- Accept a performance claim only from fixed-order ABBA samples with a deterministic bootstrap interval and checked-in JSONL.
- Preserve fork correctness, code-generation invalidation, signal/fault recovery, and Go/Rust static and PIE compatibility.
- Use `just build` before running guests; verify `__dof_carrick` remains present.
- Update this plan's checkboxes and evidence notes after every completed task.

**Design authority:** `docs/superpowers/specs/2026-07-12-dsr-profile-driven-performance-design.md`

---

## File map

- `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs` owns the per-thread indirect cache layout, typed index, publication ordering, and gateway context ABI.
- `crates/carrick-runtime/src/native_darwin/dsr/emit.rs` emits the AArch64 fast-path cache lookup and contains execution oracles for emitted control flow.
- `crates/carrick-runtime/src/native_darwin/dsr/mod.rs` owns thread-local prepared-entry state, process block lookup, translation, resolve, fork, and exec lifecycle probes.
- `crates/carrick-runtime/src/native_darwin.rs` owns DSR loop boundaries and the native exec image-replacement sequence.
- `scripts/dtrace/dsr-{profile,indirect,fork}.d` are the supported machine-protocol profiles.
- `crates/carrick-cli/src/trace_profile.rs` parses `DSRPROF1` and publishes `carrick.dsr-profile.v1` JSONL.
- `crates/carrick-cli/tests/dsr_trace_overhead.rs` owns signed-binary ABBA collection and deterministic performance decisions.
- `conformance-probes/src/bin/` contains focused Linux binaries used for live DSR correctness and performance evidence.
- `docs/perf-results/` contains checked-in provenance, raw samples, summaries, and pass/fail decisions.
- `docs/native-dsr-dtrace-profile.md` is the operator-facing baseline and remaining-cost report.

---

### Task 1: Publish the profiling baseline and optimization ledger

**Files:**
- Create: `docs/native-dsr-dtrace-profile.md`
- Add: `docs/perf-results/native-dsr-dtrace-disabled-overhead.jsonl`
- Add: `docs/perf-results/native-dsr-dtrace-enabled-overhead.jsonl`
- Modify: `docs/diagnostics-and-debugging.md`
- Modify: `docs/dynamic-syscall-rewriter.md`
- Modify: `docs/superpowers/plans/2026-07-12-dsr-dtrace-profiling.md`

**Interfaces:**
- Consumes: `carrick trace --profile {dsr,dsr-indirect,dsr-fork}`, `DSRPROF1`, and the two existing overhead JSONL artifacts.
- Produces: a committed before-state with exact counts, lifecycle percentiles, overhead intervals, commands, limitations, and links used by every later task.

- [x] **Step 1: Validate the two checked-in evidence candidates**

Run:

```bash
jq -e . docs/perf-results/native-dsr-dtrace-disabled-overhead.jsonl >/dev/null
jq -e . docs/perf-results/native-dsr-dtrace-enabled-overhead.jsonl >/dev/null
jq -c 'select(.record == "decision")' \
  docs/perf-results/native-dsr-dtrace-{disabled,enabled}-overhead.jsonl
```

Expected: every line parses; disabled syscall-floor and V8 decisions have
`"pass":true`; enabled decisions are report-only with `"pass":null`.

- [x] **Step 2: Write the operator profile report**

Create `docs/native-dsr-dtrace-profile.md` with these exact measured sections:

```markdown
## Measured optimization targets

- Prepare: 45,427 calls, 66.79 ms total; 45,140 block-index hits account for
  66.08 ms while only 264 calls use the resume-entry fast path.
- Indirect V8: 416,997 successful resolver exits, 41,152 distinct missed
  targets, and all 1,024 direct-map buckets populated by at least ten targets.
- Fork/exec: child repair p50 22.5 us; outer exec replacement/reset p50
  1.581 ms; first prepare after exec p50 12.46 us.

These are same-profile diagnostic comparisons. Enabled DTrace changes absolute
latency, so counts and before/after ratios are authoritative, not the absolute
nanoseconds as untraced runtime claims.
```

Also document the three CLI invocations, `target_exit_reason`, interruption
behavior, zero-drop/incomplete-pair requirement, host, binary SHA, workload,
and the disabled/enabled overhead decisions.

- [x] **Step 3: Link the report from the two existing docs**

Add an operator-facing paragraph to `docs/diagnostics-and-debugging.md` and a
measured-results paragraph to `docs/dynamic-syscall-rewriter.md`. State that
the optimization queue is indirect cache, prepare lookup, exec subdivision,
gateway, then translation/publication.

- [x] **Step 4: Close the profiling implementation plan**

Mark Tasks 1 through 8 and completion criteria complete in
`docs/superpowers/plans/2026-07-12-dsr-dtrace-profiling.md`, citing the two
evidence files and the live PTY Ctrl-C proof. Do not mark any optimization task
complete.

- [x] **Step 5: Verify and commit the baseline**

Run:

```bash
git diff --check
jq -e . docs/perf-results/native-dsr-dtrace-disabled-overhead.jsonl >/dev/null
jq -e . docs/perf-results/native-dsr-dtrace-enabled-overhead.jsonl >/dev/null
```

Commit:

```bash
git add docs/native-dsr-dtrace-profile.md \
  docs/perf-results/native-dsr-dtrace-disabled-overhead.jsonl \
  docs/perf-results/native-dsr-dtrace-enabled-overhead.jsonl \
  docs/diagnostics-and-debugging.md docs/dynamic-syscall-rewriter.md \
  docs/superpowers/plans/2026-07-12-dsr-dtrace-profiling.md
git commit -m "docs(native): publish DSR profiling baseline" \
  -m "Record the measured long poles, disabled and enabled overhead, supported profiling commands, and fail-closed completion semantics that govern the optimization program." \
  -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 2: Add a reusable improvement-only ABBA gate

**Files:**
- Modify: `crates/carrick-cli/tests/dsr_trace_overhead.rs`
- Test: `crates/carrick-cli/tests/dsr_trace_overhead.rs`

**Interfaces:**
- Consumes: `CARRICK_DSR_BASELINE_BIN`, `CARRICK_DSR_CANDIDATE_BIN`, commit IDs, workload commands, and `bootstrap_median_ratio`.
- Produces: ignored tests `indirect_cache_improvement`, `prepare_cache_improvement`, and `gateway_improvement`, each atomically writing the existing `carrick.dsr-overhead.v1` schema.

- [x] **Step 1: Write the failing decision-policy tests**

Add a pure helper and tests:

```rust
#[derive(Clone, Copy)]
struct ImprovementPolicy {
    upper_bound: f64,
    minimum_estimate_gain: f64,
}

fn passes_improvement(interval: RatioInterval, policy: ImprovementPolicy) -> bool {
    interval.upper < policy.upper_bound
        && interval.estimate <= 1.0 - policy.minimum_estimate_gain
}

#[test]
fn improvement_policy_requires_supported_nonzero_gain() {
    let policy = ImprovementPolicy {
        upper_bound: 1.0,
        minimum_estimate_gain: 0.01,
    };
    assert!(passes_improvement(
        RatioInterval { estimate: 0.98, lower: 0.97, upper: 0.995, resamples: 10_000 },
        policy,
    ));
    assert!(!passes_improvement(
        RatioInterval { estimate: 0.995, lower: 0.98, upper: 0.999, resamples: 10_000 },
        policy,
    ));
    assert!(!passes_improvement(
        RatioInterval { estimate: 0.98, lower: 0.96, upper: 1.001, resamples: 10_000 },
        policy,
    ));
}
```

- [x] **Step 2: Run the test red**

Run:

```bash
cargo test -p carrick-cli --test dsr_trace_overhead improvement_policy -- --nocapture
```

Expected: FAIL because `ImprovementPolicy` and `passes_improvement` do not yet
exist.

- [x] **Step 3: Implement the policy and reusable binary gate**

Refactor the disabled binary comparison into:

```rust
fn run_binary_gate(
    mode: &'static str,
    gates: &[BinaryGate],
    output_env: &str,
) {
    // Reuse provenance validation, fixed ABBA collection, seeded bootstrap,
    // atomic JSONL output, scoped run-id cleanup, and final assertions.
}
```

Add ignored entry points with exact policies:

```rust
#[test]
#[ignore = "explicit opt-in indirect-cache performance gate"]
fn indirect_cache_improvement() {
    run_binary_gate(
        "indirect-cache-improvement",
        &[BinaryGate {
            workload: Workload::DirectV8,
            cycles: 5,
            policy: BinaryGatePolicy::Improvement(ImprovementPolicy {
                upper_bound: 1.0,
                minimum_estimate_gain: 0.01,
            }),
        }],
        "CARRICK_DSR_OPTIMIZATION_OUT",
    );
}

#[test]
#[ignore = "explicit opt-in prepare-cache performance gate"]
fn prepare_cache_improvement() {
    run_binary_gate(
        "prepare-cache-improvement",
        &[
            BinaryGate {
                workload: Workload::SyscallFloor,
                cycles: 15,
                policy: BinaryGatePolicy::Improvement(ImprovementPolicy {
                    upper_bound: 1.0,
                    minimum_estimate_gain: 0.01,
                }),
            },
            BinaryGate {
                workload: Workload::DirectV8,
                cycles: 5,
                policy: BinaryGatePolicy::Improvement(ImprovementPolicy {
                    upper_bound: 1.01,
                    minimum_estimate_gain: 0.0,
                }),
            },
        ],
        "CARRICK_DSR_OPTIMIZATION_OUT",
    );
}
```

The existing disabled non-inferiority and enabled report-only tests must keep
their current policies and evidence schema.

- [x] **Step 4: Run focused tests and clippy**

Run:

```bash
cargo test -p carrick-cli --test dsr_trace_overhead improvement_policy -- --nocapture
cargo test -p carrick-cli --test dsr_trace_overhead bootstrap_ratio -- --nocapture
cargo test -p carrick-cli --test dsr_trace_overhead --no-run
cargo clippy -p carrick-cli --test dsr_trace_overhead -- -D warnings
```

Expected: all tests pass and the ignored live gates compile without running.

- [x] **Step 5: Commit the reusable gate**

```bash
git add crates/carrick-cli/tests/dsr_trace_overhead.rs \
  docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md
git commit -m "test(native): gate attributable DSR improvements" \
  -m "Reuse signed-binary ABBA collection and deterministic bootstrap intervals for cache and gateway changes that must prove a nonzero workload gain." \
  -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 3: Prove the current indirect-cache collision red

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`

**Interfaces:**
- Consumes: `IndirectTargetCache::publish`, `enter_translated_with_cache`, emitted indirect lookup, typed `GuestVa`/`CacheVa`, and target generation guards.
- Produces: `dsr_indirect_cache_keeps_old_index_aliases_hot`, a deterministic execution oracle that is red with the 1,024-entry page-offset index.

- [x] **Step 1: Write the old-alias red oracle**

Add an oracle beside `dsr_indirect_flow_cache_hit_stays_in_translated_code`.
It uses executable targets separated by `0x6000`, proves those addresses alias
under the old formula without depending on the production index, publishes
both, then enters the emitted source once for each target:

```rust
#[test]
fn dsr_indirect_cache_keeps_old_index_aliases_hot() {
    let source_guest = GuestVa(0x41_000);
    let first = GuestVa(0x42_000);
    let second = GuestVa(0x48_000);
    assert_eq!(
        (first.raw() >> 2) & 1023,
        (second.raw() >> 2) & 1023,
        "fixture must collide under the old page-offset index",
    );

    let target_plan = |target: GuestVa| BlockPlan {
        start: target,
        end: GuestVa(target.raw() + 4),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Syscall {
            guest: target,
            resume: GuestVa(target.raw() + 4),
        },
    };
    let mut code = TranslationCache::new(32 * 1024).expect("allocate alias oracle");
    let first_block = emit_block(&mut code, &target_plan(first))
        .expect("emit first alias target");
    let second_block = emit_block(&mut code, &target_plan(second))
        .expect("emit second alias target");
    let source = emit_block(
        &mut code,
        &BlockPlan {
            start: source_guest,
            end: GuestVa(source_guest.raw() + 4),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Indirect {
                guest: source_guest,
                word: 0xd61f_0000, // br x0
                exit: IndirectExit {
                    kind: IndirectKind::Branch,
                    register: bad64::Reg::X0,
                    resume: GuestVa(source_guest.raw() + 4),
                },
            },
        },
    )
    .expect("emit alias source");
    let indirect = IndirectTargetCache::new();
    indirect.publish(first, CodeGeneration::INITIAL, first_block.entry());
    indirect.publish(second, CodeGeneration::INITIAL, second_block.entry());

    let mut stack = vec![0_u8; 16 * 1024];
    for target in [first, second] {
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.x[0] = target.raw();
        let mut exit = NativeDsrExit::ResolveIndirect {
            source: source_guest,
            target,
            link: None,
        };
        enter_translated_with_cache(source.entry(), &mut snapshot, &mut exit, &indirect)
            .expect("execute cached alias target");
        assert_eq!(
            exit,
            NativeDsrExit::Syscall {
                resume: GuestVa(target.raw() + 4),
            },
            "both stable targets must remain cached",
        );
    }
}
```

This executes the production emitted lookup; it does not simulate the cache in
Rust. With the old direct-map formula, publishing `second` overwrites `first`,
so the first entry returns `ResolveIndirect` instead of reaching its syscall.

- [x] **Step 2: Run red and retain the exact failure**

Run:

```bash
cargo test -p carrick-runtime \
  dsr_indirect_cache_keeps_old_index_aliases_hot --lib -- --nocapture
```

Expected: FAIL on the first target because the two targets overwrite the same
direct-map entry.

Observed: the first target returned
`ResolveIndirect { source: GuestVa(266240), target: GuestVa(270336), link: None }`
instead of `Syscall { resume: GuestVa(270340) }`.

- [x] **Step 3: Commit only the red oracle**

```bash
git add crates/carrick-runtime/src/native_darwin/dsr/oracle.rs \
  docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md
git commit -m "test(native): expose indirect-cache alias thrash" \
  -m "Alternate two executable targets that share the old page-offset index and prove the direct-mapped cache repeatedly returns to the resolver." \
  -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 4: Expand and mix the direct-mapped indirect cache

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`

**Interfaces:**
- Consumes: the red alias oracle from Task 3.
- Produces: `INDIRECT_CACHE_ENTRIES = 8192`, `indirect_cache_index(GuestVa) -> usize`, and matching emitted `eor`/`ubfx` lookup code within 256 KiB per thread.

- [x] **Step 1: Add layout and index contract tests**

```rust
#[test]
fn indirect_cache_uses_approved_256kib_layout() {
    assert_eq!(INDIRECT_CACHE_ENTRIES, 8192);
    assert_eq!(std::mem::size_of::<IndirectTargetCacheEntry>(), 32);
    assert_eq!(
        INDIRECT_CACHE_ENTRIES * std::mem::size_of::<IndirectTargetCacheEntry>(),
        256 * 1024,
    );
}

#[test]
fn mixed_index_separates_old_page_offset_aliases() {
    let first = carrick_guest_mem::GuestVa(0x4_2000);
    let second = carrick_guest_mem::GuestVa(0x4_8000);
    assert_ne!(indirect_cache_index(first), indirect_cache_index(second));
}
```

- [x] **Step 2: Run the new tests red**

```bash
cargo test -p carrick-runtime indirect_cache_ --lib -- --nocapture
```

Expected: FAIL because the table is still 1,024 entries and the old aliases
still share an index.

- [x] **Step 3: Implement the shared Rust index**

Replace the old constants/index with:

```rust
pub(super) const INDIRECT_CACHE_ENTRIES: usize = 8192;
pub(super) const INDIRECT_CACHE_MASK: u64 = (INDIRECT_CACHE_ENTRIES - 1) as u64;
pub(super) const INDIRECT_CACHE_INDEX_BITS: u32 = 13;
pub(super) const INDIRECT_CACHE_ENTRY_SHIFT: u32 = 5;

#[inline(always)]
fn indirect_cache_index(guest: carrick_guest_mem::GuestVa) -> usize {
    let raw = guest.raw();
    let mixed = raw ^ (raw >> 12);
    ((mixed >> 2) & INDIRECT_CACHE_MASK) as usize
}
```

Use `indirect_cache_index` from `publish`. Keep entry size, release publication,
clear ordering, and `DsrContext` offsets unchanged.

- [x] **Step 4: Emit the identical mixed index**

Replace the 10-bit `ubfx` with:

```rust
dynasmrt::dynasm!(assembler
    ; .arch aarch64
    ; eor x16, x17, x17, LSR #12
    ; ubfx x16, x16, #2, #super::gateway::INDIRECT_CACHE_INDEX_BITS
);
```

Retain the base load, 32-byte shift, acquire key load, target comparison,
nonzero cache-PC check, generation guard, register restoration, and miss exit.

- [x] **Step 5: Run the red oracle green and the full focused oracle**

```bash
cargo test -p carrick-runtime \
  dsr_indirect_cache_keeps_old_index_aliases_hot --lib -- --nocapture
cargo test -p carrick-runtime dsr_indirect_flow --lib -- --nocapture
cargo test -p carrick-runtime dsr_generation --lib -- --nocapture
cargo test -p carrick-runtime dsr_signal_fault --lib -- --nocapture
```

Expected: both old-alias targets remain hot and all existing
indirect/generation/signal tests pass.

- [x] **Step 6: Commit the cache experiment**

```bash
git add crates/carrick-runtime/src/native_darwin/dsr/gateway.rs \
  crates/carrick-runtime/src/native_darwin/dsr/emit.rs \
  docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md
git commit -m "perf(native): mix and expand the DSR indirect cache" \
  -m "Use the approved 256 KiB per-thread budget and mix page-number bits into the emitted direct-map index so hot targets with identical page offsets no longer evict each other." \
  -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 5: Gate and either promote or reject the indirect-cache experiment

**Files:**
- Create: `docs/perf-results/native-dsr-indirect-cache-v1.jsonl`
- Create: `docs/perf-results/native-dsr-indirect-cache-hit-v1.jsonl`
- Create: `conformance-probes/src/bin/perf_dsr_indirect.rs`
- Modify: `crates/carrick-cli/tests/dsr_trace_overhead.rs`
- Modify: `docs/native-dsr-dtrace-profile.md`
- Modify: `docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md`

**Interfaces:**
- Consumes: signed before/after binaries, `indirect_cache_improvement`, and `dsr-indirect`.
- Produces: an accepted new baseline or an explicit escalation to two-way associativity within 256 KiB.

- [x] **Step 1: Freeze distinct signed binaries**

Build the pre-cache commit in a detached temporary worktree and current HEAD in
this worktree. Copy to:

```text
target/perf/dsr-indirect-cache/baseline-carrick
target/perf/dsr-indirect-cache/candidate-carrick
```

Record commits, SHA-256 values, inodes, codesign details, host, and power state.
Reject identical hashes or inodes.

Capture `baseline_commit` and `candidate_commit` shell variables when the
binaries are frozen. Pass those recorded values to the gate; do not recompute
them from a later documentation or harness commit.

- [x] **Step 2: Run signed correctness and V8 smoke**

```bash
just build
otool -l target/release/carrick | grep -A2 __dof_carrick
CARRICK_RUN_ID=dsr-cache-v1 target/release/carrick run \
  --name dsr-cache-v1 --max-traps 18446744073709551615 --raw --fs host \
  --entrypoint /opt/nodejs-conformance/bin/node24 \
  --exec-backend native --native-page-profile native16k --native-code-mode dsr \
  localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 \
  /opt/nodejs-conformance/fixtures/v8-smoke.js
scripts/sudo/kill.sh dsr-cache-v1
```

Expected: `v8-smoke ok` and no leftover stamped processes.

- [x] **Step 3: Bound the monomorphic hit-path cost**

Build `perf_dsr_indirect` as an AArch64 static PIE. Its single inline `blr`
site calls one fixed target and returns to one fixed resume PC in 20,000-call
batches, so both directions exercise stable emitted-cache hits after warmup.
Run it under Carrick and native Linux for mechanism validation, then collect 30
ABBA samples per binary:

```bash
CARRICK_DSR_BASELINE_BIN=target/perf/dsr-indirect-cache/baseline-carrick \
CARRICK_DSR_CANDIDATE_BIN=target/perf/dsr-indirect-cache/candidate-carrick \
CARRICK_DSR_BASELINE_COMMIT="$baseline_commit" \
CARRICK_DSR_CANDIDATE_COMMIT="$candidate_commit" \
CARRICK_DSR_HIT_OUT=docs/perf-results/native-dsr-indirect-cache-hit-v1.jsonl \
  cargo test -p carrick-cli --test dsr_trace_overhead \
  indirect_cache_hit_noninferiority -- --ignored --nocapture --test-threads=1
```

Expected: the candidate/base p50 ratio interval includes or lies below 1.0 and
its upper bound is at most 1.02.

- [x] **Step 4: Run the improvement ABBA gate**

```bash
CARRICK_DSR_BASELINE_BIN=target/perf/dsr-indirect-cache/baseline-carrick \
CARRICK_DSR_CANDIDATE_BIN=target/perf/dsr-indirect-cache/candidate-carrick \
CARRICK_DSR_BASELINE_COMMIT="$baseline_commit" \
CARRICK_DSR_CANDIDATE_COMMIT="$candidate_commit" \
CARRICK_DSR_OPTIMIZATION_OUT=docs/perf-results/native-dsr-indirect-cache-v1.jsonl \
  cargo test -p carrick-cli --test dsr_trace_overhead \
  indirect_cache_improvement -- --ignored --nocapture --test-threads=1
```

Expected for promotion: candidate V8 median is at least 1% faster and the
bootstrap ratio upper bound is below 1.0.

- [x] **Step 5: Re-run the exact indirect profile**

```bash
CARRICK_RUN_ID=dsr-cache-v1-profile target/release/carrick trace \
  --profile dsr-indirect \
  --trace-out target/conformance/dsr-indirect-v8-cache-v1.raw \
  --summary-jsonl target/conformance/dsr-indirect-v8-cache-v1.jsonl -- \
  run --name dsr-cache-v1-profile --max-traps 18446744073709551615 \
  --raw --fs host --entrypoint /opt/nodejs-conformance/bin/node24 \
  --exec-backend native --native-page-profile native16k --native-code-mode dsr \
  localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 \
  /opt/nodejs-conformance/fixtures/v8-smoke.js
```

Expected: complete, zero drops/incomplete pairs, exact total equals source and
pair sums, and resolver exits fall materially from 416,997.

- [x] **Step 6: Apply the decision table**

- Promote v1 only if correctness is green, the monomorphic hit-path bound and
  V8 improvement gate pass, and resolver exits fall.
- If resolver exits fall but wall time is inconclusive, record v1 as rejected
  and execute a two-way 4,096-set cache experiment using the same 256 KiB.
- If two-way remains inconclusive, execute a four-way 2,048-set experiment.
- If neither associative variant passes, restore the smallest correct cache,
  record the area as inconclusive, and move to Task 6.

Each associative experiment receives its own red alias/eviction oracle,
separate commit, signed binary, JSONL, and the same V8 gate. Never stack an
untested variant on an unaccepted one.

- [x] **Step 7: Commit the accepted evidence or rejection record**

Use subject `perf(native): promote the DSR indirect cache` for an accepted
variant or `docs(native): record indirect-cache experiment` when all bounded
variants are inconclusive. The body must name exact resolver counts, wall-time
interval, and verification commands.

**Promotion record:** accepted direct-mapped v1 at `f70ec7f8`. Signed baseline
`905b2c11` (`2123a8f9…`, inode 22906259) and candidate (`e38e6b04…`, inode
22906392) were distinct and ad-hoc signed. Direct V8 p50 changed 7982.07 ms to
7883.38 ms; ratio estimate 0.986873, 95% interval 0.967409–0.999295. The
monomorphic hit-path ratio was 0.980442, interval 0.943388–1.003053 against the
1.02 limit. The complete zero-drop indirect profile reduced successful
resolver exits from 416,997 to 132,213 (68.3%) while distinct missed targets
held at 41,151 versus 41,152. No associative fallback is warranted.

---

### Task 6: Turn the last prepared entry into a persistent validated cache

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`

**Interfaces:**
- Consumes: `ThreadTranslator.resume_entry`, `PreparedEntry`, `CodeGeneration`, and `NativeMappedMemory::dsr_generation_observation`.
- Produces: persistent last-prepared-entry lookup that is cleared on fork/exec and invalidated on generation mismatch.

- [x] **Step 1: Write red cache-state tests**

```rust
#[test]
fn repeated_prepare_keeps_valid_last_entry_hot() {
    let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001]).expect("map test memory");
    let snapshot = super::super::NativeUcontextSnapshot {
        pc: guest.raw(),
        ..Default::default()
    };
    let mut translator = super::ThreadTranslator::new(16 * 1024)
        .expect("create translator");
    let first = translator
        .prepare_entry::<false>(&memory, &snapshot)
        .expect("prepare first entry");
    let before = translator.profile_snapshot();
    let second = translator
        .prepare_entry::<false>(&memory, &snapshot)
        .expect("prepare repeated entry");
    let after = translator.profile_snapshot();
    assert_eq!(first.entry, second.entry);
    assert_eq!(after.one_entry_hits - before.one_entry_hits, 1);
}

#[test]
fn generation_change_discards_last_prepared_entry() {
    let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001]).expect("map test memory");
    let snapshot = super::super::NativeUcontextSnapshot {
        pc: guest.raw(),
        ..Default::default()
    };
    let mut translator = super::ThreadTranslator::new(16 * 1024)
        .expect("create translator");
    let first = translator
        .prepare_entry::<false>(&memory, &snapshot)
        .expect("prepare first entry");
    let changed = memory
        .note_dsr_code_mutation(guest.raw(), 4)
        .expect("record code mutation")
        .expect("DSR generation");
    let before = translator.profile_snapshot();
    let second = translator
        .prepare_entry::<false>(&memory, &snapshot)
        .expect("prepare after mutation");
    let after = translator.profile_snapshot();
    assert_eq!(second.generation, changed);
    assert_ne!(first.generation, second.generation);
    assert_eq!(after.one_entry_hits, before.one_entry_hits);
    assert_ne!(first.entry, second.entry);
}
```

- [x] **Step 2: Run red**

```bash
cargo test -p carrick-runtime repeated_prepare_keeps_valid_last_entry_hot --lib -- --nocapture
cargo test -p carrick-runtime generation_change_discards_last_prepared_entry --lib -- --nocapture
```

Expected: `repeated_prepare_keeps_valid_last_entry_hot` fails because the normal
prepare path never publishes the slot. The generation-change test is a safety
oracle and may already pass; it must remain green after publication changes.

- [x] **Step 3: Implement persistent publication and validation**

Replace `self.resume_entry.take()` with a non-consuming copy of the typed tuple.
After any successful fallback lookup/translation, publish:

```rust
self.resume_entry = Some((guest, generation, entry));
```

On a matching guest PC with mismatched generation, clear the slot before the
fallback. Preserve existing clears in `after_fork_child` and `reset_for_exec`.
Do not add an untyped raw-PC cache.

- [x] **Step 4: Run focused correctness**

```bash
cargo test -p carrick-runtime repeated_prepare --lib -- --nocapture
cargo test -p carrick-runtime generation_change_discards --lib -- --nocapture
cargo test -p carrick-runtime dsr_generation --lib -- --nocapture
cargo test -p carrick-runtime dsr_concurrency --lib -- --nocapture
cargo test -p carrick-runtime dsr_fork --lib -- --nocapture
```

Expected: persistent hits occur only at the current generation and all
fork/invalidation/concurrency tests pass.

- [x] **Step 5: Commit the experiment**

```bash
git add crates/carrick-runtime/src/native_darwin/dsr/mod.rs \
  docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md
git commit -m "perf(native): retain validated DSR prepared entries" \
  -m "Publish successful prepares into a persistent typed last-entry slot so repeated syscall resumes avoid the process block index while generation checks remain authoritative." \
  -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 7: Gate and either promote or reject the prepare-cache experiment

**Files:**
- Create: `docs/perf-results/native-dsr-prepare-cache-v1.jsonl`
- Modify: `docs/native-dsr-dtrace-profile.md`
- Modify: `docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md`

**Interfaces:**
- Consumes: signed before/after binaries, `prepare_cache_improvement`, and the broad `dsr` profile.
- Produces: accepted persistent last-entry cache, bounded four-entry fallback, or an evidence-backed stop record.

- [x] **Step 1: Freeze signed before/after binaries with provenance**

Use a detached worktree for the pre-prepare commit and copy distinct binaries to
`target/perf/dsr-prepare-cache/{baseline,candidate}-carrick`. Record SHA-256,
inodes, commits, codesign, host, and power. Capture the two commit IDs in
`baseline_commit` and `candidate_commit` before later harness or documentation
commits can move `HEAD`.

- [x] **Step 2: Run the improvement gate**

```bash
CARRICK_DSR_BASELINE_BIN=target/perf/dsr-prepare-cache/baseline-carrick \
CARRICK_DSR_CANDIDATE_BIN=target/perf/dsr-prepare-cache/candidate-carrick \
CARRICK_DSR_BASELINE_COMMIT="$baseline_commit" \
CARRICK_DSR_CANDIDATE_COMMIT="$candidate_commit" \
CARRICK_DSR_OPTIMIZATION_OUT=docs/perf-results/native-dsr-prepare-cache-v1.jsonl \
  cargo test -p carrick-cli --test dsr_trace_overhead \
  prepare_cache_improvement -- --ignored --nocapture --test-threads=1
```

Expected for promotion: syscall-floor estimate improves by at least 1% with
upper bound below 1.0; V8 upper bound stays at or below 1.01.

- [x] **Step 3: Re-run the broad profile and reconcile**

Use the exact syscall-floor command from the profiling baseline. Require at
least 90% of the former 45,140 block-index outcomes to become resume-entry hits,
with zero drops and incomplete pairs.

- [x] **Step 4: Apply the bounded fallback**

If one persistent entry misses the 90% count goal or wall gate, replace it with
a four-entry thread-local direct map keyed by mixed guest PC and guarded by
`CodeGeneration`. Give that variant its own tests, commit, signed binaries, and
`native-dsr-prepare-cache-v2.jsonl`. If v2 also fails the wall gate, record the
area inconclusive and restore the smallest correct state.

- [x] **Step 5: Commit the decision**

Commit the accepted evidence and report update, or a rejection record naming
both variants and their intervals. Promote the accepted candidate as the exec
area's baseline.

**Promotion record:** accepted the one-entry candidate at `23993da4`; the
four-entry fallback was not run. Signed baseline `a0b22a2e` (`e38e6b04…`, inode
22907801) and candidate (`fa8532b8…`, inode 22907932) were distinct. The
syscall-floor p50 changed 0.705 us to 0.678 us; ratio 0.960340, interval
0.934247–0.989146. V8 ratio was 0.996667, interval 0.992741–1.002235 against
1.01. The complete broad profile moved 43,986 outcomes (97.4% of the old
block-hit count) to `ResumeEntryHit`: 44,250 resume hits, 1,151 block hits, and
23 translations. Commit `5724f9a6` also makes `--profile dsr` enable the
required const-specialized runtime probes automatically; its exact operator
command completed naturally with zero drops and incomplete pairs.

---

### Task 8: Subdivide the exec replacement interval

**Files:**
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `scripts/dtrace/dsr-fork.d`
- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Test: `crates/carrick-cli/tests/trace_profile.rs`

**Interfaces:**
- Consumes: existing `dsr-cache-lifecycle` exec begin/end probes and `dsr-fork` pairing.
- Produces: stable scalar lifecycle phases for unmap, map/protection, cache reset/allocation, relocation/vvar, and translator handoff; JSONL samples reconcile with the outer interval.

- [x] **Step 1: Add red ABI and bundled-script tests**

Define typed ordinals without renumbering existing phases:

```rust
ExecImageUnmapBegin = 5,
ExecImageUnmapEnd = 6,
ExecImageMapBegin = 7,
ExecImageMapEnd = 8,
ExecCacheResetBegin = 9,
ExecCacheResetEnd = 10,
ExecRelocationBegin = 11,
ExecRelocationEnd = 12,
ExecTranslatorHandoffBegin = 13,
ExecTranslatorHandoffEnd = 14,
```

Extend ABI uniqueness tests and require `dsr-fork.d` to emit samples named
`exec-image-unmap`, `exec-image-map`, `exec-cache-reset`, `exec-relocation`, and
`exec-translator-handoff`.

- [x] **Step 2: Run red**

```bash
cargo test -p carrick-observability dsr_probe_abi --lib -- --nocapture
cargo test -p carrick-cli --test trace_profile fork_profile -- --nocapture
```

Expected: new enum variants and sample names are absent.

- [x] **Step 3: Instrument non-overlapping runtime boundaries**

Fire the typed begin/end pairs around the exact operations inside native exec
replacement. Keep arguments scalar: tid, phase, used bytes, block count, and
generation-page count. Do not clock inside Rust; DTrace supplies timestamps.

- [x] **Step 4: Pair and reconcile in `dsr-fork.d`**

Use thread-local start timestamps and open/overwrite/missing-begin aggregates
for every new phase. Emit sampled duration rows. Add an `exec-accounted` exact
total and verify the sum of subphase durations does not exceed the outer
`exec-reset` duration for the same pid/tid; emit incomplete rows on mismatch.

- [x] **Step 5: Run parser, probe, live profile, and 220-sample gate**

```bash
cargo test -p carrick-observability dsr_probe_abi --lib -- --nocapture
cargo test -p carrick-cli --bin carrick trace_profile::tests:: -- --nocapture
cargo test -p carrick-cli --test trace_profile -- --nocapture
just build
```

Run the existing 220-iteration static-PIE fork/exec workload under `dsr-fork`.
Expected: 220 samples per outer and subphase class, zero drops/incomplete pairs,
and per-event subphase sums bounded by the outer interval.

- [x] **Step 6: Commit the subdivision**

```bash
git add crates/carrick-observability/src/probes.rs \
  crates/carrick-runtime/src/native_darwin.rs \
  scripts/dtrace/dsr-fork.d crates/carrick-cli/src/trace_profile.rs \
  crates/carrick-cli/tests/trace_profile.rs
git commit -m "diagnostics(native): subdivide DSR exec replacement" \
  -m "Attribute the outer exec interval to non-overlapping image, cache, relocation, and translator phases before choosing a structural optimization." \
  -m "Co-Authored-By: Codex <codex@openai.com>"
```

**Initial live record:** 220 complete samples per phase, natural completion,
zero drops/incomplete pairs, and every subphase sum below its matching outer
interval (maximum accounted/outer ratio 0.9755). P50/p95: image map plus
protections/vvar 1.055/1.165 ms; reusable cache reset 477.8/529.1 us; old-image
unmap 84.5/110.9 us; translator handoff 14.4/18.8 us; relocation 9.2/16.4 us;
outer reset 1.724/1.885 ms. Mapping contributes 61.7% of summed outer time,
cache reset 26.7%, unmap 5.0%, handoff 0.9%, and relocation 0.6%. Median
unaccounted boundary work is 91.1 us. The clean committed rerun in Task 9 is
the selection authority.

---

### Task 9: Select the exec implementation from measured authority

**Files:**
- Create one of:
  - `docs/superpowers/plans/2026-07-12-dsr-exec-mapping-performance.md`
  - `docs/superpowers/plans/2026-07-12-dsr-exec-cache-reset-performance.md`
  - `docs/superpowers/plans/2026-07-12-dsr-exec-relocation-performance.md`
  - `docs/superpowers/plans/2026-07-12-dsr-exec-handoff-performance.md`
- Modify: `docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md`

**Interfaces:**
- Consumes: the 220-sample subphase JSONL from Task 8.
- Produces: one focused, approved implementation plan for the largest reproducible subphase; no exec optimization occurs before this selection.

- [ ] **Step 1: Rank p50, p95, and total contribution**

Aggregate each subphase across 220 samples and compute its fraction of the outer
1.581 ms p50. Record noise and incomplete-pair status.

- [ ] **Step 2: Select by deterministic rule**

- Choose mapping when unmap plus map/protection is the largest contribution.
- Choose cache reset when reset/allocation alone is largest.
- Choose relocation when relocation/vvar is largest.
- Choose handoff when translator installation/thread-local clearing is largest.
- If no subphase contributes at least 30% or the ranking changes across two
  complete reruns, record exec as not yet attributable and move to Task 10.

- [ ] **Step 3: Write the focused child plan**

The selected plan must include a red mechanism test, exact implementation,
220-sample before/after gate requiring at least 10% improvement in both selected
subphase and outer exec p50, vfork/non-leader exec/static/PIE correctness, and a
revert rule. Commit that plan before executing it.

- [ ] **Step 4: Execute the selected plan inline**

Use `superpowers:executing-plans`, promote only a passing candidate, and update
this umbrella plan with commit, evidence path, old/new p50/p95, and remaining
exec ranking.

---

### Task 10: Establish a low-perturbation gateway benchmark

**Files:**
- Create: `conformance-probes/src/bin/perf_dsr_gateway.rs`
- Modify: `crates/carrick-cli/tests/perf_support/cases.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`
- Create: `docs/perf-results/native-dsr-gateway-baseline.jsonl`

**Interfaces:**
- Consumes: DSR gateway entry/exit, scalar and SIMD guest states, existing performance schema.
- Produces: untraced scalar and SIMD gateway distributions that can support an assembly change without DTrace boundary cost.

- [ ] **Step 1: Write the probe and host parser tests red**

The probe prints:

```text
gateway_scalar_p50_us=<f>
gateway_scalar_p95_us=<f>
gateway_scalar_min_us=<f>
gateway_simd_p50_us=<f>
gateway_simd_p95_us=<f>
gateway_simd_min_us=<f>
iters=20000
```

The scalar loop crosses a DSR syscall boundary without guest SIMD operations.
The SIMD loop seeds and verifies all observable vector registers around the same
boundary. Add the case to the existing performance registry.

- [ ] **Step 2: Run parser tests red, then implement the probe**

Build via `scripts/build-probes.sh --native-pie`; run signed DSR; require exact
SIMD sentinel preservation and finite positive metrics.

- [ ] **Step 3: Collect baseline ABBA/noise evidence**

Run at least 30 repetitions, record p50/p95/min/IQR and host/power provenance,
and check in `native-dsr-gateway-baseline.jsonl`.

- [ ] **Step 4: Audit gateway instructions against the oracle**

Classify every save/restore as guest-observable, host-ABI-required, signal
recovery-required, or redundant. Record the disassembly and category in the
gateway child plan. No assembly is removed in this task.

- [ ] **Step 5: Write and execute a focused gateway child plan**

Create `docs/superpowers/plans/2026-07-12-dsr-gateway-performance.md`. The first
variant removes only instructions proven redundant. A scalar/SIMD specialization
is allowed only when emitted block metadata proves which state may be omitted.
Acceptance is at least 5% syscall-floor improvement with upper ratio below 1.0,
no V8 regression beyond 1%, and all register/signal/kick/fault oracles green.

---

### Task 11: Reprofile translation and publication after cache fixes

**Files:**
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`
- Modify: `scripts/dtrace/dsr-profile.d`
- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Create: `docs/perf-results/native-dsr-translation-subphases.jsonl`

**Interfaces:**
- Consumes: promoted indirect/prepare/exec/gateway baselines.
- Produces: decode, plan, emit, publication/index, and duplicate-wait attribution plus a deterministic decision whether translation still warrants work.

- [ ] **Step 1: Add stable typed subphase ordinals and red ABI tests**

Define begin/end probe phases for decode, plan, emit, publication/index update,
and duplicate-publication wait. Keep scalar args and compile-time uniqueness.

- [ ] **Step 2: Instrument exact non-overlapping boundaries**

Use DTrace timestamps. Preserve the current total translate pair so subphase
sums reconcile with it. Emit open/overwrite/missing-begin rows.

- [ ] **Step 3: Profile cold start, V8, code churn, and concurrent publication**

Run each Carrick workload separately. Require zero drops/incomplete pairs and
check in the aggregate JSONL with provenance.

- [ ] **Step 4: Apply the translation decision rule**

- If no subphase contributes at least 10% of relevant untraced workload wall
  time, record translation as below the next pole and stop.
- If collection/index lookup dominates, benchmark typed `BTreeMap`, std
  `HashMap`, and `hashbrown` candidates before selecting one.
- If publication locking/wait dominates, write a focused concurrency design;
  do not introduce lock-free reclamation directly from this umbrella task.
- If decode/emit dominates, benchmark `bad64`/`dynasmrt` usage and batch shape
  before changing instruction coverage.

- [ ] **Step 5: Write, commit, and execute the selected focused child plan**

Require at least 10% improvement in the selected subphase and an improved cold
or code-churn wall-time gate, with duplicate-publication, generation,
invalidation, and fork concurrency remaining green.

---

### Task 12: Run the ecosystem and final remaining-cost campaign

**Files:**
- Create: `docs/perf-results/native-dsr-profile-driven-final.jsonl`
- Modify: `docs/native-dsr-dtrace-profile.md`
- Modify: `docs/dynamic-syscall-rewriter.md`
- Modify: `docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md`

**Interfaces:**
- Consumes: every accepted candidate/evidence artifact and every inconclusive stop record.
- Produces: final ranked remaining costs and a green correctness/performance handoff.

- [ ] **Step 1: Run focused and full repository gates**

```bash
just fmt-check
just clippy
just lint-domains
just build
otool -l target/release/carrick | grep -A2 __dof_carrick
just ci
```

Expected: all pass from the repository root.

- [ ] **Step 2: Run signed ecosystem workloads sequentially**

Run static and PIE Rust, static and PIE Go, V8/Node, fork/vfork/exec, and the
generation/invalidation/concurrency probe set. Stamp and clean every run ID.
Do not run Docker concurrently.

- [ ] **Step 3: Run Linux semantic comparisons separately**

For any behavior-affecting probe, run the native arm64 Docker oracle after all
Carrick runs complete. Use in-container `bpftrace` when syscall shape is needed.

- [ ] **Step 4: Re-run all three DSR profiles**

Require complete summaries, zero drops/incomplete pairs, exact reconciliation,
and current host/binary provenance. Compare the final ranking with the initial
prepare/indirect/exec/gateway/translation baseline.

- [ ] **Step 5: Publish final evidence and stop records**

Document every accepted change, rejected variant, confidence interval, and
remaining pole. Mark an area complete only with a promoted improvement or the
design's two-variant evidence-backed stop condition.

- [ ] **Step 6: Commit the final campaign**

Use a `docs(native): record profile-driven DSR performance` commit with a body
that names exact correctness gates, before/after workload medians, confidence
intervals, and remaining architectural issues.
