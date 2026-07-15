# Biased Exclusive-Fusion Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure why biased AArch64 exclusive regions still trap, then natively
fuse the measured canonical regions without context memory accesses inside the
exclusive reservation window.

**Architecture:** Refactor the existing direct-only recognizer into a shared,
typed analysis that records structural and lowering dispositions for both
address modes. Extend `NATIVEPERF1` with execution-weighted and unique-site
coverage, capture a pre-enablement census, then add a biased emitter that saves
scratch state before `LDXR`, materializes and validates the host address, and
uses typed recovery for every pre-load, in-region, and post-store interruption.

**Tech Stack:** Rust 1.96.0, AArch64 DSR JIT (`bad64`, `dynasmrt`),
`parking_lot`, the `NATIVEPERF1` pipe protocol, Python 3 standard library,
Carrick's signed-build and differential conformance tooling.

## Global Constraints

- Never read Linux kernel or other GPL source. Use Carrick's current code,
  AArch64 architectural semantics, man-pages/specs, and the Docker oracle.
- Keep ordinary memory/context accesses out of the interval from native
  exclusive load through native exclusive store.
- Preserve width, family, acquire/release, status-register, retry, NZCV,
  x18/x28 virtualization, signal, and fault semantics.
- Every unproven shape keeps the current sensitive emulator path with a stable
  typed rejection reason; no coarse-lock or generic host-atomic replacement.
- Do not reserve physical x18 in this plan.
- Profile-off runs perform no new per-gateway measurement work. Profiled runs
  route optimization; untraced signed runs are performance authority.
- Do not increase the 1,000,000 W1 gateway ceiling, the c94 timeout, or the
  committed `20x`/`10x` targets.
- Build and sign with `just build` before guest execution. Give every run a
  unique `CARRICK_RUN_ID` and clean only that ID with
  `scripts/sudo/kill.sh <run-id>`.
- Never overlap Carrick and Docker phases.
- Preserve unrelated worktree state. Stage exact paths for every commit.

## File map

- `crates/carrick-runtime/src/native_darwin/dsr/types.rs` — typed fusion
  disposition, site metadata, scratch-register plan, and exclusive exit data.
- `crates/carrick-runtime/src/native_darwin/dsr/decode.rs` — exclusive-family
  and operand queries used by the structural recognizer and scratch allocator.
- `crates/carrick-runtime/src/native_darwin/dsr/block.rs` — shared structural
  analysis, typed rejection selection, and direct/biased planner policy.
- `crates/carrick-runtime/src/native_darwin/dsr/emit.rs` — biased exclusive
  prelude, base rewrite, memory-clean native region, exits, and recovery map.
- `crates/carrick-runtime/src/native_darwin/dsr/mod.rs` — sensitive metadata,
  unique-site process gauges, runtime disposition attribution, and recovery.
- `crates/carrick-runtime/src/native_darwin/dsr/profile.rs` — fixed-size
  per-thread disposition counters and atomic protocol frames.
- `crates/carrick-runtime/src/native_darwin/dsr/gateway_aarch64.S` — clear the
  local monitor on asynchronous signal exit.
- `crates/carrick-runtime/src/native_darwin.rs` — profile the disposition at
  the existing sensitive-emulation seam.
- `scripts/perf/native_compiler_budget.py` — strict v3 frame parser,
  reconciliation, coverage summary, and JSON serialization.
- `scripts/perf/test_native_compiler_budget.py` — protocol and coverage tests.
- `scripts/perf/evidence/native-exclusive-fusion-coverage-pre-biased-v1.json`
  — checked-in pre-enablement census.
- `scripts/perf/evidence/native-exclusive-fusion-coverage-post-biased-v1.json`
  — checked-in post-enablement census.
- `docs/native-default-conformance-campaign.md` and `handoff.md` — measured
  state, commands, artifacts, decisions, and next residual class.

---

### Task 1: Return typed fusion analysis for both address modes

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/types.rs:224-286`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/decode.rs:607-730`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/block.rs:120-570`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/block.rs:692-1270`

**Interfaces:**
- Produces: `ExclusiveFusionRejection`, `ExclusiveFusionDisposition`,
  `ExclusiveFusionSite`, `DsrScratchGpr`, `BiasedExclusiveScratch`,
  `ExclusiveRegionAnalysis`, and `analyze_exclusive_region`.
- Preserves: direct mode still produces the same `PlannedExit::ExclusiveRegion`
  for every currently accepted region.
- Supplies Task 2: one disposition attached to every sensitive exclusive exit.
- Supplies Task 4: a two-register biased scratch plan attached to eligible
  candidates, while biased execution remains disabled.

- [ ] **Step 1: Add red-first typed-result tests**

Add these tests beside `production_planner_keeps_the_trap_path_when_fusion_is_disallowed`:

```rust
#[test]
fn biased_planner_reports_canonical_region_as_eligible_but_disabled() {
    let start = GuestVa(0x4000);
    let plan = plan_via_production(
        &canonical_cas(start),
        start,
        ExclusiveFusionPolicy::BiasedDisabled,
        0x1000,
    );
    assert!(plan.instructions.is_empty());
    assert!(matches!(
        plan.exit,
        PlannedExit::Sensitive {
            fusion: Some(ExclusiveFusionSite {
                disposition: ExclusiveFusionDisposition::EligibleBackendDisabled,
                biased_scratch: Some(_),
                ..
            }),
            ..
        }
    ));
}

#[test]
fn exclusive_store_is_a_typed_non_entry_site() {
    let start = GuestVa(0x4000);
    let words = [STLXR_W3_W4_X1, SVC0];
    let plan = plan_via_production(
        &words,
        start,
        ExclusiveFusionPolicy::BiasedDisabled,
        0x1000,
    );
    assert!(matches!(
        plan.exit,
        PlannedExit::Sensitive {
            fusion: Some(ExclusiveFusionSite {
                disposition: ExclusiveFusionDisposition::Rejected(
                    ExclusiveFusionRejection::NotLoad
                ),
                ..
            }),
            ..
        }
    ));
}
```

Extend the existing negative tests to assert the exact variants
`VirtualizedBase`, `VirtualizedOperand`, `PageBoundary`,
`ScanLimitOrNoStore`, `MismatchedStore`,
`UnsupportedBodyMemoryOrSensitive`, `UnsupportedControlFlow`, and
`InvalidRetryEdge`. Add a register-saturated region and require
`BiasedNoSafeScratch` in biased policy while the same structural candidate
continues to fuse in direct policy.

- [ ] **Step 2: Run the focused test and verify red**

Run:

```bash
cargo test -p carrick-runtime --lib native_darwin::dsr::block::tests::exclusive_region_fusion -- --nocapture
```

Expected: compilation fails because the typed fusion policy/result types and
new `fusion` fields do not exist.

- [ ] **Step 3: Define the semantic types**

Add the following shapes in `types.rs`; keep constructors private to the DSR
module and reject indices above x30:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct DsrScratchGpr(u8);

impl DsrScratchGpr {
    pub(super) fn new(index: u32) -> Option<Self> {
        (index <= 30).then_some(Self(index as u8))
    }

    pub(super) const fn index(self) -> u32 {
        self.0 as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BiasedExclusiveScratch {
    pub(super) address: DsrScratchGpr,
    pub(super) bias: DsrScratchGpr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExclusiveFusionRejection {
    NotLoad,
    VirtualizedBase,
    VirtualizedOperand,
    PageBoundary,
    ScanLimitOrNoStore,
    MismatchedStore,
    UnsupportedBodyMemoryOrSensitive,
    UnsupportedControlFlow,
    InvalidRetryEdge,
    BiasedNoSafeScratch,
    BiasedAddressFormUnsupported,
    AnalysisUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExclusiveFusionDisposition {
    FusedDirect,
    FusedBiased,
    EligibleBackendDisabled,
    Rejected(ExclusiveFusionRejection),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExclusiveFusionSite {
    pub(super) guest: GuestVa,
    pub(super) word: u32,
    pub(super) disposition: ExclusiveFusionDisposition,
    pub(super) biased_scratch: Option<BiasedExclusiveScratch>,
}
```

Add `fusion: Option<ExclusiveFusionSite>` to `PlannedExit::Sensitive` and
`fusion: ExclusiveFusionSite` to `PlannedExit::ExclusiveRegion`. Non-exclusive
sensitive exits use `None`. Add `fallback: SensitiveExit` to
`ExclusiveRegionExit`, initialized as the original exclusive load's
`SensitiveKind::Exclusive(load_word)` with `resume = start + 4`. The fused
biased block's invalid-address stub consumes this payload; it is not an
optional diagnostic.

- [ ] **Step 4: Refactor the recognizer without changing direct behavior**

In `block.rs`, replace the `Option` result with:

```rust
enum ExclusiveRegionAnalysis {
    Candidate {
        instructions: Vec<PlannedInst>,
        exit: ExclusiveRegionExit,
        biased_scratch: Option<BiasedExclusiveScratch>,
    },
    Rejected(ExclusiveFusionRejection),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExclusiveFusionPolicy {
    Direct,
    BiasedDisabled,
    BiasedEnabled,
}
```

Rename `try_fuse_exclusive_region` to `analyze_exclusive_region`. Convert each
existing conservative `Ok(None)` to the exact rejection pinned in Step 1.
Keep decode/read errors as `Err` for `Direct`; for biased measurement, map an
analysis error to `Rejected(AnalysisUnavailable)` and preserve the sensitive
fallback.

Select two scratch registers with the existing register order
`x17..x9, x8..x0, x30, x29, x27`. A candidate is safe only when neither
register is mentioned by any planned instruction or by `retry_word`:

```rust
fn biased_exclusive_scratch(
    instructions: &[PlannedInst],
    retry_pc: GuestVa,
    retry_word: u32,
) -> Option<BiasedExclusiveScratch> {
    let mut selected = Vec::with_capacity(2);
    for index in (9_u32..=17)
        .rev()
        .chain((0_u32..=8).rev())
        .chain([30, 29, 27])
    {
        let used = instructions.iter().any(|inst| {
            let word = match inst.action {
                InstAction::Copy(word) | InstAction::Memory(MemoryAccess { word, .. }) => word,
                _ => return true,
            };
            decode::decoded_operands_mention_gpr(word, inst.guest, index)
        }) || decode::decoded_operands_mention_gpr(retry_word, retry_pc, index);
        if !used {
            selected.push(DsrScratchGpr::new(index)?);
        }
        if selected.len() == 2 {
            return Some(BiasedExclusiveScratch {
                address: selected[0],
                bias: selected[1],
            });
        }
    }
    None
}
```

Use `Direct` for `NativeAddressMode::Direct` and `BiasedDisabled` for
`NativeAddressMode::Biased`. Direct candidates still fuse. Biased candidates
remain `Sensitive` with either `EligibleBackendDisabled` or
`BiasedNoSafeScratch`.

- [ ] **Step 5: Run the focused and full runtime unit tests**

Run:

```bash
cargo test -p carrick-runtime --lib native_darwin::dsr::block::tests::exclusive_region_fusion -- --nocapture
cargo test -p carrick-runtime --lib
just fmt-check
```

Expected: all commands exit 0; current direct-fusion tests remain green and
biased tests expose typed dispositions without enabling behavior.

- [ ] **Step 6: Commit the typed analysis**

```bash
git add crates/carrick-runtime/src/native_darwin/dsr/types.rs crates/carrick-runtime/src/native_darwin/dsr/decode.rs crates/carrick-runtime/src/native_darwin/dsr/block.rs
git commit -m 'refactor(runtime): type exclusive fusion outcomes' \
  -m 'Exclusive fusion misses were collapsed into an opaque fallback, preventing biased compiler traps from being classified by cause.' \
  -m 'Share one structural recognizer across direct and biased policies, attach stable dispositions to every exclusive site, and compute a typed two-register biased scratch plan without enabling biased execution.' \
  -m 'Verified with the exclusive-region planner matrix, the full carrick-runtime library tests, and fmt-check.' \
  -m 'Co-Authored-By: Codex <codex@openai.com>'
```

### Task 2: Export reconciled execution and unique-site coverage

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/profile.rs:56-170,670-1030`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs:80-315,1030-1100,1800-1900`
- Modify: `crates/carrick-runtime/src/native_darwin.rs:1740-1860`
- Modify: `scripts/perf/native_compiler_budget.py:20-115,770-1050,2350-2915,3540-3670`
- Modify: `scripts/perf/test_native_compiler_budget.py:650-930`

**Interfaces:**
- Consumes: Task 1's `ExclusiveFusionDisposition` on sensitive metadata.
- Produces: `ExclusiveFusionClass`, four v3 protocol frames
  (`fusion-exec-a`, `fusion-exec-b`, `fusion-sites-a`, `fusion-sites-b`), and
  `fusion-coverage --input ... --output ...`.
- Guarantees: execution-class sum equals `sensitive_exclusive`; per-process
  unique-site gauges deduplicate `(guest_pc, word)` across retranslation.

- [ ] **Step 1: Add red-first Rust protocol tests**

Add `exclusive_fusion_frames_reconcile_and_fit_pipe_buf` to `profile.rs`:

```rust
#[test]
fn exclusive_fusion_frames_reconcile_and_fit_pipe_buf() {
    let mut budget = ThreadBudget::enabled_for_test(41, 42);
    budget.record_exit(ExitClass::Sensitive).expect("sensitive exit");
    budget.record_sensitive(SensitiveClass::Exclusive).expect("exclusive");
    budget
        .record_exclusive_fusion(ExclusiveFusionClass::EligibleBackendDisabled)
        .expect("fusion disposition");
    let record = budget.complete_record().expect("complete record");
    let mut snapshot = super::super::ProfileSnapshot::default();
    snapshot.exclusive_fusion_sites
        [ExclusiveFusionClass::EligibleBackendDisabled.index()] = 1;
    let frames = record
        .to_protocol_frames_with_resolver(snapshot, FlushGauges::default())
        .expect("serialize frames");
    assert!(frames.iter().all(|frame| frame.len() + 1 <= DARWIN_PIPE_BUF));
    assert!(frames.iter().any(|frame| {
        frame.contains("frame=fusion-exec-a")
            && frame.contains("fusion_eligible_backend_disabled=1")
    }));
}
```

Add a `ProcessState` test in `mod.rs` that records the same `(PC, word)` under
two generations and asserts the `EligibleBackendDisabled` unique-site gauge is
one.

- [ ] **Step 2: Add red-first Python v3 parser tests**

Add a `nativeperf_frames_v3()` fixture by extending the v2 fixture with the
four exact fusion frames. Add:

```python
def test_v3_reconciles_exclusive_fusion_execution_counts(self):
    profile = budget.parse_nativeperf(nativeperf_frames_v3())
    budget.validate_profile(profile)
    self.assertEqual(profile.version, 3)
    self.assertEqual(
        sum(
            profile.threads[0].value(frame, field)
            for frame in ("fusion-exec-a", "fusion-exec-b")
            for field in budget.FRAME_FIELDS_V3[frame]
        ),
        profile.threads[0].value("sensitive", "sensitive_exclusive"),
    )

def test_v3_rejects_unreconciled_fusion_counts(self):
    lines = nativeperf_frames_v3()
    lines = [line.replace("fusion_not_load=0", "fusion_not_load=1") for line in lines]
    with self.assertRaisesRegex(budget.BudgetError, "fusion execution mismatch"):
        budget.validate_profile(budget.parse_nativeperf(lines))
```

- [ ] **Step 3: Run both test sets and verify red**

```bash
cargo test -p carrick-runtime --lib native_darwin::dsr::profile::tests -- --nocapture
python3 -m unittest scripts.perf.test_native_compiler_budget.NativePerfTests scripts.perf.test_native_compiler_budget.NativePerfV2Tests
```

Expected: Rust fails on missing fusion counters; Python fails on missing v3
contract and fixture helpers.

- [ ] **Step 4: Implement fixed-size runtime and site accounting**

Define `ExclusiveFusionClass` with the flattened stable classes
`FusedDirect`, `FusedBiased`, `EligibleBackendDisabled`, and one class for each
Task 1 rejection. Give it exhaustive `ALL`, `COUNT`, `index`, and `field_name`
methods. Add `[u64; ExclusiveFusionClass::COUNT]` to `ThreadBudget` and
`CompleteThreadRecord`.

Replace the sensitive map value with:

```rust
#[derive(Clone, Copy)]
struct SensitiveMetadata {
    exit: types::SensitiveExit,
    fusion: Option<types::ExclusiveFusionSite>,
}
```

When `finish_exit_profiled::<true>` resolves a sensitive exit, call
`record_exclusive_fusion` for its disposition before returning the existing
`ThreadExit::Sensitive`. Profile-off uses the existing const-false path.
During translation, insert `SensitiveMetadata` for both
`PlannedExit::Sensitive` and `PlannedExit::ExclusiveRegion`: the latter uses
`exit.fallback` plus the fused site's disposition so its biased invalid-address
stub can take the existing emulator path without a missing-metadata error.

Add a process catalog:

```rust
exclusive_fusion_sites:
    [std::collections::BTreeSet<(u64, u32)>; profile::ExclusiveFusionClass::COUNT],
```

Initialize it with `std::array::from_fn`, insert `(site.guest.raw(), site.word)`
only while profiling, and expose the set lengths as
`ProfileSnapshot::exclusive_fusion_sites`. Retranslation under a new generation
therefore does not increase site breadth.

- [ ] **Step 5: Emit and strictly parse NATIVEPERF v3**

Split `ExclusiveFusionClass::ALL` at index 8 and emit execution/site frames.
Add `FRAME_FIELDS_V3` as v2 plus the four fusion frames; retain v1/v2 parsing
for checked-in historical evidence. Require v3 for new runtime output and
reconcile:

```python
fusion_executions = sum(
    thread.value(frame, field)
    for frame in ("fusion-exec-a", "fusion-exec-b")
    for field in FRAME_FIELDS_V3[frame]
)
if fusion_executions != thread.value("sensitive", "sensitive_exclusive"):
    raise BudgetError(f"fusion execution mismatch for {identity}")
```

Implement `fusion_coverage(profile)` and the CLI command. The output is a
single sorted JSON object containing schema, run ID, binary SHA, total residual
exclusive gateways, exact execution counts/shares, and per-class unique-site
counts. Per-process site gauges use the maximum reported value for each class;
execution counters sum across thread eras.

- [ ] **Step 6: Run protocol, analyzer, serialization, and runtime tests**

```bash
python3 -m unittest scripts.perf.test_native_compiler_budget.NativePerfTests scripts.perf.test_native_compiler_budget.NativePerfV2Tests scripts.perf.test_native_compiler_budget.AnalyzerTests
cargo test -p carrick-runtime --lib native_darwin::dsr -- --nocapture
just fmt-check
```

Expected: all commands exit 0; v1/v2 fixtures still parse, v3 rejects unknown or
missing fields, and every frame remains within `PIPE_BUF`.

- [ ] **Step 7: Commit the coverage protocol**

```bash
git add crates/carrick-runtime/src/native_darwin/dsr/profile.rs crates/carrick-runtime/src/native_darwin/dsr/mod.rs crates/carrick-runtime/src/native_darwin.rs scripts/perf/native_compiler_budget.py scripts/perf/test_native_compiler_budget.py
git commit -m 'feat(runtime): measure exclusive fusion coverage' \
  -m 'Exclusive gateway counts identified the dominant class but could not distinguish hot eligible regions from structural or lowering rejections.' \
  -m 'Add reconciled execution-weighted dispositions, deduplicated process site gauges, a strict backward-compatible NATIVEPERF v3 contract, and a deterministic coverage summary command.' \
  -m 'Verified with Rust protocol/retranslation tests, Python v1-v3 parser and analyzer tests, the DSR unit suite, and fmt-check.' \
  -m 'Co-Authored-By: Codex <codex@openai.com>'
```

### Task 3: Capture the pre-enablement biased coverage census

**Files:**
- Create: `scripts/perf/evidence/native-exclusive-fusion-coverage-pre-biased-v1.json`
- Modify: `docs/native-default-conformance-campaign.md`
- Modify: `handoff.md`

**Interfaces:**
- Consumes: Task 2's signed NATIVEPERF v3 binary and `fusion-coverage` command.
- Produces: the immutable evidence selecting the canonical
  `eligible-backend-disabled` class for Task 4.
- Stop condition: if the execution count for `eligible-backend-disabled` is
  zero, do not enable biased fusion; record the actual top rejection and write
  a replacement lowering/recognizer design for that class.

- [ ] **Step 1: Create a fresh Docker-only preflight**

```bash
python3 scripts/perf/native_compiler_budget.py preflight \
  scripts/perf/manifests/native-compiler-w1-v1.json \
  --output target/conformance/native-exclusive-coverage-preflight.json
```

Expected: exit 0 with a receipt for the pinned W1 image and output contract.

- [ ] **Step 2: Build, sign, and verify the measured binary**

```bash
just build
codesign --verify --verbose=2 target/release/carrick
```

Expected: both commands exit 0.

- [ ] **Step 3: Run one profile in a separate Carrick phase**

```bash
python3 scripts/perf/native_compiler_budget.py run \
  scripts/perf/manifests/native-compiler-w1-v1.json \
  --engine carrick --plane profiled --repetition 1 \
  --artifacts target/conformance/native-exclusive-coverage-pre-artifacts \
  --results target/conformance/native-exclusive-coverage-pre.jsonl \
  --preflight target/conformance/native-exclusive-coverage-preflight.json
```

Expected: cleanup is clean, NATIVEPERF v3 reconciles, and the unchanged
1,000,000 gateway ceiling remains authoritative if reached.

- [ ] **Step 4: Produce and inspect the deterministic census**

```bash
python3 scripts/perf/native_compiler_budget.py fusion-coverage \
  --input target/conformance/native-exclusive-coverage-pre.jsonl \
  --output scripts/perf/evidence/native-exclusive-fusion-coverage-pre-biased-v1.json
python3 -m json.tool scripts/perf/evidence/native-exclusive-fusion-coverage-pre-biased-v1.json
```

Expected: execution counts sum to residual `sensitive_exclusive`, site counts
are nonnegative, and `eligible-backend-disabled` is nonzero.

- [ ] **Step 5: Record the measured selection and commit**

Append the command, run ID, binary identity, exact counts/shares, site counts,
profile ceiling status, and Task 4 selection to the ledger and handoff.

```bash
git add scripts/perf/evidence/native-exclusive-fusion-coverage-pre-biased-v1.json docs/native-default-conformance-campaign.md handoff.md
git commit -m 'diagnostics(runtime): census biased fusion opportunities' \
  -m 'Biased exclusive traps were known to dominate gateway volume, but their structural eligibility and rejection breadth had not been measured.' \
  -m 'Record the reconciled W1 execution-weighted and unique-site census and select the first nonzero eligible biased lowering class without projecting it as a completed performance win.' \
  -m 'Verified with the signed W1 profile, clean scoped cleanup, strict NATIVEPERF v3 reconciliation, and deterministic coverage rendering.' \
  -m 'Co-Authored-By: Codex <codex@openai.com>'
```

### Task 4: Emit a disabled biased exclusive region with typed recovery metadata

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/types.rs:224-270`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs:100-220,1820-2130`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs:3540-3840`

**Interfaces:**
- Consumes: Task 1's `BiasedExclusiveScratch` and existing
  `ExclusiveRegionExit`.
- Produces: `BiasedExclusiveRecovery` and
  `emit_biased_exclusive_region`; the production planner remains
  `BiasedDisabled`, so this commit cannot change guest behavior.
- Supplies Task 5: a fully emitted but not yet selectable biased block with a
  recovery entry for every instruction after the first scratch spill.

- [ ] **Step 1: Add red-first emitted-code tests**

Extend `exclusive_region_emission` with a biased plan carrying scratch x17
(address) and x16 (bias). Assert:

```rust
#[test]
fn biased_region_rewrites_only_the_exclusive_base_and_keeps_pair_clean() {
    let emitted = emit_test_biased_cas().expect("emit biased CAS");
    let words = emitted_words(&emitted);
    let rewritten_load = with_base_register(LDAXR_W0_X1, 17);
    let rewritten_store = with_base_register(STLXR_W3_W4_X1, 17);
    let load = words.iter().position(|word| *word == rewritten_load).expect("load");
    let store = words.iter().position(|word| *word == rewritten_store).expect("store");
    for (offset, word) in words[load + 1..store].iter().copied().enumerate() {
        let pc = emitted.entry().host().raw() as u64 + ((load + 1 + offset) * 4) as u64;
        assert!(!word_touches_memory(word, pc), "memory word 0x{word:08x} inside pair");
    }
}

#[test]
fn biased_region_recovery_covers_every_post_spill_instruction() {
    let emitted = emit_test_biased_cas().expect("emit biased CAS");
    let offsets = emitted
        .recovery()
        .iter()
        .filter(|entry| matches!(entry.action, RecoveryAction::RecoverBiasedExclusive(_)))
        .map(|entry| entry.cache.get())
        .collect::<Vec<_>>();
    assert!(offsets.len() > 4, "prelude, pair, retry, and restores need recovery");
    assert!(offsets.windows(2).all(|pair| pair[1] == pair[0] + 4));
}
```

Also assert the current production biased planner still returns
`EligibleBackendDisabled`.

- [ ] **Step 2: Run the focused emitter tests and verify red**

```bash
cargo test -p carrick-runtime --lib native_darwin::dsr::emit::tests::exclusive_region_emission -- --nocapture
```

Expected: fails because the biased emitter and recovery action do not exist.

- [ ] **Step 3: Add typed recovery state**

Add:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BiasedExclusiveResume {
    Load,
    Retry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BiasedExclusiveRecovery {
    pub(super) scratch: super::types::BiasedExclusiveScratch,
    pub(super) resume: BiasedExclusiveResume,
}
```

Add `RecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery)` and keep
`instruction_complete()` false for it. The PC map, not `+4`, selects either the
original load PC or the original retry-branch PC.

- [ ] **Step 4: Emit the biased prelude and native region**

Implement `emit_biased_exclusive_region` with this exact ordering:

1. store address/bias scratch values to context offsets 1120/1128;
2. copy the guest base into address scratch;
3. reject an address whose access width overflows or whose upper bits exceed
   the biased fast aperture, branching to a restore-and-sensitive-exit stub;
4. materialize `host_bias.get()` with `emit_mov_u64` into bias scratch;
5. `add` bias scratch to address scratch with a flag-neutral instruction;
6. emit the exclusive load/store with only base bits `[9:5]` rewritten to the
   address scratch;
7. keep the accepted body verbatim, preserve the existing early-exit CLREX,
   and make store-failure retry at the rewritten load while scratch remains in
   host coordinates;
8. restore both scratches only on edges leaving the internal region;
9. on aperture/overflow failure, restore both scratches and call
   `emit_gateway_exit(..., fallback.resume, Some(exit.start), 6,
   gateway::sensitive_exit_address())`, using Task 1's published
   `ExclusiveRegionExit::fallback` metadata.

Map prelude and load-to-store instructions to the guest load PC with
`BiasedExclusiveResume::Load`. Map instructions after the store to the guest
retry PC with `BiasedExclusiveResume::Retry`; this prevents a kick after a
successful store from replaying the RMW.

Add an emitted slow-stub test that forces the invalid-address branch target,
asserts both scratch restores precede the status-6 sensitive gateway exit, and
asserts the exit source is the original load PC.

- [ ] **Step 5: Run emitter, DSR, and formatting tests**

```bash
cargo test -p carrick-runtime --lib native_darwin::dsr::emit::tests::exclusive_region_emission -- --nocapture
cargo test -p carrick-runtime --lib native_darwin::dsr -- --nocapture
just fmt-check
```

Expected: all exit 0; the biased production policy is still disabled.

- [ ] **Step 6: Commit the disabled lowering**

```bash
git add crates/carrick-runtime/src/native_darwin/dsr/types.rs crates/carrick-runtime/src/native_darwin/dsr/emit.rs
git commit -m 'feat(runtime): lower biased exclusive regions safely' \
  -m 'Biased memory lowering could not be reused for exclusive regions because its context accesses would sit inside the reservation window.' \
  -m 'Add a disabled scratch-based lowering that validates and biases the address before the load, rewrites only the exclusive base, keeps the pair memory-clean, and publishes load-versus-retry recovery metadata.' \
  -m 'Verified with emitted-word, memory-window, recovery-coverage, DSR unit, and formatting tests while the production biased policy remains disabled.' \
  -m 'Co-Authored-By: Codex <codex@openai.com>'
```

### Task 5: Recover asynchronous exits and enable the measured biased class

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs:1990-2195`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/block.rs:280-315`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/gateway_aarch64.S:118-132`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs:2340-2420`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/block.rs:1170-1245`

**Interfaces:**
- Consumes: Task 4's complete disabled emitter and recovery metadata.
- Produces: production `BiasedEnabled` selection for candidates with a safe
  scratch plan; all other reasons remain sensitive exits.
- Guarantees: pre-store interruption resumes at load; post-store interruption
  resumes at retry; both restore guest scratch values; signal exit clears the
  local exclusive monitor.

- [ ] **Step 1: Add red-first recovery tests**

Add tests that call `recover_rewrite_state` with distinct saved values:

```rust
#[test]
fn biased_exclusive_recovery_restores_both_scratch_registers() {
    let scratch = BiasedExclusiveScratch {
        address: DsrScratchGpr::new(17).expect("x17"),
        bias: DsrScratchGpr::new(16).expect("x16"),
    };
    let action = RecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery {
        scratch,
        resume: BiasedExclusiveResume::Load,
    });
    let mut snapshot = NativeUcontextSnapshot::default();
    snapshot.x[17] = 0xaaaa;
    snapshot.x[16] = 0xbbbb;
    recover_rewrite_state(&mut snapshot, action, 0x1717, 0x1616, 0, 0, 0)
        .expect("recover");
    assert_eq!(snapshot.x[17], 0x1717);
    assert_eq!(snapshot.x[16], 0x1616);
}
```

Add emitted-map tests forcing recovery at one pre-load, one between-pair, and
one post-store offset. Require load/load/retry guest PCs respectively. Add a
planner test requiring `FusedBiased` only for a candidate with scratch and
`BiasedNoSafeScratch` for the saturated fixture.

- [ ] **Step 2: Run focused tests and verify red**

```bash
cargo test -p carrick-runtime --lib biased_exclusive -- --nocapture
```

Expected: recovery does not handle the new action and biased policy still
reports `EligibleBackendDisabled`.

- [ ] **Step 3: Restore scratch state and preserve the correct guest PC**

Handle `RecoverBiasedExclusive` before the generic recovery match:

```rust
if let RecoveryAction::RecoverBiasedExclusive(recovery) = action {
    let address = usize::try_from(recovery.scratch.address.index())
        .map_err(|_| DsrError::CachePolicy("biased exclusive address scratch overflow".into()))?;
    let bias = usize::try_from(recovery.scratch.bias.index())
        .map_err(|_| DsrError::CachePolicy("biased exclusive bias scratch overflow".into()))?;
    snapshot.x[address] = saved_scratch;
    snapshot.x[bias] = saved_context_scratch;
    return Ok(());
}
```

Ensure every recovery entry's `PcMapEntry` is the load or retry PC described in
Task 4. Do not mark either action instruction-complete.

- [ ] **Step 4: Clear the local monitor on asynchronous signal exit**

Insert `clrex` at `_carrick_dsr_exit_signal` before switching to host ABI:

```asm
_carrick_dsr_exit_signal:
    clrex
    ldr x9, [sp]
```

This is correct for every interrupted translated region: host/signal handling
must never inherit a guest reservation. The explicit early-exit CLREX in the
emitter remains required.

- [ ] **Step 5: Enable biased selection and run all host tests**

Change `plan_block` to select `ExclusiveFusionPolicy::BiasedEnabled` for
`NativeAddressMode::Biased`. A candidate with scratch becomes
`PlannedExit::ExclusiveRegion { disposition: FusedBiased }`; rejected cases
retain their sensitive metadata.

```bash
cargo test -p carrick-runtime --lib biased_exclusive -- --nocapture
cargo test -p carrick-runtime --lib
just fmt-check
just clippy
```

Expected: all exit 0.

- [ ] **Step 6: Verify the signed assembly contains CLREX and commit**

```bash
just build
otool -tvV target/release/carrick \
  | awk '/_carrick_dsr_exit_signal:/{seen=1; next} seen && /^_/{exit} seen{print}' \
  | grep -i clrex
codesign --verify --verbose=2 target/release/carrick
```

Expected: one `clrex` appears in the signal-exit block and codesign verifies.

```bash
git add crates/carrick-runtime/src/native_darwin/dsr/mod.rs crates/carrick-runtime/src/native_darwin/dsr/block.rs crates/carrick-runtime/src/native_darwin/dsr/gateway_aarch64.S
git commit -m 'feat(runtime): enable biased exclusive fusion' \
  -m 'The measured canonical biased regions now have a memory-clean lowering, but enabling it also requires exact recovery when a kick lands before versus after the store.' \
  -m 'Restore typed scratch state, resume post-store interruptions at the guest retry branch, clear reservations on signal exit, and select only candidates with a proven scratch plan.' \
  -m 'Verified with forced recovery-map tests, the runtime unit suite, clippy, signed assembly inspection, and codesign verification.' \
  -m 'Co-Authored-By: Codex <codex@openai.com>'
```

### Task 6: Prove guest correctness and measure the real improvement

**Files:**
- Create: `scripts/perf/evidence/native-exclusive-fusion-coverage-post-biased-v1.json`
- Modify: `docs/native-default-conformance-campaign.md`
- Modify: `handoff.md`
- Preserve/commit when canonical: `scripts/conformance/oracle-cache.jsonl`

**Interfaces:**
- Consumes: Task 5's signed enabled binary and Task 3's pinned pre-census.
- Produces: differential correctness evidence, post-census, untraced W1/c94
  authority, full CI, and the next evidence-ranked rejection class.

- [ ] **Step 1: Rebuild probes and signed Carrick**

```bash
scripts/build-probes.sh
just build
codesign --verify --verbose=2 target/release/carrick
```

Expected: all exit 0.

- [ ] **Step 2: Run repeated atomic, futex, and signal stress serially**

```bash
for probe in perf_futex_pingpong futexrequeue futexwakeexact sigreenter; do
  for repetition in $(seq 1 10); do
    scripts/run-probe.sh "$probe"
  done
done
```

Expected: forty `MATCH` results, no timeout, crash, livelock, or scoped-cleanup
failure. `run-probe.sh` runs Carrick then Docker; do not launch another oracle
phase concurrently.

- [ ] **Step 3: Run the focused native workload gate**

```bash
cargo run -p carrick-conformance -- \
  --tier smoke --lane macos-native-dsr --workers 1 \
  --suite go-go_sync --suite go-go_runtime \
  --jsonl target/conformance/native-exclusive-focused.jsonl
```

Expected: the focused Go rows match their cached Docker oracle and complete
without new crashes/timeouts.

- [ ] **Step 4: Run post-change profile and render coverage**

```bash
python3 scripts/perf/native_compiler_budget.py run \
  scripts/perf/manifests/native-compiler-w1-v1.json \
  --engine carrick --plane profiled --repetition 1 \
  --artifacts target/conformance/native-exclusive-coverage-post-artifacts \
  --results target/conformance/native-exclusive-coverage-post.jsonl \
  --preflight target/conformance/native-exclusive-coverage-preflight.json
python3 scripts/perf/native_compiler_budget.py fusion-coverage \
  --input target/conformance/native-exclusive-coverage-post.jsonl \
  --output target/conformance/native-exclusive-coverage-post-summary.json
```

Expected: `eligible-backend-disabled` collapses to zero for the promoted class,
residual exclusive gateways fall, all residual executions reconcile to typed
rejections, and cleanup is clean.

- [ ] **Step 5: Run untraced W1 authority**

```bash
python3 scripts/perf/native_compiler_budget.py run \
  scripts/perf/manifests/native-compiler-w1-v1.json \
  --engine carrick --plane untraced --repetition 1 \
  --artifacts target/conformance/native-exclusive-untraced-artifacts \
  --results target/conformance/native-exclusive-untraced.jsonl \
  --preflight target/conformance/native-exclusive-coverage-preflight.json
```

Expected: natural completion with the existing max-trap ceiling and lower
wall/CPU than the pinned pre-change untraced row. If it does not improve, record
the result and re-profile before claiming a performance win.

- [ ] **Step 6: Rerun exact c94 without refreshing or overlapping Docker**

```bash
cargo run -p carrick-conformance -- \
  --tier full --lane macos-native-dsr \
  --suite go-go_internal_srcimporter --workers 1 \
  --jsonl target/conformance/native-perf-c94-post-biased.jsonl
```

Expected: the cached 3,069 ms Docker oracle remains the comparison point. Do
not increase the timeout; record completion/timeout and the measured ratio
honestly.

- [ ] **Step 7: Run the full local gate**

```bash
just ci
```

Expected: exit 0 through fmt, clippy, domain lint, deny, matrix check, build,
docs, unit tests, and integration tests.

- [ ] **Step 8: Update the ledger/handoff and commit measured evidence**

Render the already-measured post profile into its checked-in path only now,
after every clean-tree measurement and gate has completed:

```bash
python3 scripts/perf/native_compiler_budget.py fusion-coverage \
  --input target/conformance/native-exclusive-coverage-post.jsonl \
  --output scripts/perf/evidence/native-exclusive-fusion-coverage-post-biased-v1.json
cmp target/conformance/native-exclusive-coverage-post-summary.json \
  scripts/perf/evidence/native-exclusive-fusion-coverage-post-biased-v1.json
```

Expected: `cmp` exits 0, proving the durable summary is a deterministic render
of the profile inspected in Step 4.

Record pre/post execution counts, shares, unique sites, W1 wall/CPU, c94
status/ratio, probe/gate receipts, binary identity, artifacts, and the largest
remaining runtime-weighted rejection. Keep projections visibly separate from
measured results. Include `scripts/conformance/oracle-cache.jsonl` only if its
current diff came from the canonical refreshed Docker phase and still matches
the recorded c94 oracle.

```bash
git add scripts/perf/evidence/native-exclusive-fusion-coverage-post-biased-v1.json docs/native-default-conformance-campaign.md handoff.md
git add scripts/conformance/oracle-cache.jsonl
git commit -m 'perf(runtime): verify biased exclusive fusion' \
  -m 'Canonical biased exclusive regions were the largest measured removable gateway class in the native compiler profile.' \
  -m 'Record the post-promotion coverage census, differential stress evidence, untraced W1 and exact c94 results, full local gate, and the next residual typed rejection without promoting projections to measured state.' \
  -m 'Verified with forty repeated atomic/futex/signal probe matches, focused Go conformance, signed profile and untraced runs, the exact c94 lane, and just ci.' \
  -m 'Co-Authored-By: Codex <codex@openai.com>'
```

## Self-Review Results

- **Spec coverage:** Tasks 1–2 implement typed structural/lowering analysis,
  execution-weighted impact, exact unique-site breadth, stable protocol names,
  profile-off behavior, and deterministic evidence. Task 3 enforces the
  pre-enablement measurement checkpoint. Tasks 4–5 implement scratch-based
  biased lowering without physical x18, memory-clean reservation semantics,
  emulator fallback, CLREX, and load-versus-retry asynchronous recovery. Task 6
  covers red/green guest evidence, repeated stress, post-census, untraced
  authority, c94, CI, ledger, and handoff.
- **Placeholder scan:** no placeholder marker, deferred implementation
  instruction, unnamed error handling, or missing test step remains. The one conditional
  stop is explicit: zero measured eligible executions blocks enablement and
  selects the actual top rejection for a new design.
- **Type consistency:** `ExclusiveFusionDisposition` attaches to
  `ExclusiveFusionSite`; it flattens exhaustively to `ExclusiveFusionClass` for
  Task 2. `BiasedExclusiveScratch` is produced in Task 1, consumed by Task 4,
  and restored by `BiasedExclusiveRecovery` in Task 5. The same load/retry PC
  distinction is used by emitter mapping and recovery.
- **Correctness review:** post-store interruption resumes at the guest retry
  branch, so a successful atomic write is not replayed. Signal exit executes
  `CLREX`; early compare exit retains its own `CLREX`; store completion consumes
  the reservation. The fused plan publishes the original sensitive fallback,
  so an invalid biased address restores scratch state and reaches the existing
  emulator with valid metadata. No context access or profiling store appears
  inside the pair.
- **Honesty review:** the plan does not predict a c94 completion or ratio. It
  requires the unchanged ceiling/timeout and records a win only from untraced
  measured wall/CPU.
