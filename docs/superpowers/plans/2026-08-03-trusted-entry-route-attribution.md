# Trusted-Entry Route Attribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a default-off, fail-closed Darwin/AArch64 diagnostic that separates guard-fallthrough, patched-direct, and flavor-1-indirect residency in the common trusted-entry sequence without changing the normal emitted bytes, persistent wire, invalidation semantics, or guest behavior.

**Architecture:** The AArch64 leaf emitter owns an exact-value diagnostic mode and emits three adjacent, word-identical trusted sequences only when that mode is enabled. The translator derives typed route addresses from the existing trusted-entry offset, routes direct and flavor-1 indirect arrivals independently, and exports validated retirement snapshots; Carrick's trace and debug surfaces retain DTrace loss state, join sampled PCs to those snapshots, and export a versioned JSON decision receipt. The persistent ABI-8 wire remains unchanged because replay derives and validates the two additional offsets from the stored first trusted entry and its baked generation.

**Tech Stack:** Rust 2024, `dynasmrt` AArch64 emission, Carrick's translation-unit store, `serde`/`serde_json`, `clap`, Carrick's in-process libdtrace consumer, `scripts/dtrace/native-shape-census.d`, SHA-256 provenance, LLDB/core diagnostics on abnormal retirement.

## Global Constraints

- The switch is exact `CARRICK_DSR_TRUSTED_ROUTE_SPLIT=1`; absent or any other value is byte-for-byte the current emitter path.
- The diagnostic exercises the default-on persistent translation store from a dedicated, initially empty `CARRICK_DSR_STORE_DIR`; it never consults or mutates the normal ABI-8 namespace.
- Fallthrough, direct, and indirect sequence spans contain identical instruction words; each route then executes exactly one artificial unconditional branch to the common body.
- The persistent translation-unit wire and ABI stay unchanged; replay derives route geometry from the existing trusted-entry offset and baked generation.
- Generation checks, eager direct-link severing, flavor-1 inline validation, guest x17 authority, recovery metadata, and guest-visible behavior remain unchanged.
- Zero route samples, malformed rows, missing snapshots, missing PID/range coverage, overlapping spans, unequal words, DTrace errors/drops/interruption, store-authority changes, and incomplete process retirement fail closed.
- Traced wall time is perturbing diagnostic output and is never product performance evidence.
- Tier D, eager whole-image translation, guest ABI changes, and any production-default change are outside this plan.
- Remove the diagnostic switch and support code after the route decision and durable evidence are committed.

---

## File Structure

- Modify `crates/carrick-dsr-aarch64/src/emit.rs`: exact switch parsing, shared trusted-sequence renderer, diagnostic geometry, recovery coverage, and emitted route offsets.
- Modify `crates/carrick-dsr-aarch64/src/artifact_spike.rs`: derive and validate route offsets during artifact/unit replay while leaving `TrustedEntryTemplate` and the hot/cold wire unchanged.
- Modify `crates/carrick-dsr-aarch64/src/translator.rs`: typed absolute route entries, direct/indirect route selection, reset/invalidation invariants, and validated code-snapshot route spans.
- Modify `crates/carrick-runtime/src/native_darwin.rs`: export validated route spans in retirement snapshot JSON and surface dump failures loudly.
- Modify `crates/carrick-runtime/src/dtrace_consumer.rs`: bundle the already-existing `native-shape-census.d` program under Carrick's trace surface.
- Modify `crates/carrick-cli/src/trace_profile.rs`: add the `trusted-route` profile vocabulary and a lossless capture-status receipt rather than trying to parse the PC histogram as a normal DSR metric profile.
- Modify `crates/carrick-cli/src/args.rs`: add `debug trusted-route-census` and `debug trusted-route-capture` arguments.
- Modify `crates/carrick-cli/src/commands.rs`: dispatch the portable census and macOS-only capture workflow.
- Modify `crates/carrick-cli/src/main.rs`: declare the focused route-attribution module.
- Create `crates/carrick-cli/src/debug_trusted_route.rs`: typed trace/snapshot parsing, hashing, validation, report schema, isolated-store capture protocol, and JSON export.
- Modify `crates/carrick-cli/tests/trace_profile.rs`: pin the new bundled profile and loss-state behavior.
- Modify `handoff.md` and create `docs/perf-results/2026-08-03-trusted-entry-route-attribution.md`: bind implementation provenance, both captures, decision, and next production hypothesis or explicit pivot.

---

### Task 1: Exact diagnostic mode and word-identical route geometry

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/emit.rs:112-180`
- Modify: `crates/carrick-dsr-aarch64/src/emit.rs:5270-5520`
- Test: `crates/carrick-dsr-aarch64/src/emit.rs:7060-7140`

**Interfaces:**
- Consumes: `GenerationGuard`, `CacheOffset`, `RecoveryAction::RestoreGuestX17`, and the current narrow generation materialization.
- Produces: `TrustedRouteSplit`, `TrustedRouteOffsets`, `trusted_route_split_enabled()`, `trusted_sequence_words(CodeGeneration)`, and `derive_trusted_route_offsets(&[u32], TrustedEntryTemplate, TrustedRouteSplit)` for replay and translator publication.

- [ ] **Step 1: Write red tests for exact parsing and unchanged normal bytes**

Add tests that call the pure parser and an option-taking assembly seam:

```rust
#[test]
fn trusted_route_split_requires_exact_one() {
    assert_eq!(trusted_route_split_from(None), TrustedRouteSplit::Disabled);
    assert_eq!(
        trusted_route_split_from(Some(std::ffi::OsStr::new("0"))),
        TrustedRouteSplit::Disabled
    );
    assert_eq!(
        trusted_route_split_from(Some(std::ffi::OsStr::new("true"))),
        TrustedRouteSplit::Disabled
    );
    assert_eq!(
        trusted_route_split_from(Some(std::ffi::OsStr::new("1"))),
        TrustedRouteSplit::Enabled
    );
}

#[test]
fn disabled_route_split_is_byte_identical_to_current_shape() {
    let generation = AtomicU64::new(7);
    let guard = GenerationGuard::new(&generation, CodeGeneration::claimed(7));
    let block = assemble_block_inner_with_route_split(
        &copy_plan(),
        Some(guard),
        EmitAddressMode::Direct,
        None,
        TrustedRouteSplit::Disabled,
    )
    .expect("assemble normal trusted entry");
    let offset = block.trusted_entry.expect("trusted entry").get() as usize / 4;
    assert_eq!(
        &block.words[offset..offset + 3],
        &[0xd280_00f1, 0xf902_3f91, 0xf942_3791]
    );
    assert_eq!(block.trusted_routes, None);
}
```

- [ ] **Step 2: Run the focused tests and verify red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 trusted_route_split -- --nocapture
```

Expected: compilation fails because `TrustedRouteSplit`, `trusted_route_split_from`, `assemble_block_inner_with_route_split`, and `trusted_routes` do not exist.

- [ ] **Step 3: Add the typed mode and shared sequence renderer**

Introduce these exact shapes near `EmittedBlock`:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrustedRouteSplit {
    Disabled,
    Enabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedRouteOffsets {
    pub fallthrough: CacheOffset,
    pub direct: CacheOffset,
    pub indirect: CacheOffset,
    pub sequence_bytes: u32,
    pub common_body: CacheOffset,
}

fn trusted_route_split_from(value: Option<&std::ffi::OsStr>) -> TrustedRouteSplit {
    if value == Some(std::ffi::OsStr::new("1")) {
        TrustedRouteSplit::Enabled
    } else {
        TrustedRouteSplit::Disabled
    }
}

pub(crate) fn trusted_route_split_enabled() -> TrustedRouteSplit {
    static MODE: std::sync::OnceLock<TrustedRouteSplit> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        trusted_route_split_from(
            std::env::var_os("CARRICK_DSR_TRUSTED_ROUTE_SPLIT").as_deref(),
        )
    })
}
```

Add a `trusted_sequence_words(expected)` helper that returns the minimal `movz`/nonzero `movk` words followed by the exact generation store and guest-x17 reload. Use that helper for the existing one-copy normal path; do not retain a second hand-coded sequence.

- [ ] **Step 4: Write red geometry, branch-target, and recovery tests**

Add a diagnostic test that asserts:

```rust
let routes = block.trusted_routes.expect("diagnostic routes");
let words = block.words.as_slice();
let sequence_words = routes.sequence_bytes as usize / 4;
let indices = [routes.fallthrough, routes.direct, routes.indirect]
    .map(|offset| offset.get() as usize / 4);
assert_eq!(
    &words[indices[0]..indices[0] + sequence_words],
    &words[indices[1]..indices[1] + sequence_words]
);
assert_eq!(
    &words[indices[0]..indices[0] + sequence_words],
    &words[indices[2]..indices[2] + sequence_words]
);
for index in indices {
    assert_eq!(
        decode_b_target(index, words[index + sequence_words]),
        routes.common_body.get() as usize / 4
    );
}
for offset in routes.fallthrough.get()..routes.common_body.get() {
    if offset.is_multiple_of(4) {
        assert_eq!(recovery_at(&block.recovery, offset), RecoveryAction::RestoreGuestX17);
    }
}
```

The test must use generations `0`, `7`, `0x1_0000`, and `0x1_0000_0001` so the stride is proven for each minimal materialization width.

- [ ] **Step 5: Implement the three-copy diagnostic emission**

Split `assemble_block_inner` into a production wrapper and an option-taking implementation:

```rust
fn assemble_block_inner(...) -> Result<AssembledBlock, DsrError> {
    assemble_block_inner_with_route_split(
        plan,
        guard,
        mode,
        recording,
        trusted_route_split_enabled(),
    )
}
```

In enabled mode, emit three copies with a dynamic branch to one `common_body` label. Set the existing `trusted_entry` to `fallthrough`, record only that offset in `ArtifactRecording`, and store the complete `TrustedRouteOffsets` in `AssembledBlock`/`EmittedBlock`. In disabled mode, emit the helper once with no new branch so the bytes remain identical to the pre-diagnostic shape.

- [ ] **Step 6: Run emitter tests and the full leaf-crate suite**

Run:

```bash
cargo test -p carrick-dsr-aarch64 trusted_route -- --nocapture
cargo test -p carrick-dsr-aarch64
```

Expected: all focused tests and the full leaf-crate suite pass.

- [ ] **Step 7: Commit the emitter slice**

```bash
git add crates/carrick-dsr-aarch64/src/emit.rs
git commit -m "feat(dsr): emit diagnostic trusted routes"
```

---

### Task 2: Unchanged-wire replay validation and typed route publication

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/artifact_spike.rs:1050-1085`
- Modify: `crates/carrick-dsr-aarch64/src/artifact_spike.rs:2430-2555`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:839-870`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:2135-2185`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:2890-3000`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:3540-3565`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:3900-3955`
- Test: `crates/carrick-dsr-aarch64/src/translator.rs:5960-6160`

**Interfaces:**
- Consumes: `TrustedEntryTemplate { offset, expected }`, `TrustedRouteOffsets`, `EmittedBlock::trusted_entry()`, and the existing `trusted_entries` map.
- Produces: `TrustedRouteEntries { fallthrough, direct, indirect, sequence_bytes, common_body }`, an optional `trusted_route_entries` map keyed like `blocks`, direct routing through `.direct`, and flavor-1 publication through `.indirect`.

- [ ] **Step 1: Write red replay tests with no wire-field additions**

Extend the recorded/native parity fixture to assert that enabled native emission and enabled replay produce the same route offsets and words. Serialize `UnitBlockHotWire` before and after the test fixture and assert its field set is still exactly `relocations`, `trusted_entry`, and `direct_links`; do not add a route field or bump the store ABI.

Add corruption cases that change one word in the direct sequence and one word in the indirect sequence. Both must return a `DsrError::CachePolicy` containing `trusted route sequences differ` before publishing code.

- [ ] **Step 2: Run replay tests and verify red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 replayed_trusted_route -- --nocapture
```

Expected: the tests fail because replay neither derives routes nor compares the three spans.

- [ ] **Step 3: Derive replay geometry from the existing trusted entry**

After applying relocations, call the emitter-owned derivation helper with the replayed words, `TrustedEntryTemplate`, and the exact diagnostic mode. The helper must:

```rust
let sequence = trusted_sequence_words(CodeGeneration::claimed(trusted.expected));
let stride_bytes = u32::try_from((sequence.len() + 1) * 4)?;
let fallthrough = CacheOffset::published(trusted.offset);
let direct = CacheOffset::published(trusted.offset.checked_add(stride_bytes).ok_or(...)?);
let indirect = CacheOffset::published(trusted.offset.checked_add(2 * stride_bytes).ok_or(...)?);
```

It then bounds-checks every `[start, start + sequence_bytes)` span, compares each span to `sequence`, verifies each following word is an unconditional `B` to one common-body offset, and returns `TrustedRouteOffsets`. Disabled mode returns `None` after the existing trusted-entry validation and therefore replays ABI-8 units exactly as before.

- [ ] **Step 4: Write red direct/indirect route-selection tests**

Update the two-block fixture to assert the patched A→B branch targets `routes.direct`, not `routes.fallthrough`. Add a flavor-1 fixture that reads the published cache entry and asserts its code pointer equals `routes.indirect`. Keep the existing generation-bump tests and assert stale direct links are severed and stale flavor-1 entries miss.

- [ ] **Step 5: Add typed absolute route publication**

Define beside `ProcessState`:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedRouteEntries {
    pub fallthrough: types::CacheVa,
    pub direct: types::CacheVa,
    pub indirect: types::CacheVa,
    pub sequence_bytes: u32,
    pub common_body: types::CacheVa,
}
```

Add `trusted_route_entries: BTreeMap<(GuestVa, CodeGeneration), TrustedRouteEntries>` to `ProcessState`, initialize it empty, and clear it at the same whole-index reset that clears `trusted_entries`. In `publish_emitted_with_metadata`, convert offsets to checked absolute cache VAs and populate both maps atomically under the existing state write guard.

Change `trusted_target` to select `.direct` when a typed route exists, then fall back to the existing trusted offset. Change `publish_indirect_target` to select `.indirect` when present, then fall back to the existing trusted offset. Do not change flavor-0 publication.

- [ ] **Step 6: Run routing, invalidation, replay, and full leaf tests**

Run:

```bash
cargo test -p carrick-dsr-aarch64 trusted_route -- --nocapture
cargo test -p carrick-dsr-aarch64 cross_block_direct_links_patch_to_the_target_trusted_entry -- --nocapture
cargo test -p carrick-dsr-aarch64 flavor_1 -- --nocapture
cargo test -p carrick-dsr-aarch64
```

Expected: routes are distinct, replay is word-identical, corruption fails closed, and all prior invalidation tests pass.

- [ ] **Step 7: Commit replay and routing**

```bash
git add crates/carrick-dsr-aarch64/src/artifact_spike.rs crates/carrick-dsr-aarch64/src/translator.rs
git commit -m "feat(dsr): route diagnostic trusted arrivals"
```

---

### Task 3: Validated route spans in retirement snapshots

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:610-630`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:2245-2280`
- Modify: `crates/carrick-runtime/src/native_darwin.rs:3330-3370`
- Test: `crates/carrick-dsr-aarch64/src/translator.rs` snapshot tests
- Test: `crates/carrick-runtime/src/native_darwin.rs` snapshot serialization tests

**Interfaces:**
- Consumes: `ProcessState::blocks`, `ProcessState::trusted_route_entries`, and the copied cache bytes.
- Produces: `TrustedRouteSnapshot` rows with guest/generation, three half-open sequence spans, three artificial branch PCs, and common-body PC.

- [ ] **Step 1: Write red snapshot-validation tests**

Construct one valid cache fixture and fixtures with overlapping spans, an out-of-range direct span, an unaligned indirect start, unequal sequence bytes, and a common body outside the dumped cache. Assert valid geometry serializes and every invalid fixture returns a named error rather than omitting a row.

- [ ] **Step 2: Run the focused tests and verify red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 code_snapshot_trusted_route -- --nocapture
```

Expected: compilation fails because `TrustedRouteSnapshot` and fallible snapshot validation do not exist.

- [ ] **Step 3: Add the typed snapshot row and validation**

Add:

```rust
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TrustedRouteSnapshot {
    pub guest_start: u64,
    pub generation: u64,
    pub fallthrough: std::ops::Range<u64>,
    pub direct: std::ops::Range<u64>,
    pub indirect: std::ops::Range<u64>,
    pub fallthrough_branch: u64,
    pub direct_branch: u64,
    pub indirect_branch: u64,
    pub common_body: u64,
}
```

Change `code_snapshot()` to return `Result<CodeSnapshot, DsrError>`. While holding the state read guard, validate 4-byte alignment, strict range ordering, containment in `[cache_base, cache_base + code.len())`, identical bytes across the three sequence spans, three valid unconditional branches to `common_body`, and one route row for every diagnostic map entry.

- [ ] **Step 4: Export route rows and make failures visible**

Extend the retirement JSON with schema `carrick.code-snapshot.v2` and `trusted_routes`. Change `maybe_dump_code_snapshot` to return `Result<(), RuntimeError>` internally; at the process-exit seam, emit a named warning and no JSON index when validation or either atomic file write fails. Write the `.bin` before a temporary JSON and rename the JSON last so an index is the commit marker.

- [ ] **Step 5: Run focused runtime and leaf tests**

Run:

```bash
cargo test -p carrick-dsr-aarch64 code_snapshot_trusted_route -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime code_snapshot -- --nocapture
```

Expected: valid route snapshots pass; every malformed geometry case fails with its named invariant.

- [ ] **Step 6: Commit snapshot support**

```bash
git add crates/carrick-dsr-aarch64/src/translator.rs crates/carrick-runtime/src/native_darwin.rs
git commit -m "feat(native): export trusted-route snapshots"
```

---

### Task 4: Lossless trusted-route trace profile receipt

**Files:**
- Modify: `crates/carrick-runtime/src/dtrace_consumer.rs:80-95`
- Modify: `crates/carrick-cli/src/trace_profile.rs:1879-1920`
- Modify: `crates/carrick-cli/src/commands.rs:1350-1600`
- Modify: `crates/carrick-cli/tests/trace_profile.rs:450-680`
- Reuse unchanged: `scripts/dtrace/native-shape-census.d`

**Interfaces:**
- Consumes: existing native-shape `SHAPE1`/`PC` output and `DTraceRunReport` drop counters.
- Produces: `TraceProfileKind::TrustedRoute` and one `carrick.trusted-route-capture.v1` JSON receipt containing raw-trace SHA-256, binary/source/command provenance, all six DTrace drop classes, interruption, `copyin-errors`, total samples, PC-row population, and target completion.

- [ ] **Step 1: Write red profile-vocabulary and loss-state tests**

Pin `trusted-route` parsing, the bundled script hash, `requires_runtime_profile() == false`, and receipt rejection for each nonzero drop class, interruption, nonzero `SHAPE1|copyin-errors`, zero PC samples, missing `SHAPE1|section=pc`, and malformed PC rows.

- [ ] **Step 2: Run CLI profile tests and verify red**

Run:

```bash
cargo test -p carrick-cli --test trace_profile trusted_route -- --nocapture
```

Expected: tests fail because the profile and receipt parser do not exist.

- [ ] **Step 3: Bundle the existing D program and add the profile kind**

Add `BUNDLED_TRUSTED_ROUTE_D = include_str!("../../../scripts/dtrace/native-shape-census.d")` and map `TraceProfileKind::TrustedRoute` to it. Keep the D program itself unchanged unless a test proves its current end markers cannot establish completion.

- [ ] **Step 4: Add the dedicated capture receipt**

Do not send `SHAPE1` through `ProfileSummary`. Add a focused parser that requires exactly one totals section, region section, PC section, `copyin-errors=0`, positive total and PC populations, and only syntactically valid `PC <pid> 0x<pc> <count>` rows. Combine it with `ProfileCaptureStatus`; any drops or interruption return nonzero.

When `--profile trusted-route --summary-jsonl FILE` is used, atomically write one JSON object with schema `carrick.trusted-route-capture.v1`. The generic DSR profiles keep their current JSONL behavior.

- [ ] **Step 5: Run profile tests and CLI unit tests**

Run:

```bash
cargo test -p carrick-cli --test trace_profile trusted_route -- --nocapture
cargo test -p carrick-cli --bin carrick trace_profile -- --nocapture
```

Expected: the existing profiles remain unchanged and trusted-route loss cases fail closed.

- [ ] **Step 6: Commit the trace receipt**

```bash
git add crates/carrick-runtime/src/dtrace_consumer.rs crates/carrick-cli/src/trace_profile.rs crates/carrick-cli/src/commands.rs crates/carrick-cli/tests/trace_profile.rs
git commit -m "feat(trace): capture trusted-route samples"
```

---

### Task 5: Rust-owned trusted-route census and JSON export

**Files:**
- Create: `crates/carrick-cli/src/debug_trusted_route.rs`
- Modify: `crates/carrick-cli/src/main.rs:120-135`
- Modify: `crates/carrick-cli/src/args.rs:910-970`
- Modify: `crates/carrick-cli/src/debug.rs:35-115`
- Modify: `crates/carrick-cli/src/commands.rs:1320-1340`
- Test: `crates/carrick-cli/src/debug_trusted_route.rs`

**Interfaces:**
- Consumes: trusted-route raw trace, capture receipt, v2 snapshots, `--jit-share <0..=1>`, and optional `--output` path.
- Produces: `carrick.trusted-route-census.v1` JSON plus nonzero exit for every validation failure.

- [ ] **Step 1: Write red parser and report tests from literal fixtures**

Use two PIDs and route samples with known shares. Assert exact totals for matched, missing PID, missing range, fallthrough/direct/indirect sequence samples, each artificial branch, block count, sequence bytes, and `route_total * jit_share / total_pc_samples` opportunity.

Add independent red cases for zero route samples, malformed PC rows, duplicate snapshot commit markers, missing `.bin`, snapshot hash mismatch, missing PID, missing range, overlapping spans, unequal words, invalid branch targets, capture drops/errors/interruption, and JIT shares `0`, negative, NaN, and greater than `1`.

- [ ] **Step 2: Run the focused parser tests and verify red**

Run:

```bash
cargo test -p carrick-cli --bin carrick trusted_route_census -- --nocapture
```

Expected: compilation fails because `debug_trusted_route` and the command variant do not exist.

- [ ] **Step 3: Implement typed parsing and hashing**

Define the report with these stable top-level fields:

```rust
#[derive(Serialize)]
struct TrustedRouteCensusReport {
    schema: &'static str,
    trace_sha256: String,
    capture_sha256: String,
    snapshots_sha256: String,
    total_pc_samples: u64,
    matched_samples: u64,
    missing_pid_samples: u64,
    missing_range_samples: u64,
    routes: RouteTallies,
    artificial_branches: RouteTallies,
    route_shares: RouteShares,
    jit_share: f64,
    projected_total_cpu: RouteShares,
    sequence_bytes: u32,
    block_count: u64,
    validation_failures: Vec<String>,
}
```

Hash the raw trace bytes, capture receipt bytes, and a deterministic manifest of every sorted snapshot JSON/bin path plus its SHA-256. Parse every nonblank line that starts with `PC `; a malformed `PC ` line is an error rather than ignored input. Require every sampled PID and every sampled PC to resolve to exactly one snapshot/cache range.

- [ ] **Step 4: Add `carrick debug trusted-route-census`**

Add exact CLI arguments:

```text
carrick debug trusted-route-census \
  --trace RAW \
  --capture CAPTURE.json \
  --snapshots DIR \
  --jit-share 0.46505 \
  [--output REPORT.json]
```

Print pretty JSON to stdout when `--output` is absent; otherwise atomically write the file and print its path and SHA-256 to stderr. Always include `validation_failures`; return nonzero when it is nonempty.

- [ ] **Step 5: Run census, CLI parsing, formatting, and lint tests**

Run:

```bash
cargo test -p carrick-cli --bin carrick trusted_route_census -- --nocapture
cargo test -p carrick-cli --bin carrick debug -- --nocapture
cargo fmt --check
cargo clippy -p carrick-cli --all-targets -- -D warnings
```

Expected: all fixture cases pass, invalid input exits nonzero, and the CLI/lint gates are clean.

- [ ] **Step 6: Commit the census**

```bash
git add crates/carrick-cli/src/debug_trusted_route.rs crates/carrick-cli/src/main.rs crates/carrick-cli/src/args.rs crates/carrick-cli/src/debug.rs crates/carrick-cli/src/commands.rs
git commit -m "feat(debug): export trusted-route census"
```

---

### Task 6: Isolated-store capture protocol and diagnostic correctness gate

**Files:**
- Modify: `crates/carrick-cli/src/debug_trusted_route.rs`
- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/debug.rs`
- Test: `crates/carrick-cli/src/debug_trusted_route.rs`

**Interfaces:**
- Consumes: `--evidence-dir`, `--jit-share`, and a trailing Carrick workload command such as `run --exec-backend native IMAGE sh -lc SCRIPT`.
- Produces: isolated store, warmup receipt, pre/post store manifests, raw trace, capture receipt, retirement snapshots, and final census report.

- [ ] **Step 1: Write red protocol tests**

Use a fake executable seam to assert the runner refuses a nonempty store, removes `CARRICK_DSR_PERSISTENT_STORE` from both children, sets the exact route switch and dedicated store directory, omits snapshot output from warmup, enables it for trace, runs warmup before trace, rejects a nonzero warmup/trace status, rejects an authority inode change, rejects zero payloads, and invokes census only after every prior check succeeds.

- [ ] **Step 2: Run protocol tests and verify red**

Run:

```bash
cargo test -p carrick-cli --bin carrick trusted_route_capture -- --nocapture
```

Expected: tests fail because the capture protocol does not exist.

- [ ] **Step 3: Implement `debug trusted-route-capture`**

Add exact surface:

```text
carrick debug trusted-route-capture \
  --evidence-dir DIR \
  --jit-share 0.46505 \
  -- run --exec-backend native IMAGE sh -lc SCRIPT
```

Require `DIR/store` to be absent or empty before creating it. Run the untraced workload with `CARRICK_DSR_STORE_DIR`, exact route split, and persistent enable unset. Record authority inode, recursive payload count, and byte size. Then run the same command through:

```text
carrick trace --profile trusted-route \
  --trace-out DIR/trace.raw \
  --summary-jsonl DIR/capture.json \
  <workload>
```

with `CARRICK_DSR_CODE_SNAPSHOT_DIR=DIR/snapshots`. Re-census the store, reject an authority change or empty payload set, write sorted pre/post manifests, and invoke the same census function used by the standalone debug command.

- [ ] **Step 4: Run protocol and CLI tests**

Run:

```bash
cargo test -p carrick-cli --bin carrick trusted_route_capture -- --nocapture
cargo test -p carrick-cli --bin carrick trusted_route_census -- --nocapture
```

Expected: ordering, environment isolation, store checks, and all fail-closed paths pass.

- [ ] **Step 5: Run focused implementation gates**

Run:

```bash
cargo test -p carrick-dsr-aarch64
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib
cargo test -p carrick-cli --bin carrick
cargo test -p carrick-cli --test trace_profile
```

Expected: all focused suites pass serially where required.

- [ ] **Step 6: Build and prove the signed diagnostic binary**

Run:

```bash
just build
codesign --verify --verbose=2 target/release/carrick
strings -a target/release/carrick | rg 'CARRICK_DSR_TRUSTED_ROUTE_SPLIT|carrick.trusted-route-census.v1'
otool -l target/release/carrick | rg '__dof_carrick'
shasum -a 256 target/release/carrick
dwarfdump --uuid target/release/carrick || otool -l target/release/carrick | rg -A3 LC_UUID
```

Expected: signature verification succeeds, both markers are present, the DOF section exists, and digest/UUID are retained in the evidence directory.

- [ ] **Step 7: Run the full local gate**

Run:

```bash
RUST_TEST_THREADS=1 just ci
```

Expected: the full repository gate passes before the diagnostic is used for a route decision.

- [ ] **Step 8: Commit the capture protocol**

```bash
git add crates/carrick-cli/src/debug_trusted_route.rs crates/carrick-cli/src/args.rs crates/carrick-cli/src/debug.rs
git commit -m "feat(debug): orchestrate trusted-route capture"
```

---

### Task 7: Two-capture attribution decision and diagnostic removal

**Files:**
- Create: `docs/perf-results/2026-08-03-trusted-entry-route-attribution.md`
- Modify: `handoff.md`
- Remove after decision: diagnostic-only code added by Tasks 1-6, while retaining the evidence document and any generally reusable validation/export infrastructure explicitly justified by a separate review.

**Interfaces:**
- Consumes: exact signed binary provenance, quiet-box metadata, two complete route-census reports, store manifests, and current receipt-bound JIT share `0.46505` unless a newer same-binary attribution replaces it.
- Produces: one committed route decision: advance exactly one separately designed production hypothesis when it projects at least 10% total CPU, or stop the trusted-entry line and pivot.

- [ ] **Step 1: Preflight a quiet host and create two distinct evidence roots**

Prove no Carrick/Docker workload overlaps the capture, no material background process owns a performance core, macOS reports no thermal/performance/CPU-power warning, and power source is recorded as metadata only. Use two different empty evidence directories and two different empty store roots.

- [ ] **Step 2: Run capture A to natural completion**

Run the approved cold-go-build workload through `debug trusted-route-capture`. Do not interrupt DTrace. Require `BUILD_OK`, zero capture drops/errors, a complete retirement snapshot set, both native-emitted and replayed route spans, and a census report with no validation failures.

- [ ] **Step 3: Run capture B independently**

Repeat from a second empty store/evidence root after a fresh quiet-box preflight. Do not reuse capture A's store or snapshots.

- [ ] **Step 4: Apply the decision rule**

For each route, compute absolute percentage-point difference between capture A and B's trusted-sequence share. Reject attribution if the dominant route differs or its share differs by more than five points. Multiply each accepted route share by the receipt-bound JIT share; advance only a route at or above `0.10` projected total CPU.

- [ ] **Step 5: Use LLDB/core evidence for abnormal retirement**

If either capture loses a process, crashes, or lacks retirement snapshots, stop timing interpretation and run the same scoped workload through `carrick debug lldb-run` or attach the guest process and save a core. Export the always-on event ring from the core with `scripts/carrick_lldb.py`; do not diagnose from missing trace output.

- [ ] **Step 6: Write durable evidence and update the controller**

Record source commit, binary SHA-256/UUID/signature/DOF receipt, D program SHA-256, workload image digest, exact host environment, store manifests, both route reports and hashes, agreement calculation, projected opportunity, and the advance/stop decision. Explicitly state that traced wall time is non-citable and that eager full translation remains deferred.

- [ ] **Step 7: Remove the diagnostic before production-candidate work**

Delete `CARRICK_DSR_TRUSTED_ROUTE_SPLIT` handling and the route-copy/routing support. Restore the one-sequence production shape and prove its emitted bytes match the pre-diagnostic receipt. Keep the durable evidence document. Run focused suites and `RUST_TEST_THREADS=1 just ci` again.

- [ ] **Step 8: Commit the decision and cleanup**

```bash
git add -A crates/carrick-dsr-aarch64 crates/carrick-runtime crates/carrick-cli docs/perf-results/2026-08-03-trusted-entry-route-attribution.md handoff.md
git commit -m "docs(perf): decide trusted-entry route"
```

Expected: the branch ends with no diagnostic hot-path code, a clean full gate, and one evidence-backed next hypothesis or an explicit pivot.

---

## Self-Review

- Spec coverage: exact switch, normal byte identity, three equal sequences, unchanged ABI-8 wire, replay validation, distinct direct/indirect routing, generation/invalidation/recovery preservation, validated snapshots, existing D program, Rust report, drop/error/coverage failure, isolated store warmup/trace protocol, two-capture agreement, 10% threshold, LLDB/core fallback, cleanup, evidence, and handoff are each assigned to a task.
- Placeholder scan: the plan contains no deferred implementation placeholders; every code-producing step names its interfaces, tests, command, and acceptance result.
- Type consistency: Tasks 1-3 consistently use `TrustedRouteOffsets` for block-relative geometry, `TrustedRouteEntries` for absolute published VAs, and `TrustedRouteSnapshot` for exported half-open ranges. Tasks 4-6 consistently use `trusted-route`, `carrick.trusted-route-capture.v1`, and `carrick.trusted-route-census.v1`.
- Scope: emitter, replay, routing, capture, and census are one diagnostic pipeline; none is useful or independently shippable without the others, so one plan is the correct unit.
