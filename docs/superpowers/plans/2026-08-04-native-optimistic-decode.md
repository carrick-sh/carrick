# Native Optimistic Decode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move fresh Darwin/AArch64 DSR block decoding outside the process-wide translation writer, retain authoritative single-writer emission/publication, and keep the candidate only if controlled CPU and mechanism evidence are positive.

**Architecture:** Split the current monolithic `ProcessState::translate` into locked preparation, an owned optimistic decode interval, and locked authoritative commit. A private decoder closure makes the production decoder and deterministic concurrency tests use the same orchestration; generation revalidation and a second `blocks` lookup discard stale or losing plans before any visible cache mutation.

**Tech Stack:** Rust 2024, `parking_lot::RwLock`, Carrick DSR AArch64 translator/cache types, NATIVEPERF frames and Python evidence parser, signed Darwin builds, Carrick DTrace `native-wall`, receipt-bound eight-quad ABBA.

## Global Constraints

- Correct guest behavior and invalidation semantics are immovable.
- The translation cache remains single-writer; do not make the bump cursor, emitted bytes, metadata, direct links, or publication indexes concurrent.
- Shared-unit and persistent-artifact hits stay ahead of fresh decode.
- Tier D remains default-off.
- Replace the obsolete diagnostic fields; do not retain a compatibility schema or second spelling.
- Add no per-key mutex/map and do not revive `ConcurrentPublicationIndex`.
- Fork and exec gain no persistent synchronization state.
- Eager whole-image translation remains deferred; incremental translation must continue to support JIT-on-JIT code.
- Total child CPU is retention authority; traced runs are mechanism attribution only.
- Use the exact shipped-default overlay for both ABBA arms and never run Carrick concurrently with the Docker oracle.

---

## File map

- Modify `crates/carrick-dsr-aarch64/src/translator.rs`: owned preparation state, decoder orchestration, authoritative commit, discard counters, and deterministic translator tests.
- Modify `crates/carrick-dsr-aarch64/src/artifact_spike.rs`: one `cfg(test)` empty-store factory used to exercise the real artifact-hit ordering without global environment state.
- Modify `crates/carrick-dsr/src/profile.rs`: replace the resolver-process field and expose discard duration in NATIVEPERF.
- Modify `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`: migrate runtime tests to the real thread translator path and replace the obsolete impossible-duplicate invariant/field list.
- Modify `scripts/perf/native_compiler_budget.py`: accept and aggregate the new exact resolver fields.
- Modify `scripts/perf/test_native_compiler_budget.py`: pin the new NATIVEPERF frame contract and aggregation.
- Modify `scripts/perf/test_direct_binding_mechanism.py`: update its complete-profile fixture to the replaced schema.
- Modify `handoff.md`: record the experiment outcome and next measured bucket.
- Create `docs/perf-results/2026-08-04-native-optimistic-decode.md` only if the candidate survives the retention gate; otherwise create a stopped-hypothesis evidence note with the same path.

### Task 1: Replace the obsolete duplicate-publication diagnostic

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:1155-1365,1800-2010,4175-4215`
- Modify: `crates/carrick-dsr/src/profile.rs:770-805,950-985,1760-1790`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs:330-350,1348-1375`
- Modify: `scripts/perf/native_compiler_budget.py:75-105`
- Modify: `scripts/perf/test_native_compiler_budget.py:600-635`
- Modify: `scripts/perf/test_direct_binding_mechanism.py:45-70`

**Interfaces:**
- Produces: `ResolverStats::{optimistic_decode_discards, optimistic_decode_discard_ns}: u64`.
- Produces: `ResolverStat::{OptimisticDecodeDiscards, OptimisticDecodeDiscardNs}` with exact field names `optimistic_decode_discards` and `optimistic_decode_discard_ns`.
- Produces: NATIVEPERF `resolver-process` fields `translations`, `optimistic_decode_discards`, `optimistic_decode_discard_ns`, `cache_lookups`, `cache_lookup_hits`, and `invalidated_blocks`.
- Removes: every `duplicate_publications` field, variant, parser expectation, fixture, and runtime invariant.

- [ ] **Step 1: Change the parser fixtures first**

Replace the resolver-process fixture fragments with this exact frame:

```python
prefix
+ "resolver-process|translations=1|optimistic_decode_discards=2|"
  "optimistic_decode_discard_ns=17|cache_lookups=1|"
  "cache_lookup_hits=0|invalidated_blocks=0"
```

Add assertions that the parsed/aggregated profile preserves both `2` and `17`, and that the old `duplicate_publications` spelling is rejected as an unexpected field.

- [ ] **Step 2: Run the parser tests and prove red**

Run:

```bash
PYTHONPATH=scripts/perf python3 -m unittest \
  scripts/perf/test_native_compiler_budget.py \
  scripts/perf/test_direct_binding_mechanism.py -v
```

Expected: FAIL because `resolver-process` still requires `duplicate_publications` and does not know the two optimistic-decode fields.

- [ ] **Step 3: Replace the Rust statistics schema**

Make the process-wide fields and enum variants exact:

```rust
pub struct ResolverStats {
    // existing fields...
    pub translations: u64,
    pub optimistic_decode_discards: u64,
    pub optimistic_decode_discard_ns: u64,
    // existing fields...
}

pub enum ResolverStat {
    // existing variants...
    OptimisticDecodeDiscards,
    OptimisticDecodeDiscardNs,
    // existing variants...
}
```

Update `ResolverStat::ALL`, `name`, `ResolverStats::{get,set}`, checked deltas, snapshots, drained-sibling structural zeros, and `resolver_stats`. Replace comments that enumerate process-wide deltas.

- [ ] **Step 4: Replace the NATIVEPERF producer and consumers**

Emit this exact Rust frame shape:

```rust
let _ = write!(
    process,
    "|translations={}|optimistic_decode_discards={}|optimistic_decode_discard_ns={}|cache_lookups={}|cache_lookup_hits={}|invalidated_blocks={}",
    resolver.translations,
    resolver.optimistic_decode_discards,
    resolver.optimistic_decode_discard_ns,
    resolver.cache_lookups,
    resolver.cache_lookup_hits,
    resolver.invalidated_blocks,
);
```

Update `FRAME_FIELDS["resolver-process"]` to the same six fields. In the runtime test, remove the assertion that a nonzero duplicate count is impossible; the later race test will own the new semantic assertion.

- [ ] **Step 5: Run the focused diagnostics gates**

Run:

```bash
cargo test -p carrick-dsr --lib profile -- --nocapture
cargo test -p carrick-dsr-aarch64 --lib resolver -- --nocapture
PYTHONPATH=scripts/perf python3 -m unittest \
  scripts/perf/test_native_compiler_budget.py \
  scripts/perf/test_direct_binding_mechanism.py -v
rg -n "duplicate_publications|DuplicatePublications" crates scripts/perf
```

Expected: tests PASS and `rg` returns no matches.

- [ ] **Step 6: Commit the schema replacement**

```bash
git add crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-dsr/src/profile.rs \
  crates/carrick-runtime/src/native_darwin/dsr/mod.rs \
  scripts/perf/native_compiler_budget.py \
  scripts/perf/test_native_compiler_budget.py \
  scripts/perf/test_direct_binding_mechanism.py
git commit -m "perf(native): expose optimistic decode discard cost"
```

### Task 2: Introduce preparation/decode/commit boundaries

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:1060-1095,3180-3710,3950-4040,4880-4960`

**Interfaces:**
- Produces: private `TranslationPreparation` owning the observation and every fresh-path input needed after releasing the writer.
- Produces: private `PreparedTranslation::{Complete, Fresh}`.
- Produces: `ProcessState::prepare_translation(...) -> Result<PreparedTranslation, DsrError>`.
- Produces: `ProcessState::commit_translation(...) -> Result<TranslationResult, DsrError>`.
- Produces: `ThreadTranslator::translate_read_mostly_with<D>(...)`, where `D` receives `(memory, guest, generation, superblock_segments)` and returns `Result<block::BlockPlan, DsrError>`.
- Preserves: `ThreadTranslator::translate_read_mostly` as the production caller using `block::plan_block_with_segments`.

- [ ] **Step 1: Add the red structural test**

Add this source-contract test beside `warm_process_lookup_does_not_take_the_translation_state_lock`:

```rust
#[test]
fn fresh_block_decode_is_outside_the_process_state_writer() {
    let source = include_str!("translator.rs");
    let body = source
        .split_once("    fn translate_read_mostly_with<")
        .expect("optimistic translation orchestrator")
        .1
        .split_once("    fn translate_read_mostly(\n")
        .expect("orchestrator end")
        .0;
    let first_drop = body.find("drop(state);").expect("release preparation writer");
    let decode = body.find("decode(").expect("decoder call");
    let second_write = body[first_drop + 1..]
        .find("self.process.state.write()")
        .map(|offset| first_drop + 1 + offset)
        .expect("commit writer");
    assert!(first_drop < decode && decode < second_write);
}
```

- [ ] **Step 2: Run the structural test and prove red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 --lib \
  fresh_block_decode_is_outside_the_process_state_writer -- --exact --nocapture
```

Expected: FAIL because `translate_read_mostly_with` does not exist.

- [ ] **Step 3: Define the owned state and preparation result**

Add private types near `TranslationResult`:

```rust
struct TranslationPreparation {
    tid: i32,
    guest: carrick_guest_mem::GuestVa,
    key: (carrick_guest_mem::GuestVa, types::CodeGeneration),
    source_page: carrick_guest_mem::GuestVa,
    observation: cache::PageGenerationObservation,
    artifact_address_mode: emit::EmitAddressMode,
    artifact_key: Option<artifact_spike::ArtifactKey>,
    artifact_template: Option<artifact_spike::ArtifactTemplate>,
    profiling: bool,
    translation_started: Option<std::time::Instant>,
    superblock_segments: usize,
}

enum PreparedTranslation {
    Complete(TranslationResult),
    Fresh(TranslationPreparation),
}
```

Do not store a `ProcessState` reference, lock guard, cache reservation, emitted extent, or publication token in either type.

- [ ] **Step 4: Extract locked preparation without changing precedence**

Move the current generation observation/invalidation, authoritative `blocks` recheck, `try_load_shared_unit`, BlockMiss/translate-begin, artifact key/lookup, and artifact replay into `prepare_translation` in their current order. Return `Complete` for authoritative/shared/artifact completion and `Fresh` only after artifact replay has missed or declined.

Use one helper to close `dsr_translate_end` for artifact success and all errors that occur after `dsr_translate_begin`; block-index and shared-unit hits still emit no translate begin/end pair, matching the current lifecycle.

- [ ] **Step 5: Extract locked commit**

`commit_translation` consumes `TranslationPreparation`, the owned `BlockPlan`, and `Option<Duration>` for the measured decode duration. The option must be `None` when profiling is disabled so the shipped-default path does not read a clock. Its first operations are:

```rust
if let Some(elapsed) = decode_elapsed {
    self.stats.add_elapsed(ResolverStat::TranslationDecodeNs, elapsed);
}
if preparation.observation.current() != preparation.key.1 {
    return Err(types::DsrError::GenerationChanged {
        page: preparation.source_page.raw(),
        expected: preparation.key.1.get(),
        observed: preparation.observation.current().get(),
    });
}
if let Some(entry) = self.blocks.get(&preparation.key).copied() {
    self.stats.add(ResolverStat::CacheLookupHits, 1);
    if self.profiling {
        self.stats.add(ResolverStat::OptimisticDecodeDiscards, 1);
        if let Some(elapsed) = decode_elapsed {
            self.stats
                .add_elapsed(ResolverStat::OptimisticDecodeDiscardNs, elapsed);
        }
    }
    // Backfill PublishedBlockIndex and return BlockIndexHit.
}
```

After those checks, move the existing source-word capture, plan metadata, emit, artifact/shared recording, `Translations`/`TranslationNs`, and `publish_emitted` code unchanged under the writer.

- [ ] **Step 6: Orchestrate the unlocked decoder**

Add the private generic method:

```rust
fn translate_read_mostly_with<D>(
    &mut self,
    memory: &NativeMappedMemory,
    guest: carrick_guest_mem::GuestVa,
    decode: D,
) -> Result<TranslationResult, types::DsrError>
where
    D: FnOnce(
        &NativeMappedMemory,
        carrick_guest_mem::GuestVa,
        types::CodeGeneration,
        usize,
    ) -> Result<block::BlockPlan, types::DsrError>,
```

Acquire the writer with `DsrSynchronizationKind::ProcessStateWrite`, call preparation, and return a `Complete` result immediately. For `Fresh`, explicitly `drop(state)`, begin/end the Decode subphase around the closure, start/read `Instant` only when `preparation.profiling` is true, reacquire the same writer, and call commit. Close `dsr_translate_end` exactly once for every fresh result, including decode and commit errors.

Keep production `translate_read_mostly` as:

```rust
self.translate_read_mostly_with(memory, guest, |memory, guest, generation, segments| {
    block::plan_block_with_segments(memory, guest, generation, 256, segments)
})
```

- [ ] **Step 7: Run the structural and ordinary translation tests**

Run:

```bash
cargo test -p carrick-dsr-aarch64 --lib \
  translator::tests::fresh_block_decode_is_outside_the_process_state_writer \
  -- --exact --nocapture
cargo test -p carrick-dsr-aarch64 --lib translator::tests -- --nocapture
```

Expected: PASS. Do not commit yet; the concurrency semantics are the deliverable of Task 3.

### Task 3: Prove race, generation, error, and replay semantics

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:4880-6500`
- Modify: `crates/carrick-dsr-aarch64/src/artifact_spike.rs:880-910,2860-3020`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs:315-490`

**Interfaces:**
- Consumes: `translate_read_mostly_with` and `TranslationPreparation` from Task 2.
- Produces: deterministic tests with no sleeps and no production synchronization state.
- Produces: hidden `ThreadTranslator::translate_for_test` so cross-crate runtime tests exercise the production orchestration instead of locking `ProcessState` directly.

- [ ] **Step 1: Write the red deterministic same-key race test**

Use `NativeMappedMemory::shared_install_test_fixture(4096)`, an `Arc<ProcessTranslator>`, two `ThreadTranslator`s, and a two-party `Barrier`. Each decoder closure waits at the barrier and returns the same minimal syscall `BlockPlan` at its supplied generation.

Set `process.state.write().profiling = true` before launching the threads so duration assertions exercise the opt-in counters while production profile-off code remains clock-free.

Assert:

```rust
assert_eq!(first.entry, second.entry);
assert_eq!(process.lifecycle_snapshot().1, 1);
let stats = process.state.read().stats;
assert_eq!(stats.translations, 1);
assert_eq!(stats.optimistic_decode_discards, 1);
assert!(stats.optimistic_decode_discard_ns > 0);
assert!(stats.translation_decode_ns >= stats.optimistic_decode_discard_ns);
```

- [ ] **Step 2: Run the race test and prove red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 --lib \
  translator::tests::concurrent_same_key_decode_emits_and_publishes_once \
  -- --exact --nocapture
```

Expected: FAIL until the second authoritative lookup and discard accounting are correct.

- [ ] **Step 3: Make the race test green**

Repair only preparation/commit ordering and counters. Do not add an election map, sleep, retry loop, or concurrent emission. Both callers return `BlockIndexHit`/`Translated` in either order but the same authoritative entry.

- [ ] **Step 4: Add generation-change and decode-error tests**

For generation change, have the decoder closure call:

```rust
memory
    .note_dsr_code_mutation(guest.raw(), 4)
    .expect("generation bump")
    .expect("changed generation");
```

before returning its plan. Assert `GenerationChanged`, zero blocks, zero translations, and unchanged cache used bytes.

For decode error, return `Err(types::DsrError::BlockPolicy("injected decode failure".into()))`; assert the same zero-mutation state and no optimistic discard. The probe lifecycle source test must find one fresh-path `dsr_translate_begin` and one common fresh-path `dsr_translate_end`, rather than per-error duplicated ends.

- [ ] **Step 5: Prove replay paths never call the fresh decoder**

Extend `native_tap_unit_install` so a configured unit is moved into an `Arc<ProcessTranslator>`, translated through a `ThreadTranslator`, and passed a closure that increments an `AtomicU64` then panics. Assert `TranslationOutcome::SharedUnit` and decoder count zero.

Add this test-only artifact factory inside `artifact_spike.rs`:

```rust
#[cfg(test)]
pub(crate) fn empty_store_for_test() -> Result<ArtifactStore, DsrError> {
    ArtifactAuthority::create_for_test()?.map_store()
}
```

In the translator test, use a separate recording cache plus `emit_block_recording_artifact` to obtain an `ArtifactRecord`. Insert its template into the factory store under `ArtifactKey::from_image_digest`, set the target process's `artifact_image_digest` and `artifact_store`, then call `translate_read_mostly_with` with the same panic/counting decoder closure. Assert `TranslationOutcome::ArtifactReplay` and decoder count zero. This exercises the real filter, lookup, relocation/replay, and publication path without process-global environment state.

Also retain a structural ordering assertion that `store.lookup(artifact_key)` appears before the only `PreparedTranslation::Fresh` construction.

- [ ] **Step 6: Migrate runtime tests off direct ProcessState translation**

Add:

```rust
#[doc(hidden)]
pub fn translate_for_test(
    &mut self,
    memory: &NativeMappedMemory,
    guest: carrick_guest_mem::GuestVa,
) -> Result<TranslationResult, types::DsrError> {
    self.translate_read_mostly(memory, guest)
}
```

Replace the five runtime-test `process.state.write().translate(...)` calls with `ThreadTranslator::for_process(...).translate_for_test(...)`. Keep direct read-only `cached_block` assertions where the test is specifically about the authoritative index.

- [ ] **Step 7: Prove process-delta accounting exactly once**

Extend `process_resolver_deltas_are_counted_exactly_once_across_threads` and drained-sibling field lists to cover both new fields. Seed `optimistic_decode_discards = 7` and `optimistic_decode_discard_ns = 19`, claim from two threads, and assert the summed records equal exactly 7 and 19 while drained siblings report zero.

- [ ] **Step 8: Run the concurrency and lifecycle gate repeatedly**

Run:

```bash
for run in 1 2 3 4 5; do
  cargo test -p carrick-dsr-aarch64 --lib \
    translator::tests::concurrent_same_key_decode_emits_and_publishes_once \
    -- --exact --nocapture || exit 1
done
cargo test -p carrick-dsr-aarch64 --lib translator::tests -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime \
  native_darwin::dsr::tests --lib -- --nocapture
```

Expected: every run PASS with one emitted block and one discard in the deterministic race.

- [ ] **Step 9: Commit the lock split**

```bash
git add crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-dsr-aarch64/src/artifact_spike.rs \
  crates/carrick-runtime/src/native_darwin/dsr/mod.rs
git commit -m "perf(native): decode blocks outside process writer"
```

### Task 4: Run focused correctness gates and inspect the candidate

**Files:**
- Modify only if a gate exposes a candidate defect in the files already listed.

**Interfaces:**
- Consumes: committed optimistic-decode implementation.
- Produces: a clean focused-test/clippy result and a signed candidate binary with recorded source and hash.

- [ ] **Step 1: Format and run focused gates**

```bash
just fmt
cargo test -p carrick-dsr --lib -- --nocapture
cargo test -p carrick-dsr-aarch64 --lib -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib -- --nocapture
cargo clippy -p carrick-dsr -p carrick-dsr-aarch64 -p carrick-runtime --all-targets -- -D warnings
PYTHONPATH=scripts/perf python3 -m unittest \
  scripts/perf/test_native_compiler_budget.py \
  scripts/perf/test_direct_binding_mechanism.py -v
```

Expected: all PASS and no warning. Fix candidate defects red-first and make a narrow corrective commit before continuing.

- [ ] **Step 2: Audit forbidden shapes**

```bash
rg -n "ConcurrentPublicationIndex|duplicate_publications|DuplicatePublications" \
  crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-dsr/src/profile.rs \
  crates/carrick-runtime/src/native_darwin/dsr/mod.rs \
  scripts/perf
git diff a5bd4971 -- crates/carrick-dsr-aarch64/src/translator.rs
```

Expected: no revived arbitration/obsolete field; diff shows decode outside the writer and all cache mutation inside commit.

- [ ] **Step 3: Build and prove the signed binary**

```bash
just build
codesign -d --entitlements :- target/release/carrick
otool -l target/release/carrick | rg '__dof_carrick'
shasum -a 256 target/release/carrick
git rev-parse HEAD
git status --short
```

Expected: signed binary, retained DOF section, known SHA/source, and clean tree.

### Task 5: Run untraced counters and repeated DTrace mechanism checks

**Files:**
- Create target-only receipts under `target/perf/native-optimistic-decode/`.
- Modify candidate code only if the mechanism contradicts the design.

**Interfaces:**
- Produces: two complete NATIVEPERF logs with exact discard work.
- Produces: two accepted `native-wall` captures comparable to `target/perf/current-syscall-split/candidate-stack-{A,C}`.

- [ ] **Step 1: Run two untraced mechanism profiles**

```bash
mkdir -p target/perf/native-optimistic-decode
mkdir -p target/perf/native-optimistic-decode/stack-A \
  target/perf/native-optimistic-decode/stack-B
for label in A B; do
  python3 scripts/perf/native_go_dtrace_target.py \
    --variant default \
    --run-id "optimistic-decode-profile-$label-20260804" \
    --mechanism-profile \
    >"target/perf/native-optimistic-decode/profile-$label.out" \
    2>"target/perf/native-optimistic-decode/profile-$label.log" || exit 1
done
```

Require `BUILD_OK`, complete NATIVEPERF groups, no parser errors, and record sums for translations, decode ns, discard count/ns, emit ns, publication ns, and nested translation ns.

- [ ] **Step 2: Apply the duplicate-work stop condition**

Compute for each run:

```text
discard_share = optimistic_decode_discard_ns / nested_translation_decode_ns
```

Stop the candidate if discard share consumes the plausible concurrency benefit, if discard counts approach published translations, or if total decode CPU rises enough to erase the previous 10.52% opportunity. Otherwise continue and record the observed count/share before interpreting timing.

- [ ] **Step 3: Run two qualified native-wall captures**

```bash
for label in A B; do
  python3 scripts/perf/native_go_dtrace_target.py \
    --variant default \
    --run-id "optimistic-decode-stack-$label-20260804" \
    --trace-script scripts/dtrace/native-wall.d \
    --trace-output "target/perf/native-optimistic-decode/stack-$label/raw.trace" \
    >"target/perf/native-optimistic-decode/stack-$label/launcher.out" \
    2>"target/perf/native-optimistic-decode/stack-$label/launcher.err" || exit 1
done
```

Let each trace finish naturally. Require `complete=true`, zero drops, zero incomplete pairs, no overflow, and accepted symbolization. Compare total `psynch_cvwait` share and the exact `RawRwLock::lock_exclusive_slow -> translate_read_mostly` stack to the retained 15.1508% / 15.2155% candidate captures.

- [ ] **Step 4: Decide whether the mechanism gate passes**

Continue to ABBA only if both traces remove or materially reduce the intended exclusive-writer stack and the NATIVEPERF counters explain the residual/duplicate work. If the stack is unchanged, revert the candidate implementation commits and write the stopped-hypothesis evidence in Task 7.

### Task 6: Run the controlled eight-quad CPU gate

**Files:**
- Create target-only detached worktree `.worktrees/native-optimistic-control` at `a5bd4971`.
- Create target-only arm receipts and ABBA artifact under `target/perf/native-optimistic-decode/`.

**Interfaces:**
- Produces: exact signed control and candidate arm receipts.
- Produces: complete two-warmup plus eight A-B-B-A-quad campaign using identical `native-default.json` overlays.

- [ ] **Step 1: Prepare a clean exact control worktree**

```bash
git worktree add --detach \
  /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control \
  a5bd4971
git -C /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control status --short
git status --short
```

Expected: both worktrees clean. Do not move local `main`.

- [ ] **Step 2: Build and freeze both signed arms**

```bash
just \
  -f /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control/justfile \
  -d /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control \
  build
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control \
  --destination target/perf/native-optimistic-decode/control-arm \
  --label retained-a5bd4971 \
  --role control \
  --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo "$PWD" \
  --destination target/perf/native-optimistic-decode/candidate-arm \
  --label optimistic-decode-tip \
  --role candidate \
  --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
```

Require clean source receipts, signed binaries, exact hashes, arm64 image identity, and DOF sections.

- [ ] **Step 3: Run the official comparison**

```bash
python3 scripts/perf/native_go_build_abba.py run \
  --harness-repo "$PWD" \
  --control-receipt "$PWD/target/perf/native-optimistic-decode/control-arm/arm.json" \
  --candidate-receipt "$PWD/target/perf/native-optimistic-decode/candidate-arm/arm.json" \
  --control-overlay "$PWD/scripts/perf/overlays/native-default.json" \
  --candidate-overlay "$PWD/scripts/perf/overlays/native-default.json" \
  --quads 8 \
  --cooldown-seconds 2 \
  --timeout-seconds 30 \
  --allow-battery \
  --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b \
  --output "$PWD/target/perf/native-optimistic-decode/abba-v1.json"
```

Battery is explicitly authorized by the user; thermal/load/cleanup/image gates remain mandatory.

- [ ] **Step 4: Apply the retention rule**

Require complete/accepted evidence, 32/32 `BUILD_OK`, and no cleanup, timeout, thermal, load, image, or receipt failures. Retain when the two-sided paired total-child-CPU interval excludes 1.0 in the favorable direction and supported secondary metrics do not regress. At least 10% CPU is desired; a smaller result requires an explicit evidence-backed non-regrettable-enabler decision. Treat wall as resolved only if its ratio interval excludes 1.0.

If CPU is flat/regressed, revert only the candidate implementation commits, preserve the design/plan and target receipt, and proceed to Task 7 as a stopped hypothesis.

### Task 7: Close the candidate with full gates and durable evidence

**Files:**
- Create: `docs/perf-results/2026-08-04-native-optimistic-decode.md`
- Modify: `handoff.md`
- Modify implementation files only for red-first correctness fixes exposed by gates.

**Interfaces:**
- Produces: retained or stopped evidence with source/binary/semantics/receipt provenance.
- Produces: current next bucket and confidence levels in `handoff.md`.

- [ ] **Step 1: Run full correctness gates for a retained candidate**

```bash
RUST_TEST_THREADS=1 just ci
just build
just conformance-native smoke
```

- [ ] **Step 2: Write the evidence record**

Record:

- control/candidate commit and binary SHA-256;
- signed/DOF status and exact image digest;
- NATIVEPERF counter sums and discard share for both runs;
- both DTrace artifact hashes and acceptance invariants;
- eight-quad CPU/user/sys/wall ratios, intervals, wins, and sign-test result;
- whether the candidate was retained or reverted and the exact criterion;
- all focused/full/conformance gates actually run;
- current official 10.1776x scoreboard status (unchanged unless a serialized Carrick-then-Docker refresh is justified);
- the next largest measured residual bucket and updated confidence.

- [ ] **Step 3: Update the handoff**

Replace the optimistic-decode next step with measured outcome. Keep eager whole-image translation explicitly deferred. If retained wall is unresolved, do not claim a new official Docker ratio; if wall resolves, schedule a fresh serialized Carrick-then-Docker scoreboard before changing the official ratio.

- [ ] **Step 4: Commit evidence and handoff**

```bash
git add docs/perf-results/2026-08-04-native-optimistic-decode.md handoff.md
git commit -m "docs(perf): record optimistic decode experiment"
git status --short
```

Expected: clean candidate worktree. Nothing is pushed and local `main` is not moved.

- [ ] **Step 5: Continue the active performance goal**

If the official ratio remains above 3x, do not close the goal. Attribute the next largest remaining non-guest CPU bucket or guest-operation amplification with Carrick DTrace/USDT or LLDB and begin one new single-variable design cycle.
