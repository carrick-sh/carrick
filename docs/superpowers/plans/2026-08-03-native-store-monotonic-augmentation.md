# Native Translation-Store Monotonic Augmentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the shipped-default Darwin/AArch64 native translation store monotonically accumulate valid demand-observed executable blocks, cutting both `segment-repeat` and total private translations by at least 50% and retaining the change only if cold `go build` child CPU improves by at least 10% under a receipt-bound n>=8 ABBA campaign.

**Architecture:** Replace the frozen two-file store with one atomically replaced `unit-v1` inode per translation key. Normalize loaded and newly recorded blocks into one owned artifact, elect at most one nonblocking recorder per process/segment, append the winner's artifacts to crash-readable stable chunks, and deterministically merge that committed prefix at guest exec or process exit. Store failures remain performance-only; live/core diagnostics export the same pending bytes through a separate read-only ABI and can never publish them.

**Tech Stack:** Rust 2024, existing bincode/serde/SHA-256/memmap2/getrandom dependencies, Darwin `openat`/`flock`/`rename`/`fsync`, the current AArch64 DSR native-emission tap, Python only inside the existing LLDB and performance harnesses, DTrace/USDT mechanism evidence, and the signed Carrick native conformance lane.

## Global Constraints

- Scope is Darwin/AArch64 native DSR. Do not alter VMM/HVF, KVM, bhyve, NVMM, x86 DSR, Tier D defaults, or add a second native-driver wiring point.
- `TRANSLATOR_ABI_CURRENT` moves from 8 to 9. ABI 9 reads only `{stem}.unit-v1`; it does not migrate, search, delete, or account the old ABI-8 `.code`/`.metadata-v5` cache.
- Preserve source identity, complete `TranslationUnitKey`, page profile, address mode, source fingerprint, code digest, relocation, recovery, PC-map, and sensitive-metadata validation.
- Record only INITIAL-generation native-tap blocks inside the exact configured executable segment. Regenerated, self-modified, guest-JIT, JIT-on-JIT, and out-of-segment blocks remain private.
- The only translation-hot-path filesystem action is one nonblocking claim attempt on the first eligible uncovered block per process/segment. There is no wait, periodic flush, background thread, or per-block store merge.
- Store load, claim, merge, sync, capacity, validation, and debugger failures never change whether the current guest executes. They become typed counters/diagnostics and private-translation fallback.
- One final bundle is one inode. Readers stay lockless and pin whichever complete inode they opened; writers lock, reload, union, preflight, and atomically rename.
- The append-only pending representation is canonical. Publication and debugger export read its release-committed prefix; neither creates a second artifact copy.
- Core handling is export-only. No importer, replay command, recovery hook, store rename trick, or store mutation from a core/export is permitted.
- The temporary `CARRICK_DSR_STORE_AUGMENTATION=0` hatch is evidence-only. Exact `0` suppresses augmentation of an attached unit but still permits first publication on a true file miss. Remove the hatch, its overlays, and its performance-control entry before the retained implementation is finalized.
- AC versus battery is recorded metadata, never an inclusion/exclusion rule. Thermal/load/core-placement gates remain authoritative.
- Never run Carrick and Docker concurrently. Build runnable binaries with `just build`, prove the exact binary hash/signature/DOF section, and serialize Carrick before Docker.
- Use red-first tests. Keep each implementation commit narrow, independently compiling, and verified. Preserve unrelated worktree state.
- Eager recursive-descent translation is deliberately deferred. Add no eager traversal, configuration, or placeholder API.

## File Structure

- Create `crates/carrick-dsr-aarch64/src/shared_cache/unit_bundle.rs`: portable `unit-v1` header/codec, normalized artifacts, deterministic pack/decode/union, and typed merge outcomes.
- Modify `crates/carrick-dsr-aarch64/src/shared_cache.rs`: ABI/schema identity, source extents, trait contracts, loaded-unit views, miss reasons, and re-exports from `unit_bundle`.
- Modify `crates/carrick-dsr-aarch64/src/artifact_spike.rs`: exact conversion between `ArtifactTemplate` and normalized code/hot/cold bytes.
- Create `crates/carrick-dsr-aarch64/src/pending_augmentation.rs`: process-incarnation owner, segment claim state, stable chunk arena, core ABI root, committed-prefix reader, caps, and fork reset.
- Modify `crates/carrick-dsr-aarch64/src/lib.rs`: expose the pending module to the native runtime and retain the core root.
- Modify `crates/carrick-dsr-aarch64/src/translator.rs`: augmentation hatch, claim-on-gap state machine, canonical append, lifecycle merge, typed counters, exact census schema, and integration tests.
- Modify `crates/carrick-native-darwin/src/aot_cache.rs`: `.unit-v1` pruning/loading, one-inode lease, typed builder records, stale takeover, deterministic locked merge, failure injection, and atomic publication.
- Modify `crates/carrick-runtime/src/native_darwin.rs`: nonfatal pre-exec/exit merge consumption and existing fork-child reset wiring.
- Modify `crates/carrick-cli/src/debug_census.rs`: aggregate the new counters and bump the report schema.
- Modify `scripts/carrick_lldb.py`: register `carrick xlat-pending` summary/export commands.
- Create `scripts/carrick_lldb_xlat.py`: pure validated core-ABI reader and export serializer imported by the LLDB plugin.
- Create `scripts/test_carrick_lldb_xlat.py`: synthetic live/core reader tests independent of an installed `lldb` Python module.
- Modify `scripts/perf/native_go_build.py` and every `scripts/perf/overlays/*.json`: temporary augmentation control provenance.
- Modify `scripts/perf/native_go_dtrace_target.py` and `scripts/perf/test_native_go_dtrace_target.py`: explicit store directory/augmentation mechanism controls.
- Modify `scripts/perf/native_go_build_abba.py` and `scripts/perf/test_native_go_build_abba.py`: validated sparse seed snapshot, per-sample exact restoration, receipt hashes, and 0.90 retention threshold.
- Modify `scripts/perf/README.md`: exact sparse-seed mechanism and ABBA invocation.
- Create or update a dated artifact under `docs/perf-results/`: measured mechanism, ABBA, regression, correctness, and official-ratio result.
- Modify `handoff.md`: current retained/killed decision, receipts, confidence, and next attributed bucket.

---

### Task 1: Define the portable normalized artifact and `unit-v1` codec

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs:31-32,270-460,664-684,943-1140,1247-1808`
- Modify: `crates/carrick-dsr-aarch64/src/artifact_spike.rs:213-230,1898-2115`
- Create: `crates/carrick-dsr-aarch64/src/shared_cache/unit_bundle.rs`
- Test: `crates/carrick-dsr-aarch64/src/shared_cache/unit_bundle.rs`

**Interfaces:**

```rust
pub const TRANSLATOR_ABI_CURRENT: u32 = 9;
pub const TRANSLATION_UNIT_SCHEMA_V6: u32 = 6;
pub const UNIT_BUNDLE_SCHEMA_V1: u32 = 1;
pub const UNIT_BUNDLE_MAGIC_V1: [u8; 8] = *b"CUNITB1\0";
pub const UNIT_BUNDLE_HEADER_BYTES_V1: usize = 104;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBlockArtifact {
    pub guest_start: GuestVa,
    pub source_end: GuestVa,
    pub generation: CodeGeneration,
    pub requires_sensitive_metadata: bool,
    pub code: Box<[u8]>,
    pub hot: Box<[u8]>,
    pub cold: Box<[u8]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTranslationUnit {
    pub key: TranslationUnitKey,
    pub blocks: Vec<StoredBlockArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeRefusal {
    Conflict { guest_start: GuestVa },
    Capacity,
    Preflight(UnitMissReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeKind {
    Created,
    Merged,
    Unchanged,
    Repaired,
    Yielded,
    Refused(MergeRefusal),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeOutcome {
    pub kind: MergeKind,
    pub blocks_added: u64,
    pub duplicates: u64,
    pub post_rename_sync_failed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitStoreFailureClass {
    Io,
    Validation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitStoreFailure {
    pub class: UnitStoreFailureClass,
    pub reason: UnitMissReason,
}
```

The 104-byte bundle header is fixed little-endian: magic `[0..8]`, schema u32, header length u32, exact file length u64, translator ABI u32, reserved u32, metadata offset/length u64, code offset/length u64, block count u64, and exact code-region SHA-256 `[72..104]`. Metadata V6 adds `source_end` to every fixed index row and uses a new magic; no V5 decoder is reachable from ABI 9.

- [ ] **Step 1: Write failing normalized-artifact and bundle tests**

Add exact tests named:

```rust
#[test] fn unit_v1_round_trip_is_byte_deterministic()
#[test] fn unit_v1_rejects_bad_magic_schema_abi_and_key()
#[test] fn unit_v1_rejects_bad_extent_offset_alignment_overlap_and_trailing_bytes()
#[test] fn unit_v1_rejects_bad_digest_order_duplicate_start_and_truncation()
#[test] fn normalized_union_adds_disjoint_blocks_in_guest_order()
#[test] fn normalized_union_coalesces_only_byte_exact_duplicates()
#[test] fn normalized_union_preserves_old_on_same_start_conflict()
#[test] fn normalized_union_rejects_code_and_metadata_capacity_boundaries()
#[test] fn artifact_template_round_trips_through_stored_block_artifact()
```

The deterministic test must encode the same input twice and encode both input orders; all three byte strings must be identical. The conflict test must vary `source_end`, code, hot metadata, and cold metadata separately and verify that every variation conflicts.

- [ ] **Step 2: Run the focused test and confirm red**

```bash
cargo test -p carrick-dsr-aarch64 unit_v1_ --lib
```

Expected: compilation fails because `StoredBlockArtifact`, V6 metadata, and the `unit_bundle` codec do not exist.

- [ ] **Step 3: Implement exact artifact conversion**

Add crate-visible helpers to `ArtifactTemplate` that consume a native-tap record into canonical code/hot/cold bytes and reconstruct replay metadata from those same bytes. Use the existing `into_unit_record_metadata`, `into_unit_wire_parts`, and `from_unit_wire_parts` logic; do not invent a second serialization. Reject empty/non-word-aligned code and any generation other than `CodeGeneration::INITIAL`.

The candidate conversion records `BlockPlan.end` as `source_end`, zeroes relocation immediates exactly as the current packer does, and charges serialized hot+cold byte lengths before returning the artifact.

- [ ] **Step 4: Implement the fixed bundle header and V6 metadata**

Use checked arithmetic for every addition/multiplication/conversion. Require:

- exact `file_len == bytes.len()` and no trailing bytes;
- metadata and code ranges aligned to 8 bytes, non-overlapping, and within the exact extent;
- code length `1..=64 MiB`, divisible by four;
- decoded/mapped metadata `<=256 MiB`;
- bundle block count equal to the V6 manifest block count;
- current translator ABI and the complete expected key;
- strict guest-start ordering and unique starts;
- `guest_start < source_end`, with the complete source extent inside the key's guest segment; and
- exact SHA-256 over only the code region.

Make `TranslationUnitManifest` retain the whole backing byte owner plus `code_offset`; block replay uses `source_base = mapping_base + code_offset` without copying the bundle.

- [ ] **Step 5: Implement deterministic union and pack**

Union into `BTreeMap<GuestVa, StoredBlockArtifact>`. Validate every pending artifact independently before insertion. Exact equality increments `duplicates`; any unequal artifact at the same guest start returns `MergeRefusal::Conflict` and the caller must preserve the old bundle. Sort by guest start, rebuild entry offsets, and produce a byte-identical bundle for an identical artifact set.

Permit `PendingTranslationUnit { blocks: vec![] }`; this represents an empty lease release and is not encodable as a new unit.

- [ ] **Step 6: Run focused tests and the crate library suite**

```bash
cargo test -p carrick-dsr-aarch64 unit_v1_ --lib
cargo test -p carrick-dsr-aarch64 normalized_union_ --lib
cargo test -p carrick-dsr-aarch64 artifact_template_round_trips_through_stored_block_artifact --lib
cargo test -p carrick-dsr-aarch64 --lib
just fmt-check
```

Expected: all new corruption/round-trip/union tests and the existing DSR library suite pass.

- [ ] **Step 7: Commit Task 1**

```bash
git add crates/carrick-dsr-aarch64/src/shared_cache.rs \
  crates/carrick-dsr-aarch64/src/shared_cache/unit_bundle.rs \
  crates/carrick-dsr-aarch64/src/artifact_spike.rs
git commit -m "feat(dsr): define atomic translation unit bundles"
```

The body must name ABI 9, the single-inode V1 format, deterministic union semantics, and focused test commands.

---

### Task 2: Build append-only pending storage and the crash-readable core ABI

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs:19-42`
- Create: `crates/carrick-dsr-aarch64/src/pending_augmentation.rs`
- Test: `crates/carrick-dsr-aarch64/src/pending_augmentation.rs`

**Interfaces:**

```rust
pub const XLAT_PENDING_CORE_MAGIC_V1: [u8; 8] = *b"CXLATP1\0";
pub const XLAT_PENDING_CORE_SCHEMA_V1: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordingOwner {
    pub pid: i32,
    pub incarnation: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentClaimState {
    Unseen,
    Attached,
    Uncovered,
    ClaimWon,
    ClaimLost,
}

#[repr(C)]
pub struct XlatPendingCoreRootV1 {
    pub magic: [u8; 8],
    pub schema: u32,
    pub root_len: u32,
    pub pid: AtomicI32,
    pub incarnation_hi: AtomicU64,
    pub incarnation_lo: AtomicU64,
    pub first_unit: AtomicPtr<XlatPendingUnitV1>,
    pub committed_units: AtomicU64,
}

#[used]
#[unsafe(no_mangle)]
pub static carrick_xlat_pending_core_v1: XlatPendingCoreRootV1 =
    XlatPendingCoreRootV1::dormant();
```

Each stable `XlatPendingUnitV1` node contains the serialized complete key pointer/length, segment bounds, claim state, exact owner PID/nonce, and its first record chunk. Each fixed-capacity chunk owns stable boxed code/hot/cold buffers and fixed `#[repr(C)]` descriptors containing guest start/end, generation, sensitive flag, pointers, and lengths. Allocate/init payload, write the complete descriptor, then release-store the committed record count. Link a fully initialized next chunk before release-incrementing that unit's committed chunk count; link a fully initialized unit node before release-incrementing the root's committed unit count. Nodes/chunks are retained until exec/exit publication or fork reset.

- [ ] **Step 1: Write failing prefix, cap, and fork tests**

Add tests named:

```rust
#[test] fn pending_prefix_exposes_only_release_committed_records()
#[test] fn pending_chunk_link_is_visible_only_after_initialization()
#[test] fn pending_prefix_reuses_canonical_artifact_bytes()
#[test] fn pending_capacity_keeps_the_already_committed_prefix()
#[test] fn pending_reset_after_fork_clears_owner_claims_chunks_and_root()
#[test] fn owner_nonce_is_fresh_after_reset_and_never_all_zero()
#[test] fn core_root_layout_and_symbol_schema_are_pinned()
```

The torn-record fixture writes a descriptor without advancing the committed count and proves a reader returns the earlier prefix only. The canonical-bytes test compares all exported pointers/lengths to the `StoredBlockArtifact` buffers later consumed by publication.

- [ ] **Step 2: Run the focused tests and confirm red**

```bash
cargo test -p carrick-dsr-aarch64 pending_augmentation::tests --lib
```

Expected: compilation fails because the module and ABI root do not exist.

- [ ] **Step 3: Implement process ownership and stable chunks**

Generate the 128-bit incarnation with `getrandom` lazily on the first won claim after process start/fork repair. Treat an all-zero result as invalid and retry/fail the claim without guest impact. Appends remain serialized by the existing `ProcessState` write lock; atomics exist solely for stopped-live/core readers.

Charge code against 64 MiB and serialized metadata against 256 MiB before linking a record. On overflow, stop recording that unit, preserve its existing prefix, and return a typed capacity result to the counter layer.

- [ ] **Step 4: Implement committed-prefix conversion and reset**

`PendingAugmentation::drain_committed_units()` first detaches the published core root, then groups committed records by complete `TranslationUnitKey` and moves their canonical `StoredBlockArtifact` buffers into `PendingTranslationUnit` values. It does not clone a second pending representation. `reset_after_fork_child()` clears segment states, pending chunks, owner/nonce, and publishes a dormant root. The parent is unchanged.

Do not free a chunk while its address can remain reachable from the published root. At exec/exit publication, first detach the root, then consume/drop the arena after merge outcomes are recorded.

- [ ] **Step 5: Run focused tests and symbol retention check**

```bash
cargo test -p carrick-dsr-aarch64 pending_augmentation::tests --lib
cargo test -p carrick-dsr-aarch64 --lib
just build
nm -gU target/release/carrick | rg 'carrick_xlat_pending_core_v1'
```

Expected: all tests pass and exactly one externally visible core-root symbol is present in the signed binary.

- [ ] **Step 6: Commit Task 2**

```bash
git add crates/carrick-dsr-aarch64/src/lib.rs \
  crates/carrick-dsr-aarch64/src/pending_augmentation.rs
git commit -m "feat(dsr): retain crash-readable pending translations"
```

The body must explain release-published stable prefixes, fork reset, caps, and why the core ABI is diagnostic rather than store authority.

---

### Task 3: Replace the Darwin pair store with atomic bundle loading and merging

**Files:**
- Modify: `crates/carrick-native-darwin/src/aot_cache.rs:21-282,385-607,815-1196,1294-1364,1376-2300`
- Test: `crates/carrick-native-darwin/src/aot_cache.rs`

**Interfaces:**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordingClaim {
    pub owner: RecordingOwner,
    pub stale_takeover: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    Won(RecordingClaim),
    LiveOwner,
    Yielded,
}

pub trait TranslationUnitStore: Send + Sync {
    fn load(
        &self,
        key: &TranslationUnitKey,
        source_words: &[u32],
    ) -> Result<Option<SharedLoadedTranslationUnit>, UnitMissReason>;

    fn claim_recording(
        &self,
        key: &TranslationUnitKey,
        owner: &RecordingOwner,
    ) -> Result<ClaimOutcome, UnitStoreFailure>;

    fn merge(
        &self,
        pending: &PendingTranslationUnit,
        claim: &RecordingClaim,
    ) -> Result<MergeOutcome, UnitStoreFailure>;
}
```

The builder record is a fixed versioned mode-0600 value containing PID, 16-byte nonce, creation Unix nanoseconds, and exact stem. A lease is live only if PID liveness succeeds and age is nonnegative and below `BUILDER_CLAIM_TTL`; malformed records, dead owners, future/negative ages, and aged owners are stale.

- [ ] **Step 1: Write failing one-inode reader and pruner tests**

Add tests named:

```rust
#[test] fn unit_v1_load_pins_one_read_only_private_inode()
#[test] fn unit_v1_load_rejects_symlink_directory_and_nonregular_file()
#[test] fn unit_v1_old_reader_survives_atomic_replacement()
#[test] fn unit_v1_new_reader_sees_complete_union_after_replacement()
#[test] fn pruner_counts_and_removes_only_unit_v1_files_in_current_abi()
#[test] fn abi9_ignores_abi8_code_and_metadata_v5_pairs()
```

- [ ] **Step 2: Write failing lease and merge tests**

Add tests named:

```rust
#[test] fn live_owner_blocks_claim_without_waiting()
#[test] fn busy_unit_lock_returns_yielded_without_waiting()
#[test] fn dead_aged_malformed_and_future_builder_records_are_taken_over()
#[test] fn matching_owner_releases_builder_on_every_clean_merge_return()
#[test] fn stale_owner_cannot_unlink_successor_builder()
#[test] fn existing_unit_does_not_refuse_a_new_recording_claim()
#[test] fn sequential_publishers_reload_and_preserve_both_unions()
#[test] fn exact_duplicate_merge_is_unchanged_and_counted()
#[test] fn corrupt_final_is_replaced_only_by_valid_pending_data()
#[test] fn conflict_capacity_and_preflight_preserve_old_valid_bundle()
#[test] fn post_rename_directory_sync_error_keeps_visible_union_and_reports_it()
```

- [ ] **Step 3: Run focused tests and confirm red**

```bash
cargo test -p carrick-native-darwin unit_v1_ --lib
cargo test -p carrick-native-darwin builder --lib
cargo test -p carrick-native-darwin sequential_publishers_reload --lib
```

Expected: compilation fails because the current store uses two files, boolean claims, and frozen publication.

- [ ] **Step 4: Implement one-file loading and pruning**

Open `{stem}.unit-v1` beneath the already validated authority via `openat(authority_fd, name, O_RDONLY | O_NOFOLLOW)`, `fstat` a regular file, mmap the whole exact extent `MAP_PRIVATE | PROT_READ`, and pass the mapped owner through the portable production decoder. `LoadedTranslationUnit` retains one mapping/FD lease; `source_base` points to the mapping's code offset.

Replace `.code`/`.metadata-v5` pair enumeration with strict `.unit-v1` recognition. Ignore `.builder`, `.lock`, temporaries, old suffixes, and old ABI directories. Keep the current 1 GiB cap against complete current-ABI bundle sizes.

- [ ] **Step 5: Implement typed nonblocking claims**

Under `LOCK_EX | LOCK_NB`, parse the builder record and apply both liveness and age. Do not reject because a final bundle exists. Write the replacement builder via a mode-0600 temporary plus atomic rename while holding the lock. Return `Won { stale_takeover }`, `LiveOwner`, or `Yielded`; I/O/validation returns `UnitStoreFailure` with an exact class and miss reason.

Create a `BuilderReleaseGuard` containing stem and exact `RecordingOwner`. On drop/explicit finish it reacquires the unit lock and removes `.builder` only if both PID and nonce still match. It must run for empty publication, conflict, capacity, preflight, temporary-write, rename, and ordinary I/O exits. A hard crash intentionally leaves the record.

- [ ] **Step 6: Implement locked reload/union/publication**

For nonempty pending data:

1. acquire the unit lock;
2. reopen and fully validate the current final path for the expected key;
3. treat `ENOENT` as creation and an invalid existing file as repair without decoding any of its blocks;
4. union current valid blocks and individually revalidated pending blocks;
5. preserve old on conflict/cap/preflight refusal;
6. encode one deterministic bundle;
7. create a mode-0600 same-directory temporary, write/flush/`sync_all`;
8. preflight the temp through the production bundle reader using the expected key;
9. rename over `{stem}.unit-v1`; and
10. `fsync` the authority directory.

If directory sync alone fails after rename, return the successful created/merged/repaired kind with `post_rename_sync_failed=true`. Never delete or roll back the visible new inode.

An empty pending unit skips final-file work, releases its lease, and returns `Unchanged` with zero counts. A former owner whose claim token was superseded may still safely merge under the content lock, but its release guard must not remove the successor lease.

- [ ] **Step 7: Add failure injection and concurrency proof**

Add a test-only `PublicationFault` enum with `BeforeTempSync`, `BeforePreflight`, `BeforeRename`, and `DirectorySync`. At every point open a fresh reader and assert it sees the complete old or complete new unit. Hold an old mapping across rename and verify it continues to replay the old bytes. Use a barrier and elapsed-time bound to prove contenders do not block on a held unit lock.

- [ ] **Step 8: Run Darwin store tests and crate gates**

```bash
cargo test -p carrick-native-darwin aot_cache::tests --lib
cargo test -p carrick-dsr-aarch64 shared_cache::tests --lib
just fmt-check
just clippy
```

Expected: all atomicity, stale-owner, concurrency, corruption, and old-reader tests pass; clippy is clean.

- [ ] **Step 9: Commit Task 3**

```bash
git add crates/carrick-dsr-aarch64/src/shared_cache.rs \
  crates/carrick-native-darwin/src/aot_cache.rs
git commit -m "feat(native): merge translation bundles atomically"
```

The body must state that publication is one-inode replacement, old readers pin old content, existing units can be augmented, and every clean path uses nonce-checked lease release.

---

### Task 4: Wire claim-on-gap recording, lifecycle merge, fork reset, and counters

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:141-180,850-920,1055-1160,2180-2420,2474-2580,3049-3465,5650-5940,6595-7650`
- Modify: `crates/carrick-runtime/src/native_darwin.rs:3309-3328,4189,4334`
- Modify: `crates/carrick-cli/src/debug_census.rs:1-90,775-900`
- Test: `crates/carrick-dsr-aarch64/src/translator.rs`
- Test: `crates/carrick-cli/src/debug_census.rs`

**Control semantics:**

```rust
fn store_augmentation_enabled_from(value: Option<&OsStr>) -> bool {
    value != Some(OsStr::new("0"))
}
```

Unset/default means augmentation on. Exact `0` suppresses claims only when a valid existing unit is attached and the block is absent. Both arms still claim on a true missing-file load and may create the identical sparse seed.

**Required counter names:**

```text
shared_augment_claim_won
shared_augment_claim_live_lost
shared_augment_claim_yielded
shared_augment_claim_stale_takeover
shared_augment_claim_error
shared_unit_initial_publish
shared_unit_merge
shared_unit_blocks_added
shared_unit_duplicate_coalesced
shared_unit_conflict
shared_unit_repair
shared_unit_capacity_refused
shared_unit_preflight_refused
shared_unit_io_failed
shared_unit_validation_failed
shared_unit_empty_release
shared_unit_post_rename_sync_failed
```

Map outcomes without inference: `Won` increments claim-won and additionally stale-takeover when flagged; `LiveOwner`, `Yielded`, and claim `Err` increment their exact claim counters. `Created`, `Merged`, and `Repaired` increment their named publication classes; `Unchanged` carries only its duplicate count, while a boundary `Yielded` emits a structured diagnostic and no false success counter. `blocks_added` and `duplicates` add their carried counts. Each `MergeRefusal` variant maps to conflict, capacity, or preflight. `UnitStoreFailureClass::{Io,Validation}` maps directly to its failure counter, an empty drained unit maps to empty-release, and the durability flag independently maps to post-rename-sync-failed.

- [ ] **Step 1: Write failing real-path translator tests**

Extend the fixtures that already drive `try_load_shared_unit` and the real translate/install path. Add tests named:

```rust
#[test] fn loaded_unit_gap_attempts_one_claim_and_records_current_block()
#[test] fn loaded_unit_gap_control_off_never_claims_or_records()
#[test] fn missing_unit_claims_and_initially_publishes_in_both_control_modes()
#[test] fn live_and_yielded_claim_losers_never_record_or_retry()
#[test] fn winner_records_subsequent_eligible_gaps_in_same_segment()
#[test] fn regenerated_outside_segment_and_guest_jit_blocks_never_record()
#[test] fn exec_and_exit_each_merge_at_most_once_per_incarnation()
#[test] fn store_errors_are_counted_and_never_escape_as_dsr_error()
#[test] fn fork_child_clears_claim_nonce_pending_prefix_and_publish_guard()
#[test] fn next_process_replays_merged_bytes_relocations_pc_maps_and_recovery()
```

Use a recording fake `TranslationUnitStore`; do not install a block directly into a private fixture map. The first test must assert that the block which caused the claim is present in the committed prefix, not merely later misses.

- [ ] **Step 2: Run the focused tests and confirm red**

```bash
cargo test -p carrick-dsr-aarch64 loaded_unit_gap_ --lib
cargo test -p carrick-dsr-aarch64 exec_and_exit_each_merge --lib
cargo test -p carrick-dsr-aarch64 next_process_replays_merged --lib
```

Expected: the loaded-unit test fails because `segment-repeat` currently never claims; lifecycle publication still uses frozen `publish` and may return `DsrError`.

- [ ] **Step 3: Replace segment sets/maps with the explicit state machine**

Replace `shared_recording_segments`, `shared_candidates`, and `shared_publish_attempted` with `PendingAugmentation` plus one state entry per key/segment. Transitions are:

```text
Unseen -> Attached
Unseen -> Uncovered -> ClaimWon | ClaimLost       (true missing bundle)
Attached -> Uncovered -> ClaimWon | ClaimLost     (eligible loaded-unit gap, augmentation on)
```

Attempt only once per process/segment. Claim before privately translating the triggering gap, then append its finished native-tap artifact after emission. An invalid existing bundle or attach refusal may claim for repair only when augmentation is enabled. Never claim on regenerated, non-INITIAL, outside-segment, capacity-refused, or guest-JIT paths.

- [ ] **Step 4: Make lifecycle publication nonfatal**

Replace `publish_shared_candidates -> Result<Vec<PublishOutcome>, DsrError>` with a method that drains the committed prefix once, calls `store.merge`, records typed outcomes/errors, and returns no guest-facing error. Keep both existing call sites: immediately before host self-re-exec and at normal process exit. Guard by process incarnation so repeated cleanup calls cannot publish twice.

If candidate revalidation skips an invalid pending record, merge the valid prefix and count validation failure. Map `UnitStoreFailureClass::Io` and `Validation` directly to their named counters; never infer the class from an error string. Empty units release their exact claims and increment `shared_unit_empty_release`. Always detach the core root before dropping chunks.

- [ ] **Step 5: Wire fork reset through the existing seam**

At the current post-fork child reset, call `PendingAugmentation::reset_after_fork_child()` in addition to existing dispatcher/cache resets. Prove the parent retains its batch and the child starts with no inherited claim, batch, nonce, or publish guard.

- [ ] **Step 6: Add typed runtime/census counters and bump schemas**

Add each counter to `ResolverStats`, `ResolverStat::ALL`, token/index round-trip tests, the exact `XLATCENSUS` wire, and the atomic `CensusStore` drain. Bump the process census schema from `XLATCENSUS4` to `XLATCENSUS5`. Update `debug_census.rs` to parse all fields and bump `carrick.xlat-census.v2` to V3.

Add invariant tests that fail aggregation when a recurring-contained workload has zero merges or zero blocks added, when process-incarnation coverage is incomplete, when flushes are imbalanced, or when an unknown V5 field is silently ignored.

- [ ] **Step 7: Run translator, runtime, and census tests**

```bash
cargo test -p carrick-dsr-aarch64 loaded_unit_gap_ --lib
cargo test -p carrick-dsr-aarch64 next_process_replays_merged --lib
cargo test -p carrick-dsr-aarch64 resolver_stat --lib
cargo test -p carrick-cli debug_census --lib
RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_darwin --lib
just fmt-check
```

Expected: real-path replay equivalence, at-most-once publication, nonfatal failure, counter index/token, schema, and fork-reset tests pass.

- [ ] **Step 8: Commit Task 4**

```bash
git add crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-runtime/src/native_darwin.rs \
  crates/carrick-cli/src/debug_census.rs
git commit -m "feat(dsr): augment stored units on demand"
```

The body must distinguish true-miss initial publication from attached-unit augmentation, name the temporary control hatch, and state that store failures never alter guest execution.

---

### Task 5: Add export-only LLDB live/core diagnostics

**Files:**
- Modify: `scripts/carrick_lldb.py:1-30,375-505`
- Create: `scripts/carrick_lldb_xlat.py`
- Create: `scripts/test_carrick_lldb_xlat.py`
- Modify: `docs/diagnostics-and-debugging.md`
- Test: `scripts/test_carrick_lldb_xlat.py`

**Export contract:**

```text
(lldb) carrick xlat-pending
(lldb) carrick xlat-pending --output /absolute/path/pending
```

The second command writes `/absolute/path/pending.json` and `.bin` through mode-0600 same-directory temporaries plus atomic rename. The binary diagnostic magic/schema must differ from `CUNITB1\0`; no store reader accepts it.

- [ ] **Step 1: Write failing pure-reader tests**

In `scripts/test_carrick_lldb_xlat.py`, use a fake sparse address space and add:

Name the tests `test_complete_live_prefix_round_trips`,
`test_torn_uncommitted_record_is_excluded`,
`test_missing_later_chunk_exports_partial_prefix_and_address`,
`test_missing_root_refuses_stack_only_core_by_name`,
`test_bad_magic_schema_pointer_count_offset_and_length_fail_closed`,
`test_export_files_are_mode_0600_atomic_and_hash_bound`, and
`test_export_magic_cannot_be_parsed_as_store_bundle`.

- [ ] **Step 2: Run the pure tests and confirm red**

```bash
python3 scripts/test_carrick_lldb_xlat.py
```

Expected: import fails because the pure reader/export module does not exist.

- [ ] **Step 3: Implement the pure validated reader**

`carrick_lldb_xlat.py` receives only a `read_memory(address, length) -> bytes` callback, root address, and source identity. It validates root/chunk/record magics and schemas, fixed lengths, nonzero/canonical pointers, committed counts within chunk capacity, all checked byte lengths, guest start/end, current INITIAL generation, and exact readable payloads.

Return a structured summary with schema `carrick.xlat-pending-export.v1` and
write binary payload magic `CXLATE1\0`. The summary contains
`complete`, the optional first unreadable address, PID/incarnation, live-or-core
source identity, Mach-O UUID, binary SHA-256, a validated unit-record array,
record count, binary length, and binary-payload SHA-256.

If a later page is absent, stop at the first unreadable address and return the valid committed prefix with `complete=false`. If the root is absent/unreadable, raise a named error that says stack-only cores are insufficient and requests a full or modified-memory core. Never turn an unreadable root into an empty result.

- [ ] **Step 4: Register the LLDB commands**

Extend `_static_load_addr` use to locate `carrick_xlat_pending_core_v1`, use `SBProcess.ReadMemory` for live and core targets, and obtain:

- live identity: target PID plus root incarnation;
- core identity: resolved core path;
- both: matching Carrick Mach-O UUID and SHA-256 of the symbol-bearing executable.

Parse arguments with `shlex.split`. Accept no options for summary and exactly `--output /absolute/output/stem` for export. Refuse relative/empty stems if their parent cannot be resolved. Register `xlat-pending` in `_SUBCOMMANDS` and update the module help text.

- [ ] **Step 5: Prove a real stopped-live and modified-memory core agree**

Build the signed binary, start the targeted multi-process augmentation fixture with a won claim and at least two committed records, attach to the guest Carrick process, and capture before publication:

```bash
just build
sudo lldb -p "$guest_pid" \
  -o "command script import scripts/carrick_lldb.py" \
  -o "process save-core -s modified-memory target/perf/xlat-core-fixture/core" \
  -o "carrick xlat-pending --output target/perf/xlat-core-fixture/live" \
  -o detach -o quit
lldb -c target/perf/xlat-core-fixture/core target/release/carrick \
  -o "command script import scripts/carrick_lldb.py" \
  -o "carrick xlat-pending --output target/perf/xlat-core-fixture/core-export" \
  -o quit
```

Compare JSON record/unit counts and `.bin` hashes. Separately create/load a stack-only core and verify the named refusal. Treat generated cores and exports as ephemeral `target/perf` evidence; do not commit them.

- [ ] **Step 6: Run tests and validate no importer exists**

```bash
python3 scripts/test_carrick_lldb_xlat.py
python3 -m py_compile scripts/carrick_lldb.py scripts/carrick_lldb_xlat.py
rg -n "xlat-pending|xlat_pending" scripts crates docs/diagnostics-and-debugging.md
```

Expected: pure and real fixtures pass; the only mutation is writing diagnostic `.json`/`.bin`; no import/publish/store API consumes them.

- [ ] **Step 7: Commit Task 5**

```bash
git add scripts/carrick_lldb.py scripts/carrick_lldb_xlat.py \
  scripts/test_carrick_lldb_xlat.py docs/diagnostics-and-debugging.md
git commit -m "feat(debug): export pending translations from cores"
```

The body must state export-only semantics, stable-prefix behavior, stack-core refusal, and the live/core equivalence receipt path.

---

### Task 6: Make sparse-store mechanism and ABBA controls receipt-safe

**Files:**
- Modify: `scripts/perf/native_go_build.py:52-108,330-380,900-935,1090-1120`
- Modify: `scripts/perf/native_go_dtrace_target.py:653-790`
- Modify: `scripts/perf/test_native_go_dtrace_target.py`
- Modify: `scripts/perf/native_go_build_abba.py:154-184,883-1100,2196-2285`
- Modify: `scripts/perf/test_native_go_build_abba.py:615-1810`
- Modify: every file returned by `rg --files scripts/perf/overlays`
- Create: `scripts/perf/overlays/native-store-augment-control.json`
- Create: `scripts/perf/overlays/native-store-augment-candidate.json`
- Modify: `scripts/perf/README.md`

**Harness contract:**

```text
native_go_dtrace_target.py:
  --store-dir target/perf/native-store-augmentation/mechanism/active-store
  --store-augmentation {on,off}

native_go_build_abba.py run:
  --store-seed-dir target/perf/native-store-augmentation/mechanism/seed
  --active-store-dir target/perf/native-store-augmentation/abba/active-store
```

Before every warmup and measured sample, ABBA restores the seed into the same active store pathname. Both arm overlays set the identical `CARRICK_DSR_STORE_DIR`; only `CARRICK_DSR_STORE_AUGMENTATION` differs. No arm inherits another sample's merged store.

- [ ] **Step 1: Write failing DTrace-target control tests**

Add tests proving:

- `--store-dir` must exist, be a directory, contain only production-validated `.unit-v1` seed files before launch, and resolve to the exact environment value;
- augmentation `on` unsets the hatch, `off` sets exact `0`;
- store and augmentation values appear in the capture identity/receipt; and
- unknown/mismatched environment input fails before Carrick launches.

Run:

```bash
python3 scripts/perf/test_native_go_dtrace_target.py
```

Expected red: parser rejects the new options.

- [ ] **Step 2: Write failing ABBA seed-restoration tests**

Add tests named:

Name the tests `test_run_requires_immutable_validated_sparse_seed`,
`test_every_warmup_and_sample_restores_exact_seed`,
`test_both_arms_use_same_active_store_path`,
`test_seed_hash_and_per_sample_restore_hash_are_receipt_bound`,
`test_mutated_or_symlinked_seed_fails_before_next_sample`,
`test_decision_requires_primary_median_ratio_at_most_point_90`, and
`test_battery_source_is_metadata_not_an_exclusion`.

The restoration test mutates the candidate active store after each fake sample and asserts the next control sees the original sparse hash. It must cover both excluded warmups and all A1/B1/B2/A2 positions.

Run:

```bash
python3 scripts/perf/test_native_go_build_abba.py
```

Expected red: run arguments and seed receipts do not exist; the current decision accepts any median below 1.0.

- [ ] **Step 3: Add the temporary performance control key and overlays**

Add `CARRICK_DSR_STORE_AUGMENTATION` to `PERFORMANCE_CONTROL_KEYS`, semantic overlays, and every JSON overlay with `null` unless explicitly selected. Create each new overlay by copying the complete exact key set from `native-default.json`: set persistent store to `"1"` in both, augmentation to `"0"` only in control and `null` in candidate, and leave store directory `null` because the receipt-bound runner injects the identical active path into both. Partial overlay objects are forbidden.

- [ ] **Step 4: Implement validated seed hashing/restoration**

Define a deterministic tree receipt over relative path, file type, mode, size, and SHA-256. A seed contains only validated `.unit-v1` files; `.builder`, `.lock`, temporary, and old-format files are refused rather than copied. Refuse symlinks, nonregular files, any link count other than one, group/other-writable entries, unexpected suffixes, path traversal, or a changing double hash. The seed is read-only input and is never used directly as `CARRICK_DSR_STORE_DIR`.

Restore by creating a fresh sibling staging directory, copying validated files with modes, and syncing every file plus the staged directory. With no Carrick sample running, rename any prior active directory to a campaign-owned quarantine name, rename the staged directory to the stable active-store pathname, sync the parent, validate/hash the new active tree, and then remove the exact quarantined directory. If the second rename fails, restore the quarantined directory before returning an evidence error. Do this before every warmup and sample. Record the seed tree hash and post-restore active tree hash in the campaign identity and each sample annotation.

Do not delete an unresolved broad path. Resolve and validate both paths under an explicit campaign-owned parent before replacing the known active directory.

- [ ] **Step 5: Tighten the ABBA decision gate**

Change the primary criterion to:

```python
"total_cpu_median_at_most_point_90": primary["median_quad_ratio"] <= 0.90,
"total_cpu_two_sided_interval_below_one": (
    primary["bootstrap"]["two_sided_upper"] < 1.0
),
"workload_wall_median_below_one": wall["median_quad_ratio"] < 1.0,
```

Retain the exact sign-probability and supported-secondary no-regression checks. Record power source on every preflight, but remove any battery rejection from campaign acceptance; `--allow-battery` becomes unnecessary and is deleted rather than kept as a second policy path.

- [ ] **Step 6: Run all harness tests and overlay validation**

```bash
python3 scripts/perf/test_native_go_build.py
python3 scripts/perf/test_native_go_dtrace_target.py
python3 scripts/perf/test_native_go_build_abba.py
python3 - <<'PY'
import json
import pathlib
import sys
sys.path.insert(0, "scripts/perf")
import native_go_build
for path in sorted(pathlib.Path("scripts/perf/overlays").glob("*.json")):
    value = json.loads(path.read_text())
    assert set(value) == set(native_go_build.PERFORMANCE_CONTROL_KEYS), path
print("all overlays match the exact performance-control key set")
PY
```

Expected: all harness tests pass and every overlay has the exact control-key set.

- [ ] **Step 7: Commit Task 6**

```bash
git add scripts/perf/native_go_build.py \
  scripts/perf/native_go_dtrace_target.py \
  scripts/perf/test_native_go_dtrace_target.py \
  scripts/perf/native_go_build_abba.py \
  scripts/perf/test_native_go_build_abba.py \
  scripts/perf/overlays scripts/perf/README.md
git commit -m "test(perf): restore translation seeds for every ABBA arm"
```

The body must explain that seed reset prevents candidate accumulation from contaminating later arms and that battery state is retained only as metadata.

---

### Task 7: Close focused correctness and atomicity gates on a current signed binary

**Files:**
- Modify only if a discovered defect requires a narrow fix in the files already listed above.
- Evidence (untracked until Task 9): `target/perf/native-store-augmentation/correctness/`

- [ ] **Step 1: Run focused Rust/Python suites from a clean source state**

```bash
cargo test -p carrick-dsr-aarch64 shared_cache::tests --lib
cargo test -p carrick-dsr-aarch64 pending_augmentation::tests --lib
cargo test -p carrick-dsr-aarch64 loaded_unit_gap_ --lib
cargo test -p carrick-native-darwin aot_cache::tests --lib
cargo test -p carrick-cli debug_census --lib
RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_darwin --lib
python3 scripts/test_carrick_lldb_xlat.py
python3 scripts/perf/test_native_go_build.py
python3 scripts/perf/test_native_go_dtrace_target.py
python3 scripts/perf/test_native_go_build_abba.py
```

Expected: all pass. Fix any failure red-first and amend only the task commit that owns it if it has not been shared; otherwise add a narrow corrective commit.

- [ ] **Step 2: Build and bind the exact runnable artifact**

```bash
just build
codesign -dv --verbose=4 target/release/carrick 2>&1 | tee target/perf/native-store-augmentation/correctness/codesign.txt
otool -l target/release/carrick | rg '__dof_carrick' | tee target/perf/native-store-augmentation/correctness/dof.txt
shasum -a 256 target/release/carrick | tee target/perf/native-store-augmentation/correctness/binary.sha256
git rev-parse HEAD | tee target/perf/native-store-augmentation/correctness/git-head.txt
git status --porcelain=v1 | tee target/perf/native-store-augmentation/correctness/git-status.txt
```

Expected: signed binary, present DOF section, hash receipt, and no unexplained source dirt.

- [ ] **Step 3: Run the targeted multi-process replay probe**

Create a fresh explicit store. Run the existing Go-build workload or a focused in-repo multiprocess executable twice with census/profile enabled. First run must create a sparse unit; second must merge an absent block; third must replay it without private emission. Confirm exact guest output, block bytes, relocations, PC maps, and recovery actions against augmentation-off and the private path.

Use unique `CARRICK_RUN_ID` values and reap only with:

```bash
sudo scripts/sudo/kill.sh native-store-augment-replay-v1
```

- [ ] **Step 4: Run repository correctness gates**

```bash
RUST_TEST_THREADS=1 just ci
just conformance-native smoke --workers 4 --flake-retries 1
```

Expected: `just ci` passes. Native smoke has no candidate-only DIFF/CRASH/TIMEOUT; compare any flip with the same binary under `CARRICK_DSR_STORE_AUGMENTATION=0` and with pre-change/current HEAD before attribution.

- [ ] **Step 5: Commit any gate-only correction**

If no correction was needed, do not create an empty commit. If needed:

Stage only the corrected owning file from Tasks 1-6, then commit it with:

```bash
git commit -m "fix(dsr): close translation augmentation gate"
```

The body must name the reproduced defect and the exact focused/CI/conformance receipts.

---

### Task 8: Prove the causal mechanism on one restored sparse seed

**Files:**
- Evidence: `target/perf/native-store-augmentation/mechanism/`
- Modify after measurement: `docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md`

- [ ] **Step 1: Create and validate one sparse ABI-9 seed**

Use the exact signed candidate binary with augmentation disabled only for attached-unit gaps. Start from an empty explicit store and run the canonical cold Go-build workload once so true file misses publish initial units. Stop; validate every `.unit-v1` through the production reader, record the deterministic tree hash, file/block census, binary hash, source SHA, workload identity, and command receipt. Copy it to a read-only seed directory; never run Carrick directly against that seed.

- [ ] **Step 2: Run counterbalanced exact-control/candidate mechanism captures**

For every arm, restore the seed into the same active store path. Use `native_go_dtrace_target.py` with an empty per-arm xlat-census directory and the same signed binary:

```bash
python3 scripts/perf/native_go_dtrace_target.py \
  --variant default \
  --store-dir target/perf/native-store-augmentation/mechanism/active-store \
  --store-augmentation off \
  --mechanism-profile \
  --xlat-census-dir target/perf/native-store-augmentation/mechanism/control-census \
  --run-id native-store-augment-control-v1

python3 scripts/perf/native_go_dtrace_target.py \
  --variant default \
  --store-dir target/perf/native-store-augmentation/mechanism/active-store \
  --store-augmentation on \
  --mechanism-profile \
  --xlat-census-dir target/perf/native-store-augmentation/mechanism/candidate-census \
  --run-id native-store-augment-candidate-v1
```

Restore the seed between commands. If the target wrapper needs the canonical Go-build manifest arguments, use the exact invocation recorded in `scripts/perf/README.md`; do not substitute a smaller workload for the gate.

- [ ] **Step 3: Aggregate exact censuses**

```bash
control_incarnations="$(jq -r '.processes.incarnations' \
  target/perf/native-store-augmentation/mechanism/control-profile.json)"
candidate_incarnations="$(jq -r '.processes.incarnations' \
  target/perf/native-store-augmentation/mechanism/candidate-profile.json)"
target/release/carrick debug xlat-census \
  target/perf/native-store-augmentation/mechanism/control-census \
  --processes-observed "$control_incarnations" \
  > target/perf/native-store-augmentation/mechanism/control-summary.json
target/release/carrick debug xlat-census \
  target/perf/native-store-augmentation/mechanism/candidate-census \
  --processes-observed "$candidate_incarnations" \
  > target/perf/native-store-augmentation/mechanism/candidate-summary.json
```

Before aggregation, validate that each profile JSON exists, is complete, names the
same run ID as its census, and reports a positive integer incarnation count.

- [ ] **Step 4: Apply the stop/go mechanism gate**

Continue only if all are true:

- 100% process-incarnation coverage and balanced census flushes in both arms;
- candidate `segment-repeat <= 0.50 * control segment-repeat`;
- candidate total private translations `<= 0.50 * control`;
- successful merges, `shared_unit_blocks_added > 0`, and monotonically nondecreasing per-key block counts;
- no candidate-only load miss/refusal;
- zero conflicts, repairs, capacity refusals, malformed bundles, and validation failures on the clean workload; and
- the targeted next process replays the newly merged block with exact semantics.

If any condition fails, stop before ABBA, revert runtime candidate behavior and temporary hatch/harness controls, keep portable tests only if independently valuable, and write negative evidence. A traced run is causal evidence only, never official timing.

- [ ] **Step 5: Draft the measured evidence record**

Create `docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md` with source/binary/signature/DOF identities, seed tree hash, exact commands, census hashes, counter table, control/candidate ratios, validation status, and explicit separation between measured reductions and the earlier 18% projection.

- [ ] **Step 6: Commit mechanism evidence**

```bash
git add docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md
git commit -m "docs(perf): prove monotonic translation coverage"
```

Commit only durable summaries and hashes, not raw cores or bulky `target/perf` captures.

---

### Task 9: Run ABBA, regression screens, remove the hatch, and refresh the official ratio

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `scripts/perf/native_go_build.py`
- Modify: `scripts/perf/native_go_dtrace_target.py`
- Modify: `scripts/perf/native_go_build_abba.py`
- Modify: corresponding Python tests and every performance overlay
- Delete: `scripts/perf/overlays/native-store-augment-control.json`
- Delete: `scripts/perf/overlays/native-store-augment-candidate.json`
- Modify: `scripts/perf/README.md`
- Modify: `docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md`
- Modify: `handoff.md`

- [ ] **Step 1: Run receipt-bound n>=8 ABBA from the same seed**

Prepare immutable control/candidate receipts from the same source and exact signed binary. Require equal source commit, binary SHA-256, Mach-O UUID, signature identity, workload image, and semantic environment except for exact augmentation selection. Use the same seed/active-store paths from Task 8:

```bash
python3 scripts/perf/native_go_build_abba.py run \
  --harness-repo "$PWD" \
  --control-receipt target/perf/native-store-augmentation/arms/control/arm.json \
  --candidate-receipt target/perf/native-store-augmentation/arms/candidate/arm.json \
  --control-overlay scripts/perf/overlays/native-store-augment-control.json \
  --candidate-overlay scripts/perf/overlays/native-store-augment-candidate.json \
  --store-seed-dir target/perf/native-store-augmentation/mechanism/seed \
  --active-store-dir target/perf/native-store-augmentation/abba/active-store \
  --quads 8 \
  --output target/perf/native-store-augmentation/abba/campaign.json
```

The harness must record power/thermal/core/load state and restore/hash the seed before both warmups and every A1/B1/B2/A2 sample.

- [ ] **Step 2: Apply the performance retention decision**

Retain only if:

- median candidate/control child CPU `<=0.90`;
- paired two-sided 95% bootstrap interval lies entirely below `1.0`;
- median workload wall improves; and
- the completed artifact remains receipt-valid and reports the mechanism/correctness gates externally satisfied.

If this fails, revert the runtime candidate and record the negative result. Do not average it with the store-default 8.33% win or revise the official 10.44x ratio.

- [ ] **Step 3: Run same-binary regression screens**

Run control/candidate comparisons for the canonical `compute`, `fs-walk`, `startup`, and 20-exec workloads with identical store state and environment. No metric may regress by more than 3%. Rerun any apparent failure against current HEAD before attributing it.

Then run the canonical workload spread in serialized phases:

```bash
scripts/perf/workload-spread.sh
```

Record exact invocation/output paths and confirm no Carrick/Docker overlap.

- [ ] **Step 4: Remove the evidence-only hatch after a retain decision**

Delete `CARRICK_DSR_STORE_AUGMENTATION` parsing and its control branch from the translator. Remove the key from `PERFORMANCE_CONTROL_KEYS`, all overlays, DTrace-target arguments, ABBA-specific overlay handling, documentation, and the two temporary overlay files. Update tests so default monotonic augmentation is the sole shipped path.

Run:

```bash
rg -n 'CARRICK_DSR_STORE_AUGMENTATION|store-augment-(control|candidate)|store-augmentation' \
  crates scripts docs --glob '!docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md' \
  --glob '!docs/superpowers/specs/2026-08-03-native-store-monotonic-augmentation-design.md' \
  --glob '!docs/superpowers/plans/2026-08-03-native-store-monotonic-augmentation.md'
```

Expected: no production/harness/config occurrence remains. Historical design, plan, and measured evidence may name the removed control.

- [ ] **Step 5: Commit the retained single path**

```bash
git add crates/carrick-dsr-aarch64/src/translator.rs \
  scripts/perf/native_go_build.py scripts/perf/native_go_dtrace_target.py \
  scripts/perf/native_go_build_abba.py scripts/perf/test_native_go_build.py \
  scripts/perf/test_native_go_dtrace_target.py \
  scripts/perf/test_native_go_build_abba.py scripts/perf/overlays \
  scripts/perf/README.md
git commit -m "refactor(dsr): make translation augmentation unconditional"
```

Do not make this commit if the candidate is rejected; instead remove candidate behavior and controls in a narrow revert/negative-evidence commit.

- [ ] **Step 6: Run final correctness and repository gates**

```bash
cargo test -p carrick-dsr-aarch64 --lib
cargo test -p carrick-native-darwin --lib
RUST_TEST_THREADS=1 just ci
just conformance-native smoke --workers 4 --flake-retries 1
```

Expected: all pass with the sole shipped path. Attribute any conformance flip against the last pre-change binary before changing code.

- [ ] **Step 7: Build and prove the final signed artifact**

```bash
just build
git status --porcelain=v1
git rev-parse HEAD
shasum -a 256 target/release/carrick
codesign -dv --verbose=4 target/release/carrick 2>&1
otool -l target/release/carrick | rg '__dof_carrick'
strings target/release/carrick | rg 'CUNITB1|carrick_xlat_pending_core_v1'
```

Expected: clean intended source state, current commit and binary hash, valid signature, DOF section present, and new bundle/core markers in the binary.

- [ ] **Step 8: Run the official serialized shipped-default ratio refresh**

Use the established canonical cold-build command from `scripts/perf/README.md`/`handoff.md`, not a new ad hoc runner. Run at least five Carrick repetitions first. Verify no live Carrick run remains, then run at least five native-arm64 Docker oracle repetitions. Never overlap phases.

Bind source commit, final binary SHA-256/signature/DOF, workload manifest, image identity, sparse-seed hash, raw artifact hashes, schedule, process cleanup, and statistics. Report workload and process elapsed ratios separately. The official ratio changes only from this clean final run.

- [ ] **Step 9: Finalize durable evidence and handoff**

Update `docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md` with:

- mechanism control/candidate counts and ratios;
- n>=8 ABBA child CPU, wall, bootstrap, sign, host-state, and seed receipts;
- all four <=3% regression screens;
- focused, CI, native-smoke, live/core-export, signature, and DOF receipts;
- final Carrick/Docker samples and official ratio;
- retention or rejection decision;
- measured result separated from theoretical ceiling; and
- the next largest attributed performance bucket, since this plan alone does not claim the <=3x goal.

Update `handoff.md` with current branch/commit, clean/dirty status, exact achieved ratio, remaining gap to <=3x and 2x, confidence levels, and the deferred eager-recursive-descent improvement.

- [ ] **Step 10: Commit the final evidence state**

```bash
git add docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md handoff.md
git commit -m "docs(perf): record translation augmentation result"
git status --short --branch
```

The workstream is complete only when the implementation decision and all receipts are durable. The parent performance goal remains active unless the official shipped-default cold-build ratio is `<=3x`; otherwise continue with the next DTrace/LLDB-attributed bucket under a new approved design/plan.

---

## Plan Completion Audit

- [ ] Every requirement in `docs/superpowers/specs/2026-08-03-native-store-monotonic-augmentation-design.md` maps to at least one implementation step and one verification step above.
- [ ] The only persistent store wire is ABI-9 `{stem}.unit-v1`; no V5 compatibility reader, migration, or paired publication remains.
- [ ] `StoredBlockArtifact` is the sole normalized input to union, bundle packing, pending publication, and core export.
- [ ] Claim/merge types are consistent across portable trait, Darwin implementation, translator, counters, and tests.
- [ ] Store errors are performance-only at every lifecycle seam.
- [ ] Fork child state cannot publish parent candidates or reuse the parent's incarnation nonce.
- [ ] Core export is read-only and cannot be parsed or published as a store bundle.
- [ ] The mechanism comparison and every ABBA sample restore the exact same sparse seed.
- [ ] The temporary augmentation hatch is absent from the retained production/harness/config state.
- [ ] No placeholder commands, filenames, test names, interfaces, or unresolved design decisions remain before execution; runtime-derived identities and counts come from receipt-bound files named by the plan.
- [ ] Eager recursive descent remains documented only as a deferred future improvement.
