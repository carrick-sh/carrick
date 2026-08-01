# Native Mapped Translation Metadata V3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace per-descendant bincode manifest decoding and immutable-index reconstruction in the Darwin/AArch64 shared-translation path with validated read-only V3 metadata mappings.

**Architecture:** The publisher converts the existing owned `TranslationUnitManifest` into a fixed little-endian V3 sidecar and validates it before atomic publication. Loaders mmap that sidecar, retain a typed validated lease, and reference mapped block, PC, recovery, range, binding, relocation, and edge tables while continuing to allocate only process-local generation and authority state. V3 is default-on; exact `CARRICK_DSR_SHARED_MAPPED_METADATA=0` preserves the current V2 path.

**Tech Stack:** Rust 2024, `zerocopy` 0.8 wire records, `memmap2` 0.9 read-only mappings, existing Mach-O/dyld cache authority, Python performance harnesses, DTrace, and LLDB escalation.

## Global Constraints

- Scope is Darwin/AArch64 native DSR only; do not change VMM/HVF, KVM, bhyve, NVMM, x86 DSR, or a second native driver wiring point.
- V3 is default-on. Exact value `0` for `CARRICK_DSR_SHARED_MAPPED_METADATA` selects the unchanged V2 writer, loader, and runtime path.
- Preserve every existing mechanism control. V3 recovery-entry mode uses one-entry spans; V2-only manifest clone/varint overlays must also select V2 explicitly.
- The cache remains a container-lifetime optimization. Every malformed or unavailable V3 artifact is a typed miss and private-JIT fallback before logical mutation.
- Runtime metadata conversion is lossless. Never truncate, saturate, or approximate guest addresses, offsets, action payloads, or ownership indexes.
- The loader keeps one complete allocation-free validation pass. Do not reintroduce post-load validation scans, bincode decode, immutable-table clones, sorting, or tree construction.
- Use typed semantic values at boundaries. Raw integers exist only in wire records and convert through named checked constructors.
- Build runnable artifacts with `just build`; do not test a stale unsigned CLI binary.
- Never run Carrick and the Docker oracle concurrently. The primary performance gate is Carrick-only and uses the exact arm64 Go-build manifest already named in `handoff.md`.
- Keep each implementation commit independently compiling and tested. Use Conventional Commit subjects, explanatory bodies, verification receipts, and `Co-Authored-By: Codex <codex@openai.com>`.

## File Structure

- Create `crates/carrick-dsr-aarch64/src/mapped_metadata/mod.rs`: public V3 API, backing lifetime, error type, and representation-neutral views.
- Create `crates/carrick-dsr-aarch64/src/mapped_metadata/wire.rs`: fixed POD header, section directory, record layouts, and structural parser.
- Create `crates/carrick-dsr-aarch64/src/mapped_metadata/builder.rs`: one-time owned-manifest flattening, action deduplication, range derivation, and edge grouping.
- Create `crates/carrick-dsr-aarch64/src/mapped_metadata/view.rs`: complete allocation-free validation and indexed mapped access.
- Modify `crates/carrick-dsr-aarch64/src/artifact_spike.rs`: crate-visible portable recovery/action access and exact V3 action conversion.
- Modify `crates/carrick-dsr-aarch64/src/shared_cache.rs`: V3 schema identity, loaded-metadata enum, view records, load evidence, and V2 compatibility.
- Modify `crates/carrick-dsr-aarch64/src/translator.rs`: mapped shared-block installation, fault lookup, range reuse, sorted-index merge, and counters.
- Modify `crates/carrick-dsr-aarch64/src/direct_binding.rs`: mapped record ownership and pre-grouped edge consumption.
- Modify `crates/carrick-native-darwin/src/aot_cache.rs`: V3 publication, read-only mmap loading, pair lifetime, and exact feature selection.
- Modify `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`: live mapped-unit equivalence and failure-atomicity coverage.
- Modify `Cargo.toml`, `crates/carrick-dsr-aarch64/Cargo.toml`, and `crates/carrick-native-darwin/Cargo.toml`: direct `zerocopy` and `memmap2` dependency ownership.
- Modify `scripts/perf/native_go_build.py`, `scripts/perf/native_go_build_abba.py`, `scripts/perf/native_go_dtrace_target.py`, their three test modules, and every native overlay: receipt-bound V2/V3 controls.
- Create `scripts/perf/overlays/native-shared-metadata-v2.json`: exact same-binary V2 control.
- Modify `handoff.md`: measured implementation and retention result only after live gates.

---

### Task 1: Define the V3 wire ABI and structural parser

**Files:**
- Modify: `Cargo.toml:123`
- Modify: `crates/carrick-dsr-aarch64/Cargo.toml:20-39`
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs:20-36`
- Create: `crates/carrick-dsr-aarch64/src/mapped_metadata/mod.rs`
- Create: `crates/carrick-dsr-aarch64/src/mapped_metadata/wire.rs`
- Test: `crates/carrick-dsr-aarch64/src/mapped_metadata/wire.rs`

**Interfaces:**
- Produces: `MAPPED_METADATA_SCHEMA_V3`, `MappedMetadataError`, `SectionKind`, `ValidatedLayout`, and all `Wire*V3` record types.
- Consumes: only byte slices and `zerocopy`; it must not depend on Darwin mapping APIs or translator state.

- [ ] **Step 1: Write the failing layout tests**

Add table-driven tests that start from one minimal valid header and separately corrupt total length, section offset overflow, overlap, stride, alignment, reserved bytes, schema, endian marker, and duplicate section kind. The assertions must name the exact typed error, for example:

```rust
#[test]
fn v3_layout_rejects_overlapping_sections() {
    let mut bytes = minimal_layout_fixture();
    set_section_for_test(
        &mut bytes,
        SectionKind::PcMap,
        SectionDescriptorValues {
            offset: HEADER_SIZE_V3 as u64,
            byte_len: 16,
            count: 1,
            stride: PC_MAP_RECORD_V3_SIZE as u32,
        },
    );
    set_section_for_test(
        &mut bytes,
        SectionKind::RecoverySpan,
        SectionDescriptorValues {
            offset: HEADER_SIZE_V3 as u64 + 8,
            byte_len: 16,
            count: 1,
            stride: RECOVERY_SPAN_RECORD_V3_SIZE as u32,
        },
    );

    assert_eq!(
        ValidatedLayout::parse(&bytes),
        Err(MappedMetadataError::SectionOverlap {
            left: SectionKind::PcMap,
            right: SectionKind::RecoverySpan,
        })
    );
}
```

- [ ] **Step 2: Run the focused test and confirm red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 mapped_metadata::wire::tests --lib
```

Expected: compilation fails because `mapped_metadata`, the V3 records, and `ValidatedLayout` do not exist.

- [ ] **Step 3: Add dependencies and the module boundary**

Add `memmap2 = "0.9.10"` to workspace dependencies for the Darwin task, add `zerocopy.workspace = true` to `carrick-dsr-aarch64`, and export the new module from `lib.rs`:

```rust
pub mod mapped_metadata;
```

The DSR crate must not depend on `memmap2`; that direct dependency belongs to `carrick-native-darwin` in Task 5.

- [ ] **Step 4: Implement fixed wire records and checked layout parsing**

Use unaligned byte-order fields so mapped offsets never rely on the host's struct alignment:

```rust
use zerocopy::byteorder::{LittleEndian, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const MAPPED_METADATA_SCHEMA_V3: u32 = 3;
pub const MAPPED_METADATA_MAGIC_V3: [u8; 8] = *b"CRKMDV3\0";

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireSectionV3 {
    pub kind: U32<LittleEndian>,
    pub stride: U32<LittleEndian>,
    pub offset: U64<LittleEndian>,
    pub byte_len: U64<LittleEndian>,
    pub count: U64<LittleEndian>,
    pub reserved: U64<LittleEndian>,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WirePcMapV3 {
    pub guest: U64<LittleEndian>,
    pub cache_offset: U32<LittleEndian>,
    pub reserved: U32<LittleEndian>,
}
```

Define fixed records for the header, key variants, blocks, recovery spans,
recovery actions, guest ranges, bindings, relocations, edge groups, and edge
members. `ValidatedLayout::parse` must use `checked_mul`, `checked_add`, exact
stride matching, sorted interval overlap checks, and `zerocopy` slice parsing.
Every record has a `const` size assertion.

- [ ] **Step 5: Run wire tests and formatting**

Run:

```bash
cargo test -p carrick-dsr-aarch64 mapped_metadata::wire::tests --lib
just fmt-check
```

Expected: every corruption case passes and formatting is clean.

- [ ] **Step 6: Commit Task 1**

```bash
git add Cargo.toml Cargo.lock crates/carrick-dsr-aarch64/Cargo.toml crates/carrick-dsr-aarch64/src/lib.rs crates/carrick-dsr-aarch64/src/mapped_metadata
git commit -m "feat(dsr): define mapped metadata v3 wire ABI"
```

The commit body must explain that this is a parser-only slice with no production selection yet and list the focused wire test command.

---

### Task 2: Encode, validate, and view complete immutable metadata

**Files:**
- Create: `crates/carrick-dsr-aarch64/src/mapped_metadata/builder.rs`
- Create: `crates/carrick-dsr-aarch64/src/mapped_metadata/view.rs`
- Modify: `crates/carrick-dsr-aarch64/src/mapped_metadata/mod.rs`
- Modify: `crates/carrick-dsr-aarch64/src/artifact_spike.rs:1109-1845`
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs:315-1020`
- Test: `crates/carrick-dsr-aarch64/src/mapped_metadata/builder.rs`
- Test: `crates/carrick-dsr-aarch64/src/mapped_metadata/view.rs`

**Interfaces:**
- Produces: `MetadataBacking`, `VecMetadataBacking`, `encode_translation_metadata_v3`, `ValidatedMappedTranslationMetadata`, `MappedBlockView`, `MappedPcMapView`, `MappedRecoveryView`, `MappedBindingView`, and `MappedEdgeGroupView`.
- Consumes: `TranslationUnitManifest`, `TranslationUnitKey`, `PortableRecoveryMetadata`, and the wire ABI from Task 1.

- [ ] **Step 1: Write a failing V2/V3 equivalence test**

Construct a manifest containing two blocks, non-contiguous PC mappings, both a coalesced recovery span and a one-entry span, two direct bindings sharing one `(source, target)` edge, relocations, and two guest ranges. Compare every scalar and indexed lookup:

```rust
#[test]
fn v3_view_is_lossless_against_the_owned_manifest() {
    let manifest = mapped_manifest_fixture();
    let encoded = encode_translation_metadata_v3(&manifest).expect("encode V3 fixture");
    let backing = std::sync::Arc::new(VecMetadataBacking::new(encoded));
    let mapped = ValidatedMappedTranslationMetadata::new(backing, &manifest.key)
        .expect("validate V3 fixture");

    assert_eq!(mapped.key(), &manifest.key);
    assert_eq!(mapped.code_len(), manifest.code_len);
    assert_eq!(mapped.block_count(), manifest.blocks.len());
    assert_eq!(snapshot_mapped(&mapped), snapshot_owned(&manifest));
}
```

Add separate red tests for an unknown recovery tag, PC-order reversal,
zero-length recovery span, bad action index, guest-range mismatch, binding
ordinal mismatch, relocation mismatch, and broken binding/member back-reference.

- [ ] **Step 2: Run the equivalence tests and confirm red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 mapped_metadata:: --lib
```

Expected: compilation fails because the encoder and validated views are missing.

- [ ] **Step 3: Expose exact portable recovery inputs inside the crate**

Keep recovery internals non-public outside `carrick-dsr-aarch64`, but make the
action and span records crate-visible and add explicit conversion methods:

```rust
impl PortableRecoveryAction {
    pub(crate) fn encode_v3(self) -> Result<WireRecoveryActionV3, DsrError> {
        WireRecoveryActionV3::from_portable(self)
    }

    pub(crate) fn decode_v3(
        wire: WireRecoveryActionV3,
        host_bias: Option<u64>,
    ) -> Result<RecoveryAction, DsrError> {
        wire.into_recovery_action(host_bias)
    }
}
```

The matches in both directions must enumerate every existing
`PortableRecoveryAction` variant. Unknown tags and nonzero unused payload words
return `MappedMetadataError::RecoveryAction`; no wildcard arm may accept them.

- [ ] **Step 4: Implement the one-time V3 builder**

`encode_translation_metadata_v3(&TranslationUnitManifest)` must:

```rust
pub fn encode_translation_metadata_v3(
    manifest: &TranslationUnitManifest,
) -> Result<Vec<u8>, MappedMetadataError>;
```

Perform these operations in order: validate the owned manifest, derive exact
guest ranges, flatten block-local tables, deduplicate recovery actions by exact
portable value, preserve entry mode with span count one, group bindings by
`(source, target)`, write binding/member forward and back indexes, compute all
checked offsets, fill zeroed reserved fields, and serialize header plus sections.
The builder may allocate and sort because it runs once in the publisher.

- [ ] **Step 5: Implement complete allocation-free validation and views**

Define a backing that keeps bytes alive without self-referential slices:

```rust
pub trait MetadataBacking: Send + Sync + std::fmt::Debug {
    fn bytes(&self) -> &[u8];
}

pub struct ValidatedMappedTranslationMetadata {
    backing: std::sync::Arc<dyn MetadataBacking>,
    layout: ValidatedLayout,
    key: TranslationUnitKey,
}
```

`new` performs the one complete pass from the design: structure, block extents,
PC ordering, recovery spans/actions, streaming guest-range equivalence, binding
and relocation geometry, and exact edge forward/back coverage. Accessors return
small copy views with start/count indexes into the retained backing. PC and
recovery lookup use binary search over mapped records and decode only the
selected recovery action.

- [ ] **Step 6: Run equivalence, corruption, and existing shared-cache tests**

Run:

```bash
cargo test -p carrick-dsr-aarch64 mapped_metadata:: --lib
cargo test -p carrick-dsr-aarch64 shared_cache::tests --lib
```

Expected: V2/V3 snapshots are identical and every malformed fixture returns its
specific typed error.

- [ ] **Step 7: Commit Task 2**

```bash
git add crates/carrick-dsr-aarch64/src/artifact_spike.rs crates/carrick-dsr-aarch64/src/shared_cache.rs crates/carrick-dsr-aarch64/src/mapped_metadata
git commit -m "feat(dsr): encode and validate mapped metadata v3"
```

The body must name lossless V2/V3 equivalence, the allocation-free validation
contract, and the corruption matrix.

---

### Task 3: Consume mapped block, PC, recovery, and guest-range views

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs:766-830`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:976-1120`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:1394-1425`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:2860-3375`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:4270-4345`
- Test: `crates/carrick-dsr-aarch64/src/translator.rs`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`

**Interfaces:**
- Consumes: `ValidatedMappedTranslationMetadata` and its indexed views from Task 2.
- Produces: `LoadedTranslationMetadata`, `TranslationMetadataLoadEvidence`, and `PublishedBlockMetadata` with exact owned and mapped variants.

- [ ] **Step 1: Write failing mapped-install and fault-lookup tests**

Add a synthetic mapped unit with direct bindings disabled. Install it through
the real `prepare_shared_install`/commit path, then assert the shared block owns
no PC or recovery vectors and still resolves every cache offset exactly:

```rust
assert_eq!(state.loaded_shared_units.len(), 1);
assert!(matches!(
    state.published[0].metadata,
    PublishedBlockMetadata::Mapped {
        loaded_unit_index: 0,
        block_index: 0,
    }
));
assert_eq!(state.published[0].owned_record_count(), 0);
assert_eq!(
    state.guest_pc_for_cache(mapped_cache_pc).expect("mapped lookup"),
    (expected_guest_pc, Some(expected_recovery))
);
```

Add a failpoint test proving a bad mapped guest range leaves catalog, blocks,
indexes, dependencies, and loaded-unit leases unchanged.

- [ ] **Step 2: Run the focused tests and confirm red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 mapped_shared_unit --lib
```

Expected: compilation fails because loaded and published metadata are still
owned-only.

- [ ] **Step 3: Add representation-neutral loaded metadata without changing V2**

Define the exact variants:

```rust
#[derive(Clone, Debug)]
pub enum LoadedTranslationMetadata {
    V2(std::sync::Arc<TranslationUnitManifest>),
    V3(std::sync::Arc<ValidatedMappedTranslationMetadata>),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TranslationMetadataMode {
    #[default]
    V2,
    V3,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TranslationMetadataLoadEvidence {
    pub mode: TranslationMetadataMode,
    pub bytes_read: u64,
    pub bytes_mapped: u64,
    pub validation_ns: u64,
    pub mapped_records: u64,
    pub owned_records: u64,
}
```

`SharedLoadedTranslationUnit` retains `LoadedTranslationMetadata`, base,
binding base, load evidence, and its existing external lease. Keep the V2
constructor and clone path byte-for-byte equivalent except for the enum wrapper.

- [ ] **Step 4: Split published metadata ownership by representation**

Replace the three shared/private fields with:

```rust
enum PublishedBlockMetadata {
    Owned {
        map: Vec<emit::PcMapEntry>,
        recovery: Vec<emit::RecoveryEntry>,
        shared_recovery: Option<SharedRecoveryMetadata>,
    },
    Mapped {
        loaded_unit_index: usize,
        block_index: u32,
    },
}
```

Keep the current V2 `Arc::make_mut` and owned-vector path inside the `V2` arm.
For `V3`, use mapped block scalars and precomputed guest ranges; create only
generation observations, bindings, dependencies, sensitive state, and the
small `PublishedBlock` records. `guest_pc_for_cache` resolves mapped lookups
through `loaded_shared_units[loaded_unit_index]` and fails closed on an invalid
index.

- [ ] **Step 5: Merge, do not resort, shared published indexes**

Add a pure helper which validates both inputs are strictly ordered and merges
them in linear time:

```rust
fn merge_published_indexes(
    current: &[PublishedIndexEntry],
    incoming: &[PublishedIndexEntry],
) -> Result<Vec<PublishedIndexEntry>, types::DsrError>;
```

Build `incoming` directly from V3 block entry order. Preserve the current V2
sort path as the exact control. Reject equal starts before commit.

- [ ] **Step 6: Run translator and live-oracle tests**

Run:

```bash
cargo test -p carrick-dsr-aarch64 mapped_shared_unit --lib
cargo test -p carrick-dsr-aarch64 translator::tests::shared_unit --lib
RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_darwin::dsr --lib
```

Expected: mapped lookup/recovery is exact, V2 tests stay unchanged, and all
shared-install failpoints remain atomic.

- [ ] **Step 7: Commit Task 3**

```bash
git add crates/carrick-dsr-aarch64/src/shared_cache.rs crates/carrick-dsr-aarch64/src/translator.rs crates/carrick-runtime/src/native_darwin/dsr/oracle.rs
git commit -m "perf(native): reference mapped shared block metadata"
```

The body must state that production selection is still disabled and quantify
the zero-owned-record invariant proven by tests.

---

### Task 4: Consume mapped direct bindings and pre-grouped edges

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/direct_binding.rs:257-330`
- Modify: `crates/carrick-dsr-aarch64/src/direct_binding.rs:560-760`
- Modify: `crates/carrick-dsr-aarch64/src/direct_binding.rs:780-1320`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:3230-3280`
- Test: `crates/carrick-dsr-aarch64/src/direct_binding.rs`
- Test: `crates/carrick-dsr-aarch64/src/translator.rs`

**Interfaces:**
- Consumes: indexed binding, relocation, edge-group, and edge-member views from Task 2 plus `LoadedTranslationMetadata` from Task 3.
- Produces: `DirectBindingRecordOwner`, mapped unit owners, and a no-regroup V3 preparation path.

- [ ] **Step 1: Write failing mapped binding tests**

Install a V3 fixture with three binding records across two edge groups. Assert
that preparation creates mapped record references, exact cell owners, and the
same edge lookup result as V2 without owning record copies or invoking the V2
group counter:

```rust
assert_eq!(prepared.record_count(), 3);
assert_eq!(prepared.owned_record_count(), 0);
assert_eq!(prepared.edge_group_builds(), 0);
assert_eq!(
    prepared.edge_members(GuestVa(0x4000), GuestVa(0x5000)),
    &[(0, 0), (0, 1)]
);
```

Add corruption tests for a member that points to the wrong binding and a
binding whose back-reference points outside the member table. Both must fail
before registry state changes.

- [ ] **Step 2: Run tests and confirm red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 mapped_direct_binding --lib
```

Expected: compilation fails because unit owners still clone a boxed binding
slice and regroup edges.

- [ ] **Step 3: Replace cloned owner records with typed references**

Use a representation-aware record owner:

```rust
enum DirectBindingRecordOwner {
    V2(UnresolvedDirectBindingRecord),
    V3 { record_index: u32 },
}

struct DirectBindingOwner {
    unit_index: usize,
    record: DirectBindingRecordOwner,
    cell: DirectBindingCellVa,
}
```

Add one `DirectBindingUnitOwner::record(index)` accessor which returns a copy
view from the V2 boxed slice or the source lease's V3 table. Every publication,
miss, clear, and validation path must use that accessor; no V3 caller may clone
the mapped table.

- [ ] **Step 4: Consume V3 edge groups directly**

Retain `prepare_unit_edges` unchanged for V2. Add
`prepare_mapped_unit_edges(unit_index, metadata)` which walks the already sorted
group/member views once and appends `(unit_index, binding_index)` references to
the process-local cross-unit map. Do not count, regroup, or sort V3 bindings.

- [ ] **Step 5: Run direct-binding, translator, and oracle tests**

Run:

```bash
cargo test -p carrick-dsr-aarch64 direct_binding --lib
cargo test -p carrick-dsr-aarch64 mapped_direct_binding --lib
RUST_TEST_THREADS=1 cargo test -p carrick-runtime direct_binding --lib
```

Expected: all existing owner/publication/fork/exec tests and new mapped tests
pass with exact V2 behavior.

- [ ] **Step 6: Commit Task 4**

```bash
git add crates/carrick-dsr-aarch64/src/direct_binding.rs crates/carrick-dsr-aarch64/src/translator.rs
git commit -m "perf(native): reuse mapped direct-binding indexes"
```

The body must name the removed clone/group/sort work and the failure-atomic
mapped corruption tests.

---

### Task 5: Publish and mmap V3 metadata on Darwin by default

**Files:**
- Modify: `crates/carrick-native-darwin/Cargo.toml:12-25`
- Modify: `crates/carrick-native-darwin/src/aot_cache.rs:1-220`
- Modify: `crates/carrick-native-darwin/src/aot_cache.rs:740-930`
- Modify: `crates/carrick-native-darwin/src/aot_cache.rs:990-1275`
- Test: `crates/carrick-native-darwin/src/aot_cache.rs`

**Interfaces:**
- Consumes: V3 encoder, validator, metadata backing, loaded enum, and evidence from Tasks 2–4.
- Produces: `ReadOnlyMetadataMapping`, default-on V3 publication/loading, and exact V2 selection.

- [ ] **Step 1: Write failing feature, lifetime, and pair tests**

Add tests proving exact feature semantics:

```rust
#[test]
fn mapped_metadata_is_default_on_with_an_exact_opt_out() {
    assert!(mapped_metadata_enabled_from(None));
    assert!(mapped_metadata_enabled_from(Some(std::ffi::OsStr::new("1"))));
    assert!(mapped_metadata_enabled_from(Some(std::ffi::OsStr::new("false"))));
    assert!(!mapped_metadata_enabled_from(Some(std::ffi::OsStr::new("0"))));
}
```

Add tests that publish/load V3, verify `bytes_read == 0`, unlink the metadata
pathname while clones still resolve records, drop the final lease, reject a
lone `.dylib` or `.metadata-v3`, and map corrupt V3 to the exact
`UnitMissReason` before `dlopen` authority is retained.

- [ ] **Step 2: Run tests and confirm red**

Run:

```bash
cargo test -p carrick-native-darwin aot_cache --lib
```

Expected: new feature and V3 mapping tests fail because production still reads
and bincode-decodes `.manifest`.

- [ ] **Step 3: Add the direct mapping dependency and backing type**

Add `memmap2.workspace = true` to `carrick-native-darwin` and implement:

```rust
#[derive(Debug)]
struct ReadOnlyMetadataMapping {
    mapping: memmap2::Mmap,
    _file: File,
}

impl MetadataBacking for ReadOnlyMetadataMapping {
    fn bytes(&self) -> &[u8] {
        self.mapping.as_ref()
    }
}
```

Open through the authority directory, require a regular file, verify the
observed size is nonzero and within the V3 maximum, and use read-only private
`MmapOptions::map_copy_read_only` (`MAP_PRIVATE|PROT_READ`). The retained `File`
binds the mapped inode across pathname unlink.

Use a single helper with the directory capability, not a path-only reopen:

```rust
fn open_metadata_at(
    directory: &File,
    name: &std::ffi::CStr,
) -> Result<File, UnitStoreError>;
```

It calls `libc::openat` with `O_RDONLY | O_CLOEXEC | O_NOFOLLOW`, wraps the
returned descriptor with `File::from_raw_fd`, and rejects non-regular `fstat`
results before mapping.

- [ ] **Step 4: Add V3 publication without weakening atomicity**

Generate the owned manifest after signing as today, encode V3 instead of
bincode when enabled, write it to a unique temporary file, flush it, map and
validate it through the production parser, then publish under the per-key lock.
Use `.metadata-v3` for V3 and `.manifest` for V2. A reader that observes only
one half returns `MissingPair`; duplicate writers load the winner.

- [ ] **Step 5: Add V3 load and preserve the V2 control**

When enabled, map and validate V3 against the expected key before resolving the
keyed dylib export. Return `LoadedTranslationMetadata::V3` plus measured map and
validation evidence. Under exact `0`, execute the current `std::fs::read`,
bincode decode, validation, and owned manifest construction unchanged.

- [ ] **Step 6: Run native cache and full DSR unit tests**

Run:

```bash
cargo test -p carrick-native-darwin aot_cache --lib
cargo test -p carrick-dsr-aarch64 --lib
RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_darwin::dsr --lib
just fmt-check
```

Expected: V3 is default, V2 exact control passes, mapping lifetime survives
unlink, and all shared runtime semantics remain green.

- [ ] **Step 7: Commit Task 5**

```bash
git add Cargo.toml Cargo.lock crates/carrick-native-darwin/Cargo.toml crates/carrick-native-darwin/src/aot_cache.rs
git commit -m "perf(native): map shared translation metadata by default"
```

The body must document file-pair behavior, typed fallback, exact opt-out, and
the live mapping lifetime tests.

---

### Task 6: Make V2/V3 mechanism evidence receipt-bound

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:1431-1620`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs:2000-2205`
- Modify: `scripts/perf/native_go_build.py`
- Modify: `scripts/perf/native_go_build_abba.py`
- Modify: `scripts/perf/native_go_dtrace_target.py`
- Modify: `scripts/perf/test_native_go_build.py`
- Modify: `scripts/perf/test_native_go_build_abba.py`
- Modify: `scripts/perf/test_native_go_dtrace_target.py`
- Modify: `scripts/perf/overlays/native-default.json`
- Modify: `scripts/perf/overlays/native-shared.json`
- Modify: `scripts/perf/overlays/native-shared-manifest-clone.json`
- Modify: `scripts/perf/overlays/native-shared-manifest-varint.json`
- Modify: every other `scripts/perf/overlays/native-shared-*.json`
- Create: `scripts/perf/overlays/native-shared-metadata-v2.json`

**Interfaces:**
- Consumes: `TranslationMetadataLoadEvidence` from Task 3 and the exact runtime switch from Task 5.
- Produces: resolver/profile counters, harness environment identity, `--metadata-mode`, and a same-binary V2 control overlay.

- [ ] **Step 1: Write failing Rust and Python evidence tests**

Rust tests must assert V3 load evidence increments mapped bytes/records and zero
owned records, while V2 increments read bytes/owned records and zero mapped
bytes. Python tests must require the new environment key in every overlay and
prove CLI routing:

```python
def test_metadata_mode_routes_exact_control(self):
    mapped = target.environment_for(metadata_mode="mapped")
    control = target.environment_for(metadata_mode="v2")
    self.assertIsNone(mapped["CARRICK_DSR_SHARED_MAPPED_METADATA"])
    self.assertEqual(control["CARRICK_DSR_SHARED_MAPPED_METADATA"], "0")
```

- [ ] **Step 2: Run tests and confirm red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 resolver_stats --lib
PYTHONPATH=scripts/perf python3 -m unittest scripts/perf/test_native_go_build.py scripts/perf/test_native_go_build_abba.py scripts/perf/test_native_go_dtrace_target.py
```

Expected: missing counters, overlay key, and CLI selection fail.

- [ ] **Step 3: Add low-frequency process counters**

Add saturating fields and `ResolverStat` names for metadata bytes read/mapped,
validation nanoseconds, mapped/owned immutable records, guest-range derivations,
and direct-edge group builds. Apply a loaded unit's evidence exactly once at
successful commit; include every field in delta, reset, profile output, fork,
exec, and test snapshot plumbing.

- [ ] **Step 4: Extend harness identity and overlays**

Add `CARRICK_DSR_SHARED_MAPPED_METADATA` to the canonical environment key list.
`native-shared.json` leaves it null/default. Create
`native-shared-metadata-v2.json` with shared translation and direct bindings on
plus mapped metadata exactly `0`. Add exact `0` to the existing V2 manifest
clone and varint overlays; leave recovery/source/dylib controls in V3 unless
their purpose is specifically the V2 object graph.

Add `--metadata-mode {mapped,v2}` to `native_go_dtrace_target.py` and record it
in target provenance. Do not add a truthy opt-in spelling.

- [ ] **Step 5: Run all focused evidence tests**

Run:

```bash
cargo test -p carrick-dsr-aarch64 resolver_stats --lib
PYTHONPATH=scripts/perf python3 -m unittest scripts/perf/test_native_go_build.py scripts/perf/test_native_go_build_abba.py scripts/perf/test_native_go_dtrace_target.py scripts/perf/test_native_pc_range_directional.py
```

Expected: receipts bind the metadata mode, every overlay has an explicit key,
and counters reconcile across process/thread reporting.

- [ ] **Step 6: Commit Task 6**

```bash
git add crates/carrick-dsr-aarch64/src/translator.rs scripts/perf/native_go_build.py scripts/perf/native_go_build_abba.py scripts/perf/native_go_dtrace_target.py scripts/perf/test_native_go_build.py scripts/perf/test_native_go_build_abba.py scripts/perf/test_native_go_dtrace_target.py scripts/perf/overlays
git commit -m "diagnostics(perf): bind mapped metadata evidence"
```

The body must explain that counters are mechanism evidence, not timing
authority, and list the exact V2 overlay.

---

### Task 7: Prove correctness and DTrace mechanism movement live

**Files:**
- Modify only if a live failure identifies a production or diagnostic defect; keep fixes in a separate conventional commit.
- Evidence: `target/perf/native-metadata-v3-*.raw`
- Evidence: `target/perf/native-metadata-v3-*.json`

**Interfaces:**
- Consumes: signed V3 candidate, V2 control, bounded `native-pc-range-directional.d`, exact analyzer, run-ID cleanup, and LLDB snapshot tooling.
- Produces: signed correctness proof and a zero-drop V2/V3 owner comparison.

- [ ] **Step 1: Run focused and full local correctness gates**

Run sequentially:

```bash
just fmt-check
just clippy
cargo test -p carrick-dsr-aarch64 --lib
cargo test -p carrick-native-darwin --lib
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib
RUST_TEST_THREADS=1 just ci
```

Expected: all commands pass. Attribute any failure against pre-change HEAD
before changing production code.

- [ ] **Step 2: Build and verify the signed runnable binary**

Run:

```bash
just build
codesign -d --entitlements :- target/release/carrick
otool -l target/release/carrick | grep __dof_carrick
```

Expected: build succeeds, entitlement output is present, and the DOF section is
reported.

- [ ] **Step 3: Run native ecosystem correctness separately from Docker**

Run:

```bash
just conformance-native smoke --workers 4
just conformance-native smoke --workers 4 --ecosystem node
just conformance-native smoke --workers 4 --ecosystem cpython
```

Do not start Docker until every Carrick process and exact run ID is gone.

- [ ] **Step 4: Capture bounded V2 and V3 directional profiles**

Run the V2 control first and V3 second with distinct exact run IDs:

```bash
sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/native-pc-range-directional.d -c "python3 scripts/perf/native_go_dtrace_target.py --variant shared --metadata-mode v2 --run-id mapped-v2-directional" > target/perf/native-metadata-v3-v2.raw
sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/native-pc-range-directional.d -c "python3 scripts/perf/native_go_dtrace_target.py --variant shared --metadata-mode mapped --run-id mapped-v3-directional" > target/perf/native-metadata-v3-v3.raw
python3 scripts/perf/native_pc_range_directional.py --input target/perf/native-metadata-v3-v2.raw --output target/perf/native-metadata-v3-v2.json
python3 scripts/perf/native_pc_range_directional.py --input target/perf/native-metadata-v3-v3.raw --output target/perf/native-metadata-v3-v3.json
scripts/sudo/kill.sh mapped-v2-directional
scripts/sudo/kill.sh mapped-v3-directional
```

Require natural completion, `BUILD_OK`, zero DTrace drops/errors, exact
PC/leaf reconciliation, and cleanup to zero. Compare exact normalized Carrick
offsets using the signed binary. The V3 arm must remove bincode decode,
manifest `Vec` deserialization, `exact_guest_ranges_from_pc_map`, and V2 edge
grouping/sort leaves without introducing a larger mmap fault, lock, dyld, or
kernel owner.

- [ ] **Step 5: Escalate contradictions with LLDB, not logging**

If a run wedges or a mapped extent faults, preserve the exact run before
cleanup:

```bash
target/release/carrick debug lldb-snapshot --run-id mapped-v3-directional --output target/perf/native-metadata-v3-lldb
```

Use the guest PID and `scripts/carrick_lldb.py` event ring. Do not add
`eprintln!` diagnostics or infer corruption from an empty parent ring.

- [ ] **Step 6: Commit only a necessary live fix**

If Steps 1–5 required a fix, commit that root cause with its exact reproducer
and live verification. If no fix was required, leave raw evidence ignored and
make no empty commit.

---

### Task 8: Run the primary CPU gate and retain or remove V3

**Files:**
- Modify: `handoff.md`
- Create only on retention: `scripts/perf/evidence/native-mapped-metadata-v3-abba.json`

**Interfaces:**
- Consumes: one immutable signed binary, V2/V3 overlays, the exact arm64 image, mechanism proof, and correctness gates.
- Produces: the authoritative eight-quad decision and resumable handoff.

- [ ] **Step 1: Prepare one immutable same-binary receipt**

Run:

```bash
python3 scripts/perf/native_go_build_abba.py prepare-arm --source-repo /Volumes/CaseSensitive/carrick/.worktrees/native-performance-m1 --destination target/perf/mapped-metadata-arm --label mapped-metadata-v2-v3 --role candidate --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
```

Verify the receipt binds the expected source commit, binary SHA, image digest,
entitlement, and DOF section. Both campaign arms below must use this exact same
receipt path; only their overlays may differ.

- [ ] **Step 2: Run the immutable eight-quad authority**

Run with the user's standing battery authorization:

```bash
python3 scripts/perf/native_go_build_abba.py run --harness-repo /Volumes/CaseSensitive/carrick/.worktrees/native-performance-m1 --control-receipt target/perf/mapped-metadata-arm/arm.json --candidate-receipt target/perf/mapped-metadata-arm/arm.json --control-overlay scripts/perf/overlays/native-shared-metadata-v2.json --candidate-overlay scripts/perf/overlays/native-shared.json --quads 8 --cooldown-seconds 2 --timeout-seconds 180 --allow-battery --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b --output target/perf/native-mapped-metadata-v3-abba.json
```

Require 32/32 runs, candidate total-CPU median below control, one-sided upper
ratio below `1.0`, sign probability below `0.05`, and no supported secondary
regression. This is the first timing decision: Task 7's bounded DTrace run is
mechanism evidence, not a timing screen, and the runner deliberately rejects
official campaigns with fewer than eight quads.

- [ ] **Step 3: Retain or remove based on the gate**

If every gate passes, publish the evidence:

```bash
python3 scripts/perf/native_go_build_abba.py publish --source target/perf/native-mapped-metadata-v3-abba.json --destination scripts/perf/evidence/native-mapped-metadata-v3-abba.json
```

If the primary gate fails, preserve the ignored artifact, revert the V3
production and harness commits with ordinary `git revert` commits, and keep the
wire/tooling only if it has independent demonstrated diagnostic value. Do not
describe projected savings as retained performance.

- [ ] **Step 4: Update the handoff with exact evidence**

Record source/binary/image identities, artifact SHA-256, all primary and
secondary ratios, wins, confidence bounds, sign probability, DTrace owner
movement, correctness commands, retained/rejected decision, and the next
measured owner. Keep the existing `15.50%` cumulative result separate from the
new incremental V2/V3 result.

- [ ] **Step 5: Commit the decision checkpoint**

On retention:

```bash
git add handoff.md scripts/perf/evidence/native-mapped-metadata-v3-abba.json
git commit -m "docs(perf): retain mapped metadata cpu result"
```

On rejection, commit only the honest handoff plus revert commits. In either
case, the body must contain the real gate result and exact verification, not a
projection.
