# Native AArch64 Direct-Binding Sidecar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove or reject an immutable-code-compatible direct-binding sidecar
that cuts eligible shared-unit direct resolver exits by at least 95% and earns
an untraced wall-time retention decision against both the 19,375 ms official
Carrick baseline and contemporaneous default controls.

**Architecture:** Keep signed shared-unit `__TEXT` immutable and add one
process-private atomic pointer cell per unresolved direct stub in
`__DATA,__data`. A 22-instruction in-place AArch64 hit path acquire-loads one
immutable process-owned target/authority descriptor, validates and installs
its complete execution authority, restores architectural scratch state, and
branches without a global lookup. Cold misses carry a typed cell address and
stub ordinal through `DsrContext`; the process translator validates the exact
loaded-unit owner, release-CAS publishes the descriptor, records the reverse
incoming edge, and clears exact stale publications on generation, fork, and
exec boundaries.

**Tech Stack:** Rust, AArch64/dynasmrt, hand-emitted Mach-O, dyld,
`AtomicPtr`, libdtrace/USDT, Python 3 benchmark tooling, Darwin native
AArch64, Docker's native-arm64 oracle.

## Global Constraints

- Scope is Darwin/AArch64 `--exec-backend native` and immutable shared
  translation units. Private JIT blocks keep their existing mutable direct
  branch patching.
- During the spike the feature is opt-in with
  `CARRICK_DSR_DIRECT_BINDINGS=1`; default execution and shared translation
  without this variable remain controls. Only a retained wave may make the
  sidecar implicit inside the still-opt-in shared-translation mode.
- The official baseline remains `C0=19,375 ms`, `D0=1,007 ms`,
  `R0=19.2403x`; the first campaign milestone remains `R<=9.6202x`.
- The current authority-carrying precursor is a correctness dependency, not a
  retained wall win. Its measured three-sample median is 25,169 ms.
- No executable page becomes writable after signing or loading.
- Every serialized unresolved stub owns exactly one cell identified by
  `(TranslationUnitKey, DirectBindingOrdinal)`. Source/target addresses only
  validate that owner.
- A cell is exactly one aligned atomic pointer. It never separately publishes
  target and authority fields.
- Published descriptors, private JIT addresses, shared-unit handles,
  generation bindings, and authority records remain pinned until a quiesced
  reset clears every reachable cell.
- Fork-child repair uses only preallocated publication bitmaps. It performs no
  allocation, dyld discovery, or unit lookup.
- The Variant 1 hit path is at most 24 instructions from its first cell-address
  instruction through its final `br`; the fixed sequence below is 22.
- No always-on hit counter is added to the translated path. Mechanism evidence
  comes from cold-path events, resolver-exit collapse, and sampled PCs.
- DTrace timing is diagnostic. Only untraced benchmark artifacts can retain a
  performance change.
- Carrick and Docker never run concurrently. Every run uses a unique
  `CARRICK_RUN_ID`, and cleanup uses `scripts/sudo/kill.sh <run-id>`.
- No Linux kernel or other GPL implementation source is consulted.
- The rejected full inline target-cache variants remain rejected.

---

### Task 1: Checkpoint the authority-carrying correctness precursor

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/emit.rs`
- Modify: `crates/carrick-dsr-aarch64/src/gateway.rs`
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-native-darwin/src/aot_cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`

**Interfaces:**
- Retains `TargetCacheAuthority { cache_start, cache_end,
  generation_bindings }` for direct and indirect target-cache entries.
- Keeps the target cache at two ways and 2 MiB while expanding each way from
  16 to 32 bytes.
- Keeps translator ABI 2 and rejects ABI 1 units.

- [ ] **Step 1: Confirm only the intended precursor diff is staged**

Run:

```bash
git diff --check
git diff --stat -- \
  crates/carrick-dsr-aarch64/src/emit.rs \
  crates/carrick-dsr-aarch64/src/gateway.rs \
  crates/carrick-dsr-aarch64/src/shared_cache.rs \
  crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-native-darwin/src/aot_cache.rs \
  crates/carrick-runtime/src/native_darwin/dsr/oracle.rs \
  crates/carrick-runtime/src/native_exec_capsule.rs
```

Expected: no whitespace errors; only the already-reviewed authority-carrying
precursor and its focused oracles appear.

- [ ] **Step 2: Re-run the focused correctness set**

Run:

```bash
cargo fmt --all -- --check
cargo test -p carrick-dsr-aarch64
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib \
  'native_darwin::dsr::oracle::portable_direct_'
```

Expected: 113 AArch64 DSR tests pass and all three
`portable_direct_*` runtime oracles pass.

- [ ] **Step 3: Commit only the precursor**

```bash
git add \
  crates/carrick-dsr-aarch64/src/emit.rs \
  crates/carrick-dsr-aarch64/src/gateway.rs \
  crates/carrick-dsr-aarch64/src/shared_cache.rs \
  crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-native-darwin/src/aot_cache.rs \
  crates/carrick-runtime/src/native_darwin/dsr/oracle.rs \
  crates/carrick-runtime/src/native_exec_capsule.rs
git commit
```

Use subject `perf(native): carry shared target authority`. The body records the
cross-unit execution-authority bug, the 32-byte two-way entry, ABI 2 rejection,
the three runtime oracles, and that 25.169 s is correctness evidence rather
than a retained wall win.

---

### Task 2: Checkpoint the mechanism and benchmark tooling

**Files:**
- Modify: `scripts/dtrace/dsr-indirect.d`
- Modify: `scripts/perf/native_go_build.py`
- Modify: `scripts/perf/test_native_go_build.py`

**Interfaces:**
- `dsr-indirect.d` reports bounded direct source/pair/outcome counts in
  addition to indirect entropy.
- `native_go_build.py --captured-output-dir PATH` retains complete output for
  each sample without changing timing boundaries.

- [ ] **Step 1: Re-run the Python contract**

```bash
python3 -m unittest scripts/perf/test_native_go_build.py -v
python3 scripts/perf/native_go_build.py --help
```

Expected: 12 tests pass and help lists `--captured-output-dir`.

- [ ] **Step 2: Inspect and commit only tooling**

```bash
git diff --check -- \
  scripts/dtrace/dsr-indirect.d \
  scripts/perf/native_go_build.py \
  scripts/perf/test_native_go_build.py
git add \
  scripts/dtrace/dsr-indirect.d \
  scripts/perf/native_go_build.py \
  scripts/perf/test_native_go_build.py
git commit
```

Use subject `diagnostics(native): retain direct-edge evidence`. The body
records the 45-second bound, whole-tree direct/indirect aggregation, captured
sample output, and the focused Python test command.

---

### Task 3: Checkpoint the measured campaign controller

**Files:**
- Modify: `docs/perf-results/native-wall-time-campaign.md`
- Modify: `handoff.md`

- [ ] **Step 1: Verify that measured and projected claims remain distinct**

Check that both documents contain:

- official `C0`, `D0`, and `R0`;
- the measured 25.169 s authority-precursor median;
- 17,155,262 bounded direct exits and the 1,473,595-event hot edge;
- both rejected inline-cache variants;
- H004 selected as `SPIKING`;
- the direct-binding sidecar as the next bounded experiment.

Run:

```bash
rg -n \
  '19,375|1,007|19\\.2403|25\\.169|17,155,262|1,473,595|H004|sidecar' \
  docs/perf-results/native-wall-time-campaign.md handoff.md
```

- [ ] **Step 2: Commit only the controller state**

```bash
git add docs/perf-results/native-wall-time-campaign.md handoff.md
git commit
```

Use subject `docs(perf): select direct-binding spike`. The body distinguishes
the retained correctness precursor from rejected performance variants and
names the sidecar's resolver-collapse and wall-screen gates.

---

### Task 4: Add typed atomic binding cells and immutable descriptors

**Files:**
- Create: `crates/carrick-dsr-aarch64/src/direct_binding.rs`
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs`

**Interfaces:**

```rust
#[repr(transparent)]
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
    serde::Serialize, serde::Deserialize,
)]
pub struct DirectBindingOrdinal(u32);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DirectBindingCellVa(usize);

#[repr(C)]
pub struct DirectBindingTargetPrefix {
    pub target_cache_pc: u64,
    pub cache_start: u64,
    pub cache_end: u64,
    pub generation_bindings: u64,
}

#[repr(C)]
pub struct DirectBindingTarget {
    pub prefix: DirectBindingTargetPrefix,
    target_page: carrick_guest_mem::GuestVa,
    target_generation: crate::types::CodeGeneration,
    private_epoch: Option<std::sync::Arc<PrivateJitEpoch>>,
    shared_lease: Option<crate::shared_cache::SharedLoadedTranslationUnit>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectBindingMiss {
    pub cell: DirectBindingCellVa,
    pub ordinal: DirectBindingOrdinal,
}
```

Both newtypes expose named domain constructors and accessors:

```rust
impl DirectBindingOrdinal {
    pub const fn claimed(value: u32) -> Self;
    pub const fn get(self) -> u32;
}

impl DirectBindingCellVa {
    pub fn mapped(value: usize) -> Option<Self>;
    pub const fn get(self) -> usize;
}
```

`DirectBindingCellRef` is the only raw mapped-cell adapter. It exposes:

```rust
pub unsafe fn from_mapped_address(
    address: DirectBindingCellVa,
) -> Result<Self, crate::types::DsrError>;
pub fn load_acquire(self) -> *mut DirectBindingTarget;
pub fn publish_null(
    self,
    target: *mut DirectBindingTarget,
) -> Result<(), *mut DirectBindingTarget>;
pub fn clear_if(self, expected: *mut DirectBindingTarget) -> bool;
pub fn clear_release(self);
```

`publish_null` uses release success ordering and acquire failure ordering.
`load_acquire` uses acquire ordering. `clear_if` uses `AcqRel/Acquire`.

- [ ] **Step 1: Add red atomic-publication and typed-domain tests**

Add tests:

```rust
#[test]
fn one_word_publication_never_mixes_target_and_authority()

#[test]
fn exact_pointer_clear_cannot_erase_a_newer_publication()

#[test]
fn mapped_cell_rejects_zero_and_unaligned_addresses()

#[test]
fn private_epoch_reports_live_descriptor_leases()
```

The concurrency test creates two complete descriptors with disjoint target
ranges, races two release-CAS publishers for at least 10,000 barriers, and
asserts every acquired winner is byte-for-byte one complete prefix.

- [ ] **Step 2: Run the focused test and verify red**

```bash
cargo test -p carrick-dsr-aarch64 direct_binding -- --nocapture
```

Expected: compile failure because `direct_binding` does not exist.

- [ ] **Step 3: Implement the atomic cell and descriptor prefix**

Add `pub mod direct_binding;`. Assert:

```rust
const _: () = assert!(std::mem::size_of::<DirectBindingTargetPrefix>() == 32);
const _: () = assert!(std::mem::offset_of!(
    DirectBindingTargetPrefix,
    target_cache_pc
) == 0);
const _: () = assert!(std::mem::offset_of!(
    DirectBindingTargetPrefix,
    generation_bindings
) == 24);
const _: () = assert!(
    std::mem::align_of::<std::sync::atomic::AtomicPtr<DirectBindingTarget>>()
        == 8
);
```

`PrivateJitEpoch` starts with one process-owner `Arc`. Descriptor construction
clones it. Quiesced reset may reuse private addresses only after descriptors
are dropped and `Arc::strong_count(&epoch) == 1`.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p carrick-dsr-aarch64 direct_binding -- --nocapture
cargo fmt --all -- --check
git add \
  crates/carrick-dsr-aarch64/src/direct_binding.rs \
  crates/carrick-dsr-aarch64/src/lib.rs
git commit
```

Use subject `feat(native): add atomic direct-binding cells`. The body explains
why the pointer is the sole publication word and names the racing-publisher and
exact-clear tests.

---

### Task 5: Carry typed sidecar misses through the gateway ABI

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/types.rs`
- Modify: `crates/carrick-dsr-aarch64/src/gateway.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`

**Interfaces:**

```rust
NativeDsrExit::ResolveDirect {
    source: GuestVa,
    target: GuestVa,
    binding: Option<DirectBindingMiss>,
}
```

Append these `DsrContext` fields without moving existing offsets:

```rust
pub direct_binding_cell: u64,       // offset 1280
pub direct_binding_ordinal: u32,    // offset 1288
pub direct_binding_present: u32,    // offset 1292
pub direct_binding_target: u64,     // offset 1296
pub direct_binding_pad: u64,        // offset 1304
```

The aligned context size becomes 1312 bytes. `DsrContext::new` zeros all five
fields for every entry. A direct rc=2 exit produces `binding: None` unless
`direct_binding_present == 1`, the cell is nonzero/aligned, and the ordinal is
typed successfully.

- [ ] **Step 1: Add red layout and stale-metadata tests**

Add tests:

```rust
#[test]
fn direct_binding_fields_append_without_moving_the_existing_gateway_abi()

#[test]
fn direct_exit_decodes_an_exact_typed_binding_miss()

#[test]
fn new_context_clears_stale_binding_authority_for_every_exit_kind()
```

The layout test retains every existing offset assertion and checks the five new
offsets and 1312-byte size.

- [ ] **Step 2: Run the focused tests and verify red**

```bash
cargo test -p carrick-dsr-aarch64 gateway:: -- --nocapture
```

Expected: compile failures because `ResolveDirect` has no `binding` and the
context has no sidecar fields.

- [ ] **Step 3: Implement the appended cold-exit ABI**

Add constants:

```rust
pub const CTX_DIRECT_BINDING_CELL: u32 = 1280;
pub const CTX_DIRECT_BINDING_ORDINAL: u32 = 1288;
pub const CTX_DIRECT_BINDING_PRESENT: u32 = 1292;
pub const CTX_DIRECT_BINDING_TARGET: u32 = 1296;
```

Update every `ResolveDirect` constructor and pattern in `gateway.rs`,
`translator.rs`, the runtime oracle, and tests to carry `binding: None` until
the specialized stub is connected.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p carrick-dsr-aarch64 gateway:: -- --nocapture
cargo test -p carrick-dsr-aarch64
cargo check -p carrick-runtime
cargo fmt --all -- --check
git add \
  crates/carrick-dsr-aarch64/src/types.rs \
  crates/carrick-dsr-aarch64/src/gateway.rs \
  crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-runtime/src/native_darwin/dsr/oracle.rs
git commit
```

Use subject `feat(native): carry direct-binding miss identity`. The body
records append-only ABI growth, fail-closed decode, and stale-context clearing.

---

### Task 6: Record stable direct-stub identity and recovery phases

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/emit.rs`
- Modify: `crates/carrick-dsr-aarch64/src/artifact_spike.rs`

**Interfaces:**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectLinkKind {
    Branch,
    Call,
    ConditionalTaken,
    ConditionalFallthrough,
    Continue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectStubEnvelope {
    pub start: CacheOffset,
    pub end: CacheOffset,
}

pub struct DirectLink {
    pub slot: CacheOffset,
    pub source: GuestVa,
    pub target: GuestVa,
    pub kind: DirectLinkKind,
    pub stub: DirectStubEnvelope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectBindingRecoveryPhase {
    ScratchCapture,
    CellAddress,
    TargetAcquire,
    AuthorityValidate,
    AuthorityInstall,
    ArchitecturalRestore,
    FinalBranch,
    MissExit,
}
```

Add `RecoveryAction::RestoreDirectBinding {
phase: DirectBindingRecoveryPhase, committed_link: Option<u64> }`.
`recover_rewrite_state` restores x15, x16, x17, x30, and NZCV from existing
context scratch fields. For a call, `committed_link` replaces the stale saved
x30 after restoration.

- [ ] **Step 1: Add red edge-identity tests**

Add table-driven tests for:

- `Branch`;
- `Call`;
- conditional taken;
- conditional fall-through;
- `Continue`;
- fused-exclusive continuation.

Each test asserts exact source, target, kind, slot, nonempty stub envelope, and
that every word in the envelope has one declared recovery phase.

Add:

```rust
#[test]
fn direct_binding_recovery_preserves_a_committed_call_link()
```

- [ ] **Step 2: Run the focused tests and verify red**

```bash
cargo test -p carrick-dsr-aarch64 \
  'emit::tests::direct_' -- --nocapture
```

Expected: failures because `DirectLink` lacks source, kind, and envelope.

- [ ] **Step 3: Record envelopes at emission time**

At every direct exit:

1. record `slot`;
2. record the resolver stub's first offset before emission;
3. emit the existing resolver-capable stub;
4. record its exclusive end offset;
5. store source, target, kind, and envelope in `DirectLink`.

Do not derive source from `PcMapEntry`. Update
`PortableArtifactTemplate` wire conversion to preserve all new fields and the
new recovery variant.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p carrick-dsr-aarch64 \
  'emit::tests::direct_' -- --nocapture
cargo test -p carrick-dsr-aarch64 artifact_spike -- --nocapture
cargo fmt --all -- --check
git add \
  crates/carrick-dsr-aarch64/src/emit.rs \
  crates/carrick-dsr-aarch64/src/artifact_spike.rs
git commit
```

Use subject `feat(native): serialize direct-stub identity`. The body explains
why PC maps cannot supply owner identity and names the five edge classes plus
committed-call-link recovery.

---

### Task 7: Pack deterministic cells and the 22-instruction Variant 1 stub

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs`
- Modify: `crates/carrick-dsr-aarch64/src/emit.rs`
- Modify: `crates/carrick-native-darwin/src/aot_cache.rs`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`

**Interfaces:**

```rust
pub const TRANSLATOR_ABI_CURRENT: u32 = 3;
pub const TRANSLATION_UNIT_SCHEMA_V2: u32 = 2;
pub const DIRECT_BINDING_CELL_SIZE: u32 = 8;
pub const TRANSLATION_UNIT_BINDING_EXPORT: &str =
    "carrick_aot_unit_bindings";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectBindingLayout {
    Disabled,
    SidecarV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnresolvedDirectBindingRecord {
    pub source: GuestVa,
    pub target: GuestVa,
    pub kind: DirectLinkKind,
    pub ordinal: DirectBindingOrdinal,
    pub stub_start: u32,
    pub stub_end: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectBindingRelocation {
    pub ordinal: DirectBindingOrdinal,
    pub adrp_offset: u32,
    pub add_offset: u32,
    pub data_offset: u32,
}
```

`PendingTranslationUnit` and `TranslationUnitManifest` gain
`binding_layout`, `binding_export`, `binding_data_len`, `cell_size`,
`bindings`, and `binding_relocations`. `PendingTranslationUnit` additionally
owns `binding_data: Vec<u8>`; manifests never serialize mutable cell contents.

`PendingTranslationUnit::pack` becomes:

```rust
pub fn pack(
    key: TranslationUnitKey,
    candidates: Vec<PortableBlockCandidate>,
    binding_layout: DirectBindingLayout,
) -> Result<Self, DsrError>;
```

Add:

```rust
pub fn direct_binding_runtime_enabled() -> bool;
```

It reads `CARRICK_DSR_DIRECT_BINDINGS` once and selects `Disabled` or
`SidecarV1` before packing. A container process tree cannot mix layouts.

- [ ] **Step 1: Add red schema and deterministic-packing tests**

Add tests:

```rust
#[test]
fn unresolved_stubs_receive_ordinals_in_source_offset_order()

#[test]
fn equal_source_target_pairs_still_own_distinct_cells()

#[test]
fn same_unit_links_patch_to_b_and_receive_no_cells()

#[test]
fn sidecar_v1_hit_path_is_exactly_twenty_two_instructions()

#[test]
fn sidecar_rewrite_rejects_an_envelope_with_the_wrong_instruction_shape()

#[test]
fn schema_v2_rejects_old_abi_nonzero_cells_and_out_of_stub_relocations()
```

Construct one manifest rejection case for each design rule: old schema,
unaligned data, inconsistent data length, duplicate ordinal, conflicting owner,
same-unit binding, out-of-envelope relocation, and nonzero cell bytes.

- [ ] **Step 2: Run focused tests and verify red**

```bash
cargo test -p carrick-dsr-aarch64 shared_cache -- --nocapture
```

Expected: compile failures because schema V2 and binding records do not exist.

- [ ] **Step 3: Implement stable ordinals and zero data**

After same-unit links are patched, sort remaining links by absolute
`stub.start` offset and enumerate them with
`DirectBindingOrdinal::claimed(0..n)`. Preserve one record per stub even when
source and target repeat.

Both layouts serialize that predeclared eligible population.
`DirectBindingLayout::Disabled` retains the exact authority-precursor code and
emits no data section or relocations. `SidecarV1` additionally creates exactly
`n * 8` zero bytes and rewrites only unresolved envelopes. Schema validation
applies layout-specific rules: disabled units have records but zero
cell/data/relocation state; Sidecar V1 units have one aligned zero cell and one
contained relocation per record.

- [ ] **Step 4: Emit the fixed hit-path sequence**

The first cell-address instruction through final branch is exactly:

```text
 1  adrp x15, binding-cell-page
 2  add  x15, x15, binding-cell-pageoff
 3  ldar x17, [x15]
 4  cbz  x17, miss
 5  str  x17, [x28, CTX_DIRECT_BINDING_TARGET]
 6  ldr  x16, [x17, #0]          ; target cache PC
 7  ldp  x15, x30, [x17, #8]    ; cache start/end
 8  cmp  x16, x15
 9  b.lo miss
10  cmp  x16, x30
11  b.hs miss
12  stp  x15, x30, [x28, CTX_CACHE_START]
13  ldr  x15, [x17, #24]        ; generation bindings
14  str  x15, [x28, CTX_GENERATION_BINDINGS]
15  str  x16, [x28, #1072]      ; staged entry
16  ldr  x16, [x28, #936]       ; saved NZCV
17  msr  nzcv, x16
18  ldr  x15, [x28, #1160]
19  ldr  x16, [x28, #1120]
20  ldr  x30, [x28, #1168]
21  ldr  x17, [x28, #1072]
22  br   x17
```

Scratch capture precedes instruction 1. The miss block rematerializes the cell
address, stores cell/ordinal/present into `DsrContext`, clears
`direct_binding_target`, restores scratch and NZCV, and enters the existing
direct resolver. Every word in both paths receives its declared
`DirectBindingRecoveryPhase`.

- [ ] **Step 5: Validate schema and bump exec-capsule ABI**

`TranslationUnitManifest::validate_ranges` verifies all code/data ranges,
owner uniqueness, ordinals, cell-size arithmetic, and relocation containment
before any `dlopen`. `PendingTranslationUnit` guarantees zero cell bytes at
publication, and the loader verifies zero mapped cells before exposing a unit.
ABI 2 must fail with `UnitMissReason::TranslatorAbi`.

Update `aot_cache.rs` fixtures and manifest construction for schema V2 in this
commit. Until Task 8 adds data-segment emission, `publish_unit` returns a typed
`ManifestRange` miss for nonempty `binding_data`; disabled-layout units keep
using the existing code-only AOT API. This keeps the workspace buildable
without publishing an incomplete Sidecar V1 dylib.

- [ ] **Step 6: Run tests and commit**

```bash
cargo test -p carrick-dsr-aarch64 shared_cache -- --nocapture
cargo test -p carrick-dsr-aarch64 \
  'emit::tests::direct_binding_' -- --nocapture
cargo test -p carrick-runtime native_exec_capsule -- --nocapture
cargo check -p carrick-native-darwin
cargo fmt --all -- --check
git add \
  crates/carrick-dsr-aarch64/src/shared_cache.rs \
  crates/carrick-dsr-aarch64/src/emit.rs \
  crates/carrick-native-darwin/src/aot_cache.rs \
  crates/carrick-runtime/src/native_exec_capsule.rs
git commit
```

Use subject `feat(native): pack direct-binding sidecars`. The body records
stable ordinal ownership, schema/ABI bump, the exact 22-word budget, and
same-unit direct patch preservation.

---

### Task 8: Emit a protected Mach-O data section and typed relocations

**Files:**
- Modify: `crates/carrick-native-darwin/src/aot.rs`
- Modify: `crates/carrick-native-darwin/src/aot_cache.rs`

**Interfaces:**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AotSection {
    Text,
    Data,
}

pub struct AotExport<'a> {
    pub name: &'a str,
    pub section: AotSection,
    pub offset: u32,
}

pub struct AotCodeToDataRelocation {
    pub adrp_offset: u32,
    pub add_offset: u32,
    pub data_offset: u32,
}

pub struct AotImage<'a> {
    pub code: &'a [u8],
    pub data: &'a [u8],
    pub exports: &'a [AotExport<'a>],
    pub relocations: &'a [AotCodeToDataRelocation],
}

pub fn emit_dylib(image: &AotImage<'_>) -> Result<Vec<u8>, AotEmitError>;
```

The file contains `__TEXT,__text` with `r-x`, `__DATA,__data` with `rw-`, and
`__LINKEDIT` with `r--`. Data is 8-byte aligned and starts at a 16 KiB segment
boundary. Text is section 1; data is section 2.

- [ ] **Step 1: Add red structural and relocation tests**

Add:

```rust
#[test]
fn emits_text_data_and_linkedit_with_exact_protections()

#[test]
fn exports_resolve_to_their_declared_sections()

#[test]
fn patches_positive_and_negative_adrp_displacements()

#[test]
fn rejects_unaligned_out_of_range_or_wrong_shape_relocations()

#[test]
fn rejects_a_data_export_when_no_data_section_exists()
```

The relocation tests decode the resulting `ADRP` immediate and low-12 `ADD`
immediate and reconstruct the exact data cell VM address.

- [ ] **Step 2: Run focused tests and verify red**

```bash
cargo test -p carrick-native-darwin aot::tests -- --nocapture
```

Expected: compile failures because `AotImage`, data exports, and relocations do
not exist.

- [ ] **Step 3: Add the `__DATA` segment**

Increase `ncmds` and `sizeofcmds` for a third segment plus `section_64`. Emit
`__DATA` between text and linkedit with `VM_PROT_READ | VM_PROT_WRITE`, never
`VM_PROT_EXECUTE`. Set each nlist's `n_sect` from `AotSection`.

- [ ] **Step 4: Patch relocations only after final layout is known**

For every relocation:

1. validate both code offsets are aligned and in range;
2. validate placeholder opcodes are `ADRP x15` and `ADD x15,x15,#0`;
3. calculate the signed page delta from final text PC to final data cell;
4. reject a delta outside signed 21-bit `ADRP` range;
5. encode `immlo`, `immhi`, and the unsigned low 12 bits;
6. write both words only after every relocation validates.

Update `aot_cache::publish_unit` in the same commit to construct `AotImage`
from `pending.code`, `pending.binding_data`, both section-aware exports, and
the mapped typed relocations. Remove Task 7's temporary typed rejection of
nonempty binding data.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p carrick-native-darwin aot::tests -- --nocapture
cargo test -p carrick-native-darwin aot_cache::tests -- --nocapture
cargo fmt --all -- --check
git add \
  crates/carrick-native-darwin/src/aot.rs \
  crates/carrick-native-darwin/src/aot_cache.rs
git commit
```

Use subject `feat(native): emit writable AOT sidecars`. The body names the
three protection domains, section-aware exports, and all-or-nothing typed
relocation validation.

---

### Task 9: Load typed cells and prove process-private COW behavior

**Files:**
- Modify: `crates/carrick-native-darwin/src/aot_cache.rs`
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs`

**Interfaces:**

`LoadedTranslationUnit` and `SharedLoadedTranslationUnit` gain a typed binding
base and retain the `dlopen` lease:

```rust
pub struct LoadedTranslationUnit {
    pub manifest: TranslationUnitManifest,
    pub base: NonNull<u8>,
    pub binding_base: Option<DirectBindingCellVa>,
    handle: NonNull<libc::c_void>,
}

pub struct SharedLoadedTranslationUnit {
    pub manifest: TranslationUnitManifest,
    pub base: usize,
    pub binding_base: Option<DirectBindingCellVa>,
    _lease: Arc<dyn Send + Sync>,
}
```

- [ ] **Step 1: Add red publish/load and isolation tests**

Add:

```rust
#[test]
fn published_unit_loads_zero_aligned_binding_cells()

#[test]
fn two_independent_processes_bind_the_same_dylib_cell_privately()

#[test]
fn text_cannot_gain_write_permission_and_data_cannot_gain_execute_permission()

#[test]
fn loaded_unit_lease_keeps_code_data_and_handle_alive()
```

The two-process test forks before either child calls `dlopen`, uses pipes as a
barrier, has each child store a different aligned pointer value to ordinal 0,
and proves each child reads only its own value. The protection test performs
`mprotect` attempts in a sacrificial child and requires both forbidden
transitions to fail.

- [ ] **Step 2: Run focused tests and verify red**

```bash
cargo test -p carrick-native-darwin aot_cache::tests -- --nocapture
```

Expected: fixture compile failures because pending units and manifests lack
binding data and the loader lacks `binding_base`.

- [ ] **Step 3: Publish code, zero data, exports, and relocations together**

Map each `DirectBindingRelocation` into `AotCodeToDataRelocation`; export both
`TRANSLATION_UNIT_BASE_EXPORT` and
`TRANSLATION_UNIT_BINDING_EXPORT`. Build schema V2 only after signing and hash
the complete signed dylib.

- [ ] **Step 4: Resolve and validate the data export**

After `dlopen`, `dlsym` both exports. Reject a code export outside text, a data
export outside data, a non-8-byte-aligned binding base, or any nonzero cell.
The `Send`/`Sync` safety comment must state that code is immutable while data is
reachable only through `DirectBindingCellRef` atomics.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p carrick-native-darwin aot_cache::tests -- --nocapture
cargo test -p carrick-dsr-aarch64 shared_cache -- --nocapture
cargo fmt --all -- --check
git add \
  crates/carrick-native-darwin/src/aot_cache.rs \
  crates/carrick-dsr-aarch64/src/shared_cache.rs
git commit
```

Use subject `feat(native): load process-private binding cells`. The body names
the live COW and protection proofs and the retained dyld lease.

---

### Task 10: Register exact owners and publish retained descriptors

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/direct_binding.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`

**Interfaces:**

```rust
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirectBindingOwnerKey {
    pub unit: TranslationUnitKey,
    pub ordinal: DirectBindingOrdinal,
}

pub struct DirectBindingOwner {
    unit_index: usize,
    record: UnresolvedDirectBindingRecord,
    cell: DirectBindingCellVa,
}

pub struct DirectBindingUnitOwner {
    key: TranslationUnitKey,
    binding_base: DirectBindingCellVa,
    records: Box<[UnresolvedDirectBindingRecord]>,
    published_bitmap: Box<[u64]>,
    source_lease: SharedLoadedTranslationUnit,
}

pub struct IncomingDirectBinding {
    source: DirectBindingOwnerKey,
    cell: DirectBindingCellVa,
    expected: *mut DirectBindingTarget,
}

pub struct DirectBindingRegistry {
    enabled: bool,
    owners_by_cell: BTreeMap<DirectBindingCellVa, DirectBindingOwner>,
    units: Vec<DirectBindingUnitOwner>,
    descriptors: Vec<Box<DirectBindingTarget>>,
    incoming: BTreeMap<(GuestVa, CodeGeneration), Vec<IncomingDirectBinding>>,
    counters: DirectBindingCounters,
}
```

`ProcessState` owns one registry. `LoadedSharedUnit` retains its unit index.
`SharedBlockAuthority` retains enough information to clone the exact
`SharedLoadedTranslationUnit` target lease. Private descriptors clone the
process's `PrivateJitEpoch`.

- [ ] **Step 1: Add red owner and publication tests**

Add:

```rust
#[test]
fn miss_must_match_one_exact_loaded_owner_cell_and_ordinal()

#[test]
fn guest_source_target_pair_cannot_select_another_unit_instance()

#[test]
fn first_publisher_sets_the_bitmap_and_incoming_record()

#[test]
fn a_valid_losing_publisher_accepts_the_complete_winner()

#[test]
fn a_stale_winner_is_exactly_cleared_and_retried_once()

#[test]
fn failed_owner_or_authority_validation_leaves_the_cell_null()
```

- [ ] **Step 2: Run focused tests and verify red**

```bash
cargo test -p carrick-dsr-aarch64 \
  'translator::tests::direct_binding_' -- --nocapture
```

Expected: compile failures because `ProcessState` has no registry.

- [ ] **Step 3: Register owners when a shared unit loads**

Only `SidecarV1` manifests register owners. For every record:

1. derive `binding_base + ordinal * 8` with checked arithmetic;
2. validate the exact range and zero cell;
3. reject duplicate cell ownership;
4. allocate the fixed publication bitmap before making blocks executable;
5. retain one source-unit lease in every owner.

- [ ] **Step 4: Return target authority with a typed lease**

Replace the pointer-only helper with:

```rust
fn direct_binding_target(
    &self,
    guest: GuestVa,
    generation: CodeGeneration,
    entry: CacheVa,
) -> Result<DirectBindingTarget, DsrError>;
```

Private targets carry `PrivateJitEpoch`; shared targets clone the exact loaded
unit. Construct the complete descriptor and retain it before attempting CAS.

- [ ] **Step 5: Publish from the direct resolver**

For `ResolveDirect { source, target, binding }`, keep translation and the
per-thread target-cache fallback unchanged. If `binding` is present and the
registry is enabled:

1. validate exact cell, ordinal, source, target, kind, and source lease;
2. construct and retain the complete target descriptor;
3. release-CAS null to its pointer;
4. on success, set the preallocated bit and append the incoming record while
   holding `ProcessState` write authority;
5. on loss, acquire-validate the winner;
6. accept an exact valid winner, or exact-CAS-clear it and retry once;
7. leave the cell null and continue normally after any validation failure.

- [ ] **Step 6: Run tests and commit**

```bash
cargo test -p carrick-dsr-aarch64 \
  'translator::tests::direct_binding_' -- --nocapture
cargo test -p carrick-dsr-aarch64
cargo fmt --all -- --check
git add \
  crates/carrick-dsr-aarch64/src/direct_binding.rs \
  crates/carrick-dsr-aarch64/src/translator.rs
git commit
```

Use subject `feat(native): bind exact shared direct stubs`. The body records
owner validation, target leases, first-writer CAS, winner validation, and the
per-thread fallback.

---

### Task 11: Clear exact incoming edges on generation changes

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/direct_binding.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`

**Interfaces:**

```rust
pub fn invalidate_target(
    &mut self,
    page: GuestVa,
    generation: CodeGeneration,
) -> DirectBindingClearStats;
```

`DirectBindingClearStats` reports visited incoming records, exact clears,
newer-publication misses, and bitmap bits cleared.

- [ ] **Step 1: Add red invalidation tests**

Add:

```rust
#[test]
fn target_generation_invalidation_clears_only_the_expected_descriptor()

#[test]
fn a_reader_of_the_old_descriptor_remains_safe_until_generation_guard()

#[test]
fn the_next_traversal_rebinds_and_then_stays_out_of_the_resolver()
```

- [ ] **Step 2: Run focused tests and verify red**

```bash
cargo test -p carrick-dsr-aarch64 \
  'translator::tests::direct_binding_target_generation_' -- --nocapture
```

Expected: the old pointer remains published because invalidation has no
reverse registry integration.

- [ ] **Step 3: Integrate with page invalidation**

In `ProcessState::translate`, before removing each stale target block, call
`invalidate_target(stale.0, stale.1)`. For each incoming record, CAS-clear only
`expected`; a newer pointer remains untouched. Clear the source publication bit
only on an exact successful clear. Keep every descriptor pinned.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p carrick-dsr-aarch64 \
  'translator::tests::direct_binding_target_generation_' -- --nocapture
cargo test -p carrick-dsr-aarch64
cargo fmt --all -- --check
git add \
  crates/carrick-dsr-aarch64/src/direct_binding.rs \
  crates/carrick-dsr-aarch64/src/translator.rs
git commit
```

Use subject `fix(native): invalidate incoming direct bindings`. The body
records expected-pointer clearing, pinned old readers, generation-guard
fail-closed behavior, and true miss/rebind.

---

### Task 12: Enforce sparse fork clearing and quiesced exec order

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/direct_binding.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-dsr-aarch64/src/mapped_memory.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`

**Interfaces:**

```rust
pub fn clear_inherited_after_fork(&mut self) -> ForkBindingClearStats;
pub fn clear_all_before_exec(&mut self) -> ExecBindingClearStats;
```

Both functions iterate preallocated bitmap words and cell arrays. Neither
function grows a collection.

- [ ] **Step 1: Add red fork and exec-order tests**

Add:

```rust
#[test]
fn fork_child_clears_only_published_ordinals_without_allocation()

#[test]
fn fork_child_clear_is_cow_private_from_the_parent()

#[test]
fn child_rebind_does_not_mutate_parent_cells()

#[test]
fn exec_clears_cells_before_descriptors_units_and_private_cursor()

#[test]
fn private_cursor_reuse_requires_the_last_descriptor_epoch_lease_to_drop()
```

Use an injected lifecycle recorder with events:

```rust
enum DirectBindingResetEvent {
    CellsCleared,
    ThreadCachesCleared,
    IndexesCleared,
    DescriptorsDropped,
    UnitsDropped,
    PrivateCursorReset,
}
```

The exec test requires exactly this order.

- [ ] **Step 2: Run focused tests and verify red**

```bash
cargo test -p carrick-dsr-aarch64 \
  'translator::tests::direct_binding_fork_' -- --nocapture
cargo test -p carrick-dsr-aarch64 \
  'translator::tests::direct_binding_exec_' -- --nocapture
```

Expected: inherited cells remain nonzero and the current reset moves the JIT
cursor before sidecar state exists.

- [ ] **Step 3: Add sparse fork-child repair**

At the start of `ProcessTranslator::after_fork_child`, clear set bits and zero
the bitmaps before resetting statistics. Leave descriptor and reverse-link
arenas pinned. Return cell/page counts and elapsed duration for diagnostics.

- [ ] **Step 4: Reorder fork-for-exec reset**

After sibling retirement and before `NativeMappedMemory::replace_image`,
`native_darwin.rs` calls
`ThreadTranslator::prepare_direct_binding_exec_reset()`. That method clears
the surviving thread's indirect target cache and `resume_entry` while the
existing quiesce barrier excludes publishers and readers. The barrier also
proves that no stack-local `DsrContext` remains in translated execution; every
later context constructor starts with zero binding fields. The mapped-memory
replacement then invokes the process reset in this exact order:

1. clear every published sidecar cell;
2. record that thread-local target and binding state was already cleared;
3. clear incoming and owner indexes;
4. drop descriptors and assert the private epoch has one owner;
5. drop loaded units, generation bindings, and target authorities;
6. clear blocks and other translator metadata;
7. reset the private JIT cursor last.

No guest execution occurs between the thread preparation call and
`ThreadTranslator::reset_for_exec`; the latter installs the new process and
clears the same thread-local state idempotently.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p carrick-dsr-aarch64 \
  'translator::tests::direct_binding_fork_' -- --nocapture
cargo test -p carrick-dsr-aarch64 \
  'translator::tests::direct_binding_exec_' -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib \
  'native_darwin::dsr::tests::fork'
cargo fmt --all -- --check
git add \
  crates/carrick-dsr-aarch64/src/direct_binding.rs \
  crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-dsr-aarch64/src/mapped_memory.rs \
  crates/carrick-runtime/src/native_darwin.rs \
  crates/carrick-runtime/src/native_darwin/dsr/mod.rs
git commit
```

Use subject `fix(native): clear bindings across fork and exec`. The body names
sparse no-allocation child clearing, parent COW isolation, and the exact
clear-before-address-reuse order.

---

### Task 13: Prove asynchronous recovery and live sidecar execution

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`
- Modify: `crates/carrick-dsr-aarch64/src/emit.rs`
- Modify: `crates/carrick-dsr-aarch64/src/gateway.rs`

- [ ] **Step 1: Add red recovery-table coverage tests**

For branch, call, conditional taken, conditional fall-through, and `Continue`,
iterate every emitted instruction boundary from scratch capture through miss
exit and assert:

- one recovery entry covers it;
- x15, x16, x17, x30, and NZCV recover exactly;
- a committed call link survives;
- source and target guest PCs remain exact;
- a recovered path never resumes in the middle of the sidecar.

Add a red-first test that removes the recovery entry for the first authority
store and requires the coverage gate to fail.

- [ ] **Step 2: Add red authority-reentry tests**

Interrupt independently after:

1. the paired cache-range store;
2. the generation-binding store;
3. the descriptor-pointer store.

Re-enter through
`enter_translated_with_cache_range_and_generation_bindings` and assert the new
context contains one complete source authority and no field from the partial
target authority.

- [ ] **Step 3: Run focused tests and verify red**

```bash
cargo test -p carrick-dsr-aarch64 \
  'emit::tests::direct_binding_recovery_' -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib \
  'native_darwin::dsr::oracle::direct_binding_' -- --nocapture
```

Expected: incomplete coverage and no live sidecar oracle.

- [ ] **Step 4: Complete recovery metadata and live oracles**

Add runtime oracles:

```rust
fn direct_binding_private_to_shared_switch_executes()
fn direct_binding_shared_to_shared_switch_executes()
fn direct_binding_first_miss_then_hit_bypasses_gateway()
fn direct_binding_generation_change_clears_and_rebinds()
fn direct_binding_jittered_sigpipe_recovers_every_preamble_phase()
```

The jittered oracle repeats until sampled fault PCs cover every declared phase
or a fixed 10,000-signal bound is reached; failure to cover a phase is a test
failure rather than an infinite loop.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p carrick-dsr-aarch64 \
  'emit::tests::direct_binding_recovery_' -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib \
  'native_darwin::dsr::oracle::direct_binding_' -- --nocapture
cargo fmt --all -- --check
git add \
  crates/carrick-dsr-aarch64/src/emit.rs \
  crates/carrick-dsr-aarch64/src/gateway.rs \
  crates/carrick-runtime/src/native_darwin/dsr/oracle.rs
git commit
```

Use subject `test(native): prove direct-binding recovery`. The body names every
edge class, all three authority installation boundaries, SIGPIPE jitter, and
the deliberate red-first metadata hole.

---

### Task 14: Add low-frequency mechanism evidence and exact screen tooling

**Files:**
- Modify: `crates/carrick-dsr/src/probes.rs`
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-dsr-aarch64/src/direct_binding.rs`
- Modify: `crates/carrick-dsr-aarch64/src/gateway.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `scripts/dtrace/dsr-indirect.d`
- Modify: `scripts/perf/native_go_build.py`
- Create: `scripts/perf/native_go_build_screen.py`
- Create: `scripts/perf/test_native_go_build_screen.py`
- Create: `scripts/perf/direct_binding_mechanism.py`
- Create: `scripts/perf/test_direct_binding_mechanism.py`

**Interfaces:**

Append mirrored `DsrCacheEventKind` values:

```rust
DirectBindingEligible = 7,
DirectBindingPublish = 8,
DirectBindingCasLoss = 9,
DirectBindingClear = 10,
DirectBindingValidationFailure = 11,
DirectBindingUnitLoaded = 12,
```

Append mirrored, typed, nonzero reason enums:

```rust
enum DirectBindingClearReason {
    TargetInvalidation = 1,
    StaleWinnerRemoval = 2,
    ForkReset = 3,
    ExecReset = 4,
}

enum DirectBindingValidationReason {
    MissingEligibleRecord = 1,
    AmbiguousEligibleRecord = 2,
    MissMetadataMismatch = 3,
    OwnerMismatch = 4,
    AuthorityMismatch = 5,
    MappedCellFailure = 6,
}
```

The existing three generic probe fields have this complete ABI:

| Event | `guest_pc` | `generation` | `used_bytes` |
|---|---|---|---|
| `Eligible` | source PC | ordinal | cell VA, zero when disabled |
| `Publish` | source PC | ordinal | cell VA |
| `CasLoss` | source PC | ordinal | cell VA |
| `Clear` | cell VA | typed clear reason | target generation, zero for lifecycle reset |
| `ValidationFailure` | source PC | typed validation reason | cell VA, zero if unavailable |
| `UnitLoaded` | stable 64-bit unit-key digest | record count | binding-data bytes |

`Publish` fires only after a successful CAS. `Clear` fires only after an actual
non-null-to-null clear. “No event fires on a hit” means no new direct-binding
event fires; the existing `BlockHit` cache event remains valid. Sidecar V1's
22-word hit sequence and no-hit-event contract do not change.

The screen artifact schema is `carrick.native-go-build-screen.v1`.
The mechanism artifact schema is `carrick.direct-binding-mechanism.v1`.

- [ ] **Step 1: Add red enum and screen-policy tests**

Add Rust enum uniqueness/mirroring tests. Add Python tests:

```python
def test_palindromic_order_is_precursor_default_candidate_then_reverse()
def test_default_drift_over_five_percent_discards_the_screen()
def test_candidate_must_beat_c0_both_defaults_and_precursor()
def test_candidate_default_median_ratio_must_be_at_most_point_97()
def test_retention_bootstrap_is_seeded_and_reproducible()
def test_retention_requires_candidate_median_below_c0()
def test_variant_environment_removes_control_variables_for_default()
def test_profile_and_container_cache_cannot_leak_into_default()
def test_drift_formula_pairs_and_nearest_rank_are_exact()
def test_rejected_screen_is_written_atomically_with_samples()
```

- [ ] **Step 2: Add red fail-closed mechanism-summary tests**

`test_direct_binding_mechanism.py` supplies complete synthetic precursor and
candidate `DSRPROF1` streams, trace-summary JSONL, stdout/status artifacts, and
complete `NATIVEPERF1` records. It asserts:

```python
def test_complete_vector_and_eligible_collapse_are_published()
def test_missing_summary_drop_or_provenance_field_rejects_the_pair()
def test_bounded_interrupted_or_nonzero_status_rejects_the_pair()
def test_build_ok_must_be_an_exact_stdout_line()
def test_missing_gateway_translation_or_complete_nativeperf_rejects_the_pair()
def test_raw_dtrace_and_nativeperf_exit_vectors_must_reconcile()
def test_reclassification_into_indirect_or_other_gateway_exits_rejects()
def test_publications_are_bounded_per_pid_cell_and_globally()
def test_zero_vectors_are_explicit_and_unknown_kinds_reject()
def test_clear_and_validation_reasons_are_nonzero_and_known()
def test_active_source_after_cross_unit_hit_selects_exit_time_authority()
def test_duplicate_source_target_never_guesses_active_source()
```

Expose:

```python
def parse_trace(inputs: MechanismInputs) -> MechanismRun
def compare(precursor: MechanismRun, candidate: MechanismRun) -> dict[str, object]
```

`compare` publishes every Gate 2 field, calculates eligible direct-exit
collapse, and reconciles the complete DTrace and `NATIVEPERF1` evidence
planes. A rejected run is written atomically with `accepted=false`, every
available sample/counter, and exact rejection reasons before the tool exits
nonzero; no rejected or partial artifact can be mistaken for accepted evidence.

- [ ] **Step 3: Run focused tests and verify red**

```bash
cargo test -p carrick-observability \
  resolver_cache_and_dsr_cache_lifecycle_values_are_stable_and_unique
python3 -m unittest \
  scripts/perf/test_native_go_build_screen.py \
  scripts/perf/test_direct_binding_mechanism.py -v
```

Expected: missing enum variants and missing screen module.

- [ ] **Step 4: Emit only cold-path mechanism events**

Fire:

- `UnitLoaded` once per loaded unit with cell count and data bytes;
- `Eligible` once per direct resolver exit after eligibility is derived from
  the active source unit's predeclared manifest record and before target
  translation or its outcome is observed;
- `Publish`, `CasLoss`, `Clear`, and `ValidationFailure` only on those cold
  events.

At each cold `ResolveDirect` exit, classify `(source,target)` against an exact
index of loaded manifests before translation starts or its outcome is known.
The selected record must belong to the source authority active at that exact
gateway exit. Initial `PreparedEntry` identity is explicitly not authority:
a preceding cache/direct hit can install another unit and branch onward
without returning to Rust. The implementation may propagate exact authority
or resolve it from the manifest index, but it must satisfy these red tests:

- a direct/cache hit from unit A into unit B followed by a cold direct exit
  selects B's record;
- duplicate `(source,target)` records in loaded units are either disambiguated
  by exact exit-time authority or emit `AmbiguousEligibleRecord` and reject;
- missing authority/record emits its typed validation failure before any
  eligibility or publication event.

For disabled units, `Eligible` reports the exact record ordinal and a zero cell
address. For Sidecar V1, miss-carried ordinal and cell must match that same
record. This is cold diagnostic/validation authority, never a translated
hit-path lookup.

Extend `dsr-indirect.d` as follows:

- seed event kinds 7 through 12 in `BEGIN` with `sum(0)`, then count with
  `sum(1)`, so legitimate zero vectors are explicit;
- capture every `arg1 >= 7`; Python rejects values above 12;
- emit `binding-cell` keyed by `(pid,cell_va)` for nonzero eligible cells;
- emit `binding-publish-cell` keyed by `(pid,cell_va)`;
- emit `binding-clear-cell` keyed by `(pid,cell_va,reason)`;
- emit `binding-unit` keyed by
  `(pid,unit_id,record_count,binding_data_bytes)`;
- explicitly seed gateway and translation totals, while retaining all existing
  direct, indirect, outcome, pair, and source rows.

The publication invariant is per process:

```text
successful_publishes(pid, cell) <= 1 + successful_clears(pid, cell)
successful_publishes_total <= unique_process_cells + successful_clears_total
```

Forked COW processes reuse virtual addresses, so cell identity without `pid`
is invalid. `dsr-translate-begin` is reported as translation attempts, not
completed translations.

Use the built-in `--profile dsr-indirect` capture with `--trace-out` and
`--summary-jsonl`; do not use `--script`, because only profile mode supplies
authoritative completion, drop, and provenance metadata. Enable
`CARRICK_DSR_PROFILE=1` only for this diagnostic mechanism pair. Traced wall
time is never a performance result.

- [ ] **Step 5: Make benchmark samples accept explicit environment overlays**

Change:

```python
def run_sample(
    repo: pathlib.Path,
    engine: str,
    index: int,
    timeout_seconds: int,
    captured_output: pathlib.Path | None = None,
    environment_overlay: dict[str, str | None] | None = None,
) -> dict[str, object]:
```

A `None` value removes the key. Record the normalized overlay in every sample
row. Docker rejects Carrick-only overlays.

Define one complete performance-control set. Every variant removes each key
unless it deliberately sets it:

```text
CARRICK_DSR_ARTIFACT_SPIKE
CARRICK_DSR_SHARED_TRANSLATION
CARRICK_DSR_DIRECT_BINDINGS
CARRICK_DSR_PROFILE
CARRICK_DSR_ARTIFACT_REPORT
CARRICK_DSR_ARTIFACT_VALIDATE_FRESH
CARRICK_DSR_ARTIFACT_MIN_SOURCE_WORDS
CARRICK_DSR_KEEP_CONTAINER_CACHE
CARRICK_ARTIFACT
CARRICK_DISABLE_VDSO
CARRICK_VDSO_MODE
CARRICK_NATIVE_TRACE_SYSCALLS
CARRICK_NATIVE_REFUSE_POSTFORK_THREADS
CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS
```

Before every sample, reject inherited `CARRICK_*` variables outside the
explicit variant overlay and fixed harness allowlist. Record the effective
controlled environment. `CARRICK_RUN_ID` is generated by the harness, not
accepted from ambient state.

Make cleanup and provenance fail closed. A nonzero `carrick_cleanup` result is
fatal and its output is retained. Before every sample, reject foreign Carrick
or benchmark processes and any running Docker oracle container. Freeze clean
git SHA, binary SHA-256, host identity, image identity, and controlled
environment immediately before the sample, re-read them immediately after,
and reject any drift. Store that frozen provenance in each sample rather than
only once for the campaign.

- [ ] **Step 6: Implement the palindromic and retention runner**

Define exact variants:

```python
DEFAULT = {
    "CARRICK_DSR_ARTIFACT_SPIKE": None,
    "CARRICK_DSR_SHARED_TRANSLATION": None,
    "CARRICK_DSR_DIRECT_BINDINGS": None,
}
PRECURSOR = {
    "CARRICK_DSR_ARTIFACT_SPIKE": "1",
    "CARRICK_DSR_SHARED_TRANSLATION": "1",
    "CARRICK_DSR_DIRECT_BINDINGS": None,
}
CANDIDATE = {
    "CARRICK_DSR_ARTIFACT_SPIKE": "1",
    "CARRICK_DSR_SHARED_TRANSLATION": "1",
    "CARRICK_DSR_DIRECT_BINDINGS": "1",
}
PALINDROMIC = (
    "precursor", "default", "candidate",
    "candidate", "default", "precursor",
)
```

`--mode screen` executes `PALINDROMIC`. `--mode retention` alternates five
default and five candidate samples. The seeded bootstrap resamples each
five-sample group independently for 100,000 draws with seed 0, computes the
candidate/control median ratio for each draw, and records the one-sided 95%
nearest-rank value (sorted draw 95,000, one-indexed). Pin an exact fixture
value.

Default drift is exactly
`max(default_wall_ms) / min(default_wall_ms) <= 1.05`. Contemporaneous screen
pairs are candidate position 3 with default position 2 and candidate position
4 with default position 5. Candidate-versus-precursor uses the two medians.
Screen and retention artifacts are atomic. Drifted, contaminated, or otherwise
rejected campaigns retain every completed sample with `accepted=false`.
Retention additionally requires the candidate median to remain below official
`C0=19,375 ms`; the ratio and bootstrap gates compare against its five
contemporaneous controls.

- [ ] **Step 7: Implement the mechanism summarizer**

Parse only versioned `DSRPROF1` rows. Read completion, interruption, drops,
source/binary SHA, host, and image provenance from each profile-mode summary
JSONL. Require identical clean git SHA, binary SHA-256, host, image, and
controlled environment; `completion.complete=true`, `bounded=false`, zero
interruptions, zero DTrace drops, command status zero, and an exact `BUILD_OK`
stdout line. Bounded capture is truncated evidence and is always rejected,
though preserved atomically.

Reuse `native_compiler_budget.parse_nativeperf()` and `validate_profile()`.
Require exactly one supervisor record, reconciled child CPU, and the complete
`NATIVEPERF1` gateway-exit vector. Raw DTrace gateway/direct/indirect totals
must equal the corresponding `NATIVEPERF1` totals. Require both full
direct-binding event vectors, including explicit zeros.

Use integer arithmetic for the collapse/reclassification decision:

```text
S = precursor_eligible - candidate_eligible
D = precursor_direct - candidate_direct
G = precursor_gateway - candidate_gateway

precursor_eligible > 0
100 * candidate_eligible <= 5 * precursor_eligible
100 * D >= 95 * S
100 * G >= 95 * D
100 * max(0, candidate_indirect - precursor_indirect) <= 5 * D
100 * total_positive_non_direct_growth <= 5 * D
candidate_fault == 0
candidate_unsupported == 0
```

Publish indirect and every other gateway-kind delta separately. Write the
artifact atomically in both acceptance and rejection cases; only accepted
artifacts exit zero.

- [ ] **Step 8: Run tests and commit**

```bash
cargo test -p carrick-observability \
  resolver_cache_and_dsr_cache_lifecycle_values_are_stable_and_unique
cargo test -p carrick-dsr probes -- --nocapture
python3 -m unittest \
  scripts/perf/test_native_go_build.py \
  scripts/perf/test_native_go_build_screen.py \
  scripts/perf/test_direct_binding_mechanism.py -v
cargo fmt --all -- --check
git add \
  crates/carrick-dsr/src/probes.rs \
  crates/carrick-observability/src/probes.rs \
  crates/carrick-runtime/src/native_darwin.rs \
  crates/carrick-dsr-aarch64/src/direct_binding.rs \
  crates/carrick-dsr-aarch64/src/gateway.rs \
  crates/carrick-dsr-aarch64/src/translator.rs \
  scripts/dtrace/dsr-indirect.d \
  scripts/perf/native_go_build.py \
  scripts/perf/native_go_build_screen.py \
  scripts/perf/test_native_go_build_screen.py \
  scripts/perf/direct_binding_mechanism.py \
  scripts/perf/test_direct_binding_mechanism.py
git commit
```

Use subject `diagnostics(native): measure direct-binding collapse`. The body
states that events are cold-path-only, documents field meanings, and names the
palindromic drift and deterministic bootstrap rules.

---

### Task 15: Pass structural, mechanism, and signed-feasibility gates

**Files:**
- Modify after measurement:
  `docs/perf-results/native-wall-time-campaign.md`
- Modify after measurement: `handoff.md`

- [ ] **Step 1: Run the complete structural gate**

```bash
cargo test -p carrick-dsr-aarch64
cargo test -p carrick-native-darwin
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib \
  'native_darwin::dsr::oracle::direct_binding_'
cargo fmt --all -- --check
```

Expected: schema, AOT protections/relocations, process COW, atomic publication,
owner validation, generation invalidation, fork/exec, and recovery tests all
pass.

- [ ] **Step 2: Rebuild signed and verify the current source is in the binary**

```bash
just build
otool -l target/release/carrick | grep -A2 __dof_carrick
strings target/release/carrick | grep CARRICK_DSR_DIRECT_BINDINGS
```

Expected: signed build succeeds, DOF is present, and the feature marker is in
the binary.

- [ ] **Step 3: Run one untraced signed feasibility sample**

```bash
CARRICK_DSR_ARTIFACT_SPIKE=1 \
CARRICK_DSR_SHARED_TRANSLATION=1 \
CARRICK_DSR_DIRECT_BINDINGS=1 \
python3 scripts/perf/native_go_build.py \
  --engine carrick \
  --samples 1 \
  --output target/perf/direct-binding-feasibility-v1.json \
  --captured-output-dir target/perf/direct-binding-feasibility-v1-logs
```

Expected: `BUILD_OK`, no crash/hang/cache exhaustion, and the output marker
executes as an exact stdout line. The sample is accepted only when command
status and stamped cleanup are both zero, the pre/post provenance snapshot is
identical, and no foreign Carrick process or running Docker oracle is present.

- [ ] **Step 4: Collect disabled and enabled mechanism traces serially**

Run the precursor trace with direct bindings absent, clean up, then run the
candidate trace:

```bash
precursor_run_id="direct-binding-mechanism-off-v1-$$"
candidate_run_id="direct-binding-mechanism-on-v1-$$"
guest_script='set -eu; cd /tmp; rm -rf "gc-$CARRICK_RUN_ID"; printf "package main\nfunc main(){println(\"ok\")}\n" > h.go; GOCACHE="/tmp/gc-$CARRICK_RUN_ID" /usr/local/go/bin/go build -o h ./h.go; ./h; echo BUILD_OK'

CARRICK_RUN_ID="$precursor_run_id" \
CARRICK_DSR_ARTIFACT_SPIKE=1 \
CARRICK_DSR_SHARED_TRANSLATION=1 \
CARRICK_DSR_PROFILE=1 \
target/release/carrick trace \
  --profile dsr-indirect \
  --trace-out target/perf/direct-binding-mechanism-off-v1.trace \
  --summary-jsonl target/perf/direct-binding-mechanism-off-v1.summary.jsonl \
  -- run --exec-backend native \
  -e "CARRICK_RUN_ID=$precursor_run_id" \
  -w /tmp \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c "$guest_script" \
  >target/perf/direct-binding-mechanism-off-v1.stdout \
  2>target/perf/direct-binding-mechanism-off-v1.stderr
precursor_status=$?
printf '%s\n' "$precursor_status" \
  >target/perf/direct-binding-mechanism-off-v1.status
scripts/sudo/kill.sh "$precursor_run_id"

CARRICK_RUN_ID="$candidate_run_id" \
CARRICK_DSR_ARTIFACT_SPIKE=1 \
CARRICK_DSR_SHARED_TRANSLATION=1 \
CARRICK_DSR_DIRECT_BINDINGS=1 \
CARRICK_DSR_PROFILE=1 \
target/release/carrick trace \
  --profile dsr-indirect \
  --trace-out target/perf/direct-binding-mechanism-on-v1.trace \
  --summary-jsonl target/perf/direct-binding-mechanism-on-v1.summary.jsonl \
  -- run --exec-backend native \
  -e "CARRICK_RUN_ID=$candidate_run_id" \
  -w /tmp \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c "$guest_script" \
  >target/perf/direct-binding-mechanism-on-v1.stdout \
  2>target/perf/direct-binding-mechanism-on-v1.stderr
candidate_status=$?
printf '%s\n' "$candidate_status" \
  >target/perf/direct-binding-mechanism-on-v1.status
scripts/sudo/kill.sh "$candidate_run_id"

python3 scripts/perf/direct_binding_mechanism.py \
  --precursor-trace target/perf/direct-binding-mechanism-off-v1.trace \
  --precursor-summary target/perf/direct-binding-mechanism-off-v1.summary.jsonl \
  --precursor-profile target/perf/direct-binding-mechanism-off-v1.stderr \
  --precursor-stdout target/perf/direct-binding-mechanism-off-v1.stdout \
  --precursor-status target/perf/direct-binding-mechanism-off-v1.status \
  --candidate-trace target/perf/direct-binding-mechanism-on-v1.trace \
  --candidate-summary target/perf/direct-binding-mechanism-on-v1.summary.jsonl \
  --candidate-profile target/perf/direct-binding-mechanism-on-v1.stderr \
  --candidate-stdout target/perf/direct-binding-mechanism-on-v1.stdout \
  --candidate-status target/perf/direct-binding-mechanism-on-v1.status \
  --output target/perf/direct-binding-mechanism-v1.json
```

`carrick trace` auto-sudos; do not prefix either command with `sudo`. If a
command exits early, still write its numeric status and run its exact stamped
cleanup. Cleanup failure is fatal: retain the rejected artifacts and do not
start the next sample. Before each trace, require clean/frozen source and
binary provenance, no foreign Carrick or benchmark process, and no running
Docker oracle. Do not substitute `--script`: the profile-mode summary is the
authority for drops, completion, and provenance.

Record for both:

- sidecar-eligible and total direct resolver exits;
- the complete `NATIVEPERF1` exit vector, with indirect and every other
  gateway kind reported separately;
- raw-DTrace versus `NATIVEPERF1` gateway/direct/indirect reconciliation;
- total gateway entries and translation attempts;
- unique reached `(pid,cell)` pairs;
- publications, CAS losses, clears, and validation failures;
- per-`(pid,cell)` and global publication/clear invariants;
- child CPU.

Reject Variant 1 immediately unless the Step 7 integer collapse and
reclassification equations pass, candidate fault/unsupported exits are zero,
all six event kinds are explicit (including zero vectors), every kind/reason
is known, publications satisfy both process-scoped bounds, and every
validation failure has a typed nonzero reason. Nonzero command status, a
missing exact `BUILD_OK` line, bounded/interrupted capture, DTrace drops,
evidence-plane mismatch, provenance drift, or cleanup failure also rejects.

- [ ] **Step 5: Update the controller with exact evidence**

Add raw/summary/stdout/status/artifact paths and SHA-256 hashes, frozen
per-sample source/binary/host/image/environment provenance, the complete event
and exit vectors, reconciliation, process-cell bounds, and pass/reject decision
to the ledger and handoff. Preserve bounded or otherwise rejected captures as
`accepted=false`. Do not use traced elapsed time as a performance result.

- [ ] **Step 6: Commit the evidence checkpoint**

```bash
git add docs/perf-results/native-wall-time-campaign.md handoff.md
git commit
```

Use subject `docs(perf): record direct-binding mechanism gate`. The body
records the complete before/after vector and whether the 95% collapse gate
passed.

Stop here on a mechanism failure. Do not tune the 22-instruction path.

---

### Task 16: Run the palindromic wall screen and make the bounded decision

**Files:**
- Modify after measurement:
  `docs/perf-results/native-wall-time-campaign.md`
- Modify after measurement: `handoff.md`

- [ ] **Step 1: Confirm idle-host preflight and no stale processes**

```bash
python3 scripts/perf/native_go_build_screen.py --help
ps -eo pid=,args= | rg 'target/release/carrick|native-go-build' || true
docker ps --format '{{.ID}} {{.Image}} {{.Names}}'
```

Reap only known stamped run IDs with `scripts/sudo/kill.sh`; cleanup failure is
fatal. Reject a running Docker oracle, a foreign Carrick/benchmark process,
dirty source, or an unexpected ambient `CARRICK_*` variable before sampling.

- [ ] **Step 2: Run the exact two-triplet screen**

```bash
python3 scripts/perf/native_go_build_screen.py \
  --mode screen \
  --output target/perf/direct-binding-screen-v1.json \
  --captured-output-dir target/perf/direct-binding-screen-v1-logs
```

The artifact must contain:

```text
precursor, default, candidate, candidate, default, precursor
```

The runner freezes and rechecks clean git SHA, binary SHA-256, host, image, and
the fully controlled environment around every sample. If
`max(defaults)/min(defaults) > 1.05`, retain the atomic artifact and samples as
`accepted=false`; rerun only after identifying and recording the instability.

- [ ] **Step 3: Apply all four promotion rules**

Promote only when:

- both candidates are below 19,375 ms;
- candidate position 3 beats default position 2 and candidate position 4
  beats default position 5;
- candidate/default median ratio is at most 0.97;
- candidate median beats the precursor median;
- every sample has zero command and cleanup status, exact `BUILD_OK`, identical
  pre/post provenance, and no foreign Carrick or Docker-oracle contamination.

If resolver exits collapsed but the wall screen fails, collect one new
whole-tree `native-wall` profile. Authorize exactly one Variant 2 design
amendment only if that profile makes either code footprint/materialization or
descriptor-authority installation dominant. Otherwise reject H004 and return
to default-path attribution. Do not combine Variant 2 refinements.

- [ ] **Step 4: Record and commit the decision**

Update H004 to `RETAIN`, `REJECT`, or keep it `SPIKING` only when the
profile-authorized Variant 2 amendment is written. Record every sample,
controls, exact contemporaneous pairs, medians, ratios, the exact drift
formula, frozen provenance, artifact hashes, and the reason. A rejected screen
remains an atomic `accepted=false` evidence artifact.

```bash
git add docs/perf-results/native-wall-time-campaign.md handoff.md
git commit
```

Use subject `docs(perf): decide direct-binding wall screen`.

Stop on rejection. A rejected candidate remains opt-in and does not enter the
default path.

---

### Task 17: Run five-plus-five retention and retained-wave closure

**Files:**
- Modify after measurement:
  `docs/perf-results/native-wall-time-campaign.md`
- Modify after measurement: `handoff.md`

This task runs only after Task 16 promotes Variant 1.

- [ ] **Step 1: Run alternating five-control/five-candidate retention**

```bash
python3 scripts/perf/native_go_build_screen.py \
  --mode retention \
  --output target/perf/direct-binding-retention-v1.json \
  --captured-output-dir target/perf/direct-binding-retention-v1-logs
```

Retain only if candidate/control median ratio is at most 0.97 and the seeded
bootstrap one-sided nearest-rank 95% upper bound is below 1.0. The candidate
median must also remain below official `C0=19,375 ms`. Every sample must retain
identical pre/post clean git SHA, binary SHA-256, host, image, controlled
environment, exact `BUILD_OK`, zero command/cleanup status, and a clean
Carrick/Docker-oracle census.

- [ ] **Step 2: Refresh Docker and the campaign ratio serially**

After Carrick sampling completes:

```bash
python3 scripts/perf/native_go_build.py \
  --engine docker \
  --samples 5 \
  --output target/perf/direct-binding-docker-v1.json
```

Refresh `C`, `D`, and `R` only when each sample's frozen image, host, clean
source, binary, controlled-environment, cleanup, and idle-state provenance is
valid. Docker remains serial with Carrick and rejects Carrick-only overlays.
State explicitly how retained candidate `C` relates to both `C0=19,375 ms`
and the five current controls, and whether `R<=9.6202x` has been reached.

- [ ] **Step 3: Run guardrails and the signed native closure**

Run:

```bash
just conformance-native smoke --workers 4
just ci
otool -l target/release/carrick | grep -A2 __dof_carrick
```

Review and record:

- signed Go compile-and-run marker;
- `go-sync`;
- `cpython-threading`;
- `cpython-subprocess`;
- untraced Node V8 guardrail;
- untraced CPython guardrail;
- scoped cleanup with no stamped descendants remaining.

- [ ] **Step 4: Decide shipping state**

If all retention and correctness gates pass, enable the sidecar for immutable
shared units while leaving shared translation itself opt-in. If any gate fails,
leave `CARRICK_DSR_DIRECT_BINDINGS=1` experimental and record H004 `REJECT`.
The default non-shared native path must not change in either outcome.

- [ ] **Step 5: Update controller state and commit the retained wave**

Record exact sample arrays, medians, ratio, bootstrap seed/draw count/upper
bound, Docker provenance, guardrails, smoke count, `just ci`, binary hash, and
the next hypothesis selected from refreshed attribution.

```bash
git add \
  docs/perf-results/native-wall-time-campaign.md \
  handoff.md
git commit
```

Use subject `docs(perf): close direct-binding wave`. If code must change only
to enable a retained mode, make that code change in a preceding narrow commit
with the same signed demo, smoke, and `just ci` receipts.

---

## Plan Self-Review Checklist

- [ ] Every fixed architecture rule in the approved design maps to at least one
  implementation task and one proof.
- [ ] The serialized owner is `(TranslationUnitKey, ordinal)`; source/target is
  never used as sole ownership.
- [ ] Atomic publication is one release-CAS of a complete immutable descriptor.
- [ ] Variant 1 contains no global hit-path lookup and its listed hit sequence
  is exactly 22 instructions.
- [ ] Manifest, Mach-O, loader, cell, owner, authority, generation, fork, exec,
  and recovery failures all fail closed before wall measurement.
- [ ] Private target address reuse is impossible before descriptors drop.
- [ ] Shared target `dlclose` is impossible while descriptors retain leases.
- [ ] Fork clearing uses only fixed cells and preallocated bitmap words.
- [ ] Exec clears cells and descriptors before private JIT cursor reset.
- [ ] No hot-hit counter perturbs the mechanism.
- [ ] The mechanism gate and wall gate remain separate evidence planes.
- [ ] The palindromic screen compares precursor, default, and candidate in both
  directions and discards unstable defaults.
- [ ] Variant 2 requires a new measured profile and a one-refinement design
  amendment.
- [ ] All commits are narrow, use Conventional Commits, include verification in
  their bodies, and preserve unrelated worktree state.
