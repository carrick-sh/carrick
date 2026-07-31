# Native Performance M2: Translation Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every accepted `native-wall` sample resolve against one
process-image-epoch catalog containing the private JIT cache and every loaded
shared translation unit, then publish stable default/shared translation
ownership.

**Architecture:** Add typed translated-range events at the observability
boundary and one catalog publisher inside `ProcessTranslator`/`ProcessState`.
The publisher resets and replays once per process image, announces shared code
before it becomes reachable, and replays after fork. Replace the PID-only
`DSRPROF1` authority with a lifecycle-complete `DSRPROF2` stream keyed by a
kernel-derived process birth key, image generation, and runtime epoch. Validate
that stream in Rust before an offline analyzer performs exact range joins and
conservative symbol classification.

**Tech Stack:** Rust/serde/usdt, libdtrace D language, Python 3 standard
library, Darwin `proc`/`profile`/`syscall`/`mach_trap` providers, Carrick's
signed native AArch64 runner.

**Design authority:** `docs/superpowers/specs/2026-07-30-native-performance-evidence-control-plane-design.md`
sections 2, 6, 8, 9, and 10.

## Global Constraints

- M1 is landed and its untraced ABBA remains the only retention authority.
- Scope is Darwin/AArch64 native DSR.
- There is one process-wide translated-range publisher. The per-thread native
  loop and compatibility `host-jit-range` probe never own reset/replay.
- Range bounds are exact half-open executable extents, AArch64-aligned, and
  never rounded to host pages.
- Provider names encode reset/private/shared/ready. No raw action or kind
  integer crosses the USDT boundary.
- The translated-range USDT family carries at most five scalars. It omits PID
  from the provider payload; `native-wall.d` supplies the unchanged
  `DSRPROF2` PID field from DTrace's built-in `pid`. Existing compatibility
  probe ABIs remain unchanged.
- A shared range is announced before any block/link can make its code
  reachable. Failed unit loads announce nothing.
- Ranges remain immutable until exec/exit. Unload or address reuse stops this
  milestone and requires a new remove-transition design.
- Raw identity is
  `(pid, pr_start_tv.tv_sec, pr_start_tv.tv_usec)`; DTrace does not allocate a
  global process-instance counter.
- Offline publication assigns dense `process_instance` values only after
  lifecycle validation.
- Fork inheritance snapshots exact parent sequence/catalog frontiers. It never
  aliases the parent's eventual mutable catalog.
- `DSRPROF1` stays readable only as non-gating compatibility evidence.
  Mixed v1/v2 streams are invalid.
- `guest-image-base` is metadata, not an executable-range classifier. There is
  no `guest-native-executable` bucket.
- A Darwin leaf remains `darwin-userspace` even when its caller initiated
  translation work.
- Traced duration is diagnostic; only populations and shares are used here.
- No Linux kernel or other GPL implementation source is consulted.

---

## Task 1: Add the typed translated-range probe domain

**Files:**

- Modify: `crates/carrick-observability/Cargo.toml`
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-dsr/src/probes.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranslatedRangeKind {
    PrivateProcessCache,
    SharedUnit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslatedRangeEpoch(NonZeroU64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslatedRangeSequence(NonZeroU64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslatedUnitId(NonZeroU64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedRangeReset {
    epoch: TranslatedRangeEpoch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranslatedRangeAdd {
    Private(TranslatedPrivateRange),
    Shared(TranslatedSharedRange),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedPrivateRange {
    epoch: TranslatedRangeEpoch,
    sequence: TranslatedRangeSequence,
    range: Range<HostVa>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedSharedRange {
    epoch: TranslatedRangeEpoch,
    sequence: TranslatedRangeSequence,
    unit_id: TranslatedUnitId,
    range: Range<HostVa>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedRangeReady {
    epoch: TranslatedRangeEpoch,
    final_sequence: u64,
}
```

- [x] **Step 1: Add red domain and probe-shape tests**

In `probes.rs`, add tests for:

- zero epoch/sequence/unit identity;
- inverted, empty, or non-four-byte-aligned range;
- private range with a unit ID;
- shared range without a unit ID;
- construction through struct literals or a kind/payload mismatch;
- sequence raw round-trip only through named accessors;
- enum ordinal uniqueness; and
- exact one/four/five/two-scalar probe function signatures with no PID,
  generic raw action, or generic raw kind argument.

- [x] **Step 2: Run and prove red**

```bash
cargo test -p carrick-observability translated_range -- --nocapture
```

Expected: unresolved translated-range types and probe functions.

- [x] **Step 3: Implement named constructors at the DSR-neutral seam**

`carrick-dsr-aarch64` deliberately does not depend on
`carrick-observability`. Put the canonical typed event domain in
`carrick-dsr::probes`, which already forms the engine-neutral sink seam and can
use `HostVa`. Mirror the same validated domain at the observability boundary.
Constructors are:

```rust
impl TranslatedPrivateRange {
    pub fn private(
        epoch: TranslatedRangeEpoch,
        sequence: TranslatedRangeSequence,
        range: Range<HostVa>,
    ) -> Result<Self, TranslatedRangeError> {
        validate_translated_range(&range)?;
        Ok(Self {
            epoch,
            sequence,
            range,
        })
    }
}

impl TranslatedSharedRange {
    pub fn shared(
        epoch: TranslatedRangeEpoch,
        sequence: TranslatedRangeSequence,
        unit_id: TranslatedUnitId,
        range: Range<HostVa>,
    ) -> Result<Self, TranslatedRangeError> {
        validate_translated_range(&range)?;
        Ok(Self {
            epoch,
            sequence,
            range,
            unit_id,
        })
    }
}
```

`validate_translated_range` requires `start < end` and both endpoints divisible
by four. Fields remain private; named accessors expose epoch, sequence, range,
and unit ID. `TranslatedRangeAdd::kind()` exhaustively derives its ordinal from
the enum variant. Do not expose a general integer-to-kind constructor.

- [x] **Step 4: Add the four scalar USDT probes**

Declare and wrap exactly:

```rust
fn host__translated__range__reset(_: u64) {}
fn host__translated__private__range(_: u64, _: u64, _: u64, _: u64) {}
fn host__translated__shared__range(
    _: u64, _: u64, _: u64, _: u64, _: u64
) {}
fn host__translated__range__ready(_: u64, _: u64) {}
```

Public wrappers accept only `TranslatedRangeReset`,
`TranslatedPrivateRange`, `TranslatedSharedRange`, and
`TranslatedRangeReady`; they unwrap typed values at this boundary and never
accept or compute a PID. Mirror identical no-op signatures in the stub module.

The Rust provider can declare six scalar arguments, but live Darwin evidence
from real DSR probe sites shows that `arg5` is returned as constant zero. Five
scalars are the reliable limit, so `native-wall.d` uses the DTrace built-in
`pid` both to admit each event and to populate the unchanged `pid=P` field in
the raw `DSRPROF2` range records. Do not split a range across companion probes.
Existing `host-jit-range`, `dsr-cache-bounds`, and other compatibility ABIs
remain unchanged.

Extend `DsrProbeSink` with:

```rust
fn translated_range_reset(&self, event: TranslatedRangeReset);
fn translated_range_add(&self, event: TranslatedRangeAdd);
fn translated_range_ready(&self, event: TranslatedRangeReady);
```

Update the exhaustive runtime forwarder in `native_darwin.rs` to map the DSR
domain into the observability domain by exhaustively matching the private and
shared enum variants and calling the correspondingly typed USDT wrapper. This
is the only engine-to-USDT bridge; the translator never calls
`carrick_observability` directly, and the sink cannot pair a shared payload
with the private probe.

- [x] **Step 5: Run focused tests and commit**

```bash
cargo test -p carrick-observability translated_range -- --nocapture
cargo test -p carrick-dsr probes::tests -- --nocapture
just fmt
git diff --check
git add crates/carrick-observability/Cargo.toml \
  crates/carrick-observability/src/probes.rs \
  crates/carrick-dsr/src/probes.rs \
  crates/carrick-runtime/src/native_darwin.rs
git commit -m "feat(observability): type native translated ranges" -m \
"Give private and shared executable ranges distinct typed constructors and
wire probes. Validate exact half-open bounds, sequence identity, and unit
identity before any scalar reaches USDT.

Verified with observability domain and probe-signature tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 2: Own reset/add/ready in `ProcessTranslator`

**Files:**

- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-dsr-aarch64/src/direct_binding.rs`
- Modify: `crates/carrick-dsr-aarch64/src/gateway.rs`
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-dsr-aarch64/src/mapped_memory.rs`
- Modify: `crates/carrick-dsr/src/cache.rs`

**Interfaces:**

```rust
#[derive(Debug)]
struct TranslatedRangeCatalog {
    epoch: TranslatedRangeEpoch,
    next_sequence: u64,
    ready_sequence: Option<u64>,
    private: Range<HostVa>,
    shared: Vec<CatalogSharedRange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogSharedRange {
    sequence: TranslatedRangeSequence,
    unit_id: TranslatedUnitId,
    range: Range<HostVa>,
}

#[derive(Debug)]
struct PreparedSharedInstall {
    tid: i32,
    catalog_entry: CatalogSharedRange,
    blocks: Vec<PreparedSharedBlock>,
    sensitive_updates: Vec<((GuestVa, CodeGeneration), SensitiveMetadata)>,
    normalized_guest_ranges: Vec<(GuestVa, GuestVa)>,
    loaded_unit: LoadedSharedUnit,
    direct_binding: PreparedDirectBindingUnit,
    page_dependencies: PreparedPageBlockDependencies,
    executable_range: PreparedExecutableRange,
    direct_binding_probe: DirectBindingUnitLoadedProbe,
}

struct PreparedSharedBlock {
    key: (GuestVa, CodeGeneration),
    entry: CacheVa,
    published: PublishedBlock,
    fusion_site: Option<ExclusiveFusionSite>,
    guest_ranges: Vec<Range<GuestVa>>,
    authority: SharedBlockAuthority,
}

#[derive(Clone, Copy)]
struct DirectBindingUnitLoadedProbe {
    digest: u64,
    record_count: u64,
    data_bytes: u64,
}

pub(crate) struct PreparedDirectBindingUnit {
    unit_index: usize,
    owner: DirectBindingUnitOwner,
    cell_owners: Vec<DirectBindingOwner>,
    edge_records: Vec<PreparedDirectBindingEdge>,
}

pub(crate) struct PreparedDirectBindingEdge {
    key: (GuestVa, GuestVa),
    records: Vec<(usize, usize)>,
    existing: bool,
}

pub(crate) struct PreparedExecutableRange {
    node: Box<ExecutableRangeCatalogNode>,
}

pub struct PreparedPageBlockDependencies {
    pages: Vec<PreparedPageDependencyPage>,
}

struct PreparedPageDependencyPage {
    page: GuestVa,
    records: Vec<(GuestVa, CodeGeneration)>,
    existing: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedCatalogExecReset {
    next_epoch: TranslatedRangeEpoch,
}

impl TranslatedRangeCatalog {
    fn dormant(private: Range<HostVa>) -> Result<Self, DsrError>;
    fn activate_if_dormant(&mut self) -> Result<(), DsrError>;
    fn replay_after_fork(&mut self) -> Result<(), DsrError>;
    fn prepare_dormant_for_exec(&self) -> Result<PreparedCatalogExecReset, DsrError>;
    fn commit_dormant_for_exec(&mut self, prepared: PreparedCatalogExecReset);
    fn prepare_shared(
        &mut self,
        unit_id: TranslatedUnitId,
        range: Range<HostVa>,
    ) -> Result<CatalogSharedRange, DsrError>;
    fn commit_shared(&mut self, prepared: CatalogSharedRange);
    fn sequence_frontier(&self) -> u64;
}

impl ProcessState {
    fn prepare_shared_install(
        &mut self,
        tid: i32,
        memory: &NativeMappedMemory,
        unit: SharedLoadedTranslationUnit,
    ) -> Result<PreparedSharedInstall, DsrError>;
    fn commit_shared_install(&mut self, prepared: PreparedSharedInstall);
}

impl DirectBindingRegistry {
    fn prepare_loaded_unit(
        &mut self,
        unit: &SharedLoadedTranslationUnit,
    ) -> Result<PreparedDirectBindingUnit, DsrError>;
    fn commit_loaded_unit(&mut self, prepared: PreparedDirectBindingUnit) -> Option<usize>;
}

impl ExecutableRangeCatalog {
    fn prepare_prepend(
        &mut self,
        start: usize,
        end: usize,
    ) -> Result<PreparedExecutableRange, DsrError>;
    fn commit_prepend(&mut self, prepared: PreparedExecutableRange);
}

impl PageBlockDependencies {
    fn prepare_record_batch(
        &mut self,
        records: &[(GuestVa, GuestVa, CodeGeneration)],
    ) -> Result<PreparedPageBlockDependencies, CacheError>;
    fn commit_record_batch(&mut self, prepared: PreparedPageBlockDependencies);
}
```

- [x] **Step 1: Add red publisher-state tests**

Cover:

- construction is dormant and emits nothing;
- first activation emits reset, private sequence 1, ready final sequence 1;
- repeated activation for the same active image is idempotent;
- two shared units emit sequences 2 and 3 exactly once;
- duplicate unit identity with equal or different bounds;
- overlap between private/shared and between two shared ranges;
- duplicate guest starts, overlapping cache extents, empty/unaligned PC maps,
  repeated-but-valid guest PCs, and nested/overlapping guest ranges that are
  not normalized to one union;
- distinct block starts that converge on one sensitive terminal PC, including
  equal exit semantics with equal/different fusion metadata and a conflicting
  sensitive-exit negative control;
- sequence overflow;
- failure in every validation, vector-reserve, block-metadata, direct-binding,
  retention, and executable-range preparation stage leaves the catalog,
  executable-range head, retained units, and all guest/cache lookup indexes
  unchanged (lookup counters and `shared_unit_segments_consulted` may record the
  failed attempt, but can never make code reachable);
- `commit_shared_install` has no `Result`, performs no validation or recoverable
  operation, emits before logical reachability, and makes every prepared
  structure visible before the exclusive guard is released;
- replay reproduces the identical ordered catalog under a fresh nonzero epoch;
- two sibling `ThreadTranslator`s do not duplicate replay;
- child replay occurs within `ProcessTranslator::after_fork_child`, after its
  inherited direct-binding/cache repair and before the method returns; and
- compatibility `dsr_cache_bounds` may still fire but is not the catalog
  authority.

Use an injected recorder in tests rather than enabling DTrace. Add
thread-local, test-only failpoints for each preparation stage plus a logical
state snapshot. A successful `try_reserve` may change capacity, but no
failpoint may change a lookup result, catalog frontier, retained unit, or
executable-range head.

- [x] **Step 2: Run and prove red**

```bash
cargo test -p carrick-dsr-aarch64 translated_range_catalog -- --nocapture
```

- [x] **Step 3: Construct dormant and activate only at the PONR handoff**

Add `translated_ranges: TranslatedRangeCatalog` to `ProcessState`. Build it
from `cache.host_range()` in `ProcessTranslator::new_with_host`, but emit
nothing there. `mapped_memory.rs` constructs an exec replacement translator
during pre-point-of-no-return preparation; publication there would reset the
still-live old image.

Activate the publisher at the initial active translator acquisition in
`native_darwin.rs`, immediately before the native loop can execute translated
code. Initial publication is:

```text
Reset(epoch)
Private(epoch, sequence=1, cache.start, cache.end)
Ready(epoch, final_sequence=1)
```

Keep `probes::dsr_cache_bounds` as compatibility only. Remove
`probes::host_jit_range` ownership from `native_darwin.rs`; if retained for
old scripts, it announces only compatibility state and never controls replay.

- [x] **Step 4: Give shared units a stable typed identity**

Reuse `direct_binding_unit_digest(&unit.manifest.key)` as the stable source,
convert it through `TranslatedUnitId::new`, and reject zero instead of
synthesizing a replacement. Store that ID in `LoadedSharedUnit`.

- [x] **Step 5: Prepare every fallible mutation, then commit publication before
reachability**

Keep shared-unit installation under the exclusive `ProcessState` write guard.
The exact shared extent is:

```rust
let range = HostVa(unit.base)
    ..HostVa(
        unit.base
            .checked_add(unit.manifest.code_len as usize)
            .ok_or_else(|| DsrError::CachePolicy(
                "shared translation range overflow".to_owned()
            ))?,
    );
```

`prepare_shared_install` completes manifest/range validation, duplicate and
overlap checks, sequence assignment, every fallible
`block.template.take_runtime_metadata`/sensitive-block planning operation, and
all vector `try_reserve` calls without changing any logical lookup result or
catalog frontier. `TranslatedRangeCatalog::prepare_shared` takes `&mut self`
because reserving its shared-entry vector is part of preparation; a successful
reserve may change capacity but not catalog contents or sequence state. The
install preparation takes `&NativeMappedMemory` because generation
observations and `plan_block_with_segments` cannot be prepared correctly
without the active address space. It builds every `PublishedBlock`,
fusion record, exact guest range, and `SharedBlockAuthority` in
`PreparedSharedBlock`; it aggregates sensitive-terminal metadata separately
by sensitive guest PC and dependency tuples into one prepared page-dependency
batch.

Block-start identity and sensitive-terminal identity are different domains
even though both currently have the raw shape
`(GuestVa, CodeGeneration)`. Do not compare an incoming block-start key
against the `sensitive` map. Distinct translated block starts may legitimately
converge on the same sensitive instruction. For one sensitive key, require
every planned `SensitiveExit` to be identical. Merge equal fusion metadata as
itself; if fusion metadata is absent or differs across owners, retain
`fusion=None` as the deterministic conservative profiling value. Apply the
same merge against already installed sensitive metadata. A conflicting
`SensitiveExit` is a real policy error and leaves all logical state unchanged.
Preparation emits one normalized `sensitive_updates` entry per sensitive key;
commit inserts those prepared entries without validation.

Do not derive guest extent from `block.template.source_words()`: production
packing deliberately clears that field in `into_runtime_metadata_only`.
Instead, derive exact four-byte guest instruction intervals from the taken
`PcMapEntry` list. Cache offsets must be aligned, in bounds, and strictly
increasing. Guest PCs must be aligned and overflow-safe, but repeated guest PCs
are valid for multiword lowering: sort and deduplicate them before interval
construction. Require that `guest_start` is represented, then merge adjacent
entries into per-block ranges. Prepare a new normalized union containing both
the existing and new guest intervals so `shared_guest_ranges` remains sorted
and non-overlapping; commit replaces the old vector with that complete
preallocated union rather than appending into the destination. A single
min/max interval is invalid when the map is non-contiguous.

Strengthen `TranslationUnitManifest::validate_ranges` to reject duplicate
guest starts and overlapping/duplicate cache extents before any preparation.
The store is a trait boundary, so clean output from the built-in packer is not
enough evidence.

Split the current mutating helpers at their real transaction boundaries:

- `DirectBindingRegistry::prepare_loaded_unit` takes `&mut self`, validates the
  manifest and cell
  ownership and builds the unit owner, per-cell owners, edge records, bitmap,
  and retained source lease without inserting them. The prepared
  `unit_index` must equal the registry length rechecked under the same
  `ProcessState` guard. `commit_loaded_unit` only moves those values into the
  registry and returns the already determined optional index.
  Preparation groups records by edge: new-edge vectors are built completely,
  and existing-edge vectors receive `try_reserve` capacity before commit.
  A flat edge list does not make extension of existing vectors allocation-free.
- `ExecutableRangeCatalog::prepare_prepend` validates the range, reserves one
  stable-node slot with `try_reserve`, and allocates the boxed node while the
  old head remains published. `commit_prepend` links that node to the current
  head, retains it, and performs the release-store.
- `PageBlockDependencies::prepare_record_batch` groups records by page, removes
  duplicates against both existing state and the prepared batch, fallibly
  reserves every existing per-page vector, and fully builds vectors for new
  pages. `commit_record_batch` only extends reserved vectors or moves a complete
  vector into the `BTreeMap`; it does not call `Vec::push` on an unreserved
  destination.
- Reserve `published`, `shared_published_index`, `shared_guest_ranges`, and
  `loaded_shared_units` for the whole batch, plus the shared catalog vector in
  `TranslatedRangeCatalog::prepare_shared`. Preflight incoming block-start
  keys against `blocks` and `shared_blocks`, plus duplicates within the
  prepared batch. Do not use the sensitive-terminal map as a block-start
  collision index; normalize it through the merge rule above. `BTreeMap` has
  no stable fallible-reserve API: its eventual inserts may terminate the
  process on allocator failure, but cannot return a recoverable error and
  resume guest execution.

Every recoverable preparation failure therefore returns with the catalog,
reachable indexes, retained-unit set, and executable-range head intact.
Diagnostic lookup counters and the consulted-segment miss cache are explicitly
outside this transaction: they may record that a load was attempted, but they
do not provide a cache entry or executable authority.

Once preparation succeeds, `commit_shared_install` is deliberately infallible:
it first appends/emits the authoritative typed catalog entry, then installs the
already prepared direct-binding owner, retained stable-pointer owners, block
indexes, normalized sensitive updates, page dependencies, normalized
guest-range union, and unit retention. The executable-range node is linked and
release-published last, after every other logical structure is visible. It
returns no `Result`, validates nothing, and is called while the exclusive
`ProcessState` write guard is held.
Capacity-backed vector inserts are allocation-free; standard-library tree
inserts have only the process-terminating allocator-failure case described
above. Only after all logical structures are committed may the guard release
and guest execution resume. An unexpected panic or allocator termination
prevents natural trace completion, so it cannot publish accepted evidence. A
recoverable failed load publishes nothing; every reachable unit was announced
first.

`PreparedSharedInstall` carries the originating `tid`; the compatibility
`DirectBindingUnitLoaded` event uses that exact value after the prepared
structures are committed. Do not substitute zero or add a second fallible
lookup at commit time. A `_with_recorder` commit seam proves publication order
without touching the process-global `OnceLock` probe sink.

- [x] **Step 6: Replay after fork**

In `ThreadTranslator::after_fork_child`, preserve this order:

```rust
self.process.after_fork_child()?;
self.block_cache.clear();
```

`ProcessTranslator::after_fork_child` itself advances to a fresh local epoch
and performs synchronous reset/replay/ready after cache repair and before it
returns. This is an explicit `replay_after_fork`, not the idempotent initial
activation method. Propagate epoch-overflow failure through
`ProcessTranslator::after_fork_child`, `ThreadTranslator::after_fork_child`,
and the runtime child-resume path; do not wrap, saturate, or panic. Before
emitting anything, validate that the inherited catalog is active, its ready
frontier covers exactly `1..=sequence_frontier`, and every retained shared
entry is replayable. Under the same process writer, emit the fresh
reset/private/shared/ready sequence and re-key retained shared-range event
owners so a grandchild can replay the same unit IDs and ranges. Preserve the
catalog contents and next sequence across replay. Clear the thread-local block
cache only after successful process replay.

The runtime child repair helper returns the error before any
`ChildTranslatorRebuild`, `fork_post`, syscall-completion, stack-mutation, or
guest-resume event. If a `Resume` service span has already opened, its RAII end
is exactly one `Aborted`; never report a completed resume after replay failure.
Tests must cover the ordered success path, checked overflow, unchanged failure
state, sibling idempotence, real COW isolation under a bounded supervisor, and
the runtime failure-event boundary.

- [ ] **Step 7: Activate replacement catalogs only after successful exec**

Do not compose inherited-translator exec from one fallible destructive reset.
Prepare the transition while the old image remains authoritative and under the
`ProcessState` writer:

- validate the reset token without consuming it;
- count every live private-JIT descriptor lease and prove the registry owns the
  exact process-epoch set using `Arc::ptr_eq`;
- reject external or stale leases before clearing a cell; and
- only when the replacement reuses the retiring translator, require an active
  catalog and precompute its checked next epoch and dormant state.

Finish that preparation immediately before the mapped-memory PONR is armed.
After PONR, consume the already validated token and commit the optional catalog
transition infallibly, then perform the existing destructive binding, cache,
and shared-state clear without another recoverable error or assertion. The
catalog commit retains its private range, installs the prepared epoch, clears
shared entries, resets the sequence frontier, becomes dormant, and emits
nothing. A fresh replacement translator stays dormant without advancing or
overflow-checking the retiring catalog.

The prepared-reset half is accepted in `44c3bd6c`, `a6b1d9d6`, and
`5889fa17`. The prepared authority retains both the `ProcessState` writer and
an immutable borrow of the exact surviving thread across
`arm_prepared_adoptions`, so neither the lease/catalog census nor token
generation can change before its infallible commit. Token mint reserves both
generation advances needed by a successful exec; `MAX-1` therefore rejects
before cache mutation or PONR. The composed fork/inherited-exec fixture runs
real child repair and proves catalog epochs `1 -> 2 -> 3` under bounded,
process-group-contained supervision. Independent final re-review is clean.

At the successful active handoff in `native_darwin.rs`, activate the selected
translator exactly once, then republish host image base/catalog and guest
compatibility metadata under the new image/runtime key. Production self-reexec
must prove the same post-success metadata state as the inherited-translator
test seam. Ignore the current transition-time pre-success announcements in
`DSRPROF2`.

- [ ] **Step 8: Run focused tests and commit**

```bash
cargo test -p carrick-dsr-aarch64 translated_range -- --nocapture
cargo test -p carrick-dsr-aarch64 shared_unit -- --nocapture
just fmt
git diff --check
git add crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-dsr-aarch64/src/direct_binding.rs \
  crates/carrick-dsr-aarch64/src/gateway.rs \
  crates/carrick-dsr-aarch64/src/shared_cache.rs \
  crates/carrick-dsr-aarch64/src/mapped_memory.rs \
  crates/carrick-runtime/src/native_darwin.rs
git commit -m "feat(dsr): publish process-wide translated catalogs" -m \
"Move private/shared executable-range ownership into the process translator,
publish shared units before reachability, and replay one ordered catalog after
fork. Keep failed unit loads invisible to tracing.

Verified with catalog lifecycle, overlap, staging, sibling, and fork tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 3: Define the `DSRPROF2` lifecycle and fork-frontier grammar

**Files:**

- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Create: `scripts/dtrace/native-birth-qualify.d`
- Create: `scripts/dtrace/native-terminal-qualify.d`
- Modify: `scripts/dtrace/native-wall.d`
- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`

**Raw identity:**

```rust
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProcessBirthKey {
    pid: u32,
    start_sec: i64,
    start_usec: i32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawProcessImageKey {
    birth: ProcessBirthKey,
    image_generation: u64,
    runtime_epoch: u64,
}
```

**Required raw records:**

```text
DSRPROF2|header|profile=native-wall|raw_schema=carrick.dsrprof.raw.v2|os_build=B|program_sha256=H|birth_qualification_sha256=Q|terminal_qualification_sha256=T|wall_hz=197|cpu_hz=499
DSRPROF2|target-birth|pid=P|start_sec=S|start_usec=U|image=1|epoch=0
DSRPROF2|process-create|child_pid=CP|child_sec=CS|child_usec=CU|child_image=1|child_epoch=0|parent_pid=PP|parent_sec=PS|parent_usec=PU|parent_image=I|parent_epoch=E
DSRPROF2|fork-inherit|child_pid=CP|child_sec=CS|child_usec=CU|parent_pid=PP|parent_sec=PS|parent_usec=PU|parent_image=I|parent_epoch=E|range_frontier=R|mapping_frontier=M
DSRPROF2|exec-attempt|pid=P|start_sec=S|start_usec=U|image=I|epoch=E
DSRPROF2|exec-failure|pid=P|start_sec=S|start_usec=U|image=I|epoch=E
DSRPROF2|exec-success|pid=P|start_sec=S|start_usec=U|retired_image=I|retired_epoch=E|new_image=J|new_epoch=0
DSRPROF2|range-reset|pid=P|start_sec=S|start_usec=U|image=I|epoch=E
DSRPROF2|range-private|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|sequence=Q|start=A|end=B
DSRPROF2|range-shared|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|sequence=Q|unit_id=D|start=A|end=B
DSRPROF2|range-ready|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|final_sequence=Q
DSRPROF2|host-image-base|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|base=A
DSRPROF2|host-image-catalog|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|payload=J
DSRPROF2|guest-image-base|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|base=A
DSRPROF2|cpu-user|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|pc=A|count=N
DSRPROF2|kernel-enter|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|tid=TID|provider=V|function=F|class=C|timestamp_ns=T
DSRPROF2|kernel-return|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|tid=TID|provider=V|function=F|class=C|timestamp_ns=T
DSRPROF2|kernel-terminal-close|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|tid=TID|provider=V|function=F|class=C|scope=G|timestamp_ns=T
DSRPROF2|cpu-kernel|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|class=C|pc=A|count=N
DSRPROF2|offcpu-block|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|tid=TID|episode=O|kind=K|pc=A|timestamp_ns=T
DSRPROF2|offcpu-wake|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|tid=TID|episode=O|observed_pid=OP|observed_sec=OS|observed_usec=OU|observed_image=OI|observed_epoch=OE|timestamp_ns=T
DSRPROF2|offcpu|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|kind=K|pc=A|count=N|total_ns=T
DSRSTACK2|begin|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|kind=K|count=N|total_ns=T
DSRSTACK2 frame body: one or more nonempty `%k`/`%u` lines preserved verbatim
DSRSTACK2|end
DSRPROF2|process-exit|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|reason=R
DSRPROF2|wall-state|kind=K|count=N
DSRPROF2|complete|profile=native-wall|bounded=0|target_exit_reason=R|live_at_end=0
```

Numeric fields are unsigned decimal except `start_sec`/`start_usec`, which use
their checked signed widths, and addresses, SHA-256 digests, and JSON payloads,
which retain their existing validated encodings. `provider` is exactly
`syscall` or `mach_trap`; `function` is the provider's qualified probe
function encoded with the existing percent-escaped token codec. The parser
recognizes exactly the records above; missing, duplicate, extra, reordered
block delimiters, unknown fields, and unknown `DSRPROF2` or `DSRSTACK2` tags
are fatal. CPU, kernel-transition, off-CPU-transition, stack, image, range, and
per-process lifecycle records carry a complete birth/image/runtime key.
`wall-state`, `header`, and `complete` are deliberately profile/process-tree
aggregates and carry no false single-process key.

The header's raw-schema ID, D-program hash, birth-qualification hash, and
terminal-qualification hash are required closed fields, not prose-only
metadata. The capture receipt retains both qualification receipts and their
raw inputs, and hashes them again; the parser verifies the header values
against that receipt before the stream can become gating-eligible.

`kernel-enter` pushes `(provider,function,class,key)` on a per-`tid` stack.
`kernel-return` must match and pop the exact top. `scope` is exactly `thread`
or `process`; a qualified non-returning entry closes only through
`kernel-terminal-close` with the receipt-qualified scope and corresponding
`proc:::lwp-exit` or `proc:::exit` observation. Every other unmatched return,
nested mismatch, key/scope change, or open stack at process exit is fatal.
`offcpu-block` opens a monotonically increasing per-thread episode.
`offcpu-wake` closes that exact episode and carries the currently observed
process-image key independently; the parser requires its `observed_*` key to
equal the latched key. Summary `cpu-kernel`/`offcpu` rows must reconcile to the
validated transition populations and durations. The raw transition rows are
retained even though the published v2 summary is aggregated.

M2 emits `mapping_frontier=0` and accepts only zero because the typed
host-backing catalog lands in M3. The field is present now so M3 extends one
fork grammar rather than creating another identity transition.

- [ ] **Step 1: Add red parser fixtures**

Add literal v2 fixtures for a target, child, fork inheritance, exec failure,
exec success, private range, two shared ranges, later addition, and natural
exit. Corrupt each independently:

- changed birth key without a PID lifecycle transition;
- duplicate create or retired-key reuse;
- sample before target birth;
- zero image generation;
- add before reset;
- duplicate/gapped/non-monotonic sequence;
- overlapping range;
- ready frontier mismatch;
- shared addition after a sequence gap;
- child frontier missing in parent;
- child inheriting the parent's later addition;
- off-CPU wake under another image key;
- kernel return with the wrong provider/function/class or another image key;
- nested kernel return out of order, terminal-close of a returning call, or
  an open kernel stack at process exit;
- duplicate/missing off-CPU episode or aggregate/transition disagreement;
- host catalog retained after successful exec;
- native process epoch missing `Ready`;
- mixed `DSRPROF1`/`DSRPROF2`; and
- unknown v2 tag, overflow, drops, or live process at completion.

- [ ] **Step 2: Run and prove red**

```bash
cargo test -p carrick-cli --test trace_profile dsrprof2 -- --nocapture
```

- [ ] **Step 3: Add launch-time process-birth qualification**

Add hidden commands
`carrick __native-profile-birth-fixture --hold-ms 500` and
`carrick __native-profile-terminal-fixture --mode {thread,process}`. The birth
fixture uses
`libc::pipe`, `libc::fork`, a parent/child handshake, and `waitpid`; the parent
and child both remain alive long enough for provider observation and print only
`BIRTH_FIXTURE_OK` after clean child exit. It is absent from normal help.

Before starting the requested victim, `carrick trace --profile native-wall`
runs `native-birth-qualify.d` against that hidden command through the same
libdtrace launch path. The qualifier emits a machine-readable receipt only when
two observations of the parent key are identical, the `proc:::create` child key
equals the child-context observation, parent and child keys differ, the marker
is present, exit is natural, and consumer-side drop counters are zero. The
actual capture starts only after that receipt validates, and its header embeds
the receipt SHA-256. This is orchestration in `commands.rs`; the D program does
not pretend it can spawn an internal fixture.

Use the terminal fixture plus the same standalone libdtrace consumer to
qualify exact non-returning entry spellings and closure scope on this OS build.
Do not hard-code Mach trap names: the qualified Mach set may be empty. For each
candidate `syscall`/`mach_trap` entry observed during controlled thread and
process termination, require fixture markers, the corresponding
`proc:::lwp-exit` or `proc:::exit`, no matching return, and zero consumer
drops. The resulting closed `(provider,function,scope)` set and receipt hash
are passed to `native-wall.d`; any unqualified purported terminal remains an
unmatched entry and fails the capture. Tests include thread- versus
process-scope mismatch, qualified syscall termination, an empty Mach set, a
returning-call negative control, and provider-list drift.

In the actual `native-wall.d`, `BEGIN` emits no sample. At the first
target-context probe, read `curpsinfo->pr_start.tv_sec`/`tv_usec`; at
`proc:::create`, read the child from `args[0]`.

Do not create a global D variable with `++` as a process ID. `proc:::create`
stores the exact parent/child relation and current translated/mapping
frontiers.

- [ ] **Step 4: Implement exec and off-CPU lifecycle**

Emit the thread-keyed `kernel-enter`, `kernel-return`,
`kernel-terminal-close`, `offcpu-block`, and `offcpu-wake` records above at
their state transitions; do not infer them later from aggregates.

An exec attempt disarms image-owned attribution. `exec-failure` restores the
same generation and epoch. `exec-success` names both the retired key and new
generation/epoch-zero key, retires the host catalog and runtime epoch, and
waits for new announcements. Latch the complete raw key at off-CPU begin; a
wake under another key invalidates the episode.

- [ ] **Step 5: Validate and assign dense presentation identity**

`trace_profile.rs` validates the entire raw graph, then assigns:

- target `process_instance=1`;
- admitted child keys sorted by `(start_sec, start_usec, pid)` to `2..N`; and
- published keys
  `(process_instance, image_generation, runtime_epoch)`.

Materialize a child's inherited catalog by copying exactly the parent prefix
through `range_frontier` and `mapping_frontier`. Never hold a reference to the
parent's mutable vectors.

- [ ] **Step 6: Publish v2 and preserve v1 compatibility**

Accepted v2 JSON uses schema `carrick.dsr-profile.v2`. V1 parsing remains
available behind a `gating_eligible=false` field and cannot satisfy M2/M3/M4.
Reject mixed streams before publication.

- [ ] **Step 7: Run focused tests and commit**

```bash
cargo test -p carrick-cli --test trace_profile dsrprof2 -- --nocapture
cargo test -p carrick-cli trace_profile -- --nocapture
just fmt
git diff --check
git add crates/carrick-cli/src/args.rs \
  crates/carrick-cli/src/commands.rs \
  scripts/dtrace/native-birth-qualify.d \
  scripts/dtrace/native-terminal-qualify.d \
  scripts/dtrace/native-wall.d \
  crates/carrick-cli/src/trace_profile.rs \
  crates/carrick-cli/tests/trace_profile.rs
git commit -m "diagnostics(trace): key native profiles by process birth" -m \
"Replace PID-only gating evidence with a birth-keyed image/runtime lifecycle,
exact fork frontiers, and contiguous translated-range epochs. Keep old profile
artifacts readable but ineligible for decisions.

Verified with valid and deliberately corrupted DSRPROF2 lifecycle fixtures.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 4: Partition kernel state and publish complete v2 profiles

**Files:**

- Modify: `scripts/dtrace/native-wall.d`
- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`

- [ ] **Step 1: Add red balanced-kernel fixtures**

Cover nested/overlapping syscall and mach-trap entry, return without entry,
unclosed state, a nonterminal call incorrectly closed by exit, each explicitly
qualified terminal thread/process exit, an OS-build receipt with no Mach
terminal, named syscall preservation,
kernel sample inside each state, and a kernel sample outside both. Assert one
of `kernel-named-syscall`, `kernel-mach-trap`, or `kernel-non-syscall` for
every kernel sample.

- [ ] **Step 2: Run and prove red**

```bash
cargo test -p carrick-cli --test trace_profile native_wall_kernel_state_v2
```

- [ ] **Step 3: Fold balanced entry state into `native-wall.d`**

Track a typed stack of `(provider, probefunc)` entries per raw
thread/image key, not an unlabelled depth. The only exit-closable names are the
exact `(provider, probefunc)` pairs in the successful launch-time terminal
qualification receipt from Task 3. Do not synthesize spellings or require a
nonempty Mach set.

Tests enumerate captured qualification rows, including any observed
`syscall::exit`, `syscall::bsdthread_terminate`, or
`syscall::terminate_with_payload` spelling, without assuming all are present
on every OS build. Simultaneous syscall and mach-trap state invalidates the
profile. At each kernel-on-CPU sample, increment exactly one state and preserve
the raw kernel PC/stack population. A return must match the top provider/name.
Thread/process exit emits the explicit scoped terminal-close row and may close
only a matching receipt-qualified non-returning entry at that scope; every
other missing return remains an acceptance failure.

- [ ] **Step 4: Enforce complete v2 acceptance**

Require natural target completion, live set zero, all drop counts zero, at
least 99% wall-state coverage, at least 85% resolved CPU, at least 80% top
blocking-stack coverage, every DSR epoch ready, contiguous range sequences,
and exact kernel-state population equality. `commands.rs` atomically publishes
no accepted summary when any invariant fails.

- [ ] **Step 5: Run focused tests and commit**

```bash
cargo test -p carrick-cli --test trace_profile native_wall -- --nocapture
cargo test -p carrick-cli trace_profile -- --nocapture
just fmt
git diff --check
git add scripts/dtrace/native-wall.d \
  crates/carrick-cli/src/trace_profile.rs \
  crates/carrick-cli/src/commands.rs \
  crates/carrick-cli/tests/trace_profile.rs
git commit -m "diagnostics(trace): reconcile native wall profile v2" -m \
"Partition kernel samples with balanced syscall and mach-trap state and make
all CPU, off-CPU, image, stack, and catalog records share one validated
process-image identity.

Verified with kernel-state, lifecycle, coverage, and completion fixtures.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 5: Classify exact translated ownership conservatively

**Files:**

- Create: `scripts/perf/native_wall_symbol_rules_v2.json`
- Modify: `scripts/perf/native_wall_attribution.py`
- Modify: `scripts/perf/test_native_wall_attribution.py`
- Modify: `scripts/dtrace/native-jit-aware-profile.d`

**Output schema:** `carrick.native-wall-attribution.v2`

**Receipt-bound input:**

```python
@dataclasses.dataclass(frozen=True)
class VerifiedWallInput:
    capture_receipt: pathlib.Path
    raw: pathlib.Path
    summary: pathlib.Path
    stdout: pathlib.Path
    receipt_sha256: str
    raw_sha256: str
    summary_sha256: str
    stdout_sha256: str

def load_verified_wall_input(
    capture_receipt: pathlib.Path,
) -> VerifiedWallInput: ...
```

The normal CLI accepts exactly two `--capture-receipt` arguments and derives
its raw, summary, stdout, arm, overlay, and qualification inputs from those
receipts. A test-only fixture entry point may parse in-memory summaries, but
there is no gating CLI mode that accepts an unbound `--profile`.

**Top-level taxonomy, in order:**

```text
private-translated
shared-translated
translation-build
translation-publication
gateway-prepare
gateway-resolve
dispatch
process-setup
other-carrick
darwin-userspace
kernel-named-syscall
kernel-mach-trap
kernel-non-syscall
unresolved
```

- [ ] **Step 1: Add red two-shared-unit and taxonomy fixtures**

Create a profile with private `[0x1000,0x2000)`, shared unit 7
`[0x4000,0x5000)`, and shared unit 9 `[0x8000,0x9000)`. Assert boundary PCs,
both shared identities, a Darwin `memmove` leaf called by publication, each
Carrick symbol class, all three kernel classes, and unresolved. Assert one and
only one category per sample.

Add rule-table tests that enumerate every fixture symbol, reject a symbol
matching multiple rules, reject unknown category names, and prove exact range
joins run before symbol rules.

Add receipt-binding tests that reject a changed raw stream, summary, stdout,
arm receipt, overlay, birth qualification, terminal qualification, or embedded
path after the capture receipt is written. The analyzed artifact records both
capture-receipt hashes plus the verified raw/summary/stdout hashes; reloading
the analysis repeats those bindings rather than trusting embedded summaries.

- [ ] **Step 2: Run and prove red**

```bash
python3 -m unittest scripts/perf/test_native_wall_attribution.py -v
```

- [ ] **Step 3: Freeze the ordered symbol-rule schema**

Use:

```json
{
  "schema": "carrick.native-wall-symbol-rules.v2",
  "rules": [
    {"category": "translation-build", "image": "carrick", "symbol_prefixes": ["carrick_dsr_aarch64::translator::ProcessState::translate", "carrick_dsr_aarch64::emit::"]},
    {"category": "translation-publication", "image": "carrick", "symbol_prefixes": ["carrick_dsr_aarch64::cache::TranslationCache::", "carrick_dsr_aarch64::shared_cache::"]},
    {"category": "gateway-prepare", "image": "carrick", "symbol_prefixes": ["carrick_dsr_aarch64::translator::ThreadTranslator::prepare"]},
    {"category": "gateway-resolve", "image": "carrick", "symbol_prefixes": ["carrick_dsr_aarch64::gateway::", "carrick_dsr_aarch64::translator::ThreadTranslator::resolve"]},
    {"category": "dispatch", "image": "carrick", "symbol_prefixes": ["carrick_runtime::dispatch::"]},
    {"category": "process-setup", "image": "carrick", "symbol_prefixes": ["carrick_runtime::native_darwin::load_native_execve_image", "carrick_runtime::native_darwin::run_image_in_child", "carrick_runtime::native_darwin::run_image_in_current_process"]}
  ]
}
```

Before acceptance, enumerate the signed binary's resolved Carrick fixture
symbols and amend prefixes only when a focused test proves a unique intended
class. `other-carrick` is the exact Carrick Mach-O image-owned fallback after
the non-overlapping table, not a broad prefix rule that overlaps every specific
entry. A sampled system-library leaf never inherits a caller category.

- [ ] **Step 4: Implement exact join then first-match rules**

After loading and rehashing both capture receipts and their closed inputs, for
each complete process image:

1. join PC to private range;
2. join PC to one shared range and preserve `unit_id`;
3. apply the ordered non-overlapping Carrick symbol rules;
4. apply exact Darwin image catalog ownership;
5. consume the already assigned kernel class; or
6. return `unresolved`.

Reject multiple exact range matches, retired epochs, missing catalogs, and
catalog/sample identity mismatch.

- [ ] **Step 5: Retire the one-range script as an authority**

Reduce `native-jit-aware-profile.d` to a clearly labeled compatibility front
end that prints a deprecation message pointing at
`carrick trace --profile native-wall`. Its output carries
`gating_eligible=false`; it cannot emit the v2 schemas.

- [ ] **Step 6: Enforce two-run stability**

For two accepted profiles, require stable dominant-category rank and no
category above 10% moving more than five percentage points unless the output
contains an explicit instability finding. Report private/shared sample counts,
distinct ranges, distinct unit IDs, and per-category shares.

- [ ] **Step 7: Run tests and commit**

```bash
python3 -m unittest scripts/perf/test_native_wall_attribution.py -v
git diff --check
git add scripts/perf/native_wall_symbol_rules_v2.json \
  scripts/perf/native_wall_attribution.py \
  scripts/perf/test_native_wall_attribution.py \
  scripts/dtrace/native-jit-aware-profile.d
git commit -m "diagnostics(perf): classify native translation ownership" -m \
"Join sampled PCs to exact private/shared catalogs before applying a
non-overlapping Carrick leaf taxonomy. Preserve Darwin callees as Darwin and
retire the lossy one-range script from gating use.

Verified with multi-unit, boundary, symbol-overlap, and two-run stability
fixtures.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 6: Live-prove default and shared translation ownership

**Files:**

- Create: `scripts/perf/native_wall_capture.py`
- Create: `scripts/perf/test_native_wall_capture.py`
- Create: `scripts/perf/evidence/native-wall-m2-v2/manifest.json`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-default-v2-a.raw`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-default-v2-a.jsonl`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-default-v2-a.stdout`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-default-v2-a.capture.json`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-default-v2-b.raw`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-default-v2-b.jsonl`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-default-v2-b.stdout`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-default-v2-b.capture.json`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-default-attribution-v2.json`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-shared-v2-a.raw`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-shared-v2-a.jsonl`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-shared-v2-a.stdout`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-shared-v2-a.capture.json`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-shared-v2-b.raw`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-shared-v2-b.jsonl`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-shared-v2-b.stdout`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-shared-v2-b.capture.json`
- Create: `scripts/perf/evidence/native-wall-m2-v2/native-wall-shared-attribution-v2.json`
- Modify: `docs/perf-results/2026-07-29-native-cpu-budget-evidence.md`
- Modify: `handoff.md`

- [ ] **Step 1: Run all focused tests and build signed**

```bash
cargo test -p carrick-observability translated_range -- --nocapture
cargo test -p carrick-dsr-aarch64 translated_range -- --nocapture
cargo test -p carrick-cli --test trace_profile native_wall -- --nocapture
python3 -m unittest \
  scripts/perf/test_native_wall_attribution.py \
  scripts/perf/test_native_wall_capture.py -v
scripts/build-signed.sh
otool -l target/release/carrick | grep -q __dof_carrick
```

- [ ] **Step 2: Add and red-first test the receipt-bound capture wrapper**

`native_wall_capture.py capture` takes `--receipt`, one complete M1 overlay,
`--run-id-prefix`, `--trace-out`, `--summary-jsonl`, `--stdout`, and
`--capture-receipt`. It re-verifies
the receipt, M1 host preflight, and complete overlay before executing exactly:

```python
command = [
    str(arm.binary_path),
    "trace", "--profile", "native-wall",
    "--trace-out", str(trace_out),
    "--summary-jsonl", str(summary_jsonl),
    "--", "run", "--exec-backend", "native",
    "localhost:5005/carrick-go-conformance:1.24",
    "/bin/sh", "-c", native_go_build.cold_go_workload_command(),
]
```

It generates the actual ID as `<validated-prefix>-<uuid4>`, proves that exact
ID absent, invokes `scripts/sudo/kill.sh <actual-id>` before launch, then runs
M1 preflight with that ID. It shares the workload-command builder rather than
copying its shell string, captures stdout/stderr, requires exactly one workload
clock and `BUILD_OK`, invokes `scripts/sudo/kill.sh` with the same actual ID as
its sole argument in `finally`, and emits a small capture
receipt containing hashes of raw, JSONL, stdout, arm receipt, overlay, and
marker result plus the generated ID. Tests prove ID collision/absence,
pre-reap failure, receipt/overlay drift, timeout, missing marker, trace
failure, cleanup failure, and a foreign-run preflight all fail closed.

The same module exposes `capture-lifecycle`. It generates a run ID as
`native-m2-lifecycle-<uuid4>`, validates that the exact ID is absent, calls
`scripts/sudo/kill.sh <run-id>` once before launch and again from `finally`,
and enforces a 120-second host timeout. It executes the fixed child-exec/wait
fixture from Step 3, writes raw/summary/stdout/capture receipt through the same
hash path, and requires both lifecycle markers. Tests interrupt each launch
phase and prove bounded exit plus scoped cleanup; the generated ID is never
reused.

`promote-set` accepts the exact closed M2 role set used in Step 8. It rehashes
every source, revalidates both analyses against their capture receipts, creates
one same-parent staging directory with an exclusive random name, copies and
`fsync`s every file, writes and `fsync`s `manifest.json`, then atomically
renames the complete directory to the absent final destination and `fsync`s
the parent. Destination collision is fatal; it never overwrites an accepted
set. An interruption may leave only an ignored staging directory, never a
mixed final directory. Failure-injection tests cover every copy, manifest,
directory-sync, rename, and collision point.

```bash
python3 -m unittest scripts/perf/test_native_wall_capture.py -v
git diff --check
git add scripts/perf/native_wall_capture.py \
  scripts/perf/test_native_wall_capture.py
git commit -m "diagnostics(perf): capture native wall evidence by receipt" -m \
"Run the primary cold-Go workload through an immutable Carrick arm and a
complete semantic overlay. Preserve raw, summary, stdout, marker, cleanup, and
input hashes so a traced capture cannot silently change workload or binary.

Verified with receipt, overlay, timeout, marker, cleanup, and contamination
fixtures.

Co-Authored-By: Codex <codex@openai.com>"
```

- [ ] **Step 3: Live-prove fork/exec lifecycle**

Prepare one immutable current-tip arm, then run a child-exec/wait reducer long
enough to guarantee translated samples:

```bash
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo "$PWD" \
  --destination target/perf/native-m2-tip \
  --label native-m2-tip \
  --role candidate \
  --image localhost:5005/carrick-go-conformance:1.24
python3 scripts/perf/native_wall_capture.py capture-lifecycle \
  --receipt target/perf/native-m2-tip/arm.json \
  --overlay scripts/perf/overlays/native-default.json \
  --timeout-seconds 120 \
  --trace-out target/perf/native-wall-private-v2.raw \
  --summary-jsonl target/perf/native-wall-private-v2.jsonl \
  --stdout target/perf/native-wall-private-v2.stdout \
  --capture-receipt target/perf/native-wall-private-v2.capture.json
```

The wrapper's fixed guest command is exactly:

```python
lifecycle_guest = (
    "set -eu; "
    "(i=0; while [ \"$i\" -lt 500000 ]; do i=$((i + 1)); done; "
    "exec /bin/sh -c 'i=0; while [ \"$i\" -lt 500000 ]; "
    "do i=$((i + 1)); done; echo CHILD_EXEC_OK') & "
    "child=$!; wait \"$child\"; echo PARENT_WAIT_OK"
)
```

Require target birth, distinct child birth, exec generation reset, one private
range, inherited frontier, fresh post-exec epoch, both output markers, nonzero
translated samples for parent and child, parent wait, no translated sample
outside exactly one range, natural exit, and zero drops.

- [ ] **Step 4: Capture two default Go builds**

Use the immutable M2 receipt, unique run IDs, and M1's exact default overlay.
Keep raw, summary, stdout, and capture receipts under `target/perf/` while the
worktree remains clean:

```bash
python3 scripts/perf/native_wall_capture.py capture \
  --receipt target/perf/native-m2-tip/arm.json \
  --overlay scripts/perf/overlays/native-default.json \
  --run-id-prefix native-m2-default-a \
  --trace-out target/perf/native-wall-default-v2-a.raw \
  --summary-jsonl target/perf/native-wall-default-v2-a.jsonl \
  --stdout target/perf/native-wall-default-v2-a.stdout \
  --capture-receipt target/perf/native-wall-default-v2-a.capture.json
python3 scripts/perf/native_wall_capture.py capture \
  --receipt target/perf/native-m2-tip/arm.json \
  --overlay scripts/perf/overlays/native-default.json \
  --run-id-prefix native-m2-default-b \
  --trace-out target/perf/native-wall-default-v2-b.raw \
  --summary-jsonl target/perf/native-wall-default-v2-b.jsonl \
  --stdout target/perf/native-wall-default-v2-b.stdout \
  --capture-receipt target/perf/native-wall-default-v2-b.capture.json
python3 scripts/perf/native_wall_attribution.py \
  --capture-receipt target/perf/native-wall-default-v2-a.capture.json \
  --capture-receipt target/perf/native-wall-default-v2-b.capture.json \
  --rules scripts/perf/native_wall_symbol_rules_v2.json \
  --output target/perf/native-wall-default-attribution-v2.json
```

- [ ] **Step 5: Capture two shared Go builds**

Repeat with the semantic shared overlay
`CARRICK_DSR_SHARED_TRANSLATION=1` and
`CARRICK_DSR_DIRECT_BINDINGS=1`, with artifact spike absent. Require at least
two shared units, every translated PC in exactly one typed range, and the same
acceptance/stability gates:

```bash
python3 scripts/perf/native_wall_capture.py capture \
  --receipt target/perf/native-m2-tip/arm.json \
  --overlay scripts/perf/overlays/native-shared.json \
  --run-id-prefix native-m2-shared-a \
  --trace-out target/perf/native-wall-shared-v2-a.raw \
  --summary-jsonl target/perf/native-wall-shared-v2-a.jsonl \
  --stdout target/perf/native-wall-shared-v2-a.stdout \
  --capture-receipt target/perf/native-wall-shared-v2-a.capture.json
python3 scripts/perf/native_wall_capture.py capture \
  --receipt target/perf/native-m2-tip/arm.json \
  --overlay scripts/perf/overlays/native-shared.json \
  --run-id-prefix native-m2-shared-b \
  --trace-out target/perf/native-wall-shared-v2-b.raw \
  --summary-jsonl target/perf/native-wall-shared-v2-b.jsonl \
  --stdout target/perf/native-wall-shared-v2-b.stdout \
  --capture-receipt target/perf/native-wall-shared-v2-b.capture.json
python3 scripts/perf/native_wall_attribution.py \
  --capture-receipt target/perf/native-wall-shared-v2-a.capture.json \
  --capture-receipt target/perf/native-wall-shared-v2-b.capture.json \
  --rules scripts/perf/native_wall_symbol_rules_v2.json \
  --output target/perf/native-wall-shared-attribution-v2.json
```

- [ ] **Step 6: Escalate disputed mappings to LLDB**

If any dominant PC is unresolved or overlaps a disputed range, attach to the
guest Carrick process, run `scripts/carrick_lldb.py`, record `image list`,
`memory region`, relevant bytes/registers, and SHA-256 the transcript. Do not
weaken the 85% coverage or exact-range gate.

- [ ] **Step 7: Run correctness and full gates**

```bash
just conformance-native smoke --workers 4
just conformance full --lane macos-native-dsr --workers 1 \
  --suite node-app-smoke --suite node-v8-smoke \
  --jsonl target/conformance/native-performance-m2-node.jsonl
just conformance full --lane macos-native-dsr --workers 1 \
  --suite cpython-subprocess --suite cpython-threading \
  --jsonl target/conformance/native-performance-m2-cpython.jsonl
just ci
```

Run these commands serially and never run Docker concurrently with a separate
Carrick workload.

- [ ] **Step 8: Record evidence and commit**

Record raw/analyzed SHA-256 values, binary/commit, host build, coverage,
private/shared shares, distinct unit counts, kernel partition, stability, and
any LLDB transcript. Do not compare traced elapsed time as a speedup.

Only after both states and every guardrail are accepted, promote all raw
streams, summaries, stdout marker receipts, capture receipts, and analyses
from `target/perf` as one atomic directory. This avoids a first capture
dirtying the source tree used by the second capture, keeps every analyzer input
auditable, and makes `manifest.json` the one publication point.

```bash
python3 scripts/perf/native_wall_capture.py promote-set \
  --destination scripts/perf/evidence/native-wall-m2-v2 \
  --input default-a.raw=target/perf/native-wall-default-v2-a.raw \
  --input default-a.jsonl=target/perf/native-wall-default-v2-a.jsonl \
  --input default-a.stdout=target/perf/native-wall-default-v2-a.stdout \
  --input default-a.capture=target/perf/native-wall-default-v2-a.capture.json \
  --input default-b.raw=target/perf/native-wall-default-v2-b.raw \
  --input default-b.jsonl=target/perf/native-wall-default-v2-b.jsonl \
  --input default-b.stdout=target/perf/native-wall-default-v2-b.stdout \
  --input default-b.capture=target/perf/native-wall-default-v2-b.capture.json \
  --input default.analysis=target/perf/native-wall-default-attribution-v2.json \
  --input shared-a.raw=target/perf/native-wall-shared-v2-a.raw \
  --input shared-a.jsonl=target/perf/native-wall-shared-v2-a.jsonl \
  --input shared-a.stdout=target/perf/native-wall-shared-v2-a.stdout \
  --input shared-a.capture=target/perf/native-wall-shared-v2-a.capture.json \
  --input shared-b.raw=target/perf/native-wall-shared-v2-b.raw \
  --input shared-b.jsonl=target/perf/native-wall-shared-v2-b.jsonl \
  --input shared-b.stdout=target/perf/native-wall-shared-v2-b.stdout \
  --input shared-b.capture=target/perf/native-wall-shared-v2-b.capture.json \
  --input shared.analysis=target/perf/native-wall-shared-attribution-v2.json
git add scripts/perf/evidence/native-wall-m2-v2 \
  docs/perf-results/2026-07-29-native-cpu-budget-evidence.md \
  handoff.md
git commit -m "diagnostics(perf): accept native translation ownership" -m \
"Capture two stable default and shared native-wall profiles with exact
private/shared range joins, birth-keyed fork/exec lifecycle, and balanced
kernel state. Use the results only to size the next removable CPU ceiling.

Verified with signed live profiles, native smoke, Node/CPython guardrails, and
`just ci`.

Co-Authored-By: Codex <codex@openai.com>"
```

## M2 Completion Gate

M2 is complete only when:

- one process-wide catalog publishes all private/shared ranges;
- fork and exec lifecycle are accepted under a qualified birth-key grammar;
- every translated sample joins exactly one typed range;
- mixed v1/v2, gaps, overlaps, drops, and stale epochs fail closed;
- two default and two shared captures meet all coverage/stability gates;
- the analyzer reports the exact 14-category taxonomy; and
- the ledger/handoff link the immutable evidence without a traced-time
  performance claim.

M2 does not select or implement the optimization; M4 compares its conservative
ceiling with M3's fault ceiling.
