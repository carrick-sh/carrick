# Native AArch64 mapped translation metadata V3

**Status:** approved for implementation.
**Lane:** Darwin/AArch64 native DSR only.
**Primary workload:** conformance `go-build` with a cold `GOCACHE`.
**Retention authority:** same-binary, eight-quad total-child-CPU ABBA.

This design extends the approved
[`2026-07-26-container-lifetime-translation-cache-design.md`](2026-07-26-container-lifetime-translation-cache-design.md).
It changes how one container-lifetime translation unit stores and consumes
runtime metadata. It does not change which guest code is eligible for sharing,
how signed code is emitted, or the fallback to private JIT translation.

## 1. Evidence and goal

The retained shared-translation mechanism stack is `15.50%` faster in total CPU
than its clean pre-stack source (`8/8` Go-build quads), but the current shared
path remains `6.76%` slower than the current default path. Exact DTrace PC
attribution resolved the next shared-only host-user cluster to:

- bincode tuple decode and decode-error destruction;
- manifest `Vec` materialization;
- `exact_guest_ranges_from_pc_map`;
- sorting and equality over reconstructed indexes; and
- direct-binding unit and edge preparation.

The largest observed manifest is `129.8 MiB` beside only `6–15 MiB` of code. It
contains `3,708,221` PC-map entries and `3,456,821` recovery entries; run
encoding reduces the latter to `454,986` records. Eight non-overlapping exact
leaf groups at this boundary account for `264` samples, `8.9%` of the shared
arm's host-user bucket.

A typed proof that skipped redundant validation, without changing the
representation, measured only `-0.31%` total CPU (`5/8` wins, one-sided upper
`1.00289`) and was removed. Therefore this design does not optimize validation
alone. It removes owned decoding and reconstruction of immutable runtime data.

The goal is that a descendant which loads a published unit:

1. maps the metadata file read-only;
2. performs one allocation-free validation pass;
3. retains typed views over the mapping; and
4. allocates only state that is genuinely process-local.

The change must be default-on with an exact V2 opt-out. A neutral or negative
primary CPU result is removed, even if component counters improve.

## 2. Selected architecture

Each V3 translation unit remains a signed Mach-O dylib plus one metadata file.
The metadata file changes from a bincode object graph to a versioned,
little-endian, mmap-native representation. Its final name is
`<unit-stem>.metadata-v3`; the V2 control continues to use
`<unit-stem>.manifest`.

`CARRICK_DSR_SHARED_MAPPED_METADATA=0` selects the unchanged V2 writer, loader,
and runtime representation for the entire top-level run. Absence or any value
other than exact `0` selects V3. All descendants inherit the choice, so a run
never mixes V2 and V3 units.

Existing controls remain honest. `CARRICK_DSR_SHARED_RECOVERY_RUNS=0` is valid
inside V3 and emits one-entry recovery spans instead of coalesced spans. The
V2-only manifest-retention and fixed/varint wire overlays explicitly set
`CARRICK_DSR_SHARED_MAPPED_METADATA=0`; they never silently measure V3 while
claiming to exercise the old object graph.

The cache is private and container-lifetime: a new top-level invocation starts
empty and the owner removes it at lifecycle end. V3 therefore does not dual-read
V2 entries. A schema or filename mismatch is a normal cache miss followed by
publication or private JIT fallback. There is no durable migration problem.

The separate file is preferred over two alternatives:

- An index-only sidecar leaves the 60–130 MiB bincode decode and most owned
  runtime metadata intact, so it does not attack the measured owner.
- Embedding metadata in the Mach-O removes the second file but couples every
  metadata iteration to object emission, signing, dyld sections, and export
  layout. The private atomic pair already supplies the required lifetime and
  trust boundary with less implementation risk.

## 3. Wire format

The file begins with a fixed V3 header containing:

- an eight-byte Carrick magic, schema `3`, endian marker, header size, and total
  file size;
- the complete fixed-width `TranslationUnitKey` identity, with explicit
  discriminants and zeroed unused payload fields for its variants;
- dylib SHA-256, code length, binding-data length, binding layout, and cell
  size; and
- a fixed directory of typed section descriptors.

Each descriptor stores section kind, byte offset, byte length, record count,
and record stride. Sections are aligned, disjoint, contained by the mapped file,
and use explicit little-endian integer fields. Rust enum layout, pointer width,
`usize`, padding, and serde ordinals are never part of the wire ABI.

V3 contains these sections:

| Section | Purpose |
|---|---|
| block records | guest start, generation binding, code extent, flags, and slices into the following tables |
| PC-map records | exact guest VA and unit-relative cache offset |
| recovery spans | cache start, nonzero entry count, and recovery-action index; entry-mode controls use count one |
| recovery actions | explicit action tag and fixed canonical payload |
| guest ranges | exact precomputed half-open ranges for each block |
| direct bindings | source, target, kind, ordinal, stub extent, and edge-member index |
| binding relocations | the five checked instruction/data offsets for each binding |
| edge groups | sorted `(source, target)` keys and slices of binding ordinals |
| edge members | binding ordinals grouped by the preceding table, with an exact back-reference from each binding |

Every V3 wire record is a dedicated `#[repr(C)]` type using `zerocopy`
little-endian fields. Record sizes have compile-time assertions. Recovery
actions use explicit stable tags; changing a tag, payload, stride, or semantic
meaning requires another schema version. Recovery runs refer to a deduplicated
action table, so repeated large action payloads are not copied into every run.

The deterministic base export and constant binding export are derived from the
validated key and layout; V3 does not store heap-backed strings. The unit stem
and signed keyed export retain the existing full-key binding.

## 4. Publisher data flow

`PendingTranslationUnit` remains the owned construction form because the first
publisher already owns emitted blocks. A new V3 encoder consumes it once:

1. preserve block order by unit-relative entry offset;
2. flatten PC maps and recovery runs into their tables;
3. deduplicate recovery actions and replace each run's action with an index;
4. compute exact guest ranges once at publication;
5. group direct-binding edges once at publication;
6. emit checked block slices and section descriptors; and
7. write the complete header and tables to a uniquely named temporary file.

The publisher maps its temporary file through the production parser and runs
the complete V3 validator before the file can win publication. It then follows
the existing per-key first-writer-wins protocol for the dylib and metadata
pair. Readers never open a temporary name; one visible half of a pair is a
typed `MissingPair` miss. Duplicate publishers discard their temporary files
and load the winner.

V3 publication performs no lossy conversion. A value that the fixed wire cannot
represent makes that unit ineligible and falls back to private JIT execution;
it is never truncated, saturated, or approximated.

## 5. Loader and validation

The Darwin loader opens the final metadata through the inherited cache
authority with read-only, no-follow semantics, verifies the file identity and
size with `fstat`, and maps it `MAP_PRIVATE | PROT_READ`. It never calls
`std::fs::read` for V3.

`MappedTranslationMetadata::validate` performs exactly one allocation-free
pass before returning `ValidatedMappedTranslationMetadata`:

- validate magic, schema, endian, key, total length, and every section
  descriptor with checked arithmetic;
- reject overlap, misalignment, unexpected stride, unknown flags/tags, and
  nonzero reserved fields;
- prove block code extents are ordered, disjoint, nonempty, and contained;
- prove block generation bindings and all table slices are in range; duplicate
  or missing generation bindings remain a failure in the unavoidable
  process-local binding-array construction;
- prove PC offsets are strictly ordered within their block;
- prove recovery runs are ordered, disjoint, nonempty, within their block, and
  name valid actions;
- compare the precomputed guest-range stream with the PC-map-derived stream
  without allocating either one;
- validate binding ordinals, stub ownership, relocation geometry, cell layout,
  and same-unit target exclusion; and
- prove edge groups are sorted and disjoint, and prove exact coverage without a
  bitmap by checking both directions of the binding-to-member/member-to-binding
  indexes; every member must also agree with its binding's source and target.

This pass intentionally remains: the rejected experiment showed that validation
alone is not the material owner, and correctness must not depend on unchecked
mapped bytes. The pass does not clone, deserialize, hash, sort, build trees, or
retain a second representation.

Only the validated wrapper exposes typed table and per-block views. Invalid
metadata closes the mapping and dylib handle and becomes the existing typed
cache miss before any translator state mutates.

## 6. Runtime ownership and lookup

`SharedLoadedTranslationUnit` changes from an
`Arc<TranslationUnitManifest>` to a representation-neutral metadata lease:

- V2 owns the existing decoded manifest for the exact control;
- V3 owns an `Arc<ValidatedMappedTranslationMetadata>`; and
- both expose the same checked key, code length, block, recovery, binding, and
  edge-group accessors.

The V3 mapping lives at least as long as the dyld handle. Cloning a loaded unit
clones leases, never metadata tables. Unlinking a published metadata pathname
after a successful load does not invalidate the open mapping.

`PublishedBlock` keeps owned PC/recovery vectors for private JIT blocks. A
shared block instead stores `(loaded_unit_index, block_index)`. Fault and kick
lookup resolves that pair through the retained unit and binary-searches the
mapped PC map or recovery runs. No shared block clones a map, recovery table, or
mapping `Arc`.

The process still creates state that cannot be shared safely:

- generation observations and the generation-binding array;
- target authority and direct-binding publication bitmap;
- page-dependency registrations;
- sensitive-exit state that depends on the live guest mapping; and
- cross-unit mutable lookup ownership.

Direct-binding owners store `(unit_index, record_index, cell)` instead of cloned
records. The registry consumes the already grouped V3 edge tables, avoiding its
current count, allocation, regroup, and sort pass. The shared published-block
index consumes block records already ordered by cache offset and merges them
with existing units; it does not sort the complete accumulated index again.

The existing two-phase prepare/commit protocol remains. Every allocation and
fallible process-local preparation completes before catalog, block, binding, or
executable authority becomes visible.

## 7. Failure and compatibility behavior

The cache remains an optimization. Missing, malformed, stale, truncated,
overflowing, unsupported, or unloadable V3 metadata produces a typed
`UnitMissReason`, closes partial resources, records the reason, and continues
through private JIT translation. It never panics and never exposes a partially
prepared unit.

VMM/HVF, Linux/KVM, FreeBSD/bhyve, NetBSD/NVMM, the x86 native translator,
persistent cross-run caching, eviction, and adversarial cache hardening remain
out of scope. The cache authority is still private `0700` container state, not
a hardened trust boundary.

## 8. Observability and decision gates

The performance protocol gains low-frequency V2/V3 counters for:

- metadata bytes read versus mapped;
- map and validation CPU/wall time;
- owned PC-map, recovery, guest-range, and binding records materialized;
- mapped records retained;
- guest-range derivations avoided;
- direct-edge group builds avoided; and
- typed V3 miss reasons.

The Go-build harness gains the exact V2 overlay and records the metadata mode in
every receipt. DTrace comparison uses the maintained bounded profiler and exact
host-PC symbolication. It must show the bincode decode, `Vec` deserialization,
`exact_guest_ranges_from_pc_map`, and binding grouping/sort cluster disappearing
without replacing it with a larger mmap, page-fault, lock, or dyld owner.

LLDB remains the escalation path if a process wedges, faults outside a validated
mapped extent, or DTrace attribution conflicts with runtime state. It is not a
substitute for the primary timing gate.

Retention proceeds in this order:

1. wire and runtime equivalence tests;
2. signed live load/reuse proof;
3. focused V2/V3 mechanism counters and bounded DTrace;
4. a short same-binary directional pair; and
5. the immutable eight-quad total-child-CPU ABBA if the mechanism moved and the
   directional pair did not regress.

The candidate stays only if all 32 measured runs complete, total CPU improves,
the one-sided upper bound is below parity, the sign test passes, supported
secondary metrics do not regress, and correctness gates remain green.

## 9. Red-first and correctness verification

Before the production reader is enabled, tests must prove:

1. V2 and V3 expose identical keys, blocks, PC lookups, recovery actions,
   guest ranges, bindings, relocations, and edge groups for the same pending
   unit;
2. V3 rejects bad magic/schema/endian, arithmetic overflow, overlapping or
   misaligned sections, bad strides, unknown tags, nonzero reserved bytes,
   unordered maps/runs, invalid action indexes, incorrect derived ranges, and
   incomplete edge coverage;
3. a mapped lease survives loaded-unit clones and unlink of its pathname;
4. dropping the final unit lease releases both metadata mapping and dyld handle;
5. a V3 load performs zero owned materialization for immutable record tables;
6. every existing shared-install failpoint remains failure-atomic; and
7. exact `CARRICK_DSR_SHARED_MAPPED_METADATA=0` restores the unchanged V2 path.

The red control must run the same fixture through a deliberately corrupt V3
section or derived index and demonstrate a typed miss before the fix. Runtime
completion requires the signed Go-build demo, Node and CPython native smoke,
native conformance smoke, and the full serialized repository gate required by
the active handoff.

## 10. Implementation boundaries

The wire codec and representation-neutral metadata API belong in
`carrick-dsr-aarch64`, next to the existing shared-cache types. Darwin file
mapping, cache authority, publication, and dyld lifetime remain in
`carrick-native-darwin::aot_cache`. Process-local installation changes remain
in the existing `ProcessState` and `DirectBindingRegistry` seams; no second
native driver or cache wiring point is added.

The implementation should be sliced so the V2 control stays runnable after
every commit. Format encoding/validation, loader lifetime, block/recovery views,
precomputed guest ranges, and direct-edge views are separate testable steps,
but the candidate is not performance-retained until the complete V3 path passes
the primary gate.
