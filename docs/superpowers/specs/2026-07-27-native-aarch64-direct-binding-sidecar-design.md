# Darwin/AArch64 native direct-binding sidecar

**Date:** 2026-07-27
**Status:** approved for implementation planning
**Scope:** immutable Darwin/AArch64 DSR translation units and the cold-GOCACHE
`go-build` wall-time campaign

## Purpose

Collapse the direct-resolver amplification caused by immutable shared
translation units without making signed executable pages writable and without
weakening generation, process, fork, exec, or asynchronous-signal correctness.

This design is one bounded wave inside
`2026-07-27-native-wall-time-attribution-campaign-design.md`. It does not
redefine that campaign's success:

- official `C0`: 19,375 ms;
- official `D0`: 1,007 ms;
- official `R0`: 19.2403x;
- first milestone: `R <= 9.6202x`;
- destination: `R <= 2.0x`;
- retain only an untraced five-sample wall win with the campaign's correctness
  and end-to-end gates.

The current authority-carrying shared-cache precursor is correct but takes a
25,169 ms three-sample median. It is a correctness prerequisite, not a retained
primary-metric win.

## Evidence selecting this wave

The accepted whole-process-tree DTrace pair classifies 88.3% and 89.8% of CPU
samples, accounts for all wall samples with zero drops, and assigns about 71%
of sampled CPU to translated guest execution plus Darwin kernel work.

The full immutable-unit path amplified:

- gateway entries from 2,395,609 to 262,216,112;
- direct resolver exits from 1,433,321 to 68,932,094;
- indirect resolver exits from 862,580 to 62,056,062;
- child CPU from 43.8 s to 127.1 s.

The authority-carrying two-way cache removes much of that regression, but a
bounded 45-second trace still records 17,155,262 direct resolver exits. The
hottest edge alone fires 1,473,595 times and is the `0x1a748 -> 0x1a74c`
fall-through of Go `compile`'s `CBZ R1`.

Static packing sees 93,430 direct links:

- 66,705 resolve within the same unit and are already patched directly;
- 26,725 remain unresolved and currently enter a resolver-capable stub.

The edge population is therefore small enough for per-edge process-local state
while its dynamic amplification is large enough to support a step-function
win.

Two previous approaches are rejected:

- a full inline target-cache lookup at every private and shared edge exhausted
  the 64 MiB private JIT cache;
- limiting that lookup to portable artifacts produced one 24.664 s sample and
  then failed in Go runtime stack machinery.

No variant may revive that inline lookup family without new evidence.

## Fixed architecture

### Immutable code, writable process-local cells

Each unresolved direct edge in a loaded translation unit owns one mutable
binding cell in a conventional Mach-O `__DATA,__data` section. The translated
stub addresses its cell PC-relatively. It does not consult a global hash table,
an active-unit table, or a `DsrContext` sidecar-base pointer on the hit path.

The dylib retains:

- signed, immutable, executable `__TEXT,__text`;
- writable, non-executable `__DATA,__data`;
- read-only `__LINKEDIT`.

The loader must prove empirically that dyld maps `__DATA` process-private/COW:
two independently loaded processes may bind the same cell differently without
observing each other's writes. Fork behavior is governed separately below.

Same-unit direct links remain ordinary patched AArch64 `B` instructions and do
not receive cells. A cell exists only when packing cannot resolve the target
inside the unit.

### Stable edge identity

Within one translation unit, an unresolved edge is identified by the typed
pair:

```text
(source guest PC, target guest PC)
```

This distinguishes conditional taken and fall-through edges because their
targets differ. The serialized owner identity is:

```text
(TranslationUnitKey, unresolved-stub ordinal)
```

Every serialized unresolved stub receives its own cell. The source/target pair
is a discovery and validation key, not the sole owner identity. At the current
26,725-cell population, deduplicating equal pairs saves little and would make
incoming-link invalidation and recovery review ambiguous. Guest addresses
alone never select a cell from an unrelated image or unit version.

`DirectLink` must retain the source guest PC in addition to its branch slot and
target. Its serialized record also retains edge kind and stub ordinal.
Deriving source identity later from the nearest PC-map entry is not accepted:
recovery maps describe instruction ownership, not a serialization identity.

### Cell payload and publication

Each dylib cell is one naturally aligned atomic machine word:

```text
null | pointer to immutable process-owned DirectBindingTarget
```

The pointer addresses a fixed, immutable translated-code ABI prefix:

```text
target cache PC
target cache-range start
target cache-range end
target generation-binding table
```

The process-owned `DirectBindingTarget` wraps that prefix with the target guest
page/generation identity, reserved version/epoch state, and a typed lease
proving that the target code bytes and their entry generation guard remain
mapped and cannot be reused. The four-word prefix is the existing
`TargetCacheAuthority` information copied into one prevalidated immutable
record, avoiding another target-authority pointer chase on every hit. The
process retains every published descriptor until all cells and executing
threads are quiesced.

Cells are shared by Carrick threads in one process and therefore use real
atomics. A resolver constructs and retains a complete immutable descriptor,
then release-CASes the cell from null to that descriptor's pointer. The first
publisher wins. A losing publisher accepts the winner only when its immutable
target identity and authority remain valid for the same edge. Otherwise it
CAS-clears that exact stale pointer and retries once before falling back. No
publisher rewrites descriptor fields.

This single-word publication is load-bearing. Separately storing target and
authority and publishing one field last is not MPMC-safe: two writers can
otherwise expose one writer's target with the other's authority.

Translated code acquire-loads the descriptor pointer. Null is a miss. A
non-null descriptor is an immutable target/authority/version tuple. The hit
path loads its target, validates that the target falls inside the authority
range, installs the authority's cache range and generation-binding table in
`DsrContext`, restores architectural state, and branches to the target.

A failed null/range/authority check takes the existing resolver path. It never
executes an unowned target.

The initial descriptor does not require a changing epoch because the following
invariants are hard requirements, not implementation assumptions:

- published descriptors and their shared/private target-authority objects
  outlive all loaded cells that can reference them;
- private JIT code is append-only between quiesced exec/reset events and no
  published cache address is reused during that interval;
- a shared target unit's owner lease prevents `dlclose` while a descriptor can
  name its code;
- shared units are not individually unloaded while guest threads can execute;
- incoming-link invalidation clears stale cells before future traversals;
- exec/reset drops the loaded units, descriptors, and cells after thread
  quiescence.

Focused tests prove the current private cache's monotonic cursor and the
quiesced ordering that clears cells before cursor reuse. If the implementation
cannot prove these invariants, an explicit checked epoch is required before a
wall screen; pointer lifetime may not be inferred from allocator behavior.

At eight bytes per cell, the current 26,725 unresolved-edge population occupies
213,800 bytes before page rounding. Descriptor count and bytes are recorded
separately because one immutable descriptor may serve multiple cells that bind
the same target and authority.

### Pack-time specialization

Private JIT blocks remain mutable and continue to use direct branch patching.
The portable artifact recorder may execute its private block before any dylib
or `__DATA` mapping exists, so raw emitted private code must not contain a
mandatory PC-relative cell address.

The first sidecar variant therefore specializes unresolved direct stubs while
packing the immutable unit:

1. the normal emitter reserves and records the resolver-stub envelope;
2. same-unit links patch their branch slots to target entries as today;
3. unresolved links receive stable cell ordinals in source-code-offset order,
   improving locality and making the serialized owner deterministic;
4. the packer rewrites the recorded lookup envelope to the sidecar sequence;
5. the AOT emitter resolves the code-to-data PC-relative relocation after the
   final Mach-O layout is known;
6. unused words in the existing envelope remain unreachable padding so block,
   PC-map, recovery, and direct-link offsets do not move.

This in-place layout is Variant 1. It proves the mechanism while minimizing
metadata churn. It is not permission to depend on undocumented instruction
positions: the emitter records typed stub boundaries and relocation sites, and
the packer validates the expected instruction shape before rewriting it.

The AOT layer, not the shared-cache packer, owns final `ADRP`/page-offset
encoding because only the AOT layer knows the final `__TEXT` and `__DATA`
virtual addresses. It validates the signed AArch64 `ADRP` page displacement,
the low-12-bit add/load offset, instruction alignment, and that both relocation
words remain inside the recorded stub before writing either word.

### Mach-O and manifest changes

The AOT emitter gains a typed data-section input and typed code-to-data
relocations. It exports both:

- the existing code base;
- the binding-cell data base.

The translation-unit manifest is bumped to a new schema and records:

- data export name and data length;
- cell size and count;
- unresolved binding records containing source, target, edge kind, and cell
  ordinal;
- typed code-to-data relocation sites;
- the existing code and block metadata.

Validation rejects:

- old-schema units;
- unaligned or out-of-range data offsets;
- a data length inconsistent with cell size and count;
- duplicate conflicting edge identities;
- relocations outside a recorded unresolved stub;
- an unencodable `ADRP` displacement or page offset;
- bindings for same-unit links;
- code or data exports outside their declared sections;
- nonzero on-disk cell publication state.

The existing dylib SHA-256 covers both code and data because it covers the
complete emitted file.

`LoadedTranslationUnit` owns both mappings for the lifetime of its `dlopen`
handle. Its safety contract changes from "the mapping is immutable" to
"executable bytes are immutable and writable bytes are accessed only through
the typed atomic-cell API."

### Resolver integration

When a unit loads, `ProcessState` builds process-local owner records for every
`(TranslationUnitKey, stub ordinal)`. On a sidecar miss, the immutable stub
publishes its own PC-relative cell address and ordinal into a typed
`DirectBindingMiss` in the cold gateway exit metadata. `DirectBindingCellVa`
and `DirectBindingOrdinal` remain distinct from guest and cache addresses. The
resolver validates that address and ordinal against one currently loaded
unit's `__DATA` range, manifest source/target/kind record, and retained lease.
This identifies the exact loaded source-unit instance; a guest source/target
lookup never chooses among old and new instances.

This ownership validation is consulted only after a direct resolver miss. It
is not on the translated hit path. A non-sidecar private direct exit carries no
cell address and continues through the existing fallback.

For `NativeDsrExit::ResolveDirect { source, target }`:

1. translate or find the target as today;
2. derive and validate its `TargetCacheAuthority`;
3. continue publishing the per-thread target cache as a safe fallback;
4. construct or reuse a retained immutable `DirectBindingTarget`;
5. validate the miss-carried source cell and ordinal against its loaded owner;
6. if the active shared source owns that cell, CAS the descriptor pointer into
   the empty cell;
7. if another publisher won, validate the winning descriptor; accept an exact
   valid winner, or CAS-clear that exact stale pointer and retry once;
8. resume at the target guest PC as today.

A missing cell, stale source generation, duplicate ownership, or failed
authority check leaves the cell empty and uses the existing fallback. Manifest
data never supplies an executable host pointer.

Successful publication also appends a cold-path incoming-link record keyed by
the exact target guest page and generation. The record contains source owner,
cell ordinal, cell pointer, and the expected immutable descriptor pointer.
Publication and generation invalidation are serialized by the same
`ProcessState` write authority:

1. retain and validate the descriptor;
2. CAS the empty cell to its pointer;
3. if the CAS wins, set the source unit's publication bit and register the
   incoming link before releasing the write authority;
4. if it loses, validate the winner and do not register the losing descriptor.

On target-generation invalidation, the incoming list CAS-clears a cell only
when it still contains that exact descriptor pointer. Descriptors remain
pinned, so a reader that acquired the old pointer cannot observe freed memory.
A successful clear also clears the source unit's publication bit. A newer
publication is never erased. The next source traversal is a real sidecar miss
and can bind the current generation.

Low-frequency load/publication diagnostics report cell count, data bytes,
descriptor count and bytes, CAS wins/losses, incoming-link clears, and failed
ownership/range lookups. There is no always-on atomic hit counter in the hot
stub. Hit coverage is inferred from resolver-exit collapse and sampled stub
PCs.

## Lifecycle and fail-closed behavior

### Independent processes

Each process begins with zero cells even when it maps the same signed dylib.
Writes are process-private/COW. A dedicated loader oracle must prove this
before guest benchmarking.

### Threads

Threads in one guest process share cells. Single-word release-CAS/acquire-load
publication and immutable descriptors make concurrent publication safe. A
stress oracle must exercise two publishers and translated readers, prove that
exactly one complete descriptor wins, and never admit a mixed target/authority
pair.

### Fork

Each loaded unit preallocates a publication bitmap matching its fixed cell
array. A successful cold-path CAS sets its ordinal's bit under the process
write authority. The existing quiesced fork-child hook can therefore iterate
only inherited published ordinals; it does not allocate, discover dylibs,
acquire a new external lock, or scan mutable ownership structures after a
multithreaded fork.

The fork child release-stores null to those inherited cells and zeros the
bitmap before guest execution resumes. This is deliberately conservative:
inherited host pointers may name private JIT state whose post-fork policy
changes. Clearing is process-private and leaves the parent unchanged.

Shared-unit mappings and metadata may remain loaded, but every child edge
rebinds through the normal resolver. A focused oracle proves:

- parent bindings survive unchanged;
- child bindings are zero immediately after reset;
- child rebinds do not mutate parent cells;
- the first child traversal remains correct.

The inherited descriptor and reverse-link arenas remain pinned until a normal
quiesced reset; the fork-child hook does not free allocator-owned nodes.
Stale reverse entries use expected-pointer CAS and therefore harmlessly miss
after the cells are cleared.

The campaign records cells and pages cleared plus reset duration. Sparse
clearing is part of Variant 1 because writing every zero cell would COW the
entire data sidecar in a fork-heavy workload.

If measurement later shows fork clearing is material, retaining proven-safe
shared-to-shared bindings is a separate hypothesis, not part of this wave.

### Exec and reset

Exec/reset uses this order:

1. block publishers and quiesce translated readers;
2. null every published sidecar cell through the precomputed bitmaps;
3. clear per-thread target caches and every `DsrContext` cache-range,
   generation-binding, and binding-descriptor pointer;
4. clear incoming-link and source-owner indexes;
5. drop retained binding descriptors and their target-code leases;
6. drop loaded source/target units and their authority records;
7. reset the private JIT cursor only after no cell or descriptor can name a
   reusable address;
8. construct or resume the next execution state.

A subsequent executable gets fresh mappings and zero cells. No cell,
descriptor, target-code pointer, or authority pointer crosses exec. Focused
tests assert this ordering rather than merely checking that the final maps are
empty.

### Generation invalidation

Source and target blocks retain their existing generation guards. A stale
source cannot reach its edge. Target invalidation uses the reverse incoming
registry to CAS-clear cells holding the invalidated descriptor. A reader that
won the race before clearing may reach the old target once; its still-mapped
entry guard fails closed. Later traversals observe the empty cell, resolve the
new target generation, and stay out of the gateway after rebinding.

A focused oracle binds a cell, changes the target generation, proves one
fail-closed race is safe, proves the old descriptor is cleared, rebinds the
cell, and then proves repeated traversals no longer enter either the sidecar
resolver or stale generation guard.

### Unit retirement

This design permits no individual `dlclose` while a block or cell can still be
reached. If unit retirement is introduced, retirement must first make all
incoming cells unreachable, quiesce executing threads, and only then release
code, data, generation bindings, and target authority.

## Asynchronous recovery contract

The sidecar sequence is a rewrite preamble, not guest architecture. A signal,
kick, or fault may land on every emitted instruction boundary.

The stub must preserve:

- guest `x15`, `x16`, and `x17`;
- guest `x30`, including a call's already-committed link value;
- guest `NZCV`;
- the exact source/target guest-PC semantics;
- no partially installed executable-authority context across host recovery.

Recovery divides the stub into declared phases:

1. scratch and NZCV capture;
2. cell address materialization;
3. acquire target read;
4. authority validation;
5. authority-context installation;
6. architectural restore;
7. final target branch;
8. miss preparation and existing gateway exit.

Every clobbering instruction has an explicit `RecoveryAction`. Recovery never
guesses a phase from an instruction count. A call edge whose link register has
already been committed restores that committed link, not the caller's stale
`x30`.

Authority installation currently requires separate cache-start, cache-end, and
generation-binding stores. This design does not pretend those stores are one
atomic commit. A signal or kick at any sidecar preamble word leaves translated
execution, reconstructs the guest state and source PC, and discards the
partially installed context. Before translated execution resumes,
`enter_translated_with_cache_range_and_generation_bindings` writes the complete
authority tuple for the selected source block. No recovery path resumes in the
middle of the sidecar sequence or observes a partially installed tuple.

Focused tests cover branch, call, conditional taken, conditional fall-through,
and `Continue` edges. The recovery gate contains:

- static metadata coverage for every instruction in every phase;
- deterministic snapshot recovery at each phase boundary;
- a test that interrupts after each of the three authority-context stores and
  proves re-entry installs one complete source authority;
- a live jittered `SIGPIPE` kick sweep that lands inside the new preamble;
- a cross-unit target switch;
- a miss-path transition;
- red-first proof against a deliberately incomplete recovery table or the
  pre-fix behavior.

No wall screen runs until this gate is green.

## Bounded variants

### Variant 1 — in-place sidecar specialization

Keep all existing block and metadata offsets. Rewrite the recorded unresolved
stub envelope in place and leave unreachable padding. This variant must prove:

- process-private cells;
- exact publication ordering;
- resolver collapse;
- authority switching;
- complete recovery coverage;
- a signed end-to-end Go build.

The plan records the exact emitted hit-path word count. From the first
cell-address instruction through the final `br`, Variant 1 may use at most 24
instructions, including descriptor/authority loads, validation, context stores,
architectural restore, and branches. It performs no guest-target hash/tag
lookup and no active-unit table lookup. Exceeding the budget requires a new
design review before benchmarking.

### Variant 2 — one profile-authorized layout refinement

Variant 2 is allowed only when Variant 1 collapses resolver exits but fails the
wall screen. One new profile selects exactly one of:

- **compact materialization**, when code footprint, instruction-cache pressure,
  page faults, or unreachable padding is dominant; or
- **prevalidated descriptor installation**, when dependent descriptor loads or
  authority-context installation dominate the hit path.

Compact materialization removes padding and rebuilds block offsets, PC maps,
recovery maps, direct links, and relocations in one checked packing pass.
Prevalidated installation may change descriptor layout but must preserve the
single atomic publication identity and all lifetime/invalidation rules. Variant
2 may not combine both experiments and is not allowed merely because a layout
looks preferable.

If Variant 1 does not collapse the intended resolver exits, or if its recovery
model is unsound, Variant 2 is not attempted. H004 stops after these two
layouts.

## Evidence funnel

### Gate 1 — structural and loader proof

- new-schema round-trip and old-schema rejection;
- Mach-O `__TEXT`, `__DATA`, and `__LINKEDIT` protections verified;
- code and data exports resolve to the declared sections;
- every `ADRP`/page-offset relocation is encodable and remains inside its
  recorded stub;
- atomic-word cell alignment/count/size validation;
- two-process COW isolation;
- private target code is monotonic/pinned until quiesced reset;
- shared target leases prevent premature `dlclose`;
- sparse publication bitmaps require no fork-child allocation or discovery;
- fork clear/rebind behavior;
- exec clears all references before private-address reuse;
- no executable mapping becomes writable.

### Gate 2 — mechanism and recovery proof

- same-unit links still patch directly;
- each unresolved identity maps to exactly one valid cell;
- first miss atomically publishes one immutable target/authority descriptor;
- concurrent publishers cannot expose a mixed tuple;
- subsequent execution bypasses the gateway;
- private/shared and cross-unit targets install the correct authority;
- target invalidation CAS-clears exact incoming cells and subsequent traversals
  rebind rather than repeatedly hitting a stale generation guard;
- all recovery obligations above are green.

The eligible population is declared before the run from loaded manifests:
direct exits whose miss metadata validates to an exact active
`(TranslationUnitKey, stub ordinal)`. An exit cannot be classified as eligible
after observing its outcome.

Compare the current authority-carrying shared mode with sidecars disabled
against the same binary with sidecars enabled. Record the complete before/after
vector:

- sidecar-eligible direct resolver exits;
- total direct resolver exits;
- indirect resolver exits;
- total gateway entries;
- unique cells reached;
- descriptor publications, CAS losses, and incoming-link clears;
- failed owner/range validations;
- translations and child CPU.

Eligible repeated direct resolver exits must fall by at least 95%, without
reclassification into another gateway exit. In the absence of generation
changes, resolver publications must be bounded by the number of cells actually
reached per process rather than the dynamic edge count.

### Gate 3 — signed feasibility

Rebuild and sign the current source. Run one untraced cold-GOCACHE Go build and
execute its output marker. Reject crashes, hangs, cache exhaustion, or a
failure to move the resolver mechanism.

### Gate 4 — two-run wall screen

Under accepted idle-host preflight, run two untraced palindromic triplets:

```text
shared authority precursor, default path, sidecar candidate
sidecar candidate, default path, shared authority precursor
```

The disabled/enabled shared pair is the exact mechanism control. The
contemporaneous default path is the primary-goal control. Discard and rerun the
screen if the two default controls differ by more than 5%.

To earn the campaign's five-sample test:

- both candidate samples must beat the official `C0=19,375 ms`;
- both candidate samples must beat their contemporaneous default controls;
- candidate/default median ratio must be at most 0.97;
- candidate must beat the sidecar-disabled shared precursor;
- every sample must complete and execute the expected marker.

If resolver exits collapse but wall does not improve, collect one new
whole-tree profile and either justify Variant 2 from measured footprint costs
or pivot away from shared-unit binding.

### Gate 5 — five-sample retention

Use the parent campaign's alternating five-control/five-candidate method and
bootstrap rule. A retained candidate must:

- have candidate/control median ratio at most 0.97;
- have bootstrap 95% upper bound below 1.0;
- keep Node and CPython guardrails healthy;
- refresh `C`, `D`, and `R` with valid provenance.

### Gate 6 — retained-wave closure

- focused tests green;
- signed native AArch64 Go compile-and-run demo;
- `just conformance-native smoke --workers 4`;
- explicit `go-sync`, `cpython-threading`, and `cpython-subprocess` review;
- untraced Node V8 and CPython guardrails;
- `just ci`;
- DOF presence and scoped cleanup verified;
- ledger, evidence registry, decision log, and `handoff.md` updated.

## Decision tree

- **Resolver collapse and wall win:** promote to five samples and closure.
- **Resolver collapse without wall win:** profile once; attempt Variant 2 only
  if either static footprint or the declared dynamic authority-install path is
  dominant, otherwise pivot to the default path.
- **No resolver collapse:** reject the variant; do not tune unrelated details.
- **Unprovable recovery, ownership, or lifecycle:** reject immediately.
- **Two layouts fail:** mark H004 `REJECT` and select the next hypothesis from a
  refreshed default-path attribution.

The first-ratio milestone and 2.0x destination remain active regardless of this
wave's outcome.

## Implementation boundaries

- No Linux kernel or other GPL implementation source is consulted.
- No executable page becomes writable after signing/loading.
- No global mutable edge hash is added to the translated hit path.
- No active-unit sidecar pointer is installed on every block transition.
- No performance claim comes from traced timing.
- No sidecar code ships on the default path unless the five-sample gate retains
  it.
- Existing rejected spikes remain rejected unless new evidence changes their
  premise.

## Delivery sequence

1. Commit this design without mixing the current experimental worktree.
2. Checkpoint the authority-carrying correctness precursor separately from
   measurement tooling and ledger changes.
3. Write a file- and test-exact implementation plan.
4. Implement Variant 1 red-first through the evidence funnel.
5. Retain, reject, or conditionally authorize Variant 2 from measured results.
6. Refresh attribution after every retained step-function change.
