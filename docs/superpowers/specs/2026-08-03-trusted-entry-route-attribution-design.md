# Trusted-entry route attribution design

**Date:** 2026-08-03  
**Scope:** Darwin/AArch64 native DSR, diagnostic-only  
**Status:** approved design, pending implementation plan

## Purpose

The current shipped-default profile puts emitted JIT execution at 46.505% of
all cold-build CPU. Within matched JIT samples, one three-part block-entry
sequence accounts for 26.23%:

1. materialize the block's expected generation in physical x17;
2. publish it to `DsrContext::generation`; and
3. reload guest x17 from its context slot.

Multiplying two separately captured shares projects that sequence at about
12.2% of all build CPU. That is large enough to investigate, but not yet large
enough to optimize blindly. Three paths reach the same trusted entry today:

- the generation guard's successful fall-through;
- a patched direct link; and
- a flavor-1 indirect-cache hit.

The next decision depends on which route pays the sequence. Direct-link-only
work is not justified if indirect hits dominate; changing the common sequence
is unnecessarily risky if one route dominates. This diagnostic will separate
the three routes without adding a counter, atomic operation, probe, or context
store to the hot path.

This is attribution, not a performance candidate. Its traced wall time is
never product evidence.

## Constraints

- The switch is exact `CARRICK_DSR_TRUSTED_ROUTE_SPLIT=1`; absent or any other
  value is byte-for-byte the current emitter path.
- The diagnostic must exercise the default-on persistent translation store,
  including replayed blocks.
- It must not read from or write to the user's normal persistent-store
  namespace. A dedicated, initially empty `CARRICK_DSR_STORE_DIR` is required.
- All three measured route sequences must contain identical instruction words.
  Only the following branch to the common block body may differ.
- Direct-link invalidation, generation validation, guest register state,
  recovery metadata, and guest-visible behavior must remain unchanged.
- Sampling output must fail closed on zero route samples, missing snapshots,
  malformed ranges, overlapping route spans, any DTrace drops, or incomplete
  guest process retirement.
- The capture remains diagnostic and perturbing. Only same-instrument route
  shares and instruction residency are citable.
- No Tier-D behavior, eager full-image translation, guest ABI relaxation, or
  production-default change is in scope.
- The switch and its support code are removed after the route decision and its
  durable evidence are committed.

## Approaches considered

### 1. Inline route copies with an isolated persistent store — selected

Emit three adjacent copies of the trusted-entry sequence. Guard fall-through
enters the first, patched direct links enter the second, and flavor-1 indirect
hits enter the third. Every copy branches to the same first body instruction.
The copies stay next to the block, minimizing the instruction-cache distortion
that an out-of-line trampoline bank would introduce.

The normal unit wire already records the first trusted-entry offset and the
baked generation. The other offsets are deterministic from the shared
sequence-word helper and therefore need no new persistent format. Because an
old unit contains only one copy, the diagnostic runner requires a dedicated
empty store root, warms that root under the diagnostic switch, and then traces
the same root. Normal ABI-8 content is never consulted or contaminated.

### 2. Post-publication shadow stubs — rejected

Two stubs could be appended after each block is published, avoiding any unit
wire concern. They would be remote from the destination body and add a branch
away and back on direct and indirect arrivals. That changes instruction-cache
locality differently by route, exactly the quantity this experiment is trying
to compare.

### 3. Hot route counters — rejected

A counter, context store, USDT probe, or atomic increment immediately names
the routes, but it also adds work to every block entry. This path executes
millions of times and prior probes on similarly hot paths materially changed
system time. A plausible count would not be trustworthy.

Apple Processor Trace could answer the question without code changes, but the
host currently has Processor Trace disabled in Developer Tools. Enabling a
system security capability is unnecessary when the bounded route split can
answer the question inside Carrick.

## Emission design

The emitter gains one shared helper that renders the trusted-entry sequence
from `CodeGeneration`. The normal path calls it once and preserves today's
words and offsets. The diagnostic path calls it three times, proving equality
before publication.

Each diagnostic route has this shape:

```text
<materialize expected generation into x17>  # identical per route
str x17, [x28, #CTX_GENERATION]              # identical per route
ldr x17, [x28, #1128]                        # identical per route
b common_body                                # route-local displacement
```

The materialization remains narrow: the number of `movz`/`movk` words is
derived from the actual generation, just as it is today. Let `S` be the number
of sequence words including the store and load. The route stride is
`(S + 1) * 4` bytes, including the final branch. From the recorded first
trusted offset, publication derives the direct entry at `+stride` and the
indirect entry at `+2*stride`.

The common body begins after all three copies. Every route executes the same
sequence and exactly one unconditional branch. This deliberately amplifies
the sequence equally for a clean sampling ratio; it is why diagnostic wall
time cannot be cited.

Normal emission, artifact recording, and unit replay all use the same helper.
The persistent wire remains unchanged. A replay whose three derived sequences
are not word-identical is rejected before any route address is published.

## Routing and invalidation

Publication records a typed `TrustedRouteEntries` value beside the existing
trusted-entry map:

```rust
struct TrustedRouteEntries {
    fallthrough: CacheVa,
    direct: CacheVa,
    indirect: CacheVa,
    sequence_bytes: u32,
}
```

The map is populated only under the diagnostic switch and cleared at every
existing translator reset.

- The guard reaches `fallthrough` by ordinary control flow.
- `trusted_target` selects `direct` for direct-link patching.
- `publish_indirect_target` publishes `indirect` in the flavor-1 cache entry.
- Flavor-0 indirect entries and blocks without a trusted entry are unchanged.
- The existing reverse direct-link index still records the guest target page;
  code writes sever the patched source exactly as they do now.
- Each route's recovery metadata maps every sequence and branch word to the
  block's guest start with `RestoreGuestX17`. An asynchronous signal or fault
  at any diagnostic word therefore lowers through the existing recovery path
  instead of becoming an unindexed JIT PC.

No generation check is removed. Guard fall-through has just performed it;
direct links retain the existing eager severing contract; flavor-1 indirect
hits retain their inline `ldar` validation before entering the diagnostic
copy.

## Capture and report flow

The existing `native-shape-census.d` PC histogram remains the sampling
instrument. No new D program is needed.

`CARRICK_DSR_CODE_SNAPSHOT_DIR` snapshots add route spans for each published
block:

```text
guest start, generation,
fallthrough [start,end), direct [start,end), indirect [start,end),
common body
```

The spans cover only the identical trusted sequence; the artificial branch is
reported separately. Snapshot publication validates alignment, strict range
ordering, containment in the dumped cache, and byte equality across all three
sequence spans.

A Rust-owned `carrick debug trusted-route-census` command joins the DTrace PC
histogram to the snapshots. It emits a versioned JSON report containing:

- trace and snapshot SHA-256 identities;
- total PC samples and DTrace drop/error counts;
- matched, missing-PID, and missing-range samples;
- sequence samples for fall-through, direct, and indirect routes;
- artificial branch samples per route;
- each route's share of trusted-sequence residency;
- observed sequence bytes and block count;
- estimated total-CPU opportunity using an explicit, receipt-bound JIT-share
  input; and
- every validation failure rather than silently skipping it.

The command exits nonzero for zero route samples, any overlap or byte mismatch,
missing snapshot coverage, a nonpositive JIT-share input, or a trace reporting
drops. Python is not extended; the new report and its schema live in Carrick.

## Diagnostic store protocol

The capture uses a newly created directory beneath the run's evidence
directory. It sets `CARRICK_DSR_STORE_DIR`,
`CARRICK_DSR_TRUSTED_ROUTE_SPLIT=1`, and the diagnostic-only
`CARRICK_DSR_CODE_SNAPSHOT_DIR` on the host; every other performance control
is unset. The persistent-store enable variable remains unset, exercising the
shipped default.

1. Prove the directory is empty.
2. Run one untraced warmup cold build to populate route-split units.
3. Record the store authority inode, payload count, and size.
4. Run the traced cold build against the same store.
5. Record the post-run store identity and reject an authority change.
6. Retain the store manifest, not the potentially large payload files, with
   the evidence receipt.

The normal `~/.carrick/native-units/abi-8` store is neither read nor modified
by this diagnostic. The warmup is excluded from every reported sample.

## Testing and gates

Implementation follows red-first TDD:

1. exact switch parsing: default/off is the current one-entry shape, exact
   `1` produces three routes;
2. emitted word identity across all route sequences and correct common-body
   branch targets;
3. native emission and persistent replay derive identical route addresses;
4. direct links target only the direct entry;
5. flavor-1 indirect publication targets only the indirect entry;
6. generation changes still sever direct links and make stale indirect hits
   miss;
7. every route PC has valid guest mapping and recovery;
8. snapshot validation rejects overlap, out-of-range spans, and unequal words;
9. the Rust census parser rejects zero events, drops, malformed PC rows,
   missing PIDs, and invalid JIT-share inputs;
10. the diagnostic store runner refuses a nonempty starting directory.

The signed live gate requires:

- focused AArch64 DSR and Darwin-native tests;
- persistent replay word identity;
- one successful untraced warmup and one successful traced cold build;
- `BUILD_OK`, zero DTrace drops/errors, and complete process retirement;
- route spans for native-emitted and replayed blocks; and
- `RUST_TEST_THREADS=1 just ci` before any diagnostic implementation commit is
  treated as usable.

## Decision rule

The report answers attribution only. A route-specific optimization advances
only when:

1. two independent clean captures agree on the dominant route within five
   percentage points;
2. that route's measured sequence residency, multiplied by the current
   receipt-bound total-CPU JIT share, projects at least 10% of end-to-end CPU;
3. the proposed change removes work rather than weakening a generation,
   recovery, or guest-register invariant; and
4. the optimization can be tested with the diagnostic switch removed.

If no route clears the 10% opportunity gate, the trusted-entry work stops and
the campaign moves to the next amplified guest operation. If a route clears
it, its production candidate gets a separate design, correctness gate, and
untraced ABBA campaign. No timing result from this diagnostic promotes code.
