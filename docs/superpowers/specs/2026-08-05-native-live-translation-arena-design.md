# Native Live Translation Arena Design

**Date:** 2026-08-05
**Status:** Approved for a compiler-unit vertical slice
**Backend:** Darwin/AArch64 native (DSR) only
**Controller:** `handoff.md` and `2026-08-02-performance-roadmap.md`

## Goal

Make an immutable translation emitted by one native guest process directly
executable by later fork/exec siblings without replaying or re-emitting its
instructions. The first retained slice must improve controlled cold `go build`
child CPU and wall time by at least 10%, preserve native-backend correctness,
and remain a non-regrettable step toward the 3x goal.

This is a live container-lifetime cache, not ahead-of-time compilation. Full
eager translation remains a future improvement. Tier D remains default-off.

## Measured Opportunity

The current shipped-default run is 8,254 ms under Carrick versus 811 ms under
native-arm64 Docker, or 10.1776x. On the compiler image:

- 27 compiler processes performed 646,234 private translations.
- 221,274 translations were served by the current persistent-store replay.
- Compiler processes account for about 81% of workload CPU.
- 478,720 compiler translations, 74.08%, had already occurred in a compiler
  that fully exited before the consuming compiler started.
- 568,472 compiler translations, 87.97%, overlapped any earlier-started
  compiler.
- The conservative completed-before opportunity is 62.4% of all workload
  translations.
- Compiler translation costs 4.441 seconds: 1.814 seconds decode, 2.511 seconds
  emission, and 0.709 seconds publication.

The compiler unit itself contains 8,319 trusted blocks over 167 guest source
pages, 4,067,544 emitted code bytes, 15,188 direct links, 1,016,886 PC-map
entries, and 747,175 recovery entries. Only six blocks are sensitive. Every
trusted entry begins 44 bytes after the private generation guard. Of 15,170
eligible links, 9,406, or 62.00%, target the same unit.

The opportunity is therefore large enough for a 10% end-to-end slice, but only
if sharing removes work instead of adding a second assembly, merge, or replay
phase. Monotonic unit augmentation previously cut translations by 56% while
regressing child CPU 7.28% and wall time 27.86%; that result is the controlling
negative evidence.

## Proven Darwin Mechanism

Disposable live experiments established all lifecycle primitives needed by
this design:

- A Mach memory-entry right survives Carrick's real fork plus host self-exec
  when registered through `mach_ports_register` and recovered with
  `mach_ports_lookup`.
- The exec successor can map the object at an unrelated address.
- A parent writer alias and a child RX alias remain coherent: code first
  returned 42, then returned 43 after the parent published replacement bytes
  and invalidated the instruction cache, without a child remap.
- `mach_vm_protect(PROT_NONE)` revokes only the calling task's RX alias. A
  child and grandchild trap while the parent continues executing the same
  physical code.
- LLDB classified the exact stale-slab abort as an instruction abort with
  `PC == FAR` inside the revoked range and ESR exception class `0x20`.
- The real fork/exec proof preserved a three-element registered-port vector
  `[arena_port, 0, 0]`, mapped at a fresh address, executed 42, and observed
  43 after parent publication.

This closes the old shared-arena kill tests. The rejected design assumed a
fork-inherited, fixed-address `MAP_JIT` mapping and process-specific embedded
addresses. This design transports a memory-entry right across exec, maps a
fresh per-process RX alias at any address, and executes only the position-
independent trusted suffix. The rejected `mprotect` claim concerned Darwin's
original `MAP_JIT` mapping; this design applies `mach_vm_protect` to a distinct
RX Mach alias, which the live test proved revocable.

## Architecture

There is one container-lifetime `LiveTranslationArena` with two memory objects:

1. an append-only code object, mapped writable by publishers and RX by every
   consumer;
2. an append-only metadata/control object, mapped read-write by every process.

The two send rights consume two of Darwin's three registered-port slots. The
third registered slot is preserved exactly as found and remains reserved. No
pointer crosses a process boundary. Every shared reference is an integer offset
plus a checked length.

The arena is an optional accelerator. Private translation remains the complete
correctness path. A missing arena, a full arena, an incompatible key, an owner
death, a torn record, a regenerated page, or any validation failure immediately
falls back to private translation. No arena state can block a guest process.

### Authority and lifetime

The container's initial Carrick process creates both memory objects. Fork
children inherit mappings. Before a fork child invokes Carrick's host self-exec,
it mints fresh send rights for both inherited objects and registers the complete
three-slot port vector. The exec successor looks up the vector, validates both
objects, maps fresh aliases at arbitrary addresses, and clears/deallocates the
transit rights after adoption.

`mach_ports_register` replaces the task's full vector, so the transaction must:

1. call `mach_ports_lookup` and retain every existing slot;
2. replace only Carrick's typed code/control slots;
3. register all three slots together;
4. restore the original vector if `execve` returns;
5. deallocate every temporary right on either success or rollback.

The serialized native-exec capsule carries only `LiveArenaTransitV1` geometry,
nonce, and schema identity. It never serializes Mach port names because names
are task-local.

### Exact identity

An arena unit is keyed by the existing `TranslationUnitKey` digest, which
already binds:

- executable identity;
- segment file offset and length;
- guest VA start and length;
- full source fingerprint;
- native page profile;
- address mode and host bias;
- translator ABI.

The live schema adds `LIVE_ARENA_SCHEMA_V1` to the digest domain. The vertical
slice accepts only `CodeGeneration::INITIAL`, trusted non-sensitive blocks, and
the compiler unit selected by an explicit experiment policy. Production
retention broadens by exact unit identity, never by basename or guest PC alone.

### Wire layout and state machine

Both objects begin with fixed-width, little-endian headers. Control records are
cache-line aligned and contain no Rust enum, pointer, `usize`, or process-local
address.

```rust
#[repr(C, align(64))]
pub struct LiveBlockRecordV1 {
    pub state: AtomicU32,
    pub owner_pid: AtomicI32,
    pub unit_key_digest: [u8; 32],
    pub guest_start: u64,
    pub source_page: u64,
    pub code_offset: u64,
    pub code_len: u32,
    pub trusted_offset: u32,
    pub hot_offset: u64,
    pub hot_len: u32,
    pub cold_offset: u64,
    pub cold_len: u32,
    pub code_sha256: [u8; 32],
}
```

The only shared states are:

```rust
pub const LIVE_BLOCK_EMPTY: u32 = 0;
pub const LIVE_BLOCK_BUILDING: u32 = 1;
pub const LIVE_BLOCK_READY: u32 = 2;
pub const LIVE_BLOCK_FAILED: u32 = 3;
```

The lookup algorithm is deliberately wait-free:

```rust
match record.state.load(Ordering::Acquire) {
    LIVE_BLOCK_READY => validate_and_consume(record),
    LIVE_BLOCK_EMPTY if claim_with_compare_exchange(record) => publish_once(record),
    LIVE_BLOCK_EMPTY | LIVE_BLOCK_BUILDING | LIVE_BLOCK_FAILED => PrivateFallback,
    _ => PrivateFallback,
}
```

The winner reserves disjoint append-only code and metadata extents, writes and
validates them, flushes the code range, writes every record field, then performs
the sole `Release` store of `READY`. A consumer's `Acquire` load of `READY`
orders all preceding bytes. A publisher that dies in `BUILDING` strands only
that record; consumers never wait, steal, or execute it. Arena exhaustion sets
the record to `FAILED` and uses the private path.

### Emit once, directly

The winner must assemble exactly once into the shared target. It must not emit
to the private cache and then copy, reconstruct, merge, serialize, or replay.
`TranslationCache::from_region` already permits the emitter to target a
borrowed `JitRegion`; the Darwin arena supplies a per-reservation region whose
exec base is the local RX alias and write base is the local RW alias.

Shared emission omits the 44-byte absolute generation guard and enters at the
existing trusted suffix. The census proves the remaining instructions are
position-independent across processes:

- gateway and host bias are loaded from `DsrContext`;
- direct branches encode a displacement within the same local code object;
- the only current replay relocations are generation-address and expected-
  generation guard fields, both absent from the trusted suffix.

The emitter must prove that the stripped template contains no remaining
process relocation before publication. Any new translator ABI shape that
violates that rule fails closed and bumps `TRANSLATOR_ABI_CURRENT`.

### Immutable direct links

READY shared code is immutable. A process may never run `patch_code_word` on a
shared source block.

Before publishing a new block, the winner may bind a direct link only when its
target is already READY in the same arena and the final displacement is
reachable. The branch word is written into the still-BUILDING source block.
Every other link retains the emitter's gateway stub permanently. Later
publication of the target does not patch an older READY source.

This sacrifices some of the measured 62% same-unit link opportunity in the
first slice, but avoids executable-byte races. A future immutable page-level
finalization or side-table branch scheme can recover the missed links if
profiles prove them material; it is not part of this slice.

### Process-local catalog

After validating a READY record, the consumer constructs process-local
metadata:

- local entry = local RX base + `code_offset` + `trusted_offset`;
- a shared `PublishedBlockMetadata::LiveArena` handle for lazy PC-map/recovery
  decode;
- direct-link target authority that distinguishes immutable shared sources
  from patchable private sources;
- a source-page to RX-slab index for revocation;
- an address-ordered shared range catalog for recovery, tracing, and core
  inspection.

The shared block then enters the existing authoritative `blocks`,
`published_blocks`, dependency, trusted-entry, and pending-target machinery.
Pending links from private sources may patch to a shared target. Pending links
from shared sources remain stubs.

### Mutation and stale-code recovery

`PageGenerationTable` remains the semantic authority. A guest write that
changes an executable source page still advances its generation. In the same
task, Carrick additionally calls `mach_vm_protect(PROT_NONE)` for every active
shared RX slab indexed to that guest page and marks those task-local slab
descriptors revoked. It does not mutate shared control state and does not
revoke another process's alias.

A host fault is classified as a stale shared-code trap only when all of these
are true:

- ESR exception class is instruction abort from lower or current EL (`0x20` or
  `0x21`);
- PC and FAR both fall inside the same active task-local revoked slab;
- the slab catalog yields a validated guest PC/recovery record;
- the mapped guest source page has a non-INITIAL current generation.

The handler reconstructs the guest snapshot, resumes at the mapped guest PC,
and privately translates the current generation. Any missing predicate remains
a real host fault. Data aborts, arbitrary `PROT_NONE` mappings, unregistered
ranges, and mismatched FAR/PC are never consumed.

Unmap, replacement mapping, exec teardown, fork repair, and every host-exposed
guest write route through the same source-page revocation seam. Fork children
inherit revoked mappings and rebuild their process-local catalog before guest
execution. An in-process guest exec drops the old catalog and maps/attaches the
new unit identity; a host self-exec adopts the transported arena first.

### Failure and rollback

The arena is installed transactionally. Before the first READY record, every
failure unmaps and deallocates the candidate. After READY publication, the
arena may remain attached, but a failing process disables its own consumer and
uses private translation. There is no repair path that rewrites READY code.

The experiment is controlled by one temporary evidence switch,
`CARRICK_DSR_LIVE_ARENA=0|compiler`, default `0` until the retention gate. If the
slice wins, the switch and compiler-only selection are removed as the path
becomes the single shared-unit implementation. If it misses the 10% gate, the
runtime candidate is removed; the design and negative evidence remain.

## Observability and Debugging

NATIVEPERF gains exact per-process counters:

- `live_arena_ready_hits`
- `live_arena_publish_wins`
- `live_arena_publish_losses`
- `live_arena_private_fallbacks`
- `live_arena_building_fallbacks`
- `live_arena_validation_refusals`
- `live_arena_code_bytes`
- `live_arena_metadata_bytes`
- `live_arena_shared_direct_links`
- `live_arena_gateway_links`
- `live_arena_revoked_slabs`
- `live_arena_stale_instruction_aborts`

The export surface is read-only. `carrick_lldb.py` prints arena headers,
process-local RX/RW ranges, READY records, revoked slabs, and the translated
guest PC for a selected cache PC from either a live process or a core. There is
no importer and no debugger mutation command.

The DTrace profile records arena lifecycle and block-state outcomes through
Carrick USDT. A zero-event capture is an error. Same-instrument comparisons are
attribution only; untraced ABBA CPU seconds remain retention authority.

## Correctness Gates

The vertical slice is not eligible for performance retention until it passes:

1. pure wire/state-machine tests, including corrupt bounds and owner death;
2. Darwin live alias coherence and task-local revocation tests;
3. real fork plus host self-exec port-vector preservation;
4. sensitive-block private fallback;
5. source mutation, `mprotect`, `munmap`, remap, fork, in-process exec, and
   host self-exec invalidation tests;
6. exact instruction-abort classification, with data-abort and foreign-range
   negative controls;
7. shared-to-private, private-to-shared, shared-to-shared, indirect branch,
   signal, and fault-recovery execution tests;
8. `RUST_TEST_THREADS=1 just ci`;
9. native smoke and applicable conformance probes on the current signed binary.

## Performance Gate

Use the quiet-box cold `go build` lane with one current signed binary and an
ABBA schedule, at least eight samples per arm. Carrick and Docker phases remain
serialized. Compare:

- live arena off, persistent store on;
- live arena compiler slice on, persistent store on.

Retention requires all of the following:

- child CPU geometric-mean ratio at most 0.90 with confidence interval below
  1.00;
- wall-time geometric-mean ratio at most 0.90 with confidence interval below
  1.00;
- the mechanism counters show READY hits replacing private translations and
  no material BUILDING wait or retry term;
- compute, filesystem, startup, and 20-exec sentinels regress by no more than
  3%;
- workload-spread correctness and timing remain healthy.

If either primary metric misses 10%, remove the candidate runtime path before
starting another optimization. If it passes, delete the old per-process replay
path rather than carrying two production implementations, remeasure the
official scoreboard, and broaden the same arena by exact unit identity.

## Future Improvements

- Amortize a full translation up front when the workload and measured startup
  budget justify it. The live JIT-on-JIT protocol remains necessary even then.
- Recover immutable direct-link coverage with page-level finalization or a
  side-table branch scheme if profiles show permanent gateway stubs are large.
- Compact or reclaim arena space between containers. The first version is
  append-only and bounded.
