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

Darwin requires the code object's named entry to originate from a nominal
`MAP_JIT` RWX mapping: controlled tests on this host returned
`KERN_PROTECTION_FAILURE` for PROT_NONE, RW, RX, and plain
`mach_vm_allocate` backings, while only RWX `MAP_JIT` produced an entry that
could later map both RW and RX. Creation therefore uses a private,
constructor-only RWX `MAP_JIT` bootstrap containing no published code and
unmaps it before the arena escapes. The live arena itself exposes only the
separate RW and RX aliases; it never retains a W+X mapping.

The two send rights consume two of Darwin's three registered-port slots. The
third registered slot is preserved exactly as found and remains reserved. No
pointer crosses a process boundary. Every shared reference is an integer offset
plus a checked length.

The outer 64 bytes of each object remain the authenticated Mach transport
header, but executable payload does not begin at byte 64. The code payload base
is `align_up(64, host_page)`. Code is packed into permanently owned 64 KiB
chunks, exactly four Darwin host pages each, so Task 7 can revoke one exact
chunk without affecting another source group. `code_offset` is relative to the
payload base and the process view adds the base exactly once.

The control object stores the protocol itself. Immediately after its outer
header is an immutable, cacheline-aligned `LiveArenaControlDirectoryV2` with an
atomic initialization state, schema/translator ABI, repeated nonce, exact
block/group/chunk geometry, code payload capacity, and HOT/COLD
bases/capacities. Separate cacheline-aligned `next_chunk`, HOT, and COLD cursors
precede a 262,144-entry block table, a 4,096-entry source-group table, and 1,024
chunk descriptors; HOT and COLD byte pools follow at checked alignment. The
creator initializes every atomic and record while private and Release-publishes
the directory. An adopter Acquire-loads initialization and rejects any nonce,
schema, ABI, count, stride, chunk size, alignment, overlap, bounds, or reserved
bit mismatch before constructing a borrowed typed view. Production records and
cursors are never a Rust-owned `Box`.

The arena-free cold-build census measured 85,525 exact blocks, 407 source
groups, 36,341,884 raw code bytes, 684,200 aligned HOT bytes, 24,681,640
aligned COLD bytes, and a 5,536-byte maximum block. It rejected the original
one-16-KiB-page-per-block layout, which would consume 1,401,241,600 code bytes.
The V2 first slice is 1,024 exclusive 64 KiB chunks (64 MiB), 1 MiB HOT, and
32 MiB COLD. Exact next-fit preflight used 781..785 chunks. A fresh V2 census
and production-hash simulation must satisfy the predeclared load, refusal,
headroom, and order-independent packing bounds before runtime ownership is
enabled.

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

The serialized V2 native-exec capsule carries only `LiveArenaTransitV2`
geometry, nonce, and schema identity. It never serializes Mach port names
because names are task-local. There is no V1 reader, alias, or compatibility
branch.

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

The live schema adds `LIVE_ARENA_SCHEMA_V2` to the digest domain. The vertical
slice accepts only `CodeGeneration::INITIAL`, trusted non-sensitive blocks, and
the compiler unit selected by an explicit experiment policy. Production
retention broadens by exact unit identity, never by basename or guest PC alone.

### Wire layout and state machine

Both objects begin with fixed-width, little-endian headers. Control records are
cache-line aligned and contain no Rust enum, pointer, `usize`, or process-local
address.

`LiveBlockRecordV2` is exactly 128 bytes and `repr(C, align(64))`. Its fixed
offsets are: state `0`, owner PID `4`, unit digest `8`, code SHA-256 `40`, guest
start `72`, source page `80`, code/HOT/COLD offsets `88/96/104`, and
code/entry/HOT/COLD lengths `112/116/120/124`. Code is nonempty, four-byte
aligned, and wholly contained in one 65,536-byte chunk.

A source group is keyed by exact `(unit_live_digest, 16 KiB source_page)` and
has `EMPTY/BUILDING/ACTIVE/FAILED`, immutable identity, canonical `NO_CHUNK`,
current-chunk index, and a packed expansion claim. A group publishes ACTIVE
without allocating code. Each chunk descriptor has `EMPTY/ACTIVE/ABANDONED`,
one immutable group owner, and one bounded four-byte-aligned cursor. Chunks are
never reused, reassigned, reclaimed, or shared between groups.

The only shared states are:

```rust
pub const LIVE_BLOCK_EMPTY: u32 = 0;
pub const LIVE_BLOCK_BUILDING: u32 = 1;
pub const LIVE_BLOCK_READY: u32 = 2;
pub const LIVE_BLOCK_FAILED: u32 = 3;
```

The block table probes at most 16 slots using the V2 domain-separated hash over
`(unit_digest, guest_start)`. The group table independently probes at most 16
slots using the V2 domain-separated hash over `(unit_digest, source_page)`.
Different-key block READY/FAILED and group ACTIVE/FAILED records continue the
bounded probe after Acquire-validating their published key. BUILDING, same-key
FAILED, CAS loss, malformed state, or 16-probe exhaustion returns private
immediately.

Lookup is two-phase. `acquire_ready_or_miss` is read-only and runs above decode;
EMPTY never CASes. Only after the complete decoded INITIAL interval is proven
supported, non-sensitive, non-exclusive, selected, and wholly inside one 16 KiB
source page may `claim_eligible` revalidate the same-domain generation
observation, resolve/create the group, revalidate again, and CAS the block. A
generation change before group mutation changes no shared state; a later change
performs no block CAS. Task 6B's reserve-time and pre-write checks still apply.

The unique block winner prepares exactly once and learns exact lengths before
allocating code. Invalid or greater-than-64-KiB code falls back before any chunk
cursor grows. Otherwise it tries the ACTIVE current chunk with at most eight
CAS attempts. `NO_CHUNK` or full capacity uses one no-wait expansion election;
the winner reserves its exact bytes in a private descriptor before
Release-publishing descriptor ACTIVE and then current chunk. Expansion losers
fail only their block and translate privately. Handled allocation failures
publish ABANDONED and clear expansion; process death may strand at most one
chunk/expansion but never permits stealing or reuse.

HOT/COLD remain checked append-only eight-byte-aligned reservations with at
most eight CAS attempts. The winner writes and validates every exact extent,
rechecks generation, flushes the code range, and obtains an unforgeable
claim-bound completion token. Only consuming that token may perform the sole
`Release` store of block READY. Consumers Acquire-load group, descriptor,
current-chunk, and block publication before reading their immutable fields, and
locally invalidate exact RX before execution. Release/acquire is not an
instruction-cache operation.

### Emit once, directly

The winner must assemble exactly once and publish that prepared byte stream
exactly once into the shared target. It must not emit to the private cache and
then copy, reconstruct, merge, serialize, or replay. Preparation validates the
shared artifact, encodes its pointer-free HOT/COLD metadata once, and exposes
the exact code/HOT/COLD lengths before consuming the publish claim. The caller
then reserves exact extents, constructs the claim-bound cache, optionally
prebinds eligible links while the source is still `Prepared`/`BUILDING`, and
consumes the prepared object in one cache publication. The published block
exposes no mutable source sites.

The AArch64 prepared emitter accepts a temporary `&mut TranslationCache` only
for that final consuming publication, but
`BorrowedLiveJitRegion<'arena>` intentionally cannot escape as the by-value
`JitRegion` retained by `TranslationCache::from_region`: doing that would erase
the arena lifetime and unique-writer reservation authority. The Darwin
integration therefore owns a lifetime-bound, private
`LiveArenaTranslationCache<'arena, 'claim>` bridge. Its private constructor
joins a checked borrowed RW/RX view with the Task-2 reservation capability and
its inner cache targets exactly that range. It does **not** expose `&mut
TranslationCache` through a public closure or HRTB: safe callback code could
use `mem::replace` to extract the lifetime-erased cache. Instead its sole
private operation consumes `PreparedSharedInitial`, invokes the emitter inside
the Darwin module, verifies exact cache consumption, and drops the inner cache
before returning no address-bearing emitter value. The bridge and all
published address handles remain dominated by the process-level arena owner.

The protocol crate owns the sole READY store while the downstream Darwin crate
owns the mappings, and Rust has no friend visibility across that dependency
edge. The narrow cross-crate seam is therefore one documented `unsafe`
certification method on the reserved portable claim. Its contract requires
exact claim-derived mapped code/HOT/COLD slices from the same branded process
view, no live mutable aliases, completed publisher I-cache maintenance, and the
current INITIAL-generation observation. An opaque proof derived from the real
`PreparedSharedInitial` after prebinding supplies the expected code/HOT/COLD
lengths and digests, so valid-looking corruption cannot be re-hashed and
blessed as a new truth. The portable method compares the mapped bytes to that
proof, exactly decodes both metadata streams, rechecks generation, and returns
a private-field, non-cloneable `LiveArenaWrittenBlock<'view>`. Safe raw portable
claims cannot construct that token. `claim.publish(token)` verifies the
storage, process-view brand, record identity, and exact extents before the sole
READY Release store.

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

- local entry = local RX base + `code_offset` + `entry_offset`;
- a shared `PublishedBlockMetadata::LiveArena` handle for lazy PC-map/recovery
  decode;
- direct-link target authority that distinguishes immutable shared sources
  from patchable private sources;
- a source-page/group hint plus authoritative descriptor-table enumeration for
  revocation;
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
64 KiB RX chunk owned by every locally executable exact group for that guest
page, including multiple chunks and multiple unit digests, and marks those
task-local chunks revoked. The shared descriptor table is authority; a local
catalog may accelerate but cannot omit later cross-process expansion. It does
not mutate shared control state and does not revoke another process's alias.

A host fault is classified as a stale shared-code trap only when all of these
are true:

- ESR exception class is instruction abort from lower or current EL (`0x20` or
  `0x21`);
- PC and FAR both fall inside the same active task-local revoked chunk;
- the revoked-chunk catalog yields a validated guest PC/recovery record;
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

NATIVEPERF gains exact per-process counters.

**2026-08-06 — RECONCILED WITH THE LANDED NAMES.** None of the
`live_arena_*` names below exist in code: Task 6F (`028d3508`) built this
surface first and its names are the ones in `ResolverStats` /
`ProfileSnapshot` / the NATIVEPERF frames, so they win under the
no-two-answers rule. This list is kept as the DESIGN INTENT with each entry
mapped to what shipped; do not reintroduce a `live_arena_*` spelling.

| Design name | Landed name (frame) | Status |
|---|---|---|
| `live_arena_ready_hits` | `live_ready_hits`, plus `live_index_hits` for a repeat serve out of this process's own index (`live-lane`) | landed, split finer |
| `live_arena_publish_wins` | `live_publish_wins` (`live-lane`) | landed |
| `live_arena_publish_losses` | `live_publish_adoptions` (race lost, still served) + `live_fallbacks[arena_cas_lost]` (race lost, fell back) | landed, split finer |
| `live_arena_private_fallbacks` | `live_fallbacks[17]`, summed (`live-fallback-a/b/c`) | landed, expanded to 17 named classes |
| `live_arena_building_fallbacks` | `live_fallbacks[arena_building]` | landed |
| `live_arena_validation_refusals` | `live_fallbacks[{arena_invalid_record, arena_unknown_state, unresolved_entry}]` | landed |
| `live_arena_code_bytes` | `live_code_bytes` (`live-bytes`) | landed |
| `live_arena_metadata_bytes` | `live_hot_bytes` + `live_cold_bytes` (`live-bytes`) | landed, split by stream |
| `live_arena_shared_direct_links` | `live_links_prebound` + refusal split `live_links_prebind_unbound_state` / `live_links_prebind_unbound_reach` (`live-bytes`) | landed with the prebind call site (2026-08-06) |
| `live_arena_gateway_links` | `live_links_out_of_reach` (`live-bytes`) | landed |
| `live_arena_revoked_chunks` | `live_revoked_chunks` (`live-revoke`) | landed in Task 8 |
| `live_arena_stale_instruction_aborts` | `live_stale_instruction_aborts` (`live-revoke`) | landed in Task 8 |

`live_arena_shared_direct_links` — a link bound between two SHARED blocks —
**landed 2026-08-06** when the winner-publication prebind call site was wired
(`LiveArenaProcessView::publish_winner` → `prebind_ready_targets`, between
`claim.reserve` and `reserved.publish`, mutating only staged bytes). It
counts as the triple beside the private→live pair in the `live-bytes` frame:
`live_links_prebound` (bound at publication), `live_links_prebind_unbound_state`
(target not an acquirable READY record — the forward-edge sacrifice this
design accepts), and `live_links_prebind_unbound_reach` (the emitter's
±128 MiB refusal; structurally zero while the code payload is 64 MiB). The
6F-seam-1 / Task 8 §1a gap is closed.

The export surface is read-only. `carrick_lldb.py` prints arena headers,
process-local RX/RW ranges, READY records, revoked chunks, and the translated
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
