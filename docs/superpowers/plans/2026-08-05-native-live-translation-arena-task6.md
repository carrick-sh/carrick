# Native live translation arena — Task 6 substrate and integration plan

> **Status:** authoritative Task 6 execution split. This refines Task 6 in
> `2026-08-05-native-live-translation-arena.md`; it does not narrow the
> performance goal or permit runtime-on evidence before Task 7.

**Goal:** make the completed portable protocol, Darwin Mach objects, exec
transport, and prepared shared emitter one real cross-process READY path. Every
consumer must observe the same records/cursors/bytes through a process-local
view, while every miss or invalid state falls through immediately to the
unchanged private translator.

**Proven bases:** Task 4 is complete through `1cb7489e`; Task 5 is complete
through `e6661fe5`; Task 6A is independently review-clean through `a7fa2883`.
Task 6B1 is independently review-clean through `0bb50612`; Task 6B2 is
independently review-clean through `c77e291a`; Task 6C1 sizing/policy is
independently review-clean through `322b3c7d`. The source-group V2 Task 6B3
replacement below is the active slice.

## Preflight corrections

The preflight proved these are prerequisites, not optional cleanup:

1. `LiveTranslationArena` currently owns a process-private record `Box` and
   three process-private cursors. Production state must instead be a borrowed
   view over the Mach control object. Any heap owner is test-only.
2. The existing 64-byte Mach object header is not the code payload base. Code
   payload begins at `align_up(64, host_page)`. V2 64 KiB chunk bases remain
   physically host-page-aligned while four-byte block reservations pack inside
   them. Logical code offsets are relative to that payload base.
3. Task 6A first established an authenticated mapped directory/cursors/record
   table and aligned HOT/COLD pools. The Task 6C1 census later disproved its
   per-block code allocator. Task 6B3 replaces that wire with V2 `next_chunk`,
   HOT, and COLD cursors; 262,144 x 128-byte block records; 4,096 source-group
   records; and 1,024 exclusive 64 KiB chunk descriptors. Logical offsets stay
   relative to their named pool bases.
4. READY cannot be published from a caller-owned `Vec`. A unique claim may
   publish only an unforgeable completion token produced after exact mapped
   writes, mapped-byte/hash validation, metadata validation, source-generation
   recheck, and publisher I-cache flush.
5. Each consumer performs a local I-cache invalidate of the acquired READY RX
   range before installing it. Release/acquire ordering is not an I-cache
   operation.
6. Runtime-on compiler evidence is forbidden until Task 7 revocation and exact
   stale-instruction-abort recovery are complete. Shared INITIAL code omits its
   generation guard, so a write after the pre-READY recheck must revoke that
   task's matching RX chunks.

Capacities remained explicit through Tasks 6A–6B. Task 6C1 measured 85,525
exact current-workload blocks, 407 exact source groups, 36,341,884 raw code
bytes, 684,200 aligned HOT bytes, 24,681,640 aligned COLD bytes, and a
5,536-byte maximum block. The old page-per-block allocator would require
1,401,241,600 code bytes and is rejected. Task 6B3 must pass a fresh V2 census,
production-hash probe simulation, and objective capacity thresholds before
Task 6C2 enables ownership.

## Task 6A — mapped protocol, authenticated layout, and claim lifecycle

> Historical completed-slice record: the V1 names and three-cursor layout below
> describe the independently accepted substrate at `a7fa2883`. Task 6B3
> replaces that wire entirely; they are not a retained production path.

**Files:**

- Modify `crates/carrick-dsr-aarch64/src/live_arena.rs`
- Modify `crates/carrick-native-darwin/src/live_arena.rs`
- Modify Task 3/4 lifecycle tests only if needed for mapped-view proof

**Red tests:**

- `mapped_views_share_claim_state_and_append_cursors`
- `object_headers_do_not_overlap_protocol_payloads`
- `logical_zero_code_offset_is_actual_host_page_aligned`
- `record_hot_cold_ranges_fit_exactly`
- `adopt_rejects_control_layout_or_translator_abi_mismatch`
- `adopt_rejects_bad_nonce_stride_alignment_or_overlap`
- `dropped_publish_claim_release_publishes_failed`
- `cross_view_claim_authority_is_rejected`

**Implementation:**

- Add fixed-width, const-asserted `LiveArenaControlDirectoryV1` and
  `LiveArenaControlLayout`. The directory repeats nonce/schema/translator ABI,
  records count/stride/range, cursor offsets, code payload capacity, and
  HOT/COLD bases/capacities. Its initialization state is an atomic with one
  Release publication by the creator and one Acquire validation by adopters.
- Place the three `AtomicU64` cursors on independent cache lines, then the
  fixed record table at 64-byte alignment, then 8-byte-aligned HOT and COLD
  pools. Round the complete control object to the host page with checked
  arithmetic and reject every malformed or overlapping range before forming a
  typed reference.
- Replace production `Box<[LiveBlockRecordV1]>` storage with
  `LiveTranslationArenaView<'a>` over borrowed initialized atomics/records.
  Claims carry the view identity and references; they never own or drop mapped
  records. A heap-backed owner may exist only under `cfg(test)` and must create
  the same wire layout through the same initializer.
- Change Darwin construction to capacity/layout input, compute
  `code_payload_base = align_up(64, host_page)`, initialize control storage
  before exporting rights, and validate it on adoption. Keep the small raw
  transport fixture test-only rather than retaining a second public arena
  constructor.
- Make unconsumed publish and reserved claims RAII-fail their BUILDING record.
  Keep the current three-cursor append-only policy for this slice, but count
  and document bounded leaked extents when a later cursor reservation loses a
  race or exhausts capacity.

**Gates:** focused portable/Darwin tests, full two crates, compile-fail lifetime
tests, clippy `-D warnings`, format, and diff check. Commit as one mapped-layout
change and obtain independent review before Task 6B.

## Task 6B — claim-bound direct-write transaction and process view

Land this as two independently reviewed slices. **6B1** owns the portable
publication authority: process-view branding, mapped-write permit, exact
metadata/digest/generation certification, owned READY record, deletion of
`LiveBlockPublication`, and the sole token-gated READY store. **6B2** owns the
Darwin authority: `Arc`-backed process view, exact local range resolution,
private claim-bound cache, safe mapped transaction, owned acquisition, local
I-cache invalidation, and the different-VA exec-successor proof. The split is a
review boundary, not permission for a second or temporary READY path.

**Files:**

- Modify `crates/carrick-dsr-aarch64/src/{emit.rs,artifact_spike.rs,live_arena.rs}`
- Modify `crates/carrick-native-darwin/src/live_arena.rs`
- Modify `crates/carrick-runtime/src/native_exec_capsule.rs` for the real
  creator/adopter different-VA lifecycle proof if required

**Implementation:**

- Add `LiveArenaProcessView` owning the concrete `Arc<DarwinLiveArena>` plus
  validated raw geometry. Its native lookup/reservation wrappers keep raw
  portable claims private. It alone converts logical record extents into local
  code RW/RX and control HOT/COLD ranges and brands capabilities with a private
  process-view identity plus shared nonce.
- Add non-escaping `LiveArenaTranslationCache<'arena, 'claim>`. Construct it
  only inside the Darwin module from `&LiveArenaProcessView` and `&mut
  LiveReservedPublishClaim`; derive the exact payload-adjusted range internally
  and privately create the non-owning `TranslationCache`. Do not expose a
  public closure/HRTB or `&mut TranslationCache`: safe callback code could
  `mem::replace` and extract its lifetime-erased addresses. Its sole private
  operation consumes `PreparedSharedInitial`, calls the emitter internally,
  verifies exact cache use, returns no address-bearing emitter value, and drops
  the cache before the claim borrow ends.
- Copy exact prepared HOT/COLD bytes only through claim-bound slices. Publish
  prepared code once into the exact cache. Require exact cache use, validate
  the mapped code/HOT/COLD digests against an opaque proof derived from the
  actual `PreparedSharedInitial` after prebinding, exact-decode/consume both
  metadata streams, recheck source generation, flush publisher I-cache, and
  return an unforgeable `LiveArenaWrittenBlock<'view>` token. Because the
  portable crate owns the
  READY store and the downstream Darwin crate owns mapped storage, use one
  documented `unsafe` portable certification method whose contract requires
  the exact claim-derived mapped slices, same process-view brand, no live
  mutable aliases, and completed flush. Safe callers have no token constructor.
  Only `claim.publish(token)` may Release-store READY.
- Replace borrowed `ValidatedLiveBlock<'a>` retention with an owned,
  offset-only `ValidatedLiveBlockHandle` containing copied immutable
  record/extents/digest plus view identity. The process view revalidates and
  resolves it. A consumer hashes mapped RX, validates exact HOT shape, locally
  invalidates RX, then exposes process-local entry/cold metadata.
- Same-view prebinding exists only while both Prepared and unique BUILDING
  claim are alive. It accepts a process-local target capability constructed by
  the same process view from acquired READY, checks AArch64 reachability, and
  mutates only staged prepared bytes. Published blocks expose no source sites.

**6B1 tests:** safe caller bytes have no READY route; mapped-write permit and
token cannot escape their claim/view; a token cannot publish another claim;
partial/short or corrupted code/HOT/COLD cannot certify; metadata requires
exact consumption; a generation change refuses completion; a failed attempt
cannot retry and drops to FAILED; READY owns a copied offset-only record.

**6B2 tests:** the transaction writes only exact reserved ranges; the private
cache cannot escape or cross threads; distinct process views reject each
other's capabilities; same-object mappings at different VAs share
records/cursors/bytes; publisher and consumer each invalidate their own exact
RX range; consumer re-hashes RX and exact-validates HOT; exact W^X and payload
boundary hold; the real exec successor observes creator READY and bytes.

## Task 6B3 — replace per-block code allocation with source-group V2 chunks

The 6C1 census makes the original V1 end state impossible: one 16 KiB code page
per exact block would reserve 1.40 GiB. Replace it, without a compatibility
path, before runtime ownership is enabled.

- Replace the portable directory/records/handles, Darwin transit/adoption,
  runtime live-arena capsule field, and affected outer capsule frame/types with
  V2 names and `carrick-live-arena-v2`; delete every affected V1 reader, alias,
  and accessor.
- Use 262,144 128-byte block records, 4,096 source-group records, and 1,024
  permanently owned 64 KiB chunk descriptors over a 64 MiB code payload, 1 MiB
  HOT, and 32 MiB COLD. A group is exact `(unit_live_digest, 16 KiB
  source_page)`, publishes ACTIVE with `NO_CHUNK`, and allocates its first chunk
  only after a unique block winner prepares exact code.
- Keep READY lookup read-only above decode. Only a supported, non-sensitive,
  non-exclusive INITIAL plan whose complete decoded interval fits one source
  page may enter `claim_eligible`. Revalidate the same-domain generation before
  group mutation and again immediately before block CAS; retain Task 6B's later
  reserve-time and pre-write checks.
- Use one no-wait expansion election for first allocation and rollover. Reserve
  the winner's exact code before Release-publishing descriptor ACTIVE and then
  current chunk. Every cursor has an eight-CAS maximum; expansion has one CAS;
  no `fetch_update`, spin, steal, reset, reclaim, or chunk reassignment exists.
  Handled post-index failures publish ABANDONED and clear expansion. Owner death
  may strand one group/chunk/expansion but cannot make partial bytes executable.
- Acquire-load group, descriptor, current-chunk, and block states before their
  immutable fields. READY validation proves exact group/descriptor ownership,
  one-chunk containment, four-byte code alignment, and all existing B2
  hash/HOT/generation/W^X authority.
- Re-run the arena-free census against V2. Production V2 block/group hashes,
  fixed orders and 100 deterministic shuffles must keep block refusals at most
  0.1%, group refusals zero, block/group load at most 50%/25%, observed chunks
  at most 90%, aligned HOT/COLD at most 85%, and the per-group
  order-independent next-fit upper bound at most 1,024 chunks. Change constants
  before C2 if any threshold fails.

Red-first tests cover the V2-only API, exact layout offsets, two-phase
generation/source-span authority, group/block collisions, ACTIVE/`NO_CHUNK`,
first/rollover contention, Release/Acquire publication, every handled/death
phase, bounded cursor exhaustion, multi-chunk/multi-digest Task-7 enumeration,
different-VA exec adoption, and exact capacity fixtures. Keep runtime lookup and
ownership disabled. Independently review the complete replacement before
commit `feat(dsr): pack live code by source page`.

## Task 6C1 — exact-key policy and arena-free sizing (complete)

Commit `322b3c7d` adds exact `0|compiler` policy, fails compiler closed before
guest entry until C2, configures exact live keys without enabling the store,
and exports lengths from the real Task-5 prepared output. Its 27-receipt census
and aggregate hash are the accepted V1 preflight evidence; B3 must repeat them
under V2.

## Task 6C2 — runtime ownership, transport, and exact-key configuration

**Files:**

- Modify `crates/carrick-runtime/src/{native_darwin.rs,native_exec_capsule.rs}`
- Modify `crates/carrick-dsr-aarch64/src/{mapped_memory.rs,translator.rs}`

Create once in the initial container process when
`CARRICK_DSR_LIVE_ARENA=compiler`; retain the owner for the complete run loop;
transport it on both self-exec call paths; use the adopted owner on resume; and
remove the `_live_arena` discard. Include live policy in shared-image segment
collection and exact `TranslationUnitKey` configuration even when the
persistent store is disabled. Use only the V2 constants accepted by B3's fresh
census and simulation.

## Task 6D — READY lookup, winner publication, lazy metadata, and indexes

At the top of an authoritative INITIAL miss, perform the read-only exact READY
lookup. READY validates actual mapped code/HOT/current generation and installs
without touching the private cache. On a miss, plan once, reject regenerated,
cross-page, sensitive/exclusive/unsupported shapes, then enter B3
`claim_eligible`: first generation check, group resolution, second generation
check, and block CAS. Only that unique block winner prepares once, reserves
exact extents, runs the Task 6B transaction, then installs through the same
READY consumer. BUILDING/FAILED/CAS loss/corruption/capacity are immediate
private fallbacks.

Add explicit live publication kind/owned handle, live address index,
source-page/group hint with descriptor-authoritative chunk enumeration, and
lazy exact COLD decode modeled on unit metadata.
Factor common bookkeeping, but do not route a live block through private
publication logic that mutates source links or the private cache.

## Task 6E — target authority and gateway routing

Give each process view one stable local target authority over its RX payload.
Carry explicit publication kind/authority into gateway entry and indirect
publication. Live targets are flavor 0; private trusted targets remain flavor
1. Private sources may patch to live targets. Live sources never enter mutable
incoming/pending indexes. Register the live RX payload in the executable range
catalog and keep ownership dominated by the process view.

## Task 6F — metrics and pre-Task-7 gates

Add typed resolver counters and every manual mapping for READY hits, publish
wins/losses, BUILDING/private fallbacks, validation refusals, live code/HOT/COLD
bytes, and shared prebound links. `cache_used_bytes` remains private-only.

Run full crate/runtime tests, compile-fail tests, clippy/format/diff, and a
signed correctness smoke with the experiment still runtime-disabled. Then
complete Task 7 before enabling the compiler policy or running performance
ABBA. Task 8 owns USDT/DTrace and official measurement.
