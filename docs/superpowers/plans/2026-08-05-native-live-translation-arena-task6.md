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
Task 6B is the active slice.

## Preflight corrections

The preflight proved these are prerequisites, not optional cleanup:

1. `LiveTranslationArena` currently owns a process-private record `Box` and
   three process-private cursors. Production state must instead be a borrowed
   view over the Mach control object. Any heap owner is test-only.
2. The existing 64-byte Mach object header is not the code payload base. Code
   payload begins at `align_up(64, host_page)` so logical 16 KiB-aligned code
   reservations remain physically page-aligned. Logical code offsets are
   relative to that payload base.
3. The control object needs an authenticated directory, three separately
   cacheline-aligned cursors, the fixed 131,072 x 192-byte record table, and
   aligned HOT/COLD pools. Logical HOT/COLD offsets are relative to their own
   pool bases.
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
   task's RX slab.

Capacities remain explicit parameters through Tasks 6A–6B. Task 6C adds a
sizing census over Task 5 prepared outputs before selecting first-slice
production constants. The current private 64 MiB cache is not evidence: the
live allocator page-aligns each block, and the measured compiler has 8,319
blocks.

## Task 6A — mapped protocol, authenticated layout, and claim lifecycle

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

**Files:**

- Modify `crates/carrick-dsr-aarch64/src/{emit.rs,artifact_spike.rs,live_arena.rs}`
- Modify `crates/carrick-native-darwin/src/live_arena.rs`
- Modify `crates/carrick-runtime/src/native_exec_capsule.rs` for the real
  creator/adopter different-VA lifecycle proof if required

**Implementation:**

- Add `LiveArenaProcessView` owning the concrete `Arc<DarwinLiveArena>` plus
  validated raw geometry. It alone converts logical record extents into local
  code RW/RX and control HOT/COLD ranges and brands capabilities with a private
  process-view identity plus shared nonce.
- Add non-escaping `LiveArenaTranslationCache<'arena, 'claim>`. Construct it
  only from `&LiveArenaProcessView` and `&mut LiveReservedPublishClaim`; derive
  the exact payload-adjusted range internally; privately create the non-owning
  `TranslationCache`; expose it only through a closure/HRTB. Dropping the guard
  ends the claim borrow so the claim may then be consumed.
- Copy exact prepared HOT/COLD bytes only through claim-bound slices. Publish
  prepared code once into the exact cache. Require exact cache use, validate
  mapped code digest and exact metadata decode/consumption, recheck source
  generation, flush publisher I-cache, and return an unforgeable
  `LiveArenaWrittenBlock` token. Only `claim.publish(token)` may Release-store
  READY.
- Replace borrowed `ValidatedLiveBlock<'a>` retention with an owned,
  offset-only `ValidatedLiveBlockHandle` containing copied immutable
  record/extents/digest plus view identity. The process view revalidates and
  resolves it. A consumer hashes mapped RX, validates exact HOT shape, locally
  invalidates RX, then exposes process-local entry/cold metadata.
- Same-view prebinding exists only while both Prepared and unique BUILDING
  claim are alive. It accepts a process-local target capability constructed by
  the same process view from acquired READY, checks AArch64 reachability, and
  mutates only staged prepared bytes. Published blocks expose no source sites.

**Tests:** completion token cannot be forged; partial/short writes cannot READY;
cache/claim/view cannot escape or cross; same-object mappings at different VAs
share records/cursors/bytes; code/HOT/COLD corruption refuses READY; per-process
I-cache flush occurs; exact W^X and payload boundary hold; real exec successor
observes creator READY.

## Task 6C — runtime ownership, transport, exact-key configuration, and sizing

**Files:**

- Modify `crates/carrick-runtime/src/{native_darwin.rs,native_exec_capsule.rs}`
- Modify `crates/carrick-dsr-aarch64/src/{mapped_memory.rs,translator.rs}`

Create once in the initial container process when
`CARRICK_DSR_LIVE_ARENA=compiler`; retain the owner for the complete run loop;
transport it on both self-exec call paths; use the adopted owner on resume; and
remove the `_live_arena` discard. Include live policy in shared-image segment
collection and exact `TranslationUnitKey` configuration even when the
persistent store is disabled. Add counters for prepared block count and
`sum(align_up(code_len, host_page))`, HOT bytes, and COLD bytes; select and
record explicit checked first-slice capacities from that census before an
enabled workload.

## Task 6D — READY lookup, winner publication, lazy metadata, and indexes

At the top of an authoritative INITIAL miss, query the exact configured key.
READY validates actual mapped code/HOT/current generation and installs without
touching the private cache. BUILDING/FAILED/CAS loss/corruption/capacity are
immediate private fallbacks. A winner plans once, rejects regenerated or
sensitive/exclusive/unsupported shapes, prepares once, reserves exact extents,
runs the Task 6B transaction, then installs through the same READY consumer.

Add explicit live publication kind/owned handle, live address index,
source-page slab index, and lazy exact COLD decode modeled on unit metadata.
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
