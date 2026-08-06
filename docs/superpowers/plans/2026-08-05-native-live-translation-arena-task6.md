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

## Amendment 2026-08-05 — fd-backed transport (supersedes the Mach transit)

Task 6C2 proved the Mach memory-entry transport does not survive `fork(2)`
(`task-6c2-report.md` §1): a forked guest child inherits the arena bytes but
no Mach rights, so `CARRICK_DSR_LIVE_ARENA=compiler` failed every
forked-then-exec'd guest `execve` with EIO. The probe-backed replacement
design is `docs/superpowers/specs/2026-08-05-live-arena-fd-transport-design.md`:
two unlinked regular files (the `kernel_arena` idiom), RW alias plus an RX
alias built by `mmap(PROT_READ)` + `mprotect(R|X)` with per-alias
`set_maximum` clamps, transported as inherited fds through the existing
`HostFdFlagTransaction`. The full fork + SETEXEC lifecycle, dual-alias W^X,
coherence, revocation, and a 10.8 µs successor attach (7.8–13.4 µs at full V2
geometry) are all probe-proven on this host; the receipts of record are
committed at `docs/perf-results/2026-08-05-fd-transport-probe-receipts.txt`.

**Superseding scope — exactly the transit/adoption mechanics.** In Task 6A's
historical record and Task 6B2's Darwin authority, every mention of memory
entries, transit send rights, registered ports, `mach_ports_register`
vectors, and the three-slot constraint is replaced by fd transport. The same
applies to the *naming* in preflight corrections 1–2: "the Mach control
object" reads as "the shared control object" and "the 64-byte Mach object
header" as "the 64-byte object header" — the substance of both corrections
(borrowed production views, `align_up(64, host_page)` payload base) is
unchanged and still binding. The V2 wire, directory, records, cursors,
claim/token authority, publisher/consumer I-cache rules, B3 geometry and
census thresholds, and the 6B2 exec-successor *proof obligations*
(different-VA adoption, creator READY observation) are NOT superseded — they
re-run unchanged on the new transport. Tasks 6D, 6E, 6F, and 7 keep their
numbering, scope, and gates.

### Task 6T1 — substrate swap: fd-backed objects and aliases

**Files:** modify `crates/carrick-native-darwin/src/live_arena.rs`.

Replace memory-entry creation with unlinked-file backing
(`std::env::temp_dir()`, `O_EXCL`, unlink, single `ftruncate`); build aliases
map→mprotect→clamp→validate; delete `MachSendRight`, `MapJitBootstrap`,
`VmMapping::map_entry`, both `create_*_memory_entry` functions,
`RegisteredPortVector`, `OolPortArray`, `register_port_names`,
`RegisteredPortExecPlan`, `LiveArenaTransitRights`,
`duplicate_transit_rights`, `transit_send_right_user_refs`, and the
`posix_spawnattr_set_registered_ports_np`/`mach_port_get_refs` SPI
declarations. The transit type gains both fd numbers, original fd flags, and
per-fd fstat identity; `LiveArenaTransitV2` (schema/lengths/nonce) is
unchanged. Keep `validate_protections` equality checking as the mandatory
guard against the probed silent-EXEC-strip failure shape.

**Red-first tests:**

- `fd_arena_dual_aliases_execute_published_code` (write via RW, consumer
  invalidate, execute via RX; append to an executed page; overwrite)
- `fd_arena_alias_protections_are_clamped_and_validated` (regions read
  `cur==max` at `rw-`/`r-x`; escalation refused)
- `fd_arena_adoption_rejects_identity_or_flag_drift` (wrong fd, changed
  flags, wrong size, wrong nonce — each named)
- `a_fork_child_inherits_arena_mappings_and_its_fd_transport` — the 6C2
  blocker test inverted: the child holds bytes AND can prepare the exec
  transport
- `fd_arena_teardown_in_fork_child_is_local` — child unwinds its `Arc`;
  parent mappings/fd still live (dissolves the 6C2 §8(a) hazard)

**Gates:** `cargo test -p carrick-native-darwin`,
`cargo test -p carrick-dsr-aarch64` (must be untouched-green), clippy
`-D warnings`, fmt, lint-domains, doc. No runtime-on evidence.

### Task 6T2 — capsule transport swap

**Files:** modify `crates/carrick-runtime/src/native_exec_capsule.rs`,
`crates/carrick-runtime/src/native_darwin.rs`,
`crates/carrick-runtime/src/direct_runner.rs` (call-site types only).

`NativeReexecLiveArenaV2` gains code/control fd numbers, original flags, and
fstat identity; both self-exec call paths add the two arena fds to
`prepared_host_fds` instead of installing a `RegisteredPortExecPlan`; resume
adopts from the inherited fds (validate flags → fstat identity →
`F_DUPFD_CLOEXEC` → map → V2 validation → close transport fds). The two
arena fds enter `prepared_host_fds` **only when the process holds an owned
arena and the capsule payload names one** (the existing both-or-neither
payload/owner consistency check extends to the fd fields); the arena-absent
self-exec path is byte-for-byte unchanged. Delete
`failed_setexec_leaves_the_registered_port_vector_unchanged` and
`failed_setexec_releases_the_duplicated_send_rights` with their subject;
extend the surviving `failed_setexec_restores_the_prepared_fd_flags` to
cover the two arena fds.

**2026-08-05 mechanism note (post-implementation):** the
`POSIX_SPAWN_SETEXEC` spawn path itself dies with the registered ports. Its
`posix_spawnattr_t` carried only the SETEXEC flag and the registered-port
vector, and the arena-absent self-exec already used plain `execve`, so with
no ports to install there is nothing for a spawn to carry. `execve` is now
the ONE self-exec mechanism, which is why this section's test names below
say `exec`, not `setexec`.

**Resolution of the 6C2 §8(b) keep-as-kernel-evidence note:** that note kept
`failed_setexec_leaves_the_registered_port_vector_unchanged` as evidence of
*kernel* behavior for the registered-port vector. This amendment deletes it
anyway, deliberately: its subject (the registered-port transport) dies with
no compatibility path, and under the no-backward-compat rule a test whose
mechanism no longer exists in the tree is exactly the second answer future
readers must not have to reconcile. The kernel fact it recorded survives in
the 6C2 report itself, which is the durable home for evidence about a
retired mechanism.

**Red-first tests:**

- `fork_exec_successor_maps_arena_from_inherited_fds_at_fresh_addresses`
- `forked_child_exec_successor_acquires_creator_ready_record_and_bytes` —
  THE boundary 6C2 proved was never crossed: creator publishes READY, a
  guest-shaped `fork(2)` child host-self-execs, the successor validates and
  executes the creator's bytes and observes a post-exec creator write
- `failed_exec_restores_the_prepared_arena_fd_flags`
- `arena_fds_never_enter_the_guest_fd_table` — the guest-fd-space isolation
  requirement's membership half (design doc "Guest fd-space isolation"): an
  arena-holding guest process's `fd_table` names no arena fd, and the fds'
  steady state is CLOEXEC outside the capsule transit window

**Gates:** serialized capsule family, `RUST_TEST_THREADS=1 cargo test -p
carrick-runtime --lib`, clippy, fmt, lint-domains, doc, `just
test-integration`.

### Task 6C2 (reopened) — completion on the fd substrate

The mechanism-agnostic ownership plumbing from `e58c59b3` (creation point,
`Arc` retention, both `begin_guest_exec` forwardings,
`NativeLiveArenaEntry`) is reused as-is. Replace the
`LIVE_ARENA_COMPILER_BLOCKED` refusal for `Launch`/`Resume` with real
create/adopt; rewrite the two blocked-truth tests
(`launch_creates_one_owned_v2_arena_only_under_compiler_policy`,
`resume_adopts_the_transported_arena_exactly_once`) back to their ownership
assertions.

**Red-first evidence:** the signed smoke that caught the blocker is the red —
today `CARRICK_DSR_LIVE_ARENA=compiler carrick run --exec-backend native
ubuntu:24.04 /bin/sh -c 'echo hi; id -u; uname -m'` refuses with EXIT=125.
Green requires EXIT=0 with output identical to the policy-off arm (the
original hard constraint 2), plus the policy-off and sizing-lane arms
unchanged.

**Gates:** everything in 6T2's list, `just build` (codesigned), the
three-arm signed smoke with `CARRICK_RUN_ID` stamping and `kill.sh` reaping.
Runtime-on compiler *performance* evidence remains forbidden until Task 7
(preflight correction 6 stands; opening the policy for correctness smoke is
this slice's exit criterion, not a perf run).

### Unchanged

Tasks 6D, 6E, 6F, and 7 are not renumbered and not rescoped; they now sit on
the fd substrate. The Task 7 revocation slice must re-prove its
instruction-abort classification predicates on the fd backing (the design
doc's fault-shape receipt: revoked-page execution presents as SIGBUS on this
host).
