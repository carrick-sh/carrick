# Native translation-store monotonic augmentation

- **Status:** approved 2026-08-03
- **Date:** 2026-08-03
- **Scope:** Darwin/AArch64 native (DSR), shipped-default persistent translation
  store
- **Primary gate:** cold `go build`, child CPU first, against an exact
  same-binary augmentation-off control

## 1. Purpose

Carrick's persistent native translation store is retained and default-on, but a
stored translation unit is frozen at its first publication. A process that
loads a sparse unit can replay its recorded blocks, yet every path absent from
that unit is translated privately forever. The store declines a recording claim
as soon as the final files exist, and publication returns `Existing` instead of
combining new blocks with the existing unit.

The result is a store that is persistent but not cumulative. On the primary cold
`go build`, two complete exact censuses at `0ae82a34` found:

- 140/140 process-incarnation coverage in each run, with no flush imbalance or
  malformed records;
- 765,678 and 766,900 private translations;
- 761,465 and 762,688 `segment-repeat` translations inside configured executable
  segments;
- 95,272 and 96,025 distinct contained block starts;
- approximately 666,000 contained translations beyond the first distinct block
  occurrence, or about 87% of private translations; and
- 5.178 s and 5.175 s of measured nested translation time.

The local source receipts are
`target/perf/store-default-confirm/current-xlat-census-v1/` and
`target/perf/store-default-confirm/current-xlat-census-v2/`. Their bound SHA-256
values are:

- v1 `census.json`:
  `b3e1b04f116e79ce96b15d8e28f4d30dd2fa0c2ce265d478699e9cdc4b5e086d`;
- v1 `summary.json`:
  `404bb39cb446068684991a023f6d44dbc7a414ec99d8a344b6023ce64bd90dd5`;
- v2 `census.json`:
  `a887f9cfb0bb8df1ea15152792355770d03d199e8458f27c95e8c9a12765dc06`;
  and
- v2 `mechanism.json`:
  `ac18ae6d1e22ee098c278003486e7b7aed948a1e85451cad1d02632a3d32c6da`.

The causal defect is therefore established: the first publisher fixes a unit's
coverage, later processes cannot augment it, and repeated processes pay again
for contained blocks the current format can represent. A proportional model
puts the theoretical opportunity near 4.5 child CPU-seconds, roughly 18% of the
measured build CPU. That is a projection, not a performance result.

This design makes each translation unit a monotonic union of valid,
demand-observed blocks. It preserves the current native emission tap, keeps all
store coordination out of the translation hot path except one nonblocking claim
per uncovered segment per process, and never changes guest execution based on a
publication outcome.

## 2. Success criteria

The implementation is eligible for retention only if all of the following are
true:

1. A controlled mechanism comparison reduces both `segment-repeat` and total
   private translations by at least 50%, with complete census coverage and no
   new store refusal class.
2. Counterbalanced ABBA with at least eight quads reports candidate/control
   median child CPU at or below 0.90, and the paired 95% bootstrap interval lies
   entirely below 1.0. Workload wall also improves.
3. `compute`, `fs-walk`, `startup`, and the 20-exec workload do not regress by
   more than 3%.
4. The current signed binary passes targeted tests, `RUST_TEST_THREADS=1 just
   ci`, and `just conformance-native smoke` without a candidate-only
   correctness regression.
5. Store races, process exit, guest exec, host crashes, malformed bundles, and
   incomplete core files fail closed to private translation or a diagnostic
   error. None can install unvalidated code or alter guest-visible semantics.

If the mechanism or end-to-end gate fails, remove the runtime candidate and
retain only the design and negative evidence. Carrick's 10.44x official cold
build ratio will not be represented as improved until the real serialized
Carrick-then-Docker lane is rerun.

## 3. Non-goals

- This change does not weaken source identity, page-profile, address-mode,
  translator-ABI, code-digest, or manifest validation.
- It does not record regenerated, self-modified, JIT-on-JIT, or out-of-segment
  code into an executable-image unit.
- It does not add a periodic flush, background thread, blocking store lookup, or
  store lock to the per-block translation path.
- It does not import data from a core file or diagnostic export into the
  persistent store.
- It does not preserve or migrate the two-file `.code` + `.metadata-v5` wire
  format.
- It does not implement eager whole-image translation. A statically reachable
  recursive-descent producer remains a future, separately measured improvement.
- It does not claim that this change alone can close the gap from 10.44x to 3x.

## 4. Chosen architecture

### 4.1 One atomic bundle per translation unit

Replace the current pair of `{stem}.code` and `{stem}.metadata-v5` files with one
`{stem}.unit-v1` file. Bump `TRANSLATOR_ABI_CURRENT`, so the persistent root moves
to a fresh ABI directory. The new reader does not recognize, migrate, or search
for the old pair. The old ABI directory remains inert cache data and is outside
the new authority's 1 GiB cap; this change does not delete it automatically.
Operators may remove it with ordinary cache cleanup after no older Carrick
binary is using it. It is not a compatibility path or an input to the new
store.

One file removes the half-pair state and makes a merged unit one atomic rename.
Readers remain lockless. A reader that opened the old pathname before a merge
pins the old inode and sees the old complete unit. A reader that opens the
pathname after rename sees the new complete union.

### 4.2 Demand augmentation

The producer remains the current native recording tap. When an INITIAL-
generation block inside a configured executable segment is absent from an
attached unit, the process privately translates it exactly as today. On the
first such uncovered block for that segment, the process attempts one
nonblocking recording claim:

- a winner records this block and subsequent eligible uncovered blocks for the
  segment;
- a loser continues private translation without recording and never waits; and
- later misses in the same process/segment do not retry the claim.

The current process records native-tap artifacts only. It does not perform
store reads, merges, repacks, or filesystem writes for each block.

### 4.3 Merge only at process boundaries

Pending candidates are merged on the existing guest pre-exec path and normal
process-exit path. Guest `execve` is a host self-re-exec and does not run normal
`atexit` handlers, so pre-exec publication is mandatory. Publication is
attempted at most once for each process incarnation.

Crash termination may lose that process incarnation's pending suffix. It cannot
damage the authoritative store. The export-only core ABI in section 8 makes the
committed diagnostic prefix recoverable without turning crash recovery into a
store mutation path.

### 4.4 Producer-independent merger

The merger accepts normalized block artifacts, not translator control flow.
Demand recording is its only producer in this change. This boundary allows a
future recursive-descent producer to feed the same validated union operation
without adding a second store format or persistence implementation.

## 5. Unit bundle format

### 5.1 Top-level layout

`unit-v1` is a bounded, little-endian, fixed-width file with these regions:

1. fixed header;
2. serialized key and manifest metadata;
3. offset-indexed block and hot/cold record tables; and
4. concatenated normalized template code bytes.

The fixed header contains:

- a bundle-specific magic distinct from the core-export magic;
- bundle schema version 1;
- header length and exact file length;
- translator ABI;
- metadata offset and length;
- code offset and length;
- block count; and
- SHA-256 of the exact code region.

Every offset and length is checked with overflow-safe arithmetic, required
alignment, containment within the exact file extent, and non-overlap of top-
level regions. Trailing bytes are rejected. Existing caps remain authoritative:
64 MiB maximum template code, 256 MiB maximum decoded/mapped metadata, and the
1 GiB bounded current-ABI store. This workstream does not raise or lower those
caps.

### 5.2 Manifest authority

The manifest carries the exact `TranslationUnitKey`: executable identity,
segment file and guest extents, source fingerprint, native page profile,
address mode, and translator ABI. Its block table is indexed by guest start and
retains every relocation, recovery, PC-map, sensitive-metadata, hot-record, and
cold-record field required to replay the current native template exactly.

The bundle does not carry executable mappings. Its code region is readable
source bytes that are privately copied and relocated into the process's existing
`MAP_JIT` cache, preserving the present copy transport.

### 5.3 Reader

The Darwin store reader opens `{stem}.unit-v1` beneath the already validated
per-user authority with `openat`, `O_NOFOLLOW`, and a regular-file check. It
pins one inode, maps it read-only/private, and validates, in order:

1. magic, schema, exact extent, all ranges, and all caps;
2. the expected complete key and current translator ABI;
3. the code-region digest;
4. deterministic block ordering, unique guest starts, and record ranges; and
5. the existing manifest invariants used before replay.

Any failure returns a named `UnitMissReason` and falls back to private
translation. A listed file is never presumed valid merely because it exists.

## 6. Merge and atomic publication

### 6.1 Canonical normalized artifact

Both a loaded block and a new native-tap candidate decode to one owned,
normalized `StoredBlockArtifact`. It contains the guest start, source extent,
template bytes, relocations, recovery actions, PC maps, and all hot/cold records
needed by `PendingTranslationUnit::pack`. It contains no store path, mapped
pointer, process-local address, or mutable translator state.

This owned form is the sole input to unioning, bundle packing, and core export.
The implementation must not create a second representation solely for the
debugger.

### 6.2 Deterministic union

Under the per-unit exclusive lock, publication performs these steps:

1. Reopen and validate the current final bundle for the expected key.
2. Decode its blocks to normalized artifacts.
3. Revalidate every pending candidate against the key, INITIAL generation, and
   configured segment bounds.
4. Union old and pending artifacts by guest start.
5. Coalesce an exact duplicate only when the entire normalized artifact is
   byte-for-byte equivalent.
6. If the same guest start has different source extent, template bytes, or
   metadata, abort the merge as a conflict and preserve the old final bundle.
7. Sort by guest start and deterministically repack metadata and code. Identical
   input sets must produce byte-identical bundles.
8. Write one mode-0600 temporary in the authority directory, flush and sync the
   file, and preflight that temporary through the production reader.
9. Atomically rename it over `{stem}.unit-v1`, then sync the authority directory.

No published inode is modified in place. A crash before rename leaves the old
bundle authoritative. A crash after rename leaves the new bundle authoritative.
If directory sync reports an error after rename, the complete new inode remains
visible and must not be rolled back or deleted. The caller treats the validated,
visible union as a successful merge and separately increments the named
post-rename durability counter; it does not report a false failed merge that a
later process would retry blindly.

### 6.3 Empty, corrupt, and over-cap cases

- An empty pending set releases its builder lease and performs no publication.
- If no final bundle exists, the valid pending set becomes the first bundle.
- If the final bundle is valid, only its union with pending candidates may
  replace it.
- If the final pathname exists but its bundle is invalid, valid pending
  candidates may replace it as a repair. The outcome is counted as a repair,
  not an ordinary merge; no bytes from the corrupt bundle are trusted.
- If the union exceeds a cap, overflows an offset, or fails reader preflight,
  preserve the old valid bundle and release the lease. Capacity failure loses
  performance only.
- If a same-address conflict occurs, preserve the old valid bundle, emit the
  named conflict counter, release the lease, and continue guest execution with
  its already-generated private block.

Publication never decides whether the current process may execute. All pending
blocks were already emitted privately and used under the normal translator
checks.

### 6.4 Nonfatal publication API

Replace the frozen-store `PublishOutcome::{Winner, Existing, Yielded}` contract
with a merge outcome that distinguishes `Created`, `Merged`, `Unchanged`,
`Repaired`, `Yielded`, and `Refused`, carrying block and duplicate counts where
applicable. A store I/O or validation error remains typed, but the lifecycle
caller consumes it into counters and diagnostics instead of returning a
`DsrError` through guest exec or exit. Claim errors likewise become a lost claim
with a named reason. Store persistence is an optimization: inability to write
it cannot change the current guest's result.

## 7. Claims, concurrency, and fork

### 7.1 Per-process segment state

Each configured segment has this process-local state machine:

`Unseen -> Attached | Uncovered`, then `Attached -> Uncovered`, then
`Uncovered -> ClaimWon | ClaimLost`

- `Unseen`: no lookup has attached a unit for the segment.
- `Attached`: a valid unit is attached; replay hits remain read-only.
- `Uncovered`: an INITIAL in-segment block is absent from the attached unit.
- `ClaimWon`: this process records eligible missing blocks until exec or exit.
- `ClaimLost`: this process does not record for the segment and does not retry.

A missing unit follows the same `Uncovered` transition after the failed load.
An existing unit is no longer a reason to refuse a claim.

### 7.2 Nonblocking builder lease

`claim_recording` remains one nonblocking operation per uncovered
process/segment. Under the existing per-unit `LOCK_EX | LOCK_NB`, the store
examines a mode-0600 builder record containing owner PID, process-incarnation
nonce, creation Unix timestamp in nanoseconds, and the exact unit stem. The
nonce is a fresh random 128-bit value generated after process start or fork
repair. A busy lock returns `Yielded`; no translator thread waits for another
process.

A lease is live only while both conditions hold:

1. its owner PID is live; and
2. its age is below the fixed builder TTL.

PID reuse cannot preserve a lease forever because age is independently
authoritative. A dead or aged owner can be replaced under the unit lock. The
owner releases its lease after successful merge, empty publication, conflict,
capacity refusal, or other completed publication attempt. A hard crash leaves a
stale record for the liveness/age takeover path.

A scope guard releases the lease on every clean return, including I/O and
validation errors. It removes the builder record only while holding the unit
lock and only if PID plus incarnation nonce still match. An aged former owner
can therefore never unlink a successor's lease after takeover.

Sequential publishers always lock, reload the latest final bundle, and merge
against that version. They never merge against the process's earlier mapped
snapshot. Lockless readers and old mappings therefore coexist safely with
monotonic pathname replacement.

### 7.3 Fork semantics

The fork child clears inherited segment claim states, pending chunks, builder
ownership, and its inherited process-incarnation nonce through the existing
native post-fork reset seam. The parent retains its claim and publishes its own
batch. The child may independently encounter an uncovered block and attempt a
fresh claim using a new nonce; it can never publish the parent's inherited
batch.

### 7.4 Required mechanism counters

The existing resolver/profile and exact census surfaces gain these typed wire
counters:

- `shared_augment_claim_won`, `shared_augment_claim_live_lost`,
  `shared_augment_claim_yielded`, `shared_augment_claim_stale_takeover`, and
  `shared_augment_claim_error`;
- `shared_unit_initial_publish`, `shared_unit_merge`, and
  `shared_unit_blocks_added`;
- `shared_unit_duplicate_coalesced`;
- `shared_unit_conflict`;
- `shared_unit_repair`;
- `shared_unit_capacity_refused` and `shared_unit_preflight_refused`;
- `shared_unit_io_failed` and `shared_unit_validation_failed`;
- `shared_unit_empty_release` and `shared_unit_post_rename_sync_failed`; and
- `segment-repeat` outcomes after an attached unit miss.

Counters are emitted per process incarnation and aggregate without double
counting across exec. On a workload with recurring contained blocks, zero
successful merges and zero blocks added is a mechanism error, not a valid empty
result.

## 8. Export-only live/core diagnostics

### 8.1 Separate core ABI

Pending augmentation data has a versioned, `#[repr(C)]` diagnostic ABI rooted
at the `#[used]`, unmangled static symbol `carrick_xlat_pending_core_v1`. It is
not the store wire format and uses a distinct magic. The root describes the
current process incarnation, claim states, unit keys, segment bounds, and a
linked list of pending chunks.

When no segment wins a claim, the cost is the dormant static root only. The
normal translator does not duplicate pending artifacts for diagnostics.

### 8.2 Crash-stable prefix

The canonical pending-candidate storage is append-only chunks. Once linked,
chunks and committed records never move or free before the process's exec/exit
publication boundary. A writer:

1. allocates and fully initializes the next record and its referenced bytes;
2. validates all intra-chunk offsets and lengths; and
3. release-stores the new committed record count.

The same publish-after-initialize rule applies when linking a new chunk. A crash
can omit the one in-flight record, but every earlier committed record remains a
stable prefix. The normal pre-exec/exit publisher reads this same committed
prefix and converts it to `StoredBlockArtifact`; there is no second candidate
copy.

Appends remain serialized by the translator's existing process-state write
lock; the release-published count exists for debugger/core readers, not as a new
multiwriter protocol. Code and metadata reservations are charged before an
append. When either existing per-unit cap would be exceeded, recording stops for
that unit, the already committed prefix remains publishable, and the capacity
counter increments.

### 8.3 LLDB commands and export files

`scripts/carrick_lldb.py` gains:

- `carrick xlat-pending` for a validated human-readable summary; and
- `carrick xlat-pending --output <stem>` for export.

The summary reports process incarnation, claim state, unit keys, segment bounds,
committed record count, and `complete`. Export creates `<stem>.json` and
`<stem>.bin` via mode-0600 temporaries and atomic rename. JSON contains the
summary, source target identity, schema, completeness, the first unreadable
address when incomplete, binary length, and SHA-256 of the exact binary payload.
Source target identity means PID plus process-incarnation nonce for a live
target, core path for a core target, and the matching Carrick Mach-O UUID and
binary SHA-256 in both cases. The binary has its own diagnostic magic/schema and
contains only validated committed normalized records.

The command supports a stopped live process and a full or `modified-memory`
core made with a matching symbol-retaining Carrick binary. It validates the
root magic/schema, pointers, counts, offsets, ranges, and all readable records.
If a core omits a later chunk page, export stops at the first missing address,
writes only the valid committed prefix, and sets `complete=false`. If the root
itself is absent, as expected for a stack-only core, the command refuses the
export and directs the operator to a full or modified-memory core. It never
silently reports an empty pending set for an unreadable root.

There is no importer, replay command, automatic recovery hook, or store
publication option. Renaming the diagnostic payload into the store cannot make
it load because the magics and layouts differ. A core is evidence only.

## 9. Deferred future improvement: eager recursive descent

A future producer may attempt statically reachable translation at image setup:
seed the ELF entry and executable-segment starts, follow direct and fallthrough
edges, and feed discovered normalized artifacts to the same merger. Linear
sweep is explicitly invalid because embedded data and unreachable bytes are not
instructions. Indirect targets, guest-generated code, and self-modifying paths
remain demand-only, so monotonic demand augmentation is required even if eager
production later proves useful.

This future phase is permitted only after the previously specified Phase 0e
measurement reports what fraction of executed block starts recursive descent
discovers. It receives its own startup, dead-code, capacity, and end-to-end
gates. No eager traversal, knob, or placeholder API is part of this
implementation; producer independence in `StoredBlockArtifact` is the only
allowance made now.

## 10. Red-first verification

### 10.1 Bundle and merge unit tests

Before wiring production publication, tests must fail for the missing behavior
and then cover:

- bundle round-trip and deterministic byte-identical encoding;
- rejection of bad magic, schema, ABI, key, digest, extent, offset, alignment,
  ordering, duplicate start, truncation, and trailing bytes;
- disjoint union, exact-duplicate coalescing, same-address conflict, overflow,
  and every capacity boundary;
- corrupt-final replacement from a valid pending set; and
- preservation of the old valid bundle on conflict, over-cap, preflight, or
  temporary-write failure.

### 10.2 Atomicity and concurrency tests

Inject failures before temporary sync, reader preflight, rename, and directory
sync. At every point, a new reader observes either the complete old unit or the
complete new unit, never a partial union. An already-open reader continues to
read the old inode after rename.

Run multiple contenders against one unit and prove:

- one live claim winner and no blocking;
- a busy lock yields;
- stale liveness/age takeover works;
- sequential publishers reload and preserve each other's blocks;
- a losing process changes performance only; and
- a fork child clears the inherited lease, nonce, and batch.

### 10.3 Translator integration tests

Drive the real `try_load_shared_unit` and translation path, not a direct fixture
install. Prove that:

- an absent block in a loaded unit attempts one claim and a winner records the
  current missing block;
- a claim loser does not record;
- subsequent eligible misses join the winner's pending prefix;
- regenerated, non-INITIAL, out-of-segment, and guest-JIT blocks never record;
- guest exec and process exit each publish at most once;
- the next process replays the merged block; and
- replayed execution has the same bytes, relocations, PC maps, recovery actions,
  and guest result as private emission.

### 10.4 Core ABI and LLDB tests

Test a synthetic reader fixture plus a real Darwin process/core fixture. Prove:

- a stopped live process and a real modified-memory core yield the same complete
  committed prefix;
- an in-flight/torn record is excluded while earlier records remain valid;
- missing later pages produce a partial export with the first missing address;
- a stack-only core is refused by name;
- JSON and binary files are mode 0600 and hashes match; and
- no command or API can import or publish the export.

Real core files are ephemeral test products and are not committed.

## 11. Causal mechanism gate

The candidate binary carries the temporary evidence-only hatch
`CARRICK_DSR_STORE_AUGMENT=0`. With augmentation disabled, it uses the same new
ABI, bundle reader, bundle format, private translation, and counters, but does
not claim or merge an attached unit's uncovered blocks. This is the exact
control; it is removed before the retained implementation is finalized.

Create one validated sparse `unit-v1` store snapshot. Before every control or
candidate arm, copy that same snapshot into a fresh explicit
`CARRICK_DSR_STORE_DIR`; do not let one arm inherit another arm's accumulated
merges. Use one current signed binary and the canonical cold `go build` workload.
Never overlap Carrick and Docker phases.

The candidate must show:

- complete process-incarnation census coverage and balanced flushes;
- successful merges and monotonically increasing per-key block counts;
- at least 50% fewer `segment-repeat` outcomes;
- at least 50% fewer total private translations;
- no candidate-only load miss or refusal relative to the exact control, and
  zero conflicts, corrupt-bundle repairs, or capacity refusals in the clean
  workload;
- exact duplicate/conflict/repair/capacity counts consistent with the test
  store; and
- exact replay semantics on the targeted multi-process probe.

Failure of any first five conditions stops the performance gate. A traced run
is mechanism evidence only, never an official timing result.

## 12. Performance retention and correctness gates

### 12.1 End-to-end ABBA

Run counterbalanced host-environment ABBA for at least eight quads against the
same restored sparse snapshot used by the mechanism gate. Child CPU-seconds are
retention authority. Retain only when:

- median candidate/control child CPU is at most 0.90;
- the paired 95% bootstrap interval lies entirely below 1.0; and
- median workload wall improves.

Record host state, thermal state, core-placement information available to the
harness, and power source. AC versus battery is metadata only and is not an
inclusion or exclusion criterion. Carrick and Docker remain strictly serialized.

### 12.2 Regression screens

With the retained candidate and a current signed binary, run the canonical
workload spread. `compute`, `fs-walk`, `startup`, and 20-exec may not regress by
more than 3%. Any apparent regression is rerun against current HEAD before
attribution.

Run targeted crate tests, `RUST_TEST_THREADS=1 just ci`, and
`just conformance-native smoke`. Compare conformance differences with the same
current binary's augmentation-off control and with current HEAD; the native
baseline overlay is not treated as mature authority. Tier D remains unchanged
and default-off.

### 12.3 Official ratio refresh

After the temporary control hatch is removed, rebuild and verify the exact
signed artifact, including its hash, signature, and `__dof_carrick` section.
Run at least five canonical Carrick repetitions, then the native-arm64 Docker
oracle in a separate phase, using the established cold-build semantics. Update
the official ratio only from that clean comparison.

The evidence record binds source commit, binary hash, signing state, workload
manifest, store-seed hash, census hashes, schedule, raw run artifacts, summary
statistics, and command receipts. Update the relevant `docs/perf-results/`
artifact and `handoff.md` whether the candidate is retained or killed. Measured
results and projected ceilings remain explicitly separate.

## 13. Implementation boundaries

The work is intentionally one plan but has separable units:

1. **Portable bundle codec and normalized artifact** in
   `carrick-dsr-aarch64`: no filesystem or Darwin dependency.
2. **Darwin atomic store and lease protocol** in `carrick-native-darwin`: one
   validated inode, deterministic merge, nonblocking coordination.
3. **Translator/lifecycle integration** in `carrick-dsr-aarch64` and the
   existing native Darwin exec/exit/fork seams: claim once, append, flush once.
4. **Export-only core ABI and LLDB reader**: the same pending chunks, a separate
   diagnostic wire, no store authority.
5. **Typed evidence and retention gate**: existing census/profile surfaces and
   canonical performance harnesses.

No unrelated translator refactor, second native driver wiring point, or new
standalone performance tool belongs in this change.
