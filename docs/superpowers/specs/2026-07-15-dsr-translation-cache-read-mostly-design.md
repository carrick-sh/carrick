# DSR Translation-Cache Read-Mostly Lock — Design

**Goal:** Remove the residual host-condvar contention left after the memory-lock
retirement (Phase 2). Pinned (rate-truthful per-event dtrace + atos, not
snapshots) to the DSR translator's single global `Mutex<ProcessState>`
(`native_darwin/dsr/mod.rs:89`), taken on EVERY block-translation entry
(`ThreadTranslator::translate`, `:1292` `self.process.state.lock().translate(...)`).
Phase 2 made the guest syscall path concurrent; now every thread's block
translation serializes on this one Mutex — ~1.17M psynch cvwait+cvsignal, ~80%
of the residual per the 208-sample rate profile.

## Measured basis
- Phase 2 (RwLock memory lock) already landed: psynch 2.34M→1.17M (-50%),
  wall 19.28s→16.83s (-12.7%), sys 21.83s→17.94s (-17.8%), back-to-back same
  load on the Go W1 reducer. Evidence: campaign ledger 2026-07-15.
- Residual pin: 208 per-event `psynch_cvwait` ustack samples, atos'd with the
  per-process slide (from the `thread_start` frame). Dominant caller:
  `RawMutex::lock_slow ← ThreadTranslator::translate (dsr/mod.rs:1292) ←
  prepare_entry (:1545) ← prepare_dsr_entry (native_darwin.rs:1606)`. Rate
  distribution ~80% DSR translate lifecycle (translate/prepare_entry/
  finish_exit_profiled), remainder background TLS crypto. NOT the memory-lock
  writers (mmap hypothesis refuted), NOT `exclusive_sequences`, NOT guest futex
  (those dominate SNAPSHOTS by long-park bias, not the RATE).

## What the lock protects
`ProcessState` (dsr/mod.rs:92): `cache: TranslationCache` (JIT code buffer),
`blocks: BTreeMap<(GuestVa,CodeGeneration),CacheVa>` (the block lookup table),
`pending`, `stats`/`reported_stats: ResolverStats`, `sensitive`, `unsupported`,
`published: Vec<PublishedBlock>`, `dependencies: PageBlockDependencies`,
`publications: ConcurrentPublicationIndex` (already "Concurrent"), `profiling: bool`.

`ProcessState::translate(tid, memory, guest)`:
1. `invalidate_page(source_page, generation)` — returns stale blocks; REMOVES
   them from `blocks` (mutation) — but only when the page generation changed;
   a NO-OP for a stable/current page.
2. `stats.add(CacheLookups)` — only when `profiling` (off in perf runs).
3. `self.blocks.get(&key)` — cache HIT lookup (read-only); returns a `CacheVa`
   (Copy address, not a borrow into the map).
4. On HIT: return `TranslationResult{outcome: BlockIndexHit, ...}` — read-only.
5. On MISS: translate the block, emit into `cache`, insert into `blocks`/
   `pending`/`sensitive`/`published` — mutation.

So a warm-page cache HIT is effectively read-only (stable page + present key +
profiling off). Misses and stale pages mutate.

## Target design

`ProcessTranslator.state: Mutex<ProcessState>` → `RwLock<ProcessState>`.

`ThreadTranslator::translate` gets a two-phase structure:
1. **Read fast-path.** `let g = state.read();` — if the source page is CURRENT
   (a read-only `dependencies` check: the recorded generation matches, no stale
   blocks) AND `g.blocks` contains `(guest, generation)`, return the cached
   `CacheVa` as a `BlockIndexHit`. Fully concurrent across threads. Drop `g`.
2. **Write slow-path.** Otherwise `let mut g = state.write();` and run the
   existing `translate` (invalidate + lookup + translate + insert). Re-check the
   cache under the write guard first (another thread may have translated it
   between the read drop and the write acquire — a benign, cheap re-check that
   avoids duplicate translation).

Method receivers: the read fast-path needs a `&ProcessState` method
(`cached_block(guest, generation) -> Option<CacheVa>` that does the
current-page + `blocks.get` check with NO mutation). The existing `translate`
stays `&mut self` for the write path. `stats` mutation stays in the write path
(or, if a hit must bump a profiling counter, use interior-mutable atomics —
but since profiling is off in perf runs, keeping stats on the write path and
simply not counting read-fast-path hits when profiling is on is acceptable IF
we instead count them via an atomic; decide in the plan, but never let a
profiling build mutate `ProcessState` under a read guard).

## Correctness argument
- A writer (`.write()`) excludes all readers, so a translation/insert or a
  stale-page invalidation cannot race a concurrent hit lookup — the exact
  invariant the Mutex enforced.
- The read fast-path returns a `CacheVa` (Copy) — no reference into `blocks`
  escapes the read guard, so a later writer that mutates `blocks` cannot
  invalidate a returned value's backing (the CacheVa points into the JIT code
  buffer, whose lifetime is governed by the generation/invalidation protocol,
  unchanged here).
- The read fast-path's "page current" check must be a true read (no mutation).
  If the page is stale, it MUST fall to the write path (which performs the
  actual invalidation) — never return a stale block.
- Publication/linking (`publications`, `pending`) that mutate stay on the write
  path.
- Compiler backbone: `state.read()` yields `&ProcessState`; the mutating
  `translate`/insert methods are `&mut self`, so they cannot be called under a
  read guard — a misclassification fails to compile.

## Risks
- **Executing a freed/wrong block** if the read fast-path returns a block whose
  generation is stale. Mitigation: the current-page check is the same
  generation gate `translate` already uses; the read path returns a hit ONLY
  when the page is provably current. Adversarial review + the atomic/futex/
  thread stress gate + a real multithreaded translation workload.
- **Duplicate translation** if two threads miss the same block concurrently
  (both take the write path serially; the second re-checks under the write
  guard and finds the first's block — no duplicate). Cheap re-check required.
- **Profiling stats under a read guard** — keep stats mutation off the read
  path (write-path only, or interior-mutable atomics). Never mutate
  `ProcessState` fields under `.read()`.
- **`invalidate_page` on the read path** — it mutates; the read fast-path must
  NOT call it. It must do a read-only currency check and defer any actual
  invalidation to the write path.

## Verification
- Red-first unit tests: a warm cache hit resolves under a shared `&ProcessState`
  (would not compile if it needed `&mut`); a stale page falls to the write
  path; concurrent misses don't duplicate.
- The native atomic/futex/thread stress gate (10x each) + a real multithreaded
  guest (the Go reducer) — identical output/status.
- Re-measure: the psynch amplification (residual should drop) and untraced
  wall/CPU vs the Phase-2 baseline (16.83s), back-to-back same load. Record
  honestly; if it doesn't move, re-pin before claiming a win.

## Deferred
- Per-thread translation caches / sharded block map (bigger; only if the
  RwLock read-fast-path leaves residual write contention on cold-heavy
  workloads where misses dominate).
