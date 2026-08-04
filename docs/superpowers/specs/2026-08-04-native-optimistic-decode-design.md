# Native optimistic decode outside the process translation lock

**Status:** Proposed; architecture approved in discussion, awaiting review of this written design.

## Objective

Reduce Darwin/AArch64 native cold-build CPU by moving fresh basic-block decoding out of the process-wide `ProcessState` writer while preserving the existing single-writer contract for translation-cache mutation, direct-link patching, artifact/shared-store publication, invalidation, fork, and exec.

This is an incremental JIT optimization. Eager whole-image translation remains a future improvement because Carrick still needs this path for JIT-on-JIT and other dynamically discovered code.

## Context

The retained published-block lock split removed the old read-side `ProcessState` contention and improved total child CPU by 8.50% in a controlled eight-quad ABBA. The remaining sampled `psynch_cvwait` stack is now concentrated in:

```text
parking_lot::RawRwLock::lock_exclusive_slow
ThreadTranslator::translate_read_mostly
```

The fresh translation path holds the process-wide writer across both pure decode and state mutation. Existing phase counters attribute about 10.52% of total CPU to decode, 14.26% to emit, and 3.71% to publication. Decode is the safest meaningful portion to make concurrent because `BlockPlan` is owned data and `plan_block_with_segments` reads guest memory but does not mutate the translation cache.

The current official clean default wall ratio is 10.1776x Docker. This candidate is one non-regrettable step toward 3x; it is not expected by itself to close that gap.

## Constraints

- Correct guest behavior and invalidation semantics are immovable.
- The translation cache remains single-writer. Its bump cursor, emitted bytes, metadata, direct links, and publication indexes are not made concurrent by this change.
- Persistent artifact and shared-unit hits must remain ahead of fresh decode so a hit never pays decoding cost.
- Tier D remains default-off.
- No compatibility path or duplicate diagnostics schema is retained; this repository owns its ecosystem.
- No new persistent synchronization object is added, so fork and exec retain their existing synchronization model.
- The implementation must support incrementally discovered and self-modifying code. Eager whole-image translation is explicitly deferred.

## Chosen design

Use optimistic pure decode followed by an authoritative locked recheck and single-writer commit.

The path becomes:

```text
thread/published fast-path reads
        |
        v
first ProcessState writer acquisition
  - generation observation and invalidation
  - authoritative block recheck
  - shared-unit lookup/replay
  - artifact lookup/replay
        |
        +---- completed hit/error ---> return
        |
        v
owned TranslationPreparation
        |
        v
drop writer; decode BlockPlan
        |
        v
second ProcessState writer acquisition
  - generation revalidation
  - authoritative block recheck
  - discard duplicate plan if another thread won
  - otherwise emit and publish under the existing contract
        |
        v
return authoritative entry
```

Competing threads may decode the same key. They may not both emit or publish it. The second locked recheck elects the winner using the authoritative block index Carrick already trusts.

### Why this design

It attacks the current writer-wait mechanism while keeping the unsafe and semantically coupled cache operations serialized. It introduces no lock table and no lifecycle state that fork or exec must reset.

A per-key election was rejected for the first candidate. Carrick previously removed a `ConcurrentPublicationIndex` whose mutex and `BTreeMap` traffic cost about 1.12 seconds of child CPU on this workload. Reintroducing similar work on roughly two million translations would undermine the experiment before it measures useful overlap.

A concurrent emitter was also rejected for this candidate. It would require redesigning allocation, direct-link patching, cache ownership, and `Send`/`Sync` invariants together. It remains a possible later step only if this experiment proves that serialization after decode is still a large retained bucket.

## Detailed state machine

### 1. Locked preparation

`ThreadTranslator::translate_read_mostly` keeps the existing thread-local and `PublishedBlockIndex` fast paths. On a miss it acquires the `ProcessState` writer and delegates to a preparation operation.

The preparation operation preserves the current ordering:

1. Observe the source page generation and apply required invalidation.
2. Recheck the authoritative block index under the writer.
3. Attempt shared-unit lookup and replay.
4. Record the fresh-miss/translation-begin lifecycle only when the request remains unresolved.
5. Construct the artifact-store lookup key and attempt artifact replay.
6. If no path completes the request, return owned preparation state for fresh decoding.

The shared and artifact paths return their final result without dropping and reacquiring the writer. They must not invoke the fresh decoder.

### 2. Owned preparation object

`TranslationPreparation` carries no references into `ProcessState`. It owns or copies the minimum data required to decode and later validate the result:

- the canonical block key and guest entry address;
- the original `PageGenerationObservation`;
- source-page and address-mode inputs required by the decoder;
- the artifact key/template and fresh-validation context already computed before decode;
- the superblock segment limit;
- profiling and lifecycle context needed to close every begun interval exactly once.

The concrete type should remain private to the translator module. It is a transient stack value, not a cache, not shared across processes, and not serialized.

### 3. Unlocked decode

After preparation returns, `ThreadTranslator` drops the writer and runs `block::plan_block_with_segments`.

Only operations proven to be pure with respect to `ProcessState` move into this interval. The first implementation should be conservative: move the decoder and its required immutable source reads; leave fingerprinting, plan classification, artifact recording, and every cache operation locked unless moving one is required for the decoder's type contract.

The decoder returns an owned `BlockPlan` or an error. It must not reserve cache space, publish metadata, or patch code.

### 4. Locked commit

On successful decode, the thread reacquires the same `ProcessState` writer and commits through an operation that consumes `TranslationPreparation` and `BlockPlan`.

Commit performs, in order:

1. Account for the completed decode interval.
2. Revalidate the original page-generation observation against current state.
3. Recheck the authoritative block index for the same canonical key.
4. If the generation changed, return the existing `GenerationChanged` outcome without emitting or publishing anything.
5. If another thread published the key, discard the decoded plan, backfill the process-published fast index as today, and return the existing authoritative entry as a block-index hit.
6. Otherwise run the existing plan metadata/classification, emission, artifact/shared recording, and `publish_emitted` sequence under the writer.

There is exactly one emission and one publication for a canonical key in a generation.

### 5. Decode error

A decode error publishes no state and reserves no cache space. Every translation/subphase probe begun by preparation must still receive its matching terminal/error event.

If opt-in profiling requires locked mutation to record elapsed decode time, the error path may reacquire the writer solely to close accounting and lifecycle state. Decode errors are not a performance-critical path; diagnostic correctness is more important than avoiding this acquisition.

## Generation and invalidation semantics

Generation validation is the correctness boundary for unlocked source reads.

The first observation identifies the source version decoded. The second locked validation ensures that version is still current before the plan can influence executable cache state. If guest code changes while decoding, Carrick rejects the stale plan through its existing generation-change outcome. It does not attempt to repair or partially reuse it.

The authoritative block recheck occurs only after generation validation. A published entry from another generation must never cause a stale plan to appear successful.

No metadata derived from a plan may become visible before both checks pass.

## Diagnostics

The experiment needs to distinguish useful decode overlap from waste caused by same-key races.

Replace the obsolete `duplicate_publications` resolver statistic, whose arbitration mechanism no longer exists, with:

- `optimistic_decode_discards`: decoded plans discarded because another thread published the same canonical key first;
- `optimistic_decode_discard_ns`: total measured decode time represented by those discarded plans.

`decode_ns` continues to include every actual decode attempt. Published translation counts continue to count committed blocks only. Together the fields expose total decode work, wasted work, and useful publications without a second compatibility schema.

`translation_ns` retains its current successful-fresh-translation meaning: only the winning committed translation adds to it. A losing attempt contributes to `decode_ns`, `optimistic_decode_discards`, and `optimistic_decode_discard_ns`, but not to `translations` or `translation_ns`.

Update the resolver-stat enum/table, profile snapshots, native performance frame, parsers, fixtures, and tests atomically. Remove any invariant that treats nonzero duplicate publication counts as a runtime error; a nonzero optimistic discard count is expected but should remain small enough that the net CPU result is positive.

The existing DTrace translation begin/end lifecycle must stay balanced. A new high-frequency USDT probe is not justified for the first candidate because opt-in counters can answer the race question without perturbing the default workload.

## Correctness and concurrency tests

Tests are written red-first against the current locked implementation.

1. **Decode occurs without the process writer.** A structural or test-only lock assertion proves `plan_block_with_segments` is not called while the writer guard is held.
2. **Same-key race emits once.** A deterministic test barrier lets two threads finish decoding the same key before commit. Both return the same authoritative entry, the cache grows once, one publication occurs, and one optimistic discard is recorded.
3. **Generation changes during decode.** A deterministic mutation between decode and commit returns `GenerationChanged`, emits nothing, and publishes no plan metadata.
4. **Decode error is inert.** An injected decode failure leaves cache extent, indexes, and metadata unchanged and closes diagnostic accounting exactly once.
5. **Artifact/shared hit skips fresh decode.** A test decoder counter remains zero for each replay path.
6. **Profiling accounting is exact.** Concurrent attempts produce the expected committed translation count, total decode count/time, discard count, and discard time without double-closing a phase.
7. **Existing lifecycle coverage remains green.** Invalidation, exec, fork-child reset, direct-link, artifact-store, and shared-store tests keep their current semantics.

Prefer narrow test-only orchestration seams over timing-dependent sleeps. Any barrier or injected decoder belongs behind `cfg(test)` or a generic private helper exercised by production without retaining test state.

## Implementation boundaries

Expected primary changes are within:

- `crates/carrick-dsr-aarch64/src/translator.rs` for preparation/decode/commit orchestration;
- existing resolver-stat/profile types and their runtime export/parser consumers;
- focused tests beside the affected translator and diagnostics code.

The candidate must not:

- change translation-cache allocation or make it concurrent;
- add a per-key mutex/map or revive `ConcurrentPublicationIndex`;
- weaken generation validation;
- change artifact/shared-store precedence;
- alter fork quiescence or exec reset semantics;
- enable Tier D by default;
- add eager full-image translation.

## Measurement and retention gates

The candidate is evaluated as a single-variable experiment against the exact retained control.

### Correctness gate

1. Focused translator and diagnostics tests.
2. Relevant crate clippy/test gates.
3. Signed default-native build.
4. Applicable default-native smoke/conformance coverage.
5. Full serialized `RUST_TEST_THREADS=1 just ci` before retention is finalized.

### Mechanism gate

Run the cold Go build with opt-in native performance counters and collect:

- total decode time and published translation count;
- optimistic discard count and discard time;
- emit/publication phase time;
- nested translation time.

Then run the same qualified DTrace stack profile twice. The candidate is mechanistically credible only if the exclusive-writer wait stack falls and counter behavior explains the change. A single traced timing is attribution, not retention authority.

### Performance gate

Run a signed, controlled eight-quad ABBA against the exact retained control (`a5bd4971`, whose runtime candidate is `64bebc26`) using the same default overlay and clean preflight rules.

Total child CPU is primary retention authority. Retain only a statistically positive CPU result with no supported correctness or secondary regression. A result of at least 10% is the desired step. A smaller result may be retained only when it is clearly positive, removes the intended mechanism, and is a non-regrettable enabler for the next serialized phase; the evidence must say that plainly.

Wall time is reported as resolved only when its ratio interval excludes 1.0. A fresh Docker scoreboard is required only after a retained wall-resolved candidate or an explicit user request.

## Stop conditions

Stop and revert the candidate if any of these holds:

- duplicate decode work consumes the concurrency benefit;
- total child CPU is flat or regresses under controlled ABBA;
- the exclusive writer-wait stack does not materially decline;
- generation, invalidation, artifact/shared replay, fork, or exec semantics fail;
- the implementation requires concurrent cache emission to show a benefit, since that is a separate design decision.

## Deferred follow-ups

- Eager whole-image translation to amortize cold decode for static images.
- Per-key election, only if measured optimistic discard waste is material enough to exceed the known arbitration cost risk.
- Concurrent or partitioned cache emission, only after this design isolates the residual serialization and a separate safety design covers allocation, patching, ownership, and lifecycle behavior.

## Expected outcome and confidence

The design is high-confidence for preserving semantics because all visible cache mutation remains under the existing writer and stale decode is rejected authoritatively. The performance outcome is less certain: decode is a meaningful CPU bucket, but achievable overlap depends on request concurrency and same-key collision rate.

Pre-implementation confidence:

- design correctness: 85%;
- measurable total-CPU improvement: 65%;
- at least 10% total-CPU improvement: 50-60%.

These levels should move only in response to red-first tests, opt-in counters, repeated mechanism profiles, and the controlled ABBA—not from implementation intuition.
