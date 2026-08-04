# Memory-intent stop and published-block lock split

**Date:** 2026-08-04  
**Workload:** Darwin/AArch64 native cold `go build`  
**Decision:** **stop the memory-lowering line; retain the published-block index
split after its controlled CPU win and carry the remaining exclusive translation
lock**

The approved memory-intent census found no guest semantic sequence large enough
to justify a production lowering. The largest exact sequence,
`mmap-anon-private` while the guest operation was active, projects to only
**6.5569% / 6.3527%** of ordinary total CPU even under the deliberately
favorable 3.84 us cost for every attributed zero-fill fault. The export-only
diagnostic remains because it closes process exit and can recover completed
records from trace artifacts without changing default execution.

The next source-distinct split found a real Darwin synchronization cost.
`psynch_cvwait` represented **17.7664% / 17.5852%** of all sampled CPU in two
clean baseline captures. ASLR-normalized user stacks assigned **15.2293% /
15.1220%** of all CPU to the single process-wide translation-state lock:
10.2014% / 10.2678% was a warm published-block lookup and 5.0279% / 4.8542%
was the trusted-entry lookup for an indirect target.

Commit `64bebc26b72ffd1f7a9ba581fded0f91fca21f63` separates those published
lookups from the authoritative mutable translation state. An eight-quad
signed-binary ABBA measured a paired total-CPU ratio of **0.91498**, an
**8.50% reduction**. The 95% two-sided bootstrap interval is
**[0.91023, 0.92113]**, all 8/8 quads favored the candidate, and the exact sign
probability is 1/256. This is below the campaign's preferred 10% step size but
is retained: it removes a measured source-distinct wait, has a narrow
correctness surface, and exposes the next larger exclusive-lock mechanism.

Wall time is not causally claimed as improved. The workload-wall median paired
ratio was 0.98593, but its 95% interval **[0.98174, 1.00320]** crosses parity.
At this experiment's decision point the official shipped-default ratio remained
10.4446x; the subsequent serialized refresh supersedes it with 10.1776x in
[`2026-08-04-current-default-wall-refresh.md`](2026-08-04-current-default-wall-refresh.md).

## Memory-intent evidence

The `native-fault` profile now emits a strict, export-only census for guest
`mmap`, `madvise`, `mprotect`, and `munmap`. Records include operation shape,
requested bytes, mapping provenance, active-operation faults, and subsequent
faults. Process-image epochs close on exec and terminal exit. The analyzer
fails closed on incomplete intents, lifecycle mismatches, live processes,
probe errors, overflow, interruption, or DTrace drops.

Both accepted captures used clean source
`44de06563213df5a6c0db097b851349897683c78` and signed binary SHA-256
`832b1380dec297b8c43e3fc318ff586fa98157b135fd4e338b8be2c7837d42ad`.
The D program SHA-256 was
`ed1f7ed1f1ed71ac261c8e090be276ab062274fe5e706f56cace676a2275b8ce`.

| input | A | B |
|---|---:|---:|
| exact zfod, all | 3,393,233 | 3,407,680 |
| exported zfod | 929,412 | 938,131 |
| completed intents | 11,671 | 11,789 |
| aborted intents | 0 | 0 |
| active-operation faults | 928,244 | 936,862 |
| guest-arena faults | 1,168 | 1,269 |
| `mmap-anon-private` active zfod | 927,321 | 935,942 |
| ordinary total CPU denominator | 54.307493 s | 56.574521 s |
| favorable opportunity | **6.5569%** | **6.3527%** |

The favorable calculation is:

```text
sequence_opportunity = exact_sequence_zfod * 3,840 ns / ordinary_total_cpu_ns
```

The next-largest tracked sequence was three orders of magnitude smaller:
fresh anonymous-map subsequent touches accounted for 1,145 / 1,192 faults.
`madvise-dontneed` subsequent touches were 8 / 60 faults. No memory sequence
approached the 10% carry gate, so no `MADV_FREE_REUSABLE`, `mprotect`, mapping,
or allocation change was attempted.

| artifact | SHA-256 |
|---|---|
| A raw trace | `a8caead326edc56edd70e1b2383231d9c225e4a94d2404b2478c1a2582d7ec00` |
| A summary | `8c6557faf6b1cb97a444e9dcfb4cd4b4d55955e763d8959910f7d7155b9b7a05` |
| B raw trace | `b872b5db5c4d57380b0eceea53b092012474b3e51432c1da132676de0eb58902` |
| B summary | `aac833b7032ef43ec89ca97d74ed9df5e545c13f5bce0c8db9a7b756c5ad8c3a` |

The raw and parsed artifacts are under `target/perf/current-memory-intent/`.
They are perturbing attribution evidence, not timing authority.

## Named-syscall and stack attribution

The `native-wall` profile was extended in two steps. First, it reports each
kernel sample by exact named syscall. Second, it records the user stack paired
with `psynch_cvwait` kernel samples. This avoids attributing a kernel leaf to a
source mechanism by name alone.

Two baseline captures at clean source
`c4be3c23745f21970b2acf4af3f2a67e55977b10`, signed binary SHA-256
`228c54c3f823a0d4fc48a927efc84f0ae2443ed18df75e257da4a42e775fcdfd`,
completed naturally with zero DTrace drops, overflow, incomplete pairs, or
lifecycle errors.

| baseline | A | B |
|---|---:|---:|
| all CPU samples | 43,239 | 42,911 |
| named-syscall samples | 12,444 (28.7796%) | 12,315 (28.6989%) |
| `psynch_cvwait` samples | 7,682 (17.7664%) | 7,546 (17.5852%) |
| exact paired-stack sum | 7,682 | 7,546 |
| warm `translate_read_mostly` state-lock path | 4,411 (10.2014%) | 4,406 (10.2678%) |
| `publish_indirect_target` state-lock path | 2,174 (5.0279%) | 2,083 (4.8542%) |
| combined state-lock path | **6,585 (15.2293%)** | **6,489 (15.1220%)** |

The two call sites use the same `ProcessTranslator.state` `parking_lot::RwLock`.
The write side deliberately spans decode, plan, emission, publication,
dependency updates, and direct-link patching. Warm readers therefore entered
Darwin `psynch_cvwait` behind useful translation work even though they needed
only one published-block or trusted-entry lookup.

| artifact | raw SHA-256 | summary SHA-256 |
|---|---|---|
| baseline stack A | `364bbe2d15cedbc1ed7fb02dad201d7953bb48587533c0709087275d03750cdc` | `9dde2ea293b9f7c11289466a5baee29e93017db784895a45af2f67382a07ddca` |
| baseline stack B | `2d424e160b3c4c0e108b7ad72c7a6412c1933274b8f144cdf6602ce5937dce5f` | `b8068c686aa9be58cc4ec5a3e48ac3b39ab72d5ef5dc1408637e595f0e544c34` |

## Candidate and correctness shape

The candidate adds a 64-shard `PublishedBlockIndex`. It mirrors only
successfully published `(guest VA, code generation)` records and their optional
trusted entries. The existing `ProcessState.blocks` and `trusted_entries` maps
remain authoritative.

The ordering is the correctness contract:

1. Translation, executable publication, dependency registration, and all
   fallible authoritative bookkeeping complete under the existing write lock.
2. Only then is the infallible mirror entry inserted.
3. A hit in authoritative state backfills the mirror, covering a partial prior
   publication without changing guest behavior.
4. Page invalidation removes the matching mirror entry, and exec reset clears
   every shard. A fork inherits the already-published warm index, matching the
   inherited JIT cache.

The per-thread direct-mapped cache remains level one. A thread's first encounter
with a process-published block now reads only one mirror shard. Indirect-target
publication reads the same mirror for its trusted entry. Neither warm path
takes `ProcessTranslator.state.read()`.

Focused validation at `64bebc26` passed all 226
`carrick-dsr-aarch64` tests and focused clippy. Tests cover the no-state-read
warm path, trusted-entry mirroring for shared units, failed publication, stale
generation publication, invalidation, exec clearing, and fork inheritance.
`RUST_TEST_THREADS=1 just ci` also passed at the same source authority after
the controlled comparison.

## Mechanism check after the split

Two accepted candidate traces used signed binary SHA-256
`aa423abce65be7408a4e565bec04383c7eb0dfeec8a3e72f56fb1cc8f96fd5df`.
The old warm-read and indirect-publish state-lock stacks disappeared. Absolute
`psynch_cvwait` samples fell 20.0% in A and 17.6% in C relative to the two
baseline captures. The dominant remaining stack is now
`parking_lot::RawRwLock::lock_exclusive_slow` reached from
`ThreadTranslator::translate_read_mostly`: real translators are waiting for the
process-wide translation writer, not performing warm lookups behind it.

| candidate | A | C |
|---|---:|---:|
| all CPU samples | 40,539 | 40,886 |
| `psynch_cvwait` samples | 6,142 (15.1508%) | 6,221 (15.2155%) |
| traced elapsed, diagnostic only | 26.175544 s | 26.665746 s |

| artifact | raw SHA-256 | summary SHA-256 |
|---|---|---|
| candidate stack A | `55f74f1b032f53e7f724981e55e886702c9d983ad40298264a70ff4953324c14` | `b8d550a160728bb13e5ef1d77da0209115ef88d7c38ebf9124e5fcb8f1155671` |
| candidate stack C | `631a0abeed4a3d4bea771723d0cc5293e456e07ff1420d5fe46cbfd5e49692b5` | `dc1681d0d7589703851c82ae1914b976d94b51d35db922813e26e05ac6b10981` |

Candidate stack B completed the guest workload but was rejected because the
post-stop symbolizer reported an unsupported raw-address kernel symbol. It
contributes no accepted samples.

## Controlled ABBA result

The timing authority is
`target/perf/current-syscall-split/abba-v1.json`, SHA-256
`b0b7350155283801f0fc24d54ed14a70267d2377f4ed79eb9fc15b0fac16512e`.
It contains two excluded warmups followed by eight A-B-B-A quads. All 32
measured executions returned `BUILD_OK`; cleanup, image identity, load, and
thermal gates passed. Battery operation was explicitly allowed by the user and
applied equally to both paired arms.

The clean detached control was `c4be3c23`, binary SHA-256
`8e13747930c4c954654e7a08aa21c4e41b13eea6e096a1fc64ec30facbb4cd9f`.
The clean candidate was `64bebc26`, binary SHA-256
`aa423abce65be7408a4e565bec04383c7eb0dfeec8a3e72f56fb1cc8f96fd5df`.
Both receipts bind image digest
`sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
and the shipped-default overlay.

| metric | control median | candidate median | paired ratio | 95% interval | wins |
|---|---:|---:|---:|---:|---:|
| total CPU | 21.8250 s | 19.9922 s | **0.91498** | **[0.91023, 0.92113]** | 8/8 |
| system CPU | 6.0265 s | 4.6335 s | **0.76539** | **[0.76130, 0.77440]** | 8/8 |
| user CPU | 15.7688 s | 15.3491 s | **0.97344** | **[0.96519, 0.98112]** | 8/8 |
| process elapsed | 8,825.5 ms | 8,715.0 ms | 0.98588 | [0.98352, 1.00205] | 6/8 |
| workload wall | 8,329.5 ms | 8,217.5 ms | 0.98593 | [0.98174, 1.00320] | 6/8 |

The harness statistical gate passed. Its receipt leaves `retained=false`
because mechanism and correctness are deliberately external gates; the accepted
stack evidence above supplies the mechanism gate, and the repository tests
supply the correctness gate.

## Next gate

Carry the remaining exclusive translation writer, not a full concurrent-emitter
rewrite. Baseline opt-in phase counters put decode at about 10.52%, emission at
14.26%, publication at 3.71%, and the complete nested translation interval at
25.46% of ordinary CPU. The candidate stacks independently show roughly 15.2%
of all sampled CPU waiting at the exclusive lock.

The next design should preserve the single-writer JIT-cache contract while
moving independently computable decode/planning work outside the global lock
or electing translation ownership per `(guest VA, generation)`. It must avoid
duplicate work and revalidate generation/publication under the lock. A fully
concurrent emitter would require changing the bump cursor and the cache's stated
`Send`/`Sync` safety argument; that is a larger design, not the first patch.

Eager whole-image translation remains a deferred future improvement. It may
amortize complete eligible images, but incremental translation is still required
for JIT-on-JIT and dynamically generated code.
