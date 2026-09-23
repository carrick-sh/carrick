# Reusable current-MM input reads — 2026-09-22

The carrier-backed research path now reuses an authenticated, range-scoped input
window. On the unchanged ELF, the two-add unchanged-watch pair falls from
**16.21 us to 1.44 us (11.29x faster, 91.1% less time)**. Fresh native ARM64 Linux
is 0.518 us: the remaining raw ratio is **2.77x**, so the 1x goal is still open.
Sustained watch churn falls from 8.69 us to 1.28 us, **1.42x Linux**.

This is a causal intervention on the carrier-copy research path. It is not a
shipped CLI improvement, signed native execution acceptance, full inotify09
result, or Node/Go/Python workload result. The research runner still publishes
private text, mocks stage-2 and supports only its bounded synchronous syscall
subset. The frozen product and earlier private-native controls remain unchanged.

## Same-binary intervention

Cache-off and cache-on use one preserved release executable. Only
`CARRICK_NATIVE_BUFFER_READ_CACHE=0/1` changes between the arms. Each cell is the
median of three invocation medians, each containing nine retained guest samples
following one warmup. Pair order alternates by case and repetition. All 36 paired
research invocations and 18 fresh Linux invocations completed successfully.
The 20 small controls (five phases at 1/8/32/128) also pass on this exact artifact.

| Control | Scale | Cache off ns/iteration | Cache on ns/iteration | Linux ns/iteration | Raw Linux ratio |
|---|---:|---:|---:|---:|---:|
| Invalid add/remove pair | 65536 | 838.60 | 838.90 | 249.47 | 3.36x |
| Two unchanged-watch adds | 65536 | 16213.05 | 1435.68 | 518.10 | 2.77x |
| Fresh watch churn | 128 | 8743.81 | 1411.13 | 1219.08 | 1.16x |
| Churn into queue overflow | 65536 | 8691.66 | 1281.92 | 901.55 | 1.42x |
| Integer loop | 65536 | 2.86 | 2.85 | 0.57 | 4.97x |
| Load/increment/store loop | 65536 | 3.14 | 3.13 | 1.15 | 2.73x |

The invalid-fd and compute controls move by less than 0.5% between research
arms. That is a useful negative control, not a statistical equivalence claim.
All request, completion, errno and checkpoint populations agree across the six
research invocations of each cell. No CPU pinning or randomized arm order was used. Small ratios, especially the
N=128 cell, should not be read as a parity guarantee. Every original guest timing
record and each invocation median are retained; no samples were discarded beyond
the declared first warmup.

The same ELF SHA-256 is asserted across all three arms. Linux uses the pinned
`localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b`.
Research timing, Linux timing, and builds/verification run in separate phases.
No tracing or allocator instrumentation runs during the release timing phase.
The release unit-test harness still has its existing test-support fixture code;
this is not a product build.

There is **no write/seek work in these timed watch loops**. Path creation, event
queue draining, and stdout are outside the measured interval. The first clock's
copyout cost follows its timestamp and remains inside each interval, particularly
visible at N=128. Native macOS filesystem I/O remains separately attributed and
the direct host-file path is preserved.

## Red-first work contract

`kernel.mm.current-read-reuse` holds the read workload fixed at sixteen 256-byte
copies while independently COW-backed 16 KiB compounds scale through 1/8/32/128.
Counters measure actual allocation calls, complete snapshot collections, and
successful backing-owner pin acquisitions. The allocator has a positive control.

| Backing compounds | Red allocations | Red full snapshots | Red owner pins | Green allocations / snapshots / pins |
|---:|---:|---:|---:|---|
| 1 | 1536 | 96 | 32 | 0 / 0 / 0 |
| 8 | 2240 | 96 | 144 | 0 / 0 / 0 |
| 32 | 4624 | 96 | 528 | 0 / 0 / 0 |
| 128 | 14000 | 96 | 2064 | 0 / 0 / 0 |

The exact pre-optimization binary, source archive, red observations and failing
budget result are preserved. An initial fixture failure at 128 compounds was
not counted as structural red evidence: mapping 2 MiB in one call had produced
a block mapping. The fixture now builds leaf mappings for independent compound
COW setup; after that correction all scales complete and fail the intended zero
work budgets before the implementation change. No timeout, budget, concurrency
or completion criterion was weakened.

These zero budgets cover **warmed reuse only**. Cold preparation still collects
full MM snapshots and transiently retains all published backing through the old
lease machinery. A window retains only its accessed owner afterward. Unsupported
ranges use the existing copy path. Owner/index lookup, locks, live generation
checks, leaf checks, and byte copying still cost CPU time; this is not a zero-cost
or constant-total-work claim. Other-MM frame inventory changes conservatively
invalidate the cache.

## Authority and semantics

The opaque kernel window binds the exact kernel, task, MM, thread, execution
generation, executor and executor epoch. Cold preparation validates the semantic
readable range and transport snapshot. Every reuse checks live non-reusing MM,
VMA and frame-inventory revisions, the actual current stage-1 leaf and EL0 read
permission, the protection tracker, live mapping/frame identity, and exact host
owner address/generation. The page-table read lock spans the copy. No raw host
pointer or cached guest bytes escapes the capability. The input window does not
retain native execution or COW exclusion across syscall dispatch.

A cache miss prepares once against current authority. A transport validation
failure during a copy returns an error and clears the window; it is not retried
through weaker checks. A changed semantic revision can prepare a newly valid
window, but an old window itself cannot revive after revoke/restore.

Controls cover changed bytes, COW replacement, VMA revoke/restore, unmapping,
remapping to another physical page, owner-generation mismatch, protection denial,
wrong context/lease, lease generation transfer, range overflow and boundary
escape. Read-only leaves and write-only denial still permit reads. A replacement
page-table authority with a coincident numeric generation is inspected live.
Multi-leaf requests exercise the original fallback. Eleven carrier-buffer tests
pass; the separate ELF test remains explicitly opt-in in the ordinary unit lane.

The API is shared kernel/HAL/carrier code; the new caller is currently only the
research `CarrierCopyMemory` adapter. No new product-native execution binding is
claimed. Executable output, code publication, asynchronous signals/cancellation,
TLS, scheduling and broad syscall coverage still need their own acceptance.

## What to move next

1. **Measure and reduce common admission/checkpoint/dispatch work.** The unchanged
   buffer path has lost its dominant full-MM reconstruction cost. The buffer-free
   invalid pair still costs 839 ns versus Linux's 249 ns. Use the same ELF,
   exact request/completion contract and same-binary intervention to test a
   specific common-path change. Preserve execution, MM, signal and cancellation
   authority; do not remove checks based only on their frequency in a profile.
2. Measure cold/moving-buffer and cross-page input patterns separately before
   generalizing to language workloads. Warm reuse does not solve a program that
   continuously changes buffer addresses or mappings. Scope cold retention to the
   actual accessed owner without losing coherent snapshot and mutation checks.
3. Keep compute controls visible: the integer and load/store research loops
   still exceed Linux by 4.97x and 2.73x. This change does not improve generated
   guest code, and the native-execution proposal has not established a universal
   1x floor.
4. Complete carrier code publication and signed execution bindings before
   claiming full inotify09 or language-workload impact. Higher-layer failures
   remain open; the >10x cache-off control is retained as historical/baseline
   evidence and is never promoted as acceptable performance.

The investigation continues the pinned permissively licensed guidance in
[the gVisor performance guide](../permissive-guidance/google--gvisor--g3doc--architecture_guide--performance.md)
(Apache-2.0) and [Coz](../permissive-guidance/plasma-umass--coz--README.md)
(BSD-2-Clause): separate implementation cost from execution architecture and
measure completed-work impact of an intervention. No third-party code was copied
and no external project's timing is used as Carrick evidence.

## Verification and provenance

Fresh checks pass: `just test-kernel` (2,120 kernel tests plus the semantics
suites), runtime memory (40 passed, two opt-in tests ignored), runtime quiesce
(27), memory doctests (4), contract verifier/registry (33), research executor
units (11), observability (83), affected-package and research clippy, formatting and product layering.
The registry now contains 31 contracts and 15 claims; no support claim was added.

The signed foreign-MM gate remains **73 passed, one failed, one ignored**.
`fresh_sparse_publication_avoids_stage1_maintenance` again reports
`PageTableInvalidations`, scale 1, actual 1, maximum 0, as at the previous
checkpoint. The unentitled negative control passes. Both signed run-ID cleanup
scopes report zero processes. No successful signed receipt was published and
this failure was not waived, retried into green, or repaired by the research
measurements. Full CI, product probes/smoke/full, full inotify09 and ecosystem
acceptance were not completed in this continuation.

`manifest.json` binds raw records, commands, complete observations and exact
artifacts. All 132 source inputs are archived. The measured-source archive
contains the inventory that existed during timing; the final source archive
also includes the subsequently regenerated contract inventory. That generated
JSON is the only post-timing source difference; Rust, Cargo, fixture and timing
code did not change. All 120 unrelated inputs from the 129-file parent snapshot
and all four frozen control artifacts match their prior hashes. Nine parent
files changed intentionally; three source files are new.

The release, red and signed executables remain under
`target/lease-cost/current-read-reuse`. The original structural red was also
replayed from its preserved executable with the archived source digest and
reproduced all four work snapshots exactly. All research subprocesses and Linux
containers completed and were reaped. No work was committed, merged or pushed.

## Subsequent entry-cost investigation

[Demand-driven native data activation](../checkpoint-floor/README.md) removes
unused data grants from register-only intervals. The same-binary follow-up
reduces invalid pairs 28.2% and sustained churn 18.9%; the latter is 1.21x fresh
Linux. This remains research evidence, with production-native execution open.
