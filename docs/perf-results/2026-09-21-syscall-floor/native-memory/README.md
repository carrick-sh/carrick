# Native memory lowering — 2026-09-22

The bounded native executor's load/increment/store loop fell from **151.92 ns to
2.12 ns per iteration**, a **71.8x speedup (98.6% less time)**. It now measures
**1.53x native ARM64 Linux**. The watch-churn result is essentially unchanged;
this change removes the memory regression that made the previous native slice
unsuitable for further integration. It is not a full inotify09 result.

Contract: `kernel.execution.native-synchronous-syscall`, still unresolved.
Implementation: [native.rs](../../../../experiments/native-syscall-slice/src/native.rs).
No product runtime path changed in this continuation. The frozen Carrick CLI
was not rebuilt or replaced. No contract budget or execution binding changed.

## Same-ELF, current measurements

| Operation | Previous native ns | Guarded native ns | Frozen HVF ns | Linux ns | Native/Linux |
|---|---:|---:|---:|---:|---:|
| Invalid add/remove pair, N=65536 | 463.40 | 474.12 | 2883.01 | 239.40 | 1.98x |
| Two unchanged-watch adds, N=65536 | 705.52 | 697.07 | 3415.08 | 492.41 | 1.42x |
| Fresh watch churn, N=128 | 698.24 | 693.36 | 3516.93 | 1123.38 | 0.62x |
| Churn growing into overflow, N=65536 | 724.71 | 727.87 | 3329.64 | 865.81 | 0.84x |
| Integer loop, N=65536 | 2.14 | 2.21 | 0.51 | 0.61 | 3.63x |
| Load/increment/store loop, N=65536 | 151.92 | 2.12 | 1.20 | 1.38 | 1.53x |

These are fresh runs of both the preserved previous native executable and the
new one, followed by frozen HVF and pinned native ARM64 Docker. Three invocation
medians per cell, nine retained guest samples each; the first of ten is warmup.
**72 successful invocations, 648 retained samples**, all raw records and cleanup
receipts retained. No build, tracing, allocator instrumentation or concurrent
Carrick/Docker phases during timing. Binary and fixture identities are recorded
per invocation. `summary.json` retains each invocation median and exact ratios.

The memory cell's invocation medians were 148.24/153.11/151.92 ns before,
2.11/2.12/2.33 ns after, and 1.26/1.38/1.38 ns on Linux. No CPU pinning or
randomized arm order was used. Small watch-loop differences are not established
improvements or regressions. This intervention identifies the avoidable callback
cost; the remaining difference is not an established architectural floor.

The long churn loop remains 0.84x Linux and takes 78.1% less time than frozen
HVF. Invalid pairs remain 1.98x Linux, unchanged adds 1.42x, and integer code
3.63x. Reaching the overall 1x goal still needs actual runtime integration and
representative workloads. The native/HVF comparison includes different runtime
services and dependency closures; it does not isolate HVF exit latency alone.
No write/seek operations occur in these timing windows. Native macOS filesystem
cost remains a separate control, and the direct host-file path remains required.

## Mechanism and work proof

The existing slow path made one full Rust gateway round trip for every scalar
load and store. A red test recorded memory callback counts **2/16/64/256/2048**
for **1/8/32/128/1024** iterations. It also checked final bytes and registers.
After native lowering those counts are zero. Total callbacks are exactly
`floor(N/256) + 1`, preserving the existing backedge checkpoint and final syscall.
The red failure and final passing test log are retained.

Each emitted memory stub computes a semantic address, checks the whole 4- or
8-byte access against one cached region, then derives a host pointer from that
region's private backing. Unsigned offset-underflow and end-bound checks reject
out-of-range accesses. Misses restore the guest scratch registers and NZCV before
entering the original permission-checked emulation path.

Only an exclusively owned, non-executable RW region that has never held code is
cached. Other regions and permission combinations remain slow. Code retains the
region's identity/shape, not a host pointer. The execution invocation obtains a
fresh pointer through the exclusive Memory borrow on entry and after every Rust
callback, after validating the exact memory identity and generation. No native
access overlaps Rust byte access. Pointer state is cleared on callback entry
and exit. Unmap, protection changes, backing replacement and code writes revoke
execution before resume; guest SP, x18 and x28 remain virtual.

**This borrowing proof applies to the experiment's private ELF backing only.**
It is not an authenticated borrow from the carrier frame inventory and does not
implement COW, concurrent invalidation or foreign-write authority. The cache is
one region, not a workload-qualified multi-mapping translation cache. Cross-
segment accesses use the bounded emulator, which can reject a valid Linux access
spanning separately declared adjacent segments. This subset limitation remains.

## Validation and limits

- Eleven executor tests pass, including **12,288 native-versus-checked-memory
  cases** covering every base/target register, 32/64-bit widths, load/store,
  offsets 0/1/4095, register aliases, NZCV, SIMD preservation, virtual reserved
  registers, SP and zero registers. These are local semantic comparisons, not
  12,288 Linux differential cases.
- Fault/boundary tests cover exact last valid starts, access straddling the end,
  addresses below the region, overflow values, RX writes and read-only data.
  Callback reborrowing observes updated bytes; unmap, permission revocation,
  restore-to-original-permissions and same-VA foreign-memory replacement prevent
  the next native load. Existing code-publication and wrong-MM tests still pass.
- The same actual ELF fixtures pass native, HVF and Linux. Guest checks include
  memory-loop final values, exact errno returns, watch IDs, queue bytes, drained
  IN_IGNORED payloads and overflow ordering. Native observer request/completion
  and syscall populations remain exact.
- A separate allocation-observation binary retains **zero warmed allocations**
  and exactly 2N requests/completions at N=1/8/32/128, nine windows each. Its
  positive control fires. Four typed observations remain explicitly Incomplete;
  no missing HVF-exit metric is fabricated.
- Clippy with warnings denied, formatting and two contract-verifier negative
  controls pass. No kernel implementation changed this continuation. Full CI,
  signed embed, full inotify09 and language-workload promotion have not run.

## Next decisive gate

Move this same bounded instruction subset onto a **current-carrier-backed
execution borrow**, before growing the translator or polishing more microloops.
The kernel's existing instruction reader and real carrier transport were already
qualified in [the authority handoff](../dsr-guest-contract/authority-handoff.md).
An instruction-read receipt grants neither durable native byte pointers nor
code-cache publication. The next implementation must establish those rights.

1. Borrow resident spans through the exact task execution lease, MM, permission
   and frame-owner generation. A borrow must have an explicit invalidation/
   quiescence lifetime covering native execution, syscall buffer access and
   foreign mutation. Cache only spans whose entire host backing is contiguous.
2. Resolve shared writable/COW spans through the existing carrier mutation path
   before a native write grant. Route unavailable or split spans through the
   real checked memory path. Fail red on stale lease/owner, same-VA different MM,
   cross-page permission changes and COW parent/child divergence.
3. Tie code publication and links to that same authority. In-place code writes,
   writes through non-executable aliases, foreign writes, unmap, mprotect and exec
   must prevent stale translated execution before it resumes. Do not substitute
   hardware I-cache invalidation or a mapping snapshot for this proof.
4. Repeat this exact fixture with those real services, then bind migratable
   register state, signal delivery/cancellation and concurrent scheduling. Only
   then use signed embed, fixed-work original inotify09 race and Node/Go/Python
   to determine retained end-to-end gain. Keep host I/O attribution separate.

The memory ratio stop condition is no longer triggered by this reducer. Promotion
still stops under the [conformance-contract skill](../../../../.agents/skills/carrick-conformance-contract/SKILL.md):
“a required execution layer has no registered binding.” This names unfinished
integration, not a need for user permission. Private backing success cannot
satisfy the current-carrier, COW and signal obligations.

## Guidance and receipts

The separation of memory execution, syscall interception and implementation cost
follows the Apache-2.0 [gVisor performance guide](https://gvisor.dev/docs/architecture_guide/performance/).
The [DynamoRIO AArch64 design material](https://dynamorio.org/page_design_docs.html)
remains a BSD-licensed reference for later code linking and state restoration.
Pinned source/license receipts are in [permissive-guidance](../permissive-guidance/sources.json).
This lowering is independently authored; no external implementation was copied.

`manifest.json` binds source hashes, dirty-source archive, compiler, fixture and
image identities, signed binary metadata and the unchanged product CLI.
The frozen measured executor is
`target/lease-cost/native-memory/native-guarded-executor` (SHA-256
`2440ad8f103e016dd6d859cec061a6065cb9708dd55e6559dbb182d28433ea65`).
Normal timing and allocation binaries remain separate. Work is local/uncommitted.
