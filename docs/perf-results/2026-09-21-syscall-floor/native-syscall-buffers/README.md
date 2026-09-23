# Carrier-backed syscall buffers — 2026-09-22

Follow-up: [current-MM read reuse](../current-read-reuse/README.md) measures an
11.29x improvement to the unchanged-watch research pair. The results below
remain the preserved pre-reuse checkpoint.

The unchanged ELF now uses actual carrier memory for data, pathname input,
clock output, queue lengths, event output and stdout input. **20/20 bounded ELF
controls pass**, but the integrated research path is much slower than the
previous private-buffer experiment. This is a functional composition milestone,
not a performance win or a product-native acceptance result.

The most useful new result is the unchanged-watch pair: **16.23 us, 30.85x
fresh native ARM64 Linux**. The earlier ~0.70 us private-buffer measurement did
not include this carrier copy path and cannot establish the native syscall floor.
The 1x goal remains open. The >10x completing result prevents promotion under
`carrick-conformance-contract`; it is not an expected gap or a relaxed budget.

## Impact measured on the same ELF

| Control | Scale | Carrier research ns/iteration | Linux ns/iteration | Raw ratio |
|---|---:|---:|---:|---:|
| Invalid add/remove pair | 65536 | 834.90 | 253.73 | 3.29x |
| Two unchanged-watch adds | 65536 | 16225.10 | 525.95 | 30.85x |
| Fresh watch churn | 128 | 8943.69 | 1126.62 | 7.94x |
| Churn into queue overflow | 65536 | 8730.11 | 901.34 | 9.69x |
| Integer loop | 65536 | 2.87 | 0.57 | 5.07x |
| Load/increment/store loop | 65536 | 3.14 | 1.37 | 2.29x |

Each cell is the median of three invocation medians, each containing nine
retained guest samples after one warmup. All **36 timing invocations** completed
successfully. Carrier and Docker phases were serial, with no concurrent builds,
tracing or allocator instrumentation. Identical ELF SHA-256 values are asserted
between the arms; the Linux image is pinned to
`localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b`.
Raw records, arguments, per-invocation medians and Docker cleanup receipts are
retained. No CPU pinning or randomized arm order was used. These measurements
identify a large cost; small differences should not be treated as established.

There is no write/seek work in these timed watch loops. Path creation, event
queue draining and stdout are outside the measured windows. Native macOS file
I/O remains a separate control and the direct host-file path remains required.
The first clock's result-copy cost occurs after its timestamp and therefore is
inside each reported interval; the ending timestamp is taken before its copy.
This fixed cost is less amortized in the N=128 cell than in N=65536.

This runtime test executable is a research host process with mock stage-2 and
private code publication. It is neither the shipped CLI nor a full inotify09 or
Node/Go/Python workload. The frozen product and private-native controls were not
rebuilt or replaced. Historical private-buffer comparisons also include prior
scope/activation integration differences; they do not isolate copy cost alone.

## What changed and what the red tests found

`KernelContext::copy_current_into/from` authenticates the exact execution lease
and current MM. Input reads use the existing live carrier read protocol. Output
uses the existing COW, prepared-write and commit protocol, with mutation
exclusion held only during the copy. No caller-provided byte store, raw host
pointer or numeric MM selector confers authority. Zero-length copies still
check the execution lease. This bounded interface refuses executable output;
full executable-buffer syscall semantics require separate code publication.

The copy-only `CarrierCopyMemory` research adapter authenticates at construction
but prepares memory only when a syscall actually accesses a buffer. Its lease
borrow excludes handoff/native re-entry while the adapter is live, and an Rc
marker makes it neither Send nor Sync. Mapping operations remain unsupported;
the research runner still admits only its explicit synchronous syscall subset.

The pre-fix clock test wrote into private ELF data and left the carrier unchanged.
The retained red binary now serves as a decoy control. Green execution changes
the carrier timespec, leaves the private bytes untouched, and preserves the
original COW source. Additional red tests found two implementation errors:

- A repeated copy across already-private pages failed because identity write
  receipts cover one 4 KiB guest leaf, whereas the first implementation chunked
  at the 16 KiB COW compound. Copies now honor the guest-leaf boundary.
- The existing identity-write transport accepted a retained, invalid descriptor
  when its AP bits still said user-RW. It now also requires the valid bit. The
  unmap control failed before this correction and passes afterward.

Negative controls also cover the wrong execution lease, address overflow before
allocation, complete semantic range rejection, read-only and inaccessible VMAs,
executable output refusal, live protection denial, repeated cross-page copies,
multiple COW compounds, and original-source isolation. All live permission
snapshots remain in place. A proposed snapshot-reuse shortcut was rejected by
automatic approval review and was not applied.

The carrier fixture supports the ELF's original data addresses and its full
262 KiB event area; ELF bytes are unchanged. Native scalar accesses use a
page-sized authenticated data window, and misses use carrier-copy emulation.
All 20 controls verify exact phase/scale/queue records, guest exit, request and
completion counts, errno population, unchanged private data and COW source.
The diagnostic field `memory_checkpoints` counts all non-syscall checkpoints,
including periodic backedges; it must not be read as a pure memory-miss count.
Large overflow draining uses this path outside the timed churn loop.

## Contract and validation

The new `kernel.mm.native-syscall-buffers` contract binds the VM-free composition
and allocator test. At scales **1/8/32/128**, warmed invalid-descriptor pairs have
**0 allocations** and exactly **2/16/64/256 dispatches and EBADF completions**.
The allocator positive control fires. This proves lazy buffer work for invalid
fds; it makes no zero-allocation claim for actual buffer accesses.

The encompassing `kernel.execution.native-synchronous-syscall` remains unbound
for signed execution. No HVF-exit metric is fabricated and no workload claim is
promoted. The inventory adds a contract, not a syscall support claim.

Fresh validation passes: `just test-kernel` (2,120 kernel tests plus the
semantics suites), runtime memory (36 passed, two opt-in diagnostics ignored),
quiesce (27), memory doctests (4), contract verifier/registry (33), private ELF
controls (20 cases) and executor units (11), changed-package and research clippy,
formatting and product layering. The registry contains 30 contracts and 15
claims; inventory support claims remain unchanged.

The corrected signed foreign-MM command completes **73 pass, one fail, one
ignored**. The existing `fresh_sparse_publication_avoids_stage1_maintenance`
failure still reports one invalidation where the budget permits zero. The
unentitled negative control passes; both scoped process censuses are zero.
No success receipt was issued. The exact signed executable, SHA-256, CDHash,
LC_UUID, entitlement and DOF load commands are retained. An earlier command
failed before execution because the VMM package has no `conformance-metrics`
feature; its original log is retained separately from the corrected command.

Validation receipts are listed in `manifest.json`. Higher-layer gates, including
signed native execution, product probes, smoke/full conformance and full CI,
remain incomplete. The previous memory-control checkpoint's failed full-kernel
receipt is preserved independently; this continuation's fresh `just test-kernel`
passes and does not rewrite that historical result.

## Next intervention, ranked by measured cost

1. **Make current-MM input copies proportional to the requested span.** The
   unchanged pair is the decisive reproducer: two tiny pathname reads and no
   watch churn. Source inspection shows `copy_current_into -> current_mm ->
   snapshot_token -> retain_foreign_lease` reconstructing a full snapshot and
   retaining all published extents, followed by additional live snapshots in
   `read_mm`. This is a concrete hypothesis for the ~15.7 us excess over Linux,
   not an attribution derived from recurring profile samples.
2. Add actual work counters for snapshot enumeration, retained-owner visits and
   allocations. Keep buffer bytes fixed while scaling unrelated mappings at
   1/8/32/128. Then implement a range-scoped current-copy capability with live
   generation/permission checks and exact owner pins. Reuse must reject mprotect,
   unmap, COW, owner reuse, exec, MM changes and execution-lease transfer. Do not
   replace current permission checks with an unchecked cached snapshot, hold an
   execution grant across dispatch, or skip authentication for trusted paths.
3. Re-run the same unchanged and churn ELFs with the same semantics and fresh
   Linux controls. Only after that intervention reduces the buffer-bearing cost
   should invalid-pair admission/checkpoint work (~0.58 us excess per pair) become
   the next target. It remains relevant, but is much smaller in absolute time.
4. After the microbench improvement, measure full inotify09 and representative
   language workloads. Code publication, signals/cancellation, TLS and scheduling
   still prevent product-native acceptance; none is established by these ELFs.

The pinned, permissively licensed guidance remains
[the gVisor performance guide](../permissive-guidance/google--gvisor--g3doc--architecture_guide--performance.md)
(Apache-2.0) for separating implementation cost from execution architecture,
and [Coz](../permissive-guidance/plasma-umass--coz--README.md) (BSD-2-Clause) for
completed-work causal questions. Source/license hashes were reverified against
[the source manifest](../permissive-guidance/sources.json). No third-party source
was copied in this continuation, and no external project's timings are used as
Carrick evidence.
