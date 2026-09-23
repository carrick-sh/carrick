# Unaligned anonymous discard: selected intervention

The previous completed-work reduction established that adding an echo child
costs 66.5 ms on Carrick versus 2 ms Linux. These separate traces locate a
concrete fallback to change; they are not a speedup prediction.

Five successful iterations per arm on the frozen signed discard candidate.
All request/argument/completion counts reconcile, scrub total=zeroed+remapped,
root exited, no errors, cleanup zero. The echo-wide and base-wide captures are
authoritative. The first echo/base captures initialized address variables with
untyped zero and truncated 64-bit addresses; retain them as invalid address
attribution evidence. Repeated captures correct that instrument bug, not workload
flakiness. Executed scripts are hash-matched to their input manifests.

Both authoritative arms perform 25 explicit scrubs totaling 207,872,000 bytes:
**41,574,400 bytes per run**, five ranges of 8,314,880 bytes each. All are advice4
(MADV_DONTNEED), begin 12,288 bytes into a 16 KiB host page, and lie within the
sparse mmap arena (example 0x6000e6f000). No bytes are remapped by ScrubRun.
Echo summed service 408.986 ms, of which 405.265 ms is in these scrub requests;
base 42.525 ms, of which 38.836 ms is in scrub requests. These are overlapping,
perturbed intervals. The increased work needed to authenticate/copy shared
backing after fork remains a hypothesis; explicit scrub bytes themselves do
not increase. Do not present these totals as critical-path time.

## Concrete next intervention

HvfVmState::prepare_anonymous_discard rejects any range whose address or length
is not 16 KiB aligned. The generic engine then falls back to zero_backing for
the entire request, including COW write preparation. For this observed shape,
only 8,192 bytes are partial host-page edges; 8,306,688 bytes form a fully aligned
interior. Support authenticated interior retirement with bounded edge handling.
This is the selected implementation experiment; no further broad profiling is
needed before the red-first structural/semantic proof.

Applicable contracts: kernel.mm.anonymous-discard and
kernel.mm.anonymous-discard-no-scrub. Add a boundary-specific structural contract
for actual scrubbed bytes, not merely callback counts. For capable HVF backing,
edge scrub must be bounded by two partial host pages independently of interior
length. Use 1/8/32/128 interior host pages and all Linux-page boundary offsets.

Required proof before performance claims:
- Red on current backend: unaligned requests scrub the whole populated range.
- Preserve bytes outside the requested range, including both host-page neighbors.
- Parent discard returns zero on later reads while a live fork peer retains its
  original bytes; read-only, executable, sparse and already-discarded mappings
  retain existing semantics. Do not broaden eligibility into shared/file VMAs.
- Prepare/commit must preserve exact MM, owner generation, stage-1 publication,
  TLBI and alias retirement invariants. Edge COW may change inventory: never
  consume an interior retirement plan made stale by edge preparation. Determine
  ordering or combine into the same authenticated transaction before coding.
- Failures before publication remain clean; after uncertain publication fail
  stopped under the existing contract. Add failure injection, not only happy path.
- Use VM-free production carrier proof, then exact signed guest differential.
- Paired untraced frozen control/candidate on ORIGINAL Node fixture, minimal-child
  reduction for explanation, and Go/Python controls. Reject if no workload gain.

No product change or new speedup in this experiment. Prior full signed promotion
obligations remain open.
