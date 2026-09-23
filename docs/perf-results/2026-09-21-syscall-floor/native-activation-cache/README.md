# Native carrier activation: remove repeated validation work

Execution-scope entry plus activation of one unchanged resident carrier page now
costs about **138 ns**, versus **1.42 us** in the preserved baseline. Scope-only
entry remains about **36 ns**. The added activation cost fell from **1.39 us to
102 ns**, a **92.6% reduction** at scale 128. This is a controlled host fixture
measurement, not an inotify09 speedup or native execution acceptance.

The structural intervention is explicit: the old implementation performed
**56 heap allocations and one terminal-leaf validation per activation**. After
one full validation, unchanged activation now performs **zero of each** at
scales 1, 8, 32 and 128. Both instruments have positive controls, and the
structural test completes 169 actual native load/add/store operations against
production carrier COW backing while preserving the original source bytes.

## Why this change is valid

An opaque preparation already pins and authenticates its backing. Rebuilding
VMA and inventory vectors on each entry repeats that work. The exact native
execution scope supplies the existing running/drain handshake; this change
preserves its execution-lease, task, MM, census and pending-control checks.

- `Stage1MmBackend::snapshot_stamp` observes the binding, backend revision,
  VMA revision and frame-inventory revision without copying table contents.
  The retained MM owns an immutable backend instance. Revision publication
  remains under the source-replacement lock, including historical-MM freeze.
  Backends without this optional interface retain full snapshot comparison.
- A private `TrackedStage1Image` wrapper advances its generation before any
  mutable access to the page-table image. Edits, failed edits, rollback,
  restore, take/replacement, predecessor adoption and exec cannot silently
  preserve an old generation. Exhaustion permanently disables reuse.
- The carrier caches a successful leaf validation together with the **retained
  authority object and generation**. Equal generation numbers on different
  authorities do not match. Any image mutation causes a fresh complete walk.
- Every activation still checks the live carrier binding, exact ledger entry,
  live owner generation/backing, and protection tracker. These checks were not
  replaced with assumed counters. Kernel snapshot stamps are checked before
  and after transport validation. The grant still borrows the active scope;
  no pointer is exposed outside activation.

This removes repeated snapshots and page walks. Owner lookup and protection
range queries remain live, so this is not a claim that all activation work is
independent of inventory size or that 102 ns is an irreducible floor. Ordinary
prepared-copy grants keep their prior path; the cache belongs only to native
spans.

## Measurement

The preserved old release executable and the candidate run in a predetermined
**baseline / candidate / candidate / baseline** sequence after compilation ends.
Within each executable, nine paired scope-only / scope-plus-activation samples
alternate order at every scale. There are **144 complete pairs and 24,920,064
successful timed activations**, plus untimed warmup. All samples are retained.
No filesystem I/O, preparation or COW runs inside either timed operation.

| Scale | Entries per arm/sample | Baseline entry + activation | Candidate entry + activation | Baseline added activation | Candidate added activation |
|---|---:|---:|---:|---:|---:|
| 1 | 4,096 | 1,463.9 ns | 200.7 ns | 1,428.7 ns | 149.3 ns |
| 8 | 32,768 | 1,418.5 ns | 140.3 ns | 1,382.3 ns | 104.1 ns |
| 32 | 131,072 | 1,413.4 ns | 138.4 ns | 1,377.4 ns | 102.3 ns |
| 128 | 524,288 | 1,421.8 ns | 138.4 ns | 1,385.6 ns | 102.2 ns |

Each column is the median of 18 samples; added activation is the median of
paired differences. Small-scale candidate startup variation is visible in the
raw data and has not been discarded. The two larger scale points agree. This
is a causal intervention on measured activation work, not an inference from
recurring profile frames. It supplies no Linux ratio and excludes platform I/O.

Runtime conformance metrics and the counting allocator are disabled in the
release diagnostic. The carrier test-support leaf counter remains compiled in
both the structural fixture and candidate diagnostic, but is visited only when
full validation occurs; every timed candidate activation uses the cached path.
The diagnostic executes host fixture code, not a guest ELF or an HVF VM.

- [Raw samples](cost-samples.json), [summary](cost-summary.json),
  [exact identities](cost-identity.json), [measurement driver](measure.py).
- Baseline SHA-256: `cde110d3f1aede9b1cebf23d01006dfcbe19119b81c9139ba73605808808bc5a`.
- Candidate SHA-256: `a291effbbdffeea80226243f362f0f028d5c140240e4b0bab15efc51f3626a4c`.

## Semantic and structural evidence

`kernel.mm.native-data-activation` is a new, bounded VM-free contract. Its
execution and Docker layers remain explicitly unresolved. It does not close
`kernel.execution.native-synchronous-syscall`.

The [red contract](red-contract.log) completes the real stores but fails the
zero-allocation budget: 56 / 448 / 1,792 / 7,168 allocations and
1 / 8 / 32 / 128 leaf validations. The [final contract](contract-final.log)
records zero allocations and zero leaf validations at all four scales, with
an explicit source revision and qualified positive controls.

Ten independent changes after successful activation are rejected: second-page
read-only rearming, tracker denial, unmap, owner-generation replacement,
read-only VMA, VMA permission change/restoration, executable VMA, a replacement
page-table authority with a deliberately colliding generation, remap to another
physical page, and backend rebinding with equal binding values. A separate
valid-image restore forces both leaves of an 8 KiB grant to be checked again;
a subsequent activation reuses that new proof. Existing wrong-authority,
pending-control, real-drain and successor-execution-lease checks remain passing.
Generation tests also cover rollback, failed edit/exec, replacement and overflow.
These are composed host fixtures; they do not substitute for a concurrent
carrier-backed guest fork or a signed native execution binding.

Verification:

- `just test-kernel`: **2,375 pass**, zero failures, one existing ignored test.
- Runtime memory: **27 pass** with metrics; the exact measured default release
  executable passes **26**. Nested subprocess output is not double-counted.
- Runtime backend lifecycle: **29 pass**; quiescence: **27 pass**; memory
  lifetime doctests: **4 pass**; AArch64 library: **66 pass**; observability:
  **83 pass**; HAL foreign-MM test: **1 pass**.
- Contract package: **33 pass**. Registry check: **29 contracts, 15 claims,
  59 surfaces**. The stale 26-descriptor assertion is updated and explicitly
  requires all three native contracts. Regenerated inventory changes only
  contract associations, including earlier unrefreshed campaign descriptors;
  claim and syscall-support states are unchanged.
- Existing bounded ELF controls: **20 cases pass**, plus **11 unit tests**.
  Exact streams and the executable hash are retained. These controls still use
  private backing; they do not exercise this new carrier activation path.
- Changed HAL/kernel/runtime/HVF packages pass `clippy --no-deps` with metrics.
  The AArch64 lint gate still reports the same six `manual_is_multiple_of`
  failures in `anonymous_discard.rs` and `engine.rs`; both files match their
  preserved parent hashes. Formatting and diff checks pass.

The initial short exact filter in `red-build.log` selected zero tests; only
`red-contract.log` is used as red execution evidence. Likewise the initial
`runtime-quiesce.log` selected zero tests; `runtime-quiesce-final.log` contains
the actual 27-test run. Those empty selections remain archived and are not
counted as validation.

## Signed gates and remaining work

The signed foreign-MM suite remains **73 pass, one fail, one ignored**. Its
failure is the already-recorded `kernel.mm.fresh-publication-maintenance`
budget: scale 1 has `PageTableInvalidations=1`, maximum 0. Its negative control
passes, cleanup finds zero matching processes, and the runner withholds a
success receipt. No budget, timeout or retry policy changed.

The separate signed carrier lifecycle test passes, as do its unentitled
negative control and scoped cleanup. Its [receipt](signed-lifecycle-receipt.jsonl)
binds the signed artifact, UUID, entitlement and DOF evidence. Re-signing for
this separate run is recorded separately; this receipt does not qualify the
failed broader suite or native guest execution.

The next useful step is **carrier control-ticket service followed by one
carrier-backed ELF memory-control round trip**, preserving the current stop/drain
protocol. Then run the invalid, unchanged-watch and churn controls through that
same path and measure the actual syscall/workload effect. That determines
whether the remaining 102 ns deserves more work. Code publication/revocation,
signals/cancellation and scheduling still need integration before full native
inotify09 acceptance. Keep raw Linux ratios and matched native macOS I/O
controls separate when measuring those workloads.

## Provenance and non-completion

Worktree: `/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick`;
source HEAD: `9bb2392396b8531e93f5262657bf3aa9c5767488`. No commit or push.
The [manifest](manifest.json), [15-file continuation patch](implementation.patch)
and source archives preserve this continuation and the parent campaign.
The measured archive predates only the final registry-test and generated
inventory updates; neither is linked into the measured runtime executable.
Red source is explicitly marked as reconstructed from the preserved pre-edit
archive and executed instrumentation script, with the retained red binary hash.

All four frozen product/native release control executables remain byte-for-byte
unchanged. No new inotify09 or Node/Go/Python speedup is claimed. Full CI,
product probes, smoke/full conformance, signed native execution and the overall
1x goal remain unclosed. The completed result is removal of approximately
**1.28 us of repeated carrier activation overhead** in this controlled fixture.
