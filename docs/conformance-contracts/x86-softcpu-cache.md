# Soft CPU translation reuse (#616)

`x86.softcpu.level0` binds unchanged loops to one decoded block, one emitted
block and one code-page walk at 64, 512 and 4096 executions. The witness drives
`SoftCpu::step_block` and evaluates the registered contract. Cold setup flushes the write plane for initial mode synchronization, locally
on activation, and when serving the published domain debt. Repeated marks do
not publish new debt or flush the write plane.

The semantic authority remains the contract's Intel/AMD instruction and paging
rules and native x86 instruction differential. Cached plans retain every fetched
page, including a straddling terminal instruction. Each dependency contains its
authenticated physical frame, code generation, virtual page and host placement.
Warm validation requires a live executable TLB entry and unchanged generation.
A TLB miss authenticates the frame again through the walker: remaps, local
invalidation, CR3 changes and domain shootdowns cannot reuse stale authority.
Generation changes invalidate alias writes. Clearing or retiring a code page
also refuses reuse. Debug single-instruction policy and caller block limits
participate in cache identity. The cache owns at most 1,024 immutable RX blocks;
one-at-a-time eviction occurs between blocks. Shared plans avoid copying decoded vectors on
hits. No executable pointer survives its owning cache entry.

Host fixture writes use the typed physical host-copy API, which authenticates
ownership and advances active code generations.
In-block self-modification remains the previously documented #626 limitation.

The original production path failed the loop witness at 64 translations versus
one. The unchanged loop, alias-write/remap/NX witness, straddling instruction
witness and repeated-mark witness cover reuse and refusal separately. The
registered work metrics count blocks planned, blocks emitted and actual walker
entries; instruction bytes are not re-decoded on a cache hit.

`translation_cache_loop_timing` is an explicitly invoked release timing fixture:
20,000 increments and backward branches, with final accumulator and RIP checks.
Pair base and candidate executables on the same VM in alternating order. This
compares translation reuse only; it is not a Docker/native overhead verdict.
Signed HVF, Docker differential and ecosystem ratios remain higher-layer gates
on their supported hosts.

Reactivation mints a fresh generation, including when a peer marks the frame
before the original CPU next runs. The two-CPU production-entry witness was
red with the old generation rule: it returned the cached backward branch
instead of the replacement syscall. Generation exhaustion leaves the frame
inactive and refuses cache reuse rather than recycling an identity.

## Original worker measurement (before independent review)

On this Linux x86_64 VM, twenty alternating base/candidate release pairs ran
the same 20,000-block loop after builds stopped, under the job's VM-local lease.
The base used the admitted main engine, walker and context with the shared
timing fixture; unused counter accessors only allowed the other tests to compile.
The candidate used the final implementation. Every sample checked RAX=20,000
and RIP at loop entry. There were no retries or discarded samples.

Median base: 242.318 ms. Median candidate: 5.611 ms.
Median paired candidate/base ratio: 0.02324.

This narrow translation-reuse result does not establish a Docker/native runtime
ratio or ecosystem throughput. The native instruction differential and VM-free
suites passed; Docker is absent and HVF is unavailable on this Linux host.
The KVM device is present, but no KVM guest gate was run for this VM-free slice.
Whole-workspace lint-domains and test-kernel remain CI responsibilities.

## Independent-review correction

Activating a code frame now publishes `RevokeWrite` in its physical inventory's
invalidation domain. The caller also flushes its local write plane immediately;
parked peers serve the domain debt before their next host access or block entry.
This closes both native-store and host-helper warm-write-TLB witnesses. Dropping
the invalidation completion does not cancel the published debt; activation
retires no backing storage. Publication exhaustion makes the domain terminal.
Repeated activation of an already active frame publishes no new invalidation.

The cache is a keyed map with 1,024 resident translations and one-at-a-time FIFO
eviction. A changed code incarnation replaces the existing key and its RX owner
in place. FIFO order contains each resident key once. The capacity is bounded
independently of execution count, and eviction happens between block executions.
The capacity witness fills 1,025 distinct keys and verifies the second key stays
resident after the oldest is evicted. This replaces the reviewed 128-entry full-clear policy.

The additional contracts `x86.softcpu.cache-hot-set` and
`x86.softcpu.cache-smc` preserve the original unchanged-loop limits rather than
loosening them to fit different workloads. Ten laps around 129, 201 and 1,001
keys permit at most n block decodes, n emissions and n instruction-fetch walks.
The modifying row executes a native guest increment through an RW alias of
its own code frame, then jumps to an independent hot block and back, at 64,
512 and 4,096 laps. It permits n+1 decodes/emissions and 2*n+1 execute walks
(two instructions in the modifying block, one in the independent hot block). This is not an in-block self-modification claim (#626).
`code_walk_count` now excludes data walks.

`ExtentTable::write_host_bytes` owns the typed physical host-copy protocol;
`SoftMmuMemory::write_host_bytes` supplies the safe memory-owner entry point.
It requires a `FrameGpa` and exact `OwnerGeneration`, preflights the entire span
against the inventory and placement, and advances each active code frame's
generation before copying. Wrong owners, invalid placement, terminal inventories
and exhausted generations copy no bytes. The Level 0 fixture uses this API for
all post-publication host writes instead of hand-written generation callbacks.
The future carrier's exec/COW writers (#671) must use this same entry point.

The existing parallel APIC fixture still has separate inventories and does not
prove cross-vCPU code-generation coherence. The regression fixtures here share
one inventory and run two real SoftCpu instances in an interleaved schedule.
Parallel shared-inventory/carrier admission remains outside this slice; these
results must not be cited as proving that integration.

### Native x86_64 review witnesses and paired measurement

Both peer warm-write witnesses returned the old `Continue` exit on the reviewed
head instead of `Syscall` (test exit 101); both return `Syscall` with the domain
revocation (exit 0). Removing only the domain publication reproduces both reds.
The old cache decoded 1,290 blocks for ten laps around 129 keys, against 129
allowed. With the execute-only counter accessor held fixed, the native modifying
loop failed the old cache at 512 laps: 517 decodes against 513 allowed
(`ScalingViolation`, exit 101). All three scale points pass after replacement
in place. Removing host generation advancement returns the old jump after a
typed host copy (exit 101); making every mark flush fails the repeated-mark
walker witness (exit 101). The restored witnesses pass with exit 0.

Twenty new alternating release pairs on this VM compare the reviewed cache
policy against the corrected policy, with the same final walker, fixture,
dependencies and build profile. The old-cache arm uses the same execute-only
counter accessor to keep instrumentation definitions fixed. Each run completes
100 laps around 201 hot blocks (20,100 executed blocks), asserting the expected
successor at every block. Timing excludes setup; builds stopped before the
pairs. Every process returned exit 0, with no retries or discarded samples.

Median old-cache time: 237.993 ms. Median corrected-cache time: 7.685 ms.
Median paired corrected/old-cache ratio: 0.03244. This measures the cache-policy
change only; it is not a native/Docker overhead or parallel-vCPU verdict.

Final focused validation passed 181 regular tests and 16 doc tests. Both
`serial_host` partitions completed with zero matching tests. Focused clippy,
the pre-push hook, Linux cross-check and native KVM compile-check passed.
Docker and HVF are unavailable here. No KVM guest gate or signed promotion ran;
whole-workspace lint-domains and test-kernel remain CI responsibilities.

## Revival on current main (#616, supersedes #1491)

The independent-review follow-ups are tracked by
[seam #2397](https://github.com/carrick-sh/carrick/issues/2397), a blocking
dependency of #671, and [flaky #2398](https://github.com/carrick-sh/carrick/issues/2398)
for the Rosetta-only population reported in the review. Activation still drops
`PendingRetirement`; it publishes debt but does not wait for running peers.
The interleaved shared-inventory witnesses cannot prove parallel coherence.

The revived production-entry witness `unchanged_loop_walks_once_at_three_scales`
failed on current main at 64 executed blocks: 64 walks against one allowed.
The restored loop contract separately bounds decodes, emissions and execute
walks at 64, 512 and 4,096 executions. Main's SIMD/x87 admission paths and
witnesses are retained. The initial port failed the existing
`x87_cx16_and_fisttp_obey_installed_view` and
`advertised_baseline_faults_and_feature_revocation` tests deterministically:
plans retained admission/refusal across a CPUID-view change. The setter now
invalidates cached plans and FIFO keys after successful host qualification.

### Native x86 Linux revival evidence

Twenty full `cargo test -p carrick-softcpu-x86 --test softcpu_level0` runs
used default test threads, in four concurrent processes. Every run passed
119 tests, with zero failures and two explicitly ignored timing fixtures.
There were no discarded or repeated final-population runs. Failure sets:

| Run | Exit | Failure set |
| --- | --- | --- |
| 1 | 0 | `[]` |
| 2 | 0 | `[]` |
| 3 | 0 | `[]` |
| 4 | 0 | `[]` |
| 5 | 0 | `[]` |
| 6 | 0 | `[]` |
| 7 | 0 | `[]` |
| 8 | 0 | `[]` |
| 9 | 0 | `[]` |
| 10 | 0 | `[]` |
| 11 | 0 | `[]` |
| 12 | 0 | `[]` |
| 13 | 0 | `[]` |
| 14 | 0 | `[]` |
| 15 | 0 | `[]` |
| 16 | 0 | `[]` |
| 17 | 0 | `[]` |
| 18 | 0 | `[]` |
| 19 | 0 | `[]` |
| 20 | 0 | `[]` |

The initial uncorrected port separately failed the same two CPUID-change
witnesses in both observed suites (117 passed, two failed). It is retained as
red integration evidence, rather than included in the corrected population.
No non-deterministic native x86 failure reproduced in these twenty runs.
This does not attribute Rosetta's defect or prove parallel shared-inventory
coherence.

All fifteen Rosetta-fidelity failures identified by #1486 pass on this native
host: the eleven AVX cases (including the library native-leaf witness),
`exact_denormal_results_fault_when_underflow_is_unmasked`,
`scalar_cmpsd_reports_guest_invalid_operation`,
`sse_exceptions_and_reserved_mxcsr_bits_are_guest_faults`, and
`legacy_save_image_matches_native_x87_formats`.

Twenty alternating release pairs executed the same 20,000-increment loop
through `step_block`, checking final RAX and RIP in every process. Median
main time was 198.943 ms; candidate time was 5.032 ms; median paired
candidate/main ratio was 0.02453. Concurrent build/test load was present,
so this **suggests** roughly 41x faster execution for this narrow fixture.
It is not a Docker/native, quiet-host or ecosystem throughput verdict.

The broader `test-touched` gate also caught the newer v3 fixture bypassing the
host-write protocol: nine instruction-family tests reused stale bytes after
raw fixture copies. That fixture now calls `write_host_bytes`; all fourteen
v3 tests pass. The retained futex replay receipt also required three explicit
zero-valued soft-CPU metrics to preserve its exact work-snapshot comparison.
Its schedule, result and every existing counter remain unchanged.
