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
