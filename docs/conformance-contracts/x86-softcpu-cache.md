# Soft CPU translation reuse (#616)

`x86.softcpu.level0` binds unchanged loops to one decoded block, one emitted
block and one code-page walk at 64, 512 and 4096 executions. The witness drives
`SoftCpu::step_block` and evaluates the registered contract. Cold setup also
flushes the write plane once for initial mode synchronization and once when
the code frame first becomes marked. Repeated marks do not flush it.

The semantic authority remains the contract's Intel/AMD instruction and paging
rules and native x86 instruction differential. Cached plans retain every fetched
page, including a straddling terminal instruction. Each dependency contains its
authenticated physical frame, code generation, virtual page and host placement.
Warm validation requires a live executable TLB entry and unchanged generation.
A TLB miss authenticates the frame again through the walker: remaps, local
invalidation, CR3 changes and domain shootdowns cannot reuse stale authority.
Generation changes invalidate alias writes. Clearing or retiring a code page
also refuses reuse. Debug single-instruction policy and caller block limits
participate in cache identity. The cache owns at most 128 immutable RX blocks;
eviction occurs between blocks. Shared plans avoid copying decoded vectors on
hits. No executable pointer survives its owning cache entry.

Host fixture writes now notify generation changes, as guest writes already do.
The unsafe memory implementation must uphold that protocol for host mutations.
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

## Worker measurement

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
