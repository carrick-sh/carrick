# Syscall cost and near-native execution campaign

Status: active investigation; no performance acceptance or integration claim.

## Objective and controls

Approach native execution cost across Node.js, Go, and Python with an explicit,
shrinking absolute budget for Carrick-added syscall overhead. Two times native
cost is an intermediate milestone, not completion. Measure common syscall
mixes, full workloads, and concurrent scaling; a cheap identity-call result
alone does not qualify an execution architecture.

The user accepts native macOS I/O being slower than Linux for now. Compare
Carrick's incremental I/O work with matched native macOS operations on the same
filesystem, retain the raw ARM64 Linux Docker comparison, and separately compare
direct host-file access with VM filesystem bridging. Do not subtract unrelated
medians or excuse Carrick-added copies, metadata work, or synchronization as
platform cost. Linux semantics, policy, observers, signals, cancellation, and
shared-state authority remain requirements.

DSR improvement is explicitly in scope. No execution strategy is selected solely
because it has a faster microbenchmark.

## Current baseline evidence

The frozen signed baseline is source `9bb2392396b8531e93f5262657bf3aa9c5767488`,
SHA-256 `726c6848cf145e2aa0474cb7b12189da08ad77931b620c243654e9a4690509c9`.
The reducer was freshly built; its exact executable and image hashes, commands,
and raw results are preserved beside this assessment. The worktree also contains
an unaccepted offset-lease alias correction; this profile does not measure it.

Untraced diagnostics at scale 65,536, nanoseconds per iteration, median of 21
internal samples (Carrick and Docker phases serialized):

| Operation pair | Carrick | Docker |
| --- | ---: | ---: |
| Add/remove watch | 3,481 | 1,000 |
| Invalid-fd add/remove | 3,011 | 249 |
| Re-add unchanged watch twice | 3,652 | 579 |

These are diagnostic baseline samples, not paired candidate acceptance. The
invalid-fd pair still executes Carrick dispatch and error handling: its latency
is not an irreducible VM transition floor. It motivates common-path attribution
before further watch-specific bookkeeping changes. No timed write/seek loop is
present in these phases; startup still creates the fixture file.

The bounded `hvpatch-carrier-cpu-low-rate` profile completed successfully:
1,732 samples, 598 distinct stacks, and exact population closure. Of those
samples, 832 (48.0%) contain Applevisor `Vcpu::run`. This is an opaque combined
guest/HVF/trampoline bucket, not a measured pure trapping cost. Host register
access, context ownership, reporting, and executor bookkeeping also appear.
Symbols outside the Carrick image remain unresolved and are not assigned to
specific host functions. Inclusive stack counts overlap and must not be added.

The first profile invocation requested an unsupported JSON summary and returned
nonzero after capture. It is not accepted. The corrected invocation omitted that
option, returned zero, and is preserved as `watch-profile-v2.raw.gz`. No Carrick
or DTrace processes remained in the subsequent inventory. Instrumented elapsed
times are not performance measurements.

## Architecture findings

1. HVF mailbox decode already captures `MailboxRequest.sp`, but
   `Aarch64Exit::Syscall` carries only the argument frame and resume PC. The
   runtime then calls `engine.get_reg(Reg::Sp)` for every dispatched syscall.
   Carrying captured SP through the trap envelope can eliminate that duplicate
   backend read without removing metadata from observers or `sigaltstack`.
   Prefer per-request metadata over a cache whose validity must survive task
   switching. Backends without captured SP must retain a correct fallback.
2. The current EL1 identity/clock shim already avoids selected HVF exits.
   Extending local completion needs exact authority, revocation, and policy
   checks. The in-progress alias regression demonstrates why a speculative
   shared-offset mirror cannot qualify solely on speed.
3. DSR's native backend was removed by `cc7d9eaa2a4ce61eab7b9daa59a4452f13a1d482`.
   Its implementation is available in Git history; historical design documents
   do not describe a currently selectable backend. Prior 0.2–0.3 microsecond
   identity-call measurements in `../native-dsr-syscall-floor.jsonl` establish
   only historical feasibility, not present-day parity with this kernel.
4. Rewriting a call site inside the VM does not itself let it call host Rust
   directly. A guest-local implementation must own the required semantics;
   otherwise a host transition remains. A native DSR execution adapter could
   avoid that transition but must also solve address-space ownership, translated
   memory access, JIT/self-modifying code, signals, and unified task scheduling.
   Restoring the old host-process-per-guest-process model is not an assumed step.

## Captured stack pointer candidate

The request now carries the transport-captured SP through `Aarch64Exit`,
`RawSyscall`, and `SyscallRequest`. HVF supplies the mailbox value. KVM/x86 and
synthetic callers that do not capture SP preserve a lazy fallible backend read.
There is no cross-request cache and no observer/interceptor metadata exclusion.
The structural test failed with one read against a zero-read budget before the
lazy fallback change, then passed at 1/8/32/128 operations, including captured
SP zero. The missing-value test preserves one read and its possible failure.

Frozen signed candidate SHA-256:
`f7129507c00b0847de6dca621bf7e016682e7e0d4a70ae53de0462473b8f316a`.
The separate production alias fix was excluded while building this candidate,
then restored in the worktree. This isolates the SP change in the paired timing
screen. The candidate is not a final integrated artifact.

Two sequential ABBA blocks (eight processes, each reporting 21 internal samples
per scale) completed with unchanged binary/probe hashes and all expected phases.
At scale 65,536:

| Operation pair | Candidate/base, block 1 | Block 2 | Geometric mean | Mean saving per syscall |
| --- | ---: | ---: | ---: | ---: |
| Add/remove watch | 0.9863 | 0.9843 | 0.9853 | 26.4 ns |
| Invalid-fd add/remove | 0.9861 | 0.9856 | 0.9858 | 21.9 ns |
| Re-add unchanged watch twice | 0.9863 | 0.9879 | 0.9871 | 23.9 ns |

This is a consistent 1.3–1.5% diagnostic microbenchmark improvement, not a
confidence-qualified performance acceptance or an end-to-end workload win.
No fresh Docker timing was needed to compare these two Carrick arms; the old
Docker diagnostic must not be described as contemporaneous candidate acceptance.
The gain is too small to justify further tuning of this metadata path. Next
priority is workload syscall density and transport-level architectural choices.

The kernel unit lanes passed. The first semantic-suite run failed registry
loading in 11 contract tests because the new descriptor used `embed` instead of
`embed_structural` for its unresolved binding. Correcting that declaration made
the full `just test-kernel-semantics` run pass. A subsequent complete
`just test-kernel` also passed. The signed filtered shard ran `altstacktid`,
`forkaltstack`, and `siglongjmpaltstack` with both freshly rebuilt musl and glibc
executables: all six matched source-hash-validated committed Docker oracles. The
unentitled negative control passed and scoped cleanup found zero processes.
This signed test artifact includes the restored alias fix; it is distinct from
the SP-only timed CLI artifact. This manifest defect was not a guest semantic
regression. Production-envelope work-counter binding and broad promotion remain
open.

## Next experiments and acceptance

- Complete the production-envelope structural binding for captured metadata;
  the focused signed alternate-stack checks have passed. Do not extend the SP experiment
  merely to accumulate additional small changes.
- Measure the modern workload mix before broad specialization: Node event-loop
  and networking, Go build/runtime scheduling, Python import/filesystem and
  subprocess activity. Report startup separately from steady state and measure
  single-thread and concurrent cases. Use Docker-only bpftrace for oracle shape;
  never run it concurrently with Carrick.
- Establish a diagnostic transport-only round trip separately from full
  dispatch; do not infer its value by subtracting the invalid-syscall median.
- Evaluate selective guest-local completion and a bounded DSR execution
  experiment against the same workloads. Include translation/indirect-branch
  overhead and semantic coverage in the decision, not just syscall entry cost.

The active near-native goal remains open. Captured metadata has red/green unit
evidence and a paired diagnostic timing screen. Its broad signed acceptance, a DSR
experiment, modern workload coverage, concurrent scaling, the alias correction's
final signed validation, and broad signed promotion remain incomplete. No commit
or push has been made for this campaign.

## Modern workload impact screen and next bounded experiment

The frozen SP-only signed candidate above was screened against pinned ARM64
Docker images, in serialized phases. These are single-pass diagnostic timings,
not paired performance acceptance. The interval includes workload process startup
but excludes container launch. Native macOS I/O controls are still outstanding;
these raw Linux ratios cannot yet be assigned wholly to Carrick overhead.

| Workload | Docker seconds | Carrick seconds | Carrick / Docker |
| --- | ---: | ---: | ---: |
| Node app smoke (files, crypto, child, TCP, worker, timer) | 0.102 | 0.506 | 4.96 |
| Go tiny build with fresh build cache | 0.862 | 1.430 | 1.66 |
| CPython test_os | 0.715 | 2.584 | 3.61 |
| CPython test_subprocess | 20.315 | 22.974 | 1.13 |

Both Python arms passed with matching executed/skipped populations. Subprocess
includes intentional waits, so its wall ratio does not establish a near-native
CPU or syscall floor. The first Node Carrick launch failed registry configuration;
the corrected invocation is explicitly retained separately. Image download is
outside the reported guest interval. Guest-reported user/sys values are not
physical host CPU attribution.

Docker-only bpftrace captures tracked the stopped command root and descendants,
completed naturally, and reconciled per-number counts to their total with no
remaining tracked tasks. Wrapper-inclusive syscall totals were Node 2,137,
Go 74,313, Python OS 155,750, and Python subprocess 16,942,439. The last includes
16,785,982 fstat calls. Both Python environments reported the same nofile limits
(1,048,576 soft and hard); a limit mismatch is not an established explanation.
Rejected early tracer captures are retained and are not counted as evidence.
Instrumented timings are not speed evidence.

A separate 20-iteration Node low-rate carrier CPU profile completed with 873
samples and exact population closure. Inclusive madvise handling appears in
547 samples (62.7%), zero_guest_backing in 421 (48.2%), physical_cow_source_in
in 294 (33.7%), and Vcpu::run in 122 (14.0%). These buckets overlap; they are
sampled CPU proportions, not predicted wall-time savings. Vcpu::run remains an
opaque guest/HVF bucket.

Source inspection identifies a bounded next candidate: zero_guest_backing
queries physical COW state before checking whether the mapping can use anonymous
remapping. Reusable global frames cannot use that remap, making that query's
result irrelevant for those mappings. First prove a zero-query budget for
ineligible mappings and exactly one query for eligible mappings, then make the
query lazy. Preserve live-owner authentication, actual zeroing, retained-fragment
publication, and COW semantics. This optimization is not implemented or timed yet.

Next decision gate: freeze matching control/candidate signed artifacts, obtain
paired untraced Node timings, check Go/Python for regressions, and run the relevant
signed memory/COW probes. Retain the change only with semantic evidence and a
workload-level benefit. If this does not move Node, return to the profile before
expanding the scope. DSR remains a later measured architectural option, not a
prerequisite for removing this demonstrated redundant work.

All workload drivers, image/binary identities, raw streams, rejected captures,
accepted counts, and profile symbolization are preserved under workloads/;
manifest.json records the original SHA-256 and size of each file (large files are
gzipped). No end-to-end improvement, platform-I/O attribution, absolute syscall
floor, or near-parity acceptance is claimed.

## Lazy COW-query implementation and measured impact

Implemented `scrub_remap_eligible` in the HVF guest-memory scrubber. Both live-IPA
and eligible VA-fallback paths now evaluate cheap independent remap guards before
querying physical COW provenance. Live mapping/owner authentication and actual
zeroing remain in place. The new `kernel.mm.scrub-remap-query` contract owns the
zero-query budget for ineligible mappings. The eager control failed that assertion
(one query versus zero at scale 1); the lazy implementation passed at 1/8/32/128.
Eligible mappings still query exactly once and preserve both COW outcomes.

The signed control and candidate both contain the earlier SP and offset-alias
changes. The control retains an eager COW query; the candidate makes it lazy.
Exact signed identities, full source patches, entitlement/UUID/DOF output, probe
receipts, and logs are preserved in `scrub-evidence/` and its manifest.

The first four-workload ABBA block completed. Node averaged 468.5 ms control and
298.5 ms candidate (36.3% less time). Go changed by -2.2%, Python OS by +4.1%,
and Python subprocess by +0.5%. The second block stopped on a control-side Python
subprocess timeout; it is incomplete and must never be pooled as a full series.

A separate focused screen investigated the potential Python OS regression using
the same frozen artifacts, two complete ABBA blocks, four observations per arm:

| Workload | Control mean seconds | Candidate mean seconds | Candidate/control |
| --- | ---: | ---: | ---: |
| Node app smoke | 0.44725 | 0.30400 | 0.6797 |
| Go cold build | 1.37550 | 1.35725 | 0.9867 |
| Python OS | 2.62200 | 2.60650 | 0.9941 |

Node is consistently faster (32.0% less workload time); the small Go/Python
changes are inconclusive. The earlier Python OS slowdown did not reproduce in
this focused comparison, but this does not certify regression freedom generally.
A subsequent serialized pinned Docker diagnostic measured 0.065/0.862/0.709 s,
respectively: candidate/raw-Linux ratios remain approximately 4.68/1.57/3.68.
These single Docker observations are not acceptance statistics. Native macOS I/O
controls and startup versus steady-state coverage remain outstanding.

Fresh musl/glibc mem, forkcow, and memflagmatrix signed executions matched their
source-validated cached Linux oracles (six combinations). Both unentitled
negative controls passed, scoped cleanup reported zero survivors, and
`just test-kernel-semantics` passed. The first shard-0 receipt was replaced by the
script's fixed receipt filename during shard 2; shard 0 was rerun explicitly to
preserve a complete artifact receipt, not to repair a test failure. The final
receipts for both shards are retained separately. Production guest work-counter
binding, windowcoherence live-oracle coverage, and broad promotion remain open.

### Control-side subprocess failure: do not erase this evidence

`floor-scrub-paired-4-A-python-subprocess` timed out at its unchanged 300-second
bound. The last test was
`ProcessTestCaseNoPoll.test_call_timeout`. Before cleanup, the Carrick LLDB
workflow saved a coherent kernel snapshot, event ring, all-thread backtrace, and
192 MiB modified-memory core. This diagnostic attach perturbed the run, so it is
not usable as a timing sample regardless of its terminal status. Scoped cleanup
reported zero remaining processes.

The snapshot contains running child pid/tid 274 with process-pending SIGKILL (9),
no blocked signals, and its parent pid 2 blocked waiting for that exact child.
One executor is inside HVF; other executors are parked. The last event-ring
records show the parent entering wait4 after earlier scheduler preemptions. This
is evidence of an undelivered kill while a child remains CPU-active; it is not
a proved root cause or a reason to add polling. It happened in the eager-query
control, so it is not introduced by the lazy-query candidate. Attribution to the
unmodified base versus other in-progress fixes remains to be established.

Next priority is a bounded reducer for this signal/preemption failure and a
red-first correction at the scheduler/interrupt ownership boundary identified by
that evidence. In parallel with that investigation conceptually (not overlapping
measurement processes), the Node optimization has a real workload benefit worth
retaining for further validation. Re-profile its remaining cost after correctness
closure; do not return to nanosecond SP tuning or declare a trapping floor.
The full goal remains active. No commit or push has been made.

## Signal lease-gap correction

The subprocess failure was reduced to 50 repetitions of Python's
`subprocess.call([python, '-c', 'while True: pass'], timeout=0.1)`, with the same
SelectSelector override used by ProcessTestCaseNoPoll. Both the frozen original
baseline and frozen scrub candidate hung under a 20-second diagnostic deadline,
after iteration markers 5 and 1 respectively. Their captured kernel states show
a CPU-running child with SIGKILL pending and its parent waiting. The initial
reducer attempt passed `-u` through the CLI and failed before guest execution
because that option was interpreted as Carrick's user argument; those setup
failures are retained separately.

The deterministic defect is in GenericVcpuRegistry: physical unregistration
removes a thread from the set traversed by wake publication. Previously accrued
debt survived migration, but a new wake published DURING an otherwise debt-free
lease gap was lost. A VM-free test forcing that exact order failed before the
fix. The correction retains logical membership in the existing debt map through
acknowledgement and physical lease absence; only logical retirement removes it.
Publication now covers those dormant members too. It also removes the temporary
vector allocation during publication. No new timer, polling loop, or retry was
added. Tests assert one record across 1/8/32/128 lease cycles, zero after logical
retirement, exact acknowledgement, and no inheritance by unrelated threads.
All 18 registry tests pass.

The fixed signed CLI artifact `carrick-lease-gap` completed all 50 reducer cycles.
The same pinned native ARM64 Docker fixture completed all 50 cycles. The full
Python subprocess suite then completed in 23.545 guest seconds, with 341 tests
run and 44 skipped. That is completion evidence, not a new paired speed claim.

A durable signed in-process regression now lives in
`crates/carrick-conformance-next/tests/signal_lease_gap.rs`, using the identical
Python fixture. Temporarily removing the production fix made this test fail with
KernelAborted at the harness's unchanged 140-second effective budget (20-second
request plus 120-second cold-start allowance). Restoring the fix made it pass in
5.24 seconds. Both unentitled controls passed and scoped cleanup found no
survivors. The failure runner deliberately does not publish a receipt; its old
fixed-name receipt was detected as stale and not used. The still-red signed test
executable was frozen before the green relink and verified with signing identifier
`tmp.63981`, matching the red log. Its SHA, CDHash, UUID, entitlement and DOF data
are preserved separately; the green run has the ordinary complete receipt.
`just test-kernel-semantics` and diff whitespace checks also passed.

The `kernel.signal.lease-gap` descriptor records the semantic binding and
explicitly unresolved versioned work observation, descriptor cost/storage budget,
and reusable Docker oracle binding. Direct unit storage assertions do not claim
full structural guest acceptance. Broad signed promotion, concurrent workload
scaling, and a paired performance screen covering this latest artifact remain
open. The prior 32% Node improvement belongs to the earlier scrub artifact and
is not silently reassigned to this newly linked binary.

Artifacts, source fixture, commands, red/green logs, and manifests are preserved
under `kill-reducer/`. Large cores and the frozen red executable remain at the
absolute local paths recorded in its manifest. Next, verify the updated artifact
on the workload screen and resume attribution of Node's remaining cost; establish
the still-missing matched native macOS I/O controls before assigning raw Linux
I/O differences to Carrick. The full near-native goal remains active.

## Updated workload screen and matched native I/O controls

Two complete ABBA blocks compared the frozen scrub candidate (A) with the
lease-gap fix (B), with no builds or Docker guests during measurement:

| Workload | A mean seconds | B mean seconds | B/A |
| --- | ---: | ---: | ---: |
| Node app smoke | 0.33225 | 0.30800 | 0.9270 |
| Go cold build | 1.36725 | 1.33950 | 0.9797 |
| Python OS | 2.57000 | 2.58325 | 1.0052 |

The Node gain from lazy COW lookup remains visible. These small differences
between the two already-optimized artifacts do not establish a separate speedup
from the signal correction (the first A Node observation was 383 ms). Subprocess
is excluded from this timing comparison because its pre-fix hang is already a
proved correctness failure; the fixed full-suite pass is recorded above.

A new same-source POSIX C control (`scripts/perf/io-floor.c`) measures hot-inode
buffered regular-file operations. Native Darwin and Carrick bind-mounted the
same host directory on `/dev/disk3s5`, mounted at `/System/Volumes/Data`.
Docker-local and Docker-bind used the exact same static ARM64 Linux executable.
Creation, warmup, verification and removal are outside reported timing. Every
process verified 64 bytes, file length, shared offset and cleanup. There is no
fsync; these numbers say nothing about durable storage throughput.

The host/Carrick phase and Linux-local/Docker-bind phase were serialized, each
with two ABBA blocks. Each process reported nine timed samples of 16,384
iterations per operation. Values below are medians of the four process medians,
in nanoseconds per iteration (write+seek contains two syscall invocations):

| Operation | Native macOS | Carrick, direct host | Linux-local | Docker host bind |
| --- | ---: | ---: | ---: | ---: |
| Rewind | 206 | 21 | 139 | 141 |
| pwrite 64 bytes | 976 | 3,266 | 339 | 12,360 |
| write 64 bytes + rewind | 1,229 | 2,267 | 476 | 12,889 |
| Valid-fd fstat | 241 | 2,034 | 170 | 160 |

This supplies an actual host-path bridge comparison: Carrick is approximately
5.7x faster than Docker-bind for write+seek and 3.8x for pwrite in this narrow
buffered control. It also exposes Carrick-added work: write+seek remains 1.84x
native macOS and pwrite 3.35x. Do not subtract these medians from unrelated
workloads or interpret the ratio as a whole-application I/O correction. No claim
is made about the Docker bridge's underlying implementation or other VM products.
The seek capability legitimately avoids a host syscall when its authority guards
pass; that row is not a full-host-dispatch floor.

The valid-fd fstat ratio is about 12x Linux-local, exceeding the project's 10x
pathology boundary. Performance promotion stays open/red for this case. The
same-host comparison (about 8.45x) shows platform-native filesystem cost cannot
explain most of this gap. The fixture deliberately measures VALID descriptors;
the existing EL1 descriptor-ceiling guard handles some invalid fstat calls,
so this ratio must not be assigned to all 16.8 million fstats in Python's Linux
subprocess census.

The original runner's `df -T` command returned empty successful output on Darwin.
A supplemental `df -h` receipt supplies the actual volume, and the durable runner
now uses that command. Original source/driver snapshots and hashes are retained.
A later optional phase selector in the C source was used only for profiling,
not silently substituted for the completed four-lane timing binaries.

## fstat attribution and transport decision

The bounded fstat-only low-rate profile completed naturally with 1,126 samples
and exact stack-count closure. Its first resolved frame was Vcpu::run in 429
samples (38.1%, combined guest/HVF bucket), fstat dispatch in 182 (16.2%, including
unresolved host callees), with the rest spread across memory writes, clocks,
reporting, scheduling, context ownership and metadata. Inclusive counts overlap;
no CPU share here is an additive wall-time saving. The profile did not reveal a
single COW-style redundant operation dominating this path.

The existing standalone HVF syscall-tax probe was freshly built and signed with
the shared post-link signer. Stage-1 aggregate round-trip cost was 727 ns; batch
p50s were 750/750/750/833/959 ns (original order retained). The register-traffic
arm was 796 ns aggregate and 792 ns for all five batch p50s. These are current
micro-VMM reference measurements, not an absolute floor or production mailbox
cost. The initial stage-1 batch was slower; core placement is uncontrolled and
the full distributions and load metadata are preserved.

A mandatory HVF exit for every cheap host operation is therefore a poor route to
1x: this measured transport alone exceeds the native macOS valid-fstat control.
Do not reopen the previously rejected helper-thread portal unchanged: the
2026-09-20 assessment records worse wall time and a cancellation race. The next
architectural experiment should evaluate an exception-free, same-thread DSR
kernel gateway, with full register/TLS/state preservation and the CURRENT kernel
request path. It must also account for per-mm address translation and guest
compute overhead before any production adoption decision. Reintroducing the
retired host-process-per-guest-process architecture is not authorized by this
experiment. A cheap identity-call result alone remains insufficient.

All controls, artifact/source identities, raw streams, current workload rows,
profiles and transport distributions are under `io-controls/`. Formal timing
acceptance, concurrent scaling, broader I/O shapes, shrinking per-syscall budgets,
and a DSR feasibility result remain open. No commit or push has been made.

## Current-kernel direct dispatch baseline

A new non-product `kernel-syscall-floor` executable calls the current public
`dispatch_threaded_with_mm_executor` path, retaining exact MM authority checks,
`prepare_syscall`, default policy and entry/completion reporting. It keeps one
resident executor admission across the synchronous batch. The example backend
supplies linear guest memory and null signal/timer bridges. This is NOT a guest
execution benchmark, DSR gateway result, production signal/cancellation proof,
or a complete observer-interface integration proof.

Two complete release processes each verified 7,280,003 syscall entries and
successful completion records, return values, and the 64-byte fstat result.
Each process used four alternating operation-order blocks, nine samples per
operation/block and 100,000 calls per sample; warmup is outside timing.

| Operation | Process 1 median ns | Process 2 median ns |
| --- | ---: | ---: |
| getpid | 70.15 | 66.36 |
| valid fstat | 521.95 | 538.13 |

The first setup attempt failed ENOENT because HostFsBackend creates its own
nested scratch root. The fixture now creates/writes the file through guest
syscalls. A second attempt deliberately failed the reporter check: the dispatcher
records entries but caller code owns completion reporting. Completion reporting
was added before the two accepted runs. Neither rejected run supports timing
claims. Existing feature-dependent unused-mut library warnings remain in build
logs; the new binary built successfully. No product implementation changed.

This evidence supports continuing the bounded same-thread gateway experiment:
the current kernel can dispatch an identity operation far below the previously
measured HVF transport reference. Valid fstat still costs hundreds of nanoseconds
without that transport. Earlier native/macOS and HVF controls used different
artifacts and memory paths; subtracting their medians here would not establish
an exact transport saving or incremental fstat overhead.

Next decision gate: measure an explicitly validated register-save/stack-switch
wrapper around this same dispatcher before restoring any DSR backend. Guest TLS,
translated memory, asynchronous signals/cancellation, migration and translated
compute remain separate unresolved requirements. Common-mix and concurrent
shrinking absolute budgets remain open; these two operations do not establish
coverage of the vast majority of syscall interactions. Evidence and exact
source/binary identities are in `direct-dispatch/`. The full goal remains active.

## Same-thread physical-register gateway envelope

The bounded gateway experiment now has two complete paired release runs. Both
arms call the SAME non-inlined function-pointer callback into the current
public dispatcher. The gateway arm additionally spills/restores the physical
GPR state, all 32 128-bit SIMD registers, NZCV/FPSR/FPCR, and switches to a
separate aligned 1 MiB native stack. Physical x18 is preserved rather than
repurposed. x0 deliberately carries the callback return value. This is an
experimental native ABI envelope, not a Linux guest trap or translated backend.

An assembly oracle seeds register values, snapshots before/after, and calls an
ABI-conforming callback that destroys caller-saved GPRs, SIMD registers (including
the caller-saved upper halves of v8-v15), and status registers. A deliberately
incomplete wrapper failed those checks. The full wrapper passed. Independently
removing the stack switch preserved registers but failed the callback-stack-range
assertion. Both negative sources and error logs are retained. The normal wrapper
was restored after fault injection. Return values, original SP, register state,
and callback stack range are checked before timing. These checks do not qualify
unwinding, stack overflow, arbitrary TLS state, or asynchronous interrupts.

Each process ran two ABBA blocks per operation, nine 100,000-call samples per
arm, with untimed warmup. All 14,560,003 actual dispatches per process have
matching entry and successful-return counts; fstat returned the fixture size.
No guest, Docker, or build ran alongside these measurements.

| Operation | Run 1 direct / gateway ns | Run 2 direct / gateway ns |
| --- | ---: | ---: |
| getpid | 66.10 / 87.25 | 66.08 / 82.00 |
| valid fstat | 516.76 / 534.21 | 521.84 / 545.15 |

The differences of pooled medians are approximately 16-23 ns. The more useful
individual ABBA-block contrasts range from 11 to 31 ns; one first-process
getpid block had approximately 102-103 ns gateway arm medians. Preserve that
variation rather than claiming an absolute 20 ns floor. These native results
cannot be multiplied into an application speedup or directly subtracted from the
earlier HVF workload results.

### Decision and provisional absolute budgets

Continue DSR feasibility: full physical register preservation plus stack switching
is cheap enough in this experiment to justify testing the missing semantics.
Do not restore the retired execution backend wholesale. Stop refining this
wrapper's few nanoseconds until real translated guest execution supplies evidence
that they matter. The next material questions are per-mm translated memory cost,
guest TLS preservation, synchronous and asynchronous signal/cancellation delivery,
and translated compute overhead under the shared kernel graph.

For the next comparable envelope experiment, use a provisional maximum of **50 ns
added gateway cost in each ABBA block**, measured as the difference of the means
of the two arm medians. The next shrinking target is **25 ns per block**; current
evidence does NOT pass that stricter target in every block. Track identity-call
end-to-end envelope medians against **100 ns per arm**; one current arm pair
exceeds that target. These are experimental investigation budgets, not relaxed
conformance limits or claims about the vast majority of production syscalls.
Valid fstat's roughly 0.54 us envelope also leaves substantial shared kernel work
to remove. Its native control must be re-paired before asserting an incremental
native-fstat budget. Common-mix, per-call tails, concurrency, exact signed guest
provenance, and end-to-end application acceptance remain open.

Frozen timed source snapshots, raw samples, negative-control receipts, per-block
statistics, and binary hashes are in `gateway-envelope/`. The subsequent removal
of an unnecessary Rust closure `drop` only addresses a Clippy warning; timed
source snapshots are retained unchanged. Existing feature-dependent library
unused-mut warnings remain outside this probe. No runtime behavior was changed,
no commit or push was made, and the full near-native goal remains active.

## DSR scope check and refreshed Node attribution

Inspection of the removed DSR implementation at `cc7d9eaa2^` confirms that the
native register envelope omits real backend work: `carrick-native-darwin`'s
`carrick_native_dsr_enter_guest_abi` manages active context, deferred kicks and
custom-x18 host ABI state; `carrick-dsr-aarch64` rewrites guest memory operands
and classifies TPIDR reads/writes as sensitive instructions. The historical
shape census records substantial per-access spill and block-transition cost.
Those historical measurements are not current performance predictions. Today's
nonidentity, generation-authenticated shared-kernel memory model also cannot be
replaced by the old host-process-per-guest address model.

This warrants a prioritization check before another DSR microbenchmark. The
recorded Node Linux workload has only 2,137 wrapper-inclusive syscalls. As an
illustration, saving 1 us on every one would save about 2.1 ms; that is NOT a
Carrick transition count or a measured speedup. It makes syscall entry alone an
unlikely explanation for the remaining roughly 300 ms Node workload time.

A fresh 20-iteration app-smoke profile on the exact frozen lease-gap binary
(SHA `15217a034e2f3286420e9464b1fb2fcf1f576f0b44c2c58f458a2b9a95f96efc`)
completed with the workload success marker, trace status ok, no drops/errors,
570 samples with exact stack-count closure, and scoped cleanup zero. Inclusive
madvise appears in 237 samples (41.6%), zero_guest_backing in 123 (21.6%), and
retained_private_reuse_alias_fragment_in in 95 (16.7%). The first resolved
Vcpu::run bucket has 141 samples (24.7%) and remains opaque guest/HVF time.
Inclusive buckets overlap and cannot be added or treated as savings.

The retained-fragment existence query searches VA size classes smallest-first.
The candidate tries widest-first ONLY for this existence query, retaining the
identical scope, full-range and IPA predicate. Newest/oldest alias selection,
owner-generation authentication and fragment publication are unchanged. A unit
fixture with one matching wide owner and 1/8/32/128 unrelated narrow fragments
failed on the old order (two rather than one predicate at the first scale), then
passed the one-candidate bound. Existence answers are compared to the original
query for matching, rejected and absent candidates. All 12 filtered retained
mapping tests pass, including exact-owner-generation and sibling-unmap cases.
The descriptor explicitly leaves versioned work observations and signed binding
open rather than claiming an unrelated metric measures candidate visits.

Matched signed control and candidate artifacts were built with the same new
query seam, changing only search order. Paired untraced Node/Go/Python OS screening
is the retention decision; no workload win is established by the profile or unit
budget alone. DSR remains in scope, but further wrapper tuning is lower priority
than a demonstrated remaining workload hotspot. Evidence is under `retained-query/`.

### Retained-fragment ordering: untraced workload result

The first two ABBA blocks completed all Node, Go-build and Python-OS arms.
Node candidate times were 256/261/263/266 ms versus warmed controls at
300/302/304 ms (the first control was 365 ms). Its pooled mean ratio of 0.823
therefore overstates the warmed comparison and is not the headline.
An independent two-block Node-only confirmation produced controls
307/296/293/291 ms and candidates 248/248/243/255 ms: **16.3% less mean guest
execution time**, with every candidate below every control. This is incremental
to the prior lazy-COW-query and signal fixes; it is not compounded with the
older 32% result. Go's first-screen ratio was 0.975 and Python OS 0.994; those
small changes are inconclusive. All workload processes exited successfully.

The production ordering candidate is retained pending its signed memory gates.
No common-syscall baseline, DSR feasibility or near-native claim follows from
this Node result. Source patches and both signed CLI artifact identities are
preserved with the paired driver and raw logs.

### Retained-fragment signed validation and current raw Linux screen

Fresh signed in-process `mem`, `forkcow`, and `memflagmatrix` probes matched the
source-validated cached Linux oracles for both musl and glibc (six comparisons).
Both signed shard runs passed their unentitled negative controls and scoped
cleanup found zero survivors. Each receipt was copied before the next signer
could overwrite its fixed output path. Probe executable hashes and exact signed
test identities are retained. These focused gates do not replace the full probe,
smoke/ecosystem or concurrent-scaling promotion ladder.

The descriptor registry initially rejected the unresolved binding key `embed`;
it now uses the required `embed_structural` key and the registry-load test passes.
This records a real missing work-observation binding rather than disguising it
as a completed contract.

After all Carrick guests and builds had stopped, a fresh pinned native ARM64
Docker diagnostic completed Node in 64 ms, Go in 832 ms and Python OS in 683 ms.
Against the candidate confirmation mean for Node (248.5 ms) and first-screen
means for Go/Python, the raw ratios are approximately **3.88x / 1.58x / 3.74x**.
These single Docker observations are diagnostic, not formal paired timing
acceptance, and are not corrected by subtracting unrelated macOS I/O medians.
They make the remaining gap visible: another substantial Node improvement does
not establish near-parity. No new Go/Python speedup or DSR production result is
claimed. The goal and broader promotion remain open.

The focused HVF library Clippy gate passed with warnings denied; formatting and
diff-whitespace checks passed. No commit or push has been made.

## Stat allocation contract integration

The previously open shared-offset signed regression now passes on the current
source, with its entitlement negative control and scoped cleanup zero. Its exact
signed receipt is preserved under `stat-allocation/`; this closes that focused
binding, not broad promotion of the campaign.

The common warm valid-file fstat path was allocating three host heap objects:
cloned path-bearing metadata, a lossy owned path string, and a temporary PathBuf
used solely to convert mode bits. An instrumented public-dispatch probe reproduced
3 allocations at scale 1. The initial bespoke assertion was insufficient as a
contract binding. Following the user's correction, it now emits the shared
`ContractObservation` type, loads `kernel.fs.stat-allocation` through
`ContractRegistry`, and calls the common `evaluate` function. A new typed
`HostHeapAllocations` metric distinguishes these events from guest backing
allocations. The TOML descriptor owns an affine zero budget at scales 1/8/32/128.

Actual pre-fix execution through that interface emitted 3/24/96/384 allocations
and failed with `ScalingViolation { metric: HostHeapAllocations, actual: 3,
maximum: 0 }`. Every row has a source-bundle identity, semantic assertions, a
work snapshot and completeness; there is no timing in the structural observation.
The allocator has an independent positive control and is enabled only by the
non-product `allocation-metrics` feature. Such a binary refuses to emit timings.
Normal product binaries do not use the counting allocator.

The candidate removes the path parameter from real-stat conversion and snapshots
scalar fallback values while holding the existing description lock. Host fstat
still executes after that lock is released, and device-node overrides are unchanged.
The first candidate correctly stayed red: eager fallback normalization retained
one allocation per call. That failed observation is preserved rather than called
green. The next candidate hashes already-normalized relative path bytes directly,
while retaining the old normalization path for dot components, repeated/trailing
separators and root escapes. Raw undecodable names and reversible encoded names
are checked against the existing normalize_raw identity. Eight focused inode
checks pass; four earlier fstat tests pass.

Signed stat/metadata proof, uninstrumented paired timings, and broad promotion
remain pending. No syscall speedup is claimed from the allocation instrument.

The final candidate emits 0/0/0/0 host heap allocations and passes the shared
contract evaluator at all four scales. The complete conformance-contract crate
test suite passes after updating its live registry inventory from 15 to 20
contracts (claims remain 15). Final observations, source and binary identities,
source snapshots, and instrumented-timing rejection are preserved in
`stat-allocation/`. This closes only the VM-free allocation budget.

### Uninstrumented fstat dispatch screen

Two ABBA blocks used separately frozen, uninstrumented release binaries built
from the same harness, with only the five stat implementation files restored
to HEAD for the control. The candidate sources were restored immediately after
the control build. Each process verified 7,280,003 successful dispatches and
reporter completions. Mean process medians: fstat 551.85 ns control versus
470.92 ns candidate (14.7% reduction; individual ABBA blocks both improve),
getpid 67.96 versus 67.85 ns. Raw samples, binary hashes and candidate sources
are in `stat-allocation/fstat-timing-*`. This screen includes public kernel
dispatch, policy and reporting, but excludes HVF guest transitions, translated
guest memory and real signal bridges. It does not establish a guest latency
improvement, DSR floor, or workload gain.

The freshly rebuilt signed embed probes fdstat, statfdino, fstatatflags and
linkstat all agree with their source-hash-validated cached Docker oracle for
both musl and glibc (8 rows). All three selected shard executables passed, the
unentitled control passed, and scoped cleanup reports zero remaining guests.
The signed receipt and rebuilt probe/helper hashes are retained. These probes
cover semantic composition; they do not emit the allocation structural
observation, which remains VM-free only.

### Real guest microbenchmark and Carrick trace

The current CLI was built with the signed build recipe and frozen as SHA-256
5936b1522fb26651edb376133cd4dc7c72e48569813c739bbb10b19db6e1f784.
Signature, entitlement, UUID, DOF, HEAD and source patch identity are recorded.
Two untraced ABBA blocks against the earlier retained-query candidate produce
mean process medians of 2144.02 ns control and 2067.24 ns candidate (3.58% lower).
Each arm completes nine measured batches of 65,536 fstats plus warmup, validates
size/offset and removes its fixture. The initial parser mistakenly counted the
final semantic confirmation as a timing row; it was corrected, preserving and
reusing that complete first control capture. No failed guest was retried.

`carrick trace --require-script-exit` with the existing fstat-service-lowering
script closes 32,770 begin/end/clear windows exactly, reports status=ok with no
nesting/orphans/mismatches/errors, and counts 32,770 host fstat64 calls, 3
fgetxattr, 2 ioctl, zero Mach traps and 5 faults across the full process. Thus
there is no repeated host-fstat amplification in this fixture. Instrumented
batch latency is about 10.5 us/call and is not acceptance timing.

A separate bundled low-rate profile completes naturally with 1,430 samples and
exact stack-count closure: first resolved frames include Vcpu::run 532 (37.2%),
fstat dispatch 214 (15.0%), Timespec::now 53 (3.7%), ReceiptLog::record 27 (1.9%),
and CompatReporter::record 25 (1.7%). The first resolved frame can include
unresolved callees; Vcpu::run includes guest/HVF activity and is not a measured
irreducible trapping floor. Remaining work is distributed. This reinforces
prioritizing shared per-syscall runtime costs and transport architecture over
further fstat-only tweaks. Captures, commands, fixture/script/binary hashes,
symbolication and zero-residual cleanup are retained in `guest-trace/`.

The descriptor now names existing signed semantic and cached Docker bindings,
while keeping the production allocation observation and broader promotion
explicitly unresolved. Registry tests pass after the binding update. Full
probe/smoke/ecosystem promotion and workload impact remain open.

## Current workload impact and priority reset

Two fresh ABBA blocks compared the current signed fstat candidate against the
retained-query candidate on Node app-smoke, Go cold build and Python test_os.
All 24 runs completed; scoped cleanup confirms zero survivors. Pooled ratios
(candidate/control) are 0.972/0.977/0.978, but the first Node/Go controls are
slower and Node's second block reverses direction. These data do not establish
a meaningful end-to-end gain from the latest syscall optimization. Keep its
verified 3.6% fstat benefit, but stop further fstat-only tuning.

Two separate native ARM64 Docker passes followed the Carrick phase. Candidate
means are Node 266 ms, Go 1.3155 s and Python OS 2.50675 s; Docker pairs are
60/49 ms, 841/813 ms and 685/689 ms. Raw ratios are 4.88x/1.59x/3.65x. These
are phase-separated diagnostic comparisons, not paired Linux acceptance or
I/O-adjusted ratios; the Node denominator variation precludes treating the
change from the earlier 3.88x screen as a Carrick regression.

Fresh natural-completion carrier profiles on the current exact signed binary
close 472 Node, 1,865 Go and 787 Python samples with no trace errors. Node has
173 inclusive madvise samples (36.7%; overlapping stacks), including 85 first
resolved at madvise; COW range lookup and backing handling remain visible.
Python has 90 first-resolved directory-enumeration samples (11.4%). Go has
1,119 first-resolved Vcpu::run samples (60.0%), a combined guest/HVF bucket
that cannot be called transition overhead. All three profile workloads emit
success markers and scoped cleanup zero.

Next priority: Node's DONTNEED/backing path, followed by Python directory
enumeration. The source currently walks scrub backing in page-sized chunks,
resolving retained/live translation and authenticated owners for each chunk;
this is a measured optimization candidate, not authorization to bypass those
identity checks. Define a contract for reusable authenticated range work and
prove its scaling before changing the path. Shared syscall and DSR work stays
in scope, but must demonstrate workload-weighted benefit rather than accumulating
small microbenchmark wins. No workload-parity or campaign-promotion claim.

## Node madvise shape: large-range work, not just syscall entry

The previously unresolved 0x192b36a70 frame was resolved live through atos
against the local shell's same-boot shared libraries as __bzero +64. It appears
in 80 of 472 Node profile samples (16.9%), under madvise. This is eager clearing
work; it is not a direct count of bytes or proof that all requested pages are
materialized.

A dedicated bounded Carrick trace uses the existing service-window and scalar
argument probes. Its first capture was rejected: concurrent Node threads made
shared scalar begin_windows++ lose one increment (2533 vs 2534 aggregate
begins). The corrected script uses DTrace aggregation counters for closure.
Its 20-iteration workload completes with exactly 2,530 begins, ends, clears and
argument records, status=ok, no errors/nesting/orphans/mismatches, and scoped
cleanup zero. The original rejected capture remains retained.

The accepted capture requests 17,875,107,840 bytes of MADV_DONTNEED: 893,755,392
bytes per app-smoke iteration, including three 256 MiB requests per iteration.
MADV_DONTFORK is counted separately and is not zeroing evidence. Requested
bytes can overlap and are NOT actual bytes cleared or unique physical bytes.
This scale makes range handling/discard a more plausible workload target than
saving another few nanoseconds in the general syscall entry path.

Source inspection: Aarch64 zero_backing runs ensure_frame_cow_write with
BackingMaintenance and then the backend scrub. Maintenance classifies each
4 KiB page because neighboring retained outputs may have different live/shared/
retired owners; backend scrub authenticates each page before coalescing writes.
These safety properties must remain. The exact-MM deferred-anonymous state
already provides pristine provenance and materialized-subrange enumeration.
Next hypothesis is to avoid page work for authenticated pristine subranges,
with a contract proving no materialization/zeroing for untouched anonymous
pages and unchanged writes for materialized, shared, retained and forked cases.
This is not yet implemented or established as the source of the measured bzero
time. True discard of materialized pages requires separate rollback-capable
stage-1/stage-2/owner retirement; do not substitute a VA-only skip or host remap.

## Rejected experiment: whole-range pristine scrub bypass

A conservative prototype queried exact-MM pristine provenance before the
existing COW preparation and physical scrub. Missing/partial/disabled authority
kept the original callback and errors. Its descriptor and shared
ContractObservation/evaluate fixture failed red on the original callback
(HostBackendCalls actual=1, maximum=0) and passed at 1/8/32/128 pages with the
prototype. All 61 AArch64 lib tests passed. A new signed embed fixture checks
twice-discarded untouched ranges, partially dirty ranges, and parent/child COW
isolation at the four scales. It passed, as did the unentitled control; a fresh
pinned native ARM64 Docker run of the identical fixture matched all four rows.
Signed receipts and source hashes are retained.

The initial two-block Node comparison suggested 9.1% improvement, but this was
entirely in the first block; the second block was unchanged. A separately
initialized confirmation warmed BOTH arms before two ABBA blocks and produced
candidate/control 0.9915 (0.9% apparent improvement), insufficient evidence of
a workload win. The prototype was therefore REMOVED from production, along
with its helper, dev dependency and live registry descriptor. Its full source,
contract descriptor, red/green logs, signed artifact and timing evidence are
archived here, so the experiment is reproducible. The new semantic fixture is
retained for the next memory-discard change. No performance gain is claimed.

Important artifact state: target/release/carrick still contains the rejected
prototype until rebuilt. Use the prior frozen fstat candidate
/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-fstat-allocation
for the retained implementation, or rebuild signed before any new acceptance
run. The no-win result does not disprove partial-pristine range work or true
materialized-page discard; those require actual work counts before another
optimization. Do not generalize from requested bytes to bytes cleared.

## Actual backing-scrub census

Added a disabled-by-default USDT probe at completed ScrubRun flushes. Its scalar
ABI is (total bytes, explicitly zeroed bytes, successfully remapped bytes,
remap eligibility 0/1). A successful partial remap counts only its explicit
tail as zeroed; failed/ineligible remaps count the full explicit clear. It
does not change clearing or ownership behavior. The non-USDT stub is present.
The observability library's 83 tests pass and the signed CLI build succeeds.

A fresh 20-iteration Node capture closes exactly 2,535 service begin/end/clear
and request records, status=ok, without errors/nesting/orphans/mismatches.
It records 616 completed scrubs totaling 16,129,982,464 bytes, ALL explicitly
zeroed; remapped bytes are zero and every recorded byte is ineligible for the
existing anonymous host-remap shortcut. Thus actual explicit clearing averages
806,499,123 bytes per Node iteration, not merely the earlier requested length.
Requested DONTNEED bytes total 17,875,369,984 separately. Both independent
partitions reconcile, the workload completes, and scoped cleanup is zero.
Timing from this instrumented run is not performance evidence.

This rules out sparse-page traversal alone as a sufficient next target. True
anonymous backing discard, followed by zero-on-demand publication, is now the
leading candidate. Existing unmap retirement already disarms exact COW ranges,
supersedes receipts and retires process aliases under MM exclusion, but it also
changes mapped/execute metadata; it cannot be substituted blindly for DONTNEED.
The new path must retain semantic VMA and exact R/W/X permissions, preserve
shared/fork-peer contents and 4-KiB siblings, publish pristine provenance only
after old backing becomes unreachable, and keep failure rollback/terminal
classification explicit. No host MAP_FIXED bypass of stage-2 owner authority.
The next contract should measure GuestMemoryZeroBytes=0 for full eligible
anonymous discard while retaining separate partial-host-granule/fallback
budgets and semantic tests at 1/8/32/128. This lowering is not implemented yet.

The ordinary target/release/carrick now contains retained code plus census
instrumentation, replacing the previously rejected pristine prototype. Exact
signed identity is in scrub-census-artifact.json; no broad promotion is claimed.


## Rejected experiment: scrub only materialized subranges

Source inspection found that ensure_frame_cow_write first invokes
ensure_sparse_mmap_backing over the full request. This made the earlier claim
that actual bzero alone rules out sparse-range work too strong: the maintenance
path can itself materialize pages. A second bounded experiment used exact-MM
pristine provenance to enumerate non-pristine subranges before invoking the
unchanged COW preparation and authenticated scrub for each subrange. Missing
or disabled authority, zero length and overflowing ranges retained the original
callback and errors; unknown gaps were still scrubbed.

The shared ContractObservation/evaluate test failed red with 8192 zeroed bytes
against a 4096-byte budget. Green passed scales 1/8/32/128 with one dirty page,
including unchanged provenance. All 62 AArch64 tests and the contract registry
passed. The signed candidate SHA-256 is
9ba591aa5f0d1d269edea2b716d3f3165916b625f8d793e54164984b483f8dff;
full source, entitlement, CDHash, UUID and DOF receipts are archived.

Both arms were warmed before two untraced ABBA blocks. Control Node times were
245/249/253/258 ms; candidate 239/270/253/251 ms: candidate/control 1.00796,
no demonstrated improvement. A natural-completion candidate trace closed 2531
service begins/ends/clears and request records, status=ok, with zero remapped
bytes and 16,128,933,888 explicitly zeroed bytes over 20 iterations. Against
the control census of 16,129,982,464, that is only 1,048,576 fewer bytes total,
0.0065%, or about 806.45 MB per iteration instead of 806.50 MB. The total
includes incidental startup variation; it establishes that essentially all
of the clearing remains, not a meaningful byte-reduction benefit.

The experiment is rejected and its production helper, routing, dependency and
live descriptor removed. Its complete evidence is retained under
sparse-scrub-experiment/. Post-revert AArch64 tests pass 59/59. All benchmark
run IDs and the trace have scoped zero-residual cleanup receipts. No signed
semantic promotion was attempted after the experiment failed the workload
benefit criterion. Existing signed discard/fork fixtures remain available.

Next Node work must address existing materialized backing rather than another
pristine-range shortcut. The current remap fast path explicitly excludes
reusable global-frame extents; removing that exclusion would bypass ownership
and stage-2 obligations. A proper private-anonymous discard needs an explicit
semantic operation, preserving VMA R/W/X and fork peers while retiring this
MM's backing visibility, with partial 16-KiB host-granule handling and rollback.
That architecture is not implemented or proven by this experiment.

Artifact caution: target/release/carrick still contains the rejected second
prototype until rebuilt. For retained code use the frozen signed
/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-scrub-census
(SHA 68bc1a5eec7d76f41bcdcbab067c28af4bda66025fc8603606a7135c2bf6c4bc),
or rebuild signed. The separate frozen carrick-sparse-scrub is evidence only.


## Discard semantics boundary: signed red, Linux green

Expanded the existing in-process signed discard fixture with dirty-to-read-only
MADV_DONTNEED and child-only 4-KiB discard preserving neighbors and parent bytes.
The retained production code fails the read-only check at fixture line 46:
madvise succeeds, but bytes are not zero. Consequently the subsequent partial-
granule case was NOT reached on Carrick. The exact same fixture passes all
four scale rows and the partial-granule fork row on pinned native ARM64 Docker.
The existing read-only kernel test asserts residency only, explaining the
coverage gap. Signed artifact receipts, unentitled negative control, source
hash, failure transcript, Docker output, and zero-residual cleanup are archived
under discard-boundary/. No production fix or performance gain is claimed.

Source locates the problem in MADV_DONTNEED's aggregate meta.writable gate.
The future semantic operation must decide per private-anonymous segment,
independent of guest write permission; do not alter the semantic protection to
make clearing convenient. anonymous-discard-design.md records the prepared
retirement seam, MM exclusion order, publication/failure requirements, and
acceptance measurements. The expanded fixture intentionally remains red until
that correctness obligation is implemented. Full signed promotion remains open.


## Retained correctness fix: private anonymous discard is per segment

The MADV_DONTNEED branch now classifies each covered segment by private-
anonymous provenance, independent of guest write permission or adjacent
shared mappings. It retains the existing COW/owner-authenticated scrub and
per-segment residency handling, without changing semantic VMA permissions.
Removed the obsolete aggregate writable metadata. This fixes the demonstrated
read-only stale-content bug; it does not reduce eager clearing or claim a
performance improvement.

Contract kernel.mm.anonymous-discard uses the live registry and shared
ContractObservation/evaluate path. It fails red with SemanticMismatch and
passes green at 1/8/32/128 pages. The callback count is measured (at most one
backend scrub per contiguous VMA), explicitly not a backing-byte or timing
claim. All eight madvise tests and 158 memory-dispatch tests pass; the live
contract registry passes with 21 contracts and 15 claims.

The signed in-process fixture passes read-only discard, repeated/partial-dirty
discard, fork-peer preservation and child-only 4-KiB discard with neighboring
pages intact. Added a mixed read-only-private/shared-anonymous range: private
bytes become zero while shared bytes remain intact. The identical expanded
fixture passes all six output rows on pinned native ARM64 Docker. Signed
artifact identity, unentitled negative control, zero-residual cleanup, source
hashes and raw outputs are retained in discard-correctness/. Full signed
probe/smoke/ecosystem promotion remains open. The signed result belongs to the
embed test executable; no newly linked CLI performance result is claimed.

The next performance change is still materialized backing retirement. The new
contract's unresolved embed-structural binding explicitly requires actual
zero-byte and allocation budgets, followed by trace census and warmed untraced
Node ABBA. Do not present this semantic prerequisite as progress in the raw
Linux runtime ratios.


## Materialized anonymous backing retirement: measured Node improvement

Implemented an explicit current-MM private-anonymous discard operation. The
AArch64 path reserves an exact-MM backend retirement, invalidates stage-1 and
flushes translations, commits the existing authenticated alias/frame retirement,
then publishes fresh-zero deferred provenance. Semantic mapping permissions
remain intact. HVF initially accepts complete aligned 16-KiB host granules;
partial granules and unsupported backends retain the authenticated scrub.
Preparation errors are clean; errors after stage-1 mutation begins are
indeterminate and fail stopped. No host MAP_FIXED ownership bypass.

The kernel.mm.anonymous-discard-no-scrub contract uses real registry observations
and the shared evaluator. Red observes one fallback scrub against a zero budget;
green skips it at 1/8/32/128 pages after a capable scripted discard. All 159
memory-dispatch tests pass, and the registry passes with 22 contracts. This
control-flow model does not prove physical retirement; production measurements
and signed semantics are separate evidence below. Failure injection, backend
matrix checks and full signed promotion remain open.

The signed fixture passes. An additional version explicitly aligns the test
range to 16 KiB at the larger scales, preserving extra neighboring allocation
space, and also passes: repeated pristine/dirty discard, read-only contents,
fork peer isolation, child-only 4-KiB fallback, and mixed private/shared ranges.
The identical aligned fixture passes all six rows on pinned native ARM64 Docker.
The focused mem, forkcow and memflagmatrix probes pass in both musl and glibc
(six executed rows); unentitled controls and scoped zero-residual cleanup pass.
Exact signed test receipts are archived separately from CLI measurements.

A fresh control keeps the read-only semantic fix and the new dispatch interface,
but its engine declines retirement without mutation. Frozen signed CLI hashes:
control 2094b5f998141f0ac74d00ce7baa199cdff537909ef4bdf475239a42a69ec061;
candidate fd96c7d450060e04ec7cc28933d82843c28521ecf80875567bd17dbdb5cec27f.
Both arms are warmed before each comparison. Two Node ABBA blocks measure
control 320/315/331/328 ms versus candidate 247/241/246/243 ms: 24.5% less
runtime. A separate warmed three-workload comparison repeats two ABBA blocks:
Node 318/328/336/337 ms versus 239/257/240/246 ms, 25.5% less runtime.
Go candidate/control is 1.0006 and Python OS 0.9953: no meaningful change.
These gains are against CORRECTED discard semantics, not the earlier faster
control that wrongly skipped read-only contents; do not compound them with
older campaign percentages or claim an extra 25% over the old 250-ms Node lane.

Matched aggregate trace captures close 2528 control and 2532 candidate service
windows with independently matching request counts, no errors, completion
markers, and scoped cleanup. Over 20 Node iterations, explicit scrub bytes are
17,873,797,120 control versus 1,744,076,800 candidate: 893.69 MB versus 87.20 MB
per iteration, a 90.24% reduction. Remapped bytes are zero in both captures.
This counter measures explicit scrub, not all allocation/zero-on-demand work;
the untraced runtime comparison is the net benefit evidence.

Fresh phase-separated native ARM64 Docker timings (two each) yield diagnostic
raw ratios Node 4.38x (candidate 245.5 ms, Linux 57/55 ms), Go 1.62x, Python OS
3.60x. These are not I/O-adjusted or paired Linux acceptance. Near parity is
still unproven. All workload rows complete successfully; run-scoped cleanup
receipts are retained.

Post-change carrier profiling closes 491 samples. The previously resolved
__bzero address is now leaf in 2 samples, versus 80/472 in the earlier profile.
Madvise remains inclusive in 136 samples (27.7%; overlapping stacks); first
resolved ownership includes Vcpu::run 137 (27.9%, guest/HVF combined, not a
trapping floor), cow_inventory_split_shape 18, BTree values next_back 13, and
other allocation/locking work. The next Node investigation should target
measured inventory/range work rather than chase the last zeroing bytes. Python
directory enumeration and shared syscall/DSR overhead remain separate targets.

All evidence is under discard-retirement/. The candidate source is restored
and target/release/carrick is restored byte-for-byte from the measured signed
candidate, replacing the temporary control. This is a scoped experiment with
positive workload evidence, not full promotion or goal completion.

## Unaligned discard: additional measured Node improvement

`discard-edges/` records a matched control/candidate change that retires aligned
interiors and scrubs partial edges. Original Node app-smoke means243.5 to184.0ms
(two warmed ABBA blocks), 24.4% less runtime. Go screen unchanged; Python OS
ratio0.9764 is a small screening result. Fresh raw Linux Node mean48.75ms gives
3.7744x; no platform-I/O adjustment or parity claim. Signed boundary/fork fixture
and Linux differential pass, but real-carrier failure injection and full signed
promotion remain open. Do not compound this percentage with historical gains.


## Full inotify09 reachability correction: seek-header candidate rejected

[seek-header/](seek-header/README.md) records a red/green metadata-input allocation
change and its full signed workload A/B result: baseline median21.90s, candidate
21.95s, fresh native ARM64 Linux5.76s (raw baseline3.80x). Four measured invocations
per Carrick arm all pass and hit the execution-loop limit. No workload gain was
demonstrated; the candidate handler change, test registration and contract were
removed, with patch and receipts retained.

A completed baseline trace reconciles exactly3M add-watch and3M remove-watch
services, but only one host-service lseek. The changed lseek handler was not on
the repeated host-service path. The smaller contract-scale128 fixture is serial,
not the original concurrent LTP pattern. CLI JSON counters describe the wrapper
here and must not substitute for the full population. EL1/engine fast paths are
outside these probes; low write/seek counts do not mean no I/O or no cost.

Native macOS and Docker-bind controls remain separate: write+seek medians1225ns
and13001ns versus Carrick2301ns. Do not subtract them from original-workload
timing. The census nominates common watch/syscall handling but does not establish
critical-path ownership. No new product speedup or near-parity claim follows.


## Inotify09 common-context borrowing rejected

[context-borrow/](context-borrow/README.md) tests the common runtime service path.
The VM-free contract reduces exact context retains from3N toN (4N toN with
redispatch), preserving exact identity and once-only completion at1/8/32/128.
The focused completion/interception/exec suite passes33 tests. Counters are
compiled out of the timed signed CLI.

Original-workload ABBA/BAAB medians are baseline21.885s and candidate22.015s,
0.594% higher, with overlapping results. The first block is slower and the
second is tied. All eight measured runs pass and reach the execution-loop
limit. Fresh Linux median5.98s gives raw baseline3.660x; the changed Linux
reference does not represent Carrick progress. Watch-only controls are also
essentially unchanged (invalid-pair3202.5 to3201ns).

The candidate, meter addition, test feature change and contract registration
were removed. Its patch, red/green observations, signed identities,17 completed
run receipts and restoration audit are archived. Baseline signed SHA1142bb6d
is restored; unrelated campaign work is preserved. No new gain or promotion
is claimed. Do not spend another cycle on context-copy counts alone.

## Architectural direction after the rejected context reduction

The [original instruction audit](native-islands/README.md) establishes a concrete
reuse case for the recovered DSR decoder: all 1,344 selected sites classify,
where the small native fixture translator rejects 493. It does not establish
emission, native residence, full-callgraph coverage or a performance gain.

The [selected design](native-islands/design.md) keeps guest regions native
across synchronous calls inside the existing HVPatch carrier, with current-kernel
service and precise HVF fallback. The next delivery combines current-MM code/data
authority, backing-wide code revocation and state/control handoff with unchanged
original inotify09 execution. A 20% full-completion screen governs further
expansion; the 1x objective and separate macOS-I/O controls remain unchanged.
The latest complete-work reference remains 21.885 s versus 5.980 s Linux (3.66x).
