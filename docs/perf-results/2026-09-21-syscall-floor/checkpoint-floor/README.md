# Native syscall floor: demand-driven data activation — 2026-09-22

The investigation found and removed work which did not serve the executed guest
interval. The research runner activated a writable carrier-data grant on every
entry, including register-only syscall setup and return checks. An immutable,
conservative control-flow analysis now asks whether any path from the current PC
can reach a native memory instruction before returning to the host. Only those
intervals activate data authority. Execution admission, the running handshake,
control checks, code-generation validation and all syscall-buffer checks remain.

This reduces invalid add/remove time **28.2%**, unchanged-watch pair time **17.0%**,
and sustained churn time **18.9%** on the same release executable. It is an
implemented research-path improvement, not a shipped CLI or full inotify09 gain.
The 1x objective remains open.

## Completed-work intervention

One preserved release binary, `CARRICK_NATIVE_DATA_DEMAND=0/1`, existing input
read-window reuse enabled in both arms, unchanged Linux ELF. `0` forces the
previous activation work; `1` uses the analysis. There are three independent
invocations per arm and cell, balanced by alternating order. Each invocation has
one discarded warmup and nine retained guest samples. Values below are medians
of the three invocation medians. All 36 paired invocations, 40 small semantic
controls (five phases at 1/8/32/128, both arms), and 18 subsequent fresh Linux
invocations passed. Exact syscall, completion, errno and checkpoint populations
agree across paired arms; unchanged ELF hashes agree with Linux.

| Control | N | Always activate, ns/iteration | Demand-driven, ns/iteration | Fresh ARM64 Linux, ns/iteration | Demand / Linux |
|---|---:|---:|---:|---:|---:|
| Invalid add/remove pair | 65536 | 845.41 | 606.63 | 239.81 | 2.53x |
| Two unchanged-watch adds | 65536 | 1440.18 | 1194.69 | 504.92 | 2.37x |
| Fresh churn | 128 | 1390.63 | 1175.78 | 1183.59 | 0.99x |
| Churn into queue overflow | 65536 | 1306.24 | 1059.51 | 878.46 | 1.21x |
| Integer loop | 65536 | 2.784 | 2.614 | 0.569 | 4.59x |
| Load/increment/store loop | 65536 | 3.151 | 3.188 | 1.311 | 2.43x |

The small churn cell is near parity in this screen, not a parity guarantee. Its
fixed clock-copyout overhead is significant and Linux invocation medians range
1104–1206 ns. The memory control is essentially unchanged by this intervention;
one forced-activation invocation was 7.50 ns, versus 3.12/3.15 ns in the other
two. That run and every sample remain in the evidence. No favorable retry,
CPU pinning, formal confidence interval or statistical-equivalence claim is made.

There is no write/seek work in the timed watch loops. Path creation, queue drain
and stdout remain outside timing. The first clock's output copy follows its
timestamp and is inside the measured interval. Raw Linux ratios are retained;
native macOS I/O is not subtracted from these numbers. Direct host-file access
remains part of the intended architecture.

The invalid control executes 1,310,783 entries per complete invocation. Its
activation count falls from 1,310,783 to **10**, with every request and completion
preserved. The sustained-churn count falls from 1,794,813 to 484,040; most remaining
activations there belong to queue draining outside the timed loop. The integer
control falls from 2,623 activations to 10; the memory control retains 2,580 of
2,623. These are full-invocation counts, not counts attributed to the timed loop.

## What the cost controls actually establish

Independent release host controls use the actual carrier fixture, exact execution
lease, real dispatcher and compatibility reporter. They are diagnostics in the
fixture's configuration, without a product launch or configured user observer
chain. Each value represents the work for two operations. They overlap and were
measured in separate loops: **do not add or subtract them as a wall-time stack**.

| Control | Median ns/pair | Interpretation |
|---|---:|---|
| Native entry plus data activation | 277.4 | The large avoidable work targeted by this intervention |
| Dispatch with a preconstructed memory adapter | 278.1 | Real semantic dispatch still has substantial cost |
| Dispatch with an adapter constructed per call | 326.6 | Repeated exact-context authentication also costs time |
| Context authentication alone | 39.8 | A ceiling for this particular repeated lookup, not all authority work |
| Checkpoint control/signal checks | 39.1 | Preserve semantics; measure any cheaper design causally |
| Policy preparation, including entry reporting | 52.6 | Part of dispatch, not another independent total |
| Metadata lookup alone | 5.8 | Too small to justify treating binary search as the main problem |
| Entry and return aggregate reporting | 16.1 | Includes required accounting; not an obvious dominant target |
| Resource capture/release, separate follow-up artifact | 46.3 | Frequent, but much smaller than the whole dispatch path |

The fresh isolated activation screen also measures about 35 ns for one execution
scope and 135 ns for scope plus activation. The older microsecond-scale activation
result no longer describes this checkpoint. This was why remeasurement preceded
implementation.

Resource capture retains credential, filesystem-context, file-table, MM and task
references and acquires a functional file-table lease. Its 46 ns pair measurement
uses the existing capture API with an empty body. It does not justify retaining
that lease across guest execution or blindly replacing its ownership rules. The
full dispatch and capture controls are not an additive decomposition. Likewise,
the remaining difference between host controls and the ELF is not an isolated
measurement of gateway cost.

A separate native macOS C control executes explicit AArch64 instruction loops,
checks completed work and preserves disassembly. The initial short screen was
variable, so a separately recorded 65,536/4,194,304-iteration screen characterizes
that sensitivity. At the larger count, invocation medians are 0.453–0.576 ns for
arithmetic and 0.334–0.598 ns for memory, versus 2.614/3.188 ns in the translated
ELF controls. This supports investigating translator overhead; it is not the same
ELF, a placement-controlled comparison, a subtractable component, or a new Linux
normalization. The memory control uses a register copy of a host stack address
where the ELF uses ADR. Both use one address-producing instruction per iteration.

## A strategy with useful impact and clear stopping points

1. **Finish a production-capable native execution experiment.** The historical
   signed product control measured invalid pairs at 3.07 us and original
   inotify09 around 21.5 s versus 5.77 s in Linux. Those are earlier frozen-artifact
   results, not fresh results from this turn. The current research path supports
   the architectural direction, but private text and mocked stage-2 still prevent
   a product claim. Bind code publication to current carrier executable authority,
   then prove invalidation, same-VA isolation, COW, signals/cancellation, TLS and
   scheduling through signed execution. Run full inotify09 and representative
   Node/Go/Python workloads before calling this delivery. This boundary must not
   remain indefinitely behind ever-smaller microbench improvements.

2. **Treat common dispatch and entry as a combined engineering budget.** The
   invalid control still needs about 367 ns less pair time to match this Linux
   reference: roughly 60% less than today's research result. The steady churn
   gap is only about 181 ns/pair. Removing tiny metadata work cannot solve either
   by itself. Investigate repeated context authentication, resource handling and
   the guest/host gateway together, but change one boundary per paired experiment.
   A typed capability may consolidate duplicate checks only while retaining exact
   task/thread/MM/execution identity and live invalidation. Do not obtain a fast
   number by extending file-table leases across guest execution or retaining a
   native running scope during dispatcher service.
   Use at least a 10% end-to-end reduction on the invalid or unchanged-watch
   control as a prioritization screen, alongside no semantic or compute regression;
   that screen does not replace existing acceptance budgets. Smaller sound wins
   can be retained, but should not monopolize the campaign.

3. **Remove instruction amplification in the native/DSR path.** The bounded
   emitter currently allocates a 64-byte slot per 4-byte guest instruction. A
   simple integer instruction executes an x17 load, the original instruction,
   an x17 store, and an extra branch. That is a concrete cost hypothesis for the
   4.59x compute ratio, independent of inotify bookkeeping. Test compact basic
   blocks, direct fallthrough and register-liveness-based spills with an exact
   guest-PC entry map. Preserve all GPR/SIMD/flags, virtual reserved registers,
   memory-fault state, W^X/revocation and the existing maximum 256-backedge
   checkpoint interval. Do not omit SIMD preservation merely because these
   integer fixtures do not modify vectors. This is the next substantial compute
   experiment; it is not yet a measured syscall speedup or a DSR implementation.

4. **Expose cold and moving-buffer costs before broad workload claims.** The
   previous read-window improvement covers warmed reuse. Cold preparation still
   builds full-MM snapshots. A fixed watched pathname is unusually favorable;
   stack buffers, moving paths and multiple active leaves can invalidate or
   displace that advantage. Hold requested bytes fixed and scale live MM regions
   and working-set pages independently. Require work proportional to accessed
   leaves/owners, then test real runtime patterns. Do not extrapolate this
   one-window fixture to general Node/Go/Python performance.

The useful investigation loop is: identify a required operation, measure its
actual work, remove only unnecessary work in a controlled arm, then compare
completed guest work. A frequent profile frame alone does not determine priority.
The activation intervention satisfies this loop; another metadata microbenchmark
without a material workload effect would not.

This separation of platform interception cost from implementation cost follows
the Apache-2.0 [gVisor performance guide](https://github.com/google/gvisor/blob/164b166ce347fdb6790603318db3e4cbbe76c0b0/g3doc/architecture_guide/performance.md).
DynamoRIO's [AArch64 linking guidance](https://dynamorio.org/page_aarch64_far.html)
and [register-management guidance](https://dynamorio.org/page_drreg.html) motivate
testing direct block transfers and necessary-only spills, with explicit context
barriers and consistent state at control-flow joins. The project's primary BSD
license and pinned source receipts are in `../permissive-guidance`. These are
architectural guidance, not performance evidence for Carrick; no third-party
implementation code was copied.

## Proof and remaining limits

New contract: `kernel.execution.native-data-demand`. The retained pre-fix binary
completes all semantic checks but reports 1/8/32/128 activations against the zero
budget. The fixed path reports zero at every scale; an actual carrier load is a
positive control and still activates once. Tests cover both conditional successors,
cycles, forward jumps over memory, checkpoint barriers, invalid PCs/targets,
register/flag/vector preservation, revoked data, wrong code identity and code
revocation. A register interval can run after data revocation precisely because
it cannot dereference data; a memory-capable interval is refused before execution.
The existing activation implementation was not weakened.

Validation completed: 41 carrier-memory tests (three deliberate opt-in diagnostics
remain ignored in that ordinary run), 12 research executor tests, 83 observability
tests, 33 contract-package tests, affected runtime/research Clippy, targeted format,
registry/inventory and product-layering checks. The 40 semantic and 36 paired ELF
invocations use the same preserved release executable. All 76 research run IDs
have zero remaining scoped Carrick processes; all 18 Linux containers were removed.

No signed native-execution binding, full inotify09 rerun, ecosystem gate, full CI,
product probe/smoke/full promotion, commit, merge or push is claimed. The prior
checkpoint's signed foreign-MM gate had an open
`fresh_sparse_publication_avoids_stage1_maintenance` failure (one invalidation
against a zero budget); it was not rerun or declared resolved here. The product
CLI and earlier private-native control hashes remain unchanged.

Timing executable SHA-256:
`6b383316c6ad628bda382d948b8fbfc48720784c1018ed87c79cb9b050b9d58e`.
The later attribution executable adds only the resource-capture diagnostic arm:
`b4136b735ee6ba3370f2ec4fbedd9d2d73e7b77942399620c78fd85363059b54`.
`manifest.json` binds source snapshots, artifacts, environment, raw cohorts and
cleanup. Executables remain in `target/lease-cost/checkpoint-floor`; durable raw
receipts and source archives are beside this report. Setup-path failures, the
outdated registry-count failure, an unnecessary lint expectation, and the timing
outlier are retained separately from the successful evidence.
