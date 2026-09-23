# inotify09: controlled common-syscall transport intervention

The current mailbox transport wins against the register-reading control in both
the corrected microbenchmarks and original inotify09. This is causal evidence
for this specific intervention, not a new production speedup: mailbox is already
the default. Keep it. Further removal of the same register reads has no headroom.
The near-1x goal and 2x intermediate milestone remain open.

## What was changed and measured

No runtime implementation or default changed. Added watch-controls to the
independently authored perf_inotify09_scale benchmark: invalid-fd add/remove and
two unchanged adds. Each sample uses a fresh instance, checks errno or the stable
watch descriptor, proves an empty queue, then removes/drains the exact IN_IGNORED
record outside timing. Existing watch-states still checks empty-batch, growing
and overflow states. No timed write/seek occurs in these five micro phases.

The single intervention is CARRICK_HVF_SYSCALL_TRANSPORT=mailbox versus legacy
on one byte-identical signed CLI. Source inspection established that BOTH modes
publish and consume the mailbox. Legacy additionally decodes registers through
HVF and writes the return register. It therefore does NOT remove the mailbox,
the hardware exit, policy, dispatch, signals, scheduling or watch semantics.
It is not the retired process-per-guest execution backend.

One warmup per mode, then two balanced four-run blocks: ABBA and BAAB. Four
measured fresh Carrick invocations per mode; each invokes watch-controls and
watch-states in separate sequential guest processes. Each phase has 21 internal
samples, which are not counted as independent process launches. After Carrick,
three independent native ARM64 Docker invocations run the same probe/image.
There are 1,155 measured and 210 warmup sample records, all complete. No tracing
or builds overlapped these measurements. Core placement is not pinned; the
short 128-pair batch is visibly noisier. This is a diagnostic screen, not a
confidence-qualified release gate or a fitted per-stage cost model.

## Microbenchmark results

Nanoseconds per operation pair; median of independent invocation medians:

| Phase | Mailbox, current default | Register control | ARM64 Linux | Default / Linux |
| --- | ---: | ---: | ---: | ---: |
| Invalid add/remove | 3074.5 | 3439.5 | 256 | 12.01x |
| Two unchanged adds | 3528.5 | 3877.5 | 554 | 6.37x |
| 128-pair batch, initially empty | 3359 | 3599.5 | 1212 | 2.77x |
| Growing queue, 8192 pairs | 3392.5 | 3727 | 861 | 3.94x |
| Overflowed queue, 65536 pairs | 3429.5 | 3771.5 | 909 | 3.77x |

Default reduces time by about 9% versus the register control for unchanged,
growing and overflow work, and 10.6% for invalid pairs. Both directions of run
order agree on the long phases. The invalid-fd control contains no path copy,
watch mutation or timed I/O, but it still contains dispatch/error handling and
the entire runtime/execution path. Its 12x ratio remains a performance pathology;
it does not establish an irreducible trapping floor.

## Original inotify09 intervention

Same pinned LTP image (version20260529), fs=host, shell entrypoint, unlimited
Carrick traps, unchanged 40-second external bound. Every run passes and reports
Exceeded execution loops; none reaches the runner's bound.

| Arm, ABBA order | Seconds |
| --- | ---: |
| Mailbox | 21.456769 |
| Register control | 23.895955 |
| Register control | 24.133779 |
| Mailbox | 21.593601 |
| ARM64 Linux, subsequent phase | 5.772674 |

The mailbox/control ratio of medians is 0.8963 (about 10.4% less time).
Default/Linux is 3.73x raw. LTP's adaptive synchronization/spin work can differ
between runs; two samples per Carrick arm and one Linux sample are a diagnostic
screen, not formal timing acceptance. Do not infer exact dispatch populations
for these untraced LTP runs from the separate tiny trace below.

## Live qualification of the intervention

The new durable hvpatch-inotify-transport-control.d runs through carrick trace
with require-script-exit. On the existing invalid-contract ELF mode, each arm
reconciles exactly169 add and169 remove requests with169 completions of each.
No missing decode, DTrace error or drop is reported; each root exits normally.

Per ordinary syscall decode/normal completion:

| Arm | GPR reads | System-register reads | GPR result writes |
| --- | ---: | ---: | ---: |
| Mailbox | 0 | 0 | 0 |
| Register control | 9 | 4 | 1 |

These counts are scoped to the instrumented decode/completion operations, not
every register operation in the runtime or signal-delivery path. The trace is
highly perturbing and supplies no timing evidence. Register traffic is genuinely
absent in the default branch; this is not an empty-probe inference.

Initial trace launch from the worktree path was refused by sudo's path-specific
password requirement. That failed launch is preserved. The completed captures
use a byte-identical copy in the existing NOPASSWD Carrick diagnostic directory;
no sudo configuration or signed contents changed.

## Decision and next implementation boundary

This experiment confirms that a common-path intervention can move original
completion time. It does not test an exception-free gateway or prove that all
remaining overhead belongs to HVF. The important distinction is that the
measured saving is already present in the baseline. Repeating register-read,
idle-signal or selected-worker tuning is not the next useful campaign.

The next new execution candidate must change the interception mechanism while
retaining the current kernel service: a bounded same-thread native/DSR guest
slice, already described by kernel.execution.native-synchronous-syscall. The
current instruction reader explicitly does not authorize code-cache execution;
the recovered planner is not an executable adapter. Native code publication,
current-MM memory access and revocation must be real before timing it. Restoring
the old identity-memory backend or fabricating host callback arguments would
not test the proposed mechanism.

Use the new controls plus valid growing/overflow watch work to evaluate that
candidate. Require exact task/MM authority, register/TLS preservation, policy
and completion, signals/cancellation, same-VA two-MM isolation, permissions/COW
and translation revocation. Include compute and memory controls before broader
language execution so translation costs remain visible. A fast invalid-only
result cannot qualify it. An instruction-reader-only extension or another host
callback microbenchmark would still leave this execution experiment unfinished.

The current growing-pair reference is0.861us at1x and1.722us at2x, compared with
3.393us now. That means roughly75% or49% less total pair time respectively.
These are arithmetic planning targets, not subtractable transport components.
Keep native macOS I/O controls separate and retain raw Linux comparisons.

The distinction between interception and implementation costs follows the
Apache-2.0 [gVisor performance guide](https://github.com/google/gvisor/blob/164b166ce347fdb6790603318db3e4cbbe76c0b0/g3doc/architecture_guide/performance.md).
The earlier pinned BSD Coz/DynamoRIO guidance remains in ../permissive-guidance;
no external implementation source was copied in this experiment.

## Evidence and limits

CLI SHA256 c3fb9fd30706f6f657531084df5a072f7c130b68096e60a9bb22df4213ac50b0,
source HEAD9bb2392396b8531e93f5262657bf3aa9c5767488 plus the lifecycle campaign's
recorded working changes. artifacts.json contains UUID, CDHash, entitlement,
DOF, OS and CPU identity. Exact image/probe/source hashes, argv, run IDs, all raw
streams, failures and scoped cleanup are preserved. results.json/summary.json
contain raw process medians; experiment.patch isolates this turn's probe change.

The applicable watch-churn and native-synchronous contracts remain open at their
unresolved execution/timing layers. This screen does not manufacture registered
timing observations from insufficient independent launches. No new production
candidate was promoted, no budgets/timeouts/known-gap policy changed, and no
smoke/full/CI gate was run this turn. The previous lifecycle public probe gate
belongs to the unchanged CLI, not to a newly implemented native adapter.
