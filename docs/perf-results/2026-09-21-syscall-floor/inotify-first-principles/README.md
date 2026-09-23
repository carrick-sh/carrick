# inotify09: first-principles performance strategy

Decision: return the investigation to inotify09. The pending first-touch
maintenance red contract is unrelated until an inotify-specific causal test
establishes otherwise. No product changes in this assessment. Near-parity
remains the objective, with native macOS I/O controlled separately.

## Actual required work

The original race concerns removing the last notification mark while another
thread writes to the file. Add-watch resolves a current path and attaches a
mark to the current file identity. Remove-watch detaches that mark and produces
IN_IGNORED. Write changes 64 bytes, advances the shared open-file offset and
produces applicable notifications. Seek changes the offset. The implementation
must preserve removal/event ordering, descriptor lifetimes, pathname mutation,
fork/dup sharing, policy and observers. A private rootfs does not require host
vnode registration: Carrick owns its mutation stream. Externally mutable mounts
retain their native observation requirements.

For the serial fixed-work reducer, total time includes four syscall envelopes,
semantic work, host write service and interactions. This is an accounting model,
not permission to subtract medians from different runs. For the concurrent
race, completion follows the dependency graph and synchronization; sums of
thread service or lock waits are not the critical path.

Upstream LTP puts add-watch outside the marked race and races remove-watch
against write/seek. Its fuzzy synchronization adds adaptive delay/spinning and
has both iteration and time limits. The existing concurrent_components reducer
starts two free-running loops together; it does not reproduce this per-iteration
race synchronization. Keep it as throughput evidence, not an exact LTP timing
surrogate. Verify the pinned image's LTP source/version and completed loop count
before interpreting an end-to-end duration as equal-work speedup.
Sources (semantic reference, GPL; no implementation copied):
https://github.com/linux-test-project/ltp/blob/master/testcases/kernel/syscalls/inotify/inotify09.c
https://github.com/linux-test-project/ltp/blob/master/include/tst_fuzzy_sync.h

## New signed/Linux evidence: unequal queue state

Independent Apache-2.0 OR MIT ctypes diagnostic, same pinned Python image,
Carrick phase completed before Docker. Signed Carrick SHA:
3e2521515cc0af0324dbd2f7639bd43ea27fc324dd84e1dbd69a4e508e780972.
Exact argv/source hashes, streams, artifact metadata and scoped cleanup kept.
All eight cases per platform completed. This is untimed semantic evidence.

| Fresh instance, 128 iterations | Carrick | Linux |
| --- | ---: | ---: |
| Add/remove: distinct returned watch descriptors | 1 | 128 |
| Add/remove: queued IN_IGNORED events | 1 | 128 |
| Add/remove: queued bytes | 16 | 2048 |
| Add/write/seek/remove: total events | 256 | 256 |

Carrick Inner::free_wd resets next_wd to 1 when the instance has no watches;
Inner::push_record coalesces identical adjacent records. Thus the churn-only
case collapses repeated removal notifications. Existing mark-race-hotpath
contract interposes writes and checks a minimum queued byte count, so it does
not catch this difference. Descriptor numbers alone are not the claim: pending
notification identity/count differs. Decide the exact Linux-compatible reuse
and coalescing contract before changing the allocator; do not assume numeric
identity equality is the whole semantic requirement.

perf_inotify09_scale also retains one undrained inotify instance across all
phases, scales and internal samples. After earlier work, queue filling,
coalescing and overflow differ by platform. Existing churn ratios remain
observations but are not proof of matched notification work. This discrepancy
does not account for the invalid-fd pair, which has no queue mutation or timed I/O.

## Evidence that still guides prioritization

The historical watch-refresh signed artifact measured medians of process
medians: invalid pair 2944ns vs Linux247ns, churn3362ns vs948ns, unchanged pair
3536ns vs555ns. These are NOT new timings on the retained artifact above.
Direct-kernel invalid pair ~303ns, production service subset ~542ns, wrapped
poll ~1003ns and selected worker operations ~1062ns used different backend
contexts. They establish feasibility questions, not subtractable transport
components. Paired idle signal boundary ~33ns/call and selected worker increment
~29ns/call do not justify another campaign of tiny wrapper optimizations.
No current executable DSR adapter or measured absolute trapping floor exists.

## Ordered strategy and stop rules

1. Repair semantic comparability. Add a watch-only contract sibling using fresh
   instances at scales1/8/32/128, exact removed-watch event identity/count and
   queue bytes. Cover pending events during descriptor reuse, concurrent remove
   and notify, overflow and drain. Run red against the frozen artifact above.
   Preserve the existing four-operation contract. Register timing parsing, which
   is currently explicitly unresolved. Do not count 21 samples in one process as
   21 independent process runs.
2. Measure separate states: fresh/drained, steady queued/coalesced, and explicit
   overflow. Setup and draining occur outside the operation timing. Keep an
   undrained original-shape lane. Add serial add/remove, unchanged add, exact
   invalid-fd, and shared-versus-independent concurrent cases. For the race,
   preserve add-before-race then remove versus write/seek; report completed work,
   spin/synchronization work and wall time separately.
3. Attack common execution overhead first for parity. The valid watch service
   must fit inside the overall syscall budget, and invalid pairs already exceed
   Linux substantially without path lookup or I/O. Test one bounded transition-
   avoiding execution path through current policy, task/MM authority, completion,
   signals and cancellation. DSR/native same-thread execution is a candidate,
   not established necessity or an implemented feature. Rewriting SVC inside
   HVF alone cannot directly call host Rust. Do not build a general translator
   before a real-guest vertical slice establishes a win and its lifecycle cost.
   An invalid-fd-only shortcut is a control, not closure: unchanged and mutating
   watch pairs must also benefit. Existing native-synchronous-syscall contract
   lists the actual missing instruction/memory/authority proofs.
4. Optimize watch semantics where a paired intervention demonstrates headroom.
   Resolve pathname input once per call to an authenticated file target, use
   bounded mark attach/detach and local event-queue operations, avoid repeated
   path/index allocation on warm churn, and avoid registry-wide serialization
   for independent targets. The current per-instance table plus global by_path /
   by_wd registry duplicates bookkeeping. This nominates a stable target/mark
   ownership experiment; it does not prove locks are the wall-time limiter.
   Preserve rename/unlink/hardlink behavior and external-mount invalidation.
   Never fuse away add/remove or delay event visibility: that removes the race.
5. Preserve native I/O as its own control. Use identical write64/seek shape on
   the same host filesystem, plus raw Linux-local and VM-host-bind controls.
   A pwrite substitution is diagnostic unless shared offset and observation
   equivalence are proven. Do not use Node memory improvements to claim progress
   on inotify09. Accept candidates only with untraced paired original-loop and
   race improvement, exact artifacts and semantic gates; reject changes whose
   only win is lower trace counts or only a synthetic invalid-fd special case.

Budget direction: derive total pair targets from a refreshed matched Linux
baseline. The historical churn reference suggests ~0.95us at1x and~1.90us at2x;
invalid pair ~0.25us at1x. These are planning references, not current acceptance
thresholds or measured floors. Host-adjusted write budgets need their own matched
control; retain raw ratios. No implementation or speedup is accepted here.

## Permissive architectural guidance

Pinned gVisor Apache-2.0 sources and license already archived in
../permissive-guidance/sources.json. Its performance guide separates interception
from syscall implementation costs. Its inotify design separates the instance,
file-target watch set, mark and event queue, with explicit lock ordering.
Adopt those questions and ownership distinctions, not its performance numbers
or filesystem assumptions.
https://github.com/google/gvisor/blob/164b166ce347fdb6790603318db3e4cbbe76c0b0/g3doc/architecture_guide/performance.md
https://github.com/google/gvisor/blob/164b166ce347fdb6790603318db3e4cbbe76c0b0/pkg/sentry/vfs/g3doc/inotify.md

BSD-licensed Coz guidance in the same archive motivates completed-work causal
experiments; profiles are hypothesis generators. Every proposed optimization
must pass the original workload intervention test. No latency share is inferred
from profile recurrence.
