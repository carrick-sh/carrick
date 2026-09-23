# inotify descriptor lifecycle and comparable queue-state baseline

The first-principles queue diagnostic exposed a real lifecycle difference, now
corrected in the working tree. No performance speedup is claimed for this fix.
The common syscall execution overhead remains the next performance target.

## Change

Watch allocation advances through positive descriptors until INT_MAX, wraps,
and skips live watches. Removing the last watch no longer resets the cursor or
recycles its descriptor immediately. The free-descriptor heap is removed. The
allocator consults live watches only; it never scans queued events. Exhaustion
returns ENOSPC with native registration/owned-fd cleanup. Virtual callers now
propagate that error. Existing coalescing and bounded overflow remain intact.
The Linux inotify manual documents incremental cyclic descriptor allocation:
https://man7.org/linux/man-pages/man7/inotify.7.html#BUGS
No Linux/LTP implementation source was copied.

## Red and green evidence

- VM-free registered kernel.inotify.watch-churn failed on old production code:
  at8 removals read returned16 bytes instead of128. The exact assertion and
  complete log are red.log. All4 scales execute before contract evaluation.
- Signed old guest fixture failed on stale-descriptor removal: a descriptor
  from a removed watch incorrectly removed its successor. Frozen embed-red
  binary remains in target/lease-cost/inotify-lifecycle, with SHA and codesign
  recorded. signed-red.log is the semantic failure; the earlier build-error
  log is a missing test trait import and is not red semantic evidence.
- Corrected VM-free inotify contract selection:8/8 pass. The new contract checks
  each unread IN_IGNORED identity and exact byte count, two-dispatch slope,
  zero queue scans and zero host notification backend calls.
- Focused kernel inotify tests:18/18 pass, including wraparound with live
  descriptors, stale removal, queue overflow/readiness and registry behavior.
- Contract registry tests pass (26 descriptors, including the separately
  pending first-touch maintenance experiment; no new performance claim).
- Signed dedicated case passes, including scales1/8/32/128, partial drain,
  continued allocation after drain, stale-descriptor rejection, modification
  of the current watch, overflow, full drain and rearming. Unentitled negative
  control passes, scoped cleanup0. signed-green-artifacts.jsonl records it.
- Same-source pinned native ARM64 Docker returns the exact same six success
  lines. Carrick and Docker run in separate phases.

The wrap unit test exercises a seeded cursor at INT_MAX; it does not claim
billions of guest operations were executed. Native Linux backend compile/runtime
coverage and full release promotion remain separate obligations.

## Comparable timing baseline

New perf_inotify09_scale watch-states mode creates a fresh inotify instance for
each sample. Initialization, prefill, FIONREAD and draining are untimed. Every
sample validates exact queue size, event masks, drain and overflow count. The
empty-batch and growing phases START empty and fill during the measured batch;
they are not an empty queue on every iteration. Overflow is explicitly prefilled.
The historical undrained mode remains available and unchanged in behavior.

Three independent processes/platform,21 internal samples/phase,all378 sample
records complete. This is a baseline screen, not paired old/new acceptance.
Raw process medians in ns/pair:

| State | Carrick | Native ARM64 Linux | Ratio of process medians |
| --- | --- | --- | ---: |
|128-iteration batch from empty|3962,3436,3530|1168,1140,1131|3.096|
|8192-iteration growing queue|3303,3422,3498|884,858,849|3.988|
|65536 iterations after overflow|3416,3453,3494|901,909,909|3.799|

No timed write/seek, no macOS I/O subtraction, no builds/tracing during timing.
All samples retained, including first-process short-batch variation. The
3.42us growing-queue pair versus0.858us Linux is now an equal-queue-work target,
not a decomposition of trapping cost. A2x intermediate milestone for this lane
would be about1.72us per pair at this Linux reference; near1x remains the goal.
These total-pair targets do not establish a per-stage or irreducible floor.

## Original LTP case

Pinned same-image inotify09 passes on both, LTP version20260529. Both report
"Exceeded execution loops" and TPASS; neither hit the40-second runner bound.
Single diagnostic wall times: Carrick21.3367s, Docker5.7867s (~3.69x raw).
Adaptive synchronization/spin work differs; the sample is not a statistically
qualified old/new speedup. Full commands and both raw streams are in ltp.json
and inotify09-lifecycle-*.{out,err,cleanup}.

## Artifact and remaining work

Frozen CLI SHA256:
c3fb9fd30706f6f657531084df5a072f7c130b68096e60a9bb22df4213ac50b0
Source HEAD9bb2392396b8531e93f5262657bf3aa9c5767488 plus recorded working changes.
Exact source manifest, patch, probe SHA, image digest, UUID/CDHash/entitlement/
DOF and run IDs are archived. Product code was not rebuilt during measurement.

Public just --no-deps conformance-probes PASSED:910 unique generic rows,
dedicated signed cases including this lifecycle fixture,66 retained ARM64 PASS
rows, and final46 passed/1 existing ignored. The x86 probe binaries are absent;
optional native-backend cases were not requested. Existing baseline/known-gap
policy is unchanged. Generic/dedicated signed receipts and complete gate log are
archived. Final scoped cleanup reports0; installed CLI SHA remains identical
to the measured frozen artifact. git diff --check passed.
Performance is still outside2x; signed structural/timing observation binding
for the new contract and full smoke/ecosystem promotion are not completed.
The unrelated first-touch red contract and rejected private-publication
foreign-copyout failure remain open. This change does not claim closure for
concurrent notification ordering beyond the tests actually run.

Next: use this corrected baseline for a bounded real-guest common-syscall
execution experiment. Preserve current kernel policy, completion, signals,
authority and watch semantics; require valid churn as well as invalid-fd
controls to improve. Do not return to queue scans, tiny wrapper costs or Node
memory work as the principal explanation of this inotify09 gap.
