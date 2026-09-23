# Fresh private publication without the global guard: not accepted

Decision: restore control. This experiment reduced concurrent workload time,
but a signed semantic failure remains unattributed. Later passing runs are
not closure. Do not revive or promote it solely from the performance result.

## Impact

Two independent fixed-size warmed ABBA screens, four measured samples per arm
per screen. All50 total Node runs completed; all samples retained. Same workload,
concurrency, image digest and host-file path; no builds or tracing during timing.

| Workload | Combined control mean ms | Candidate mean ms | Candidate/control |
|---|---:|---:|---:|
| Original Node app-smoke |171.375|170.125|0.992706|
| Eight simultaneous Node |692.625|663.750|0.958311|

Concurrent reduction3.0% initially and5.3% in confirmation (combined4.17%).
Original Node shifted2.6% faster then1.2% slower: no consistent single-workload
win. One-background-process initial screen was essentially unchanged.
No fresh Linux comparison or I/O subtraction; no compounded historical gains.

The separate one-wave eight-process topology census closed every operation's
phases, all8 markers, root exit and scoped cleanup. Materialization registry
acquisitions dropped from12759 (preceding64KiB control capture) to226. These
are separate diagnostic captures, not wall-time components. Removing roughly
98% of these acquisitions produced only a modest concurrent workload effect,
so the large instrumented wait sum was not a prediction of achievable speedup.

Control CLI SHA256:
3e2521515cc0af0324dbd2f7639bd43ea27fc324dd84e1dbd69a4e508e780972
Candidate CLI SHA256:
504e01ed7756b72ec5d81867e2e6c8cb4c51d05918302e5c30c11ddb08f69395
Exact source manifests, patches, signed identities, raw samples and scripts kept.

## Change and lower-layer evidence

The no-replacement local sparse materializer called a private-hole wrapper under
its existing exact-MM permit without FrameRegistryGuard. SparseExtentBacking
creates a unique Private/PrivateFileView identity; inventory staging uses no
inherited frame and does not deduplicate it. Replacement retirement retained the
original global guard. Internal owner/refcount and page-table locks remained.

Red used the same wrapper with the old guard. At the real publication checkpoint
after staging and stage-1 sync, an independent host thread tried registry entry.
The registered contract failed with actual1 maximum0 at scale1. After removal it
passed1/8/32/128 pages, with pre-staging and post-sync injected failures preserving
old bytes, aliases and owner keys. All506 HVF unit tests passed,3 existing ignores;
registry tests passed. These tests use a stage-2 stub and test kernel authority;
they do not establish real-kernel simultaneous publication or VM-destruction
safety. The initial red.log is a descriptor MissingBinding setup failure; the
actual structural red is contract-red.log.

## Signed failure and attribution

scripts/test-signed.sh carrick-conformance-next deferred_anonymous --nocapture
on candidate: epoll copyout, pristine scrub and unaligned discard passed;
foreign copyout failed with process_vm_writev result(-1, EFAULT14, child_status1024).
The unentitled negative control passed and cleanup reported zero processes.
The script did not publish a failed-run artifact manifest; signed-deferred.log
and the immediately frozen/attested deferred-candidate executable preserve that
failure. Do not cite the old receipt file as the failed candidate's receipt.

Restored exact pre-experiment source snapshots and rebuilt the signed control
embed executable: all4 tests passed, including the negative control and cleanup.
Then restored candidate sources byte-for-byte. Fixed additional A/B/B/A runs of
both frozen signed executables all passed4/4. This makes the original failure
intermittent and leaves attribution unresolved; it is neither a confirmed
regression nor an established baseline defect. No retries convert it to green.
No budget, timeout, concurrency or known-gap policy was changed.

## Final state

All experiment-touched files restored from their exact .before snapshots; new
contract and dev dependencies removed from the live tree. Experimental code and
contract remain archived here. target/release/carrick restored byte-identical to
control. Both signed CLI and embed experiments remain frozen under target/lease-cost/
private-publication for diagnosis. No commit/push. Goal active, not completed.

Further global-lock trimming is unlikely to close the large gap based on these
interventions. Before reconsidering this candidate, trace the intermittent
foreign-copyout failure on the frozen artifact and prove exact-MM/owner lifecycle
behavior with the real kernel. For larger performance work, investigate the
per-page resident-fault transition: current ResidentFaultPlan and commit cover
one4KiB page even when backing is materialized in a wider window. Any batching
must preserve protection boundaries, residency reporting, COW and fault delivery;
there is no batching implementation or claimed speedup in this experiment.
