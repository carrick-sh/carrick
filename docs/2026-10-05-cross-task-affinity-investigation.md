# Cross-task affinity: host scheduler correction

PR #49 extends the self-affinity correction with exact target resolution,
affinity-respecting host queue claims, and remote executor kicks. Linux
`sched_setaffinity(2)` names a thread, including a thread-group leader when
a sibling supplies `getpid()`. Only pid zero unconditionally names the caller.
The existing root/same-owner permission rule remains in place and reads the exact target thread's current credentials rather than a group projection.

## Scope and ownership

The director explicitly scoped this extension to the host scheduler on
2026-10-05. Guest-switched tasks which are host-Blocked and guest-OnCpu are
**not covered** by this correction. Their `ZoneRecord` residency, control-slot
record publication, and handback authority are being rewritten by the N1
owner cutover. A separate red witness and root-cause note belong on
`work/affinity-el1-zone`, sequenced after N1; no EL1 zone correction lands here.
The six documented N1 full-filter failures remain out of scope.

## Red-first evidence

All paths below are relative to `target/storm-investigation/` on cloudmac.

| Receipt | Observed defect before the correction |
| --- | --- |
| `cross-affinity-target-red.log` | Sibling and other-process setters leave the named mask at 1 rather than 2; a sibling query reads the caller's mask 3 rather than 1. Three kernel-semantics tests fail. |
| `cross-affinity-scheduler-red.log` | An excluded queued sibling is claimed on CPU 0; changing the remote process's running mask delivers zero exact kicks rather than one. |
| `cross-affinity-runtime-red.log` | The compute-only target, with no queue demand, fails because it was never kicked. No timer or syscall closes the witness. |
| `cross-affinity-claim-entry-red.log` | Changing affinity during backend load leaves the first guest entry on the same executor as the excluded claim. |
| `cross-affinity-credentials-red.log` | A sibling with raw uid 200 cannot change its own mask because the group leader projection has uid 100; the exact target credentials must authorize it. |
| `cross-affinity-exec-successor-red.log` | A running exec successor has no affinity kick capability after the exact binding transfer. A retired predecessor is the negative control. |

Kernel witnesses use two live kernel processes or threads. Coordination waits
are bounded. No load, retry, timeout increase, or runtime serialization was
introduced as closure.

## Correction

The set/get handlers retain the resolved exact `TaskKey` and `ThreadKey`
incarnation through the target object, after namespace and container checks.
They no longer classify a sibling as the caller or discard an other-process
set. A sibling naming its process pid queries the leader's mask.

Host queue admission reads affinity under the thread execution lock before
moving Runnable to Running. An excluded queue placement republishes the same
runnable generation through normal placement before releasing its accounted
claim. It is neither entered nor discarded. Backend load can race a later
mask change, so the executor also checks before its first guest entry; a
mid-operation EL1 resume retains its existing settlement rules.

Each host-running execution record owns a weak kick capability for its exact
executor binding and guest CPU. Mask changes and capability publication
serialize on that record: either the change sees the binding or publication
sees the changed mask. Delivery happens after releasing the execution lock,
and revalidates thread serial, execution generation, executor id, and epoch.
Widening and unrelated tasks need no kick. Exec transfers the capability to
the successor; an old predecessor cannot nudge the replacement.

## VM-free and static verification

- `cross-affinity-kernel-population.log`: `just test-kernel-semantics` passes
  316 tests in 30 suites: the original 309 plus seven new tests.
- `cross-affinity-executor-population.log`: `RUST_TEST_THREADS=1 cargo test -p
  carrick-runtime --lib vcpu_loop::executor::tests -- --nocapture` passes 95
  tests: the original 93 plus two new executor witnesses. The existing exec
  test additionally proves successor ownership and predecessor rejection.
- The syscall tests also check ESRCH 3, EINVAL 22 on an empty intersection,
  EPERM 1 for a different owner, unchanged masks after errors, and unrestricted
  getaffinity queries. They recapture resources at syscall boundaries after a
  credential change, as the production executor does.
- `cross-affinity-clippy.log`: `just clippy` passes.
- `cross-affinity-probe-check.log`: the extended sibling probe cross-compiles
  with `cargo check --manifest-path conformance-probes/Cargo.toml --target
  aarch64-unknown-linux-musl --bin schedaffinitysibling`.

The first population invocation omitted the justfile's existing
`RUST_TEST_THREADS=1` requirement. `cross-affinity-executor-green.log` retains
that parallel invocation: three existing vfork tests interfered through the
process-global activation hook/failpoint, including a hook acting on another
fixture and `UnknownTask(14503)`. The correct recipe passes. The director
queued hook isolation separately; this PR does not change those hooks or the
libtest thread count prescribed by the recipe.

The seed637 historical replay receipt changes only `source_hash` to reflect
the changed kernel sources; its decisions and fixture hash remain intact.

## Signed and differential bindings

`carrick-conformance-next::scheduler_affinity::cross_thread_affinity_changes_only_the_named_thread`
executes the extended `schedaffinitysibling` probe in-process for musl and GNU.
It sets a distinct sibling mask, reads it from both threads, queries the
leader from the sibling, and checks that the caller mask is unchanged. It
prints stable boolean lines and errno numbers. The generic shards separately
compare the same probe with the director's source-validated Docker oracle.

The director rebuilt and blessed both probe libcs on native-arm64 Docker;
the cached-oracle generic shards pass. Cloudmac uses no Docker. Signed
red/green receipts and final static-check receipts are in the PR's Verified
section and under the same investigation directory.

## Fixed five-run signed population

All five scheduled runs use clean host sources at `af1240c4c` and its exact
fixture bundle: 1,132 executables, manifest
`71cb5dc303f9a56029631c4f5ab4411efad03edfc80f5e1b9a16ed10ea11f159`, tar SHA-256
`7961ee23db125673f442662e8678d725f60cf4c129a14fd2f076f3e4f805e423`.
Each `cross-affinity-full-01/` through `cross-affinity-full-05/` retains the
source identity, complete log and all ten signed executables, with SHA-256,
CDHash, LC_UUID, entitlement and DOF identities. The documentation update
afterward changes neither production sources nor fixture inputs.

| Full run | Passing selected tests | Failures |
| --- | ---: | --- |
| 1 | 77 | Six documented N1 cases |
| 2 | 76 | Six N1 cases plus the cross-vCPU TLB witness |
| 3 | 77 | Six documented N1 cases |
| 4 | 77 | Six documented N1 cases |
| 5 | 77 | Six documented N1 cases |

All 25 handoff samples have zero cross-vCPU wakes and at least 5,000 switches;
all five fork-storm cases, entitlement negative controls and scoped cleanup
checks pass. Every raw full-filter command exits **1**. These are focused
affinity results, not full EL1 acceptance. Run 2 is retained red and was not
retried or added to the six-case N1 inventory.

## Run-2 TLB failure: ordering audit and separate capture

The additional failure is
`el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation_on_any_thread`:
`faults=[598, 728] stale=2 errors=0 timeouts=3 ok=false`, with 600 faults
expected per worker. Five isolated samples on each of `af1240c4c` and
`805eada21` pass; that comparison is inconclusive, so sampling stopped.

The existing host migration protocol does not bypass invalidation:

- `executor/backend.rs::load` waits for a cross-executor resident task to
  become Materialized. `flush_resident_task` issues the resident task's owed
  invalidation before snapshot and publication. Its ticket completes only
  after `invalidate_worker_asid` succeeds, before the residency mutex
  publication and notification let the destination proceed.
- Scoped ASID maintenance accepts only `MaintenanceDone` and absorbs kicks.
  The maintenance and mailbox-return instruction images execute
  DSB / TLBI ASIDE1IS / DSB / ISB before completion or return. The invalidation
  is broadcast, rather than local to the source CPU.
- Same-executor resume retains its debt when stopped inside the invalidation
  entry. Saving to a zone record settles the debt before zone publication.

The existing residency-wait, instruction-image, absorbed-kick and
invalidation-debt tests pass: ten tests in five invocations. Their complete
logs and the source audit are in `tlb-ordering-proof/`. This establishes the
host migration ordering; it is not a proof of every permission-edit path.

The fixture pins workers only at startup. Its aggregate-ACK timeout path
continues editing permissions and posting new commands without the preceding
command's acknowledgment. A late `OP_WARM` can therefore store while the page
is read-only or unmapped in a later phase. The excess faults do not identify
stale read-only permissions; skipped commands can also alter expected fault
counts. The timeouts and their cause remain real failures.

The director accepted the ordering evidence and queued this as a separate
capture item, including the fixture's timeout/acknowledgment flaw. Capture
must identify the first command, permission and vCPU divergence. No retry,
timeout increase, added load or expected-failure expansion was used as closure.
