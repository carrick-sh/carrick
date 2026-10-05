# Cross-task affinity: host scheduler correction

PR #49 extends the self-affinity correction with exact target resolution,
affinity-respecting host queue claims, and remote executor kicks. Linux
`sched_setaffinity(2)` names a thread, including a thread-group leader when
a sibling supplies `getpid()`. Only pid zero unconditionally names the caller.
The existing root/same-owner permission rule remains in place.

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
  315 tests in 30 suites: the original 309 plus six new tests.
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

Signed red/green receipts, exact fixture bundle and executable identities,
five full `el1_` population receipts, and the final fmt/domain receipts are
recorded in the PR's Verified section and under the same investigation output
directory. Docker blessing and fixture publication run on the director's
publisher; cloudmac uses no Docker. The six N1 failures are inventoried by
name, and their presence is never reported as a raw full-filter green.
