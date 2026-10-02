# Stage 2a: two-task layered matrix and first scoped signed census

The final scoped structural and namespace semantic gates pass on both libcs.
Milestone 0 acceptance remains open because the full host recipe hit a
separately owned teardown deadline failure. The final receipt below records
that limit and complete before/after counts; earlier sections preserve the
red-first progression.

## Matrix

`namespace_two_process.rs` now runs 16 upper cases and 16 immutable-lower cases:
scales 1/8/32/128 per actor, unrelated population 0/128, same/unrelated parents.
Pipes synchronize initial release and final task lifetime only. The upper case
imports a tar through the public carrier archive runtime in each actor; a
300-byte late path component fails at the host filesystem after an earlier
replacement. A cached open/read precedes import, and subsequent operations and
physical reads verify restoration. The final alias and moved file have equal
physical device/inode and link count 2.

The lower case renames a lower-only file into the upper and removes a second
lower-only file. Guest opens verify both source names remain hidden; destination
reads verify copied bytes; physical lower files retain their original contents
and the physical upper destination exists. No cache ownership changes.

Attempting the entire upper hardlink matrix against an empty upper separately
exposed EROFS on lower-only linkat. That failure was not fixed or declared green.
The lower matrix specifically covers copy-up and whiteout.

## Scoped signed baseline

The performance fixture `perf_namespace_scale` forks two Linux tasks, keeps both
live through independent work, and uses positive directory fds only for the
measured four operation families. Per actor/iteration it does two renameat,
one linkat, one unlinkat, and one real openat followed by a content read.
The durable `hvpatch-fs-op-ledger.d` emits those scoped counts beside its full
startup/service/outside-window ledger. Capture uses `carrick trace
--require-script-exit`, never raw sudo dtrace.

Artifact identities and raw captures are retained under
`target/el1-host-namespace/scoped-census-before/`. CLI SHA/CDHash/entitlement,
LC_UUID and load commands are recorded there. The CLI was built with
`CARGO_BUILD_JOBS=3 RUSTC_WRAPPER= just build` from the accepted product sources
at 1c1f0287c; this slice changes the backend template and fixtures only.
Image was the locally cached ubuntu:24.04 digest
`sha256:7607b6f97024ef850f1bd6e91a89273beb5973d04432c5b87f15f813d64b9c05`.
The command used the tag with `--pull never`; it is not a digest-pinned binding.

Counts below are exact observed filesystem host syscalls / completed guest
calls. Synchronization (`psynch*`) calls remain in the raw ledger but are
excluded from this filesystem column. The last column counts host openat calls
inside rename/unlink/link windows, where zero warm parent opens are required.
This is a red census: those opens vary with concurrent interleaving. It does
not establish a population-independent deterministic slope.

| Scale per actor | Population | Parents | Rename | Unlink | Link | Openat | Mutation host opens |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0 | same | 32/4 | 8/2 | 14/2 | 12/2 | 0 |
| 1 | 0 | unrelated | 32/4 | 8/2 | 14/2 | 12/2 | 0 |
| 1 | 128 | same | 32/4 | 8/2 | 14/2 | 12/2 | 0 |
| 1 | 128 | unrelated | 32/4 | 8/2 | 14/2 | 12/2 | 0 |
| 8 | 0 | same | 256/32 | 64/16 | 97/16 | 96/16 | 0 |
| 8 | 0 | unrelated | 262/32 | 65/16 | 135/16 | 96/16 | 12 |
| 8 | 128 | same | 256/32 | 64/16 | 98/16 | 96/16 | 0 |
| 8 | 128 | unrelated | 266/32 | 64/16 | 121/16 | 96/16 | 11 |
| 32 | 0 | same | 1024/128 | 256/64 | 385/64 | 384/64 | 0 |
| 32 | 0 | unrelated | 1087/128 | 295/64 | 406/64 | 384/64 | 40 |
| 32 | 128 | same | 1044/128 | 257/64 | 388/64 | 384/64 | 5 |
| 32 | 128 | unrelated | 1058/128 | 256/64 | 389/64 | 384/64 | 11 |

The next capture, 128/0/same, returned nonzero with entries=1566,
returns=1567 despite the expected scoped operation counts and successful guest
completion. It is rejected evidence. The full ledger uses concurrently updated
global scalar counters; their concurrency safety must be repaired and qualified.
The remaining three scale-128 captures were not run. Every launched run ID was
reaped with scripts/sudo/kill.sh; all reported zero remaining processes.

## Before/after status

| Operation | Scoped scale-1 baseline filesystem calls per guest call | After deletion |
| --- | --- | --- |
| Rename | 8 | Pending |
| Unlink | 4 | Pending |
| Link | 7 | Pending |
| Openat | 6 | Pending |

No product deletion is claimed from this census. Exact owned path-component
visits are not yet instrumented, the signed contract binding remains unresolved,
and the required before/after table is incomplete. The previous accepted
truncating-open API-counter reduction (4 to 3 metadata/identity operations) is
not interchangeable with this exhaustive host syscall census.

## Verification for this slice

`CARGO_BUILD_JOBS=3 RUSTC_WRAPPER= just test-kernel`, `just test`, and
`just clippy` passed. `just fmt-check` and `git diff --check` passed.
After making the archive helper propagate construction errors for clippy,
`cargo test -p carrick-kernel-example --test namespace_two_process -- --nocapture`
passed again (both matrix tests). Logs are `/tmp/stage2a-matrix-{test-kernel,
test,clippy-final2,final,fmt-check}.log`.

## Qualified concurrent baseline (2026-10-02)

The replacement `host-namespace-work` profile uses aggregation counts, verifies
one armed path census per request, and requires exact per-actor populations,
closed host syscall pairs, a program digest, and one backend open per openat.
The fixture now performs ONE operation in each family per actor/iteration.
All 16 captures completed on a digest-pinned image through `carrick trace`.
The first qualification exposed a DTrace declaration-order compile error;
initializing the thread-local predicates fixed it before any measurements.

CLI SHA-256: `e3909e5dc8774ab33beaf57d46fda08125f0cedeb151abdfa43b5cedf7b133d1`.
Probe SHA-256: `d283dc1c61dc8f9a2f701e93546604ef3cc1a05daa7ed085e3365f7c7ba561d2`.
Program SHA-256: `c3c40d892645c33efde691e5ab76fb3fd307467012c10f7abc0ddf338e86892b`.
Source: be54151a6 plus the two-line predicate initialization in the durable script.
Codesign, UUID, load commands, raw captures and zero-process cleanup receipts
are in `target/el1-host-namespace/scoped-census-qualified-before/`.

Each cell is **filesystem host calls / all Unix host calls / owned path visits**,
across both actors; divide by `2 * scale` for per-call values. Filesystem calls
are close, fgetxattr, fstat64, fstatat64, linkat, lseek, openat, pread, renameat,
unlinkat. Other calls are synchronization and thread_selfusage, retained in the
all-call count. Visits count the three named owned walk stages; lexical string
processing and cap-std internal walks are excluded, as declared by the script.
Those limitations must not be mistaken for an exhaustive lexical-work bound.

| Scale | Population | Parents | Rename | Unlink | Link | Openat | Mutation opens |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0 | same | 16/17/14 | 8/9/14 | 14/20/29 | 12/12/0 | 0 |
| 1 | 0 | unrelated | 16/16/14 | 8/8/14 | 35/35/32 | 12/12/0 | 5 |
| 1 | 128 | same | 16/19/11 | 8/8/14 | 14/15/32 | 12/12/0 | 0 |
| 1 | 128 | unrelated | 16/16/14 | 8/8/14 | 14/14/32 | 12/12/0 | 0 |
| 8 | 0 | same | 128/153/100 | 64/94/112 | 98/120/256 | 96/96/0 | 0 |
| 8 | 0 | unrelated | 146/149/121 | 65/66/112 | 124/126/264 | 96/96/0 | 12 |
| 8 | 128 | same | 128/160/106 | 64/96/112 | 98/130/256 | 96/96/0 | 0 |
| 8 | 128 | unrelated | 150/150/115 | 75/75/112 | 108/108/260 | 96/96/0 | 12 |
| 32 | 0 | same | 512/613/409 | 256/408/439 | 384/531/1027 | 384/386/0 | 0 |
| 32 | 0 | unrelated | 512/513/460 | 281/292/448 | 386/386/1063 | 384/385/0 | 6 |
| 32 | 128 | same | 512/639/418 | 256/435/436 | 383/536/1006 | 384/384/0 | 0 |
| 32 | 128 | unrelated | 540/540/457 | 279/279/448 | 389/389/1053 | 384/391/0 | 17 |
| 128 | 0 | same | 2048/2526/1663 | 1024/1720/1753 | 1526/2168/4089 | 1536/1541/0 | 0 |
| 128 | 0 | unrelated | 2071/2073/1807 | 1098/1100/1792 | 1617/1619/4289 | 1536/1538/0 | 61 |
| 128 | 128 | same | 2049/2494/1627 | 1024/1710/1753 | 1546/2179/4109 | 1536/1536/0 | 5 |
| 128 | 128 | unrelated | 2107/2114/1831 | 1043/1050/1792 | 1691/1702/4278 | 1536/1536/0 | 80 |

## Signed binding and census-driven follow-up

`host-namespace-work` now launches the fixture through the public
`carrick-embed` Carrier via `carrick debug host-namespace-work`; the trace
profile writes eight EmbedStructural observations, one per actor and operation.
Both executable hashes are checked before and after capture. The reader requires
matching operation, host-entry/return, and arming counts, a real backend open
per openat, and complete successful task execution. The contract retains the
8*n filesystem-call budget and adds 8*n owned path visits and zero warm mutation
host opens. Raw synchronization calls are retained separately.

This binding was red on f5dd42c3d: linkat made 11 path visits at n=1 (budget 8).
Removing the repeated source-kind resolution in dispatch reduced that work.
The next signed capture on 7bb0180ad remained red under concurrent invalidation:
actor 3 linkat made 28 filesystem calls, 14 path visits, and five host opens;
actor 4 made 16 calls, 11 visits, and five opens. Both tasks completed. These
are architectural failures, not incomplete captures or retry candidates.

The follow-up retains bounded, already-owned unpinned directory capabilities
when upper names expire. Every rediscovered name still requires fresh physical
identity checks; immutable lower capabilities and absence facts survive only
at the same lower path. A moved merged directory rebinds its lower view.
An attempted direct cached-parent admission increased the exact cross-parent
rename cost from seven to eight host calls in the dispatcher budget test and
was removed. Admission still uses its existing contained walk. Ownership
remains in the original caches. Red-first host tests observed two
reopens for unpinned and merged lower parents, then zero after this change.
After removing direct admission, all 46 serial VFS tests and the exact
dispatcher namespace host-call budget pass; workspace clippy passes. The earlier
full `just test` run failed only the cross-parent budget before that removal.
Fresh signed acceptance and the final before/after table remain pending.

### Retention follow-up signed result (still red)

Fresh signed artifact from `7229d1e` has SHA-256
`d5cc09dfd830410d4fd032816469a54ed385ff1600a2a06431d5f8c1c73350b0`.
Identity receipts, raw trace, and eight exact observations are retained in
`target/el1-host-namespace/scoped-census-retention/`. Run
`stage2a-retention-7229d1e-1-0-same` completed both Linux actors; scoped cleanup
reported zero remaining processes. No events were dropped. At scale 1,
population 0, same parents, the observations are:

| Actor | Operation | Before 7bb filesystem calls / path visits / opens | After retention calls / visits / opens |
| --- | --- | --- | --- |
| 3 | renameat | 8 / 7 / 0 | 8 / 7 / 0 |
| 3 | unlinkat | 4 / 7 / 0 | 4 / 7 / 0 |
| 3 | linkat | 28 / 14 / 5 | 8 / 14 / 0 |
| 3 | openat | 6 / 0 / 0 | 6 / 0 / 0 |
| 4 | renameat | 9 / 4 / 0 | 8 / 4 / 0 |
| 4 | unlinkat | 4 / 7 / 0 | 4 / 7 / 0 |
| 4 | linkat | 16 / 11 / 5 | 8 / 8 / 0 |
| 4 | openat | 6 / 0 / 0 | 6 / 0 / 0 |

The opens column counts mutation parent opens; each openat separately made one
real backend open. This compares two completed captures with different task
interleavings, not a controlled CPU ratio. All linkat visits were dentry-stage
visits (zero host-parent and host-leaf visits). Actor 3 still exceeds 8 visits:
dispatch source/target/parent checks and coordinator admission need a single
contained transaction without removing permission or errno checks. The full
16-case after table and final both-libc gate remain unexecuted on this artifact.

## Rebased link admission and fresh signed census (still open)

Work was rebased onto `8bcd7fd97`. The exact cold dispatcher linkat
contract failed with **14 dentry visits** before the change and passes with
**four visits** after it (the parent has four components). Ordinary rootfs
linkat carries the admitted source and target parent through target DAC,
physical linking and cache publication. The durable census emits an
`NSDETAIL1` record for each component visit, with actor, operation, sequence
and caller role. In the signed scale-1 fixture the three-component parent is
visited once, all under `coordinator-admission`; source, target and permission
preflights no longer perform independent walks. The historical aggregate
baseline does not contain individual role records; no observed per-role
before decomposition is claimed.

Lower-layer hardlink copy-up is now supported. Both two-live-process matrix
suites pass, including physical alias identity, same-inode no-op rename,
NOREPLACE, lower copy-up/whiteout and archive rollback. The earlier unsupported
lower-link result above is historical red evidence. A separate source-error
regression returned ENOTDIR (-20) before ENOENT (-2) for a missing source and
an invalid target parent. The new test verifies ENOENT for both that parent
and an invalid target dirfd. Different-parent links precheck source existence
from the retained capability; fresh identity checks remain inside admission.
Shared-parent links need no additional precheck.

The new signed artifact is from `4434c1c6e`:

- CLI SHA-256: `d46c3c463dec1eb202ea274aed0410214de78a1bf2ab0654c39f956aeb6794ce`.
- Census program SHA-256: `ebc525ddbae14eacb61f8846495d070150da259aa0c6f95b16bfb54b71db46a5`.
- Image remains digest-pinned to `7607b6f97024ef850f1bd6e91a89273beb5973d04432c5b87f15f813d64b9c05`.
- Identity receipts, retained binary, exact observations, component records
  and run-scoped zero-process cleanup are in
  `target/el1-host-namespace/scoped-census-closed/`.

Eleven musl captures passed. The twelfth, **32 / population 128 / unrelated**,
completed both actors without drops but failed rename's unchanged `8*n`
budget: actor 3 made **258** calls and actor 4 **259**, maximum **256** each.
Their fstatat64 counts were 162/163 rather than 160. All mutation parent opens
were zero. Linkat visits were 96 per actor (three per call). This run stopped
at the first failure; no retries were performed. Four musl cases and all 16
GNU cases remain unexecuted on this artifact.

### Exact before/after per-call counts, with the red case preserved

Each operation cell is **(filesystem host calls, owned path visits)** before
and after the link-admission change, summed across both actors and divided
by `2*n`. Fractions are exact. The final column is total mutation-window host
opens, not a per-call ratio. The before side is the qualified 16-case baseline
above; the after side is musl on `4434c1c6e`. The 32/128/unrelated after row is
**red**. Pending cells are not measurements. Different interleavings and
instrumentation revisions prohibit interpreting this as a CPU ratio.

| n | Population | Parents | Rename calls/visits | Unlink calls/visits | Link calls/visits | Openat calls/visits | Mutation opens |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0 | same | (8, 7) → (8, 11/2) | (4, 7) → (4, 7) | (7, 29/2) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 1 | 0 | unrelated | (8, 7) → (8, 7) | (4, 7) → (4, 7) | (35/2, 16) → (6, 3) | (6, 0) → (6, 0) | 5 → 0 |
| 1 | 128 | same | (8, 11/2) → (8, 7) | (4, 7) → (4, 7) | (7, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 1 | 128 | unrelated | (8, 7) → (8, 7) | (4, 7) → (4, 7) | (7, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 8 | 0 | same | (8, 25/4) → (8, 109/16) | (4, 7) → (4, 7) | (49/8, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 8 | 0 | unrelated | (73/8, 121/16) → (8, 7) | (65/16, 7) → (4, 7) | (31/4, 33/2) → (6, 3) | (6, 0) → (6, 0) | 12 → 0 |
| 8 | 128 | same | (8, 53/8) → (8, 53/8) | (4, 7) → (4, 7) | (49/8, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 8 | 128 | unrelated | (75/8, 115/16) → (8, 7) | (75/16, 7) → (4, 7) | (27/4, 65/4) → (6, 3) | (6, 0) → (6, 0) | 12 → 0 |
| 32 | 0 | same | (8, 409/64) → (8, 439/64) | (4, 439/64) → (259/64, 7) | (6, 1027/64) → (6, 189/64) | (6, 0) → (6, 0) | 0 → 0 |
| 32 | 0 | unrelated | (8, 115/16) → (8, 7) | (281/64, 7) → (4, 7) | (193/32, 1063/64) → (6, 3) | (6, 0) → (6, 0) | 6 → 0 |
| 32 | 128 | same | (8, 209/32) → (8, 109/16) | (4, 109/16) → (4, 221/32) | (383/64, 503/32) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 32 | 128 | unrelated | (135/16, 457/64) → (517/64, 7) | (279/64, 7) → (4, 7) | (389/64, 1053/64) → (387/64, 3) | (6, 0) → (6, 0) | 17 → 0 |
| 128 | 0 | same | (8, 1663/256) → pending | (4, 1753/256) → pending | (763/128, 4089/256) → pending | (6, 0) → pending | 0 → pending |
| 128 | 0 | unrelated | (2071/256, 1807/256) → pending | (549/128, 7) → pending | (1617/256, 4289/256) → pending | (6, 0) → pending | 61 → pending |
| 128 | 128 | same | (2049/256, 1627/256) → pending | (4, 1753/256) → pending | (773/128, 4109/256) → pending | (6, 0) → pending | 5 → pending |
| 128 | 128 | unrelated | (2107/256, 1831/256) → pending | (1043/256, 7) → pending | (1691/256, 2139/128) → pending | (6, 0) → pending | 80 → pending |

## Final scoped signed receipts on 6cc5ca6c2

Both-libc structural and namespace semantic gates pass on the final source.
The full host recipe still has the separately owned teardown failure below;
this receipt does not claim a green full `just test` or milestone acceptance.

The directory identity index is no longer consumed by the first rebinding
walk. Its regression failed with two parent reopens before the change and
passes with zero; ownership remains in the original directory cache. A fresh
census then identified the remaining rename publication kind lookup: the
32/128/unrelated row above exceeded the ceiling by two/three fstatat64 calls.
Passing the source kind checked under admission removes that repeated walk.
The exact cross-parent API counter decreases from seven to six; this is a
separate, narrower counter than the exhaustive signed filesystem census.

Directory symlinks retain the old followed-kind publication semantics. The
new executable-display regression failed with `/alias/app` before that
compatibility correction and passes with `/moved-alias/app` afterward.
Ordinary files and directories use their admitted kind. Physical identity
checks, hardlink no-op detection and cache/event publication remain inside
namespace admission. No cache ownership moves were made.

### Artifact and closure

- Tested source/inventory HEAD: `6cc5ca6c2`.
- CLI SHA-256: `a0800d16dab312063fffe1f621938eb705a7cd2bf0357ee522268eea583adb1e`.
- Durable program SHA-256: `ebc525ddbae14eacb61f8846495d070150da259aa0c6f95b16bfb54b71db46a5`.
- Image: `ubuntu@sha256:7607b6f97024ef850f1bd6e91a89273beb5973d04432c5b87f15f813d64b9c05`.
- Retained binary, SHA/CDHash/UUID/entitlement/DOF records, raw traces,
  component details, exact observations and cleanup receipts:
  `target/el1-host-namespace/scoped-census-complete/`.
- **32 captures passed**: 16 each for musl and GNU, covering 1/8/32/128,
  population 0/128, same/unrelated parents. **256 exact observations**
  cover both actors and renameat/unlinkat/linkat/openat. Every observation
  is complete, with no drops or unknown metrics, calls and visits `<=8*n`,
  zero mutation opens, and one real backend open per measured openat.
  Every run-scoped cleanup reports zero remaining processes.
- **50 semantic cases passed**: 25 each for both libcs, through
  `scripts/test-signed.sh carrick-conformance-next generic_probe_shard_ --nocapture`.
  The filter and all selected Linux executable hashes are retained beside
  the census. All three invoked shards and the unentitled negative control
  passed; both signed run IDs were reaped. The signed test artifact receipt
  is copied there as `semantic-signed-artifacts.jsonl`.

In `musl-1-0-same.raw`, the exact linkat component visits are:

| Actor | Sequence | Component | Role |
| --- | --- | --- | --- |
| 3 | 1 | tmp | coordinator-admission |
| 3 | 2 | namespace-scale-2 | coordinator-admission |
| 3 | 3 | shared | coordinator-admission |
| 4 | 1 | tmp | coordinator-admission |
| 4 | 2 | namespace-scale-2 | coordinator-admission |
| 4 | 3 | shared | coordinator-admission |

There are no dispatcher-source, dispatcher-target or permission-parent
walks in that common linkat path. The colder four-component dispatcher
fixture independently records the required red **14** then green **4**.

### Before/after: musl

Each cell is **(filesystem host calls, owned path visits)**, summed over both
actors and divided by `2*n`; fractions are exact. Before is the qualified
musl baseline retained above. After is the final signed artifact. The opens
column is total mutation-window opens. All after rows are green. Counts can
vary with interleavings; the same fixed ceiling applies at every population
and scale. This is a call-count receipt, not a controlled CPU ratio.

| n | Population | Parents | Rename calls/visits | Unlink calls/visits | Link calls/visits | Openat calls/visits | Mutation opens |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0 | same | (8, 7) → (7, 3) | (4, 7) → (4, 7) | (7, 29/2) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 1 | 0 | unrelated | (8, 7) → (7, 3) | (4, 7) → (4, 7) | (35/2, 16) → (6, 3) | (6, 0) → (6, 0) | 5 → 0 |
| 1 | 128 | same | (8, 11/2) → (7, 3/2) | (4, 7) → (4, 7) | (7, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 1 | 128 | unrelated | (8, 7) → (7, 3) | (4, 7) → (4, 7) | (7, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 8 | 0 | same | (8, 25/4) → (7, 21/8) | (4, 7) → (4, 7) | (49/8, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 8 | 0 | unrelated | (73/8, 121/16) → (7, 3) | (65/16, 7) → (4, 7) | (31/4, 33/2) → (6, 3) | (6, 0) → (6, 0) | 12 → 0 |
| 8 | 128 | same | (8, 53/8) → (7, 45/16) | (4, 7) → (4, 109/16) | (49/8, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 8 | 128 | unrelated | (75/8, 115/16) → (7, 3) | (75/16, 7) → (4, 7) | (27/4, 65/4) → (6, 3) | (6, 0) → (6, 0) | 12 → 0 |
| 32 | 0 | same | (8, 409/64) → (7, 45/16) | (4, 439/64) → (4, 7) | (6, 1027/64) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 32 | 0 | unrelated | (8, 115/16) → (225/32, 3) | (281/64, 7) → (131/32, 7) | (193/32, 1063/64) → (6, 3) | (6, 0) → (6, 0) | 6 → 0 |
| 32 | 128 | same | (8, 209/32) → (7, 165/64) | (4, 109/16) → (4, 221/32) | (383/64, 503/32) → (6, 189/64) | (6, 0) → (6, 0) | 0 → 0 |
| 32 | 128 | unrelated | (135/16, 457/64) → (7, 3) | (279/64, 7) → (4, 7) | (389/64, 1053/64) → (6, 3) | (6, 0) → (6, 0) | 17 → 0 |
| 128 | 0 | same | (8, 1663/256) → (7, 369/128) | (4, 1753/256) → (4, 887/128) | (763/128, 4089/256) → (6, 753/256) | (6, 0) → (6, 0) | 0 → 0 |
| 128 | 0 | unrelated | (2071/256, 1807/256) → (899/128, 3) | (549/128, 7) → (4, 7) | (1617/256, 4289/256) → (773/128, 3) | (6, 0) → (6, 0) | 61 → 0 |
| 128 | 128 | same | (2049/256, 1627/256) → (1795/256, 93/32) | (4, 1753/256) → (1027/256, 445/64) | (773/128, 4109/256) → (6, 381/128) | (6, 0) → (6, 0) | 5 → 0 |
| 128 | 128 | unrelated | (2107/256, 1831/256) → (899/128, 3) | (1043/256, 7) → (515/128, 7) | (1691/256, 2139/128) → (6, 3) | (6, 0) → (6, 0) | 80 → 0 |

### Before/after: GNU

The before side remains the same qualified musl baseline; no historical GNU
baseline was captured. The after side is GNU on the same final artifact.
These cross-libc cells are an inventory comparison, not a single-variable
performance ratio. All 16 after rows pass the identical structural bounds.

| n | Population | Parents | Rename calls/visits | Unlink calls/visits | Link calls/visits | Openat calls/visits | Mutation opens |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0 | same | (8, 7) → (7, 3) | (4, 7) → (4, 7) | (7, 29/2) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 1 | 0 | unrelated | (8, 7) → (7, 3) | (4, 7) → (4, 7) | (35/2, 16) → (6, 3) | (6, 0) → (6, 0) | 5 → 0 |
| 1 | 128 | same | (8, 11/2) → (7, 3/2) | (4, 7) → (4, 7) | (7, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 1 | 128 | unrelated | (8, 7) → (7, 3) | (4, 7) → (4, 7) | (7, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 8 | 0 | same | (8, 25/4) → (7, 3) | (4, 7) → (4, 109/16) | (49/8, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 8 | 0 | unrelated | (73/8, 121/16) → (7, 3) | (65/16, 7) → (4, 7) | (31/4, 33/2) → (6, 3) | (6, 0) → (6, 0) | 12 → 0 |
| 8 | 128 | same | (8, 53/8) → (7, 45/16) | (4, 7) → (4, 7) | (49/8, 16) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 8 | 128 | unrelated | (75/8, 115/16) → (7, 3) | (75/16, 7) → (4, 7) | (27/4, 65/4) → (6, 3) | (6, 0) → (6, 0) | 12 → 0 |
| 32 | 0 | same | (8, 409/64) → (7, 93/32) | (4, 439/64) → (4, 7) | (6, 1027/64) → (6, 3) | (6, 0) → (6, 0) | 0 → 0 |
| 32 | 0 | unrelated | (8, 115/16) → (7, 3) | (281/64, 7) → (4, 7) | (193/32, 1063/64) → (6, 3) | (6, 0) → (6, 0) | 6 → 0 |
| 32 | 128 | same | (8, 209/32) → (7, 177/64) | (4, 109/16) → (4, 445/64) | (383/64, 503/32) → (6, 93/32) | (6, 0) → (6, 0) | 0 → 0 |
| 32 | 128 | unrelated | (135/16, 457/64) → (449/64, 3) | (279/64, 7) → (131/32, 7) | (389/64, 1053/64) → (391/64, 3) | (6, 0) → (6, 0) | 17 → 0 |
| 128 | 0 | same | (8, 1663/256) → (1795/256, 675/256) | (4, 1753/256) → (4, 1765/256) | (763/128, 4089/256) → (6, 759/256) | (6, 0) → (6, 0) | 0 → 0 |
| 128 | 0 | unrelated | (2071/256, 1807/256) → (1801/256, 3) | (549/128, 7) → (129/32, 7) | (1617/256, 4289/256) → (775/128, 3) | (6, 0) → (6, 0) | 61 → 0 |
| 128 | 128 | same | (2049/256, 1627/256) → (7, 363/128) | (4, 1753/256) → (4, 893/128) | (773/128, 4109/256) → (6, 381/128) | (6, 0) → (6, 0) | 5 → 0 |
| 128 | 128 | unrelated | (2107/256, 1831/256) → (7, 3) | (1043/256, 7) → (4, 7) | (1691/256, 2139/128) → (6, 3) | (6, 0) → (6, 0) | 80 → 0 |

### Host verification and remaining acceptance

Full `just test-kernel` passed after the admitted rename kind change, including
both upper/lower two-live-process matrices. Final affected namespace tests
(32) and serial VFS tests (47), workspace clippy, formatting and clean-tree
inventory reconciliation plus `just lint-domains` passed. The latter retains
all 616 reviewed authority classifications and reports the six non-macOS
compiler profiles as pending, as before.

Full `just test` passed earlier on the link admission/source-error changes
(`/tmp/stage2a-order-test.log`). Its fresh run after the rename deletion first
hit the unchanged live-USDT-disabled-state assertion while a sibling tracer
was active (`/tmp/stage2a-kind-test.log`). Director confirmed that interference;
after `TRACE-CLEAR`, both the isolated test and the full recipe's observability
suite passed (`/tmp/stage2a-kind-trace-clear.log`).

The continued full recipe failed only
`fs_backend::tests::hostfs_teardown_retires_large_tree_before_recursive_cleanup`
while 262 other parallel VFS tests passed (`/tmp/stage2a-kind-test-clear.log`).
The director confirmed the unchanged 10-second background-delete / 250-ms
wall test is load-sensitive under the six-worker I/O load and is replacing
its deadline with a completion handle separately. No deadline inflation,
retries or test skips were added here. The publication-reservation test
including its admitted-kind assertion passed in that run.

Final signed build, census and semantic logs are
`/tmp/stage2a-final6cc-{build,census,probes}.log`. Final clippy and lint logs are
`/tmp/stage2a-alias-{clippy,lint}.log`. The full-host-recipe issue and the
Docker-oracle/paired ecosystem gates owned by the director remain outside
this scoped signed closure. No review-ready/all-tests-green claim is made
while the required full host recipe is red.
