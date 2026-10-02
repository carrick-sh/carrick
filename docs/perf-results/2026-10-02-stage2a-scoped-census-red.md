# Stage 2a: two-task layered matrix and first scoped signed census

Milestone 0 remains open. This receipt adds lower-layer copy-up/whiteout and
late archive rollback to the two-live-task evidence, and records an actual
`carrick trace` census. It is not a review-ready structural binding.

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
