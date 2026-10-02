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
