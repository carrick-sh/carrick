# HvPatch Phase 4 filesystem service lowering

Date: 2026-08-09

Status: **ATTRIBUTED; regular-file overlay preflight selected for one narrow
behavior experiment; Phase 4 remains RED.** Two count-only captures reproduce
10.52 Darwin `openat` calls per Linux `openat` and 4.58 per Linux
`newfstatat`. Two later stack captures bind the largest populations to exact
Carrick callsites and the exact signed Mach-O image. No behavior or performance
claim is made by this checkpoint.

## Question

Which Darwin operations account for the repeated 0.89--0.91 second
`openat`/`newfstatat`/`mmap` service family, and which exact Carrick callsites
offer a semantic-preserving experiment large enough to run through untraced
ABBA?

## Instrument corrections

The runtime publishes three typed CTF boundaries for a service:

- `hvpatch-syscall-service-begin(guest_pid, guest_tid, asid, nr)`;
- `hvpatch-syscall-service(guest_pid, guest_tid, asid, nr, duration_ns)`;
- `hvpatch-syscall-service-clear(guest_pid, guest_tid, asid, nr)`.

The distinct clear event is load-bearing. Clearing thread-local state in a
second clause on the completion probe made the clear visible before the
validation clause on this DTrace implementation. Earlier consumers that used
hot associative-array joins also silently lost entries without a
`dtrace:::ERROR`. The retained consumers therefore use thread-local state,
validate at completion, and retire it only at the distinct typed clear event.
Aggregate `count()` values, not racy global D scalars, are population
authority.

`hvpatch-phase4-openat-callers.d` also consumes the existing typed
`host-image-base(host_pid, runtime_text_base, slide, path)` ABI. Hvpatch now
publishes it from `finish_hvpatch_image`, the shared file/rootfs/raw-image
entry point, before image preparation. The dyld queries and path conversion
stay inside the enabled USDT closure. Every captured stack key includes the
runtime base, and the consumer fails closed if no nonzero base arrives.

The first image-publication scout was deliberately rejected: publication had
been placed only in `run_static_hvpatch`, while the container workload enters
through the rootfs path and calls `finish_hvpatch_image` directly. It produced
correct workload output and balanced services but `image_base_seen=0`. A
red-first source contract now requires publication in the shared finish path.

Both scripts declare high/very-high perturbation. Count ratios and stack
shares are citable only within the same instrument. Elapsed time is not.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`; committed parent `cc81844f` with only this tooling,
  probe-boundary, publication, test, and evidence checkpoint uncommitted.
- Signed binary SHA-256 for both symbolized captures:
  `6605d8d1cf614ae2441b2d4559ab05bf0c5ef8630a136ef0a92369343698e09f`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Every retained capture printed exact `ok` and `BUILD_OK`, exited zero, and
  reported zero nested/orphan/mismatched windows, timeout, or DTrace error.
  Carrick and Docker were not run concurrently.

Raw capture SHA-256:

- `service-lowering-4.raw`:
  `ef16d35977430d9660a631c99b36ef8dbd1d0c6e770870785597873c9039bfcf`;
- `service-lowering-5.raw`:
  `3605ae26ce3d573158fab37aa08733260dec89cc78385cce84a7284b5adce60b`;
- `openat-callers-base-2.raw`:
  `92bffc09a4ee6054eeadabee308e5ffd031cc2ac13ea23ca77708f4a03c06ded`;
- `openat-callers-base-3.raw`:
  `49743c7bfc07eaa850586c17babcf0de5e9a9200489168843d917bfc1141086c`.

Rejected instrumentation evidence is retained but not used below:
`openat-callers-base-1.raw` SHA-256
`00b065ed4dd35ad7d3ddd574badd8b13b9f23e6c65194b926d2dd06fd6188a14`
reported `status=error,image_base_seen=0` and proved the rootfs publication
gap.

Command shapes:

```sh
CARRICK_RUN_ID=<scoped-id> target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-service-lowering.d \
  --trace-out target/perf/hvpatch-phase4/<capture>.raw \
  -- run --name <scoped-id> --rm --raw --fs host \
  --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh

CARRICK_RUN_ID=<scoped-id> target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-openat-callers.d \
  --trace-out target/perf/hvpatch-phase4/<capture>.raw \
  -- run --name <scoped-id> --rm --raw --fs host \
  --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

Offline resolution used each capture's announced base and the captured binary:

```sh
atos -o target/release/carrick -l <announced-runtime-base> -fullPath <pc>...
```

## Darwin lowering ledger

The selected service populations are exact and balanced at begin, completion,
and clear in both captures.

| Linux service | Capture 4 calls | Host operation | Count | Per service | Capture 5 count | Per service |
|---|---:|---|---:|---:|---:|---:|
| `openat` (56) | 3,266 | `openat` | 34,373 | 10.5245 | 34,366 | 10.5224 |
| | | `close` | 27,488 | 8.4164 | 27,481 | 8.4143 |
| | | `fcntl` | 20,965 | 6.4192 | 20,955 | 6.4161 |
| | | `fstat64` | 11,115 | 3.4032 | 11,115 | 3.4032 |
| | | `flistxattr` | 5,349 | 1.6378 | 5,349 | 1.6378 |
| | | `fstatat64` | 3,249 | 0.9948 | 3,249 | 0.9948 |
| `newfstatat` (79) | 3,962 | `openat` | 18,152 | 4.5815 | 18,148 | 4.5805 |
| | | `close` | 14,438 | 3.6431 | 14,434 | 3.6421 |
| | | `fstatat64` | 9,045 | 2.2839 | 9,046 | 2.2842 |
| | | `fcntl` | 4,093 | 1.0331 | 4,092 | 1.0328 |
| | | `fstat64` | 2,567 | 0.6479 | 2,567 | 0.6479 |
| | | `flistxattr` | 1,438 | 0.3630 | 1,439 | 0.3632 |

Linux `mmap` generated only 282/285 host `mmap` calls across 1,922/1,938
services and 30 `pread` calls in each capture. Its traced fault population is
strongly perturbation-sensitive. It is not the first behavior candidate.

## Exact caller distribution

The stack consumer retains the 128 largest `(Linux nr, stack)` keys. It covers
33,315/34,365 (96.94%) and 33,650/34,450 (97.68%) of Linux-openat-window host
opens, plus 17,762/18,151 (97.86%) and 17,593/18,150 (96.93%) of
newfstatat-window host opens.

Immediate host-open callers are stable across the two ASLR-independent
captures:

| Linux window | Exact caller | Capture 2 | Capture 3 |
|---|---|---:|---:|
| `openat` | cap-std/rustix `openat` path | 16,771 | 16,839 |
| | `HostFsBackend::fast_open_contained` | 11,178 | 11,447 |
| | `HostFsBackend::validate_parents_fast` | 2,835 | 2,834 |
| | `HostFsBackend::fast_open_for_guest` | 2,222 | 2,221 |
| | `stat_cache_get_or_fill` | 309 | 309 |
| `newfstatat` | cap-std/rustix `openat` path | 8,508 | 8,508 |
| | `HostFsBackend::fast_open_contained` | 5,236 | 5,236 |
| | `stat_cache_get_or_fill` | 3,310 | 3,143 |
| | `HostFsBackend::validate_parents_fast` | 435 | 435 |
| | root-marker xattr path | 273 | 271 |

The deeper resolved frames identify the dominant ordinary-open chain:

1. `RootFsVfs::open_for_dispatch` calls `overlay.lookup_kind(path)`.
2. `HostFsBackend::lookup_kind` performs a contained metadata open and an
   exact-name/cap-std validation for common files.
3. Only after that preflight says `File`, `open_for_dispatch` calls
   `open_raw_fd_with_metadata`.
4. `open_raw_fd_with_metadata` performs the real contained file open and
   derives metadata from that served fd.

Thus the comment that the served fd needs "no separate lookup/metadata walk"
is true inside `open_raw_fd_with_metadata`, but the dispatcher has already
performed a separate `lookup_kind` path walk before calling it. The stack
census observes both mechanisms repeatedly in the same Linux service window.

## Selected behavior experiment

For non-creating, non-truncating ordinary `--fs host` regular-file opens, add a
backend operation that atomically attempts the served fd first while preserving
the overlay rules:

- check normalized path and whiteout state before opening;
- bind the check/open/result to the shared filesystem generation so a
  concurrent create, unlink, rename, whiteout, or symlink change forces the
  existing path;
- derive kind and metadata from the served fd;
- return only a proven contained, exact-name regular file;
- fall back unchanged for directories, symlinks, FIFOs/devices, Unicode
  aliases, misses, create/truncate, xattr uncertainty, and races.

`RootFsVfs::open_for_dispatch` can try that operation after its shared-file
entry check and before `lookup_kind`. A successful attempt removes the
`lookup_kind` preflight while returning the same real fd and metadata the
existing file arm would return. This is an experiment, not yet an accepted
optimization: correctness probes must be red-first, and retention requires a
clean untraced ABBA plus the full Phase 4 gates.

## Verification at this checkpoint

- Red-first host-publication contract failed on the original static-only
  placement, then passed after publication moved to `finish_hvpatch_image`.
- `cargo test -p carrick-runtime
  every_hvpatch_image_publishes_host_identity_before_preparation --lib`:
  passed.
- `cargo test -p carrick-observability hvpatch_guest_probe_abi --lib`: 22
  passed.
- `cargo check -p carrick-runtime`: passed.
- `cargo fmt`: passed.
- Signed `just build`: passed before both symbolized captures.
- Both retained stack captures passed every fail-closed invariant and exact
  workload output check.
- Full `just ci`: passed before commit.

A narrow commit remains required before behavior changes.
