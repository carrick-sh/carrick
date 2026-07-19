# FreeBSD/amd64 native LTP readiness

Status: initial static-musl execution gate established on FreeBSD 15.1/amd64.
This is not yet a Docker-oracle parity baseline.

## Why a separate fixture is required

The release LTP OCI image uses dynamically linked Ubuntu/glibc executables.
The current FreeBSD native x86 loader accepts static PIE images, so its first
broad LTP fixture must be built as `x86_64-linux-musl` with `-static-pie`.
This keeps the test code unmodified while avoiding a premature dependency on a
Linux dynamic-loader implementation.

LTP also reads `/proc/config.gz` through `popen("zcat …")`. A bare
`native_run` filesystem deliberately contains no host binaries: FreeBSD
`/bin/sh` is not a Linux guest executable. The readiness root therefore needs
static-PIE Linux `/bin/sh` and `/bin/zcat` helpers. Set
`CARRICK_NATIVE_ROOTFS` to attach that prepared root explicitly; the default
remains an isolated temporary scratch root.

## Runner contract

```sh
CARRICK_NATIVE_ROOTFS=/path/to/static-musl-root \
CARRICK_MMAP_ARENA_GIB=1 \
  target/debug/examples/native_run /path/to/ltp/testcase [testcase-args ...]
```

The development runner supplies guest `PATH=/bin:/usr/bin`, forwards testcase
arguments, and prints both captured stdout and stderr. The prepared root is a
cap-std root, not the FreeBSD host root. The native dispatcher reports x86_64
consistently through `uname`, `/proc/cpuinfo`, and `/proc/config.gz`.

## Initial execution evidence

Pinned LTP source: `20260529`. The following binaries were cross-built as
static PIE with an `x86_64-linux-musl` toolchain and executed through the real
native DSR runner:

| Test | LTP summary |
|---|---:|
| `getpid01` | 100 passed, 0 failed/broken/skipped |
| `uname01` | 2 passed, 0 failed/broken/skipped |
| `eventfd01` | 4 passed, 0 failed/broken/skipped |
| `fork01` | 2 passed, 0 failed/broken/skipped |
| `futex_wait01` | 4 passed, 0 failed/broken/skipped |
| `clock_gettime01` | 16 passed, 0 failed/broken/skipped |

Total: **128 assertions passed**, with no failure, breakage, skip, or timeout.
This proves the LTP framework can initialize, decompress carrick's synthetic
kernel config, create its temporary directory, fork, and execute representative
process, eventfd, futex, and time tests under native DSR.

## Honest limitations

- These runs establish execution readiness only. They have not yet been diffed
  against the canonical native-amd64 Linux oracle.
- The static-musl fixture is a bring-up lane, not a substitute for eventual
  dynamic Ubuntu/glibc support.
- Forked LTP workers can write result lines through inherited host descriptors;
  a durable sweep harness must capture the whole process group, not only the
  top-level `RunResult` buffers.
- The current conformance-probe corpus is 428/428 under its intended harness,
  including live protection/fault retry. Shared-file futex identity across exec
  and exact cross-process requeue are covered by `ltpcheckpointexec` and
  `futexforkrequeue`; this does not replace Linux-oracle LTP parity.

## Next gate

1. Automate the pinned static-musl LTP build and prepared-root assembly.
2. Run a low-parallelism curated syscall sweep with process-group capture.
3. Run the same binaries on native amd64 Linux and compare exact TPASS/TFAIL/
   TBROK/TCONF lines, not summary counts alone.
4. Reduce each confirmed divergence to a deterministic conformance probe before
   changing the runtime.
