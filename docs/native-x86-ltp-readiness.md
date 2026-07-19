# FreeBSD/amd64 native LTP readiness

Status: automated static-musl execution gate established on FreeBSD 15.1/amd64.
The goal of this lane is direct Carrick execution, not Docker/Podman result
comparison. The current curated gate is green.

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
arguments, and prints both captured stdout and stderr. Set
`CARRICK_NATIVE_RAW_OUTPUT=1` to forward captured guest bytes verbatim and keep
the exit/trap marker on stderr; the default debug-escaped summary remains stable
for `scripts/native-x86-census.py`. The prepared root is a cap-std root, not the
FreeBSD host root. The native dispatcher reports x86_64 consistently through
`uname`, `/proc/cpuinfo`, and `/proc/config.gz`.

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

## Automated local gate

`scripts/native-x86-ltp-gate.py` runs the pinned cases serially. Every case owns
a process group and a file-backed merged output stream, so forked LTP workers
cannot disappear behind the top-level `RunResult`. The JSONL artifact retains
ordered raw TPASS/TFAIL/TBROK/TCONF lines, binary hashes, exit state, wall time,
and host user/system CPU time:

```sh
CARGO_BUILD_JOBS=1 cargo build -p carrick-runtime --example native_run \
  --no-default-features --features platform-freebsd

python3.11 scripts/native-x86-ltp-gate.py \
  --ltp-bin-root /path/to/ltp/testcases/kernel/syscalls \
  --rootfs /path/to/static-musl-root \
  --output /tmp/native-x86-ltp-local.jsonl \
  --timeout 120
```

The case declaration is `scripts/native-x86-ltp-cases.txt`; execution is
intentionally serial. The expanded gate currently runs **25 cases**: 23 pass
with **194 TPASS**, while `eventfd06` and `clock_gettime03` cleanly report TCONF
for unavailable libaio and `CONFIG_TIME_NS` respectively.

## Carrick-built OCI fixture

Carrick now runs Kaniko's fixed-address static Go executable through native DSR,
including JIT-slice recycling for its larger translation working set. The image
packager builds a scratch linux/amd64 image with Carrick itself, embeds hashes
for every static LTP binary and helper, then runs `getpid01` from the image:

```sh
CARGO_BUILD_JOBS=1 cargo build -p carrick-cli \
  --no-default-features --features platform-freebsd

target/debug/carrick pull --platform linux/amd64 \
  gcr.io/kaniko-project/executor:v1.24.0

python3.11 scripts/native-x86-ltp-image.py \
  --ltp-bin-root /path/to/ltp/testcases/kernel/syscalls \
  --rootfs /path/to/static-musl-root \
  --tag carrick-ltp-static-musl:20260529
```

Podman is not involved in the execution verdict. Carrick builds the OCI image
and Carrick's native backend runs it.

## Honest limitations

- The static-musl fixture is a bring-up lane, not a substitute for eventual
  dynamic Ubuntu/glibc support.
- The gate covers 25 curated cases, not the full syscall tree. The first wider
  sweep exposed three real next targets: `futex_wait02` leaves descendants,
  `futex_wait05` exceeds its timeout-latency threshold, and `futex_wake04`
  requires writable `/proc/sys/vm/drop_caches` support.
- `eventfd06` and `clock_gettime03` execute correctly but are configuration
  skips, not syscall coverage.
- The current conformance-probe corpus remains 428/428 under its intended
  harness, including live protection/fault retry.

## Next gate

1. Make the pinned static-musl cross-build reproducible, then package the wider
   result with `native-x86-ltp-image.py`.
2. Fix `futex_wait02`, the `futex_wait05` timeout amplification, and the
   `futex_wake04` proc-control dependency without baseline excuses.
3. Continue adding syscall areas serially, reducing each failure before changing
   the runtime.
4. Add syscall-amplification and accepted wall/CPU baselines for representative
   cases.
