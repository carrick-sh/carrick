# FreeBSD/amd64 native LTP readiness

Status: automated static-musl execution gate established on FreeBSD 15.1/amd64.
The curated local gate is green; this is not yet a native-Linux oracle parity
baseline.

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
intentionally serial. A local pass records `oracle_status: "pending"` — it must
not be reported as Linux parity until the same hashed binaries have run on a
native amd64 Linux host.

## Honest limitations

- These runs establish execution readiness only. They have not yet been diffed
  against the canonical native-amd64 Linux oracle.
- The static-musl fixture is a bring-up lane, not a substitute for eventual
  dynamic Ubuntu/glibc support.
- The gate now captures the whole process group, but only the six curated
  readiness cases are declared; it is not yet a broad syscall sweep.
- The current conformance-probe corpus is 428/428 under its intended harness,
  including live protection/fault retry. Shared-file futex identity across exec
  and exact cross-process requeue are covered by `ltpcheckpointexec` and
  `futexforkrequeue`; this does not replace Linux-oracle LTP parity.

## Next gate

1. Automate the pinned static-musl LTP build and prepared-root assembly, with an
   ELF/hash manifest for every artifact.
2. Run the same hashed binaries on native amd64 Linux and compare ordered
   TPASS/TFAIL/TBROK/TCONF lines, not summary counts alone.
3. Add syscall-amplification and accepted wall/CPU baselines before broadening
   beyond the curated serial sweep.
4. Reduce each confirmed divergence to a deterministic conformance probe before
   changing the runtime.
