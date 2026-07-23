# FreeBSD/amd64 native LTP readiness

Status: automated static-musl execution gate established on FreeBSD 15.1/amd64.
The native lane also starts dynamically linked Ubuntu/glibc programs and can
execute Dockerfile `RUN` processes through Carrick-hosted Kaniko. The goal of
this lane is direct Carrick execution, not Docker/Podman result comparison. The
current curated gate is green.

## Why a separate fixture is used

The static-musl fixture keeps the pinned LTP artifact small, deterministic, and
independent of a distribution's runtime libraries. Carrick's native x86 loader
now maps a main `PT_INTERP` executable and its interpreter separately, enters
the interpreter with Linux-compatible auxv values, and supports dynamic
Ubuntu/glibc execution; static PIE is therefore a fixture choice rather than a
loader limitation.

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
CARGO_BUILD_JOBS=1 cargo build --release -p carrick-cli \
  --no-default-features --features platform-freebsd

target/release/carrick pull --platform linux/amd64 \
  gcr.io/kaniko-project/executor:v1.24.0

python3.11 scripts/native-x86-ltp-image.py \
  --ltp-bin-root /path/to/ltp/testcases/kernel/syscalls \
  --rootfs /path/to/static-musl-root \
  --tag carrick-ltp-static-musl:20260529
```

Podman is not involved in the execution verdict. Carrick builds the OCI image
and Carrick's native backend runs it.

To compile the pinned source inside an Ubuntu linux/amd64 build container—not
with FreeBSD host headers—use the source-image builder. It archives the exact
git ref, executes a bounded parallel static-musl build through Carrick-native
Kaniko, records syscall directories that do not compile, emits a scratch image,
and runs `getpid01` as its default smoke test. `--jobs` defaults to eight on the
current 8-CPU/32-GiB rig and can be reduced explicitly on a smaller host:

```sh
CARRICK_NATIVE_X86_XSTATE_POLICY=neutral-domains \
python3.11 scripts/native-x86-ltp-source-image.py \
  --ltp-source /path/to/ltp \
  --ltp-ref 20260529 \
  --jobs 8 \
  --archive /tmp/carrick-ltp-native-built-20260529.tar \
  --tag carrick-ltp-native-built:20260529
```

The archive is the same Kaniko tar Carrick ingests. Transfer those exact bytes
to a **native Linux/amd64** oracle host (not an emulated amd64 container), then:

```sh
docker load --input /tmp/carrick-ltp-native-built-20260529.tar
docker run --rm --platform linux/amd64 \
  carrick-ltp-native-built:20260529 \
  /opt/ltp/testcases/bin/getpid01
```

Run every curated case from `scripts/native-x86-ltp-cases.txt` against that same
tag and compare normalized results with Carrick before claiming parity.

A serial baseline completed the full build and packaged
`carrick-ltp-native-built:20260529` at digest
`sha256:33df40dbea9d455824551561e4fe1849080fa7a394395327897d5b28669ac418`;
its packaged `getpid01` smoke reported 100 TPASS and no failures, breakage,
skips, or warnings. The build took 16,021 seconds (about 4h27m), however, so it
is correctness evidence rather than an acceptable performance result.
Same-artifact Linux-oracle parity is also still pending.

The jobs=8 path is now structurally parallel rather than relying on LTP's
single-shell recursive traversal. Common libraries fell from about 18 minutes
to 213 seconds, and the corrected syscall-leaf traversal reached its final
expected `fmtmsg`/`addseverity` build skip in 3,324 seconds total—below the
90-minute compile target. That attempt did not package an artifact because
Kaniko was then reported as dying by SIGKILL. FreeBSD logged no OOM event and
the driver has no timeout, so the cause remains unattributed rather than being
called a runtime or resource bug.

The monitored rerun under explicit `neutral-domains` completed end to end in
4,395.82 seconds (73m15.82s), including image ingest and the 100-iteration
`getpid01` smoke. It packaged
`docker.io/library/carrick-ltp-native-built-j8-neutral:20260529` at digest
`sha256:1e1f288a83ccef901365c7ed1bc45a00e0464297082fee4fa5f3f98015c73dd8`.
The exact 604 MiB Kaniko archive has SHA-256
`a1b15d8ebf7cd9f46df312183202a2df7c89ba5a59c04a705ef41367abf42b7a`;
its build-skip manifest contains only `fmtmsg` and `timer_create`. No SIGKILL
occurred. Swap peaked near 191 MiB, page-fault OOM attempts did not increase,
and the kernel-only lifecycle trace observed no signal 9.

The 25-case curated gate then ran from that exact packaged image in 48.93
seconds: 23 PASS, two clean TCONF, 194 TPASS, zero TFAIL/TBROK/timeouts. Its
JSONL is `/tmp/native-ltp-packaged-j8-neutral.jsonl`, with the image digest and
archive hash in every row. The first gate exposed `clock_gettime04` moving
backward by sub-microsecond amounts: this FreeBSD guest selects `kvmclock` and
reports both `kern.timecounter.invariant_tsc=0` and `smp_tsc=0`, but Carrick had
trusted `machdep.tsc_freq`. Native vDSO calibration now requires both safety
flags; otherwise its existing zero-frequency path falls back to the translated
Linux clock syscall. The exact case now passes all six clock families.

The first source-build attempts exposed six runtime defects now fixed: an upper-layer hardlink could truncate its lower-layer
target (`59b87bed`), native exec stored argv/env in one 4 KiB scratch page
(`ddc21834`), every host-backed stream reported the same synthetic inode
(`70d1c98c`), the x86 control-flow resolver treated counter branches as RFLAGS
branches (`0cfdae1b`), VFS bind opens bypassed the `O_DIRECTORY` type check
(`3f77f25e`), and unsupported bind-mount xattrs leaked `ENODATA` instead of
`EOPNOTSUPP` (`4a1b5754`, with mutation-order and errno hardening in
`d412c603`). The inode defect made GNU m4 mistake stderr's pipe
for stdout's `/dev/null` after `2>&1 >/dev/null`, so autom4te discovered no builtins
and emitted empty traces. The counter defect made JRCXZ fall through with RCX=0;
GMP then wrapped the counter and walked 128 MiB before faulting. The native x86
fault probes added in `3177d9ea` identified the exact child (`expr 18 + 1`) and
captured RCX=`0xffffffffffc0001b` before teardown. The bind-open defect made GNU
`mv` treat a regular destination as a directory, append the source basename, and
leave configure's feature-test files stale. The xattr defect made GNU `install`
exit after copying but before applying mode 0755. The reducer now prints `19`,
`mv` replaces its destination correctly, `install` exits zero with mode 0755,
the exact m4 redirection emits 825 bytes,
direct autom4te emits
`configure.ac:AC_INIT`, and `aclocal` creates its 57,381-byte output. `/usr/bin/perl`
retains its 4,019,312-byte payload, 400-argument execs succeed, and predecoded
indirect control flow reduced focused `aclocal` from roughly 289 seconds to 83
seconds.

The subsequent GCC `cc1` crash in `safe_file_ops.c` was not an optimizer or
filesystem failure. LLDB watchpoints proved each hash-table allocation started
zeroed, an earlier table was legitimately deleted, and stale allocator metadata
then survived into a later `calloc`. Carrick retained physical heap bytes across
a `brk` shrink/regrow, violating Linux's zero-fill contract for re-exposed
anonymous pages; glibc consequently treated stale `MORECORE` space as already
zero. The strengthened `brkheapgrow` probe was red first
(`regrow_zero_fill=false`), then green after page-aligned released backing was
scrubbed, and the exact `cc1 ... -o -` reducer emitted 159,068 bytes with status
zero. The investigation also found an independent gateway defect: FXSAVE did
not preserve YMM/ZMM/opmask state that raw CPUID exposed. A red-first YMM gateway
round-trip now passes with complete XSAVE/XRSTOR, host PKRU restoration, and DF
normalization. The persistent host image receives one full XSAVE and later
full-mask XSAVEOPT saves. The experimental `neutral-domains` policy keeps
proven-neutral chains in their incoming ownership domain while state users and
nonzero virtual guest PKRU remain guarded. RDPKRU/WRPKRU are emulated outside
the hardware XSAVE image to protect gateway memory; guest-memory pkey rights are
not yet enforced, so CPUID/XGETBV hide PKU/OSPKE and component 9. A missed
opmask-only `kortestq` classification
was the exact historical GnuTLS corruption and is now covered alongside AMX
configuration instructions. Gateway-owned monomorphic `ret` caches extend only
already guest-resident intervals; cold/mismatched/host-resident returns retain
the Rust resolver. Non-REX FCS/FDS are now exact virtual Linux selector state,
not FreeBSD FXSAVE64 residue: plain XRSTOR imports the 16-bit fields, plain
XSAVE writes them without touching the reserved halves, XRSTOR64 preserves
them, and requested-absent x87 plus signal return use the guest ABI values. The
`x87-selectors` fixture pins those distinctions. Translation-time instruction
fetch also uses kernel-contained, execute-checked incremental copyin rather
than a guest-backed Rust slice. Typed MAPERR/ACCERR and truncated-file
BUS_ADRERR reach the unified synchronous signal policy with the exact first
unavailable byte; speculative direct edges remain cold until authoritative
execution. The `instruction-fetch-retry` fixture repairs and retries both
cross-page cases. The final exact apt/GnuTLS replay packages successfully.

The comparable 20-output cc1 timings progressed from 205.53 seconds to 202.70
seconds with host XSAVEOPT, 137.78 seconds with neutral domains, and 135.82
seconds with the return-cache slice. The last delta is modest and profiler runs
with short-lived children were rejected fail-closed, so no unsupported hotspot
claim is made. Bounded-parallel packaging and the packaged native gate pass;
same-artifact native Linux/amd64 oracle validation remains pending, so the
builder must not yet be described as fully parity-green.

For another native x86 crash, capture the executable, argv, mapped entry, and
full fault operands without relying on a teardown-time stderr breadcrumb:

```sh
target/debug/carrick trace \
  --script scripts/dtrace/native-x86-fault.d \
  --trace-out /tmp/native-x86-fault.out -- run ...
```

## Honest limitations

- Dynamic Ubuntu/glibc startup and exec are live-verified on FreeBSD/amd64, but
  remain experimental and have not been validated on macOS in this session.
- The gate covers 25 curated cases, not the full syscall tree. The first wider
  sweep exposed three real next targets: `futex_wait02` leaves descendants,
  `futex_wait05` exceeds its timeout-latency threshold, and `futex_wake04`
  requires writable `/proc/sys/vm/drop_caches` support.
- `eventfd06` and `clock_gettime03` execute correctly but are configuration
  skips, not syscall coverage.
- The current conformance-probe corpus remains 428/428 under its intended
  harness, including live protection/fault retry.
- Complete standard-format XSAVE signal frames now pass async,
  synchronous-fault, nested, malformed-frame, and dual hostile-review gates.
  Cross-thread executable mutation/exec takeover still lacks Task 43's
  stop-and-ack epoch protocol; resident direct/return-cache chains can otherwise
  outlive an old mapping. Phase 3 remains experimental until that closes.
- The serial and jobs=8 source builds both package and pass their scratch-image
  smoke. The jobs=8 run meets the sub-90-minute target and its curated packaged
  gate passes. The same archive has not yet run on a native Linux/amd64 oracle
  host, so cross-host parity remains open.

## Next gate

1. Transfer the preserved tar to a native Linux/amd64 host and run the same
   curated cases there; compare normalized rows with the Carrick JSONL.
2. Use the accepted Carrick-built image to expand the serial gate by syscall
   area while preserving its per-directory build-skip manifest.
3. Fix `futex_wait02`, the `futex_wait05` timeout amplification, and the
   `futex_wake04` proc-control dependency without baseline excuses.
4. Continue adding syscall areas serially, reducing each failure before changing
   the runtime.
5. Add syscall-amplification and accepted wall/CPU baselines for representative
   cases.
