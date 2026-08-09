# HvPatch Phase 4 resolver-path census

Date: 2026-08-09

Status: **ATTRIBUTED; repeated negative-stat revalidation selected for a
behavior experiment. Phase 4 remains RED.** A typed guest-identity DTrace
consumer now binds Darwin resolver paths, flags, outcomes, and `fcntl`
commands to Linux PID/TID/ASID/syscall service windows. The clean capture
shows a large repeated-ENOENT population common to `openat` and `newfstatat`.

## Question

The caller-stack census proved that cap-std, `fast_open_contained`, the stat
cache, and parent validation all contribute host opens. Which paths and
outcomes cause those mechanisms to repeat, and is one semantics-preserving
chain plausibly large enough to clear the campaign's 10% opportunity rule?

## Instrument

`scripts/dtrace/hvpatch-phase4-resolver-paths.d` joins the typed
`hvpatch-syscall-service-{begin,completion,clear}` boundaries and records, for
Linux `openat` (56) and `newfstatat` (79):

- Darwin `openat` path, flags, and errno;
- Darwin `fstatat64` path, flags, and errno;
- Darwin `fcntl` command;
- exact per-guest PID/TID/ASID operation populations.

Live `dtrace -lvn` qualification on this host established:

- `openat:entry`: `(int dirfd, user_addr_t path, int flags, int mode)`;
- `fstatat64:entry`: `(int dirfd, user_addr_t path, user_addr_t statbuf,
  int flags)`;
- `fcntl:entry`: `(int fd, int cmd, long arg)`;
- open/stat returns expose `(int result, int error)`, with DTrace `errno` the
  authoritative outcome.

The first live scout (`resolver-paths-2.raw`) failed closed after a
`copyinstr` at syscall entry touched a valid pathname page before the kernel
had faulted it in. The consumer was corrected to retain only the pointer and
flags at entry, then copy the path at return after kernel copy-in; EFAULT is
counted but never dereferenced. `resolver-paths-3.raw` was clean and proved
the correction. The final capture additionally keys every path by errno so
missing and successful populations cannot be conflated.

Perturbation is **VERY HIGH**: every selected host path operation takes a
bounded `copyinstr` and aggregate update. Only same-instrument populations,
lower bounds, and ranks are citable. Elapsed time is not.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`; committed parent `098b7a23`.
- Signed binary SHA-256:
  `b8dcad3ef2c5b413de66b7c5eacd2cde2aa8acbef4dc34096abf96617bb654a6`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Exact workload output: `ok`, `BUILD_OK`; exit zero.
- Carrick and Docker were not run concurrently.
- Clean raw capture: `target/perf/hvpatch-phase4/resolver-paths-4.raw`,
  SHA-256
  `27372bdc748156e28d0c135017eab5137f5139934d3c8049d304a01f1a87a0d4`.
- Corrected but pre-errno-key capture: `resolver-paths-3.raw`, SHA-256
  `4ec96aae0bc93f912d80f084f7402ca3b8f8586568f175ad65bb66814704e8dd`.

Command shape:

```sh
CARRICK_RUN_ID=<scoped-id> target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-resolver-paths.d \
  --trace-out target/perf/hvpatch-phase4/resolver-paths-4.raw \
  -- run --name <scoped-id> --rm --raw --fs host \
  --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

The harness self-sudo boundary accepts the canonical signed
`target/release/carrick`; an archived binary copy is not in that sudo allowlist.
This is a launch-path constraint, not a workload or trace failure.

## Exact populations

Every selected service has one matching begin, completion, and clear event:

| Linux service | Calls | Host operation | Calls | ENOENT | ENOENT share |
|---|---:|---|---:|---:|---:|
| `openat` (56) | 3,266 | `openat` | 34,388 | 3,916 | 11.39% |
| | | `fstatat64` | 3,250 | 2,080 | 64.00% |
| | | `fcntl` | 20,969 | — | — |
| `newfstatat` (79) | 3,962 | `openat` | 18,149 | 3,627 | 19.99% |
| | | `fstatat64` | 9,046 | 4,384 | 48.46% |
| | | `fcntl` | 4,089 | — | — |
| **combined** | **7,228** | `openat` | **52,537** | **7,543** | **14.36%** |
| | | `fstatat64` | **12,296** | **6,464** | **52.57%** |

`fcntl` command 50 (`F_GETPATH`) accounts for 17,451 calls. Successful
`O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`-shaped opens (`0x1100100`) account for
23,372 calls, the cap-std component-walk population observed in the stack
census. The fd-centric `O_EVTONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` shape
(`0x1008104`) alone produces 6,286 ENOENT opens.

The retained top 768 path keys are deliberately a lower bound. Even within
that truncation:

| Population | Captured calls | Distinct keys | Calls after first per key |
|---|---:|---:|---:|
| ENOENT `openat` | 4,481 | 298 | **4,183** |
| ENOENT `fstatat64` | 6,458 | 576 | **5,882** |
| ENOENT fd-centric leaf opens only | 4,009 | 292 | **3,717** |

The largest stable repeated misses are semantic probes, not random noise:

- `root/.config/go/telemetry/mode`: 680 fd-centric missing opens;
- `sys/kernel/mm/transparent_hugepage/hpage_pmd_size`: 264;
- missing `textflag.h` / `go_asm.h` candidates: repeated tens to hundreds;
- Go cache artifact candidates: many separate paths, commonly ten probes each;
- `fstatat64("mode")`: 408 ENOENTs;
- `fstatat64("textflag.h")`: 198 ENOENTs;
- compiler/PATH candidates (`gcc`, `gccgo`) and Go cache leaves repeat across
  tasks and ASIDs.

## Selected experiment

Extend the existing dirfd-anchored stat cache with a typed negative entry:

1. On a cache fill, only an authoritative `fstatat(parent_fd, leaf,
   AT_SYMLINK_NOFOLLOW) == ENOENT` under an already-contained parent may create
   a negative entry. Other errors, symlinks, devices, aliases, and uncertain
   parents retain the existing fallback.
2. A negative hit still performs one `fstatat` through the cached parent fd.
   Continued ENOENT is an authoritative miss; a newly-created leaf drops the
   entry and refills. Thus external creation is observed rather than hidden by
   a generation-only answer.
3. In-process rename/fork clearing and the existing 4,096-entry bound remain
   unchanged. The negative entry owns the same parent anchor as a positive
   entry, so it does not widen the documented cross-process directory-rename
   coherence window.
4. Propagate a tri-state result internally (`Hit`, `Missing`, `Fallback`) so a
   proven miss does not immediately run fd-centric and cap-std fallback walks.
   Public `real_stat` semantics remain `Some`/`None`.
5. Add an exact opt-out hatch for clean ABBA attribution. Retention requires
   red-first correctness tests, signed exact-output captures, and an untraced
   ABBA with at least 10% CPU or wall opportunity before the full Phase 4 gate.

This is a selected experiment, not an accepted optimization or Phase 4
improvement. The trace proves population and repetition; only untraced ABBA can
prove end-to-end value.
