# HvPatch Phase 4 whole-workload service attribution

Date: 2026-08-09

Status: **ATTRIBUTED; filesystem/mapping family selected for narrow mechanism
attribution; Phase 4 remains RED.** Two complete stateless captures rank Linux
`openat` (56), `newfstatat` (79), and `mmap` (222) at 0.9137 and 0.8915 seconds
of combined nonblocking service duration. That repeated family clears the
campaign's 10% opportunity screen against the 4.27-CPU-second clean workload,
but is not a speedup projection: the instrument is deliberately perturbing and
the duration is monotonic wall time, not process CPU.

## Question

After private fork snapshots proved to be only 1.6% of the cold build, which
whole-workload service family is large enough to justify the next narrow
Darwin-lowering investigation while preserving the one-VM/ASID design?

## Instrument and tooling correction

The typed CTF surface is a four-scalar begin event plus a five-scalar
completion event:

`hvpatch-syscall-service-begin(guest_pid, guest_tid, asid,
linux_syscall_number)`

`hvpatch-syscall-service(guest_pid, guest_tid, asid, linux_syscall_number,
duration_ns)`

All task and address-space identities are Linux identities multiplexed inside
the one Darwin process. The begin probe's enabled closure starts the monotonic
clock, preserving the observability layer's predicted-not-taken-branch cost
when no consumer is attached. The runtime's RAII guard publishes duration on
every normally unwinding success, wait, fork, exec, and error path. A terminal
host `_exit` cannot run Rust destructors, so the final `exit_group` completion
is deliberately absent. That omission is explicit and does not affect the
selected service family.

The first consumer design emitted entry/end boundaries and joined them in
DTrace associative arrays. Three exact-output scouts were rejected:

- host `(pid, tid)` joining produced thousands of apparent orphans;
- guest `(pid, tid, ASID)` joining proved only one actual host-thread migration
  but still lost 4,924 joins;
- no `dtrace:::ERROR` or nested window explained the loss, and entry/end event
  populations remained balanced apart from the terminal syscall.

That is evidence that hot dynamic DTrace state was the unreliable layer, not a
guest-identity mismatch. The durable completion ABI now carries its duration,
so `scripts/dtrace/hvpatch-phase4-whole-cpu.d` keeps no associative join state.
The begin record exists only to gate clock materialization and provide a rich
anchor for later narrow Darwin correlation. It separately uses `profile-199`
for whole-process CPU shape and reports typed per-task PID/TID/ASID duration
totals. Atomic DTrace aggregations—not racy global D scalars—are population
authority. The script fails on zero root/service events, timeout, or DTrace
error; retainability additionally requires aggregate begin/completion counts
to differ by exactly the documented terminal syscall and the invoking command
to exit zero with exact expected output.

Perturbation remains high: two USDT firings and one monotonic clock measurement
per serviced syscall plus 199-Hz sampling. Absolute traced time and traced to
clean ratios are not citable. Blocking `futex`, sleep, and wait-family duration
is wait time and is excluded from CPU-opportunity selection. The nonblocking
filesystem/mapping ranks below select the next mechanism only; retention still
requires an untraced ABBA.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`, committed parent `1562a3df`, with only this typed
  instrumentation, D script, and evidence document uncommitted at capture
  time.
- Signed binary SHA-256:
  `f687ccab91b9d8ad7c0df5bf12c7c29436ff655144f06cd1f38644186deb6fa2`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Both retained runs printed exact `ok` and `BUILD_OK`, exited zero, and
  reported `status=ok`, one root, no timeout, and no DTrace errors. Carrick and
  Docker were not run concurrently.
- Raw capture SHA-256:
  - `whole-cpu-9.raw`:
    `5b2d0f4ab1d4f89eec1416e9a85c1ddca1ebec35d35d76c8542ac2f1ab9f6441`;
  - `whole-cpu-10.raw`:
    `c849e670015d81154b7e77a4c2c0ebf498a8c0e1d6a5a5d539067629e0c749a8`.

Command shape:

```sh
CARRICK_RUN_ID=<scoped-id> target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-whole-cpu.d \
  --trace-out target/perf/hvpatch-phase4/<capture>.raw \
  -- run --name <scoped-id> --rm --raw --fs host \
  --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

## Capture validity and population

| Capture | Begin/completed services | CPU samples (user/kernel) | Root/timeout/errors | Result |
|---|---:|---:|---:|---|
| `whole-cpu-9.raw` | 71,518/71,517 | 1,511 (87/1,424) | 1/0/0 | `ok`, `BUILD_OK` |
| `whole-cpu-10.raw` | 71,901/71,900 | 1,438 (79/1,359) | 1/0/0 | `ok`, `BUILD_OK` |

Each capture has exactly one more begin than completion: the documented
terminal `_exit` path. The total syscall population varies with Go scheduling
and wait behavior, but the selected family is stable: 9,158 versus 9,150 calls,
a 0.09% difference. The high kernel share is tracer-perturbed: `dtrace_probe`
alone received 390 samples in each capture. It is recorded as instrument
shape, not attributed to Carrick.

## Repeated nonblocking service ranks

| Linux service | Capture 9 calls | Capture 9 duration | Capture 10 calls | Capture 10 duration |
|---|---:|---:|---:|---:|
| `openat` (56) | 3,266 | 445.585 ms | 3,266 | 439.168 ms |
| `newfstatat` (79) | 3,962 | 209.008 ms | 3,962 | 202.750 ms |
| `mmap` (222) | 1,930 | 259.141 ms | 1,922 | 249.538 ms |
| **Selected family** | **9,158** | **913.734 ms** | **9,150** | **891.455 ms** |

Other large durations are not automatically CPU opportunities: `futex` (98),
`nanosleep` (101), `epoll_pwait` (22), `wait4` (260), and `clone`/`execve`
include scheduler, child, or process-lifecycle waits. `read` (63) mixes regular
file and blocking descriptor behavior, so it is deferred until a descriptor-
typed instrument can separate those populations.

## Decision

The repeated 0.891--0.914 second filesystem/mapping family is 20.9--21.4% of
the 4.27-second clean CPU reference if treated only as a generous removable
ceiling. Even substantial trace overhead leaves enough room for this family to
clear the 10% investigation threshold, unlike the rejected fork-remap lever.

The next step is a narrow, low-perturbation Darwin-lowering ledger restricted
to Linux syscall numbers 56, 79, and 222. It must distinguish Carrick host work
from the Darwin syscalls and VM operations it induces, preserve Linux
PID/TID/ASID in every join, and identify one semantic-preserving amplification
mechanism. Only then should one candidate be implemented and tested with
untraced ABBA plus the full Phase 4 correctness/exit/exec gates.

No behavior change is made by this checkpoint. The one-HVF-VM topology, ASID
isolation, per-process state, and exact fork/exec behavior remain unchanged.

## Verification before commit

- Red-first observability test failed against the old paired ABI, then passed
  after the stateless completion ABI landed.
- `cargo test -p carrick-observability
  syscall_service_provider_and_stub_keep_guest_task_identity_typed`: passed.
- `cargo check -p carrick-runtime`: passed.
- `cargo fmt`: passed.
- Signed `just build`: passed before both retained captures.
- Both fail-closed captures and exact workload output passed.
- Full `just ci`: passed.
