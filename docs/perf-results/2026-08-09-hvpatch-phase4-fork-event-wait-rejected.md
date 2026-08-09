# HvPatch Phase 4 fork event-wait experiment

Date: 2026-08-09

Status: **REJECTED; no behavior or dormant mechanism retained. Phase 4 remains
RED.** A lost-wakeup-safe registry condition wait preserved correctness but
regressed both CPU and wall time against the legacy 200-us sleep poll in a
same-binary ABBA. The result corrects the preceding attribution: most measured
quiescence time is real sibling-retirement time, not removable polling tail.

## Hypothesis

The closed fork ledger measured 292.093 ms of quiescence across 136 forks and
315.4 us per recorded 200-us poll. Could notification from
`VcpuRegistry::unregister` remove that cost while preserving repeated recovery
kicks for a sibling that did not respond to the first nudge?

## Candidate

The unretained candidate added:

- `VcpuRegistry::wait_until_count_at_most`, implemented by
  `GenericVcpuRegistry` with one condition variable sharing the handles-map
  mutex with the population predicate;
- notification while `unregister` held that mutex, excluding the classic
  count-check-to-park lost-wakeup window;
- a default-on event path with `CARRICK_HVPATCH_FORK_EVENT_WAIT=0` selecting the
  exact legacy control in the same binary;
- the existing ten-second abort bound and the same kick, futex wake, platform
  futex wake, and signal-arrival wake bundle on recovery;
- a typed `hvpatch-fork-quiesce-wait` probe carrying mechanism, Linux parent
  PID/TID, wait iterations, and recovery timeouts without changing the
  committed legacy poll-count ABI.

The final recovery timeout matched the legacy 200-us retry cadence. Therefore
notification could return before the timer after the final unregister, while a
slow sibling received the same repeated wake pressure as the control.

Red-first tests covered immediate threshold success, wake on unregister,
bounded timeout, default-on/zero-off hatch parsing, and the typed guest-identity
probe ABI. All passed after implementation; focused clippy passed with warnings
denied. These tests prove the mechanism, not a performance win.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`, committed parent `9f4970e7`; the candidate was dirty
  and was removed after qualification.
- Final signed candidate binary SHA-256:
  `781f65e57312f5b927b4aa0befc373b04f56a5e9bf7d80b844a100e14861ba2b`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Every retained run printed exact `ok` and `BUILD_OK`. Carrick and Docker were
  not run concurrently.

## Typed trace screen

Command shape:

```sh
CARRICK_HVPATCH_FORK_EVENT_WAIT=<0-or-1> \
CARRICK_RUN_ID=<scoped-id> target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-fork-runtime-stages.d \
  --trace-out target/perf/hvpatch-phase4/<capture>.raw \
  -- run --name <scoped-id> --rm --raw --fs host \
  --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

Both final captures reported 68 events for every fork stage, 68 mechanism
events, and zero phase, mode, empty, bounded, or DTrace errors:

| Arm | Quiescence total | Process-spec total | Fork cumulative total | Retry observations |
|---|---:|---:|---:|---:|
| Legacy sleep poll | 150.591 ms | 89.304 ms | 258.252 ms | 475 polls |
| Registry event | 160.239 ms | 86.107 ms | 266.238 ms | 558 waits, 493 timeouts |

Raw streams:

- `target/perf/hvpatch-phase4/fork-event-wait-off-finaltrace-2.raw`
- `target/perf/hvpatch-phase4/fork-event-wait-on-finaltrace-2.raw`

The traced screen is not performance authority, but it rejects the claim that
the condition wait mechanically collapses the quiescence ledger. Siblings
commonly remained registered across multiple recovery periods; notification
can remove only the final post-unregister sleep tail.

Two exploratory tunings are excluded from the retained comparison:

- a 10-ms recovery cadence incurred two timeouts and made the event arm about
  32 ms slower in traced quiescence;
- a 1-ms cadence still incurred 71 timeouts and remained slower.

The exploratory six-argument event probe is also rejected as evidence: its
sixth scalar arrived as zero on this macOS/arm64 host despite a nonzero source
value. The corrected five-argument probe carried mechanism and Linux identity;
elapsed time stayed in the independently paired quiescence probe. This is a
provider-ABI warning for future `carrick trace` preflight work, not proof that
all existing six-argument probes are invalid.

## Untraced ABBA retention gate

Pattern: `off on on off / off on on off`. CPU is `/usr/bin/time -lp` user plus
system. Both arms are the same signed binary; `off` sets the hatch to zero and
`on` uses the shipped-default candidate path.

```sh
/usr/bin/time -lp /usr/bin/env \
  CARRICK_HVPATCH_FORK_EVENT_WAIT=<0-or-1> \
  CARRICK_RUN_ID=<scoped-id> \
  target/release/carrick run --name <scoped-id> --rm --raw \
  --fs host --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

| Run | Arm | Wall-s | User-s | System-s | CPU-s | Page reclaims |
|---:|---|---:|---:|---:|---:|---:|
| 1 | off | 2.39 | 2.22 | 1.64 | 3.86 | 285,414 |
| 2 | on | 2.89 | 2.21 | 2.05 | 4.26 | 283,927 |
| 3 | on | 2.79 | 2.26 | 1.97 | 4.23 | 286,583 |
| 4 | off | 2.77 | 2.22 | 2.00 | 4.22 | 285,429 |
| 5 | off | 2.80 | 2.28 | 1.99 | 4.27 | 285,838 |
| 6 | on | 2.90 | 2.30 | 2.14 | 4.44 | 288,164 |
| 7 | on | 2.75 | 2.20 | 1.97 | 4.17 | 286,098 |
| 8 | off | 2.83 | 2.24 | 1.94 | 4.18 | 287,295 |
| **Mean** | **off** | **2.6975** |  |  | **4.1325** | **285,994** |
| **Mean** | **on** | **2.8325** |  |  | **4.2750** | **286,193** |

Candidate minus control:

- CPU: **+0.1425 s, +3.45%**;
- wall: **+0.1350 s, +5.00%**;
- page reclaims: +199 mean, effectively neutral.

The direction repeats by block: +0.205 CPU-s in block one and +0.080 CPU-s in
block two. An earlier invocation that placed shell assignments directly after
`/usr/bin/time` exited 127 before Carrick and is rejected. A corrected block
whose extractor expected GNU time field order proved correctness but retained
no timings and is also excluded. Only the table above is the CPU authority.

## Decision

**Reject and remove the candidate.** No condition variable, trait method,
event-wait hatch, or dormant probe remains in production source. The existing
typed fork-stage/quiescence probes remain because they produced the diagnosis.

The result changes the next-step ranking:

1. do not spend another iteration replacing the outer sleep primitive;
2. attribute why siblings take multiple kick cycles to unregister/park only if
   that path shows enough end-to-end opportunity under an untraced gate;
3. attack the independent process-spec construction bucket (1.284 ms/fork in
   the repeated closed ledger) and exec backing-map/bank-plan work;
4. retain correct one-VM isolation and the bounded quiesce postcondition.

Phase 4 remains RED against `<1 ms` complete exec and `<3.5 CPU-s`.

## Restoration verification

- After removal, `git diff` showed no production, test, or D-script changes;
  this evidence document was the only worktree addition.
- Full `just ci`: passed on the restored source.
- `just build`: rebuilt and codesigned the restored backend.
- Restored signed binary SHA-256:
  `769a98e0175f55215c0b69554f7c04457977ae7f59e3c117864863ffdfdd9640`.
- A final restored `--exec-backend hvpatch --fs host` cold-build smoke printed
  exact `ok` and `BUILD_OK` and exited zero.
