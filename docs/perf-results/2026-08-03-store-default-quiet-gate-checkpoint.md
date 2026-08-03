# Store default quiet-gate checkpoint

**Date:** 2026-08-03  
**Scope:** Darwin/AArch64 native cold Go build, persistent translation store
default decision  
**Decision:** **NOT RETAINED / NOT REJECTED.** The authoritative quiet-box gate
is incomplete. `CARRICK_DSR_PERSISTENT_STORE` remains default-off.

## Bound artifact

Both attempted campaigns used the same signed executable:

- SHA-256: `3b21bd2406f095f84203365d976423c78d896c5704420a5b23f53e546c28ecf0`
- Mach-O UUID: `89649BB2-EB0C-3424-98C5-1B19F5238EB0`
- image digest:
  `sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
- arm A: store unset (current default-off behavior)
- arm B: `CARRICK_DSR_PERSISTENT_STORE=1`
- primary metric: `RUSAGE_CHILDREN` total CPU floor
- schedule: excluded warmups, then counterbalanced `A1 B1 B2 A2`, requested
  `n=8` quads

The candidate overlay also carries the retired
`CARRICK_DSR_DIRECT_BINDINGS=1` spelling. There is no production consumer for
that spelling at this revision, so the executable semantic difference is the
persistent-store setting.

## Attempt 1: real wedge, insufficient diagnostic

Campaign `83011-ed2c40d119604e01b76745eb03480226` started from clean source
commit `245635e7`. It completed one full quad plus `A1/B1` of quad 2. The
candidate's quad-2 `B2` Go `compile` child then consumed only `0.329 s` CPU and
made no progress before the original 900-second sample deadline.

This is a correctness/durability failure, not a timing outlier, so the campaign
closed `accepted=false`, `complete=false`, with no statistics and no retention
decision. The exact run id was:

`native-go-build-abba-83011-ed2c40d119604e01b76745eb03480226-quad-2-b2`

The automatic LLDB snapshot froze the shell, Go driver, and `compile` child,
but spent its whole 180-second diagnostic budget in the multi-process core
path. LLDB's event-ring and backtrace output remained buffered; no core
completed. Therefore the stopped process tree is evidence of a wedge, but not
authority for its mechanism. The failure must not be attributed to the store
from arm placement alone.

## Matched bounded soak

The exact populated ABI-8 store was copied to an isolated repro directory and
the same frozen binary ran the same cold-build body through `carrick debug
lldb-run --deadline-seconds 25 --no-core`:

- store on: 12/12 completed
- store off: 8/8 completed
- no Carrick process remained after scoped cleanup

This falsifies a deterministic corrupt-unit explanation. It does not clear the
rare wedge: the first official campaign remains a real occurrence, and neither
20 clean runs nor arm placement proves whether it is store-specific.

## Diagnostic repair

Commit `0d8f8f4d` makes benchmark timeout capture stack-first by passing
`--no-core` to the existing `lldb-snapshot` command. A red-first harness test
pins the command; all 38 `native_go_build` tests pass. A deliberately blocked
guest verified that the resulting path records event rings and complete host
thread backtraces for every scoped process inside the budget.

The rebuilt receipt at `0d8f8f4d` has the same binary SHA-256 and Mach-O UUID
listed above; the change is in benchmark orchestration, not the measured
executable.

## Attempt 2: power-invalidated

Campaign `87560-c868571bebf5427aa1ec8f683a65f5ab` used a 30-second per-sample
deadline and the repaired timeout path. Both warmups and one full quad
completed without a wedge. Before quad 2, the Mac changed from AC Power to
Battery Power. The harness failed closed:

`native performance campaign requires AC Power`

That campaign is also `accepted=false`, `complete=false`. Its one quad is
diagnostic only and must not be quoted as a retained performance result.

## Resume gate

Reconnect AC power, confirm no sibling compiler/Carrick/Docker load, and run:

```sh
python3 scripts/perf/native_go_build_abba.py run \
  --harness-repo "$PWD" \
  --control-receipt "$PWD/target/perf/store-default-confirm/control-arm-v2/arm.json" \
  --candidate-receipt "$PWD/target/perf/store-default-confirm/control-arm-v2/arm.json" \
  --control-overlay "$PWD/scripts/perf/overlays/native-default.json" \
  --candidate-overlay "$PWD/scripts/perf/overlays/native-shared.json" \
  --quads 8 \
  --cooldown-seconds 2 \
  --timeout-seconds 30 \
  --output "$PWD/target/perf/store-default-confirm/abba-v3.json"
```

Retention still requires a complete accepted campaign, the awk-8M compute
parity gate, 20-exec `compile -V`, cold-build correctness, and the serial
Carrick-then-Docker workload-spread scoreboard. Do not flip the default from
the partial data above.
