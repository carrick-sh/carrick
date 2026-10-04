# Fork-storm signed capture: inherited fixture lock

Source revision: `04e03c2ea45162e0156aec22c40b9b8f4fd92d6b`.
This follows [the VM-free investigation](2026-10-04-fork-storm-vm-free-investigation.md).
The failure was captured on macOS/HVF without tracing. No Docker ran.

## Baseline and artifact

`CARRICK_RUN_ID=forkstorm-base-01 ./scripts/test-signed.sh carrick-embed
el1_thread_lifecycle_fork_during_clone_storm --exact --nocapture` built and
signed the release libtest executable. That test invocation and 19 direct
invocations of the same executable passed, each with a distinct run ID and
`scripts/sudo/kill.sh <run-id>` reporting zero remaining processes. The
per-run verdicts and logs are under `target/forkstorm-baseline/`.

The signed test was `target/release/deps/el1_sched-67e2aabf7afcdc0d`:

- SHA-256 `dd6859487df812bb6c34c52a94258a45a1dae2fe8f63132371e34e0bd61c55d8`
- CDHash `7f6951b79f8ac2e956c8ccb7cb2e220b6cebc371`
- LC_UUID `D1F6DA49-0930-3E48-AF57-89B287A4F0A0`
- hypervisor entitlement and `__dof_carrick` present; fixture SHA-256
  `315d0d3c79f09e8a8ff5823d923de855f373da459814a678fecac8ddecc60bba`

The signing receipt was `target/test-results/carrick-embed-signed-artifacts.jsonl`.
The exact bytes of the pre-fix test and guest fixture were not copied aside
before the next signed rebuild. Their hashes and the unchanged source revision
are recorded; the core and its matching host source/symbol UUID remain, but
the original CDHash cannot be recovered from the rebuilt executable.

## Natural failure and core

Direct untraced attempts `forkstorm-core-001` through `-052` passed. Attempt
`-053` exited 139 (SIGSEGV) before any fork-storm summary; that separate
symptom lacks a core and is not attributed here. Attempts `-054` and `-055`
passed. `forkstorm-core-056` reproduced the reported failure in round 15:
report poll timed out, the child was not reaped in 20 seconds, and only 15
child reports arrived. Its terminal test status was failure after 40.65 s.

At about two seconds into `-056`, before the report timeout, the live kernel
graph and `carrick debug lldb-snapshot --run-id forkstorm-core-056` captured
the carrier (host PID 21054). The latter attached LLDB, dumped both rings and
all-thread backtraces, and ran `process save-core --style modified-memory`.
The capture is in `target/forkstorm-capture/`:

- `forkstorm-core-056.kernel-debug.json`
- `forkstorm-core-056.lldb.txt`
- `forkstorm-core-056.21054.core`
- `forkstorm-core-056.zone-records.txt` (offline LLDB read of the exact zone
  records and saved guest register contexts)
- `attempts.tsv`, the test log, the LLDB manifest and scoped cleanup log

The graph shows parent task `1#5` blocked in report poll with about 18.1 s
remaining, and live child task `351#7065` with leader `351#7066` and worker
`352#7352`. The worker is enrolled in zone wait record `3#901` and the
leader in record `6#211`; neither has a wake event. The core confirms both
records are parked (claim low bits `1`), not running or queued. The saved
worker context is at the AArch64 futex syscall (`x8=98`): `x0=0x2dcc68`,
`x1=0x89` (`FUTEX_WAIT_BITSET_PRIVATE`), `x2=2` (contended). The fixture ELF
symbol table resolves `0x2dcc68` to Rust std's
`stack_overflow::thread_info::LOCK`. The leader is in `pthread_join`, waiting
on its worker's clear-child-TID futex. Thus the child never reached its report
write or exit; pipe readiness and reaping are downstream symptoms.

The fixed-size lifecycle ring reported zero decode errors for its visible
8,192 events, but the clone storm had overwritten the earlier child-birth
history. The graph and core identify the blocked owner independently of that
missing range. The Rust 1.96 std source used by this fixture has a static
`LOCK: Mutex<()>` around `set_current_info()` during Rust thread startup.
The parent concurrently starts and exits Rust threads. Linux `fork(2)` copies
mutex state into the one-thread child; the vanished sibling cannot unlock
the child's private copy. The [Linux fork manual](https://man7.org/linux/man-pages/man2/fork.2.html)
explicitly describes that state copy and the limits on calls after a
multithreaded fork. Repairing this private library lock in Carrick would
diverge from Linux semantics.

## Correction and limits

Only the fork-storm child's Rust `std::thread::spawn`/join was replaced with
direct `libc::pthread_create`/`pthread_join`. The eight parent storm threads,
16 forks, one-thread child membership check, child's clone/join coverage,
20-second report and reap deadlines, and executor defaults stay intact.
The captured failing run is the red witness; the private Rust std lock offers
no deterministic fixture-controlled hold point. This is not a deterministic
red/green claim and no product runtime correction is claimed.

The corrected guest fixture SHA-256 is
`629f7fd7cd9414c60b65a6fad413626a429a64e3d3358cdf43ec428b72632efa`.
The rebuilt signed test SHA-256 is
`a653fa6132e8e233c62cdede48886139ee8515fb661d8024da62e384a591af0e`
with CDHash `ffa49a0c6e7ad46fe373e6b9dbc50676ef521331` and the same
LC_UUID. Twenty direct untraced runs passed with scoped cleanup; verdicts
are under `target/forkstorm-fixed/`. Three `el1_thread_lifecycle_` family
runs each passed eight tests and failed only the allowlisted
`ptrace_traceclone` and `spawn_slope` tests; logs are under
`target/forkstorm-family/`.
