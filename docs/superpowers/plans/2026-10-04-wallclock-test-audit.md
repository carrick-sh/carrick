# Wall-Clock Test Upper Bound Audit

**Date:** 2026-10-04  
**Scope:** `crates/` and `conformance-probes/`  
**Classification categories:**
- **U**: Wall-clock upper bound used to prove "returns promptly, doesn't wait on X". Convertible to the structural handshake pattern.
- **R**: Runtime-ratio or performance budget intentionally measured (e.g. perf-contract or algorithmic complexity guard). KEEP; report execution lane (host `just test`, signed, or perf lane).
- **L**: Lower bound only (`elapsed >= deadline`). Fine; KEEP.
- **O**: Other (e.g. test timeout watchdog loops, clock domain calibration sanity checks, CPU-time measurements). KEEP.

## Summary

Correctness upper bounds must be replaced by equivalent structural evidence.
Deleting an upper bound or retaining only a lower bound does not prove deadline
selection, nonblocking behavior, or bounded work. Runtime benchmarks remain
separate and unchanged.

The corrected fixtures use these proofs:

1. Own the release of a competing resource, observe completion on an independent
   channel, and assert the resource is still held at completion.
2. Inject a clock or deadline consumer and compare the exact supplied deadline;
   host scheduling cannot choose which deadline wins.
3. Count attempts, refusals and row visits where the work occurs, with a bound
   justified by the algorithm. Test scaling at 16, 256 and 5000 registry rows.
4. Use a 30-second safety watchdog that fails on expiry. Expiry never releases
   a holder in a way that can satisfy the correctness assertion.

The source-hash edit to `futex-wake-exit-seed637.json` is reverted to the
pre-conversion snapshot (`51bfe67f4`). Its existing provenance problem belongs
to inventory PR #46; this PR does not rebind or weaken replay acceptance.

---

## Classification Table

| File:Line | Test Name | Class | Bound | Reason |
|---|---|---|---|---|
| `crates/carrick-vmm-hvf/src/host_signal.rs:1765` | `drain_fd_forces_empty_pipe_nonblocking` | **U** | `elapsed < 50ms` | Writer remains open through bounded result receipt; assert the writer FD is live at completion. |
| `crates/carrick-vmm-hvf/src/trap/foreign_mm/tests.rs:3892` | `foreign_mm_retain_deadline_bounds_directory_inventory_and_owner_contention` | **U** | `elapsed < 150ms` | Contention deadline upper bound; landing separately in PR #41 (do NOT touch file). *(hosted-CI verified pending)* |
| `crates/carrick-vmm-hvf/src/trap/foreign_mm/tests.rs:3892` | `foreign_mm_read_deadline_bounds_mutation_coordinator_contention` | **U** | `elapsed < 150ms` | Contention deadline upper bound; landing separately in PR #41 (do NOT touch file). *(hosted-CI verified pending)* |
| `crates/carrick-vmm-hvf/src/trap/memory_protection/tests.rs:2833` | `unmap_single_row_in_5000_row_registry_is_fast` | **U** | `elapsed < 50ms` | Descending insertion puts target near scope-vector tail. At 16/256/5000 rows: planning <= tree height + 12 visits, disarm == 1 visit, removal <= height + 8 visits; compaction <= population. |
| `crates/carrick-vmm-hvf/src/trap/memory_protection/tests.rs:2885` | `perf_unmap_single_row_in_5000_row_registry` | **R** | `elapsed < 10ms` | Benchmark budget guarding single-row unmap performance; runs only in perf lane (`#[ignore]`). |
| `crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs:1089` | `no_resources_backpressure_bounds_out_when_host_is_full` | **U** | `start.elapsed() < 2s` | Production retry decision uses controllable elapsed/park callbacks: 20 x 1 ms virtual parks, exactly 21 attempts, then terminal error. |
| `crates/carrick-runtime/src/vcpu_loop/executor/tests.rs:7191` | `preemption_driver_close_during_expiry_wakes_and_terminates` | **U** | `start.elapsed() < 500ms` | Install residency/deadline, acknowledge atomic deadline wait, advance to expiry under wait mutex, observe kick, close; shutdown completes while task and clock stay held. |
| `crates/carrick-runtime/src/vcpu_loop/executor/tests.rs:7209` | `preemption_driver_shutdown_with_future_deadline` | **U** | `start.elapsed() < 500ms` | Install residency and competing runnable peer, acknowledge deadline wait; shutdown completes while future clock and task settlement remain held. |
| `crates/carrick-runtime/src/vcpu_loop/memory/tests/native_buffers.rs:188` | `carrier_buffer_elf_control` | **O** | `started.elapsed() < 40s` | Watchdog upper bound inside long ELF execution loop to prevent infinite loop on test hang. |
| `crates/carrick-runtime/src/vcpu_loop/quiesce.rs:2822` | `pt_pause_drain_waits_for_late_sibling_acknowledgement` | **R** | `waited_cpu < 100ms` | CPU-time budget contract proving quiesce drain sleeps rather than spinning on CPU; runs in host `just test`. |
| `crates/carrick-runtime/tests/integration/syscall_net_epoll.rs:2296` | `epoll_et_unread_data_does_not_spin_and_waits_for_next_edge` | **L** | `elapsed >= 40ms` | Lower bound proving epoll_pwait with 50 ms timeout waited for its duration and did not return early. |
| `crates/carrick-thread/src/fork_quiesce.rs:1610` | `a_starving_entrant_leaves_before_the_next_fence_is_raised` | **U** | `waited < 500ms` | Force exactly ENTRANT_REFUSAL_LIMIT refusals with no incidental admission gap. Hold entrant until new coordinator acknowledges its guard wait; next fence sees zero parked entrants. |
| `crates/carrick-kernel/src/kernel/mm_access.rs:3045` | `mm_access_authority_enforces_one_overall_deadline_across_attempts` | **U** | `started.elapsed() < 250ms` | Clock advances 10 ms between observations; transport records two identical start + OVERALL_DEADLINE values across Retry then TimedOut; exactly two attempts. |
| `crates/carrick-kernel/src/kernel/control/exec.rs:842` | `wait_is_a_nonblocking_consume_poll_for_running_work` | **U** | `started.elapsed() < 50ms` | Worker result observed under failing watchdog while main thread retains uncompleted work; Running query precedes completion. |
| `crates/carrick-kernel/src/kernel/control/mod.rs:1407` | `running_exec_wait_poll_does_not_monopolize_status_connection` | **U** | `started.elapsed() < 200ms` | Status returns Alive while actual ExecWait holder remains inside test-owned release gate. Sender drops before server teardown on failure. |
| `crates/carrick-kernel/src/kernel/continuation/tests.rs:396` | `timerfd_rearm_wakes_retained_read_before_old_deadline` | **U** | `rearm_started.elapsed() < 500ms` | Retained read replans to virtual due 20 ms, completes at exactly virtual time 20 ms while replaced two-second deadline is unexpired. |
| `crates/carrick-kernel/src/kernel/container.rs:1734` | `system_domain_starts_unshifted` | **O** | `diff < 5s` | Tolerance bound checking initial ClockDomain calibration matches host SystemTime within 5 s. |
| `crates/carrick-kernel/src/kernel/container.rs:1756` | `two_domains_hold_independent_offsets` | **O** | `diff < 1s` | Tolerance bound checking shared host calibration base between two clock domains is within 1 s. |
| `crates/carrick-kernel/src/dispatch/tests.rs:2017` | `epoll_wait_ready` | **L** | `start.elapsed() >= 200ms` | Lower bound polling loop exit condition ensuring timeout has elapsed. |
| `crates/carrick-kernel/src/vfs/proc.rs:6244` | `proc_stat_btime_follows_the_guest_clock` | **L** | `btime + boot >= host_now + 3599` | Lower bound verifying guest boot time reflects the +1 hour guest clock offset. |
| `crates/carrick-kernel/src/dispatch/sysv.rs:5743` | `sysv_ipc_stamps_follow_the_guest_clock` | **L** | `clock.realtime_now() >= host_now + 3599` | Lower bound verifying SysV IPC timestamp reflects the +1 hour guest clock offset. |
| `crates/carrick-kernel-example/tests/fork_pipe_wait.rs:128` | `a_lost_wake_fails_inside_the_bound` | **U** | `elapsed < WAIT_BOUND * 3` | Two tasks rendezvous at deadline consumer; both supply exactly WAIT_BOUND once. Consumer expires without host time and child read remains the named failure. |
| `crates/carrick-kernel-example/tests/fork_pipe_wait.rs:489` | `nanosleep_completes_after_its_interval_with_zero_remaining` | **L** | `start.elapsed() >= 10ms` | Lower bound verifying sleep lasted at least the requested 10 ms interval. |
| `crates/carrick-kernel-example/tests/fork_pipe_wait.rs:511` | `clock_nanosleep_completes_after_its_interval` | **L** | `start.elapsed() >= 10ms` | Lower bound verifying clock_nanosleep lasted at least the requested 10 ms interval. |
| `crates/carrick-embed/tests/el1_sched.rs:785` | `el1_sched_idle_carrier_costs_no_host_cpu` | **R** | `cpu_ns > wall_ns / 2` | Runtime-ratio check asserting idle carrier spends negligible host CPU relative to wall clock; runs in signed `just test-embed` lane. |
| `crates/carrick-embed/tests/kernel_abort.rs:56` | `a_container_that_will_not_finish_aborts_with_a_post_mortem` | **O** | `elapsed < 300s` | Safety watchdog bound ensuring abort sink fires before test runner timeout; runs in signed `just test-embed` lane. |
| `crates/carrick-embed/tests/wedge_capture_ladder.rs:108` | `a_carrier_that_cannot_consume_its_abort_is_captured_and_named` | **O** | `elapsed < 300s` | Safety watchdog bound ensuring wedge capture ladder completes before test runner timeout; runs in signed `just test-embed` lane. |
| `crates/carrick-fatal/src/lib.rs:354` | `debugger_hold_delays_the_abort_and_names_the_pid` | **L** | `elapsed >= 2s` | Lower bound verifying debugger hold delayed abort by at least 2 s. |
| `crates/carrick-hal/src/vcpu_sched.rs:628` | `acquire_timeout_returns_none_on_exhausted_pool_and_prefers_own_slot` | **L** | `start.elapsed() >= 25ms` | Lower bound verifying pool acquire timed out after the full requested 25 ms duration. |
| `conformance-probes/src/bin/blockingpipewrite.rs:68` | `main` | **L** | `elapsed >= 500` | Lower bound verifying write blocked until alarm signal. |
| `conformance-probes/src/bin/futexdeadline.rs:59` | `main` | **L** | `elapsed.as_millis() >= 100` | Lower bound verifying futex wait timed out after at least 100 ms of the 200 ms deadline. |
| `conformance-probes/src/bin/futexrealtime.rs:62` | `main` | **L** | `elapsed.as_millis() >= 100` | Lower bound verifying CLOCK_REALTIME futex wait timed out after at least 100 ms. |
| `conformance-probes/src/bin/futexsharedto.rs:55` | `main` | **L** | `elapsed.as_millis() >= 250` | Lower bound verifying shared futex wait timed out after at least 250 ms. |
| `conformance-probes/src/bin/perf_net_tcp_stream.rs:56` | `main` | **R** | `start.elapsed() < WINDOW` | Timed window benchmark measuring loopback TCP throughput; runs in perf/conformance lane. |
| `conformance-probes/src/bin/perf_net_xclient.rs:78` | `main` | **R** | `start.elapsed() < STREAM_SECS` | Timed window benchmark streaming data for STREAM_SECS; runs in perf/conformance lane. |
| `conformance-probes/src/bin/ptyjobcontrol.rs:1193` | `test_pipe_read_timeout_on_blocked_empty_pipe` | **U** | `elapsed < 500ms` | One exact 50 ms poll budget with controlled clock, plus real poll completion while writer stays open; bounded helper receipt. |
| `conformance-probes/src/bin/selecttimeout.rs:81, 111, 143, 169, 212, 257` | `case_select_*` / `case_pselect_*` | **R** | `elapsed_ms_since < 1000` | Oracle conformance probe reports checking select/pselect wait is bounded within 1 s; runs against Docker oracle. |
| `conformance-probes/src/bin/epollinmemwake.rs:90` | `main` | **R** | `elapsed < 1500ms` | Conformance probe report verifying epoll_pwait woke via eventfd before 3 s watchdog; runs against Docker oracle. |
| `conformance-probes/src/bin/epollexclusive.rs:148` | `main` | **R** | `elapsed < 1500ms` | Conformance probe report verifying epoll woke before 2 s timeout; runs against Docker oracle. |
| `conformance-probes/src/bin/epolloutxthread.rs:183` | `main` | **R** | `elapsed < 2800ms` | Conformance probe report verifying epoll woke via EPOLLOUT before watchdog; runs against Docker oracle. |
| `conformance-probes/src/bin/epollzonetimeout.rs:99` | `main` | **R** | `t < 1500ms` | Conformance probe report verifying finite epoll wait woke early by thread write; runs against Docker oracle. |
| `conformance-probes/src/bin/ppollwaitset.rs:305, 357, 721` | `run_case_c`, `run_case_d`, `run_case_g` | **L** | `elapsed_ms >= 29.0`, etc. | Lower bound oracle probe reports verifying poll waited at least the requested duration. |
| `conformance-probes/src/bin/ltpcheckpoint.rs:195` | `main` | **O** | `duration_since > 2s` | Child process polling loop exit timeout (exits with 1 after 2 s). |

## Correction evidence (2026-10-05)

All mutations below change the implementation, leaving the converted assertions
unchanged. Each Linux mutation was uncommitted and restored byte-for-byte by the
foreground harness. Logs are retained under `/tmp/wallclock2-evidence/`.

| Fixture | Implementation mutation | Red result |
|---|---|---|
| Status alongside ExecWait | Serialize connection handlers under one mutex | EXIT 101, response watchdog while holder remains gated (`red-status-serialized.log`) |
| Exec consume poll | Park on Running instead of returning it | EXIT 101, held-work watchdog (`red-consume-poll-blocked.log`) |
| Foreign read deadline | Supply start + 5 s instead of start + 50 ms | EXIT 101, exact recorded deadlines differ (`red-foreign-deadline-extended.log`) |
| Timerfd replacement | Keep two-second timer deadline on settime | EXIT 101, due Some(2s) != Some(20ms) (`red-timerfd-old-deadline.log`) |
| Driver close during expiry | Ignore scheduler shutdown in work loop | EXIT 101, shutdown watchdog (`red-driver-close-ignored.log`) |
| Driver with future deadline | Ignore scheduler shutdown in work loop | EXIT 101, shutdown watchdog (`red-driver-stop-ignored.log`) |
| Starving entrant | Disable await_starving_entrants guard | EXIT 101, guard returns with one held entrant (`red-starvation-guard-disabled.log`) |
| Lost wake | Multiply operation deadline by six | EXIT 101, read/wait4 consume 30 s instead of 5 s (`red-lost-wake-deadline-extended.log`) |
| Empty pipe | Extend helper deadline by five seconds | EXIT 101, poll consumes 5050 ms instead of 50 ms (`red-pipe-deadline-extended.log`) |
| HVF drain | Remove nonblocking repair before empty-pipe read | EXIT 101, writer-held watchdog (`mac/red-drain.log`); restored EXIT 0 |
| HVF retry | Extend retry allowance by five seconds | EXIT 101, attempt 22 exceeds budget (`mac/red-retry.log`); restored EXIT 0 |
| HVF unmap | Replace binary lookup with instrumented population scan, including a mutation enabled only at 5000 rows | EXIT 101, removal visits 5000 rows (`mac-unmap-5000-mutation.log`); restored EXIT 0 |
| Foreign read deadline renewal | Renew deadline at each transport attempt while clock advances | EXIT 101, two later deadlines differ from operation-wide deadline (`red-foreign-deadline-renewed.log`) |

Production seams preserve the default paths: `read_mm_with_now` takes
`Instant::now`; `ScriptedWaitDriver` defaults to host time and the existing
wait-service consumer; pipe helper defaults to the existing clock/poll calls;
HVF admission uses the same retry predicate with host elapsed/park callbacks.
Scheduler/entrant acknowledgements and disarm visit accounting are test-only
(or behind the existing `test-support` feature). No timeout, retry policy,
concurrency limit, runtime benchmark, or printed probe report is relaxed.

Contract families: `kernel.mm.address-space-occupancy` owns the exact four
entrant refusals; `kernel.scheduler.runnable-progress` owns driver residency
and deadline cancellation. Linux `timerfd_settime(2)`, `read(2)`, `poll(2)` and
`munmap(2)` own replacement deadlines, non-EOF empty pipes and row retirement.
The VM-free fixtures prove named deadline/work invariants only; signed execution,
Docker differentials and batch acceptance remain director-owned.

## Initial correction verification receipts

All commands ran in the foreground. Linux logs are in
`/tmp/wallclock2-evidence/`; individual macOS mutation logs are copied into
its `mac/` directory. The macOS scratch source was
`8b88791ee3949a28084eeb72ecf023a32f4a7632`. Before this re-review correction, the final amendments changed the
foreign-read **test** clock and documentation only; those tested HVF files
remained byte-identical through `25e634df0`. Every remote build/test held `just lease carrick`; no signed
execution or Docker was run.

| Command | EXIT | Receipt |
|---|---:|---|
| `cargo test -p carrick-kernel --features test-support -- --skip serial_host` | 0 | `/tmp/wallclock2-evidence/kernel.log` |
| `env RUST_TEST_THREADS=1 cargo test -p carrick-kernel --lib --features test-support serial_host` | 0 | `/tmp/wallclock2-evidence/kernel-serial.log` |
| `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --no-default-features --features syscall-shim,platform-linux` | 0 | `/tmp/wallclock2-evidence/runtime.log` |
| `env RUST_TEST_THREADS=1 cargo test -p carrick-thread` | 0 | `/tmp/wallclock2-evidence/thread.log` |
| `cargo test -p carrick-kernel-example --no-fail-fast` | 101 | `/tmp/wallclock2-evidence/kernel-example.log` |
| `env RUST_TEST_THREADS=1 cargo test --manifest-path conformance-probes/Cargo.toml --bin ptyjobcontrol` | 0 | `/tmp/wallclock2-evidence/ptyjobcontrol.log` |
| `just test-kernel-semantics` | 101 | `/tmp/wallclock2-evidence/kernel-semantics.log` |
| `just check` | 0 | `/tmp/wallclock2-evidence/check.log` |
| `just clippy` | 0 | `/tmp/wallclock2-evidence/clippy-final.log` |
| `just fmt-check` | 0 | `/tmp/wallclock2-evidence/fmt-check.log` |
| `ssh rentamac@cloudmac 'source /Volumes/carrick/dev/env.sh; cd /Volumes/carrick-build/wt/wt-wallclock-mac; just lease carrick just check --tests'` | 0 | `/tmp/wallclock2-evidence/mac-check.log` |
| `ssh rentamac@cloudmac 'source /Volumes/carrick/dev/env.sh; cd /Volumes/carrick-build/wt/wt-wallclock-mac; just lease carrick cargo clippy -p carrick-vmm-hvf --all-targets -- -D warnings'` | 0 | `/tmp/wallclock2-evidence/mac-hvf-clippy.log` |

The three focused macOS `cargo test -p carrick-vmm-hvf --lib <fixture> --
--nocapture` restored runs each exit 0. The full Linux kernel-example run
(`--no-fail-fast`) has only `schedule_replay` failing; `just
test-kernel-semantics` also exits 101 at
`futex_wake_exit_receipt_replays`: `replay source hash mismatch`. The fixture
is byte-identical to `51bfe67f4`, as requested. This is an open PR #46
integration gate, not a pass or an ignored test. The other converted tests
pass after restoration. All twelve representative implementation mutations
exit 101 through unchanged assertions or failing watchdogs.

Static comparison proves every production probe section outside the internal
read helper is byte-identical to `51bfe67f4`, including all printed oracle
reports. No oracle refresh is necessary for changed report text because none
changed; guest execution acceptance still belongs to the director.

`just lint-domains` on `25e634df0`: EXIT 0 (director-run, 2026-10-05).


## Re-review correction (2026-10-05)

The refusal observer now enrolls once and loops on condvar returns without a
predicate transition. A test-only, one-shot spurious return is injected before
refusal 1. With the old handshake it fails `(true, 0) != (true, 1)` (EXIT 101);
with transition-only observation it passes (EXIT 0).

The HVF deadline fixture now calls
`create_with_no_resources_backpressure_bounded` with a controllable clock/park
observer. The retry decision records the budget received from that adapter;
the fixture requires exactly 20 ms, 21 attempts, 20 parks and the lowered
`NoResources` error. The default clock still uses `Instant` and `vcpu_gate`.
The pipe fixture installs per-thread clock/poll observations and calls the
production `read_exact_timeout` wrapper. A wrapper forwarding 5050 ms produces
`[5050] != [50]` (EXIT 101); restoration passes (EXIT 0). Host clock/poll and
all production report sections retain their original behavior and bytes.

All unmap setup, planning, disarm discovery, removal and thread-local work
measurements now run on one worker. An independent 30-second completion
observer fails with process EXIT 101 on expiry: it cannot leave a stuck worker
holding the global test lock and strand other tests. Population and visit
budgets and the ignored benchmark are unchanged.

Receipts for this correction use `/tmp/wallclock2-evidence/r3-*.log`.
macOS unsigned tests and compilation used pushed source
`5984209cf9d40e456d8ccdad8ea704afa0d9a662` under `just lease carrick`.
Subsequent edits are audit/commit metadata and mechanical inventory positions;
the five source files tested in this correction are unchanged. The scratch
macOS worktree was removed after verifying restoration. No signed guest,
Docker or batch acceptance result is claimed.

| Fixture | Real implementation mutation | Red EXIT | Restored EXIT | Receipt |
|---|---|---:|---:|---|
| Starving entrant | Treat the injected spurious condvar return as a transition and enter the release gate | 101: `(true, 0) != (true, 1)` | 0 | `/tmp/wallclock2-evidence/r3-red-spurious-observer.log`, `r3-green-spurious-observer.log` |
| Admission backpressure | Adapter forwards supplied 20 ms plus 4980 ms to the retry decision | 101: `5s != 20ms` at the deadline observer | 0 | `/tmp/wallclock2-evidence/r3-mac/red-adapter-forwarding.log`, `green-adapter-forwarding.log` |
| Empty-pipe timeout | Production wrapper forwards 5050 ms for the supplied 50 ms | 101: `[5050] != [50]` | 0 | `/tmp/wallclock2-evidence/r3-red-pipe-forwarding.log`, `r3-green-pipe-forwarding.log` |
| Single-row unmap | Binary-search traversal forgets to advance its lower bound | 101: independent 30-second watchdog expires and fails the process | 0 | `/tmp/wallclock2-evidence/r3-mac/red-unmap-stuck-traversal.log`, `green-unmap-stuck-traversal.log` |

Each mutant was local and uncommitted, and restored byte-for-byte. The spurious
return is retained as fixture input; the mutation bypasses the predicate loop
and enables acknowledgment of that return. No assertion was inverted.

| Verification command | EXIT | Receipt |
|---|---:|---|

| `cargo test -p carrick-kernel --features test-support -- --skip serial_host` | 0 | `/tmp/wallclock2-evidence/r3-kernel.log` |
| `env RUST_TEST_THREADS=1 cargo test -p carrick-kernel --lib --features test-support serial_host` | 0 | `/tmp/wallclock2-evidence/r3-kernel-serial.log` |
| `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --no-default-features --features syscall-shim,platform-linux` | 0 | `/tmp/wallclock2-evidence/r3-runtime.log` |
| `env RUST_TEST_THREADS=1 cargo test -p carrick-thread` | 0 | `/tmp/wallclock2-evidence/r3-thread.log` |
| `cargo test -p carrick-kernel-example --no-fail-fast` | 101 | `/tmp/wallclock2-evidence/r3-kernel-example.log` |
| `env RUST_TEST_THREADS=1 cargo test --manifest-path conformance-probes/Cargo.toml --bin ptyjobcontrol` | 0 | `/tmp/wallclock2-evidence/r3-ptyjobcontrol.log` |
| `just test-kernel-semantics` | 101 | `/tmp/wallclock2-evidence/r3-kernel-semantics.log` |
| `just check` | 0 | `/tmp/wallclock2-evidence/r3-check.log` |
| `just clippy` | 0 | `/tmp/wallclock2-evidence/r3-clippy-final.log` |
| `just fmt-check` | 0 | `/tmp/wallclock2-evidence/r3-fmt-check.log` |
| `ssh rentamac@cloudmac 'source /Volumes/carrick/dev/env.sh; unset CARGO_TARGET_DIR; cd /Volumes/carrick-build/wt/wt-wallclock-mac; just lease carrick just check --tests'` | 0 | `/tmp/wallclock2-evidence/r3-mac-check.log` |
| `ssh rentamac@cloudmac 'source /Volumes/carrick/dev/env.sh; unset CARGO_TARGET_DIR; cd /Volumes/carrick-build/wt/wt-wallclock-mac; just lease carrick cargo clippy -p carrick-vmm-hvf --all-targets -- -D warnings'` | 0 | `/tmp/wallclock2-evidence/r3-mac-clippy.log` |

The macOS focused restored command
`cargo test -p carrick-vmm-hvf --lib no_resources_backpressure -- --nocapture`
passes all three adapter cases (EXIT 0). The restored unmap command with
`--lib unmap_single_row_in_5000_row_registry_is_fast -- --nocapture` passes
all three populations (EXIT 0). Detailed commands/exits are retained in
`/tmp/wallclock2-evidence/r3-mac/commands.jsonl` and the aggregate
`/tmp/wallclock2-evidence/r3-mac-mutations.log`.

The two EXIT 101 integration gates fail only at
`futex_wake_exit_receipt_replays` with `replay source hash mismatch`.
The fixture remains byte-identical to main's reviewed base; PR #46 remains
an explicit integration dependency.


Final clean-tree reconciliation (EXIT 0,
`/tmp/wallclock2-evidence/r3-reconcile.log`) required no inventory changes.
Static source verification (EXIT 0,
`/tmp/wallclock2-evidence/r3-source-invariants.log`) confirms unchanged probe
report sections, the unchanged replay fixture and identical macOS-tested source.

Final `just lint-domains`: EXIT 0, run on the clean committed tree after
reconciliation (`/tmp/wallclock2-evidence/r3-lint-domains.log`). The live
host-authority subset covers `linux-cli` and `linux-runtime`; other profiles
remain pending in that census. This receipt amendment changes documentation
only. Full acceptance still belongs to the director.
