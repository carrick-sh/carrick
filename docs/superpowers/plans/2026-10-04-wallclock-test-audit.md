# Wall-Clock Test Upper Bound Audit

**Date:** 2026-10-04  
**Scope:** `crates/` and `conformance-probes/`  
**Classification categories:**
- **U**: Wall-clock upper bound used to prove "returns promptly, doesn't wait on X". Convertible to the structural handshake pattern.
- **R**: Runtime-ratio or performance budget intentionally measured (e.g. perf-contract or algorithmic complexity guard). KEEP; report execution lane (host `just test`, signed, or perf lane).
- **L**: Lower bound only (`elapsed >= deadline`). Fine; KEEP.
- **O**: Other (e.g. test timeout watchdog loops, clock domain calibration sanity checks, CPU-time measurements). KEEP.

## Summary

Wall-clock upper bounds in tests measure the machine, not the code. Under shared-host load, virtualized CI runners, or heavy thread contention, machine latency causes arbitrary upper bounds (such as `< 50ms` or `< 150ms`) to fail spuriously even when code semantics are completely correct.

The structural handshake pattern fixes this:
1. An asynchronous operation or contended resource holder holds until the test explicitly signals release (with a generous ~30 s safety bound to prevent hangs).
2. The test asserts:
   - (a) the result returned as expected (e.g. `TimedOut`, nonblocking status, or unparked state),
   - (b) the holder or peer was still holding / active at return (proving no dependency on the release or external deadline), and
   - (c) if testing a deadline, elapsed time is greater than or equal to the deadline (lower bound).

---

## Classification Table

| File:Line | Test Name | Class | Bound | Reason |
|---|---|---|---|---|
| `crates/carrick-vmm-hvf/src/host_signal.rs:1765` | `drain_fd_forces_empty_pipe_nonblocking` | **U** | `elapsed < 50ms` | Asserts drain_fd made pipe nonblocking and did not block on writer; convertible to holding writer until release. *(hosted-CI verified pending)* |
| `crates/carrick-vmm-hvf/src/trap/foreign_mm/tests.rs:3892` | `foreign_mm_retain_deadline_bounds_directory_inventory_and_owner_contention` | **U** | `elapsed < 150ms` | Contention deadline upper bound; landing separately in PR #41 (do NOT touch file). *(hosted-CI verified pending)* |
| `crates/carrick-vmm-hvf/src/trap/foreign_mm/tests.rs:3892` | `foreign_mm_read_deadline_bounds_mutation_coordinator_contention` | **U** | `elapsed < 150ms` | Contention deadline upper bound; landing separately in PR #41 (do NOT touch file). *(hosted-CI verified pending)* |
| `crates/carrick-vmm-hvf/src/trap/memory_protection/tests.rs:2833` | `unmap_single_row_in_5000_row_registry_is_fast` | **U** | `elapsed < 50ms` | Converted from wall-clock to deterministic work budget asserting O(1) rows scanned (<= 32) and single-pass compaction (<= 5000) in 5000-row registry. *(hosted-CI verified pending)* |
| `crates/carrick-vmm-hvf/src/trap/memory_protection/tests.rs:2885` | `perf_unmap_single_row_in_5000_row_registry` | **R** | `elapsed < 10ms` | Benchmark budget guarding single-row unmap performance; runs only in perf lane (`#[ignore]`). |
| `crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs:1089` | `no_resources_backpressure_bounds_out_when_host_is_full` | **U** | `start.elapsed() < 2s` | Asserts NoResources backpressure loop gives up after max_wait (20 ms) rather than hanging; convertible to asserting elapsed >= max_wait and calls >= 2. *(hosted-CI verified pending)* |
| `crates/carrick-runtime/src/vcpu_loop/executor/tests.rs:7191` | `preemption_driver_close_during_expiry_wakes_and_terminates` | **U** | `start.elapsed() < 500ms` | Asserts driver thread wakes and joins on scheduler close rather than blocking; convertible to joining the driver thread directly. |
| `crates/carrick-runtime/src/vcpu_loop/executor/tests.rs:7209` | `preemption_driver_shutdown_with_future_deadline` | **U** | `start.elapsed() < 500ms` | Asserts driver thread shuts down promptly rather than waiting on future deadlines; convertible to clean join assertion. |
| `crates/carrick-runtime/src/vcpu_loop/memory/tests/native_buffers.rs:188` | `carrier_buffer_elf_control` | **O** | `started.elapsed() < 40s` | Watchdog upper bound inside long ELF execution loop to prevent infinite loop on test hang. |
| `crates/carrick-runtime/src/vcpu_loop/quiesce.rs:2822` | `pt_pause_drain_waits_for_late_sibling_acknowledgement` | **R** | `waited_cpu < 100ms` | CPU-time budget contract proving quiesce drain sleeps rather than spinning on CPU; runs in host `just test`. |
| `crates/carrick-runtime/tests/integration/syscall_net_epoll.rs:2296` | `epoll_et_unread_data_does_not_spin_and_waits_for_next_edge` | **L** | `elapsed >= 40ms` | Lower bound proving epoll_pwait with 50 ms timeout waited for its duration and did not return early. |
| `crates/carrick-thread/src/fork_quiesce.rs:1610` | `a_starving_entrant_leaves_before_the_next_fence_is_raised` | **U** | `waited < 500ms` | Asserts starving entrant is admitted promptly under back-to-back fences; convertible to verifying entrant admitted within bounded fence iterations. |
| `crates/carrick-kernel/src/kernel/mm_access.rs:3045` | `mm_access_authority_enforces_one_overall_deadline_across_attempts` | **U** | `started.elapsed() < 250ms` | Asserts foreign read stops after one deadline attempt rather than retrying; convertible to checking single attempt and elapsed >= deadline. |
| `crates/carrick-kernel/src/kernel/control/exec.rs:842` | `wait_is_a_nonblocking_consume_poll_for_running_work` | **U** | `started.elapsed() < 50ms` | Asserts wait on running work returns promptly without waiting for work to complete; work is held running by the test. |
| `crates/carrick-kernel/src/kernel/control/mod.rs:1407` | `running_exec_wait_poll_does_not_monopolize_status_connection` | **U** | `started.elapsed() < 200ms` | Asserts control Status query returns promptly while concurrent ExecWait is active; convertible to structural release handshake holding ExecWait. |
| `crates/carrick-kernel/src/kernel/continuation/tests.rs:396` | `timerfd_rearm_wakes_retained_read_before_old_deadline` | **U** | `rearm_started.elapsed() < 500ms` | Asserts timerfd rearmed with 20 ms wakes promptly before the old 2 s deadline; convertible to verifying wake before old deadline structurally. |
| `crates/carrick-kernel/src/kernel/container.rs:1734` | `system_domain_starts_unshifted` | **O** | `diff < 5s` | Tolerance bound checking initial ClockDomain calibration matches host SystemTime within 5 s. |
| `crates/carrick-kernel/src/kernel/container.rs:1756` | `two_domains_hold_independent_offsets` | **O** | `diff < 1s` | Tolerance bound checking shared host calibration base between two clock domains is within 1 s. |
| `crates/carrick-kernel/src/dispatch/tests.rs:2017` | `epoll_wait_ready` | **L** | `start.elapsed() >= 200ms` | Lower bound polling loop exit condition ensuring timeout has elapsed. |
| `crates/carrick-kernel/src/vfs/proc.rs:6244` | `proc_stat_btime_follows_the_guest_clock` | **L** | `btime + boot >= host_now + 3599` | Lower bound verifying guest boot time reflects the +1 hour guest clock offset. |
| `crates/carrick-kernel/src/dispatch/sysv.rs:5743` | `sysv_ipc_stamps_follow_the_guest_clock` | **L** | `clock.realtime_now() >= host_now + 3599` | Lower bound verifying SysV IPC timestamp reflects the +1 hour guest clock offset. |
| `crates/carrick-kernel-example/tests/fork_pipe_wait.rs:128` | `a_lost_wake_fails_inside_the_bound` | **U** | `elapsed < WAIT_BOUND * 3` | Upper bound asserting scripted lost wake fails near 5 s deadline; lower bound `elapsed >= WAIT_BOUND` retained. |
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
| `conformance-probes/src/bin/ptyjobcontrol.rs:1193` | `test_pipe_read_timeout_on_blocked_empty_pipe` | **U** | `elapsed < 500ms` | Upper bound verifying empty pipe read timed out promptly; convertible to asserting read returned while writer held open and elapsed >= 40 ms. |
| `conformance-probes/src/bin/selecttimeout.rs:81, 111, 143, 169, 212, 257` | `case_select_*` / `case_pselect_*` | **R** | `elapsed_ms_since < 1000` | Oracle conformance probe reports checking select/pselect wait is bounded within 1 s; runs against Docker oracle. |
| `conformance-probes/src/bin/epollinmemwake.rs:90` | `main` | **R** | `elapsed < 1500ms` | Conformance probe report verifying epoll_pwait woke via eventfd before 3 s watchdog; runs against Docker oracle. |
| `conformance-probes/src/bin/epollexclusive.rs:148` | `main` | **R** | `elapsed < 1500ms` | Conformance probe report verifying epoll woke before 2 s timeout; runs against Docker oracle. |
| `conformance-probes/src/bin/epolloutxthread.rs:183` | `main` | **R** | `elapsed < 2800ms` | Conformance probe report verifying epoll woke via EPOLLOUT before watchdog; runs against Docker oracle. |
| `conformance-probes/src/bin/epollzonetimeout.rs:99` | `main` | **R** | `t < 1500ms` | Conformance probe report verifying finite epoll wait woke early by thread write; runs against Docker oracle. |
| `conformance-probes/src/bin/ppollwaitset.rs:305, 357, 721` | `run_case_c`, `run_case_d`, `run_case_g` | **L** | `elapsed_ms >= 29.0`, etc. | Lower bound oracle probe reports verifying poll waited at least the requested duration. |
| `conformance-probes/src/bin/ltpcheckpoint.rs:195` | `main` | **O** | `duration_since > 2s` | Child process polling loop exit timeout (exits with 1 after 2 s). |
