# HVPatch orphan triage — 2026-08-22

The ~97 `dead_code` errors `just clippy` reports after the retired execution
model was deleted are **not all corpses**. Guest fault-signal delivery lived
only inside the welded loop and had to be PORTED, not deleted; deleting it would
have silently removed guest-visible behaviour. So a symbol having no callers
does not make it safe to delete — it may be a live responsibility that lost its
only caller.

This table is the first systematic pass over all 89 of them (four `unneeded
return` style errors excluded). It was produced by three independent read-only
Antigravity workers, one per group, each given the file:line list, the shape of
the trap, and a rule to bias toward UNCERTAIN.

**These are CANDIDATES, not conclusions.** Read the calibration warning below
before acting on a row.

## Calibration — read this first

Every one of the 89 rows came back with `confidence: certain` and **not one**
worker used UNCERTAIN, despite the brief explicitly asking them to prefer it and
explaining that a wrong CORPSE verdict silently deletes working behaviour while
a wrong UNCERTAIN costs five minutes. Treat the confidence column as
uninformative. Verify each row before acting on it.

One row has been verified so far, and it was CORRECT:
`vcpu_loop/signal.rs:330 complete_signal_thread`, reported LIVE. `xthreadsig`
hung to its timeout logging `persistent HVPatch loop reached an unlowered
outcome other=SignalThread { signum: 10 }`; adding the `service_outcome` arm
fixed it (`dbfffc6f`). That is the same shape as the `SigReturn` bug found
earlier in the campaign, which suggests the other `DispatchOutcome`-adjacent
rows deserve the same treatment first.

## How to verify a row

Run the capability, don't read the code. A LIVE verdict predicts a specific
guest-visible failure — run the probe that exercises it and look for
`unlowered outcome`, a hang, or a wrong result. A CORPSE verdict predicts
nothing changes; the cheap check is `grep -rn '\bSYMBOL\b' --include='*.rs'
crates/` plus `git log -S SYMBOL` to see whether the last caller died in
`202237b75` / `807174fa2` / `f2731ae13`.

## LIVE_RESPONSIBILITY candidates (23)
Reported as behaviour the persistent executor does not otherwise provide.
| file:line | symbol | what a guest loses if deleted |
|---|---|---|
| `dispatch/mem.rs:906` | `boot_region_is_carrick_kernel_hole` | Excludes Carrick's internal EL1-only kernel hole (trampoline, vector table, page tables) from guest ELF core dump PT_LOAD segments and /proc/self/maps projections. Deleting it corrupts ELF c |
| `dispatch/mem.rs:961` | `project_core_maps` | Projects Linux-visible VMAs for ELF core dump generation, filtering hidden Carrick reservations and clamping heap to brk. Deleting it silently removes accurate VMA layout in guest core dumps |
| `dispatch/mod.rs:2449` | `CoreProcessSnapshot` | Holds the process state (identity, auxv, maps, file_mappings, cwd, rlimit_core, dumpable) required to render ELF core dump headers, notes, and mappings on fatal signal termination. Deleting  |
| `dispatch/mod.rs:2451` | `auxv, maps, file_mappings, rlimit_core, and dumpable` | Provides core dump configuration and layout data: auxv for AT_* notes, maps for PT_LOAD headers, file_mappings for NT_FILE notes, and rlimit_core/dumpable for enforcing core generation limit |
| `dispatch/mod.rs:2460` | `CorePublication` | Carries the publication receipt of a committed core dump artifact, allowing the process exit status to set WCOREDUMP (bit 0x80) for wait4/waitid observers. Deleting it prevents WCOREDUMP fro |
| `dispatch/mod.rs:2463` | `generation` | Tracks crash capture generation to ensure atomic core dump publication and avoid races across process image generations. Must be ported with CorePublication to finalize_persistent_process_te |
| `dispatch/mod.rs:2467` | `CorePublicationError` | Represents fail-closed errors during core dump creation (I/O failures, malformed auxv, rlimit), ensuring a process exit gracefully clears WCOREDUMP and does not abort the runtime if writing  |
| `dispatch/mod.rs:2469` | `KernelIdentity and MalformedAuxv` | Captures kernel graph identity errors and auxv parsing errors during core dump generation, failing core publication cleanly without WCOREDUMP. Must be ported with core_process_snapshot to fi |
| `dispatch/mod.rs:4186` | `take_signal_pump_request, core_process_snapshot, and publish` | take_signal_pump_request: activates host signal pump thread when guest registers handlers via rt_sigaction (without it host signals are not pumped to guest handlers; port to ProductionHvpatc |
| `hvpatch/mod.rs:484` | `wait_until_job_control_resumed, syscall_trace_identity, reco` | wait_until_job_control_resumed: suspends execution of tasks stopped by job-control signals (SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU) or ptrace until SIGCONT or a fatal signal resumes them. Deleti |
| `kernel/objects.rs:3592` | `wait_until_job_control_resumed` | Blocks the calling thread on job_control_changed condvar while the task is stopped under POSIX job control (SIGSTOP/SIGTSTP/ptrace). Deleting it removes job control task pausing. Must be por |
| `kernel/objects.rs:5485` | `publish_crash_registers and withdraw_from_crash_capture` | publish_crash_registers publishes a thread's CPU register state into the crash capture quorum for ELF core dump NT_PRSTATUS note generation. withdraw_from_crash_capture withdraws parked thre |
| `vcpu_loop/mod.rs:146` | `GuestBlockedGuard` | Guest processes reading /proc/[pid]/stat or /proc/[pid]/status of a sleeping/blocked task (and LTP tests such as TST_PROCESS_STATE_WAIT(pid, 'S', 0)) observe the task state remaining as 'R'  |
| `vcpu_loop/mod.rs:153` | `publish` | Publishing task run state to /proc/[pid]/stat ('S' for blocked, 'R' for running) as required by Linux ABI and LTP state polling. Must be ported to persistent executor continuation suspend an |
| `vcpu_loop/mod.rs:1340` | `core_note_resume_pair` | ELF core dumps generated on fatal signal crashes require accurate PC/PSTATE registers in NT_PRSTATUS notes (distinguishing synchronous fault ELR/SPSR from parked syscall resume registers). D |
| `vcpu_loop/mod.rs:1400` | `recorded_for` | Retrieval of the exact crash signal, si_code, and fault address for the current image generation upon process fatal termination. Without this, fatal signals cannot determine if WCOREDUMP sho |
| `vcpu_loop/mod.rs:1408` | `fatal_for_terminal_owner` | Verification of whether the terminal process owner died from a fatal signal requiring core dump generation and WCOREDUMP reporting in wait status. Without this, waitpid cannot report WCOREDU |
| `vcpu_loop/mod.rs:2145` | `crash_capture` | Collection of multi-threaded register state for core dumps upon fatal signal crashes. Without crash register capture, core dumps of multithreaded guest processes cannot capture sibling threa |
| `vcpu_loop/mod.rs:2207` | `PreparedCorePublication` | Creation and atomic publication of ELF core dump files upon fatal signal termination, and setting the WCOREDUMP bit in the exit status returned to waitpid/wait4. Must be ported to finalize_p |
| `vcpu_loop/mod.rs:5268` | `HvpatchSyscallServiceGuard` | Host DTrace probes (carrick*:::hvpatch_syscall_service_begin, hvpatch_syscall_service, and hvpatch_syscall_service_clear) used by scripts/dtrace/native-amplification.d and carrick trace to m |
| `vcpu_loop/mod.rs:5277` | `begin` | Constructs HvpatchSyscallServiceGuard and arms the start timing for hvpatch_syscall_service DTrace USDT probes. Must be ported to ProductionHvpatchLoopJob::poll_with_engine around service_th |
| `vcpu_loop/mod.rs:7743` | `write_hvpatch_child_output` | When an in-VM multiplexed child process runs with buffered stdio and exits, any buffered stdout and stderr bytes in final_result are lost instead of being written out to host stdout/stderr d |
| `vcpu_loop/signal.rs:330` | `complete_signal_thread` | Guest calls to tgkill(2)/tkill(2)/pthread_kill(3) targeting sibling threads return DispatchOutcome::SignalThread. Currently service_outcome does not handle SignalThread and errors with unlow |

## CORPSE candidates (66)
Reported reachable only from the retired execution model.
| file:line | symbol | evidence summary |
|---|---|---|
| `dispatch/mod.rs:3681` | `multiple methods are never used` | grep -rn 'exit_one_task_thread' --include='*.rs' crates/ returned crates/carrick-runtime/src/dispatch/mod.rs:3063 (test), 3681 (def), and vcpu_loop/th |
| `hvpatch/mm_resources.rs:282` | `acknowledge_tlb_flush` | grep -rn 'acknowledge_tlb_flush' --include='*.rs' crates/carrick-runtime/src/hvpatch/mm_resources.rs returned line 282 (def) and unit tests. git show  |
| `hvpatch/stage1_mm.rs:237` | `acknowledge_tlb_flush` | grep -rn 'acknowledge_tlb_flush' --include='*.rs' crates/carrick-runtime/src/hvpatch/stage1_mm.rs returned line 237 (def), line 326 (Stage1MmRetiremen |
| `hvpatch/stage1_mm.rs:349` | `ForeignRetirement` | grep -rn 'ForeignRetirement' --include='*.rs' crates/ returned stage1_mm.rs:242 (construction in Stage1MmPool::acknowledge_tlb_flush) and stage1_mm.rs |
| `kernel/guest_execution.rs:100` | `reset_for_forked_child` | grep -rn 'reset_for_forked_child' --include='*.rs' crates/ returned only guest_execution.rs:100. git show 807174fa showed it was called in handle_fork |
| `kernel/scheduler.rs:1003` | `take_exact` | grep -rn 'take_exact' --include='*.rs' crates/ returned kernel/scheduler.rs:1003 (def) and kernel/scheduler.rs:1700 (called by take_transitional_lease |
| `kernel/scheduler.rs:1653` | `settle_transitional_blocked_continuation, take_transitional_` | grep -rn 'settle_transitional_blocked_continuation\\|take_transitional_lease\\|settle_transitional_runnable' --include='*.rs' crates/ returned only li |
| `vcpu_loop/continuation.rs:13` | `std::sync::mpsc` | git grep -n 'std::sync::mpsc' crates/carrick-runtime/src/vcpu_loop/continuation.rs returned only line 13. The import was used in tests of OwnerThreadE |
| `vcpu_loop/continuation.rs:15` | `Wake` | git grep -n 'Wake' crates/carrick-runtime/src/vcpu_loop/continuation.rs shows line 15 `use std::task::{Context, Poll, Wake, Waker};`. In continuation. |
| `vcpu_loop/continuation.rs:2403` | `retire_terminal_exact` | git grep -n 'retire_terminal_exact' crates/ returns only definition at continuation.rs:2403 and caller retire_terminal at line 3036, which had its onl |
| `vcpu_loop/continuation.rs:2989` | `event_outside_quiesce` | git grep -n 'event_outside_quiesce' crates/ returns only line 2989. git log -S 'event_outside_quiesce' shows its only caller was in suspend_hvpatch_co |
| `vcpu_loop/continuation.rs:3079` | `QuiesceEventAwaitState` | git grep -n 'QuiesceEventAwaitState' crates/ returns lines 3079, 3085, 3109 (used only by QuiesceEventFuture and next_quiesce_event in event_outside_q |
| `vcpu_loop/continuation.rs:3084` | `QuiesceEventFuture` | git grep -n 'QuiesceEventFuture' crates/ returns lines 3084, 3089, 3108, 3126, 3132 (constructed only by next_quiesce_event for event_outside_quiesce) |
| `vcpu_loop/continuation.rs:3105` | `next_quiesce_event` | git grep -n 'next_quiesce_event' crates/ returns only lines 3005 and 3105. Called only from event_outside_quiesce, which lost its caller in commit 807 |
| `vcpu_loop/continuation.rs:3680` | `VcpuAdmissionWait` | git grep -n 'VcpuAdmissionWait' crates/ returns lines 3680, 3687, 3776 (used only in VcpuAdmissionFuture inside await_vcpu_admission). No external cal |
| `vcpu_loop/continuation.rs:3686` | `VcpuAdmissionState` | git grep -n 'VcpuAdmissionState' crates/ returns lines 3686, 3696, 3775 (used only by VcpuAdmissionFuture inside await_vcpu_admission). No external ca |
| `vcpu_loop/continuation.rs:3691` | `VcpuAdmissionFuture` | git grep -n 'VcpuAdmissionFuture' crates/ returns lines 3691, 3699, 3748, 3770 (constructed only by await_vcpu_admission). No external callers exist. |
| `vcpu_loop/continuation.rs:3765` | `await_vcpu_admission` | git grep -n 'await_vcpu_admission' crates/ returns only continuation.rs:3765. Callers in suspend_hvpatch_continuation and terminate_siblings_for_exec  |
| `vcpu_loop/continuation.rs:3865` | `LogicalJobCompletionGuard` | git grep -n 'LogicalJobCompletionGuard' crates/ returns line 3865 and threads.rs:998. Line 998 is inside spawn_clone_thread, the retired welded loop's |
| `vcpu_loop/continuation.rs:3868` | `new` | git grep -n 'LogicalJobCompletionGuard::new' crates/ returns only threads.rs:998 inside unused spawn_clone_thread. |
| `vcpu_loop/continuation.rs:4973` | `enqueue_root` | git grep -n 'fn enqueue_root' crates/ shows definition in continuation.rs:4973 in tests module, but no tests in continuation.rs call it (tests in exec |
| `vcpu_loop/continuation.rs:7096` | `new` | git grep -n 'ManualGate' crates/ shows struct and impl at line 7089-7123 in continuation.rs tests module with zero callers after dedicated runner test |
| `vcpu_loop/exec.rs:101` | `Fresh` | git grep -n 'ExecveInput::Fresh' crates/ returns only line 1459 in unused handle_execve. The persistent path uses ExecveInput::Prepared via finish_pre |
| `vcpu_loop/exec.rs:1446` | `handle_execve` | git grep -n 'handle_execve' crates/ shows no production callers. Its caller in the welded loop (run_vcpu_until_exit_inner) was deleted in commit 80717 |
| `vcpu_loop/mod.rs:63` | `SHORT_TIMED_WAIT_RECLAIM_CUTOFF` | grep -rn '\bSHORT_TIMED_WAIT_RECLAIM_CUTOFF\b' --include='*.rs' crates/ returned mod.rs:63 (definition), mod.rs:108 (in should_reclaim_vcpu_for_timed_ |
| `vcpu_loop/mod.rs:84` | `ResumeCensusGuard` | grep -rn '\bResumeCensusGuard\b' --include='*.rs' crates/ returned mod.rs:84, mod.rs:86, and mod.rs:6381 inside resume_vcpu_after_blocking_wait. resum |
| `vcpu_loop/mod.rs:105` | `should_reclaim_vcpu_for_timed_wait` | grep -rn '\bshould_reclaim_vcpu_for_timed_wait\b' --include='*.rs' crates/ returned mod.rs:105, mod.rs:6365 (in park_vcpu_for_timed_wait), and unit te |
| `vcpu_loop/mod.rs:170` | `should_keep_vcpu_for_blocking_wait` | grep -rn '\bshould_keep_vcpu_for_blocking_wait\b' --include='*.rs' crates/ returned mod.rs:170, 6259 (in park_vcpu_for_blocking_wait_with_policy), and |
| `vcpu_loop/mod.rs:178` | `threaded_fd_wait_should_interrupt` | grep -rn '\bthreaded_fd_wait_should_interrupt\b' --include='*.rs' crates/ returned lines 178 and unit tests 10090-10092. git show 807174fa showed its  |
| `vcpu_loop/mod.rs:186` | `should_destroy_departing_vcpu` | grep -rn '\bshould_destroy_departing_vcpu\b' --include='*.rs' crates/ returned lines 186 and unit tests 9458-9460. git show 807174fa showed its caller |
| `vcpu_loop/mod.rs:359` | `mt_vm_lease_enabled` | grep -rn '\bmt_vm_lease_enabled\b' --include='*.rs' crates/ returned lines 359, 6269, 6425, 6465 (inside park_vcpu_for_blocking_wait_with_policy and r |
| `vcpu_loop/mod.rs:377` | `mt_vm_lease_fdbacked_release_enabled` | grep -rn '\bmt_vm_lease_fdbacked_release_enabled\b' --include='*.rs' crates/ returned lines 377 and 6322 (in try_release_vm_mt). Called only by the de |
| `vcpu_loop/mod.rs:647` | `upgrade_protection_si_code` | grep -rn '\bupgrade_protection_si_code\b' --include='*.rs' crates/ returned line 647 (an unused pub(crate) use signal::{..., upgrade_protection_si_cod |
| `vcpu_loop/mod.rs:841` | `need_resched` | grep -rn '\bneed_resched\b' --include='*.rs' crates/ showed line 841 (HvpatchRuntimeDirectory::need_resched) was called only by transitional_need_resc |
| `vcpu_loop/mod.rs:1110` | `is_closing` | grep -rn '\bclaim_process_exit\b' --include='*.rs' crates/ and grep -rn '\bis_closing\b' --include='*.rs' crates/ showed CloneAdmission::is_closing, i |
| `vcpu_loop/mod.rs:1486` | `transitional_need_resched` | grep -rn '\btransitional_need_resched\b' --include='*.rs' crates/ and grep -rn '\bclone_admission_cancelled\b' --include='*.rs' crates/ showed these K |
| `vcpu_loop/mod.rs:1722` | `BlockingWaitCompletion` | grep -rn '\bBlockingWaitCompletion\b' --include='*.rs' crates/ returned lines 1722 and threads.rs:488-855. Returned by synchronous futex wait methods  |
| `vcpu_loop/mod.rs:1727` | `SharedWordWaitCompletion` | grep -rn '\bSharedWordWaitCompletion\b' --include='*.rs' crates/ returned line 1727 and threads.rs:825. Returned by synchronous shared word wait in th |
| `vcpu_loop/mod.rs:1747` | `trace_hvpatch_wait_begin` | grep -rn '\btrace_hvpatch_wait_begin\b' --include='*.rs' crates/ returned line 1747 and threads.rs:514. Called by welded loop in-loop wait arms delete |
| `vcpu_loop/mod.rs:1773` | `trace_hvpatch_wait_end` | grep -rn '\btrace_hvpatch_wait_end\b' --include='*.rs' crates/ returned line 1773 and threads.rs:578. Called by welded loop in-loop wait arms deleted  |
| `vcpu_loop/mod.rs:1803` | `hvpatch_wait_result_phase` | grep -rn '\bhvpatch_wait_result_phase\b' --include='*.rs' crates/ returned line 1803 with zero callers. Welded loop wait arm callers deleted in 807174 |
| `vcpu_loop/mod.rs:1931` | `stamp_guest_tid` | grep -rn '\bstamp_guest_tid\b' --include='*.rs' crates/ showed line 1931 is an unchecked wrapper around stamp_guest_tid_checked (line 1940). Productio |
| `vcpu_loop/mod.rs:2194` | `BlockingWaitReclaim` | grep -rn '\bBlockingWaitReclaim\b' --include='*.rs' crates/ returned line 2194, 6223, 6364, 6375. Reclaim token for the retired 1:1 host-thread vCPU m |
| `vcpu_loop/mod.rs:2220` | `VcpuLeaseGuard` | grep -rn '\bVcpuLeaseGuard\b' --include='*.rs' crates/ returned line 2220 and threads.rs:1063 (in retired spawn_clone_thread). Unit tests in continuat |
| `vcpu_loop/mod.rs:5360` | `current_migratable_binding` | grep -rn '\bcurrent_migratable_binding\b' --include='*.rs' crates/ returned lines 5368, 5422. Methods in lines 5360-5550 implemented transitional/weld |
| `vcpu_loop/mod.rs:6765` | `service_threaded_syscall` | grep -rn '\bservice_threaded_syscall\b' --include='*.rs' crates/ and inspecting lines 6765-6955 in mod.rs. The loop { ... } inside service_threaded_sy |
| `vcpu_loop/mod.rs:7007` | `terminal_settlement` | grep -rn '\bVcpuLoopLaunch::Persistent\b' --include='*.rs' crates/ and viewing VcpuLoopLaunch::wait (lines 7176-7180). Field terminal_settlement on Vc |
| `vcpu_loop/mod.rs:7025` | `Host` | grep -rn '\bVcpuThreadHandle::Host\b' --include='*.rs' crates/ returned line 7025 and threads.rs:1384 (in retired spawn_clone_thread). Unit tests in c |
| `vcpu_loop/mod.rs:7051` | `diagnostic_name` | grep -rn '\bdiagnostic_name\b' --include='*.rs' crates/carrick-runtime/src/vcpu_loop/ returned line 7051 on VcpuThreadHandle and threads.rs:1553 insid |
| `vcpu_loop/mod.rs:7576` | `InitialRunnerStartState` | grep -rn '\bInitialRunnerStartState\b' --include='*.rs' crates/ returned lines 7576 and 7588. Unused helper struct for InitialRunnerStartGate, superse |
| `vcpu_loop/mod.rs:7581` | `InitialRunnerStartGate` | grep -rn '\bInitialRunnerStartGate\b' --include='*.rs' crates/ returned lines 7581 and 7585. Never constructed; persistent path uses context.thread(). |
| `vcpu_loop/mod.rs:7586` | `new` | grep -rn '\bInitialRunnerStartGate\b' --include='*.rs' crates/ returned lines 7581-7624. All methods on InitialRunnerStartGate (new, settle, open, can |
| `vcpu_loop/quiesce.rs:175` | `fork_barrier` | git grep -n 'fork_barrier' crates/ shows definition in quiesce.rs:175, re-export in mod.rs:636, and only call in park_if_fork_quiescing in ThreadRunti |
| `vcpu_loop/quiesce.rs:413` | `release_and_park_vcpu_for_fork` | git grep -n 'release_and_park_vcpu_for_fork' crates/ shows calls in threads.rs:698, 805, 1298 (inside complete_futex_wait_with_value, complete_shared_ |
| `vcpu_loop/signal.rs:35` | `signal_wait_remaining` | git grep -n 'signal_wait_remaining' crates/ returns only definition at line 35. git log -S 'signal_wait_remaining' shows callers in the welded loop's  |
| `vcpu_loop/threads.rs:8` | `SharedWordWaitRaw` | git grep -n 'SharedWordWaitRaw' crates/ shows usage only within unused complete_shared_futex_wait_raw and wrappers in threads.rs. Persistent executor  |
| `vcpu_loop/threads.rs:33` | `SharedWordWait` | git grep -n 'SharedWordWait' crates/ shows construction occurred only in the retired welded loop's SharedFutexWait/WaitOnSharedWord arms (deleted in 8 |
| `vcpu_loop/threads.rs:190` | `finish_compatibility_clone_failure` | git grep -n 'finish_compatibility_clone_failure' crates/ shows callers at line 279 (test) and lines 1340, 1358 in unused spawn_clone_thread. Persisten |
| `vcpu_loop/threads.rs:288` | `SiblingStartFailure` | git grep -n 'SiblingStartFailure' crates/ returns only lines 288, 1036, 1098, 1239, 1273, 1274 (all inside unused spawn_clone_thread). |
| `vcpu_loop/threads.rs:293` | `guest_host_thread_name` | git grep -n 'guest_host_thread_name' crates/ shows calls in line 973 (inside unused spawn_clone_thread) and unit tests at lines 384, 387. Persistent e |
| `vcpu_loop/threads.rs:300` | `has_dispatch_signal_for_futex_wait` | git grep -n 'has_dispatch_signal_for_futex_wait' crates/ returns lines 300, 336 (in futex_wait_is_interrupted), and tests at lines 418, 428. Persisten |
| `vcpu_loop/threads.rs:328` | `futex_wait_is_interrupted` | git grep -n 'futex_wait_is_interrupted' crates/ returns line 328, tests at lines 448-458, and callers in complete_futex_wait_with_value (line 562) and |
| `vcpu_loop/threads.rs:346` | `CLONE_CHILD_SLOT_WAIT_SLICE` | git grep -n 'CLONE_CHILD_SLOT_WAIT_SLICE' crates/ returns lines 346 and 1053 (inside unused spawn_clone_thread). Persistent executor handles clone adm |
| `vcpu_loop/threads.rs:348` | `acquire_vcpu_lease_while_live` | git grep -n 'acquire_vcpu_lease_while_live' crates/ returns line 348, test at line 397, and caller at line 608 in complete_futex_wait_with_value (reti |
| `vcpu_loop/threads.rs:482` | `complete_futex_wait` | git grep -n 'complete_futex_wait' crates/ shows definition on ThreadRuntimeState at line 482. In 807174fa^:crates/carrick-runtime/src/vcpu_loop/mod.rs |
| `vcpu_loop/threads.rs:1740` | `engine` | git grep -n 'terminate_siblings_for_exec' crates/ shows definition in threads.rs:1740. git show f2731ae1 shows engine was used in terminate_siblings_f |

## Worker method notes

**res-g1.json** — Every assigned dead_code symbol in crates/carrick-runtime/src/vcpu_loop/mod.rs was analyzed against codebase references using ripgrep (`grep_search`), git log revision history (`git log -S`), and diff inspection of recent collapse commits (807174fa2 'refactor(runtime): delete the welded-thread vcpu loop, port guest fault delivery' and f2731ae13 'refactor(runtime): delete the transitional dedicated runner pool'). Each uncalled symbol was compared against the surviving persistent executor path (launch_persistent_hvpatch_job -> ProductionHvpatchLoopJob::poll_with_engine -> service_outcome -> finalize_persistent_process_terminal) to differentiate retired execution mechanisms (CORPSE) from orphaned capabilities implementing guest-visible semantics or DTrace instrumentation (LIVE_RESPONSIBILITY) such as guest task blocked state publication for /proc, core dump ELF generation / WCOREDUMP wait s

**res-g2.json** — Used git log, git show, git grep, and ripgrep to inspect the history of Carrick's recent collapse commits (807174fa, f2731ae1, 202237b7, 633d32a3) and trace all 32 assigned group 2 symbols across the workspace. We verified callers across both the retired execution models (the welded per-thread vCPU loop, dedicated runner pool, and compatibility thread waiters) and the surviving persistent executor path (ProductionHvpatchLoopJob::poll_with_engine, service_outcome, finalize_persistent_process_terminal). We identified one critical LIVE_RESPONSIBILITY: complete_signal_thread (and the handling of DispatchOutcome::SignalThread), which was previously serviced in the welded loop and is currently unhandled in ProductionHvpatchLoopJob::service_outcome, causing tgkill/tkill/pthread_kill targeting sibling threads to hit the unlowered outcome error arm. The remaining 31 symbols are CORPSE artifacts l

**res-g3.json** — Systematic codebase search using ripgrep and git log/diff history tracing across recent execution model collapse commits (202237b75, 807174fa2, f2731ae13). For every dead_code symbol, checked active callers, test callers, historical callers in the deleted welded vCPU loop / runner pool / legacy 1:1 host-process model, and whether the underlying guest-visible capability (ELF core dump generation & WCOREDUMP, crash register capture quorum, host signal pump activation, POSIX job-control SIGSTOP/SIGCONT task suspension, TLB invalidation & ASID retirement, scheduler lease transitions) survived or was ported into the persistent executor path (ProductionHvpatchLoopJob::poll_with_engine, service_outcome, finalize_persistent_process_terminal).
