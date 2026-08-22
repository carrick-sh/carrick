# Job control and guest run state: the port plan

**Status: POSIX job control does not work under HVPatch. A guest that receives
`SIGSTOP` is MARKED stopped and reported as stopped to `wait4`, but it never
actually stops running.**

Verified against the tree:

- `stop_task_for_job_control` IS called, from `vcpu_loop/mod.rs:7010`, so the
  kernel graph records the stop.
- `wait_child_with_job_control` IS called, from `dispatch/proc.rs:2981,3380,3386`,
  so `wait4(WUNTRACED)`/`WCONTINUED` encode the right status bits.
- `wait_until_job_control_resumed` — the only thing that would PARK the stopped
  thread — has exactly one caller, `hvpatch/mod.rs:491`, and that caller is
  itself the method clippy reports as never used. Its real caller lived in the
  welded vCPU loop and died in `807174fa2`.

So the middle link of the chain is missing. The observable result is a guest
that reports itself stopped while continuing to execute, which is worse than an
unimplemented feature: `wait4` tells the parent something false.

## The chain, and which links exist

1. Guest sends `SIGSTOP`/`SIGTSTP`/`SIGTTIN`/`SIGTTOU` — **works**
   (`stop_task_for_job_control`, `vcpu_loop/mod.rs:7010`).
2. The target task stops running — **MISSING**. This is the port.
3. `wait4`/`waitid` with `WUNTRACED`/`WSTOPPED` reports `(signum << 8) | 0x7f` —
   **works**.
4. `SIGCONT` resumes and `WCONTINUED` reports `0xffff` — depends on 2.
5. `/proc/[pid]/stat` shows `T` while stopped — **see `GuestBlockedGuard` below**.

## Per-symbol disposition

| symbol | file:line | disposition | note |
|---|---|---|---|
| `wait_until_job_control_resumed` | `kernel/objects.rs:3592` | **PORT** | crates/carrick-runtime/src/vcpu_loop/mod.rs in ProductionHvpatchLoopJob::poll_with_engine around line 4485 (before engine.next_syscall(), after checki |
| `wait_until_job_control_resumed` | `hvpatch/mod.rs:484` | **PORT** | crates/carrick-runtime/src/vcpu_loop/mod.rs in ProductionHvpatchLoopJob::poll_with_engine around line 4485 via self.kernel.hvpatch_process.as_ref().un |
| `syscall_trace_identity` | `hvpatch/mod.rs:571` | **PORT** | crates/carrick-runtime/src/vcpu_loop/mod.rs in poll_with_engine around line 4734 (or service_threaded_syscall at line 5855) to instantiate HvpatchSysc |
| `record_process_exit_commit` | `hvpatch/mod.rs:798` | **DELETE** | N/A |
| `retire_address_space_with` | `hvpatch/mod.rs:840` | **DELETE** | N/A |
| `GuestBlockedGuard` | `vcpu_loop/mod.rs:125` | **PORT** | crates/carrick-runtime/src/vcpu_loop/mod.rs around line 3825 (service_outcome on blocking dispatch outcome) and continuation::persistent_block_exit /  |
| `publish` | `vcpu_loop/mod.rs:132` | **PORT** | crates/carrick-runtime/src/vcpu_loop/continuation.rs and vcpu_loop/mod.rs at continuation block and resume boundaries. |

Two of these are genuine corpses with named replacements —
`record_process_exit_commit` (redundant with the terminal's own lifecycle probe)
and `retire_address_space_with` (redundant with the persistent retirement path).
Delete those rather than porting them.

`GuestBlockedGuard` is a separate question from job control but the same shape:
it published a task's run state (`'S'` blocked / `'R'` running) into the
process-wide arena for `/proc/[pid]/stat` and `/proc/[pid]/status`. With no
publisher, a blocked task reports `'R'` forever. LTP's
`TST_PROCESS_STATE_WAIT` polls exactly that field, so this silently breaks any
case that waits for a child to reach `'S'`.

## Ordering hazards

- Stop publication vs. condvar wait: stop_task_for_job_control sets stopped_by and notifies the parent before the child reaches wait_until_job_control_resumed. If the parent consumes WUNTRACED and immediately sends SIGCONT before the child reaches wait_until_job_control_resumed, SIGCONT clears stopped_by and signals the condvar. The child's wait_until_job_control_resumed must check stopped_by.is_some() in a while loop so it does not block on a past condition that was already cleared.
- Lock-free parking: wait_until_job_control_resumed must NOT be invoked while holding any dispatcher subsystem locks (proc lock, memory lock, fd table lock, or stage-1 page-table pause). Parking with a lock held deadlocks any peer or parent calling wait4, kill, or /proc reads.
- vCPU lease exhaustion: A stopped task must release its execution lease while waiting for SIGCONT; otherwise, stopped background processes in a session will starve active processes of vCPU leases in the bounded carrier pool.
- Resume signal priority: After waking from wait_until_job_control_resumed, pending signals (such as PTRACE_KILL or injected fatal signals) must be evaluated and serviced before executing guest instructions, guaranteeing that fatal terminations win races against guest syscalls.
- GuestBlockedGuard Drop timing: Blocked state ('S') must be published before entering a blocking continuation and restored to Running ('R') in Drop or upon continuation resumption. If 'S' is not restored upon resumption, running processes report 'S'; if 'S' is never published during continuations (as currently occurs), LTP TST_PROCESS_STATE_WAIT hangs indefinitely.

## Open questions the analysis raised — these are real design choices

- Whether wait_until_job_control_resumed on the persistent executor should be a synchronous condvar park in poll_with_engine (matching the welded loop) or a first-class asynchronous HvpatchLoopSuspension / HvpatchProductionPhase variant that yields the carrier worker and releases the vCPU lease back to the executor pool.
- Whether multi-threaded guest tasks with multiple logical threads require an explicit broadcast kick/quiesce mechanism to ensure all sibling threads park when one thread handles a process-directed stop signal.
- Whether /proc/[pid]/stat should dynamically query Task.job_control.stopped_by in synthetic_proc_processes (dispatch/mod.rs:7291) to render 'T' when stopped, rather than relying exclusively on run_state::published_stat_char.

## Provenance

Produced by a read-only Antigravity worker directed for this purpose, then
checked. The decisive claims — that `stop_task_for_job_control` and
`wait_child_with_job_control` have live callers while
`wait_until_job_control_resumed` does not — were verified by grep before this
document was written.

Unlike the core-dump analysis, this one returned real open questions, and they
are the right ones: whether the park should be a synchronous condvar wait or a
first-class `HvpatchLoopSuspension`, and whether sibling threads need an
explicit broadcast to park on a process-directed stop. Decide those before
writing code; the second one is the difference between a working stop and a
half-stopped thread group.

Done means a probe passes, not that it compiles. Find or write one that stops a
child, checks `wait4(WUNTRACED)`, resumes it with `SIGCONT`, and verifies the
child made no progress in between — the last part is what distinguishes this
port from what the code already claims to do.
