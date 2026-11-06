# exit_group terminal CPU custody (#1666)

`kernel.el1.thread-lifecycle` requires `exit_group` to retire every sibling
without corrupting a terminating task's continuation. Linux authority is
`exit_group(2)`; the Carrick invariant is that a task snapshot retains the
current MM's complete translation root and ASID, even while host teardown
waits for another member, a task-graph reservation, or a physical owner.

## Mechanism

The raw saved-state writer `aarch64_task_state_from_snapshot` in
`carrick-aarch64/src/engine.rs` copies the hardware TTBR pair, reached lazily
through `Aarch64ResidentTaskMetadata::snapshot_guest_cpu` and
`flush_resident_task`. That lazy path is valid only while hardware still
represents the saved task. EL1's `sched::vacate::leave_space` installs the
carrier maintenance root (`0x2d001f8000`) and clears the slot's installed
space (`0`) before releasing the slot. When a process terminal or cancelled
sibling suspends on the host after EL1 has vacated hardware roots, saving it
as `Resident` lets a later flush sample `0x2d001f8000/0x2d001f8000`, and a
same-executor resident reaffirmation does not restore process translation.

1. **Terminal CPU materialization and hardware-root cleanup.** Host-only
   termination suspensions in `HvpatchProductionPhase::needs_terminal_cpu_save`
   (`TerminalProcessDrain`, `TerminalClaimRetry`, `TerminalRetireRetry`,
   `RetainedMemoryAction::{ProcessFinish, ThreadExit}` waits/retries, and
   `RetryThreadExit`) explicitly request `TaskCpuSave::Terminal`. The binding
   verifies the captured MM and strong `AsidGeneration`, then composes both
   TTBRs from its live `Stage1MmLease`. `HvpatchPersistentExecutor::save`
   stores `Materialized` state, updates the lease's CPU image, and vacates
   both stopped worker hardware roots via `retire_terminal_resident_vcpu_root`
   before publishing the detached backend; if a hardware root write fails, the
   binding retains its detached backend and the worker retains its vCPU.
   Member thread-exit phases (`RetainedMemoryAction::ThreadExit` and
   `RetryThreadExit`) remain `false` in `is_terminal_transition` so a peer's
   process or exec drain can still overtake and settle them as losing members.
   Ordinary guest snapshots, load audits, and exec successor drains are
   unchanged, and terminal suspension takes one full snapshot.
2. **Vacated EL1 zone-slot authentication.** Because terminal materialization
   and native cancellation (`El1Exit::seal` -> `leave_space`) vacate the zone
   slot to maintenance space zero, `owns_installed_space` /
   `own_space_installed` (`carrick-runtime/src/vcpu_loop/zone.rs`) accepts
   `installed == 0` when the local continuation is in
   `is_terminal_transition()` or the loaded thread's exact `ThreadControlSlot`
   has `host_exit_requested()`, while rejecting ordinary runnable
   maintenance-space returns and every foreign nonzero process space.

## Witnesses

- **VM-free (`carrick-runtime`):**
  - `vcpu_loop::binding::tests::sibling_exit_group_terminal_save_keeps_process_translation`
    parks the leader, dispatches `exit_group(23)` on a live sibling through
    `ProductionHvpatchLoopJob::poll` over maintenance-root hardware, and
    verifies `Materialized` state, exact process TTBR/ASID load validation,
    stale-generation rejection, and one snapshot per terminal suspension (red
    before the fix: rejected `0x2d001f8000/0x2d001f8000`, expected
    `0x1000000004000`).
  - `vcpu_loop::binding::tests::retry_thread_exit_terminal_save_keeps_process_translation`
    and `retry_thread_exit_remains_non_terminal_transition_for_peer_drain`
    cancel a live sibling under native `Closing` while an exclusive
    `reserve_fork` task reservation forces `TaskBusy` -> `RetryThreadExit`
    before `process_exiting()` is published, verifying terminal TTBR
    materialization, `ThreadDone` completion once the reservation drops, and
    non-terminal losing-member settlement under peer drains (red before
    including `RetryThreadExit`: rejected `0x2d001f8000/0x2d001f8000`,
    expected `0x1000000004000`).
  - `vcpu_loop::zone::terminal_space_tests::sibling_owned_terminal_accepts_its_vacated_zone_slot`
    verifies vacated-slot (`0`) acceptance under `host_exit_requested()` and
    rejection of foreign nonzero spaces and unrequested maintenance returns.
- **Signed HVF (`carrick-embed::el1_files`):**
  - `native_sibling_exit_group_reloads_process_roots` and
    `native_exit_group_save_diagnostic` exercise native EL1 `leave_space`,
    sibling cancellation, and production process-root reload on HVF without
    synthetic register images.
  - `terminal_save_vacates_both_roots_before_publication` and
    `terminal_save_second_root_write_failure_retains_ownership` drive
    `HvpatchPersistentExecutor::save` on the `exit-group-stress` guest,
    verifying both hardware roots are vacated before detached backend
    publication and that a second-root write failure retains detached backend
    and worker vCPU ownership.
