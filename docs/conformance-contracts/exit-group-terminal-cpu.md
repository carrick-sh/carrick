# exit_group terminal CPU custody (#1666)

`kernel.el1.thread-lifecycle` requires exit_group to retire every sibling
without corrupting the terminating owner's continuation. Linux authority is
exit_group(2); the Carrick invariant is that a task snapshot retains the
current MM's complete translation root and ASID, even while host teardown
waits for another member or a physical owner.

The director's capture named TTBR0/TTBR1 `0x2d001f8000`, the carrier
maintenance root, under a process projection with ASID 1. The raw saved-state
writer is `aarch64_task_state_from_snapshot` in `carrick-aarch64/src/engine.rs`:
it copies the hardware TTBR pair. The lazy path reaches it through
`Aarch64ResidentTaskMetadata::snapshot_guest_cpu` and the runtime executor's
`flush_resident_task`. That is correct only while hardware still represents
the saved task. EL1's `sched::vacate::leave_space` installs the maintenance
root before releasing the slot. Native root exit bypasses ordinary zone
reconciliation; the process terminal then suspends for host teardown, including
an unconditional yield when its sibling drain is already ready. Saving that
terminal as Resident lets the later flush sample the maintenance root. A same
executor reload is also unsafe: reaffirmation does not restore translation.

The process terminal now explicitly requests a nonresident save. The binding
checks the captured MM and strong ASID generation, then obtains both TTBRs
from its current Stage1MmLease. The executor stores Materialized state and
replaces the lease's CPU image before detaching. Both hardware roots are
vacated with the existing terminal-root helper before publishing detached
state: there is no resident record left to perform that retirement later.
It cannot use the resident reaffirmation path. Metadata extraction failure
preserves that canonical image. Ordinary guest snapshots and both existing load audits are unchanged.
Exec drains keep their separate successor path.

The VM-free witness parks the live leader, runs a second real kernel thread,
and dispatches exit_group(23) through ProductionHvpatchLoopPoll. Its test
backend supplies the captured maintenance-root state; it does not emulate
EL1 instruction execution or independently reproduce when EL1 vacates roots.
The executor's shared save selector must produce Materialized state, and the
production binding load audit must accept the exact process root and ASID.
A stale generation must still fail. The structural bound is one full snapshot
per terminal suspension; normal guest quanta request no additional snapshot.

Red evidence on admitted main with the witness scaffolding: the load audit
rejected `0x2d001f8000/0x2d001f8000`, expecting `0x1000000004000`.
The fixed witness passes. The director still owns the native failure capture and ten signed
passes on one artifact, including the original el1_files exit-group stress
binding; neither is verified here. This VM-free reduction does not claim those signed results, Docker
timing, or a runtime ratio.

The fix-round signed witnesses in `carrick-embed::el1_files` now drive the
actual `HvpatchPersistentExecutor::save` with the existing exit-group guest
fixture. A test-support-only probe seeds both stopped hardware roots with the
still-owned process root, so an already-vacated EL1 root cannot conceal a
missing cleanup write. It reads both roots immediately before backend
publication. The failure row injects the second register-write refusal after
the first real hardware write, then checks that the original binding again
owns its detached backend and the failing executor retains its vCPU. No
replacement executor, synthetic MM or hand-built terminal record is used.
The old source-text ordering test is removed.

These new signed witnesses have not run on this Linux worker. Their red-first
mutation check (omit the cleanup call, and separately omit backend publication
on failure) and green signed runs remain required on the Mac. Part of #1666;
keep the PR draft until the failure capture and ten passes on one artifact
are attached. The VM-free selector witness remains only a lower-layer proof.


## carrick-87 investigation remains incomplete

The forwarded host-syscall witness above is not a reduction of the native
EL1 process-entry path. A temporary diagnostic using the existing
`vcpu_loop::zone::affinity_tests::with_pair` native graph exercised two live
threads: `exit_group(23)` parked the owner, requested the sibling's exit,
and the production `El1Exit::seal` vacated the slot to both maintenance roots.
Host materialization preserved a supplied process TTBR pair and rewound the
retained native syscall. That diagnostic passed without a new runtime fix.

It supplied the canonical base explicitly and bypassed production zone
reconciliation and executor save. It therefore could not establish the bad
save or satisfy the required red-on-head witness, and was not retained as a
regression test. The existing terminal-save changes remain unqualified
against the continuing signed failure. No additional runtime fix or root
cause is claimed by this investigation.

One candidate is `RetryThreadExit`, which is absent from
`HvpatchProductionPhase::needs_terminal_cpu_save`. Native cancellation can
enter `drive_thread_exit` before phase dispatch, and Busy retirement parks
that phase. However, no schedule has shown that Busy transition with
maintenance-root hardware under this native close. It is a hypothesis, not
a reason to change the selector. The next witness must drive the native
close through production reconciliation and save, retaining the sibling's
actual base and MM/ASID identity, rather than supplying canonical registers.
The director's named fatal/call-site capture and ten signed passes on one
artifact remain outstanding.
