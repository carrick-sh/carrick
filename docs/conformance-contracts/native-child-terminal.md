# Terminal native child (`process.native.terminal-child`)

A carrier service wake preserves the distinction between a completed syscall
and a parked operation. The VM-free `carrier_work_*redrives_parked_wait4*`
witnesses park a blocking parent wait4, exit the child, then interpose a real
CarrierWork ticket before the parent resumes. Both supplied and cancelled
ACKs must re-drive the retained wait owner, copy status once, return the child
PID and refuse a second reap with ECHILD (10). Readiness alone is never a
completed wait result. Completed syscall results remain retained separately.

Plain process wait/IPC parks also publish `OwnerContinuation(Syscall)` on the
scheduler record. Host materialization preserves arguments and re-enters the
saved instruction; fresh dispatch consumes the retained operation before
invoking a new syscall. `blocking_wait4_reenters_its_owner_after_host_materialization`
binds the parked disposition to that fresh-entry owner and exact status copy.
A closing participant still follows its terminal owner rather than wait/IPC.

Linux authority is exit(2)/wait(2): release the child's resources before
notification, retain the parent's wait, and consume its terminal status once.
The VM-free ARM production service witness
`arm_terminal_child_retirement_and_parent_handback_once` was red on main:
the child became reapable while ARM `retire_mm` performed zero retirements.
Its parked-parent case also requires the runtime handback venue when no guest
slot can place the parent. It asserts one accepted retirement and one host
handback, resumes the original wait with the child's status, and refuses a
second reap with -10/ECHILD.

The shared entry transition retains the exact task, execution generation, MM
and thread generation in CPU-slot terminal custody before the freed record can
be reused. A new slot entry invalidates that custody.
`terminal_retirement_cannot_retire_a_reused_record_or_slot_generation` proves
record reuse preserves the released authority, while a stale generation cannot
retire the new slot execution: four stale controls each differ from the
retained custody in exactly one of task, execution generation, MM and thread
generation, so dropping any one comparison admits a stale retirement. It also
refuses completion authority while
that CPU still has the child's MM installed; the host additionally validates
the hardware maintenance root before a parent handback.
`unplaceable_parent_host_handback_consumes_one_park`
asserts one host wake, no remaining queue entry, and zero duplicate handbacks.
Authentication reads one exact CPU-slot authority and one committed child root;
there is no population scan, polling, syscall redispatch, or timeout change.

The ARM physical crossing checks the retained committed root incarnation and
live hardware root before accepting the existing child-retirement wire record.
Physical table stock stays quarantined; its reclamation belongs to the next
stock slice. The zone ABI signature changes with the retained custody storage,
so signed verification needs fixtures admitted against the new input identity.
VM-free Linux tests do not prove the ARM HVC, hardware root switch, full process
adoption, or native ARM runtime ratio. Those gates remain director-owned.
