# Fork-child group exit with live members (#2282)

The existing `kernel.el1.thread-lifecycle` contract owns this change. Linux
`exit_group(2)` terminates every thread in the calling process, and `wait4(2)`
publishes the child's selected exit status only after group retirement.

Closing already snapshots exact controls, publishes terminal requests, cancels
retained services, and retains the caller until all member receipts settle.
The missing progress edges were plain futex interruption and running-member
retirement. A service cancellation alone does not wake a plain futex park.
A running sibling does not own the closing caller's continuation, so its next
syscall previously bypassed lifecycle resumption.
Closing can also race a worker between futex enrollment and park publication.
The existing bucket-held final interruption check now sees the terminal request,
so this interval cannot lose the close wake.

`NativeProcessEntry::begin_closing` now uses the same member interruption owner
as signal arrival, without enqueueing a signal. That owner cancels a retained
service, interrupts a single-entry futex wait, or requests rescheduling of the
CPU holding the exact record. The syscall and interrupted user-return
checkpoints enter the existing `resume_pending_lifecycle` /
`retire_closing_member` transaction. Before the member receipt becomes
observable, the neutral owner requires `vacate_terminal_space`: each ISA moves
to its maintenance translation and releases installed-space occupancy. This
orders the physical detachment before the group owner may retire the root,
including when the sibling's next boundary owes host work. The same ordering
applies to a raw exit racing group close. ISA-specific code supplies only the
existing translation, wake/kick and register mechanics.

The KVM `cpl0_group_exit` binding forks a child with two live members. Its worker
waits on a private futex, repeatedly calls `sched_yield`, or computes without
syscalls. The child leader calls `exit_group(5)`; the original parent must reap
exactly status 5. Each run is bounded externally at 60 seconds. This bound is a
failure detector, not an operational budget increase. Closing visits the
bounded member snapshot once and issues one interrupt per member; it introduces
no polling, retries, host readiness object, or serialization of unrelated work.

The fixtures use only raw Linux ABI instructions and Carrick's existing
production KVM pool. Native x86 execution is a fixture sanity check; it does
not replace the project's native-arm64 Docker authority or signed ARM gate.
The parked-fault witness remains with #2263 until that work lands. Its COW
pause and retry implementation is outside this change.

The ARM EL0 return binding also drives the production venue and no-signal
gate. A host-loaded member whose entry venue becomes Host after closure, and
a member holding a native-owned record, both owe the terminal checkpoint;
neither may return an interrupted futex result to user space. The losing
exit-group binding holds a host retirement reservation across a second
member's close. HostCustody must retain its installed translation and live
record; exact release vacates translation before publishing the retirement
receipt. These are structural invariants as well as the parent's wait4 status
claim.
