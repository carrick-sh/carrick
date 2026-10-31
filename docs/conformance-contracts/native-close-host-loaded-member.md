# Native close with a host-loaded member (`kernel.el1.thread-lifecycle`)

A native process close publishes cancellation for every exact outstanding
member before publishing its exit wait. A host-loaded member can have no live
zone record after its admission home was released; record cancellation alone
cannot reach an EL0 compute loop. The host applies the owner's requests with
scheduler control wakes before settling the exit owner's zone wait. It scans
the process members once per exact retained lifecycle page and delivers at
most one control wake per member, including a loaded member whose own boundary
observes the close. Late host adoption retains the cancellation request.

`arm_two_live_threads_exit_group_ends_group_with_status` exercises the ARM
native owner with two live threads and requires a host cancellation request
after the adopted sibling's zone record is released. It was red before this
fix. `native_terminal_request_kicks_loaded_member_without_zone_record_once`
separately exercises the production host adapter and exact scheduler binding:
no close means no wake, close delivers one kick, repeated observation delivers
none. It does not claim to execute the HVF kick or the whole exit receipt path.
`arm_signal_setup_then_timed_futex_keeps_its_deadline` is a passing timer
control on the signal stack, requiring an in-guest timeout after native signal
setup. The signed `el1_files_kick_delivery_spin_loop` census's untimed park
was the native exit receipt wait, not the preceding 50 ms sleep. Signed
`el1_sched_timed_wait_times_out_in_guest` remains required alongside it.

Closing requests retirement of live members; only their host withdrawal can
return the exact receipts it owes. It must preserve their zone records until
the host control wake and its deferred vCPU/producer handback complete.
`Handback::Cancelled` retires a plain futex record without a handback, so it
belongs after logical withdrawal, never to the pre-settlement wake request.
The VM-free
`serial_host_arm_exit_group_preserves_deferred_control_handback` binds ARM
dispatch to three real Kernel threads and their Scheduler continuations. A
host-parked sibling and a sibling switched in from a zone wait must both reach
host withdrawal before the third thread completes exit with status 42. Its
bounded missing-handback check was red with the switched-in sibling still
Blocked and its record gone. No timeout, retry or polling supplies progress.

An uninitialized EL1 birth also owns first-entry activation capacity. The same
one-shot host batch claims its exact record for Control and publishes immediate
handbacks through the existing first-entry route; an active vCPU or producer
owns deferred handbacks. The VM-free
`serial_host_native_terminal_wake_routes_uninitialized_parked_member` binds a
real ledger birth to that runtime batch and the service record offered to its
first-entry executor. It was red when the batch skipped uninitialized threads.
Work remains one process-member scan per retained page and at most one control
request per member. Signed parked-thread exit and first-entry execution remain
required director gates.
