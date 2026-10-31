# Native short-lock contention (`process.native.short-lock`)

Surface: wait4, signal waits, SysV IPC enrollment, committed exit and record
retirement in the CPL0/EL1 process runtime. Linux authority: wait(2),
msgrcv(2), semop(2), exit(2); internal scheduler lock contention is not a
guest admission error. In particular wait4 has no EAGAIN result.

VM-free bindings: `pending_default_stop_does_not_interrupt_wait4`,
`bucket_contention_msgrcv`, `bucket_contention_semtimedop`,
`child_exit_retains_wake_custody_across_parent_bucket_contention` and
`child_signal_exit_retains_wake_custody_across_parent_bucket_contention`.
The fixture holds all 1024 buckets until the wait-policy probe observes the
old refusal threshold. No sleep, load generator or wall-clock deadline
decides lock release. A completion guard also releases on the red refusal
or assertion unwinding.

The structural invariant is zero contention-to-errno or contention-to-run-
failure transitions and one enrollment/retirement per operation. The tests
retain the owned handoff, queue registration, terminal status and wake
assertions; the probe measures contention, not a runtime ratio. Native KVM
mounted wait/IPC fixtures are the CPU execution bindings; the #231 owner
decision requires their receipt from the merge queue. No local KVM result
is claimed. Signed HVF and Docker ratio evidence require their respective
hosts and remain outstanding here.
