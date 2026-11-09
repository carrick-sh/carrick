# Anonymous edit release from a peer CPU (#1898)

`kernel.el1.anonymous-reservations` requires internal contention to retain
and resume the exact mmap operation. The KVM binding
`production_anonymous_release_to_idle_peer_preserves_wake` orders the
synthetic editor-holder release on CPU1 after CPU0 has published its real
anonymous wait. It uses the production pool, scheduler, notification and
native resume checkpoint, with one park, no handback or host forward, and
exit status 7. The existing fixture watchdog bounds the actor coordination.

On main d3fc09759, port 0xcc at guest RIP 0xffffffff800d05ac resolves to
`release_injected_edit_wait`'s local-queue assertion. The test-only holder
could be released by either physical CPU's scheduler. A wake placed on
CPU0's queue leaves CPU1's queue empty, which is valid. Discarding the wake
effects also loses the required reschedule IPI.

A first correction exposed an earlier edge in the same hook: CPU1 can
consume the synthetic Busy before CPU0 publishes its wait (2/60 runs returned
fixture exit 9). A test-image publication latch now admits the holder release
only after `EditWaitOutcome::Parked`. It orders the synthetic actor; it does
not delay or serialize production execution.

The correction reuses `native_process::release`, which already delivers the
shared scheduler's owned notification effects through
`carrick_el1::sched::object_wait::deliver_host_completion`. No queue, lock,
notification owner or physical doorbell policy is added. The fatal port
remains fatal. Only the injection-enabled x86 test image changes; the
feature-free CPL0 artifact and ARM/HVF have no synthetic release hook.
ARM already uses the shared effect delivery; there is no parallel ARM
handshake to change or new ARM semantic claim.

This binding changes no work budget: one enrollment and release resume the
same operation. The production runtime protocol and signed acceptance remain
unchanged. Paired KVM populations supply the runtime evidence for this
fixture defect; no signed or Docker performance claim is made.
