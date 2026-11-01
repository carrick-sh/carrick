# Native forwarded continuation signal return (#1090)

`kernel.el1.signal-delivery-owner` covers native handler selection and
`SA_RESTART` at an interrupted forwarded syscall's return. The Linux authorities
are [signal(7)](https://man7.org/linux/man-pages/man7/signal.7.html) and
[sigaction(2)](https://man7.org/linux/man-pages/man2/sigaction.2.html).

Native-owned signals remain queued in the native owner. `SignalReadinessProbe`
wakes their host continuations with `Signal`, without dequeuing a carrier
`ReservedSignal`. The native return checkpoint selects the action and publishes
the handler frame through the same shared owner on both ISAs.

CPL0 carries the original saved RAX and continuation restart eligibility in the
exact thread control allocation when completion returns errno 4. The checkpoint
consumes that witness once, even without a handler. Only ISA mechanics restore
RAX and rewind the syscall instruction. ARM retains its existing authenticated
saved-frame FAR/ESR transport; live EL1 X0 does not name the interrupted user
argument. No host redispatch may precede native handler selection.

The work bound is constant: two atomic payload/state stores at publication,
one bounded read/clear at consumption, and no queue rescan, polling, or extra
host object. Partial progress publishes no restart witness. Rebirth clears the
witness so an old execution cannot rewind a successor's syscall.

The VM-free frame bindings decode both real signal codecs for restart,
nonrestart and restart-ineligible cases. X86 bindings also cover empty, ignored,
blocked-then-unblocked and default-fatal checkpoints and consumption exactly
once. These prove shared frame publication, not guest handler execution or the
host continuation's production capture/publication boundary.

The issue's historical `route_cpl0_resume_effects` carrier-reservation refusal
remains unchanged. Transferring that reservation into a native selector would
require preserving its exact action, job-control generation, masks and selection
side effects; merely requeueing it would introduce a second selection. The
normal native CPL0 path does not produce such reservations. The literal
reservation-transfer acceptance and a two-live-thread KVM/HVF continuation
witness remain open, and this slice must not be reported as closing #1090.
