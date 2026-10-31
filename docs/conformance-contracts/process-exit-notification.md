# Native reparented exit notification (`kernel.process.exit-notification`)

Surface: delayed SIGCHLD and wait-channel publication after native child MM
retirement. Linux authority: [exit(2)](https://man7.org/linux/man-pages/man2/exit.2.html),
[PR_SET_CHILD_SUBREAPER(2)](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)
and wait(2): orphaned children are adopted
by the nearest live subreaper or init, which receives their termination signal
and can reap their status. A concurrently exiting parent is not a run failure.

The real `NativeProcessRuntime` binding
`delayed_child_exit_notifies_adopter_when_selected_parent_exits_on_peer`
forks R -> P -> C, parks R in wait4, and runs P and C on distinct compact
scheduler slots. A test-only boundary after MM retirement releases P
on a peer host thread through actual exit_group before C reacquires graph
custody. The witness checks the reparented receipt, no run failure, C's SIGCHLD
siginfo at R, no notification or channel publication to departed P, one wake
of R's enrolled waiter, and both terminal statuses through real wait4.
The companion bindings
`delayed_child_exit_uses_adopter_interest_when_old_parent_ignored_default` and
`delayed_child_exit_does_not_inherit_departed_parents_signal_interest` require
the current adopter's signal policy, even when it differs from P's.

These witnesses are registered as VM-free bindings of
`kernel.el1.signal-delivery-owner` (all three), `core.entry.completion`,
`process.native.terminal-child` and the supplemental
`process.native.short-lock` list (the peer witness), and as
the process-exit interleave note of `kernel.el1.thread-lifecycle`. Two
owner-level bindings in `process_owner_tests.rs` cover the same
pending-retirement reparent window for `kernel.wait.process-group`
(`pending_reparented_zombie_keeps_process_group_until_adopter_reaps`) and
`kernel.wait.child-rusage`
(`pending_reparented_child_charges_adopter_once_and_never_departed_parent`).
The native runtime records no per-task CPU, so the rusage binding proves the
shared charge ledger, not native CPU measurement.

Structural budget: exactly one final notification publication per exit, no
retry or unrelated-task scan, exact TaskKey generation selection, and zero
stale-parent-to-run-failure transitions. Current recipient selection, signal
publication and wake-channel capture form one graph projection; wake execution
runs outside graph custody. Signed HVF and Docker evidence require their
respective hosts; this Linux worker binding does not claim either.
