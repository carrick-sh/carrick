# In-ring signal handler admission

`signal.handler.admission` owns handler masks, reset disposition, alternate
stack selection and failed-frame escalation. Authority: sigaction(2) and
sigaltstack(2). Native/KVM witnesses check nested delivery with SA_NODEFER
clear, SA_RESETHAND publication, DF clearing/restoration, a SIGSEGV handler
on the retained alternate stack after stack overflow, and default SIGSEGV
when handler frame construction fails. The first four admission witnesses
failed before correction; the VM-free reset-action contract failed before
the action was committed at selection.

Action selection and reset share the sighand lock. Frame publication saves
the old mask and stack before applying the handler mask. Stack selection is
constant work; failure admits at most one forced SIGSEGV frame, whose own
failure terminates the task. No allocation, sleep or polling is introduced
in successful frame construction. Signed ARM acceptance remains outstanding.

## Owned in-ring signal waits

`signal_wait_owns_context_and_shared_deadline` checks that a finite signal
wait retains its saved context, releases its executor and completes only
when the shared timer reaches its deadline. The mounted native/KVM
`sigsuspend` and `sigtimedwait` witnesses retain three fork/reap iterations;
they must not be shortened to hide fork-stock exhaustion. Their second fork
currently depends on the separately owned shared child-MM retirement work.
The signal-free `x86_fork_stock_reuse.S` reduction records this dependency.

The current single-owner timer still refuses a concurrent finite wait on
that slot; this is unfinished admission work, not Linux timeout semantics.
