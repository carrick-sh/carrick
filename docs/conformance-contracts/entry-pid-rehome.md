# Exact process identity after record renewal (#887)

The process.native.arm-admission contract requires user return to reuse
the already admitted process after a host execution record is renewed.
Linux's clone and getpid contracts retain the parent's process identity
while its child lives; execution-slot reuse cannot transfer namespace PIDs.

The VM-free binding
live_fork_child_cannot_supply_renewed_roots_entry_pid forks through
production ARM process admission, retains both live process rows, releases
the parent's old execution record, and schedules the child before the
renewed root. The scheduler publishes execution, MM and lifecycle identity;
production unregistered resume has no record-indexed native owner yet.
User-return admission must resolve the root's exact retained process and
observe PID 41, rather than the child's PID 42. A second owner must never
be admitted against the root's retained pending writer.

This adds no retry, polling, new wait, timeout or concurrency reduction.
Ordinary entry uses the existing execution-key index and a single exact
process-row lookup; record renewal retains the existing rehome protocol
and its fixed lifecycle bounds. Existing dispatch and backend-call budgets
remain authoritative. The director owns signed inherited-descriptor
population evidence and physical-artifact acceptance.
