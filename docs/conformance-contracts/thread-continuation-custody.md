# Per-thread native continuation custody (#1401)

Contract: `process.native.terminal-child`. Linux `vfork(2)` suspends the
calling thread until its child execs or exits; another thread's `wait4(2)`
cannot prevent that suspension or return the clone early.

Native wait, IPC and vfork rows are keyed by the exact process TaskKey and
waiting task ID and thread birth generation. Owner authentication also
checks the thread control and visible tid. Thread-directed signals select the
same waiting task through its live record; process-directed signals visit the
deliverable member records. A host rehome preserves custody for the same
logical task while a new thread birth cannot borrow it.
An authenticated rehome also restores native execution ownership before the
runtime unhomes a retained wait, allowing a live child exec to place its wake
on an idle native executor. The host-request witness reparks before that live
release and checks the exact child PID and the sibling wait.
Process retirement discards all operation rows for that process generation.
Terminal close and service settlement retain their existing independent keys.
An already-created vfork uses the shared owned-park publication used by
terminal close: a winning host request receives its retained owner, never
a post-clone errno or an early clone result.

The VM-free production-entry witness
`sibling_wait4_and_vfork_retain_independent_continuations` keeps A parked in
wait4 while B creates a vfork child. B must park independently, resume after
its own child exits, and leave A's wait intact. Only after B resumes may the
other child finish, allowing A to reap it. One execution slot serves all
participants, so a parked continuation cannot retain execution capacity.
The deterministic dependency substitutes for the guest pipe. The signed
`el1_sched_thread_continuation_wait4_vfork_pipe` binding uses the identical
native-Linux-tested fixture with a real pipe and 1 or 32 waiting siblings.
Run it with `just test-embed el1_sched_thread_continuation --ignored`.
Its execution remains required; native control results do not prove Carrick
execution or default host pool exhaustion.
The existing vfork witness covers child exec admission and exit release.
There is no polling, host wait, extra worker or timeout budget in this change.

Signed pipe and pool-exhaustion integration and Docker comparison remain
required higher-layer evidence; VM-free results do not confer acceptance.
