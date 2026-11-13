# Ring-born robust-registered member exit (#2182 / #2109)

The existing `kernel.el1.thread-lifecycle` contract owns non-last raw exit.
The Linux semantic authority is exit(2) and clone(2): raw exit retires one
thread, and CLONE_CHILD_CLEARTID clears its word and wakes the joiner.

The shared serve_exit owner already reserves and publishes member retirement,
clears the child-tid word and performs its wake. A registered robust list must
not select host custody for a ring-born member with no host thread. This slice
removes that decline; it adds no alternate retirement path or robust walker.

The pinned production-entry witness switches a ring-born member onto CPU 1's
idle executor, registers robust and child-tid state, exits it while the leader
and sibling stay live, and requires one retirement, a cleared word, no host
custody and continued sibling execution. Lifecycle and two-live-thread tests
cover the same result. The existing primary binding and work budgets remain.

The rebase preserves main's appended yield/wait fixtures and declares the
renamed robust-exit witness in the retired-test registry. Earlier independent
red/green evidence remains on PR #2182. No signed crash disappearance is
inferred: the prior affinity-probe population failed 10/10 on both sides.
Robust OWNER_DIED walking and other host-custody declines remain the linked
follow-ups #2193, #2194 and #2195. Signed runtime acceptance remains open.
