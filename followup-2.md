title: exhaust the default execution pool with native IPC readers
parent: #2271

The production KVM witnesses have two live processes and reuse native owner
parking; they do not exhaust the default executor pool. Add a bounded fixture
with more parked readers than executor slots and a runnable producer, verifying
exact bytes, last-writer EOF, retained vector headers, and no host readiness
pipe. Preserve the existing pool size and time budgets. This closes the
capacity witness acknowledged by #2153 without changing its park mechanism.
