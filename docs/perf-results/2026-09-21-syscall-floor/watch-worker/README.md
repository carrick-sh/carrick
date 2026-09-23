# Paired worker-operation diagnostic

Eight independent release-process comparisons, balanced direct/worker order,
one warmup and 21 samples of 65,536 invalid-inotify pairs in each process.
Production wrapped poll alone: 1002.93 ns/pair. With selected ordinary worker
operations: 1061.67 ns/pair. Increment: 58.74 ns/pair (29.37 ns/call).
All eight tests pass exact request/errno completion population assertions.

The added calls are production authority take/restore, execution-lease transfer,
zero CPU-receipt accounting, scheduler note_syscall_boundary/should_preempt and
ReceiptLog::record. The receipt ring is warmed to its bounded steady state.
These operations are invoked by the diagnostic in worker order; the diagnostic
does not run executor_worker itself and is NOT a complete worker timing. Panic
boundaries, backend receipt extraction and per-iteration construction differ.
No contention, preemption, pending signal or hardware transition is exercised.
No product behavior changed.

Decision: do not pursue the roughly 30 ns/call single-resident worker increment
as the principal explanation of the full guest gap. Shared receipt/scheduler
locks remain concurrency hypotheses, not established throughput bottlenecks.
Together with wrapper and signal comparisons, the evidence is sufficient to
stop expanding single-thread wrapper instrumentation as the main investigation.

Next architectural experiment: a bounded same-thread DSR/native gateway using
the current unified kernel and production policy/completion semantics. Require
real guest instruction execution, current MM authority, TLS/register preservation,
signal/cancellation and scheduler handoff; a host function-call benchmark alone
cannot qualify it. Compare the exact invalid-fd, unchanged-watch and watch-churn
fixtures, then common syscall mixes and compute/JIT controls. Keep an HVF control
and matched signed artifact identity. This tests attainable transition avoidance;
it does not presume the residual is entirely HVF cost or restore the retired
one-host-process-per-guest architecture.

If delivering that bounded guest gateway requires broad architecture changes,
first write the precise authority/lifecycle contract and demonstrate its red
state. Existing kernel-syscall-floor gateway results are feasibility evidence
only. Do not optimize the nearby tiny wrapper targets just because they are
easier to change.

Raw outputs, binary SHA, source snapshot and build log are retained here. No
absolute floor, signed acceptance, production speedup or near-parity is claimed.
