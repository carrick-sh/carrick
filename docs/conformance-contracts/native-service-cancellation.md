# Native service cancellation across child retirement (#1467)

`process.native.terminal-child` owns this service-cancellation reduction.
Linux exit/wait semantics permit a parent to reap and fork again while another
execution lane finishes delivering a signal to the departed process. That
signal cannot cancel a different process that reused its scheduler record.

`obsolete_service_cancellation_preserves_reforked_record` drives the VM-free
native process harness. A real fork child parks a CarrierWork request while
its live parent retains a wait4. A one-shot schedule hook pauses cancellation
after it captures the child's exact request and retained control. The other
lane acknowledges the request, resumes its native owner, exits through neutral
terminal custody, reaps the child and forks a replacement. The replacement
must reuse the record ID with a newer incarnation and a different TaskKey.
It publishes and acknowledges its own service. Delayed cancellation must
complete without quarantining that queue or changing the replacement's exact
Supplied result. The schedule uses no blocking actor waits or retries.

The control reference retains the control allocation; it does not retain the
scheduler record. Neutral terminal custody remains the sole retirement owner.
Cancellation must authenticate its captured request after queue-admission
refusal as well as after successful queue admission. Only an obsolete request
can settle without queue custody. A still-current request with invalid queue
custody remains an invariant failure. This is one queue lookup and at most one
exact pending-record lookup; it adds no polling, population scan, extra syscall
dispatch, or alternate retirement mechanism.

This is independent of #1485's physical MM owed-return settlement and #1545's
native thread-birth stock. It uses the existing exact ServiceRequest identity
(TaskKey, thread generation, record incarnation, MM, execution and sequence),
existing graph owner and existing neutral retirement. No ABI changes are needed.

The fatal NativeServiceQuarantined reason also represents other invariants;
its name alone does not establish which branch failed in the signed workload.
This reduction must not be reported as attribution of the director's heavy
failures without exact-artifact signed evidence. The director retains the
24-run heavy workload, signed smoke, Docker differential and runtime ratio.
