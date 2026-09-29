# Deferred handback capture boundary (work in progress)

The pending implementation extends the existing carrier scheduler publisher
with a deferred-capture event and snapshots its Arc before invoking callbacks.
The event is routed to that scheduler kernel's AuditorChain; no separate
process-global test gate is introduced. Capture precedes record liveness
filtering after scheduler-core evacuation has returned.

The VM-free hook witness was red when its callback was not invoked (empty
capture instead of the exact RecordRef). With capture wired, the callback
can acquire the released slot lock, retire/reuse the allocation, and leave the
replacement parked with no publication. Three focused tests passed. The
initial short --exact invocation selected zero tests and is not evidence;
red.log is the corrected fully qualified failing execution.

The additional serial-host test verifies the callback can acquire the
publisher registration's write lock. All four boundary tests and affected
kernel/runtime Clippy passed. Capture now runs after already-owed placement
kicks and before deferred filtering; all four tests passed again after that
ordering adjustment. No signed guest fixture or signed acceptance exists for this hook.
This is measurement infrastructure, not a new ownership fix or historical
crash attribution. A first signed feasibility witness runs one short two-process workload and
requires nonzero real record captures. That test is pending and supplies no
retirement/reuse or historical-attribution claim.
