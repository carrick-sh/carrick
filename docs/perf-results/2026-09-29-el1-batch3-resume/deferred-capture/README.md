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
requires nonzero real record captures. That test failed with zero captures; see below. It supplies no
retirement/reuse or historical-attribution claim.

## First signed trigger rejected

Source `497096b2f`, run `el1-deferred-capture-497096b2f`: the guest completed
the two-process 200-round workload, including child success, but the audit
vector was empty. The test failed as required. This is a fixture-trigger
failure, not an ownership red or a passing signed contract. No retry or larger
workload was run. Negative entitlement and both runner cleanup checks passed;
an independent process census was also empty. Exact executable bytes were
SHA-verified and preserved under `target/el1-resume-b3/deferred-capture-red/`
as `238257809e8fcce214dc4ae1829ff48cfa153b35b6232e5f8bcfe19dce0ea77c`.
See `signed-no-capture.log` and `signed-no-capture-identity.json`; the failed
runner does not publish a successful execution manifest.

Source inspection narrows the next trigger: ordinary in-guest handoffs need
not leave records for `leave_slot` to return. `host_wait_began` invokes
`step_away_from_slot`, whose vacate path returns queued records it cannot
relocate. A fixture needs to establish that queue state before an actual host
wait (e.g. the owned stdio write path), with exact slot/driver ownership.
Affinity alone and a fortunate timer schedule are insufficient proof. Do not
force raw record allocation or mutate a slot from a non-owning test thread.
Further inventory/whole-suite runs wait until this hook/fixture slice is
stable; the prior source gates do not qualify the new hook.
