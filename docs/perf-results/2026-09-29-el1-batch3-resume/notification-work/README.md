# Scoped child-exit notification work

The new measurement asserts actual retained-snapshot thread visits and exact
scheduler wake calls in `HvpatchRuntimeEndpoint::wake_scheduler_exact`.
All three counters compile only with conformance-metrics and use the existing
kernel graph WorkScope. Normal builds add neither scope lookup nor counters.

Red: the existing delayed/reaped-parent fixture reported zero thread visits
where one was required, before the delivery sites were instrumented. Green:
at 1/8/32 deliveries, each single-thread snapshot is visited once per delivery
and the retired parent causes zero scheduler wake calls. Contract observations
are retained, and extra visits or wake attempts are rejected at every scale.
The existing live-parent endpoint fixture is a positive control: one visit,
one wake call, and one queued task. Meter tests and affected all-target Clippy
with conformance-metrics pass. Contract registry: 68 contracts/15 claims/148
surfaces. This is not a measurement of total scheduler work or runtime cost.

The initial signed fixture attached a WorkScope to its existing three-process
container. Its whole-fixture budget is exactly two snapshot visits and at most
one scheduler call: the middle parent is already reaped on delayed delivery;
the root may still be live for the other delivery. Original capture/reap/
release ordering and zero reaped-wake rejections remain mandatory. That initial budget was rejected by the first signed observation below.

## Correction after the first signed observation

Signed source 44b2834c1 preserved capture/reap/release ordering and reported
exactly two thread visits, but two scheduler calls exceeded the proposed
limit of one. `signed-budget-red.log` retains that failure; the exact failed
executable and identity are retained separately. Negative entitlement and
scoped cleanup passed.

Ruling: the attempted-call bound incorrectly treated authentication as wake
delivery. The existing ExactWakeTarget contract explicitly permits a thread
snapshot to retain its execution generation after graph reap; wake_exact
then returns Pending without a queued or kicked wake. Adding a redundant
precheck or changing valid delivery semantics to satisfy that mistaken bound
would be the wrong fix. Instead, keep one authentication per visited thread
(maximum two here), and separately enforce actual Queued/Kicked deliveries:
zero for the retired VM-free target, at most one for the whole signed fixture.
The root is the only live candidate. The original signed semantic ordering
and zero reaped-wake rejections are still mandatory. This does not license a
stale delivered wake or add a retry.

The new actual-delivery counter was red-first: the live-parent test reported
zero instead of one before instrumentation. After instrumentation the live
control reports one visit/attempt/delivery and one queue row; retired tests
at 1/8/32 report N visits, zero attempts and zero deliveries. Extra visits,
attempts or deliveries are each rejected. Corrected observations, affected
Clippy, meter tests and registry checks pass. Signed qualification of this
corrected distinction passed on source `9ba825eacc0a919aa57ba4d0d5ea9497865f4996`:
exactly two visits, two authentication attempts and one delivered wake, with
complete observations (zero dropped events, no unknown metrics). The exact
capture/reap/release semantics and all excess-work controls passed.

`delivery-signed.log`, `delivery-signed-artifacts.jsonl` and
`delivery-signed-observation.jsonl` retain the successful result. One selected
signed test and the unentitled negative control passed; runner cleanup was
zero and an independent post-run process census found no Carrick/EL1 fixture
processes. The executable SHA-256 was independently verified and its bytes
preserved under `target/el1-resume-b3/notification-delivery-signed/`:
`ad9e0c6198ebc2ec5b0e8a9db10e76a3eab254fd7a361595d186f93fa42e0928`.

This closes only the scoped notification structural binding. Historical crash
attribution, remaining lifecycle obligations, source reconciliation and full
candidate qualification remain open. The earlier failed budget and its ruling
remain part of the evidence; this is not retry-until-green acceptance.
