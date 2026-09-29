# Scoped child-exit notification work

The new measurement asserts actual retained-snapshot thread visits and exact
scheduler wake calls in `HvpatchRuntimeEndpoint::wake_scheduler_exact`.
Both counters compile only with conformance-metrics and use the existing
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

The signed fixture now attaches a WorkScope to its existing three-process
container. Its whole-fixture budget is exactly two snapshot visits and at most
one scheduler call: the middle parent is already reaped on delayed delivery;
the root may still be live for the other delivery. Original capture/reap/
release ordering and zero reaped-wake rejections remain mandatory. Signed
qualification of these new assertions is pending; do not call it accepted.
