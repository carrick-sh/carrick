# Node child/worker diagnostic reduction

Four independent process samples per variant per lane, after one warm sample
per variant. Balanced variant order; Carrick phase completed before Docker.
No rebuild or trace during timings. All 40 runs completed with exactly one
app-smoke marker. Carrick cleanup returned zero for every run. Frozen CLI hash
checked after each lane. Commands, image digest, raw stdout/stderr, warm samples,
and exact source variants are retained. Timing covers the entire Node process,
including teardown, at bash millisecond precision. Preparing the JS file occurs
outside the measured interval. All variants retain imports and the other work.

Median milliseconds:

| Variant | Carrick | Linux |
| --- | ---: | ---: |
| Both child and worker | 236.5 | 46.0 |
| Child only | 193.5 | 34.5 |
| Worker only | 134.0 | 35.5 |
| Neither | 98.0 | 21.0 |

Carrick both samples are 239, 233, 381, 234 ms; the 381 ms observation is retained,
not retried or excluded. Its mean is 271.75 ms. Differences of medians are coarse
screening effects, not confidence bounds or additive implementation attribution.
The child increment is 95.5 ms without a worker and 102.5 ms with one; Linux
increments are 13.5 and 10.5 ms. Worker increments are 36 and 43 ms on Carrick,
14.5 and 11.5 ms on Linux. Child launch/exec/exit is the next bounded diagnostic.

This removes requested work, so it is NOT a performance improvement. The full
original image fixture remains the acceptance workload. /tmp/node-phase.js is a
different file path from the original fixture; do not replace historical raw
ratios with these numbers. No platform-I/O correction is applied. This smoke
mix includes multiple startups and does not represent sustained JS throughput.

Next distinguish child lifecycle from child Node initialization using a minimal
child and a standalone Node startup control, followed by task-correlated service
counts. Require a semantics-preserving paired intervention on the original
fixture before claiming impact. No evidence yet permits deleting any required
memory, signal, authority, observer, or process-lifecycle operation.
