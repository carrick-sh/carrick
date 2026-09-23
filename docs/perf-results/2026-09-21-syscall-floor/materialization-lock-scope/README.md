# Preparation outside the frame registry: measured and rejected

Decision: restore the prior implementation. The structural correction was real,
but this experiment did not demonstrate a compelling net workload improvement.
This does not prove that preparation is free or that a 1-2% effect is impossible.
It rejects this change as the next meaningful step toward near-parity.

## Paired results

Frozen signed control SHA256:
3e2521515cc0af0324dbd2f7639bd43ea27fc324dd84e1dbd69a4e508e780972
Candidate SHA256:
84099635cd7a57f1edddcb11d7cdb51e52c8bedd69889e347afc182c0a52ff54

Both retain the prior unaligned-discard improvement. Source manifests, full dirty
patches, experiment snapshots and exact signed metadata are archived. The control
is the previously frozen discard-edges candidate; intervening source changes
outside this experiment are tests/formatting/contract metadata, not new runtime
behavior. No compilation or tracing during these timing runs.

| Workload | Initial control/candidate mean ms | Confirmation control/candidate mean ms |
|---|---:|---:|
| Original Node app-smoke | 178 / 184.5 | 175.5 / 176.75 |
| One background Node | 181 / 181.25 | not repeated |
| Eight concurrent Node | 705.5 / 695.5 | 720.5 / 702 |

Each screen used two warmed ABBA blocks (four measured samples per arm).
Confirmation was fixed-size and retained all samples, including 207 ms Node and
784 ms concurrent control observations. All 50 runs completed successfully with
exact expected markers; raw timing, argv, output and scoped cleanup retained.

Combined original Node means: 176.75 / 180.625 ms (candidate/control 1.02192).
Combined eight-process means: 713 / 698.75 ms (0.98001); medians703.5 /694 ms.
These small screening differences are not a proven broad speedup. No new Linux
phase: prior unrestricted Linux receipts remain visible separately. No I/O
subtraction, altered workload acceptance, confidence-interval claim or multiplied
historical improvement.

## Implementation and tests (experimental snapshots only)

A shared local publication wrapper held the original guard placement for red.
The actual stage-2 preparation test backend asked a second host thread to try
entering the frame registry. It could not. The contract evaluator reported
ScalingViolation: host_backend_calls actual2 maximum0 at scale1. This measured
whether independent registry entry was possible at preparation, not whether an
entire second publication completed concurrently.

The candidate prepared backing before acquiring FrameRegistryGuard, while the
same exact-MM permit remained alive and inventory staging through publication
and prior-owner retirement stayed guarded. Foreign wrappers used the shared
prepared publication helper. The existing reservation now followed preparation;
this ordering change is part of the measured candidate, not an isolated lock-only
instruction swap.

Green contract covered1/8/32/128 pages at two injected failure boundaries:
pre-staging and after page-table sync. Original bytes, aliases and owner keys
were preserved. All506 HVF unit tests passed,3 existing ignores. Contract registry
suite passed. These are real carrier components with a stub stage-2 backend and
test authority, not live guest failure injection or full shutdown-race proof.
A source-order guard regression test was adapted to the callback transfer.

No full signed semantic promotion was attempted after the timing rejection.
Candidate and control guest Node runs completed, but that is not a substitute
for signed probe/smoke/full gates. The candidate is not a promoted artifact.

## Restored state and next question

Restored each experiment-touched runtime file from its exact pre-experiment
snapshot; removed only this experiment's contract/dev dependencies and restored
the affected registry count/source-order test. Other campaign changes retained.
target/release/carrick is byte-identical to the frozen control (SHA above).
No commit or push. Goal remains active.

The existing topology-operation trace combines multiple lock classes/nested
scopes under operation IDs. Its wait sums cannot identify the removable registry
critical path. Next distinguish actual frame-registry hold time from exact-MM
quiescence/publication/invalidation before selecting another lock change. This
negative intervention rules out assigning the large concurrency gap to private
backing preparation under this guard on the measured workload.
