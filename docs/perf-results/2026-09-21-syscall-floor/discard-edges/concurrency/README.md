# Concurrent Node groups

Frozen matched control/candidate from the unaligned-discard experiment. Each
sample launches N copies of the unchanged pinned app-smoke fixture concurrently
inside one guest carrier, then waits for EVERY child and checks every exit.
Shell time covers complete group execution. Exact N app markers plus GROUP_OK
required. Four independent samples per arm and scale after one warm run per arm,
two ABBA blocks; all retained. Linux phase follows Carrick; no tracing/builds
in timing windows. Group-launch semantics differ from the original foreground
single-workload test, so these ratios do not replace its historical result.

| Concurrent workloads | Control ms | Candidate ms | Linux ms | Candidate/control | Candidate/Linux |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 259.50 | 207.75 | 48.00 | 0.801 | 4.328 |
| 2 | 288.75 | 205.50 | 49.75 | 0.712 | 4.131 |
| 4 | 525.25 | 330.00 | 56.75 | 0.628 | 5.815 |
| 8 | 1155.25 | 779.50 | 82.00 | 0.675 | 9.506 |

The improvement survives all scale points. Candidate throughput rises to12.12
workloads/s at4, then falls to10.26 at8 (Linux97.56 at8). At8 one candidate sample
is956ms; all four samples690/727/745/956ms are retained, with no retries or
outlier exclusion. The mean raw Linux ratio is9.506, near the10x pathology
boundary. This is not near-parity or a concurrency acceptance pass.

## Resource context and diagnostic trace

Host logical CPUs10; Docker configured CPUs10. A separate Node query reports
Carrick cpus=4/availableParallelism=4 and Docker10/10. No bound/spare executor
overrides were set. Therefore the raw comparison also includes CPU-exposure
policy differences; do not attribute the whole scaling gap to lock behavior.
The first direct-entrypoint CPU query failed before a receipt was saved; only
the subsequent shell-wrapped query and its recorded output are cited.

Two separate trace captures each complete five groups (5 or40 workloads).
Request/acquire/release/try-miss counts reconcile per operation, root exited,
no errors, and all markers complete. Wait sums overlap; probes cover multiple
locks and nested scopes, not one global mutex. No traced speedup prediction.

For sparse materialization (operation3), accumulated waits are46.4ms atN=1
and13051.8ms atN=8 across five groups; requests8012 and63692. COW waits34.4 to
6807.9ms; alias-unmap waits26.6 to5285.3ms. These are same-instrument diagnostics,
not critical-path shares. The operation3 acquisition is FrameRegistryGuard
around sparse_materialization::publish_replacing in cow_engine.rs. A narrow
candidate would move safe preparation outside that guard while retaining exact
publication/rollback authority; it needs a red-first proof and untraced
intervention. CPU exposure is a separate variable that must also be controlled.

No product changes in this experiment. Full discard failure injection and the
remaining promotion gates are still open. Do not reduce workload concurrency or
relax budgets to hide the throughput decline.
