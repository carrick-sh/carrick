# CPU-affinity sensitivity control

Forty successful Docker-only runs: N=1/2/4/8 unchanged Node app-smoke
processes, one warm run per arm and two ABBA blocks per N. Each group waited
for all child statuses and emitted exactly N app-smoke markers plus GROUP_OK.
All 32 timed samples retained; no exclusions. Raw argv records pin image digest,
arm64 platform and CPU sets. Source scripts and raw streams preserved with hashes.

| Concurrent processes | Linux CPUs 0-9 mean seconds | Linux CPUs 0-3 mean seconds |
|---|---:|---:|
| 1 | .04875 | .04700 |
| 2 | .04850 | .05000 |
| 4 | .05500 | .06275 |
| 8 | .08425 | .11375 |

Prior Carrick candidate eight-process group mean was .77950 seconds, about
6.85 times this restricted Linux mean. This is a separate-session screening
comparison, not a matched causal subtraction or proof of equivalent resource
exposure. The unrestricted Linux arm remains the goal reference. CPU restriction
does not explain most of the observed concurrency gap. These data do not isolate
macOS I/O and do not alter the representative workload or concurrency requirement.

Archive verification reread all 40 exit statuses, timeout flags, completion
markers and timing records, and recomputed every arm mean against summary.json.
