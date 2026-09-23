# Current signed candidate: watch-only refresh

Diagnostic screen, three independent processes per platform, 21 internal samples
per scale. Values below are nanoseconds per operation pair at scale 65,536.
Carrick ran completely before Docker; no build or other guest was present.

| Pair | Carrick process medians | Docker process medians | Ratio of medians |
| --- | --- | --- | --- |
| watch_churn | [3307, 3362, 3413] | [939, 948, 952] | 3.55x |
| watch_invalid_pair | [2860, 3372, 2944] | [247, 247, 246] | 11.92x |
| watch_existing_pair | [3507, 3572, 3536] | [554, 555, 556] | 6.37x |

All six processes returned zero with complete markers. This repeats the exact
historical probe executable (SHA recorded in runs.jsonl), not a newly rebuilt
probe. Current candidate SHA is fd96c7d450060e04ec7cc28933d82843c28521ecf80875567bd17dbdb5cec27f.
Source/build provenance is in ../discard-retirement; current artifact metadata
is in artifact-receipt.txt. This is not paired old/new acceptance.

The shared low-work path remains expensive. Invalid-fd variance is visible
between processes; do not infer a small improvement from the historical median.
The invalid fixture checks libc -1 returns, not exact EBADF; tighten semantic
evidence in the matched contract experiment before accepting a candidate.

Coverage audit: kernel.inotify.mark-race-hotpath covers add/write/seek/remove,
with a still-unresolved timing binding. kernel-syscall-floor covers getpid/fstat
and currently rejects DispatchOutcome::Errno. Thus no existing result measures
the same invalid-fd fixture across the direct kernel and full runtime paths.
The next implementation must add correct errno completion/reporting and matched
fixture coverage; it must not use getpid timing as the inotify transport baseline.

No matching candidate or Docker run remained in the post-run process inventory.
