# Host-read scheduling lost wake (#847)

The signed baseline population on carrick-m4 passed 16 of 20 runs. Four
runs hung at the existing 120-second fixture watchdog; none returned a
wrong value or hit the 300-second outer bound. Every run used the same
preserved signed executable and restored fixture input identity. Each
selected test started, and scoped cleanup reported zero remaining guests.

| Population | Passed | Watchdog hang | Other failure |
|---|---:|---:|---:|
| Main, `847-base-1` through `847-base-20` | 16 | 4 | 0 |

The failing run IDs are `847-base-1`, `847-base-10`, `847-base-15`, and
`847-base-20`. Runs 1 and 15 completed the first 1,000-round workload,
then hung during the next 6,000-round workload. Runs 10 and 20 hung during
the first 1,000-round workload. Watchdog abort produced the panic
`container run failed: kernel aborted: kernel abort requested`, followed
by scoped reaping (exit 137).

Evidence is retained outside the worktree under
`/Users/administrator/m4-host/evidence/847/`: `base/results.tsv`, each
run's full `test.log`, identity and cleanup records, post-mortems and both
event rings, plus the preserved executable and symbols under `artifacts/`.
`base-focused.log` records the successful known-answer signed runner and
negative entitlement control before the population. `fixtures.log` records
verification and restoration of all 1,195 fixture executables from the
locally staged bundle, admitted by fixture input identity.

No code was changed in the baseline executable. No runtime concurrency,
timeout or scheduling parameters were changed. A bounded host sample was
taken during run 10. Separate diagnostic runs use a debuggable signed copy
and do not enter the population above.

Diagnostic run `847-diag-2` reproduced a stranded Editor wait on queue
5186 (MM 2), with four idle vCPU executors and all spare executors asleep.
The matching modified-memory core shows `key=2`, `gate=0`, and
`active_editor=0`: no editor remains to release it. Both ring captures
reported zero errors. The coherent kernel snapshot refused with an explicit
busy-authority result; the degraded result and later watchdog census are
retained alongside the core, rather than treated as a coherent snapshot.

The production editor destructor advances its Editor notification revision
before releasing `active_editor`. A contender can observe that new revision,
receive an Editor refusal, and enroll after delivery has already drained the
queue. Its snapshot is then current forever. The generic resource release
has the same ordering defect.

The two deterministic production-path witnesses fail on the baseline with
`owner parked after the final editor release with no producer` and
`owner parked after the final PreparedOverlap release with no producer`.
The raw failures are in `editor-red.log` and `release-red.log`.
