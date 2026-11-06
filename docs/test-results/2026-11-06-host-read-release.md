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
