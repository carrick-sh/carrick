# Host-read scheduling lost wake (#847)

The signed baseline population on carrick-m4 passed 16 of 20 runs. Four
runs hung at the existing 120-second fixture watchdog; none returned a
wrong value or hit the 300-second outer bound. Every run used the same
preserved signed executable and restored fixture input identity. Each
selected test started, and scoped cleanup reported zero remaining guests.

| Population | Passed | Watchdog hang | Other failure |
|---|---:|---:|---:|
| Main, `847-base-1` through `847-base-20` | 16 | 4 | 0 |
| Fix, `847-fix-1` through `847-fix-20` | 20 | 0 | 0 |

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

After unlocking before notification revision advancement, both witnesses
pass in the full scheduler library suite (268 passed). Its `serial_host`
partition contains zero tests. The fix population used one preserved signed
artifact, checked before every run, with no runtime scheduling or fixture
change. Every selected test started and finished; all 20 cleanup records
report no remaining guests. `fix/results.tsv`, per-run logs and identities,
and `fix-signed-artifacts.jsonl` retain the evidence. The signed runner also
passed its negative entitlement control before this population.

Independent initial and confirming reviews found no P0/P1 defects in the
changed editor and generic resource-release paths. They identified an
unchanged Gate-specific release with the same ordering pattern as a P2
follow-up. That actual Gate producer is distinct from the six causes tested
through the generic resource-release primitive. GitHub issue creation was
refused by the connected integration (403); the director was notified to
file it, with a production open/final-lower red-first witness and signed
integration as its acceptance criterion. No follow-up issue URL is yet
available. The reviewer also noted two adjacent ordering comments for that
follow-up.

The remaining requested checks pass: scheduler regular suite (268), its
empty `serial_host` partition, `just test-el1-native` (708 passed, one
existing ignored case), workspace/all-target clippy with `-D warnings`,
formatting, conformance contract coverage against the original main base,
and both source-only authority-debt ceilings and the PR-base ratchet. The
freestanding `carrick-x86-cpl0` release image also cross-builds for
`x86_64-unknown-none`; this is compile evidence, not an x86 runtime verdict.
Full logs use the corresponding names in the external evidence directory.

Signed smoke is the final check after this evidence commit. Its exact-HEAD
receipt is retained externally as `smoke-signed/receipt.json`, together
with `smoke-signed.log`. No Docker oracle or full signed acceptance gate
was run on this worker; neither is claimed by this focused fix evidence.
