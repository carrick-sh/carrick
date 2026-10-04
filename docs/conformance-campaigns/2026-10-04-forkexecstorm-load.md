# forkexecstorm shard-load investigation (2026-10-04)

## Fault and classification

The signed gate reported one `forkexecstorm` child unreaped after 183
successful spawns: `total_reaped=182`, `wait_failures=1`, first wait error
`110` (`ETIMEDOUT`), and 13,446 ms elapsed. Isolated runs took about 270 ms.
The gate retained no carrier core or event ring, so the state of that child at
the failed wait is unknown.

The probe's old `bounded_reap_pid` checked its wall-clock deadline **before**
calling `waitpid(pid, WNOHANG)`. A waiter descheduled past its deadline could
therefore return `ETIMEDOUT` without observing a child that had already exited.
This is a proven probe time-assumption defect. The gate failure is consistent
with it: the director measured minute-scale stalls on the USB drive during
concurrent builds at the time of the failure. That attribution is an inference,
not a captured child lifecycle. A child that genuinely failed to exit or an
incorrect wait scan in that original run has not been ruled out.

The probe polls `waitpid(WNOHANG)` instead of blocking for `SIGCHLD`, so a lost
SIGCHLD wake alone does not explain its timeout. The observed child PID means
the vfork parent was released for that spawn. The remaining live distinction
would have been child exit publication versus elapsed wall time while the
waiter was off-CPU; the lifecycle DTrace script in this branch is ready for a
future failing capture.

The correction calls `waitpid(WNOHANG)` first and reports a timeout only after
that call says the child is still running. The five-second child bound, the
20-second supervisor bound, four workers, and 200 expected reaps are unchanged.

## Deterministic red-first witness

The signed Linux test `tests::test_bounded_reap_attempts_ready_child_at_expired_deadline`
forks a child, uses `waitid(P_PID, WEXITED|WNOWAIT)` to prove it exited while
still unreaped, then calls `bounded_reap_pid` with an expired deadline. In a
temporary build with only the main deadline ordering restored, it failed:

```text
red_rc=101
assertion `left == right` failed: ready child must be checked before timeout
test ...test_bounded_reap_attempts_ready_child_at_expired_deadline ... FAILED
```

The same test on the candidate ordering passed (`1 passed; 0 failed`). Both
ran through the signed Carrick CLI under `just lease carrick`, with run IDs
`fes-reap-red` and `fes-reap-green`; scoped cleanup reported zero processes.
The red and green Linux test ELF SHA-256 values were respectively
`a3aa237e4e01ccfd7bb9b815e337c217bc8fce6ab1b555d78a0d89ff8fe5a655`
and `095e093954f844733c13b6111248b17fff97d094de4eb16f9a5d628cccca7bb7`.
Logs remain in ignored `target/fes-load/reap-{red,green}.log` on cloudmac.

## Loaded controls on SSD

The branch was rebased onto `github/main` `0250e7f2a834e8bd1b080780bd0f5b8e67bc30ad`.
Its signed CLI SHA-256 was
`a9d95295fd8a689745a51e8679dd33ae7f990d5ec3ae3335ecefa2390905a3e6`;
the signed shard-2 test executable SHA-256 was
`8f48133cc7620506d6b12f1b9738a3e5fb5fa3cce6c818c8d1a91e8dd6e54d6f`.
For these diagnostic controls alone, the two Linux `forkexecstorm` ELFs were
replaced by binaries built from exact main source (musl SHA-256
`12dc81b22c5e49507f65d3d8da3bd291a3c36274da0992834847c5054a1acea0`,
GNU SHA-256
`3374601b7de50da5548efdf2b02792773723804e7efea96b3ea81047c058d217`).
The candidate ELFs were restored after each command and their hashes checked.
The committed oracle **bodies** are unchanged; their source-hash headers are
provisional until refreshed by a native ARM64 Linux Docker authority, which
this host does not have.

- Thirty rounds of three concurrent signed shard-2 carriers, filtered to
  `forkexecstorm`, passed: 90 carriers and 180 libc probe executions.
- Three full concurrent shard 0/1/2 triads passed; all six `forkexecstorm`
  libc executions passed.
- A further ten full triads ran with an automatic `lldb-snapshot` trigger at
  1.5 seconds inside `forkexecstorm`. All 19 reached `forkexecstorm`
  executions passed (315–1300 ms), so no useful live snapshot fired. In
  triad 9, shard 2 stopped at a later musl `lifecycleflagmatrix` mismatch
  before reaching GNU `forkexecstorm`.

The ten-triad command exited nonzero and its failures remain red:
triad 1 had `expectcontinue_body_wake=false` in shard 1; triad 9 had a
truncated `inotifymatrix` run in shard 0 and multiple `lifecycleflagmatrix`
false lines in shard 2. Other worktrees were compiling during triad 9. These
failures are outside the forkexecstorm change and are not waived by later
passes. Full logs and scoped zero-process cleanup lines remain in ignored
`target/fes-load/mon-main-*.log` on cloudmac.

## Remaining promotion

Run ten normal shard cycles, `just test-kernel`, `just clippy`,
`just lint-domains`, `just ci`, and the exclusive host and signed acceptance
phases. No additional trace or stress campaign is authorized. A fresh signed
receipt and a native ARM64 Linux oracle refresh are separate from the
deterministic witness above.

## Continuation: fresh red-first proof

Inspection found that published commit `7a2da61a2` already contains both the
witness and the readiness-first fix, alongside the diagnostic script and
provisional oracle headers. The handoff's claim that they were uncommitted
was stale. The director explicitly requested preserving that mixed commit
instead of rewriting published history or reverting and reapplying it.

The affected surface is the retained `forkexecstorm` probe's
`bounded_reap_pid`, not Carrick's kernel wait implementation. The witness
contract is: a child proven exited and unreaped by `waitid(WEXITED|WNOWAIT)`
must be observed by one `waitpid(WNOHANG)` attempt even when the helper's
remaining budget is zero. The fix adds no retry, sleep, timeout, concurrency
reduction, or runtime path. Existing waits and workload sizes are unchanged.

For fresh red evidence, only the helper's three-line deadline-first check
from main `0250e7f2a` replaced the candidate comment; the witness remained.
The signed CLI and Linux musl test ELF were rebuilt locally, then run with
`CARRICK_RUN_ID=fes2-witness-red` under the shared host lease:

```text
assertion `left == right` failed: ready child must be checked before timeout
  left: 0
 right: 8
test tests::test_bounded_reap_attempts_ready_child_at_expired_deadline ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 17 filtered out
witness_red exit=101
remaining carrick procs (run-id fes2-witness-red) = 0
```

Red ELF SHA-256:
`0e945fdf5c2de27ec7aa9219ec677e86997e034c2c75b3e781a8ffa40d2e121d`.
Full logs are `target/fes-load2/witness-red{,-driver}.log`. The driver records
HEAD, CLI/ELF SHA-256, signing metadata, entitlement, LC_UUID and DOF section.
The exact committed candidate source was then restored for the green run.

The restored candidate passed with `CARRICK_RUN_ID=fes2-witness-green`:

```text
test tests::test_bounded_reap_attempts_ready_child_at_expired_deadline ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out
witness_green exit=0
remaining carrick procs (run-id fes2-witness-green) = 0
```

Green logs: `target/fes-load2/witness-green{,-driver}.log`. These results prove
the ordering defect and its correction. They do not establish whether the
original unreaped child was ready when the USB-stalled waiter timed out.
