# Issue #735: scheduler verdict attribution

The supplied `/tmp/735-evidence.txt` and issue comments distinguish guest
failure from the host test's later scheduling assertions. Signed attribution
remains provisional until the owner reruns the corrected artifact on HVF.

- `el1_sched_preemption_reaches_compute_loops`: the 8 ms, zero-preemption
  sample fails `assert!(measured.result.success())`, with exit 139 and the
  std sleep panic (errno 14 versus 4). It never reaches `preemptions >= 2`.
  `compute_pair` calls `sleep_ms(30)` after starting the sibling. That calls
  `std::thread::sleep`, whose Unix nanosleep failure assertion expects EINTR.
- `el1_sched_host_woken_thread_preempts_a_compute_loop`: the same success
  assertion fails after the same sleep panic. `pipe_compute` also calls
  `sleep_ms(30)`. Separately its `b_first_ms < 100` assertion measures host
  descheduling as well as guest scheduling; its pipe is now in-zone, despite
  the test's promise to exercise host completion.
- `el1_sched_pipe_pingpong_stays_in_guest`: `pingpong_rates` fails its guest
  success assertion, before checking any host-work slope. Guest iteration
  1199 is the final exchange of 200 warmups plus 1000 measured rounds. The
  fixture does not currently report which syscall failed or its return value.
  A sibling exits after writing that final byte, so memory edits during exit
  can coincide with the reader resuming. This ordering is a hypothesis, not
  a live trace proving the exact historical interleaving.

## Production refusal paths

The sleep input path is `dispatch_time::{nanosleep,clock_nanosleep}` ->
`read_timespec` -> `read_kernel_struct` -> `read_kernel_prefix`. The final
helper applies `map_err(|_| LINUX_EFAULT)` to `GuestMemory::read_bytes`.
On admitted ARM roots, `Aarch64EngineCore::read_bytes_raw` calls
`read_owner_bytes` / `continue_owner_read`; owner-lock, physical and supply
waits return `MemoryError::ReadSuspended` with a retained transfer. The ABI
helper discards that transfer and manufactures EFAULT. This is a product
error; no guest pointer fault is required.

The pipe adapter's `ipc::run` returns `written as i64` for any resumed
`StepStatus::Fault` on `PipeRead`, including zero bytes. `ValidatedCopy`
returns false if the live memory validator cannot authorize the destination.
Consequently a resumed read can report EOF while its pipe still contains the
byte. The operation must preserve its description and transfer custody and
hand back for memory resolution when no byte was copied. A partial read must
still return its positive prefix.

Applicable contracts: `kernel.el1.guest-scheduler`,
`kernel.el1.guest-run-queue`, and the IPC read/write contract. Deterministic
VM-free witnesses must exercise these production adapters before fixes;
no change to timing budgets, retries, concurrency or scheduler polling is
justified by this evidence. HVF and Docker are unavailable on this worker.

## Changes and deterministic proof

The resumed pipe refusal witness failed with `Returned` instead of `Handback`
before the fix. After the fix all 26 IPC adapter tests pass, including short
positive reads and descriptor reuse. The signed fixture now reports the
operation, return value and errno on a failed exchange; this distinguishes
false EOF from EFAULT without adding production logging.

The sleep witness failed with `LinuxErrno(14)` before the fix. Sleep now owns
its copied timespec prefix, clock domain, absolute/relative mode and remaining
pointer through `SleepCopyInSuspended`. Runtime owner-wait routing retains that
continuation rather than redispatching the numeric syscall. The focused
witness requires exactly one copy start and two resumptions before a 30 ms
sleep becomes eligible. Negative controls preserve EFAULT for invalid pointers
and EINVAL for invalid timespecs; a deterministic clock advanced during input
suspension proves an expired absolute deadline is not extended.

The old compute-pair window could finish while its host vCPU was descheduled;
the host-completion assertion similarly counted host scheduling delay against
100 ms. Neither measures a guest-only scheduling slice. The replacement
requires both CPU-0 threads to complete 16 atomic turns without syscalls, plus
at least two actual EL1 preemptions. The atomic observations are intrinsic to
the compute workload; no scheduler polling, timeout extension or retry is
introduced. The outer 60 s watchdog remains a failure bound. The exact virtual
slice boundary remains covered by `the_virtual_timer_preempts_a_compute_loop`
with a fake clock. The 30 ms nanosleep stays as the original EFAULT regression
surface; no correctness predicate assumes the peer parked during that sleep.

`host-compute` replaces the obsolete `pipe-compute` fixture spelling and uses
an AF_UNIX socketpair, whose read crosses to the host. Its test also requires a
forwarded read and in-guest preemptions (the old test accepted zero). This
proves host-served completion followed by shared-CPU progress. It does not
force the exact instant of host wait enrollment; the VM-free host-wake and
virtual-timer bindings remain the deterministic proof of that boundary.

## Signed commands for the director

Changed fixture inputs require a new Linux-published bundle. On Linux,
`env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 just fixtures-publish "$(git rev-parse HEAD)"`
produces the archive locally; transfer it to the Mac, then run
`just fixtures-restore /absolute/path/to/bundle.tar.gz`. No old bundle or
source hash alone certifies the new executable.

Build/sign once through the established recipe (this initial run also
qualifies the signer and its unentitled negative control):

```sh
env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 CARRICK_RUN_ID=735-sign \
  just test-embed el1_sched_pipe_pingpong_stays_in_guest --exact --nocapture
```

Then qualify all three tests five times on that exact executable. Do not
rebuild or re-sign between invocations. This uses the artifact already signed
by the recipe, retains its complete identity receipt, takes the host gate
lease and cleans up each run by ID. A failure stops qualification; it is not
retried to obtain five successes. Run from the repository root on the Mac:

```sh
just lease gate bash -c '
set -euo pipefail
. scripts/lib/test-signed-identity.sh
receipt=target/test-results/carrick-embed-signed-artifacts.jsonl
sched_exe=$(jq -sr '\''[.[] | select(.record_type == "executable") |
  .canonical_path | select(test("/el1_sched-[^/]+$"))] | unique |
  if length == 1 then .[0] else error("expected one scheduler artifact") end'\'' "$receipt")
evidence="$PWD/target/735-signed-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$evidence"
cp "$receipt" "$evidence/artifacts.jsonl"
shasum -a 256 "$sched_exe" target/embed-fixtures/el1-sched-aarch64 > "$evidence/artifact.sha256"
test_signed_has_entitlement "$sched_exe"
test_signed_has_dof "$sched_exe"
test_signed_cdhash "$sched_exe" > "$evidence/cdhash.txt"
test_signed_lc_uuid "$sched_exe" > "$evidence/lc-uuid.txt"
test_index=0
for test_name in \
  el1_sched_pipe_pingpong_stays_in_guest \
  el1_sched_preemption_reaches_compute_loops \
  el1_sched_host_woken_thread_preempts_a_compute_loop
do
  test_index=$((test_index + 1))
  for round in 1 2 3 4 5; do
    shasum -a 256 -c "$evidence/artifact.sha256"
    run_id="735-t${test_index}-r${round}"
    trap '\''scripts/sudo/kill.sh "$run_id"'\'' EXIT
    rc=0
    env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 RUST_TEST_THREADS=1 \
      CARRICK_RUN_ID="$run_id" "$sched_exe" "$test_name" --exact --nocapture \
      > "$evidence/$run_id.log" 2>&1 || rc=$?
    scripts/sudo/kill.sh "$run_id"
    trap - EXIT
    printf "%s exit=%s\n" "$run_id" "$rc"
    test "$rc" -eq 0
  done
done
shasum -a 256 -c "$evidence/artifact.sha256"
'
```

Each fixture still has its existing 60/120-second embed watchdog. These
focused runs do not replace the director's full signed acceptance population,
probe/smoke/full promotion or independent review.

Residual diagnostic boundary: `continue_owner_read` also has an unreceipted
`TransferProgress::Suspended` -> `MemoryError::HostMap` path (portal selection
change or missing submission/completion receipt). This change does not invent
an owner wait for that state. If a signed sleep still returns EFAULT, capture
the existing `hvpatch_el1_host_read_progress` probe to distinguish that backend
path from a typed owner/physical/supply suspension. Neither the historical logs
nor the VM-free injection identify the exact backend event in the old run.
