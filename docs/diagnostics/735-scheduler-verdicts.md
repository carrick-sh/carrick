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
  original fixture did not report which syscall failed or its return value.
  A sibling exits after writing that final byte, so memory edits during exit
  can coincide with the reader resuming. This ordering is a hypothesis, not
  a live trace proving the exact historical interleaving.

## Production refusal paths

Before the fix, the sleep input path was
`dispatch_time::{nanosleep,clock_nanosleep}` -> `read_timespec` -> `read_kernel_struct` -> `read_kernel_prefix`. The final
helper applied `map_err(|_| LINUX_EFAULT)` to `GuestMemory::read_bytes`.
On admitted ARM roots, `Aarch64EngineCore::read_bytes_raw` calls
`read_owner_bytes` / `continue_owner_read`; owner-lock, physical and supply
waits return `MemoryError::ReadSuspended` with a retained transfer. The ABI
helper discarded that transfer and manufactured EFAULT. This is a product
error; no guest pointer fault is required.

Before the fix, the pipe adapter's `ipc::run` returned `written as i64` for
any resumed `StepStatus::Fault` on `PipeRead`, including zero bytes. `ValidatedCopy`
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
Specifically, `sched::tests::a_slice_ending_before_a_host_runnable_thread_leaves_for_the_host`
publishes host work through `place_from_host`, delivers the owed reschedule
interrupt, advances a fake clock by one slice, and asserts a host-service exit
with the compute thread's registers retained. It passes on this branch.

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

## Linux verification

Both production witnesses were committed red before their fixes: the pipe
witness exited 101 with `Returned` instead of `Handback`, and the sleep
witness exited 101 after observing errno 14 for a retained input transfer.
The corrected IPC adapter suite passes all 26 tests. All three sleep
copy-in tests and the runtime continuation-routing test pass. The virtual
timer and host-service slice tests pass through the production scheduler
adapter with a fake CPU clock.

`just test-kernel`, `just clippy`, `just clippy-linux`, `just fmt-check`,
`just lint-domains`, and finally the full `just test` all exit zero with
`env -u RUSTC_WRAPPER CARRICK_SCCACHE=0`. The final kernel gate reports
3,080 passed tests across 40 suites, with seven existing ignored tests.
No sched-core code changed, so `just test-loom` is not applicable. The revised fixture passes the AArch64
musl compile check and builds as a static AArch64 ELF with
`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc`.
The first fixture build failed because it selected the x86 host linker;
selecting the installed cross-linker fixed that build configuration.

The first `just lint-domains` run rejected the two new bare `Debug` derives
in the glob-importing time dispatcher. Qualifying them through
`::core::fmt::Debug` fixes that census ambiguity; the focused sleep tests
and source authority-debt check against the original main base pass. The
final gate sequence passed after that correction. The live authority census
checked Linux CLI and runtime; its other host profiles remain pending.

Final gate logs are `/tmp/735-final-<recipe>.log` on ctb-w2, with exit codes
in `/tmp/735-final-gates.status`. The full host log includes the new pipe,
sleep and runtime-route witnesses passing; its final zero-test entries are
the serial partition of targets whose tests ran in the preceding parallel
partition. No gate was piped through an output filter, retried without a
fix, or run with reduced test concurrency.

HVF execution, five-of-five signed qualification, refreshed Docker evidence
and signed promotion remain outstanding. The unreceipted backend refusal
above also remains outside the proven fix. This is not issue closure.


## Independent review follow-up

The two P1 findings on the first handoff were valid. Sleep retained the input
but selected an ordinary interruptible owner wait. The pipe witness stopped
at EL1 handback; host completion still consumed bytes after a writability
check and before the actual copy. A typed transient refusal at that last copy
was collapsed to EFAULT.

The branch was rebased onto the fetched #739 branch while that PR remained
open. Its owner-wait policy, single killable-wake query and prepared-copyout
API are the only wait/copy mechanism used here. All original fixes were kept;
the owner-resume enum and contract surfaces were ported to the new base.
The scheduler test rewrite and guest fixture were unchanged by this rebase.

The extended sleep witness enters the real production owner park with a
second live thread holding the editor. With the old policy, handled SIGUSR1
queues the waiter before editor release (1 instead of 0). With the fix,
nanosleep and clock_nanosleep complete their retained zero-duration input
after release, then deliver the handler; SIGKILL still terminates before
release. The existing nonzero-duration input/prefix witness remains separate.

The host pipe completion witness initially consumed all six bytes and
returned EFAULT. The fix prepares a page-bounded destination permit before
the object transfer; only bytes secured by that permit can be consumed.
A refused prepare retains the original token and endpoint pin. Host
completion resumes it through #739's owner-memory wait, without an fd lookup
or replay. Cancellation drops the exact pin. The runtime witness holds a real
sibling editor, posts handled SIGUSR1, releases the editor, and verifies all
six bytes and the EL0 return. Its fatal variant verifies cancellation and pin
release without consuming data. Kernel witnesses also check the next EOF,
exact count, invalid-pointer EFAULT without consumption, and an unaligned
page-prefix read that leaves the suffix in the pipe.

The direct EL0 completion origin is retained explicitly: a read resumed from
an IPC wait record has no host syscall trap frame to complete. Its owner wait
uses that saved EL0 state and returns at the original SVC only after the
secured copy commits.

The broad copy-in/EFAULT sweep remains #711 slice 2, outside this change.
The signed commands above remain the required Mac qualification; portable
results from the earlier handoff do not certify this new artifact.

A second independent review caught a missing loader edge in that direct EL0
path: `park_host` retained host ownership, but the executor materializer still
required a mailbox syscall continuation. Extending the runtime witnesses to
consume the actual `ZoneSave` and call `TaskCpuResidency::materialize_with`
made both completion and cancellation fail at that production check. The
saved residency now carries `ZoneResumeOrigin`: guest-record completion,
host trap completion, or host EL0 completion. All loader paths validate this
origin against the record ownership and retained CPU frame. The read stays
host-owned while waiting; an ordinary IPC re-park returns to guest-record
ownership. The witnesses pass through materialization and check the direct
return PC advances from the SVC at 0x4000 to 0x4004. Wrong completion origins
are rejected. The second review found no further P1 in this correction.

Red evidence is `/tmp/735-review-materialize-red.log` (exit 101, both IPC
tests rejected by the old materializer). The corrected two IPC witnesses,
two sleep witnesses and residency tests pass. No scheduler interleaving or
sched-core code changed. Dedicated runtime supply/physical refusal and
owner-to-empty-pipe re-park schedules remain outside these witnesses; the
existing typed wait machinery serves those paths.

After #739 landed, the branch was rebased onto GitHub main. Every scheduler,
kernel, runtime, fixture and contract file in this fix was byte-for-byte
unchanged by that rebase: all fixes were kept, none dropped, and no code move
required a port. Main added only agent-dispatch/tooling changes outside this
slice. The earlier follow-up gate run passed kernel, Clippy, Linux Clippy and
formatting, then was stopped during domain lint for this rebase. Fresh gates
on the landed dependency are required; the interrupted run does not certify
the final branch. The earlier agent trailers now include the exact model name.

## Main-based follow-up verification and remaining gates

The landed-main branch passes the two IPC runtime witnesses, two sleep runtime
witnesses, five residency tests and eight focused kernel IPC tests. It also
passes `just test-kernel` (3,110 tests in 40 suites, seven existing ignores),
`just clippy`, `just clippy-linux` and `just fmt-check`, all with
`env -u RUSTC_WRAPPER CARRICK_SCCACHE=0`. Logs are
`/tmp/735-main-<step>.log`; completed exit codes are in
`/tmp/735-main-gates.status`.

The worker supervisor's total time budget was almost exhausted after the
required main rebase and fresh gates. Extension requests received no response.
Domain lint was stopped during its tooling build, and the foreground gate
script exited 143. This is an interrupted check, not a passing result or a
reported lint failure. The full `just test` has not run on this follow-up.
The earlier full host pass predates these review fixes and cannot certify them.
No load generator or VM was started. The interrupted gate process tree was
terminated before handoff.

A continuation must finish these gates, keeping the full test last:

```sh
env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 just lint-domains
env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 just test
```

No sched-core code changed relative to the landed dependency, so Loom is not
applicable to this slice. Signed HVF qualification remains on the Mac using
the one-artifact commands above. This branch has not been pushed, and the
requested verification is not complete.


## Round-2 review: native fatal custody without a mailbox request

The new P1 in the review of `c21986da6` is a completion-authority mismatch.
A pipe read resumed from an IPC record has `HostEl0` residency, no mailbox
syscall continuation, and Idle guest completion ownership. Both
`resume_owner_zone` and the `ResumeOwnerPhysical` arm called the same
cancellation helper, which required a RequestReady mailbox response and then
unconditionally called `retire_syscall`. Native SIGKILL therefore became a
runtime error instead of an irrevocable transfer to the native terminal owner.

`NativeOwnerWaitOrigin` now travels with both owner-wait phases and through
the runtime helper, shared engine and mailbox transport. HostTrap retains its
existing mailbox response and guest-token retirement. HostEl0 validates Idle
completion ownership, consumes only its IPC return marker, and stages entry
into the existing native fatal checkpoint without a syscall response or EL0
return. The retained IPC operation drops its pin without consuming pipe bytes.
The single killable-wake query and #739's native cancellation custody remain
the owners of the decision and terminal work.

The fatal entry PC also owns migration: a short register-preserving prefix
re-establishes the fatal selector in the destination executor's Idle mailbox
before branching into the existing signal hook. The source mailbox payload
is not task state. No new signal selection or terminal implementation exists.
The shared AArch64 adapter preserves GPRs and SP_EL0, stages ELR/SPSR and the
executor-local SP_EL1, and publishes the entry PC last.

Red evidence (VM-free, production at `c21986da6`):

- `serial_host_native_ipc_owner_wait_cancellation_from_el0` and
  `serial_host_native_ipc_physical_owner_wait_cancellation_from_el0` both failed
  with `threaded syscall retired without guest completion ownership` (exit
  101, `/tmp/735-r3-native-red3.log`). The physical case uses the runtime's
  actual scheduler; the initial fixture used a different scheduler and was
  corrected before recording this red result.
- The actual mailbox implementation, compiled into Linux runtime tests,
  failed `native_owner_cancel_from_el0_keeps_idle_without_syscall_authority`
  with `UnexpectedState { expected: RequestReady, actual: 0 }` (exit 101,
  `/tmp/735-r3-mailbox-portable-red.log`). Building the whole HVF crate natively
  on Linux was unavailable because of its macOS APIs.
- The emitted-vector interpreter started from a destination Idle mailbox with
  a nonfatal selector. Before the durable prefix it observed ordinary ESR
  `0xfffe` instead of fatal ESR `0xfffc` (exit 101,
  `/tmp/735-r3-migration-red2.log`).

The runtime witnesses retain a real six-byte pipe read, park on either exact
owner contention or an unready physical dependency, publish native SIGKILL
from a live sibling, and require native terminal custody without a runtime
error. They check zero copyout commits, an empty guest completion slot,
release of the operation's endpoint pin, and all six bytes still unread.
The zone case reloads the actual saved residency. Component witnesses cover
CPU capture/restore across executors, mailbox protocol authority, and actual
emitted hook execution in both IRQ modes; no HVF execution is claimed here.

P2 #2 (sleep remaining-time copyout) stays in #711 slice 2. P2 #3 remains
open: the host-compute test proves forwarded socket completion and counted
compute progress, but does not prove read enrollment preceded the write.
The guest has no existing enrollment notification; the startup sleep is not
such a proof. Adding a host admission rendezvous is outside this P1 slice.
The original exact signed commands above still apply; run them on a freshly
built, signed artifact containing this correction.
