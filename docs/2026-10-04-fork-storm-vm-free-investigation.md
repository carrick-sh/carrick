# Fork-storm: VM-free investigation

Base: `b148d69eb1135f55ab915ae6dff36c2d6c97576d`, Linux x86_64.
No runtime or kernel implementation fix is claimed. The deterministic
reductions pass on the main kernel. There is no red witness for the reported
signed failure, so this investigation stops at a capture handoff.

## Surface and authority

`fixtures/embed-el1-sched/src/threads.rs:1150` forks while eight siblings
create and join threads. Each child closes its pipe read end, reads
`/proc/self/task`, creates and joins a thread, writes eight bytes, then
calls `_exit(0)`. The parent closes its writer, polls, reads, and reaps.
The signed binding is
`crates/carrick-embed/tests/el1_sched.rs:4074`.

The observed missing report plus unreaped child does not prove a pipe bug.
The child must get through its own join before writing. Reaping uses repeated
`waitpid(WNOHANG)` (`threads.rs:1122`), so a single lost wait-enrollment edge
cannot explain both symptoms. A stuck child before write, an unpublished
terminal transition, or a scheduler wake that never becomes executable still
can. These are candidates, not diagnoses.

Linux semantic authorities are [fork(2)](https://man7.org/linux/man-pages/man2/fork.2.html),
[clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html),
[pipe(7)](https://man7.org/linux/man-pages/man7/pipe.7.html),
[poll(2)](https://man7.org/linux/man-pages/man2/poll.2.html),
[set_tid_address(2)](https://man7.org/linux/man-pages/man2/set_tid_address.2.html),
[wait(2)](https://man7.org/linux/man-pages/man2/wait.2.html), and
[exit(2)](https://man7.org/linux/man-pages/man2/exit.2.html).
Relevant existing contract families are `kernel.fork.filetable`,
`kernel.futex.contention`, `kernel.scheduler.runnable-progress`, and
`kernel.scheduler.preemption-lifecycle`. These reductions are characterization
tests, not a newly closed fork-storm contract.

## Forced schedules

`crates/carrick-kernel-example/tests/fork_clone_orderings.rs` exercises:

1. A sibling clone paused after reserving its exact identity, and again after
   preparing its resources. The leader replaces an old pipe with a fresh pipe,
   forks, polls, reads, and reaps while that clone remains paused. The child
   joins its own thread through `set_tid_address`/futex before reporting.
   After release, the sibling's new thread observes the leader's closes as
   EBADF, proving CLONE_FILES still names the live table rather than a snapshot.
2. The child report already written before poll starts: one poll dispatch.
3. The report written after the initial readiness check and registration
   preparation, but before enrollment: two poll dispatches, one read.
4. The report written after poll enrollment: the same bounded dispatch counts.
5. Child exit after the parent's wait scan but before enrollment. A sibling
   observer sees the durable zombie with `waitid(WNOWAIT)` before releasing the
   waiter. The consuming wait returns once; the next wait returns ECHILD.
6. Child exit while the parent holds another prepared fork transaction.
   Exit publication completes before that fork resumes.
7. Child exit while the parent holds a clone publication reservation. Exit
   publication and default SIGCHLD notification complete before clone resumes.

The seven tests contain eight schedules because the first has two pause points.
There are no sleeps or probabilistic stress repetitions. Every checkpoint uses
the existing five-second failure bound. Missing or unused checkpoints fail.
The child joins dispatch once: waking a futex continuation completes it without
restarting its syscall. Blocking poll and wait dispatch at most twice; report
reads dispatch once. Zombies are consumed exactly once.

The original harness held its dispatcher mutex across all clone preparation,
preventing a sibling fork from overlapping that phase. Preparation now owns the
kernel's exact reservation outside that backend mutex; publication remains
serialized with this backend's terminal paths and takes the kernel's explicit
publication reservation. Bounded pauses are confined
to this non-product backend. Production source is unchanged.

## Candidate orderings and limits

The following anchors refer to the base revision's unchanged production files.

| Candidate | Source seam | VM-free result / remaining limitation |
| --- | --- | --- |
| Wrong fd table copied during fork versus clone | `kernel/operations/thread.rs:127`, `kernel/objects/task.rs:52`, `kernel/objects.rs:2362` under `crates/carrick-kernel/src/` | Exact clone resources and fresh pipe survive both forced preparation overlaps. CLONE_FILES observes subsequent closes. No failure in the host graph. |
| Readiness published before enrollment | `dispatch/fs/pipe.rs:585`, `:612`; `kernel/continuation/wait_service.rs:1172`, `:1313` | Before-call, before-enrollment, and after-enrollment reports all arrive. The pipe's level state survives a missed edge in these schedules. Does not prove EL1 notification/host wake-index delivery. |
| Child exit before wait enrollment | `kernel/continuation/readiness.rs:459`, `:782`; `kernel/operations/exit.rs:865` | The captured child-scan generation preserves exit across the gap; zombie is consumed once. Notify follows exit reservation commit. Default SIGCHLD does not auto-reap. |
| Exit while parent is mid-fork or mid-clone publication | `kernel/operations/exit.rs:503`, `:865`; `kernel/operations/thread.rs:238` | Childless exit completes with the parent's task reserved, then both transactions finish. No topology or notification deadlock in these forced schedules. |
| Child's joining futex never wakes | `carrick-runtime/src/vcpu_loop/threads.rs:11`, `:797`; `carrick-kernel/src/el1_zone.rs:241` | Host futex clear/wake joins pass. The real runtime wakes the EL1 zone when admitted; the scripted backend uses its per-process host futex table. Zone placement/handback is untested by these scripts. |
| Wake arrives before scheduler settlement / task executes with the wrong MM | `carrick-runtime/src/vcpu_loop/zone.rs:274`, `:343`, `:369`; `binding.rs:1289` | Scripts own one host thread per actor and have no vCPU pool, guest zone, installed TTBR0, or cross-process in-zone switch. This candidate remains open. |
| Fork admission or lease drain strands a runnable child/sibling | `carrick-runtime/src/vcpu_loop/quiesce.rs:624`, `:707`, `:733` | Kernel reservation overlaps pass; runtime admission, lease drain, and executor claim/load are outside this backend. This candidate remains open. |

An apparently suspicious unclosed lifecycle ForkClosing gate is not established
as the cause: the current production `GuestLifecycleVenue::born_slot` at
`carrick-el1/src/personality/lifecycle.rs:621` declines EL1 clone births.
`serve_clone` backs out when that slot is absent (`:429`). Do not infer that
an ABI/test-only Born path ran in the failing artifact; capture its counters
and exact source first.

## Signed capture recommended to the director

Keep the exact signed test executable, fixture, source revision, hashes,
CDHash/LC_UUID, entitlements and DOF identity. Do not rebuild while it runs.
Keep default pool size, all eight storm siblings and the 16 rounds. Run IDs
and cleanup remain scoped; do not run Docker alongside Carrick.

Use the existing per-Linux-task script, with its built-in 45-second bound,
against the **exact already-signed libtest executable**, through the existing
external-witness route (`crates/carrick-cli/src/trace_cli.rs:278`). Set
`FORKSTORM_TEST_EXE` to the absolute `target/release/deps/el1_sched-<hash>` path
from the failing gate's executable inventory. Do not put a build/signing
launcher inside this 45-second capture window. A successful signed runner's
inventory is `target/test-results/carrick-embed-signed-artifacts.jsonl`; a
failed run does not publish a new successful receipt, so use the failing
gate's actual executable path and identity, not an older receipt.

Before execution, record identity from that file and the fixture:

```sh
shasum -a 256 "$FORKSTORM_TEST_EXE" target/embed-fixtures/el1-sched-aarch64
codesign -dvvv --entitlements :- "$FORKSTORM_TEST_EXE"
otool -l "$FORKSTORM_TEST_EXE"
```

From the same repository root, capture the exact signed test:

```sh
CARRICK_RUN_ID=forkstorm-flow-01 target/release/carrick trace \
  --require-script-exit \
  --script scripts/dtrace/hvpatch-guest-syscall-flow.d \
  --trace-out target/forkstorm-flow-01.out -- \
  --external "$FORKSTORM_TEST_EXE" \
  --exact el1_thread_lifecycle_fork_during_clone_storm \
  --test-threads=1 --nocapture
```

The tracer drops the witness to the caller's credentials and follows it with
`pid == $target || progenyof($target)`. Require nonzero returns and inspect
DTrace errors/drops. Preserve the test's own terminal result separately from
the D program's bound receipt. The full syscall stream has high perturbation
and may suppress the race; its timing is not performance evidence. Do not
treat one green instrumented run as closure.

The flow script's header predates the bounded executor pool. Its `self->`
service-begin/args correlation is local to one host service slice;
`syscall-return` carries no exact task identity, and a continuation can
complete on a different executor without another dispatcher call. Do not
attribute such a return using stale host-thread state. Cross-check its task
with the wait token and execution-generation ring records. If ambiguity
remains, add the exact-identity completion record specified below before
claiming a child wrote eight bytes.

If capture points to exit/SIGCHLD, the existing narrower script records
identity on service slices and distinguishes publication from delivery:

```sh
CARRICK_RUN_ID=forkstorm-sigchld-01 target/release/carrick trace \
  --require-script-exit \
  --script scripts/dtrace/hvpatch-sigchld-delivery.d \
  --trace-out target/forkstorm-sigchld-01.out -- \
  --external "$FORKSTORM_TEST_EXE" \
  --exact el1_thread_lifecycle_fork_during_clone_storm \
  --test-threads=1 --nocapture
```

Run these captures sequentially. The SIGCHLD script's 90-second bound is a
failed capture, not a pass. Default SIGCHLD requires no handler injection;
absence of `signal-inject` alone is expected in this fixture. Both existing
scripts are diagnostic and need live provider qualification on the gate box.

For a failure that disappears under tracing, capture the uninstrumented
carrier during the **first stalled report poll**, before the fixture's later
SIGKILL destroys the state. Run the same executable without tracing:

```sh
CARRICK_RUN_ID=forkstorm-core-01 "$FORKSTORM_TEST_EXE" \
  --exact el1_thread_lifecycle_fork_during_clone_storm \
  --test-threads=1 --nocapture
```

In another terminal, request the kernel graph before LLDB attachment:

```sh
target/release/carrick debug hvpatch-kernel --run-id forkstorm-core-01
target/release/carrick debug lldb-snapshot --run-id forkstorm-core-01 \
  --out-dir target/forkstorm-capture
```

The fixture only prints its round failures after finishing the whole loop;
waiting for that output is too late. Capture when the current report poll is
stalled, ideally before its 20-second deadline, or during the following
20-second reap window. Do not increase either guest deadline. This checkout's
`lldb-run` launches CLI runs, not external libtest executables; do not substitute
that binding for the exact signed witness.

Save a modified-memory core and all-thread backtraces. Preserve a degraded or
failed kernel snapshot as evidence. For embed, the libtest process itself owns
the carrier (`carrick-embed/src/carrier.rs:102`), rather than a CLI child. Its
runtime stamps `carrick:<CARRICK_RUN_ID>:` (`carrick-runtime/src/carrier.rs:513`,
`:568`), so the existing scoped snapshot command selects it. It detaches after
capture; the caller still owns cleanup. The existing ring supplies:

- `CLONESPAWN`: parent pid, child tid, errno;
- `HVPBLOCK`/`HVPBLOCK_ARG0`/`HVPBLOCK_ARGS`: blocked syscall, exact tid and args;
- `HVPWAITX`, `HVPWAITFD`, `HVPWAIT_TARGET`, PC/SP/LR: correlated wait identity;
- `HVPPEXIT_BEGIN`/`END`: process terminal publication;
- `FDOWNER`/`FDREF`: process-qualified endpoint retirement;
- `HVPEXEC_CLAIM`/`LOAD`/`BOUNDARY`/`SETTLEMENT`, `HVPSETTLE`: whether a runnable
  child was claimed, loaded, settled, or dropped with an unsettled claim.

Dump both lifecycle and high-rate rings; busy/gap/overwrite/torn ranges cannot
attest complete history. Join graph task/thread/mm/file-table generations,
not recycled pid/tid/fd numbers. Read the child's saved guest PC and its join
word through the child's exact MM; a guest VA is not a host pointer.

```text
(lldb) command script import /absolute/repo/scripts/carrick_lldb.py
(lldb) carrick eventring 8192
(lldb) carrick eventring --high-rate 8192
(lldb) thread backtrace all
```

If those records leave the wake seam ambiguous, add a bounded, allocation-free
event-ring family (with matching LLDB decoder) recording these exact fields:

| Point | Fields required |
| --- | --- |
| `clear_persistent_child_tid_and_wake` before/after copyout and wake | exact TaskKey/ThreadKey/ExecutionGeneration; owning MmId, installed MM/TTBR0; clear-child-TID GuestVa; copyout result; zone mm; wake count; handed RecordRefs |
| zone wake placement and `publish_zone_handbacks` | source TaskKey; target ThreadKey/generation; RecordRef incarnation; MM; before/after claim and park sequence; host/guest destination; scheduler wake result |
| continuation enroll/publish/settle | ContinuationId/token generation; exact task/thread/execution identity; wait source authority; observed wake generation; event; scheduler wake result and settled state |
| syscall completion before publishing the return | exact TaskKey/ThreadKey/ExecutionGeneration; syscall/completion-token identity; fd where applicable; signed return/errno; owning and installed MM |
| report write/readiness | exact task/thread; FileTableId, fd slot generation, description/object incarnation; byte count/result; readiness before/after; host subscription generation and notification publication/consumption |
| task exit/reap | exact child and parent TaskKeys; transaction/epoch; reservation participants; zombie publish; default/action SIGCHLD classification; notify result; consuming wait identity |

Do not add printf/eprintln or silently discard a scheduler wake error. Record
both successful and declined transitions so a missing event is distinguishable
from a refused operation. Keep hot storm events out of the lifecycle ring or
filter to forked child processes to preserve failure history.

Decide from the capture: no child write entered points to startup/join;
an eight-byte write with unread core bytes points to readiness or scheduling;
zero unread bytes points to endpoint identity/consumption; a zombie present
while WNOHANG repeatedly returns zero points to wait visibility; a live child
after its exit boundary points to terminal settlement. Only then build a red
witness at the implicated seam and correct its authority.

## Verification on this Linux VM

- `cargo test -p carrick-kernel-example --test fork_clone_orderings -- --nocapture`:
  seven tests, eight forced schedules pass on the unchanged base kernel.
  There is no red/green claim.
- `cargo test -p carrick-kernel-example --tests`: the new tests and earlier
  binaries pass, then the existing
  `unix_socketpair_local_shut_rd_wakes_epoll_with_epollrdhup` fails (expected
  one epoll event, observed zero). Cargo stops before the remaining binaries.
  The same exact test fails in a detached worktree at `b148d69eb`. The
  remaining `socket_receive`, `stdio_host_wait_contention`,
  `stdio_inherited_backpressure`, and `unicode_paths` binaries were then
  selected explicitly and all 29 tests passed.
- `just test-kernel`: the kernel library reports 2298 passed, ten failed,
  one ignored, 138 filtered. A detached base run with
  `cargo test -p carrick-kernel --lib -- --skip serial_host` reproduces exactly
  the same ten failures (memfd/proc reopening, lseek, writable host mappings,
  AF_UNIX metadata, epoll edges and large host writes).
- `cargo clippy -p carrick-kernel -p carrick-kernel-example --all-targets --no-deps -- -D warnings`:
  blocked by eleven diagnostics in unchanged Linux kernel code. The narrower
  `cargo clippy -p carrick-kernel-example --all-targets --no-deps -- -D warnings`
  exits zero; dependency and Linux-inapplicable Clippy configuration warnings
  remain visible.
- `just fmt-check` and `git diff --check` pass.

The director confirmed the pre-existing Linux failures are handled on other
branches and asked to retain this characterization coverage. No signed/HVF
or Docker tests ran here. `just accept --phase host` includes an unconditional
`carrick-vmm-hvf --lib` step and continues after failures, so it was not run
under this task's explicit prohibition on HVF tests. No acceptance receipt
is claimed.
