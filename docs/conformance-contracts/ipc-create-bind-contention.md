# Create admission contention (#1669, Fix 1)

Status: design for review; the continuation is not implemented. Fix 2's
object ceiling, readiness-domain sizing and metadata separation stay intact.
Contract: `kernel.el1.ipc-two-process`; epoll creation also belongs to
`kernel.el1.epoll-zone`.

## Required result

Linux pipe2, eventfd2 and epoll_create1 must not expose Carrick's internal
wait-binding contention as an errno. The same saved syscall must finish
with its original flags, initial value and output address. Contention must
release execution capacity, subscribe to the actual holder's unlock and
recheck once after enrollment. No polling, host readiness pipe, worker
parking or unrelated global serialization is admissible.

The production-entry witnesses in `dispatch/fs/tests.rs` inject one bind
Busy and require the original call to succeed. Pipe creation checks two
distinct fds and cleanup; eventfd creation checks descriptor publication
and cleanup. Epoll creation checks that the resulting description retains
its zone authority: returning an fd after discarding the Busy error is
also a failure. These are red requirements, not proof of a continuation.
A real held-lock schedule is still required to prove the suspended branch.

## Existing mechanisms and the missing producer

Memory-root refusal retains `ReservationBusy { wait, holder }`. The
provider observes an admitted MM source before its failed probe;
`root_refusal` and the completed-host-venue path return
`DispatchOutcome::OwnerMemoryWait`. The runtime enrolls the authenticated
owner dependency, retains the syscall and releases its executor.
Zero-progress IPC and pipe operations likewise retain their operation
through the shared scheduler notification protocol.

The neutral front door is `refusal::ReleaseTicket::park_and_rerun`.
Completion-enabled object queues own the existing intrusive admission
handoff chain. Their unlock owner drains deferred enrollment and delivers its
effects after unlock; `ObjectNotificationTicket::park_host_rechecked` uses that same
chain when enrollment meets queue contention.

The legacy queue used by `HostIpc::bind_waits` is different:

- `bind_object_wait` explicitly rejects a completion-enabled queue.
- `lock_object_index` acquires legacy lock word 1. A fallible policy returns
  only `ObjectWaitError::Busy`, without an observed revision or source.
- `ObjectWaitGuard::release_with` with no completion venue just clears
  the lock. It publishes no release notification or deferred handoff.
- `HostLockWait` currently spins/yields indefinitely, so production
  contention can retain a pool worker even before errno conversion.

Consequently there is no existing bind-release receipt to pass into the
owner-wait runtime. Reusing an MM receipt would authenticate the wrong
producer. Retrying Busy immediately in a loop would retain capacity and
would not establish release custody.

## Proposed shared change

Extend the existing scheduler admission handoff protocol to cover legacy
queue binding. Do not add a separate host callback registry or waiting
system. The queue's actual unlock owner must inherit deferred admission
custody and deliver it through the existing host/guest completion venue.
An unlocked-before-enrollment race returns the owned operation for one
immediate rerun. Enrollment must also work before the queue's first object
generation is bound; assuming an already admitted object source is wrong.

This changes the shared queue-lock protocol: legacy lock word 1 and
completion-owned lock word 2 currently have different release obligations.
The new mode and its handoff custody need a reviewed protocol definition
and an `OBJECT_WAIT_PROTOCOL`/ABI-fingerprint update before implementation.
All existing host and guest queue guard releases must implement that one
protocol, including cancellation and the release-before-post race. The
existing admission chain's linear population bound must remain enforced.

Carry an owned pending creation through a shared dispatcher continuation.
It retains the IPC authority, allocated object, completed binding lanes,
original syscall arguments and exact task/file-table authority. No fd or
user output is published before both bindings complete. A pipe output
permit must be dropped before suspension and prepared again on resumption.
Cancellation releases the unpublished object and only its admitted lanes;
a successful lane must not be rebound with the same generation. Retain
the object across the wait; do not allocate a replacement object on
resumption. Its lane cursor skips every successfully admitted lane,
avoiding same-generation rebind and repeated allocation on contention.

Keep guest limit errors separate from the retained contention type; that
type must have no errno conversion. Epoll admission must propagate it
through `epoll_zone::admit` and `new_epoll_description` rather than losing
it through `map_err(|_| Exhausted)` and `.ok()`.

## Required evidence after the protocol review

In addition to the three production-entry Busy-once witnesses, hold a real
bind lock, enroll the original create operation, and prove no completion
or errno before release. Unlock must wake that exact operation; a release
between miss and enrollment must rerun immediately. Cover partial lane
binding, cancellation, first admission, reuse, and two live callers.
Counters must show bounded probes and handoffs, without polling or leaked
objects/descriptors. Exercise host and guest unlock venues in the shared
scheduler tests, then the retained dispatcher/runtime continuation.

Run the requested VM-free/kernel/host partitions, clippy, formatting,
CPL0 build, contract-change and authority-debt gates with JOBS=3. No HVF is
available on this worker. The director still needs the signed gate and
PID-1 pipemass runtime evidence on the final artifact. Red witnesses or a
design review do not close Fix 1.
