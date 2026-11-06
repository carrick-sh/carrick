# x86 IPC venue (#1756): red witness and remaining implementation

This work adds a red-first real-KVM fixture and shared retained scatter
copyout for `kernel.el1.ipc-two-process`. It does **not** implement the
x86 execution venue.
The native x86_64 Linux oracle runs the same `native_pipe_vectors.S`:
exit 0, stdout `pipe-vectors=once\n`, no stderr. Child `writev` publishes
three vectors after a one-byte scalar `write`; parent `read` consumes that
prefix and `readv` scatters the six vector bytes into two vectors. All four
transfer entry points therefore belong to the same witness. A subsequent
nonblocking scalar read must return EAGAIN (11), then closing the parent's
last writer must expose EOF. All I/O is nonblocking and the child is finite.

The fixture is ignored with #1756 until implementation. Run explicitly with
`CARRICK_REQUIRE_KVM=1 cargo test -p carrick-vmm-kvm --test cpl0_initial_mm
in_zone_two_process_pipe_vectors_move_bytes_exactly_once -- --ignored --exact`.
The guest-exit budget bounds exits, not a parked carrier's wall time; a
bounded external test runner is still required.

The adapter in `carrick-el1-linux/src/ipc.rs` uses the shared
`carrick-pipe-core` and `carrick-fd-core` authority. Its transfer and epoll
engines now take `IpcExecution`, whose associated context and frame need not
be ARM types. `IpcFrame` separates canonical family decoding from the native
ordinal retained for refusal accounting. The existing ARM `Sched` implements
this capability and owns its SVC rewind, register restart marker and handoff.
The x86 production dispatcher still supplies neither an IPC venue nor an
execution capability. Passing a venue alone cannot enable x86 transfer.

The capability preserves one transfer state machine and its owned token,
pin, imported vectors and byte cursor. Execution implementations supply
context capture, resumption PC and scheduler handoff mechanics. Owner-wait
enrollment remains held across park so its source cannot retire between the
snapshot and queue enrollment. The extraction adds no lock order. The
adapter now admits scalar read/write and both vector directions on pipes.
Readv requires native ring custody (legacy handback has only contiguous
output permits). Without that owner it declines before any pin or effect.
Readv uses the same imported headers and logical byte cursor as writev,
and the same staged pipe transaction as scalar read. A failed scatter output leaves its incomplete pipe buffer unread; earlier
complete buffers keep their committed cursor. The vector range walker remains one binary
search followed by the touched vectors, without rescanning earlier headers.
The x86 carrier also needs the shared IPC authority mapped and published,
with complete descriptor namespace admission and fork/exit custody.

Preserve the existing lock order: short descriptor-table pin, then one
object's staged step; notify under the object lock, drop it before wake
delivery or parking. No table/object lock or copy permit may span a park.
A reviewer must check any new cross-crate lock order before implementation
is accepted.

Acceptance remains open: enable and pass the real-KVM served fixture, update
`x86_writev_remains_counted_enosys_under_strict_ring_first` with the oracle,
and run the requested lower-layer and real-KVM gates. The oracle above
proves bytes and EOF only; it does not prove a ring execution venue.

On the admitted base, real KVM runs the fixture and returns guest exit 90
(the `pipe2` stage) instead of 0. It therefore establishes the missing pipe
creation precondition, **not** a reached two-process vector transfer failure.
The native oracle reaches and passes every stage. Do not claim vector parity
from this red run; later witnesses must reach the transfer and count it.

The vector witness now asserts the terminal census as well as guest bytes:
three scalar reads and one call in each vector direction must be served,
with zero forwards or refusals for those operations. At least the child's
scalar pipe write must be served; the final stdout diagnostic may cross.
Service arrays use canonical ordinals, while refusal arrays use native
x86 ordinals. This assertion remains behind the same ignored red fixture
until the production venue exists.

`non_venue_writev_is_counted_without_host_crossing` independently calls
native ordinal 20 on host-backed stdout, without requiring pipe creation first.
It requires one root ring refusal, no carrier refusal, no served vector
write and no host forward. Its same-source native Linux oracle is compiled
with `-DNATIVE_ORACLE` and requires result 1 and stdout `!`; Carrick requires
ENOSYS (38) with empty output for the non-pipe venue under strict ring-first.
Both variants exit 0 when their own contract holds. An invalid fd would not
prove this boundary: a complete namespace must settle it as EBADF (9).
This independent
refusal witness does not demonstrate pipe service.

## Shared scatter copyout prerequisite

`el1_ipc_readv_scatters_and_consumes_each_byte_once` fails before the change
with `Forward` instead of a returned six-byte result. It passes after shared
scatter copyout is enabled. The production adapter tests also cover a payload
fault after two delivered bytes and an owner wait after one delivered page.
A fresh native Linux oracle requires errno 14 with all six bytes unread for
a fault inside the first buffer, or a 4096-byte result with the failing
six-byte buffer unread after one complete buffer. The fault witness was red
at result 2 rather than errno 14 before committing scatter per pipe buffer.
The latter keeps two live MMs, changes the original guest vector headers
while parked, and checks exact cursor resumption or a short prefix if the peer
drains the source. Normal operation retirement reclaims the vector allocation.
These are VM-free adapter proofs, not x86 execution or signed HVF evidence.

Readv's shared family route cannot enter the scalar-file fallback: an iovec
array is not a byte buffer. A declined non-venue descriptor stays under the
existing counted-refusal policy. No crossing allowlist or lock order changes
are made by this prerequisite. X86 still supplies no IPC venue or matching
execution capability, so its acceptance witness remains red at pipe2 and its
writev counted-ENOSYS invariant remains unchanged.

## Shared execution-capability prerequisite

The production ARM entry now uses the generic transfer engine for scalar and
vector I/O and epoll. `IpcExecution` exposes the exact context-typed zone,
running slot/task and counters, the existing wait primitives, clock conversion,
and the park/wake transport. Native ordinal retention is distinct from
canonical family selection; neither ISA may substitute its canonical syscall
number for the original refusal census index. No x86 transfer implementation,
window mapping, descriptor namespace admission or creation path is claimed by
this prerequisite. Existing shared IPC and two-live-process owner-wait tests
remain the lower-layer witnesses; the real-KVM acceptance remains red.

## Shared descriptor lifecycle prerequisite

`file_table::DescriptorNamespace` now owns the fork and retirement sequence
for both native execution services. ARM supplies its existing IPC binding;
x86 currently supplies no IPC binding. Delegated-map inheritance, ring-table
fork/publication, delegated rollback on publication failure, owned ring-table
retirement and boundary-work publication have one implementation. This moves
the existing ARM policy without changing its authority or lock order: the
map snapshot releases its mutation guard before the fd-core fork, publication
and rollback. Retirement releases directory custody before retiring the ring
table, then retires delegated descriptions. Neither lock spans the other
operation. The x86 file-region lifecycle witness now calls this production
owner and verifies child retirement preserves the live parent's descriptions.
The existing ARM native-fork witnesses still exercise complete ring namespace
inheritance, publication failure rollback and last-writer EOF through this owner.

This prerequisite does not install x86's IPC mapping or wire its transfer
execution capability. In particular, x86's `ipc: None` is an explicit remaining
admission gap, not a second IPC authority or a claim of pipe support. The real
KVM witness and counted-writev invariant remain unchanged until those parts
are implemented.

## Execution-owned queue completion

The generic execution capability also owns detached queue completion delivery.
`IpcExecution::deliver_completion` is required: the shared observation and
operation-slot release paths cannot silently choose the ARM task aperture.
ARM's execution implementation retains its existing completion transport.
Native operation retirement receives that callback explicitly from its service
owner, including cancellation after retained copyout. Object state, release
revision publication and queue membership remain with the shared owners.

`ipc_operation_completion_uses_execution_transport` drives the production
transfer entry against an eventfd and an exhausted operation arena with a real
release waiter. Before wiring the callback, the call returns eight bytes and
wakes its waiter but fails `retirement bypassed the execution transport`.
This is a VM-free transport witness, not x86 venue acceptance. Its initial
unmapped simulated output failed with errno 14; that fixture error was
corrected before recording the transport red result.

This step does not supply the x86 execution adapter, IPC mapping or descriptor
admission. Final-description release transport is now explicit as described below;
the x86 venue must still supply its task publication and wake mechanics. Pipe creation and the real-KVM served
fixture remain unresolved; no x86 pipe-service claim is made.


## Execution-owned final endpoint release

Native refusal cleanup and native service cancellation now receive an explicit
wake-effects callback alongside detached queue completion. Dropping the final
operation pin releases the backing through the shared fd/pipe owner and sends
its readiness wakes through that callback. `IpcExecution::deliver_release_wake`
is required for an execution adapter. ARM supplies its existing scheduler
transport, including native descriptor close/dup and cancellation callers.
The shared release owner retains its lane notification and deferred-work policy;
no object/table lock survives into transport delivery. The bounded lane and
epoll traversal is unchanged.

`native_final_pipe_pin_release_uses_execution_transport` enters the public
transfer adapter on an empty pipe. Its execution venue closes the numeric read
descriptor after the operation has pinned it, then refuses park. Production
native refusal cleanup returns counted ENOSYS (38), retires the final reader
reference and must invoke the execution's release-wake callback. Before the
callback is wired, it reaches the same result and endpoint retirement but fails
`final endpoint release bypassed execution transport`. The test binds the
writer notification lane without inventing a blocked writer. It proves native
cleanup transport, not two-process guest scheduling or an x86 execution venue.
An independent callback counter separates final release from ordinary queue
completion, which may also occur during the call.

The production x86 adapter, shared IPC mapping, complete namespace admission,
pipe creation and passing real-KVM served witness remain required for #1756.
