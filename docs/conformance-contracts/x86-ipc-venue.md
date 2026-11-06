# x86 IPC venue (#1756): red witness and remaining implementation

This slice adds a red-first real-KVM fixture for
`kernel.el1.ipc-two-process`. It does **not** implement the x86 venue.
The native x86_64 Linux oracle runs the same `native_pipe_vectors.S`:
exit 0, stdout `pipe-vectors=once\n`, no stderr. Child `writev` publishes
three vectors; parent `readv` scatters them into two vectors. A subsequent
nonblocking scalar read must return EAGAIN (11), then closing the parent's
last writer must expose EOF. All I/O is nonblocking and the child is finite.

The fixture is ignored with #1756 until implementation. Run explicitly with
`CARRICK_REQUIRE_KVM=1 cargo test -p carrick-vmm-kvm --test cpl0_initial_mm
in_zone_two_process_pipe_vectors_move_bytes_exactly_once -- --ignored --exact`.
The guest-exit budget bounds exits, not a parked carrier's wall time; a
bounded external test runner is still required.

The existing adapter in `carrick-el1-linux/src/ipc.rs` uses the shared
`carrick-pipe-core` and `carrick-fd-core` authority. Its production entry
currently requires an ARM `TrapFrame` and `Sched` whose zone and handoff
receipt carry `Aarch64ParkedContext`. `park_key` rewinds by ARM SVC length.
The x86 production dispatcher supplies neither an IPC venue nor this ARM
scheduler. Passing a venue alone cannot enable x86 transfer.

The remaining implementation should extract a context-neutral IPC execution
capability from that adapter, preserving one transfer state machine and its
owned token, pin, imported vectors and byte cursor. ARM and x86 should supply
only context capture, resumption PC and scheduler handoff mechanics. The
current adapter admits scalar read/write and writev but excludes readv;
readv must be added to the shared operation and retained copyout path.
The x86 carrier also needs the shared IPC authority mapped and published,
with complete descriptor namespace admission and fork/exit custody.

Preserve the existing lock order: short descriptor-table pin, then one
object's staged step; notify under the object lock, drop it before wake
delivery or parking. No table/object lock or copy permit may span a park.
A reviewer must check any new cross-crate lock order before implementation
is accepted.

Acceptance remains open: enable the real-KVM fixture, add served/refusal
census assertions, test a non-venue descriptor's counted ENOSYS, update
`x86_writev_remains_counted_enosys_under_strict_ring_first` with the oracle,
and run the requested lower-layer and real-KVM gates. The oracle above
proves bytes and EOF only; it does not prove a ring execution venue.

On the admitted base, real KVM runs the fixture and returns guest exit 90
(the `pipe2` stage) instead of 0. It therefore establishes the missing pipe
creation precondition, **not** a reached two-process vector transfer failure.
The native oracle reaches and passes every stage. Do not claim vector parity
from this red run; later witnesses must reach the transfer and count it.
