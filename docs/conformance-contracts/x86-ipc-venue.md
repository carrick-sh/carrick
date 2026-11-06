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
