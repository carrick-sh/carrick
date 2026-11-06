# Exec child output through an in-zone pipe (#1507)

Contract: `kernel.el1.ipc-two-process`.

Alpine 3.20 BusyBox `seq` writes through musl stdio with `writev`, whereas
its shell builtin `echo` uses scalar `write`. A native x86 diagnostic of
BusyBox 1.36.1-r31 observed `["1", "\n"]` followed by `["2\n3\n", ""]`.
This diagnostic establishes syscall shape, not ARM oracle acceptance.

On admitted main, the ring adapter forwards ordinal 66. Native host-file
staging recognizes its in-zone pipe, leaves it in ring, and returns counted
ENOSYS because no ring transfer family claims it. This loses command output
without establishing that exec destroyed an endpoint.

The red VM-free binding `el1_ipc_writev_preserves_vector_order_on_a_pipe`
returned `(Forward, 1)` instead of `(Returned, 6)` before implementation.

Vector headers are imported once into a variable allocation in the existing
shared metadata pool. The operation slot owns that allocation; finishing or
cancelling the operation reclaims it before publishing slot availability.
Payload copying uses the same pipe transaction and aggregate byte progress as
scalar writes, preserving PIPE_BUF admission, pinned endpoints and partial
write continuation. Prefix offsets permit binary search on resume and linear
visits through the vectors crossed by each copy, avoiding repeated prefix
scans. No vector array lives on the EL1 stack.

VM-free witnesses require ordered bytes, no host calls, immutable headers
across a large blocked write, no replay, no prefix for a small atomic write
with insufficient room, and exact allocation reclamation after completion,
fault, invalid count and total-length overflow. A final writer close followed
by EOF checks that rejected imports do not retain an endpoint pin.

Signed Alpine command substitution, same-source native ARM Docker comparison,
and signed artifact promotion remain higher-layer acceptance requirements.
Eventfd vector I/O and vector reads retain their existing routing; this slice
implements pipe vector writes.

Vector import rejects nonempty payload ranges that overflow, exceed the
48-bit guest address envelope, or overlap the reserved EL1 window before
transferring any pipe bytes. This is address-range admission, not a page
presence probe: an unmapped but representable later segment still permits
the ordinary delivered prefix. Empty segments never dereference their base.
The production dispatcher witness
`el1_ipc_writev_invalid_payload_range_has_no_pipe_effects` requires errno 14,
an empty nonblocking pipe and exact storage reclamation after each rejection.

## Review corrections

Vector custody publishes initialized headers with Release and reads them with
Acquire before either transfer or reclamation. The Loom binding calls those
production custody methods and rejects observing published metadata with stale
header bytes. Token ownership continues to exclude concurrent mutation.

Header copy refusal follows EventFdWrite admission: release the operation and
pin before `refuse(... CopyInFault)`, with no pipe effect. Admitted main has
only boolean `carrick_core::UserCopy`, so the done/fault/not-yet outcome from
#1677 is not available here. This path must migrate with that shared outcome;
it does not introduce another copy outcome type. Invalid imported payload
ranges still return EFAULT immediately. The production dispatcher binding
refuses an unavailable header, then supplies it and completes exactly one byte.
A native child has no host syscall venue: a refused header therefore settles
EFAULT in ring instead of becoming counted ENOSYS. The two-process production
dispatch witness checks NULL, non-canonical and unavailable headers without a
pipe effect.

The host handback gathers physical page prefixes before locking the pipe.
An imported vector can fault between logical page boundaries; its transfer
therefore consumes the exact gathered prefix, rather than losing it through
a boolean whole-page copy. The handback binding requires one delivered byte
when the first three-byte vector begins at the final byte of a backed page.

The fork/exec witness now enters `dispatch_syscall_with_ipc` with registered
user buffers for the child's scalar/vector writes and the parent's read.
It no longer calls the IPC adapter directly.

X86's existing strict crossing set excludes writev (canonical 66/native 20),
and its IPC venue has no ARM frame. The reported P0 regression is refuted:
on admitted main, `route_shared` (dispatch.rs:658) does not claim 66,
`route_x86` (dispatch.rs:790) falls through to that route, and the unchanged
crossing census (crossing.rs:508) permits only 22, 62, 63, 64, 67, 68, 93 and
94. Both before and after this change, strict x86 therefore returns counted
ENOSYS. The production dispatch binding now witnesses errno 38, exactly one
native-20 refusal, and zero forwards. The shared route remains; no crossing
allowlist or ISA wiring-gap ceiling changes. This slice does not claim x86
pipe writev support.

## Vector payload invariant classification (#1684 ratchet)

`copy_vector_input` returns `VectorInputInvariant` only for operation-token,
header-custody or logical-range corruption. Guest copy refusal remains
`Ok(delivered_prefix)`, including zero bytes. The native adapter matches each
invariant explicitly and retains its existing fatal entry-binding disposition;
the host handback converts the invariant back to its original `IpcError`.
No guest errno, copy order, allocation, cursor or work budget changes.
`vector_input_copy_fault_is_a_prefix_not_an_invariant` checks zero, partial and
full delivery and rejects an invalid token before invoking the copy callback.
The guest-copy debt scanner and its ceilings are unchanged.
