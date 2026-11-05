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
