# One syscall operand authority (#1396)

Status: proposed design for independent review before implementation. This
change contains documentation only. It does not establish runtime acceptance
or close the migration issues. The owner decision on #231 (2026-11-01) makes
this descriptor the implementation of #1363, rather than a second table.

## Problem and current seams

Today syscall metadata, output preparation and retained completion each know
part of a syscall's user-memory contract. A handler can still describe a
pointer independently and turn an internal owner wait into EFAULT (14).

These references describe the admitted main used for this design; they are
review navigation, not an executable inventory or acceptance receipt:

- `crates/carrick-abi/src/syscall.rs:280` generates canonical constants and
  metadata from `define_aarch64_syscall_table!`. Its private x86 identities
  start at line 290 and must also receive explicit operand descriptions.
- `crates/carrick-personality-linux/src/crossing.rs:401` evaluates crossing
  policy. Permission to cross is separate from authority to access memory;
  an operand declaration must never expand this allowlist.
- `crates/carrick-guest-mem/src/lib.rs:495` exposes `GuestMemory`, including
  `prepare_write` and resumable reads. It currently permits arbitrary ranges.
- `crates/carrick-guest-mem/src/prepared.rs:138` distinguishes limits, faults,
  physical waits, owner waits and supply; line 153 defines the non-suspending
  prepared-write capability. Its bounded stream permit is not an arbitrary
  whole-syscall reservation.
- `crates/carrick-kernel/src/dispatch/copyout.rs:1` explains preparation before
  effects; line 67 defines independently constructed `UserSlot` ranges.
  Preparation may park before effects, while an invalid destination can still
  fault at commit according to the syscall's effect ordering.
- `crates/carrick-kernel/src/kernel/continuation/output.rs:18` binds completion
  to the exact task, thread, MM and ASID generation. Line 110 owns retained
  output; its operation variants currently describe completed waits, fd waits,
  recvfrom address output and directory reads separately.
- `crates/carrick-xtask/src/copyout_debt.rs:1` documents the syntactic ratchet
  and its alias/wrapper blind spots; line 22 selects its ceiling ledger and
  dispatcher scope. Removing a scanner hit alone does not prove migration.
- `crates/carrick-hal/src/x8664_arch.rs:1048` normalizes x86 syscalls;
  `crates/carrick-x86/src/engine.rs:1083` consumes that normalization.
  `crates/carrick-abi/src/lib.rs:2280` checks ARM stat layout and the following
  assertions check the separate x86 stat layout. Canonical identity alone
  cannot select a wire layout.

## Descriptor model

Extend the existing metadata declaration to generate `SyscallOperands` in
`carrick-abi`. A generated closed syscall identity enum allows an exhaustive
match: `CanonicalNr` is an integer newtype, so matching it with a wildcard
would not prove coverage. Conversion from a raw ordinal returns either a
known identity or an explicitly unsupported identity. Every declared syscall,
including deferred calls and private x86 canonical identities, must have an
explicit operand status. Unsupported must not masquerade as an empty list.
A true scalar-only call explicitly declares no user-memory operands.

Descriptors are immutable, allocation-free Linux ABI data. They contain no
host pointer, scheduler dependency or VMM authority. Proposed vocabulary:

| Operand | Required declaration |
|---|---|
| Path | Argument index, NUL termination, bound, null/empty-path policy |
| Input buffer | Pointer index, checked length expression, access condition |
| Fixed input | Pointer index, wire-layout identity, optionality |
| Output buffer | Pointer index, capacity expression, committed-length rule |
| Fixed output | Pointer index, wire-layout identity, completion condition |
| Iovec | Vector pointer/count, element layout, payload direction, ordered prefix |
| Msghdr | Header layout, nested name/iovec/control shapes, value-result fields |

Use typed argument indices, operand keys, `GuestVa`, `GuestLen`, directions
and layout IDs. Length expressions cover scalar arguments, checked
multiplication, captured value-result words and bounded decoded fields. Reject
address, sum and product overflow before allocating. Output capacity and actual
result length are distinct: `read` authorizes arg2 bytes at arg1 but publishes
only its successful prefix; `write` consumes arg2 bytes at arg1 and has no
memory output. Length-zero buffers must not force pointer validation.

Nested graphs have finite depth and checked population/byte limits derived
from Linux ABI limits and existing service windows. Capture each pointer and
length once at its Linux-defined intake point; never chase a changed header
when resuming. Input/output aliases share staged backing where required;
ordered overlapping outputs follow the syscall's declared publication order.
Do not silently merge overlapping ranges into a different write order.

Command-dependent calls (`ioctl`, `fcntl`, `prctl`, socket options, SysV control)
require typed selector branches in the same descriptor source. Unknown commands
use the syscall's existing unsupported-command result without following opaque
pointers. `execve` needs bounded path/vector/string nesting; futexes and robust
lists require explicit live shared-memory/lifecycle access semantics rather
than snapshots. Remote-MM syscalls require an explicit target authority, never
an implicit current-MM fallback. These are mandatory review cases for the whole
table, not reasons to add an unrestricted pointer escape hatch.

Wire-layout selection takes a captured guest ABI, separately from host ABI and
canonical ordinal. Size, alignment, field offsets and codecs belong to ABI
records in `carrick-abi`; no Rust struct cast from byte-aligned staging storage.
The descriptor selects the codec for both intake and output. Host libc records
are translated through that codec, never copied as guest wire bytes.

## One retained operation

`StagedOperation` is the move-only owner of descriptor identity, captured guest
ABI, scalar arguments, staged input bytes/read cursor, output slots and bytes,
completion result, publication cursor and exact execution identity. Place the
Linux descriptor interpreter shared by ring and host in an ISA-neutral Linux
crate; keep generic range preparation and memory capabilities in the existing
shared guest-memory/neutral layers. Do not put Linux operand rules in HVF or
make a neutral crate depend on the Linux personality. Host integration in
`carrick-kernel` must consume the same interpreter, not recreate its rules.

Implement by moving/generalizing existing retained-output machinery. An
operation-specific resource (socket description, dequeue reservation, directory
cursor, accepted fd or wait result) can remain a typed payload, but cannot own
a second pointer/length list. It refers to descriptor operand keys. An accepted
socket waiting on copyout retains that socket and its cleanup obligation;
resuming must not call accept again or look up a recycled fd number.

The state transitions are intake, ready, executing, completed, publishing and
settled; a suspended wrapper owns exactly one typed dependency plus the state
to resume. No clone duplicates effect or completion authority.

1. Resolve active operands and stage inputs through exact live owner authority.
   A refused read retains its completed prefix and one read continuation.
2. Give the handler a staged view with named inputs and `op.output(key)`.
   Outputs expose bounded slots, not writable guest addresses. A handler cannot
   request a different pointer or more bytes than declared. Scalar validation,
   pointer validation and effect ordering must retain Linux error precedence;
   do not eagerly fault every pointer before checking an invalid fd or command.
3. Reserve the appropriate bounded output unit before irreversible consumption,
   or retain an owned completed effect when the family requires later copyout.
   The type of the operation state prevents replay after that transition.
4. Freeze the result and produced output; publication uses exact owner
   preparation and revalidates task/thread/MM generations on every resume.
5. Return the original result only after required output completion, or settle
   according to the syscall's genuine-fault/cancellation/partial-result rule.

OwnerWait, Supply and Physical remain typed dependencies, not EFAULT. Release
execution capacity, enroll on the existing release notification, probe once,
and resume that operation. Drop permits, editors and object locks before
parking. Ordinary signals do not convert internal MM contention into EINTR;
fatal cancellation uses existing terminal custody and drops unpublished bytes
and resources once. Stale or invalid identity is an invariant failure, not a
license to restage against a new MM after exec.

### Meaning of atomic completion

Atomic completion means one owned completion decision and no replay, lost output
or successful return before the declared outputs settle. It cannot promise
simultaneous visibility of arbitrarily large user buffers to sibling threads.
For a bounded multi-output record, prepare all participating ranges together
before committing; a preparation refusal publishes nothing in that unit.
Prepared commit cannot suspend. For streams, preserve Linux-valid prefixes with
an exact cursor across bounded units; never roll back bytes already visible or
pretend the whole buffer fits one MM portal permit. Multi-permit operations
retain completed data and resource custody between units. Error outputs such as
an interrupted sleep remainder are explicitly selected even on error results.

Review must confirm this interpretation against the owner's atomic-completion
requirement before code. Whole-call transactional visibility would require a
new cross-page memory protocol and would conflict with existing partial-copy
contracts; this design does not claim that protocol already exists.

## Replacement and enforcement

#1363 builds crossing staging directly from `SyscallOperands`. A staged
`GuestMemory` facade can bridge a migrated handler signature, but its capability
is only the descriptor's active ranges. It never falls back to raw memory for
an undeclared read or write. Eventually handlers take the narrower staged view.
Ring-served calls use the same declaration without gaining permission to cross.

Replace independent `UserSlot` construction and retained range lists family by
family with descriptor keys. Keep low-level prepared writes as the mechanism,
not a competing operand authority. Existing #744/#986 payload ownership moves
into the operation. #711's ratchet remains during migration with monotonically
decreasing per-file ceilings; each migrated family removes its old path in the
same change. Extend enforcement to forbid direct memory capabilities in migrated
handlers, including helper/alias bypasses and ring paths outside today's scope.
At zero, delete the scanner, ledger and gate wiring together. Do not bless
`op.output` by spelling alone or reset ceilings after moving files.

The owner brief's 95-site count is historical: current ceiling totals must be
computed from the live ledger by the gate. No new pinned site list is needed.

## Landable slices and proof

The following are proposed dependencies, not authorization to implement before
independent design review. The whole descriptor table uses the owner's size-cap
exception; family migrations remain independently reviewable below the cap.
Use native GitHub stack tooling if layers are dispatched together.

| Slice | Removal/replacement | Red-first production witness |
|---|---|---|
| 1. Complete descriptor and codecs | Generate every canonical/private identity beside metadata; no private #1363 table | Missing entry fails exhaustiveness; wrong arg/length/layout fails generated audit on both ABIs |
| 2. Operation and crossing integration | Move retained completion and wire crossing staging to the shared interpreter | Production crossing refuses undeclared range; Busy once retains input snapshot, then succeeds without a second effect |
| 3. Fixed records, paths, value-result words | Migrate stat/time/identity and simple fs output; remove their ad-hoc ranges | Both stat layouts, optional NULL, invalid fd precedence, length mutation, second-slot refusal and exact output sentinels |
| 4. Readiness and consuming records | Migrate wait/epoll/directory and fd creation outputs | Completed wait is not reaped twice; accepted fd survives suspension/close/reuse; second page refusal preserves original readiness |
| 5. Streams and vectors | Migrate read/write/readv and transfer families | Default executor pool exhausted by producers; two live MMs, COW, sparse vectors, partial fault, no prefix replay |
| 6. Message/control families and retirement | Migrate msghdr, socket options, queues, SysV, command-dependent and lifecycle operands; delete zero debt | Nested iovec/control aliases, truncated ancillary data, SCM resource cleanup, fatal cancellation and command/layout coverage |

Each slice extends existing contracts `kernel.copyout.owner-refusal`,
`kernel.memory.owner-wait`, `kernel.fs.directory-copyout` or
`kernel.el1.arm-ring-first-crossing` as applicable. Add a proposed
`kernel.syscall.operands` contract before implementation for descriptor coverage,
access confinement and staging work. Register actual bindings and capture red
results through production dispatch/crossing entry points before fixes. This
document does not register hypothetical passing bindings.

A generated handler census must run every registered handler through its staged
view with representative selector branches and assert reads/writes are contained
in the active declared ranges, including nested ranges and error outputs.
Missing fixture/selector coverage fails the census; deferred/unrouted syscalls
must prove refusal without memory access. Compare an independent Linux fixture
oracle as well: a descriptor and a handler making the same mistake can pass a
self-consistency test. Inject an undeclared access to prove the guard is live.

Structural counters are per operation/generation: staged bytes, decoded vector
elements, page preparation units, backend effects, park/enroll/resume and output
bytes. Require zero repeated consumed effects and zero recopy of published
prefixes. At three or more scales bound traversal by O(operands + elements +
pages + bytes), with bounded outstanding window storage rather than capacity-
sized staging for every large stream. Check overlapping and zero-sized vectors
so coalescing cannot hide quadratic work. Derive numeric coefficients in the
first implementation from the algorithm and measured scaffolding; never widen
existing budgets to accommodate the migration.

## ARM/x86 parity and acceptance

Normalize syscall identity and preserve guest ABI before descriptor lookup.
Private x86 calls need explicit entries, not ARM reinterpretation. Run the same
VM-free handler census for ARM64 and x86_64 wire records, including stat, iovec,
msghdr, time and command-specific layouts. Assert wire sizes and offsets at
compile time and compare emitted bytes to ABI-specific native Linux fixtures.
HAL changes retain only register/ordinal mechanics; routing, staging, refusal
and continuation logic stay shared. Guest architectures must not select host
`usize`, alignment or libc layout. Compat ABIs not currently supported must
receive explicit refusal rather than accidental LP64 decoding.

Workers run affected regular and serial_host suites, contract-change and
source-only authority-debt checks, pre-push clippy, plus macOS cross-checks for
macOS/HVF code and Linux/KVM checks for HAL/KVM code. The director independently
reviews each shared-kernel layer and runs the portable and signed gates at the
stack top. Signed ARM and real x86 KVM witnesses must prove the same suspension,
identity and completion cases through production entry points. Run applicable
native Linux differential phases serially with Carrick, then promote one exact
signed artifact through probes, smoke and full conformance. Compare populations
as well as failure sets. This design-only PR needs no runtime demonstration.

## Risks and review decisions

- **Observable ordering:** eager staging can change errno precedence and race
  visibility. Each descriptor needs conditional access timing, not just size.
  Review read/recv partial faults, EINTR remainders and invalid later outputs.
- **Memory amplification:** snapshotting an unbounded readv/writev or msghdr can
  exhaust memory. Bound metadata and stream windows without reducing Linux
  transfer sizes; retain cursors rather than recopying prefixes.
- **Authority drift:** a completed effect must never resume in a recycled MM,
  thread or fd. Preserve exact binding and resource generations end to end.
- **False confidence:** exhaustive declarations do not prove semantic accuracy.
  Require independent Linux bytes/errno observations and production tests;
  mocks alone do not prove carrier or page-table behavior.
- **Persistent pointers:** shared futex words, robust lists and lifecycle writes
  cannot be modeled as ordinary snapshot inputs. Review their explicit access
  mode before claiming the descriptor is the only authority.
- **Migration boundaries:** an unmigrated handler cannot obtain staged access
  plus unrestricted fallback. Limit legacy access to the remaining unmigrated
  families, enforce that boundary and remove it at zero.
- **Atomicity:** independent review must settle the completion-unit definition
  above and confirm error/overlap publication order. No all-buffer atomicity or
  runtime parity claim is established by this document.

After design review, record the accepted decisions on #1396 before dispatching
slice 1. The subsumed issues (#711, #744, #746, #986, #993, #538, #539, #540,
#708, #775, #818, #970 and #1318) remain evidence sources until their actual
paths and acceptance obligations have migrated; a design post alone closes none.
