# One syscall operand authority (#1396)

Status: round 2 proposed design for independent review before implementation. This
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

The ring is part of the same migration, not a later adapter exercise:

- `carrick_core::personality::UserCopy` erases copy failure to `bool`;
  `UserMemory::copy_in` and its convenience methods accept caller-built ranges.
- `crates/carrick-el1/src/file.rs` implements
  `copy_{to,from}_user_guarded`; the ARM and x86 user-access veneers reach it.
- `crates/carrick-x86-cpl0/src/native_process/user_copy.rs` and
  `src/linux_personality.rs` expose CPL0 copying and personality integration.
- `crates/carrick-core/src/mm/transaction/user_write.rs` owns exact-MM write
  selection, supply and progress. Keep that neutral mechanism; remove its
  availability as an independent syscall range authority.

The review estimates about 120 ring sites in addition to host copyout. That is
scope guidance, not a pinned acceptance count. Census both copy directions,
including aliases, guarded helpers, typed loads/stores and lifecycle callers.

## Descriptor model

Extend the existing metadata declaration to generate `SyscallOperands` in
`carrick-abi`. A generated closed syscall identity enum allows an exhaustive
match: `CanonicalNr` is an integer newtype, so matching it with a wildcard
would not prove coverage. Conversion from a raw ordinal returns either a
known identity or an explicitly unsupported identity. Every declared syscall,
including deferred calls and private x86 canonical identities, must have an
explicit operand status: `Declared`, `ScalarOnly`, `Pending` or `Unsupported`.
`Pending` names an unmigrated family and cannot enter staged execution or
pretend to be scalar-only. Existing legacy dispatch remains available only for
that family until its atomic migration; crossing staging cannot use a Pending
entry. Unsupported must not masquerade as an empty list.
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

Use typed argument indices, operand keys, directions and layout IDs. The
single operand address vocabulary is `carrick_guest_arch::{UserVa, GuestLen,
UserRange}`; checked conversion at the memory adapter is the only bridge to
host `GuestPtr` or transfer-internal `GuestVa`. Do not add another pointer or
length newtype in the interpreter. Length expressions cover scalar arguments,
checked multiplication, captured value-result words and bounded decoded fields. Reject
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

## Access timing and Linux witnesses

Every operand declares its access phase, NULL policy, fault granularity,
publication order, and source of authority, as well as its byte shape. A
`Declared` entry requires a witness for each applicable choice below. These
are acceptance fixtures to implement and bless, not results obtained by this
document. Oracle results must record errno numbers and touched-byte sentinels.

| Case | Descriptor choice | Required native Linux witness |
|---|---|---|
| Lazy input | Resolve shape from scalars at intake; read bytes only at the handler's declared validation phase | `write(-1, bad, n)` returns EBADF (9), with zero input reads; a valid fd plus bad input exercises EFAULT (14); zero length never forces a pointer read |
| Fault versus effect (#746, #591) | Separate non-faulting reservation from fault-reporting access; encode validation, consumption and publication as ordered phases per operand | Invalid fd plus bad output, valid source plus second-page fault, and multi-output later-slot fault; observe return, source consumption, fd creation and earlier output on both ABIs. Never infer a universal preflight rule from one family |
| Partial fixed outputs (#920) | Fixed size describes capacity, not all-or-nothing publication; declare ordered fields/chunks and genuine-fault prefix rules | `waitid` siginfo crossing a writable/inaccessible boundary, with sentinel bytes and a child-state check using WNOWAIT and consuming variants; pin which bytes and reaping effects survive EFAULT before enabling this entry |
| NULL | Distinguish forbidden, ignored, optional, and zero-length-only for each operand | NULL stat output, optional wait status, socket address/length combinations, and zero-length buffers. **getresuid NULL needs an oracle check** for each of its three outputs and earlier-output visibility; leave that policy Pending until observed |
| Futex atomic word | Live aligned atomic access, with explicit read/compare/RMW and memory ordering; never snapshot a word into ordinary staged input | Misalignment versus inaccessible address, value mismatch EAGAIN (11), and two-thread compare/wake race; verify shared-word identity and no lost wake on both ISAs |
| Overlap and error output | Explicit ordered publication and result-dependent selection | Overlapping output slots, interrupted nanosleep remainder, partial readv and recvmsg truncation with independent sentinels |

An internal refusal publishes no bytes in its current prepared unit and parks;
a genuine later fault may preserve earlier Linux-visible bytes. Thus partial
fixed records do not contradict retained completion. A family's exact field
order is an oracle-pinned property, never guessed from its Rust struct order.

### Pointers outside the syscall argument array

The descriptor source also generates typed operation kinds for non-argument
accesses. A pointer source can be an argument, decoded field, captured register,
registered task state or an owned target-MM capability; handlers cannot supply
an arbitrary address to bypass an operand key.

| Source | Lifetime and semantics | Required witness |
|---|---|---|
| sigreturn frame | Capture frame address from the guest ABI's saved SP; validate/decode at restore, with declared register and mask restoration phases | Malformed frame, inaccessible trailing frame bytes and signal-mask restoration; no new-MM fallback on resume |
| `set_tid_address`, robust list, `rseq` | Registration stores an exact task/MM-generation binding; exit, robust traversal and rseq abort create typed child operations using that registered source | Clear-child-tid plus futex wake with two live threads; robust-owner death and bounded/cyclic list; rseq registration mismatch and abort during scheduling |
| `sigaltstack` | Snapshot the configuration record at syscall access time; retain the registered stack region as a later signal-frame destination, not as copied input | NULL query, invalid size/flags, on-stack replacement, fault while delivering onto an alternate stack |
| exec stack | Builder-owned destination in the newly admitted MM; bounded argv/envp inputs remain tied to the old MM until captured | Bad later argv/envp element and stack exhaustion; failed exec preserves old image; successful exec publishes only the new MM |
| io_uring and AIO | Registration/submission/completion operation kinds capture exact MM, buffer generation and resources; live shared rings need atomic fields, not frozen snapshots | Buffer unregister/unmap versus completion, CQ wrap, cancellation and teardown with outstanding work; unsupported operations refuse before access |
| remote MMs | Each local and remote operand carries its own authenticated target generation and access rights | process_vm read/write with two live MMs, inaccessible later remote vector, target exit/exec and partial transfer; never substitute the caller's MM |

Lifecycle operations remain owned across suspension and lose authority on the
specified teardown, rather than borrowing a completed syscall's staging view.
Deferred facilities get explicit Pending/Unsupported operation kinds, not a
blanket memory capability. Registration does not pin arbitrary user pages for
the lifetime of a task.

## One retained operation

`StagedOperation` is the move-only owner of descriptor identity, captured guest
ABI, scalar arguments, staged input bytes/read cursor, output slots and bytes,
completion result, publication cursor and exact execution identity. Put the
`no_std` interpreter and `StagedOperation` in a new Linux-owned crate
`carrick-linux-operands`. Its dependency edges are to `carrick-abi` (immutable
schema/codecs) and `carrick-guest-arch` (address types). It defines the narrow
capability-consuming memory venue and owns no scheduler or VMM. `carrick-kernel`,
`carrick-personality-linux` and `carrick-el1-linux` depend on it; host and ring
adapters implement its venue using existing neutral memory/continuation
mechanisms. `carrick-abi` may depend on `carrick-guest-arch`, never the reverse.
No edge from `carrick-core` or a neutral personality API to this Linux crate is
allowed. Check the actual feature closures and cycle-free build in slice 1.
Neutral `UserRange` preparation remains below this Linux interpretation layer.

Implement by moving/generalizing existing retained-output machinery. An
operation-specific resource (socket description, dequeue reservation, directory
cursor, accepted fd or wait result) can remain a typed payload, but cannot own
a second pointer/length list. It refers to descriptor operand keys. An accepted
socket waiting on copyout retains that socket and its cleanup obligation;
resuming must not call accept again or look up a recycled fd number.

The state transitions are intake, ready, executing, completed, publishing and
settled; a suspended wrapper owns exactly one typed dependency plus the state
to resume. No clone duplicates effect or completion authority.

1. Resolve scalar-derived operand shapes without touching user memory. Decode
   nested shapes only when their parent input reaches its access phase. Stage
   each input lazily through exact live owner authority.
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
For a bounded publication unit, prepare its participating ranges together
before committing; a preparation refusal publishes nothing in that unit. Group
multiple outputs only when the Linux witness permits joint fault detection;
otherwise retain ordered units so a later fault preserves the earlier output.
Prepared commit cannot suspend. For streams, preserve Linux-valid prefixes with
an exact cursor across bounded units; never roll back bytes already visible or
pretend the whole buffer fits one MM portal permit. Multi-permit operations
retain completed data and resource custody between units. Error outputs such as
an interrupted sleep remainder are explicitly selected even on error results.

The proposed rule is owned completion with Linux-prescribed publication units,
including partial fixed outputs as above. Independent review must confirm it
against the owner's atomic-completion requirement before code. Whole-call
transactional visibility would require a new cross-page memory protocol and would conflict with existing partial-copy
contracts; this design does not claim that protocol already exists.

## Replacement and enforcement

#1363 builds crossing staging directly from `SyscallOperands`. A staged
`GuestMemory` facade can bridge a migrated handler signature, but its capability
is only the descriptor's active ranges. It never falls back to raw memory for
an undeclared read or write. Eventually handlers take the narrower staged view.
Ring-served calls use the same declaration without gaining permission to cross.
#1393's crossing/RootOnly retirement and #1363's staging must share these operand
keys: retiring a host-served root path also removes its operand adapter, rather
than leaving a second authority behind. This design neither expands crossing
policy nor claims that root retirement has already landed.

Replace independent `UserSlot` construction and retained range lists family by
family with descriptor keys. Keep low-level prepared writes as the mechanism,
not a competing operand authority. Existing #744/#986 payload ownership moves
into the operation. #711's ratchet remains during migration with monotonically
decreasing per-file ceilings; each migrated family removes its old path in the
same change. Extend enforcement to forbid direct memory capabilities in migrated
handlers, including helper/alias bypasses and ring paths outside today's scope.
Retire `UserCopy` itself, including its boolean copy methods and blanket impls;
do not wrap it with a staged facade. Migrated personality handlers receive only
operand capabilities. Restrict `UserMemory::copy_in` and raw guarded-copy entry
points to low-level venues that require those capabilities. The neutral
`user_write` transaction keeps exact-MM fencing and progress but accepts only
authorized bounded units at its Linux boundary. ISA veneers do byte mechanics,
never independently select Linux ranges or collapse Busy to false/EFAULT.

Extend the ratchet to host copy-in, ring copy-in and ring copyout from the first
migration. Ceilings decrease by family with source scanning plus capability
visibility checks; moving a call to a wrapper does not retire debt. Census
lifecycle accesses too. At zero, delete the scanner, ledger and gate wiring
together. Do not bless `op.output` by spelling alone or reset ceilings after moving files.

The owner brief's 95-site count is historical: current ceiling totals must be
computed from the live ledger by the gate. No new pinned site list is needed.

## Landable slices and proof

The following are proposed dependencies, not authorization to implement before
independent design review. Slices follow coherent production behavior and
removal boundaries, rather than being sized to a line cap. Use the owner's
table exception only if the actual exhaustive schema needs it; retain independent review for every landable.
Use native GitHub stack tooling if layers are dispatched together.

| Slice | Removal/replacement | Red-first production witness |
|---|---|---|
| 1. Exhaustive schema plus one live consumer | Explicit status for every canonical/private identity; Pending for unmigrated families; migrate getresuid through production host and ring dispatch with ABI codecs, shared interpreter and minimal retained completion, after its NULL oracle check | Missing status fails exhaustiveness; NULL and later-slot fault oracle pins publication; Busy once resumes the original result on ARM and CPL0; no direct-copy fallback in this consumer |
| 2. Crossing integration | Extend slice 1's live operation machinery to crossing staging; move the applicable retained completion payloads | Production crossing refuses undeclared range; Busy once retains input snapshot, then succeeds without a second effect |
| 3. Fixed records, paths, value-result words | Migrate stat/time/identity and simple fs output; remove their ad-hoc ranges | Both stat layouts, optional NULL, invalid fd precedence, length mutation, second-slot refusal and exact output sentinels |
| 4. Readiness and consuming records | Migrate wait/epoll/directory and fd creation outputs | Completed wait is not reaped twice; accepted fd survives suspension/close/reuse; second page refusal preserves original readiness |
| 5. Streams and vectors | Migrate read/write/readv and transfer families | Default executor pool exhausted by producers; two live MMs, COW, sparse vectors, partial fault, no prefix replay |
| 6. Message/control families | Migrate msghdr, socket options, queues, SysV, command-dependent operands | Nested iovec/control aliases, truncated ancillary data, SCM resource cleanup, fatal cancellation and command/layout coverage |
| 7. Lifecycle, live atomic and remote operations; retirement | Migrate registered pointers, sigreturn, exec construction, futex atomic capabilities and supported async/remote-MM paths; retire UserCopy and all zero debt | Two-thread exit/robust/rseq, malformed signal frame, exec failure, futex compare/wake and remote target exec; no raw copy authority remains |

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
so coalescing cannot hide quadratic work. Commit to these hot-path bounds:
scalar-only calls allocate no operation storage and copy zero bytes; descriptor lookup is O(1), with no table scan. Each active
input byte is staged at most once per declared capture (live atomic loads are
separate actions), each output byte is published at most once, and each nested
metadata element is decoded once. Per-page preparation is at most one successful
unit plus one attempt per delivered refusal notification; no polling. Ordinary
fixed operands need no heap allocation for payloads up to 256 bytes, stored in
retained task-owned storage rather than automatic ring arrays. Streams retain
at most one page of payload per active transfer, plus bounded ABI metadata;
never reserve total user capacity. Handle/dispatch stack overhead is capped at
256 additional bytes, with no by-value StagedOperation or payload returns.
Prove that bound with the existing EL1/CPL0 frame-budget checker and full entry
envelope, not just size_of. If a no-allocation fixed path cannot meet the frame
budget, change ownership/storage before migration; do not widen the budget.

Measure paired, interleaved uninstrumented base/candidate scalar and fixed-copy
hot loops on the same host, with native Linux control. Require candidate median
per-call cost <= 1.05x base and the affected workload <= 2x native Linux;
report distributions and measurement completeness. A failed cost gate blocks
migration, rather than becoming a deferred optimization.

## ARM/x86 parity and acceptance

Normalize syscall identity and preserve guest ABI before descriptor lookup.
Private x86 calls need explicit entries, not ARM reinterpretation. CPL0 is a
required consumer, including #591 fault/effect ordering and #599 child descriptor
ownership: test a real forked child using pipe2/read/write with bad destinations,
owner suspension, fd close/reuse and exact source-consumption checks. An ignored
#599 fixture or ARM-only staged consumer cannot satisfy parity. Run the same
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
