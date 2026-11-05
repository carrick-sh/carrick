# Signal-mask input and sparse output (#1677)

`kernel.memory.owner-wait` applies to `rt_sigprocmask` input as well as
output. Linux `sigprocmask(2)` reports EFAULT for inaccessible memory, not
for internal memory arbitration. An anonymous writable page need not be
resident before a syscall writes it.

The dispatch reduction separates three boundaries:

- `sigprocmask_copyout_into_untouched_sparse_mmap` uses the production sparse
  `AddressSpace`, dispatches an 8 MiB anonymous PROT_NONE mmap followed by
  mprotect(RW), and checks that no bytes were initialized. It then saves
  oldset near the end and writes a clock record through a different copyout.
  This control passes before the signal fix. It is the Legacy memory venue;
  it does not prove HVF descriptor publication or physical supply.
- `sigprocmask_output_supply_preserves_mask_until_copyout_completes` injects
  a grant dependency at the owner preparation boundary. Dispatch already
  returns OwnerMemorySupply without writing oldset or changing the mask.
  Redispatch saves the previous mask and then installs the requested mask.
- `sigprocmask_input_owner_wait_preserves_mask_and_oldset` was red before the
  fix: errno 14 instead of OwnerMemoryWait. The handler erased the typed
  input error. The fix uses the existing dependency-to-outcome conversion,
  before either output or mask mutation. The input-supply companion checks
  the same ordering for sparse first-touch supply.

These small fixed records need one input read and one successful prepared
output. Refused admission commits no output and changes no signal mask.
There is no eager population, new fault classifier, polling or timeout change.
The sparse mmap classification and transactional host snapshots come from
#1675; its commits are retained beneath this slice.

## Copy-path audit

The shared `dispatch::copyout` helpers (fixed slots, records, arrays and
byte windows) all call `GuestMemory::prepare_write` on the owner venue and
preserve supply/owner/physical refusals. The AArch64 engine's prepared writes,
raw writes and unchecked writes use the owner transfer protocol when an MM
owner is admitted. `user_transfer::staging` selects every touched output page
before admitting any output permit. The shared `MmPortal::select` checks VMA
permissions and asks its existing fault-plan owner for supply when a leaf is
absent. Host-backed pointer access instead calls `commit_prepared_host_write`;
its absent-run grant and prepared-leaf publication precede pointer lookup.
The x86 raw write path asks its backend to materialize each translated page.
No demonstrated copyout failure justifies adding another materializer here.

## Identity and remaining acceptance

`HvpatchSyscallService::new` rejects pid/tid <= 0 and ASID zero. Runtime service
instrumentation gets the process identity from `syscall_trace_identity` and
the thread identity from the executor's Linux tid. The flow D script prints
all syscall-return probes using host-thread-local fields last set by a
service-begin. An unpaired return can therefore print default 0/0; executor
migration also means that thread-local pairing alone is insufficient evidence
of guest identity. This source audit does not establish the observed child's
actual GETPID/GETTID results.

The reductions do not prove that input arbitration caused the director's
thread census failures, and they do not reproduce a sparse HVF copyout fault.
Keep the work draft until the director captures the failing memory dependency
on the Mac and reruns the glibc census and Go/CPython workloads against the
exact rebuilt signed artifact. No signed or Docker acceptance is implied by
these VM-free controls.

## Re-brief: diagnose the remaining native refusal

The glibc-shaped sparse control now blocks an all-bits set and places oldset
0x1600 bytes below the end of the 8 MiB PROT_NONE-to-RW mapping. It remains a
Legacy-venue control, not a native-owner reproduction. No new materializer is
justified by this passing control.

The host handler's size check returns EINVAL (22), not EFAULT. Its set read
returns EFAULT only when `from_owner_memory_error` cannot retain a dependency.
Its oldset write uses `copyout_bytes`: owner preparation faults become deferred
EFAULT, while waits and supply remain typed; a Legacy write failure becomes
EFAULT at commit. The fixed eight-byte output cannot exceed the permit budget,
but a pointer whose range overflows is a genuine fault. Owner permits commit
without a fallible memory operation after successful preparation.

The shared AArch64 engine selects `read_owner_bytes` for an admitted owner.
Incarnation mismatch, absent custody/portal, service transport errors, a
retired owner, or a refused selection can all reach the set-read boundary as
MemoryError. SELECT errno 14 becomes OutOfBounds; other missing-receipt errors
retain HostMap text. Supply failures also propagate through this boundary.
The write path selects every output page through the same owner portal before
preparing the permit. The existing SELECT/PREPARE and owner-lowering probes
remain available to distinguish these lower boundaries.

`guest-internal-write-fault` now preserves the failing set pointer and debug
MemoryError at phase 28 (historical probe name includes this input diagnostic).
Phase 29 preserves the copyout admission error before lowering, including
range overflow; phase 30 preserves Legacy commit failure. For a multi-slot
copyout phase 29 identifies the attempted prefix's final slot, not necessarily
the offending slot. Sigprocmask has exactly one output slot. These are
failure-only probes; formatting can perturb repeated refusals. They are not
performance evidence and need live qualification on the Mac.

The durable syscall-flow script consumes these existing probes and clears
its attribution on `hvpatch-syscall-service-clear`. It prints returns without
a matching active service as `ret-unpaired` with host tid, rather than
inventing a Linux identity. Constructor validation still rejects zero Linux
identity. This corrects diagnostic attribution only; guest GETPID/GETTID and
the glibc crashes remain unverified until the director's signed capture.
