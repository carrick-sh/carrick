# Signal setup copies (#1677; Bet 6 bottom layer)

The lifecycle and signal families use the existing neutral
`carrick_core::personality::UserCopy` with `CopyOutcome::{Done, Fault, NotYet}`.
This replaces that interface's boolean result rather than adding a parallel
copy trait. Lifecycle and signal adapters must explicitly provide wait and
retained-output settlement; no default turns `NotYet` into errno 14.
File, IPC and other boolean interfaces are outside this slice.

`kernel.memory.owner-wait` covers unavailable input and retained output.
Linux signal setup accepts valid user pages even when backing is not resident;
only a genuine address or permission fault returns errno 14. Input must become
readable before any setup effect. The ARM adapter asks the existing exact-MM
transfer owner to prepare a read, using the same selection and physical supply
protocol as write preparation with `UserRead` intent. Read-only libc data must
not be sent through write/COW admission.

The input continuation reuses native service custody, owner release queues,
physical fault supply and SVC redispatch. It neither sleeps on a host worker
nor retries inside the syscall. Handled signals remain pending during this
internal wait; terminal cancellation retains its existing owner.

Service intake observes the retained continuation before its notice can be
consumed. Temporary ring execution preserves the member's host ownership.
After consuming that continuation, a host-owned member hands its completed
saved context back to its host executor instead of returning to EL0 on a
hostless vCPU. Input redispatch rewinds only the saved syscall PC through
`ProcessContext`; ARM and x86 implement their instruction lengths there.

An idle member service follows the exact scheduler record when a host boundary
rehomes it. The same guarded service-birth rebind used by exec preserves its
MM, lineage and monotone request sequence. The new service queue is admitted
outside the graph guard; an already admitted queue is retained. Old selectors
cannot claim a request from the replacement record.

Mask, altstack and disposition updates commit before a genuine old-value output
fault, preserving the existing Linux ordering. Completed output is handed to
the existing retained copyout owner with the original bytes and return value.
Its page cursor survives a wait; resumption never re-applies the setup change
or recomputes the old value. The VM-free output witness requires no writes
before release, exactly one eight-byte old-mask write after release, and no
second mask update or completion.

The production ARM input witness was red on the base with syscall 135 returning
-14 when the guarded-copy boundary refused its input. On success it must retain
the original arguments for redispatch, preserve the old-value sentinel until
completion, and publish the pre-change mask once. This physical-boundary
injection is not an instruction-execution or live libc witness.

Signed evidence uses the restored, input-identity-verified GNU and musl thread
probes on HVF. The committed probe oracle and director supply Linux authority;
Docker is unavailable on this worker. No runtime-ratio acceptance is inferred
from the VM-free tests or from matching process exit codes.
