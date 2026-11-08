# Ring-owned pipe metadata (#1901)

Contract: `kernel.el1.ipc-fd-authority`.

Linux authority: stat(2), fcntl(2), F_GETFL(2const), F_GETPIPE_SZ(2const),
pipe(7), ioctl(2), dup(2), close(2), and lseek(2). Both pipe ends identify
one inode; separate live pipes differ. Description status flags and capacity
are shared by aliases; descriptor close-on-exec flags are private.

The structural invariant is zero host descriptor operations for a ring-owned
pipe. The production-dispatch witnesses require a completed ring route for
each call. They use the existing two-live-child native-fork fixture and test
the borrowed root table as well as the fork child's owned table. Each case
creates its pipe through pipe2. All I/O in these cases is nonblocking.

The first witness set covers fstat, empty-path newfstatat, fcntl status and
fd flags, both fcntl duplication commands, pipe capacity, FIONREAD, FIONBIO,
TCGETS, lseek, dup, dup3 and close. It is deliberately red before routing
and metadata repairs. Exec-successor and FIOCLEX/FIONCLEX cases extend the same matrix. The exec
fixture also checks an inherited CLOEXEC alias is removed while the parent
keeps it, and the non-CLOEXEC pipe ends survive. Shrink-EBUSY, contention and
x86 execution still need witnesses. No signed or end-to-end
CPython result is claimed by these VM-free tests.

## Required shared interface review before implementation

The complete acceptance requires more than adding descriptor match arms.
`IpcObjectGuard::drop` only clears its lock, and the fd core's `Locked::drop`
only clears the table lock. Neither publishes a release notification.
`NativeFdWait` always returns true, so using it for the new object operations
would indefinitely spin on a host-held lock. Existing readiness notifications
are not lock-release notifications: a holder can unlock without changing
readability or writability. Waiting on readiness would lose that wakeup.

This is the same architectural prerequisite tracked by #1845 (queue-lock
release and constructor custody), alongside the typed-refusal work in #1879.
The implementation must share that protocol instead of adding a second lock
wait mechanism to this metadata family. The relevant proposed interface is:

- A failed table/object admission returns an owned typed release ticket,
  retaining the holder identity and revision sampled before the probe.
  Reuse `carrick_sched_core::refusal::{Refusal, ReleaseTicket}`.
- The guard that releases that authority publishes its release revision and
  notification. Delivery occurs after dropping all table/object guards.
  An unlock with no readiness change must still wake a metadata waiter.
- The existing per-thread continuation owner retains the metadata operation,
  its exact description pin, imported scalar operands and any completed output.
  A release race returns that same operation for one immediate reprobe;
  otherwise parking releases execution capacity. Numeric fd reuse must never
  redirect a resumed request to another description.
- Output uses the existing `ProcessNative::complete_copyout` owner, which
  retains bytes through owner-memory waits. Input uses the typed guest-copy
  result and owner preparation; a refused raw copy is not proof of EFAULT.
- Capacity resizing moves the host algorithm into the shared object owner.
  Preserve its provision/recheck/reclaim transaction, pipe-core rounding and
  EBUSY shrink test, and deliver the shared wake result in each venue.
- Both stat encoders consume one pipe-identity record. The existing
  `LinuxStatFields::CARRICK_PIPE` uses a constant inode and cannot distinguish
  separate pipes. Move the host x86 stat encoder into the shared ABI rather
  than copying its layout into the ring.

Lock-release publication and lifetime retention change the shared protocol
and cross-crate lock order. AGENTS.md requires a separate design pass reviewed
before code for those changes. The director must coordinate the shared
interface with #1845/#1879; this proposal is not an approved ABI layout.

The full x86 I/O reproduction also intersects #1756, whose tracked work wires
CPL0 to the shared ring IPC execution venue. In this base, `ipc_transfer`
still requires `arm_frame()`. Metadata routing must remain ISA-neutral, but
an x86 bytes-moving acceptance claim cannot be inferred from ARM-frame tests
on an x86 host. No unrelated x86 IPC implementation is copied into this PR.
