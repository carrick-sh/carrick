# Native epoll_pwait2 routing (#1671)

The existing `kernel.el1.epoll-zone` contract owns this surface. Linux
`epoll_pwait2(2)` uses a nullable timespec with nanosecond precision; a null
pointer waits indefinitely, zero polls, and negative seconds or nanoseconds
outside [0, 1000000000) return EINVAL. The shared epoll engine retains one
absolute deadline in its owned operation, so resume never imports the timeout
again. It uses the same object queue, enrollment probe and descriptor pin as
`epoll_pwait`.

The production native-child netpoll witness was red on GitHub main: ordinal
441 returned Forward for a ring-created epoll and a zero timespec. It now
checks zero and invalid timespecs, then parks a finite pwait2 and wakes it
from another live process. Mutating the timespec while parked must not
change the resumed result. Existing epoll_pwait readiness checks remain.

This slice does not establish the director's Node blocking-wait attribution.
The following forwarding paths still need retained owner work:

- `ipc/epoll.rs`: sigmask or timespec input the ring cannot read, table/pin
  contention, object harvest failure, mixed host items, an events buffer with
  no native owner (#2178 prepares a native caller's buffer in ring),
  timer-slot refusal and park refusal. Each is counted under one named
  `IpcLeave` (#2166); a refused pwait2 timespec counts `CopyInFault`.
- `dispatch.rs::serve_owned_ipc_descriptor`: a host-backed epoll member and
  the shared epoll core's HostHalf refusal.
- `dispatch.rs::ipc_transfer`: absence of an execution venue (ARM scheduler
  or the retained native record source).

The existing neutral NativeIpcExecution used by poll also serves native
IPC transfers. The production CPL0 frame witness was red with Forward for a
child-created epoll. It covers packed x86 epoll_event output and eventfd
read/write through that same owner. An empty infinite wait retains an
operation and releases the slot. The fixture places lifecycle ABI records in
TestEl1Region storage in the production metadata address window, retaining the
exact identity check including the live affinity source. The KVM binding adds
USE_EPOLL to the existing pipe-wake guest: epoll_create1, ADD, parent pwait(-1),
child write and packed readiness cookie, with no ring refusals or epoll
forwarding. With x86 epoll_pwait reaching the ring owner, #2178's KVM
copy-out witness (an untouched events page prepared by the native owner) is
no longer ignored. A pre-fix KVM replay, signal-mask and exhaustive member-kind
witnesses remain required. No crossing
allowlist change is included. Signed Node validation, blocked-pool capacity,
EINTR, Docker differential and signed artifact promotion remain required.

The native adapter also uses the existing ARM input-completion rule: a
returned input-owner errno is installed in the syscall frame before lowering
the completion. The production CPL0 witness was red with `(Served, 441)`
instead of `-EFAULT`; the real KVM bad-timeout variant failed at exit 18.
The host-only witness injects the guarded instruction refusal (the host
fixture has no EL1 exception fixup), while KVM uses an actual unmapped guest
timeout pointer. Both drive production dispatch and the native input owner.
