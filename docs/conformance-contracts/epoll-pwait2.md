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

- `ipc/epoll.rs`: sigmask input, table/pin contention, object harvest failure,
  mixed host items, output preparation, timer-slot refusal and park refusal.
- `dispatch.rs::serve_owned_ipc_descriptor`: a host-backed epoll member and
  the shared epoll core's HostHalf refusal.
- `dispatch.rs::ipc_transfer`: absence of the ARM scheduler execution venue.

The existing neutral NativeIpcExecution used by poll is the venue to reuse
for x86 epoll work. Its integration and packed x86 epoll_event copyout need
production-dispatch and KVM witnesses before claiming that lane. No crossing
allowlist change is included. Signed Node validation, blocked-pool capacity,
EINTR, Docker differential and signed artifact promotion remain required.
