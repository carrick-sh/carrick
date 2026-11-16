# Native host network venue (`kernel.native.host-network-venue`)

A forked or exec'd native child reaches the host network (#231) through one
typed record, `HostFileOp::NetSyscall`, served by the carrier's own socket
handlers against a scratch descriptor table that holds only the caller's
socket. There is no second socket implementation: the run root's network
model applies unchanged.

Blocking is an owner wait on the member's own host-readiness queue
(`ObjectWaitKey::native_host_ready`, `PortalWaitCause::HostReadiness`). The
carrier samples the queue before its single non-blocking probe and enrols the
host fd with its one wait reactor (`CarrierWaitService`, the reactor that
serves the run root's host-fd waits; there is no second readiness thread).
The reactor notifies the queue when the host fd is ready, or when a poll's
deadline passes, and the member reruns the call once.

The call runs under the caller's own identity: the ring stamps each socket
record with the member's `NetCaller` (ring `TaskKey`, namespace pid, ids,
effective capabilities), and the carrier's scope answers every credential,
capability and pid read with it, never the run root's. SIGPIPE is raised by
the ring on the caller. One record carries at most 60 KiB of a transfer, so
a larger blocking send returns a short count.

Not yet served (counted ENOSYS, never a guessed result): the run root's x86
sockets, `sendmsg`/`recvmsg`/`sendmmsg`/`recvmmsg`, a ring epoll over a
socket, waits on an in-zone loopback pair, and socket waits with
`SO_RCVTIMEO`/`SO_SNDTIMEO`.
