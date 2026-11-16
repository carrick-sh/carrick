# Native host network venue (`kernel.native.host-network-venue`)

A forked or exec'd native child reaches the host network (#231) through one
typed record, `HostFileOp::NetSyscall`, served by the carrier's own socket
handlers against a scratch descriptor table that holds only the caller's
socket. There is no second socket implementation: the run root's network
model applies unchanged.

Blocking is an owner wait on the member's own host-readiness queue
(`ObjectWaitKey::native_host_ready`, `PortalWaitCause::HostReadiness`). The
carrier samples the queue before its single non-blocking probe; its
readiness watch notifies the queue when the host fd is ready, or when a
poll's deadline passes, and the member reruns the call once.

Not yet served (counted ENOSYS, never a guessed result): the run root's x86
sockets, `sendmsg`/`recvmsg`/`sendmmsg`/`recvmmsg`, a ring epoll over a
socket, waits on an in-zone loopback pair, and socket waits with
`SO_RCVTIMEO`/`SO_SNDTIMEO`.
