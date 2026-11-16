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
deadline passes, and the member publishes the call's own record again (the
same staged input, as Linux reads a poll set and a send's bytes once per
call), which probes once. A signal that interrupts the wait wakes the member
from that queue: the call answers EINTR, and a socket call, read or write
that moved nothing is restarted under `SA_RESTART` by the shared signal
policy on both ISAs (a poll never is).

A poll's deadline is keyed on the member and the call's ring serial
(`HostCallSerial`, `HostFileOp::Poll` `args[2]`): the ring stamps a new
serial at the call's entry and keeps it on every record it publishes again
for that call, so a re-issued identical poll waits its own timeout.

The call runs under the caller's own identity: the ring stamps each socket
record with the member's `NetCaller` (ring `TaskKey`, namespace pid, ids,
effective capabilities), and the carrier's scope answers every credential,
capability and pid read with it, never the run root's. SIGPIPE is raised by
the ring on the caller, only for a send that moved nothing.

A `send` or `recv` keeps its caller's whole extent. One record stages at
most 64 KiB of its data (`NET_TRANSFER_MAX_BYTES`), which every inet
datagram fits, beside its framing (`HOST_FILE_AREA_BYTES`): a datagram is
one transfer, and the carrier answers EMSGSIZE for a larger datagram send
before it transmits anything. Each reply leads with the socket's facts
(`NetTransferFacts`: stream, blocking). The ring's owned continuation moves
a stream transfer record by record from the byte after the last one moved:
a blocking send until every byte moved, a non-blocking one while each record
moves its whole range, and a MSG_WAITALL receive on a blocking stream until
its buffer is full or the stream ends. A signal or an error after progress
answers the bytes moved. The rest of a send's buffer is proven readable, and
of a MSG_WAITALL buffer writable, before the first record crosses.

Not yet served (counted ENOSYS, never a guessed result): the run root's x86
sockets, `sendmsg`/`recvmsg`/`sendmmsg`/`recvmmsg`, a ring epoll over a
socket, waits on an in-zone loopback pair, and socket waits with
`SO_RCVTIMEO`/`SO_SNDTIMEO`.
