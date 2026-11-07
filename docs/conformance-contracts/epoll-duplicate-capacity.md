# Duplicate epoll ADD at the member fan-out bound

Contract: `kernel.el1.epoll-zone`. Linux `epoll_ctl(2)` requires EEXIST
(errno 17) for an existing `(file, fd)` registration. A failed duplicate
ADD leaves that registration intact, and MOD updates its event data.

The shared IPC owner checked the member fan-out limit before duplicate
identity. At that bound it returned `HostHalf(MemberFanOut)`. The host
syscall dispatcher could then create a second item in its host half,
returning success for a duplicate ADD. Check duplicate identity while holding
the existing member then epoll locks, before considering capacity for a new
registration. The lock order and distinct-registration fan-out bound stay
unchanged. Duplicate ADD and MOD allocate zero items.

The component binding covers eventfd and pipe-reader objects at the bound,
asserts unchanged free-item counts, and harvests the MOD data. The syscall
binding drives the production dispatcher, including the inherited descriptors
of a real kernel fork with its parent still alive, and checks errno 17 and
MOD success. It is a host dispatcher binding to the same shared IPC owner;
it is not a native-process syscall binding.

This defect has not been attributed to Node startup in #1671. On admitted
main, epoll_create1 and epoll_ctl are temporary ring-owed services with no
native ring syscall family. The contract already describes those operations
as host-served. The director's signed Node rerun and exact failing syscall
trace are still required; neither this capacity reduction nor the existing
component Exists test proves which call caused libuv's abort.

The host `epoll_ctl` USDT probe currently fires on successful exits only
(`epoll_ops.rs`); its errno argument is always zero. If the director's count
of 38 successes came from that probe, it cannot exclude a host-dispatched
failure. Capture the syscall-return stream as well before inferring that an
unseen failing control operation was served in ring.
