# Epoll copy conversion prerequisites (#1704)

The copy slice is not implemented. Its acceptance combines
`kernel.el1.epoll-zone` semantics with `kernel.memory.owner-wait`: an
unavailable event page must suspend the exact call, and a wait must deliver
each harvested edge or one-shot event exactly once. A real invalid access
must return errno 14.

The #1691 dependency provides the required neutral `UserCopy` trait and
`CopyOutcome::{Done, Fault, NotYet(GuestCopyRequest)}`. It also provides
native owner-memory suspension. No additional outcome type is needed.

The admitted implementation has two service prerequisites:

- Canonical ordinal 21 (`epoll_ctl`) has no in-ring family in
  `carrick-personality-linux::dispatch::route_shared`. The crossing table
  retains its temporary host service. ADD reads its event through
  `read_epoll_event` in the host kernel dispatcher. A native-process
  production-entry ADD witness therefore needs an in-ring ctl service and
  routing, including descriptor identity and mutation authority. Testing
  `IpcRegion::epoll_add` directly would bypass the missing production path.
- The in-ring wait adapter in `El1PendingFamilies::ipc_transfer` requires
  an ARM frame. Its epoll serializer uses 16-byte ARM records; x86 needs
  packed 12-byte records. ARM and x86 support needs a shared service with
  ISA-specific entry and record-layout adapters.

The existing wait copy uses the boolean substrate `UserCopy`, restores the
harvested items on refusal, then forwards. Converting its output must retain
the harvest or restore it before owner-memory suspension, with the original
deadline and cancellation custody preserved. Simply mapping every refusal
to EFAULT or replaying an already committed registration cannot satisfy the
contract.

Before claiming acceptance, resolve the service scope, add two-live-thread
native-process witnesses through production entry, and commit their red
result before the fix. ADD must return 0 after backing becomes available
and errno 17 on duplication. Wait output must preserve edge and one-shot
delivery across memory suspension. Then lower the guest-copy debt ratchet
and run the required native, CPL0, platform, authority and review gates.
Signed execution, Docker comparison and the director's scoreboard remain
separate evidence; a successful build cannot substitute for these witnesses.
