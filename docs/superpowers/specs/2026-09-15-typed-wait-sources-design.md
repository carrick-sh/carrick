# Typed wait sources: proposed change, not implemented

## Problem and evidence

Three lost-wake hangs were fixed on this branch inside one day with one shape. `ed1d29e66` (`cpython-asyncio` `TestSSL.test_remote_shutdown_receives_trailing_data`, 60 s handshake abort): `pselect6` probed host pollfds with a zero timeout, saw `n == 0`, and returned `WaitOnFds` before the loop that samples in-zone descriptions. `28445af8c` (`inzonetcp` level-triggered round 2, server tid 6 parked in `ppoll` on accepted in-zone fd 8 at +0.806 ms, client `sendto` at +0.878 ms, wake at +5002 ms): `host_poll_target` returned `None` for `OpenDescription::InMemorySocket`, both mixed paths dropped the fd from `wait_targets`, `WaitFds::logical_interest()` computed 0, and `install_producer_subscriptions` skipped its post-enrollment readiness probe. `54fde3e88` (`cpython-wsgiref` `test_interrupted_write`, `cpython-xmlrpc` `KeepaliveServerTestCase2.test_transport`): an in-zone listener is `OpenDescription::HostSocket` with `base.inzone_listener()` set, registered by host fd only, so `logical_interest()` was again 0 and the Darwin listen socket never becomes readable for an in-zone connection.

The mechanism is structural, not incidental. `WaitFds` carries two independently-built lists joined by one scalar. `fds: Vec<WaitFd>` is a list of `(i32 host_fd, i16 events)` produced by `NetView::wait_target_for_poll` (`dispatch/net.rs:691`), where `-1` is an in-band sentinel meaning "carrick-owned description, no host object". `WaitFdAuthority::Logical { strict, watched, interest }` (`dispatch/wait_authority.rs:36`) carries a list of `FileSlotAuthority` built separately from the guest fd list by `with_guest_slots` / `with_redispatch_and_watched_slots`. Nothing correlates entry `i` of one list with entry `j` of the other. The only bridge is `WaitFds::logical_interest()` (`wait_authority.rs:275`), which folds the events of every registration with `fd < 0` into a single `i16` and applies it to EVERY slot in `strict ∪ watched`.

`install_producer_subscriptions` (`vcpu_loop/continuation/wait_service.rs:1158-1216`) iterates `strict.iter().chain(watched)`, subscribes each slot authority, enrolls on `description.wait_queue()` when the description exposes one, and then runs the post-enrollment readiness probe only `if *interest != 0` (line 1203). That probe is the ONLY place a description is sampled after enrollment. `ReadinessProbe::Fds::poll()` (`vcpu_loop/continuation/readiness.rs:756-792`) is description-blind: it builds a `pollfd` array from `registrations`, which `BlockingFdWait::new` (`dispatch/fd_wait.rs:110`) already filtered to `fd >= 0`, and returns `None` when that list is empty. So for a description-only wait the reactor has nothing to poll, `recheck_registration` (`wait_service.rs:1450`) re-runs the same blind probe, and the only readiness signals are the wait-queue callback and the one gated post-enroll probe. `interest == 0` is therefore not a mild imprecision; it is a permanent lost wake with `timeout: None`.

`WaitQueue::enroll_callback` (`kernel/wait_set.rs:125`) keeps the callback live until the enrollment is dropped, and `wake_all_with_depth` invokes every registered callback, so wakes are repeatable once enrolled. The window is exactly [syscall's own readiness check, enrollment], and nothing else closes it.

## The fourth instance, still open

`NetView::empty_netlink_recv` (`dispatch/net/netlink.rs:142-160`) parks with `WaitFds::raw_one(-1, 0).with_guest_slots(&files, [fd])` and `timeout: None`. The events are literally `0`, so `logical_interest()` is 0, so the post-enroll probe is skipped, so a `enqueue_netlink_message` (`netlink.rs:166-195`) landing in the gap calls `wq.wake_all()` with no enrollment and is lost. `OpenDescription::Netlink` reports `IN` when `recv_queue` is non-empty (`fd_table.rs:2466`) and exposes a wait queue (`fd_table.rs:1709`), so the description is sampleable — it is simply never sampled. `enqueue_netlink_message` also calls `host_signal::wake_all_waiters()`, a process-wide broadcast, which wakes threads ALREADY parked in `kevent`; it does not help a thread that has not parked yet. This is glibc's `mq_notify` `SIGEV_THREAD` helper blocking in `recvfrom` on a `NETLINK_ROUTE` socket. It is the same bug, unfixed, and it is the natural red-first target for this migration.

## Alternatives and decision

1. Keep the `(i32, i16)` list and the `-1` sentinel; fix each new lost wake as it is found. Rejected: three fixes in one day, a fourth already present, and the failure mode is a workload hang whose only reproduction is a dtrace timing trace.
2. Drop the `interest != 0` gate and always probe every slot in `strict ∪ watched` with the scalar union. Rejected: the scalar has no per-fd meaning (a set containing an in-memory socket wanting `POLLOUT` and an epoll instance would probe the epoll with `POLLOUT`), and `watched` slots carry no events at all, so the "interest" for them would be fabricated.
3. Replace the representation: one typed wait source per guest fd, fusing the host target and the exact slot authority into a single registration, with the description interest carried per source and constructible only non-empty. Selected. `logical_interest` disappears with the sentinel; the post-enroll probe becomes unconditional for every description-bearing source, with its own precise interest.

## Contract

A wait is a list of `WaitRegistration`, one per guest fd the caller named, in caller order. Each registration owns the guest fd, the events the guest requested, the exact `FileSlotAuthority` captured at admission (for EVERY source kind — close/reuse invalidation is unchanged), and one `WaitSource`.

`WaitSource::Host { host }` means the host descriptor both wakes the reactor and decides guest-visible readiness; its revents are the answer verbatim. It carries no description interest, which makes "a host registration for an fd whose readiness the description decides" unrepresentable.

`WaitSource::Description { interest }` means there is no host object: the description's wait queue is the only wake source, and the wait service MUST probe `description.readiness(interest.epoll(), ..)` exactly once after the enrollment is live.

`WaitSource::Dual { host, interest, coverage }` means both. `coverage` is `HostProxyCoverage::LatchedLevelTriggered` when the host descriptor is a complete latched mirror of the description's readiness (an in-memory pipe or eventfd readiness pipe; an epoll instance's `EVFILT_USER` wake via `event_mux::trigger_user_wake_fd`, `event_mux.rs:22`), and `HostProxyCoverage::HostPeersOnly` when the host descriptor observes only host-crossing producers (an in-zone listener: a connection paired in-zone never touches the Darwin listen socket). `coverage` exists only inside `Dual`, so "complete coverage with no host descriptor" is unrepresentable.

`WaitInterest` wraps `carrick_abi::LinuxPollEvents` and its only constructor returns `None` for an empty set, so "a description-backed registration with no events" is unrepresentable. That single type retires `netlink.rs`'s `raw_one(-1, 0)` at compile time.

No bare `i32` fd crosses the new boundary: the guest fd is `dispatch::abi_args::Fd`, the host fd is `dispatch::abi_args::HostFd`, the slot is `kernel::objects::FileSlotAuthority`, the events are `carrick_abi::LinuxPollEvents`. Lowering to raw `i32` happens only in `WaitFds`'s reactor list and at the `libc` boundary.

`WaitFdAuthority::Logical` carries `registrations: Vec<WaitRegistration>` and `watched: Vec<WatchedSlot>`; `strict` and `interest` are deleted. `watched` remains an advisory, probe-exempt role: epoll's `watched_guest_fds` exist to force a re-dispatch when an interest target's slot is replaced, they carry no requested events, and the epoll instance's own latched user wake covers their readiness. That exemption is a property of the type, not of a comment: a `WatchedSlot` has no `WaitInterest` to probe with.

The wait service's obligation becomes one rule with no scalar gate: for every registration, subscribe the slot authority; if the source carries a `WaitInterest`, enroll on `description.wait_queue()` and probe once with THAT interest, unless the source is `Dual` with `LatchedLevelTriggered` coverage, in which case the reactor's level-triggered host descriptor already reports a gap edge and the probe is redundant. Every `LatchedLevelTriggered` construction site owes a test that proves the latch (producer fires in the gap, host descriptor alone reports the waiter Ready). Absent that proof the site must be `HostPeersOnly`.

## One assembly, ABI-only syscalls

Every wait-shaped syscall calls one function: given the guest fds and their requested events, and whether the caller may block, it classifies each fd into a `WaitRegistration`, batches the `Host`-sourced fds into one `libc::poll(..., 0)`, samples the description for `Description` sources and for `Dual` sources per their coverage, and returns either per-fd readiness or the typed park. Syscalls retain only ABI marshalling: `fd_set` bitmaps and `clear_on_timeout` for select, `pollfd` writeback for poll, the `epoll_event` list for epoll, the buffer/`msghdr` handling for recv/send, the `sockaddr` writeback for accept.

The per-fd normalizations that today live ONLY in `ppoll`'s all-host arm are semantics, not marshalling, and move into the assembly: Darwin has no `POLLRDHUP` so it is reconstructed from kqueue `EV_EOF` (`net.rs:3371-3377`); macOS `poll(2)` sets `POLLPRI` on any vnode that requested it, which Linux never does, so it is stripped for fds that cannot carry OOB (`net.rs:3385-3387`); a listening socket must not report `POLLOUT`/`POLLHUP` (`net.rs:3389-3393`). `pselect6` does none of these today, which is a live divergence between two syscalls that are supposed to share one classification.

## Census of hand-rolled "probe then park"

Every site below independently re-implements some part of check-readiness-then-construct-a-wait. Line numbers are HEAD `69dd945cb`.

- `dispatch/net.rs:2944` — `pselect6` empty-set park (`WaitFds::empty()` + timeout; signal-interruptible sleep).
- `dispatch/net.rs:2952-3033` — `pselect6` all-host arm: `libc::poll(...,0)` at 2970, per-fd revents synthesis 2975-2990 (`readiness_pipe` / `sample_description` / verbatim), park 3003-3033. No RDHUP/PRI/listening normalization.
- `dispatch/net.rs:3035-3103` — `pselect6` mixed arm: `poll_ready_events` loop 3038-3044, park + `BlockingFdWait::Select` 3045-3100.
- `dispatch/net.rs:3330-3432` — `ppoll` all-host arm: `libc::poll(...,0)` at 3346, revents synthesis + all three normalizations 3354-3400, park 3405-3432.
- `dispatch/net.rs:3434-3488` — `ppoll` mixed arm: `poll_ready_events` loop, park + `BlockingFdWait::Poll`.
- `dispatch/net.rs:844-891` — `NetView::blocking_io`: run the op, on `EAGAIN` park on `WaitFds::raw_one(host_fd, dir.events())`. The host-socket recv/send/accept path.
- `dispatch/net.rs:3728-3751` — `wait_in_memory_slot`: description-only park via the `-1` sentinel. Called from `net/send_recv.rs:340,726,1019,1455`, `net/lifecycle.rs:1401`, `fs/rw.rs:1065,1286,2599,3280`.
- `dispatch/net/lifecycle.rs:1452-1477` — `accept_common` in-zone arm: hand-rolled `WaitFds::raw(vec![(host_fd, POLLIN), (-1, POLLIN)])`, the only dual registration built by hand.
- `dispatch/net/lifecycle.rs:1670-1692` and `:3640-3665` — connect-completion parks on `POLLOUT`.
- `dispatch/net/epoll_ops.rs:1719-1795` — three `epoll_pwait` park arms (`kq_drained_all_filtered` with events `0`; `!has_interests`; the ordinary arm), all `raw_one(kq_fd, ..)` + `with_redispatch_and_watched_slots`.
- `dispatch/net/netlink.rs:142-160` — `empty_netlink_recv`, `raw_one(-1, 0)`. Open lost wake; see above.
- `dispatch/fs/transfer.rs:1430-1452` — `splice` in-memory park, `raw_one(-1, POLLIN)`.
- `dispatch/fs/pipe.rs:342`, `:562`, `:882` — blocking pipe reads, `authorized_raw_one(host_fd, POLLIN, authority)`.
- `dispatch/fs/sendfile.rs:412` — `sendfile` `POLLOUT` park.
- `dispatch/ioring.rs:1147`, `dispatch/io_pipe.rs:567`, `dispatch/syslog.rs:107`, `dispatch/proc.rs:3724` — single-host-fd parks.
- `dispatch/fs/open.rs:387`, `:403` — blocking FIFO `open`, `WaitFdAuthority::Internal(FifoOpen)`. Out of scope: there is no guest fd and no description yet; the `ParkedOpenerToken` owns the host pipe.

## Descriptions that expose a wait queue

From `OpenDescription::wait_queue` (`dispatch/fd_table.rs:1697-1713`), the complete set is: `PipeReader`, `PipeWriter`, `EventFd`, `TimerFd`, `InMemorySocket` (its `InZoneListener` queue when `base.inzone_listener()` is set, else `socket.wait_queue`), `Epoll`, `Netlink`, `Packet`, and `HostSocket` when `base.inzone_listener()` is set. Ten distinguishable producer/consumer pairs. Every one of them must survive a wake that fires between the syscall's readiness check and the wait service's enrollment; that is the acceptance property, and it must be enumerated by an exhaustive `match` over `OpenDescription` so a new wait-queue-bearing kind fails to compile rather than silently skipping the property.

## Review correction from current source

The diagnosis that `logical_interest` folds only `fd < 0` registrations is correct, but three points need correcting before implementation.

First, `interest` is not per-source; it is one scalar applied to every slot in `strict ∪ watched`. A design that merely renames the sentinel without fusing the registration list and the slot list keeps the defect. The fusion is the change.

Second, "always probe unconditionally for description-backed sources" is right for `Description` and for `Dual`/`HostPeersOnly`, and is a real behaviour change for the readiness-pipe kinds (`PipeReader`, `PipeWriter`, `EventFd`, `Epoll`), which today have `interest == 0` and no probe. `OpenDescription::readiness` for `Epoll` (`fd_table.rs:2156-2200`) performs a `libc::poll` on the instance kqueue and then recursively queries every registered target's readiness. Adding that to every `epoll_pwait` park would put a recursive readiness sweep on Go's netpoll hot path. The honest resolution is the typed `HostProxyCoverage`: the epoll instance's wake is a latched `EVFILT_USER` (`event_mux.rs:22` → `carrick_host_bsd::kqueue::trigger_user`), and the readiness pipes are level-triggered, so a gap edge leaves the host descriptor readable and the reactor reports it. That justification must be discharged by a test per site, not asserted in a comment.

Third, `epoll_pwait`'s `watched` slots have no requested events anywhere in the current code — the epoll registration's mask lives in `reg.event.events` inside the `Epoll` description, not in the wait. Forcing "always probe" on them would require fabricating an interest. They stay probe-exempt by type.

Additionally: `host_poll_target` returns `direct(fd)` for `fd < 0` (`net.rs:668`), passing a negative number through as a host fd. It is currently unreachable because `wait_target_for_poll` early-returns empty for `guest_fd < 0`, but the arm is a live trap for any new caller and must not survive the typed rewrite.

## Red-first proof and acceptance

The migration is gated on a generated test before any representation changes: for every wait-queue-bearing `OpenDescription` kind, install the description at a guest fd, assert its readiness is empty, perform the producer action, THEN prepare and enroll the registration, then assert the registration reports `ContinuationEvent::Ready`. The existing harness carries this: `bootstrap`, `capture`, `BlockedContinuation::from_dispatch_outcome`, `CarrierWaitService::prepare_registration`, `enroll`, `await_event` (`vcpu_loop/continuation/tests.rs:2382-2420`). The test must be RED today for `Netlink` (interest `0`) and for every kind reached through a path that does not set the sentinel; it must stay green for all ten afterwards. A separate dual-source test proves an in-zone listener wakes from BOTH a host client connecting to the Darwin listen socket and an in-zone connect, each with the producer firing in the gap.

`proptest` is already a dev-dependency of `carrick-runtime` (`Cargo.toml:155`); the generated dimension is (description kind, requested-events subset, producer-before-enrollment vs producer-after-enrollment), bounded to a case count that fits `RUST_TEST_THREADS=1`.

No behaviour change for pure host fds is a gate, not an aspiration: `WaitSource::Host` lowers to exactly the `(host_fd, host_events)` pair the current code produces, and the existing `dispatch::` suite (938 tests on `54fde3e88`) must not lose a test or change a count without a named reason. No new flags and no opt-out hatch: this replaces a representation, so the old one must be deleted in the same branch — `WaitPollTargets` (`net.rs:315`), `HostPollTarget::sample_description` as a bare `bool`, `WaitFds::logical_interest`, and every `raw_one(-1, ..)` call site.

Acceptance is `just conformance-probes` green, `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::` green, `just ci` green, and the five serial workloads re-verified one at a time against their recorded baselines: `cpython-asyncio` 2551/2551, `go-net_http` MATCH 1316/1316, `cpython-xmlrpc` MATCH 84/84, `cpython-wsgiref` MATCH 36/36, and `go-net`. Never concurrently with Docker.

## Review status

Source-reviewed against HEAD `69dd945cb`. The mechanism in the director's diagnosis is confirmed by the code; the three corrections above are binding. A fourth live instance of the same lost wake exists at `dispatch/net/netlink.rs:146` and is the red-first target. No implementation has been made.
