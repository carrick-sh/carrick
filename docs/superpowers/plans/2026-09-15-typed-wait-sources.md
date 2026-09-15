# Typed Wait Sources Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** A guest fd's participation in a wait is one typed value that names where its readiness comes from, so a producer edge landing between a syscall's readiness check and the wait service's enrollment can never be lost.

**Architecture:** One `WaitRegistration` per guest fd fuses the host target and the exact `FileSlotAuthority` that today live in two independently-built lists joined by the `logical_interest` scalar. `WaitSource` is `Host` (host descriptor wakes and decides), `Description` (no host object; wait queue only), or `Dual` (both, with typed coverage). A `WaitInterest` cannot be empty and a `Host` source cannot carry one. One shared assembly function classifies, probes and parks for every wait-shaped syscall; the syscalls keep only ABI marshalling.

**Tech Stack:** Rust (`carrick-runtime`), `carrick_abi::LinuxPollEvents`/`LinuxEpollEvents`, the continuation wait service, `proptest`, line-exact conformance probes vs the Docker oracle.

**Spec:** `docs/superpowers/specs/2026-09-15-typed-wait-sources-design.md`

## Global Constraints

- `RUSTC_WRAPPER=""` prefixes EVERY `cargo` and `just` command in this environment; the global sccache wrapper fails under subagents.
- Runtime lib tests always run with `RUST_TEST_THREADS=1`.
- Never run the Docker oracle concurrently with carrick guests; serial workloads run one at a time.
- Typed domains everywhere: guest fds are `dispatch::abi_args::Fd`, host fds are `dispatch::abi_args::HostFd`, slots are `kernel::objects::FileSlotAuthority`, events are `carrick_abi::LinuxPollEvents`. No bare `i32` fd or `i16` events cross the new boundary; raw values appear only in `WaitFds`'s reactor lowering and at the `libc` call.
- A rule that lives in a comment is a bug: every exemption from the post-enrollment probe is a type, and every `HostProxyCoverage::LatchedLevelTriggered` site owes a test that proves the latch.
- No second paths, no new flags, no opt-out hatch. The old representation is deleted in this branch: `WaitPollTargets`, `HostPollTarget::sample_description` as a bare `bool`, `WaitFds::logical_interest`, `WaitFdAuthority::Logical::{strict, interest}`, and every `raw_one(-1, ..)` call site.
- TDD red-first: each task names its failing test and keeps the red receipt under `target/`.
- No behaviour change for pure host fds.
- Everything under `-D warnings`; Conventional Commits with Why/What/Verified; line-pinned inventories reconciled on a clean tree (`just reconcile-inventories --rehome`) before lint.

## Baselines to preserve

`RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::` = 942 passed at `69dd945cb`. `just conformance-probes` = 46 passed. `cpython-asyncio` 2554/2554 MATCH (after eb0578e11). `go-net_http` MATCH 1316/1316. `cpython-xmlrpc` MATCH 84/84. `cpython-wsgiref` MATCH 36/36.

## Task 1: The gap property, red against today

Files: `crates/carrick-runtime/src/dispatch/fd_table.rs` (add the exhaustive classifier next to `wait_queue`, ~L1697), `crates/carrick-runtime/src/vcpu_loop/continuation/tests.rs` (new `mod wait_enrollment_gap`).

Interfaces:
```rust
// dispatch/fd_table.rs — exhaustive, no wildcard arm: a new wait-queue-bearing
// OpenDescription variant must be classified here or the crate does not build.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitQueueKind {
    PipeReader, PipeWriter, EventFd, TimerFd,
    InMemorySocket, InZoneListenerSocket, Epoll, Netlink, Packet, InZoneListenerHostSocket,
}

#[cfg(test)]
impl OpenDescription {
    pub(crate) fn wait_queue_kind(&self) -> Option<WaitQueueKind>;
    pub(crate) const ALL_WAIT_QUEUE_KINDS: &'static [WaitQueueKind];
}
```

- [ ] Write `every_wait_queue_kind_survives_a_wake_in_the_enrollment_gap`: for each `WaitQueueKind`, install the description at a guest fd in a real `FileTable`, assert `description.readiness(interest.to_epoll(), &NoReadinessContext)` is empty, run the producer action, THEN `service.prepare_registration(&continuation)` + `service.enroll(&mut registration)`, then assert `await_event(&service, token) == Some(ContinuationEvent::Ready)`. Reuse `bootstrap` / `capture` / `BlockedContinuation::from_dispatch_outcome` / `await_event` (`continuation/tests.rs:2382-2420`).
- [ ] Write `wait_queue_kind_enumeration_is_exhaustive`: assert `ALL_WAIT_QUEUE_KINDS.len()` equals the number of `Some` results over a constructed sample of every `OpenDescription` variant, so the list cannot rot.
- [ ] Write `inzone_listener_wakes_from_host_kqueue_and_from_description_queue`: same gap ordering, twice — once with a HOST client connecting to the Darwin listen fd, once with an in-zone connect — and assert Ready both times.
- [ ] Add the `proptest` dimension `(kind, requested-events subset, producer before vs after enrollment)` with `ProptestConfig { cases: 64, .. }`; assert Ready is reported in both orderings.
- [ ] Run red and keep the receipt: `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib wait_enrollment_gap 2>&1 | tee target/red-ws-gap.log`. It MUST fail at least on `Netlink` (`net/netlink.rs:146` builds `raw_one(-1, 0)`, so `logical_interest()` is `0` and the probe is skipped).
- [ ] Verify: `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::` still 938 passed; `RUSTC_WRAPPER="" just fmt-check`; `RUSTC_WRAPPER="" just clippy`.

## Task 2: The typed wait-source domain

Files: new `crates/carrick-runtime/src/dispatch/wait_source.rs`; `crates/carrick-runtime/src/dispatch/mod.rs` (module declaration and re-export only).

Interfaces:
```rust
use carrick_abi::{LinuxEpollEvents, LinuxPollEvents};
use crate::dispatch::abi_args::{Fd, HostFd};
use crate::kernel::objects::FileSlotAuthority;

/// The poll interest a description-backed source is probed with. NEVER empty:
/// an empty interest is the state that produced three lost-wake hangs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WaitInterest(LinuxPollEvents);

impl WaitInterest {
    pub(crate) fn new(events: LinuxPollEvents) -> Option<Self>;
    pub(crate) const fn events(self) -> LinuxPollEvents;
    pub(crate) const fn epoll(self) -> LinuxEpollEvents;
}

/// A host descriptor the reactor parks on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostWaitTarget { fd: HostFd, events: LinuxPollEvents }

/// Whether a `Dual` source's host descriptor is a COMPLETE latched mirror of
/// the description's readiness, or only observes host-crossing producers.
/// Every `LatchedLevelTriggered` construction owes a latch proof test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostProxyCoverage { LatchedLevelTriggered, HostPeersOnly }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitSource {
    Host { host: HostWaitTarget },
    Description { interest: WaitInterest },
    Dual { host: HostWaitTarget, interest: WaitInterest, coverage: HostProxyCoverage },
}

impl WaitSource {
    /// `Some` exactly when the wait service must enrol on the description's
    /// wait queue; `None` for a pure host source.
    pub(crate) const fn description_interest(&self) -> Option<WaitInterest>;
    /// `true` when the post-enrolment probe is required.
    pub(crate) const fn probe_after_enrol(&self) -> bool;
    pub(crate) const fn host(&self) -> Option<HostWaitTarget>;
}

/// One guest fd's participation in a wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WaitRegistration {
    guest_fd: Fd,
    slot: FileSlotAuthority,
    requested: LinuxPollEvents,
    source: WaitSource,
}

/// An advisory slot: re-dispatch on slot replacement, never probed. Carries no
/// `WaitInterest`, so "probe a watched slot" is not expressible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WatchedSlot(FileSlotAuthority);
```

- [ ] Write red unit tests in the new module: `wait_interest_rejects_empty_events`; `host_source_has_no_description_interest`; `dual_source_requires_both_a_host_target_and_an_interest`; `latched_coverage_is_unrepresentable_without_a_host_target` (type-level: assert by construction that `HostProxyCoverage` has no path outside `Dual`).
- [ ] Implement the module. No `Default`, no `pub` constructor that takes a bare `i32`.
- [ ] Verify: `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::wait_source`; `RUSTC_WRAPPER="" just fmt-check`; `RUSTC_WRAPPER="" just clippy`; `RUSTC_WRAPPER="" just lint-domains`.

## Task 3: Carry registrations in the authority; delete the scalar

Files: `crates/carrick-runtime/src/dispatch/wait_authority.rs`; `crates/carrick-runtime/src/vcpu_loop/continuation/wait_service.rs`; `crates/carrick-runtime/src/vcpu_loop/continuation/readiness.rs`; `crates/carrick-runtime/src/dispatch/fd_wait.rs`.

Interfaces:
```rust
pub(crate) enum WaitFdAuthority {
    Empty,
    Missing,
    Logical { registrations: Vec<WaitRegistration>, watched: Vec<WatchedSlot> },
    Internal(InternalWaitAuthority),
}

impl WaitFds {
    /// Build both the reactor lowering and the authority from ONE list.
    /// `Host`/`Dual` sources lower to a `WaitFd::raw(host.fd.get(), host.events.bits())`;
    /// `Description` sources contribute NO reactor entry (the `-1` sentinel is gone).
    pub(in crate::dispatch) fn from_registrations(
        registrations: Vec<WaitRegistration>,
        watched: Vec<WatchedSlot>,
    ) -> Result<Self, LinuxErrno>;
}
```

- [ ] Rewrite `install_producer_subscriptions` (`wait_service.rs:1158-1216`) to iterate `registrations`: subscribe `registration.slot`; if `registration.source.description_interest()` is `Some`, enrol on `description.wait_queue()`; if `registration.source.probe_after_enrol()`, probe `description.readiness(interest.epoll(), &NoReadinessContext)` UNCONDITIONALLY and publish `Ready` when non-empty. Then iterate `watched`: subscribe the slot and enrol on its wait queue, never probe.
- [ ] Delete `WaitFds::logical_interest`, `WaitFdAuthority::Logical::{strict, interest}`, and the `if *interest != 0` gate.
- [ ] Keep `with_guest_slots` / `with_redispatch_and_watched_slots` as thin adapters ONLY for the duration of Tasks 4-7, each marked with the task that removes it; they must produce `Host` sources from a raw host fd and `Description` sources from an explicit `WaitInterest` — never from a sentinel.
- [ ] Update `logical_authorities_for_test` / `watched_authorities_for_test` and `ReadinessProbe::Fds`'s `fd_authority` clone to the new shape.
- [ ] Verify Task 1 turns GREEN: `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib wait_enrollment_gap 2>&1 | tee target/green-ws-gap.log`.
- [ ] Verify: `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::`; `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib vcpu_loop::`; `RUSTC_WRAPPER="" just conformance-probes`.

## Task 4: Classification — `wait_source_for` replaces the sentinel

Files: `crates/carrick-runtime/src/dispatch/net.rs` only.

Interfaces:
```rust
impl<'a> NetView<'a> {
    /// The ONE classification every wait-shaped syscall shares. Replaces
    /// `host_poll_target` + `wait_target_for_poll`.
    pub(in crate::dispatch) fn wait_source_for(
        &self,
        files: &crate::kernel::FileTable,
        guest_fd: Fd,
        requested: LinuxPollEvents,
    ) -> Result<Option<WaitRegistration>, LinuxErrno>;
}
```

- [ ] Write red tests: `inzone_listener_classifies_as_dual_host_peers_only`; `in_memory_socket_classifies_as_description`; `readiness_pipe_classifies_as_dual_latched`; `host_socket_classifies_as_host`; `negative_guest_fd_yields_none_and_never_a_host_target` (pins the `net.rs:668` `fd < 0 => direct(fd)` trap closed); `bare_stdio_classifies_as_host`.
- [ ] Implement `wait_source_for` by porting the `host_poll_target` match (`net.rs:592-672`): `HostPipe`/`HostFile`/`HostSocket`(non-in-zone)/`Pidfd`/`Inotify`/`Fanotify`/stdio → `Host`; `PipeReader`/`PipeWriter`/`EventFd`/`Epoll` readiness pipes → `Dual { coverage: LatchedLevelTriggered }`; listening `HostSocket` with `inzone_listener` → `Dual { coverage: HostPeersOnly }`; everything else with an open description → `Description`. Delete the `fd < 0` arm.
- [ ] Route `ppoll` (both arms) and `pselect6` (both arms) through `wait_source_for` + `WaitFds::from_registrations`. Do NOT yet move the revents normalizations.
- [ ] Delete `WaitPollTargets` (`net.rs:315-350`), `wait_target_for_poll` (`net.rs:691-710`), and `HostPollTarget`.
- [ ] Verify: `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::`; `RUSTC_WRAPPER="" just conformance-probes`; the four `*_carries_logical_pollin_interest` tests from `28445af8c`/`54fde3e88` are rewritten in terms of `WaitSource` and stay green.

## Task 5: One shared assembly

Files: new `crates/carrick-runtime/src/dispatch/wait_plan.rs`; `crates/carrick-runtime/src/dispatch/net.rs`; `crates/carrick-runtime/src/dispatch/mod.rs` (module declaration).

Interfaces:
```rust
pub(in crate::dispatch) struct WaitRequestFd { pub fd: Fd, pub requested: LinuxPollEvents }

pub(in crate::dispatch) enum WaitAssembly {
    /// Per-fd guest-visible revents in request order; at least one non-empty.
    Ready { revents: Vec<LinuxPollEvents> },
    /// Nothing ready and the caller may block.
    Park { revents: Vec<LinuxPollEvents>, wait: WaitFds },
    /// Nothing ready and the caller may not block.
    NotReady { revents: Vec<LinuxPollEvents> },
    Errno(LinuxErrno),
}

impl<'a> NetView<'a> {
    pub(in crate::dispatch) fn assemble_wait(
        &self,
        files: &crate::kernel::FileTable,
        request: &[WaitRequestFd],
        may_block: bool,
        watched: &[Fd],
    ) -> WaitAssembly;
}
```

- [ ] Write red tests: `assemble_batches_all_host_sources_into_one_poll`; `assemble_samples_description_for_dual_host_peers_only_even_when_host_is_idle`; `assemble_samples_description_for_latched_dual_only_when_the_host_edge_fired`; `assemble_returns_not_ready_when_may_block_is_false`; `assemble_orders_revents_by_request_index`.
- [ ] Implement: classify via `wait_source_for`; one `libc::poll(..., 0)` over the `Host` and `Dual` host targets; sample `poll_ready_events` for `Description` always, for `Dual/HostPeersOnly` always, and for `Dual/LatchedLevelTriggered` only when its host entry fired (the current `readiness_pipe` gate, now typed).
- [ ] Reduce `pselect6` (`net.rs:2722`) and `ppoll` (`net.rs:3177`) to ABI marshalling over `assemble_wait`: `fd_set` read/write and `clear_on_timeout` for select, `pollfd` writeback for poll, `BlockingFdWait` construction where they build one today. The two four-arm bodies collapse to one arm each.
- [ ] Verify: `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::`; `RUSTC_WRAPPER="" just conformance-probes`; `RUSTC_WRAPPER="" just --no-deps conformance full --suite cpython-asyncio --workers 1 --carrick-timeout-cap-s 0 --flake-retries 0 --require-cached-oracle` (expect MATCH 2554/2554).

## Task 6: Blocking syscalls adopt the assembly

Files, in this order, one commit each so a regression bisects to a single syscall family: `dispatch/net/netlink.rs`; `dispatch/net.rs` (`blocking_io`, `wait_in_memory_slot`); `dispatch/net/send_recv.rs`; `dispatch/net/lifecycle.rs`; `dispatch/fs/rw.rs`; `dispatch/fs/transfer.rs`; `dispatch/fs/pipe.rs`; `dispatch/fs/sendfile.rs`; `dispatch/ioring.rs`; `dispatch/io_pipe.rs`; `dispatch/proc.rs`; `dispatch/syslog.rs`.

- [ ] `netlink.rs:146` FIRST: it is the open lost wake. Replace `WaitFds::raw_one(-1, 0)` with a one-element `assemble_wait` whose `WaitInterest` is `LinuxPollEvents::IN`. Red test: `netlink_recv_wakes_when_the_dump_lands_in_the_enrollment_gap` (drive `empty_netlink_recv`, then `enqueue_netlink_message`, then enrol, assert Ready). Keep the red receipt.
- [ ] `net.rs:3728 wait_in_memory_slot` and `net.rs:844 blocking_io` become thin wrappers over `assemble_wait` with a single `WaitRequestFd`; delete `WaitFds::raw_one(-1, ..)` entirely.
- [ ] `lifecycle.rs:1452-1477`: the hand-rolled `raw(vec![(host_fd, POLLIN), (-1, POLLIN)])` becomes the `Dual { HostPeersOnly }` that `wait_source_for` already produces. No special case survives in `accept_common`.
- [ ] `lifecycle.rs:1670`, `:3640`: connect-completion parks go through the assembly with `LinuxPollEvents::OUT`.
- [ ] Remaining files: mechanical, one `WaitRequestFd` each.
- [ ] Delete `WaitFds::raw`, `raw_one`, `authorized_raw_one`, `with_guest_slots`, `with_redispatch_and_watched_slots` and the `#[cfg(test)] with_slot_authorities` adapter once the last caller is gone. `anchored_one` / `anchored_parked_opener` stay (host-fd guards and the FIFO `Internal` authority are out of scope).
- [ ] Verify after EACH file: `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::` and `RUSTC_WRAPPER="" just conformance-probes`.

## Task 7: epoll adopts the assembly, with the latch proven

Files: `crates/carrick-runtime/src/dispatch/net/epoll_ops.rs`.

- [ ] Write the latch proof red-first: `epoll_instance_user_wake_is_latched_across_the_enrolment_gap` — register an in-memory target, park `epoll_pwait`, fire the producer (which calls `notify_inmem_epoll` → `event_mux::trigger_user_wake_fd`) BEFORE enrolment, enrol, assert the reactor's host poll on `kq_fd` reports readable. Without this, the epoll source must be `HostPeersOnly` and take the probe.
- [ ] Write `readiness_pipe_is_level_triggered_across_the_enrolment_gap` for `PipeReader`/`PipeWriter`/`EventFd`, same shape. These three tests are what licence `HostProxyCoverage::LatchedLevelTriggered`.
- [ ] Route the three park arms (`epoll_ops.rs:1719`, `:1751`, `:1780`) through `assemble_wait` with `watched` carrying the interest targets as `WatchedSlot`. The `kq_drained_all_filtered` arm keeps its empty-mask backstop; express it as `Host { events: LinuxPollEvents::empty() }`, not as `raw_one(kq_fd, 0)`.
- [ ] Verify: `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::net::epoll_ops`; `RUSTC_WRAPPER="" just conformance-probes`; `RUSTC_WRAPPER="" just --no-deps conformance full --suite go-net_http --workers 1 --carrick-timeout-cap-s 0 --flake-retries 0 --require-cached-oracle` (expect MATCH 1316/1316) — this is the Go netpoll regression gate for the probe policy.

## Task 8: revents normalization parity

Files: `crates/carrick-runtime/src/dispatch/wait_plan.rs`; `conformance-probes/src/bin/pollhup.rs`, `selectbits.rs`, `inzonetcp.rs`; `crates/carrick-cli/tests/probe-oracle/arm64-{gnu,musl}/*`.

- [ ] Write red probe cases proving `pselect`/`select` and `poll`/`ppoll` currently DISAGREE with Linux on the same fd: `POLLRDHUP` reconstruction from `EV_EOF`, spurious `POLLPRI` on a regular file, `POLLOUT`/`POLLHUP` on a listening socket. Capture the red run and refresh the gnu/musl Docker oracles.
- [ ] Move the three normalizations from `ppoll`'s all-host arm (`net.rs:3371-3393`) into `assemble_wait` so both syscalls and epoll share them. This is the only deliberate behaviour change to `pselect6` in this plan; it must be its own commit.
- [ ] Verify: `RUSTC_WRAPPER="" just conformance-probes`; `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::`.

## Task 9: Delete the old representation and reconcile

Files: `dispatch/wait_authority.rs`, `dispatch/net.rs`, `scripts/migrate/*` inventories.

- [ ] `grep -rn "raw_one(-1\|logical_interest\|WaitPollTargets\|sample_description\|host_poll_target" crates/` returns nothing outside history.
- [ ] `RUSTC_WRAPPER="" just reconcile-inventories --rehome` on a clean tree; commit as `chore: reconcile line-pinned inventories ...`.
- [ ] Verify: `RUSTC_WRAPPER="" just lint-domains`; `RUSTC_WRAPPER="" just fmt-check`; `RUSTC_WRAPPER="" just clippy`; `RUSTC_WRAPPER="" just deny`.

## Task 10: Full closure

- [ ] `RUSTC_WRAPPER="" just ci`.
- [ ] `RUSTC_WRAPPER="" RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch:: 2>&1 | tee target/unit-ws-final.log` — count must be >= 942 plus the new tests, with no test deleted without a named reason in the commit.
- [ ] `RUSTC_WRAPPER="" just conformance-probes 2>&1 | tee target/probes-ws-final.log`.
- [ ] Serial workloads, ONE AT A TIME, never concurrently with Docker, each as
      `RUSTC_WRAPPER="" just --no-deps conformance full --suite <name> --workers 1 --carrick-timeout-cap-s 0 --flake-retries 0 --require-cached-oracle`:
      `cpython-asyncio` (MATCH 2554/2554), `go-net_http` (MATCH 1316/1316), `cpython-xmlrpc` (MATCH 84/84), `cpython-wsgiref` (MATCH 36/36), `go-net` (MATCH 449/449), `ltp-connect02` (MATCH).
- [ ] Stop at the first red rung; a failed rung blocks promotion. No retries-until-green.

## Rulings

- The migration is red-first on a property, not on a symptom: Task 1's generated gap test must fail before any representation changes, and it is the acceptance criterion for Task 3.
- `netlink.rs:146` is a live instance of the fixed bug class and is repaired first in Task 6, not opportunistically.
- `HostProxyCoverage::LatchedLevelTriggered` is the ONLY exemption from the unconditional post-enrolment probe, it exists only inside `Dual`, and it is licensed per site by a latch test in Task 7. If a latch test cannot be written for a site, that site is `HostPeersOnly` and takes the probe.
- Blocking FIFO `open` (`fs/open.rs:387,403`, `WaitFdAuthority::Internal(FifoOpen)`) is out of scope: there is no guest fd and no description to register.
- Moving `ppoll`'s revents normalizations into the shared assembly changes `pselect6` behaviour toward Linux; it is sequenced last and gated on refreshed line-exact oracles so a regression bisects cleanly.
