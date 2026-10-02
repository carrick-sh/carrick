# M2–M5 contract preparation (no cutover)

Baseline: `1047fefdc7cf6ee99faca70c90bf94b2e5e854d4`.
Production behavior is unchanged. No Docker, signed execution, EL0 delivery,
runtime ratio or migration acceptance is claimed. Known-red gates execute
normally and use exact `expect_err` reasons; unexpected green fails. At
cutover invert the assertion in the same commit that deletes the old owner.

## M2 — flips at M2 cutover

`dispatch::fs::pipe::tests::red_until_step3_m2_shared_close_still_needs_host_endpoint_release`
requires final shared writer close to retire the endpoint. Exact current red:
`final shared writer close retains host endpoint pin`. At 1/8/64 pairs, two
live shared tables retain respectively 1/8/64 host writer pins after shared
close. Explicit host release then produces EOF and balanced object retirement.
This is an ownership defect, not a Linux EOF bug: today's production close
also invokes the host release. Tables are live owners as in M1, not scheduled
EL0 processes.

Semantic bindings: existing broken-pipe/EOF, zero write, capacity/nonblocking,
partial-write lifetime and ABI continuation/no-replay/overlapping-VA tests.
The new `kernel.el1.ipc-lifecycle` descriptor keeps the signed 32-writer default
pool exhaustion and lifecycle differential explicitly unresolved. M2 cutover
must also cover eventfd semaphore/overflow, vectored faults, restart/cancel,
splice/tee, elastic growth and backed steady-state allocation. A host-pin
count is not a forwarded-dispatch measurement.

## M3 — flips at M3 cutover

`dispatch::net::epoll_zone::tests::red_until_step3_m3_zone_pipe_waits_create_host_proxies`
requires zero host readiness proxies for zone pipe wait enrollment. Exact red:
`all-zone pipe wait enrollment creates host readiness proxies`. At 1/8/64
members the fixture observes exactly 1/8/64 scoped proxy handles. Reader and
writer descriptions reside in two live tables; no process-global fd count is
sampled. This calls the current enrollment seam directly, not ppoll through
EL0. Existing ABI epoll LT/ET/ONESHOT, harvest/maxevents and last-file detach
and kernel cycle/fd-reuse/POLLNVAL fixtures remain positive semantics.

`kernel.el1.poll-select-owner` complements `kernel.el1.epoll-zone`; it does not
replace the landed guest harvest. Mixed external-socket plus pipe completion,
stale host token incarnation, zero/finite/infinite waits, copyout faults and
atomic mask install/enroll/recheck/restore on ready/timeout/EINTR/cancel still
need executable two-process bindings. Proxy count is not a queue-visit or
forwarded-dispatch counter; no scan-work claim is made by this fixture.

## M4 — flips at M4 cutover

- `dispatch::net::scm_rights::tests::red_until_step3_m4_rights_create_placeholder_per_message`:
  exact red `guest rights transport creates host placeholder pipes`.
  Two live tables park an eventfd description, close/reuse sender fd 3,
  claim the original description, install receiver fd 3 with CLOEXEC and
  return every logical reference. Exactly 1/8/64 scoped placeholders remain
  necessary for 1/8/64 messages. The fixture does not call host sendmsg.
- `dispatch::net::unix_pure::tests::red_until_step3_m4_stream_payloads_live_in_host_socket_state`:
  exact red `guest stream payload remains in host PureSocketState queue`.
  Two live tables own the connected endpoints. At 1/8/64 streams,
  7/56/448 payload bytes reside in host socket state before recv. Payload
  roundtrip and guest peer credentials pass independently of ownership red.

`kernel.el1.unix-owner` and `kernel.el1.unix-rights` are registered separately.
`m4_equal_address_bytes_are_isolated_by_registry_owner` keeps identical abstract
and pathname bytes in separate registries, removes/rebinds one and verifies
that the other survives. This is registry isolation, not proof that two
containers select different registries in production. Existing stream/dgram,
shutdown/HUP, claim/abort/orphan-GC reducers are positive semantics.

Still missing executable cutover bindings: pipe writer/epoll/host-file rights,
shared flags and cursor, ancillary truncation/fault rollback, queued-message
socket close, cyclic graph collection and bounded historical scan work,
backlog/nonblock/partial stream writes, datagram peek/truncation and SEQPACKET,
actual container namespace/pathname permission wiring and host-peer imports.
No Linux-semantics defect was observed in these new fixtures.

## M5 — flips at M5 cutover

`kernel::objects::signal::tests::red_until_step3_m5_shared_pending_clear_does_not_consume_host_queue`:
exact red `shared pending clear leaves host realtime queue authoritative`.
Two live task/thread fixtures in separate containers enqueue independent RT
payloads at 1/8/32/128 queue lengths. Clearing the target shared summary
leaves every host payload live; the peer remains unchanged. Host consumption
then returns each payload FIFO and both queues empty.

This intentionally exposes the projection seam. Summary clear is **not** a
Linux signal-delivery operation. At cutover replace this seam operation with
consumption through the new shared payload owner, then invert the red gate;
do not make summary clear silently discard payloads to satisfy the test.
The scale axis is queued payload count, not a target-population routing
measurement. Existing standard coalescing, RT FIFO, fork/exec mask/pending/
action reducers and thread-first provenance remain positive semantics.

`kernel.el1.signal-delivery-owner` complements the existing lease-gap,
thread-lifecycle and job-control contracts. Still missing executable cutover
bindings: multi-thread born/exit/reuse routing, permission/sender info,
CLONE_SIGHAND, exact routing at 1/8/32/128 targets, SIGPENDING accounting,
SA_RESTART/NODEFER/RESETHAND, interrupted partial pipe/socket I/O,
ppoll/pselect/sigsuspend/sigtimedwait/signalfd transactions, stop/continue/kill,
SIGCHLD, nested altstack/siglongjmp/fault/malformed sigreturn/PSTATE,
ptrace/seccomp and delivery on IRQ/fault EL0 returns.

## Preparation status and evidence limits

These five executable ownership seams and five registered descriptors are
initial preparation, **not full M2–M5 contract coverage**. The missing bindings
above must be authored before claiming any milestone is immediately ready
for cutover. No new executable guest probe was added; all new fixtures are
VM-free Rust unit tests. Any subsequent executable probe belongs in
carrick-conformance-next. Two descriptor-owner tables follow M1's reducer
convention; they do not substitute for scheduled two-process integration.
No ownership assertion is ignored or should-panic. No budget is relaxed.

Initial fixture checks caught insufficient descriptor backing and a private
module import; both were corrected. Neither is Linux red evidence. No new
Linux-semantics bug was reproduced, so no production fix is included.

## Verification receipt

With `CARGO_BUILD_JOBS=3`, foreground, on committed fixture sources:

- `just test-kernel`: exit 0; ABI 109, fd-core 32, kernel 2354 passed;
  one pre-existing ignored kernel test, 155 serial-host filtered tests.
  All kernel-semantics suites completed. All five new known-red gates and
  the registry-isolation positive test executed.
- `just clippy`: exit 0, workspace/all targets with `-D warnings`.
- `just lint-domains`: exit 0. Host-authority census is the existing macOS
  subset; Linux/FreeBSD/NetBSD compiler profiles remain pending. The exact
  97 production raw-lock-site gate passed; no production owner retired.
- `just check-inventory`: exit 0; 338 syscall rows, support classifications
  unchanged. Associations include the five new contract descriptors.
- `just fmt` and `git diff --check`: exit 0.

The first `just reconcile-inventories` refused three new SCM fixture table
guards. They are explicitly classified `test_or_definition` / `inspect_misc`
under `red_until_step3_m4_rights_create_placeholder_per_message`; taxonomy
rebinding and the full domain gate then pass. Production category counts and
compiler capture row hash are unchanged. Capture source-head is refreshed.
The read-only final review found no blocking defect in this partial groundwork
and confirmed the missing coverage prevents full cutover readiness.

Milestone commits: M2 `98ed6ae2c`, M3 `49cb164c4`, M4 `525cb6ebc`,
M5 `b1b5b007d`. Inventory reconciliation: `9a34d6937`.

Fixture source SHA-256 (after all Rust edits):

```
8228b79c5235a50831aa13474e24c9d654c6cb382640263ec777e34b1102a600  crates/carrick-kernel/src/dispatch/fs/pipe.rs
dea04f5175d27233bcc4b0cec9b625681495ccb02a0b524173f5f5f01d96e649  crates/carrick-kernel/src/dispatch/net/epoll_zone.rs
6fb32aecd9bbd588387d383f9cf085ee4e556fe19ec0f9c7b630935ef6316462  crates/carrick-kernel/src/dispatch/net/scm_rights.rs
d24c1ee0735def7a60c2352751854a1678151f5414903cad0ab26edf95254d24  crates/carrick-kernel/src/dispatch/net/unix_pure.rs
a401dc5beb024894ad54fe0a3c51e65381356c62d03bcfefeaca49f0d988f287  crates/carrick-kernel/src/kernel/objects/signal.rs
```
