# M2–M5 contract preparation (no cutover)

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
