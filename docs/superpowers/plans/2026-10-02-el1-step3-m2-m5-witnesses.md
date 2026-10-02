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
