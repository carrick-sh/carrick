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
