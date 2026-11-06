# TLB publication retains editor admission (#1736)

The existing `kernel.el1.anonymous-permissions` and
`kernel.el1.anonymous-munmap` contracts require protection and unmap effects
to be visible before successful return. The exact-MM editor remains admitted
while a host pause closes the gate and waits for that editor to finish.
Publication must therefore carry the editor's grant; requesting another open
grant after editing the mapping can turn ordinary contention into a fatal.

The permission policy now passes its held editor's grant to the hardware
venue before descriptor mutation. Resident retirement and delegated anonymous
operations do the same. Publication uses that retained translation identity
without reopening the gate. The VM-free permission witness drives the real
resident policy, raises the gate during the edit, and calls the publication
helper used by hardware. A subsequent operation refuses before editing while
the gate stays raised and succeeds after release. It adds no retry, timeout,
polling, or host-worker wait.

The scheduler witness calls `ZoneTables::cover_cow` for both slots, checks
that one slot cannot cover another, rebinds a slot to an MM with the same
publication number, then closes and frees the old MM and reuses its root/ASID
under a new MM key. Every new binding owes its own invalidation.

These witnesses establish admission lifetime and local coverage bookkeeping.
They do not prove completion on an already-running sibling. The current
publisher invalidates and covers only its own slot; sibling installation
checks do not establish when a sibling already executing EL0 stops using its
old translation. Issue #1736's P1 remains open. Closure requires qualified
backend broadcast completion, or an exact-MM shootdown whose editor retains
an owned parked continuation until every target acknowledges, including slot
rebinding and ASID retirement. A synchronous pool-worker wait is not valid.
The director must run fresh paired signed populations on the final head;
the prior recorded population is not evidence for this fix round.
