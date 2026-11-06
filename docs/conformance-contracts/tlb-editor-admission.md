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

## Running-sibling witness still required

The missing schedule keeps two vCPUs installed in the same live MM. The
sibling primes a writable translation, then stays in EL0 while the editor
changes the descriptor and publishes its generation. The sibling must not
perform a scheduler installation between priming and the post-completion
access. After successful editor return, that access must observe the new
permission or retired mapping. A witness that explicitly re-enters the
scheduler proves a different property.

The production gap is between `HardwareAnonymousPermissionEditor` (and its
retirement counterpart) returning after `invalidate_asid` and
`ZoneTables::cover_cow` for the editing slot, and `Sched::enter_space`
checking the other slot's owed generation only on a subsequent entry. There
is no sibling acknowledgement in that return path. `ThreadCpu`'s broadcast
completion documentation states the intended architectural guarantee, but
is not a backend qualification. The recorded negative control already
strengthened `DSB ISHST`/`DSB ISH` to `DSB SY` and still failed 1/20; repeating
that change is not a fix.

An explicit acknowledgement solution must retain the exact MM, edit
generation and target slot incarnation until completion. It must close
enrollment against simultaneous slot rebinding and ASID retirement, release
execution capacity while waiting, and wake through the existing owner
notification path. Neither marking all slots covered after one broadcast
nor waiting synchronously for their coverage establishes that protocol.
Fresh signed populations must follow the actual correction; portable
scheduler bookkeeping tests cannot supply the missing hardware observation.
