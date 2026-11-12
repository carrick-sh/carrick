# follow-up: no lane walks a thread's robust futex list at exit

Refs #2109, PR #2182.

**What happens.** `set_robust_list` is stored (ring: `ThreadControlSlot::set_robust_list`;
host: `Thread::set_robust_list`), but neither the ring nor the host walks the list
when a thread exits. Linux walks the list at thread exit and execve. For each lock
word whose TID bits name the dying thread, it sets `FUTEX_OWNER_DIED`, keeps
`FUTEX_WAITERS`, clears the TID, and wakes one waiter (set_robust_list(2), futex(2),
pthread_mutexattr_setrobust(3)).

Before #2182 the ring declined a robust-registered exit into host custody "for the
host to walk". The host never walked it, so the decline was a no-op hand-off, and on
an executor with no host task it was fatal (#2109).

**What it means.** A thread that dies while holding a robust mutex leaves the mutex
owned by a dead TID. The next locker blocks forever instead of getting `EOWNERDEAD`.

**Acceptance.** One shared walker in a `no_std` `*-core` crate (the old comment named
sched-core), called by both lanes at thread exit and exec. Add a red-first
conformance probe: a thread locks a robust mutex and exits, and the survivor gets
`EOWNERDEAD`, compared against the Docker oracle. Clean room: man pages only.
