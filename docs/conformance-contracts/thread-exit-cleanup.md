# Thread exit cleanup (#1724)

Contract: `kernel.el1.thread-lifecycle`.

Linux's `set_tid_address(2)` and `get_robust_list(2)` describe best-effort
terminal memory accesses. A bad robust head ends the walk; a bad robust word
is skipped after retaining its successor. A bad clear-TID store must never
return an errno from exit. This contract also requires one TID wake after
settling that store.

The neutral `ThreadCleanup<P>` retains the exact execution binding, entry
incarnation, original status and personality cursor. The native pending table
keys it by `RecordRef`, including its incarnation. Both ordinary native entry
and service re-entry consume it before user execution. Linux owns the robust
list's 24-byte header, successor, pending entry, 2048-entry cycle bound and
owner-death CAS policy. The successor is read before touching each futex.
Pending entries present in the list are processed once at the end. PI entries
remain outside the non-PI CAS protocol; this change does not implement PI
futex ownership.

`MmPortal::access_user_target` uses the same selection, supply and exact-MM
fence as byte writes. ARM and x86 perform aligned atomic accesses while that
fence remains alive. Preparation alone never authorizes an unfenced CAS.
The service cell owns backing supply or the existing MM producer wait. A
terminal payload is exempt from cancellation by the very process exit it is
finishing. A refusal consumes the current cursor phase as Fault; Supplied
resumes that phase. Neither result becomes a user errno or syscall replay.
No editor, transfer fence or scheduler bucket survives a park.

After cleanup, the existing neutral membership and scheduler retirement
transactions settle the member. A member which becomes last during cleanup
enters process exit with its original status. Terminal group workers use the
same cleanup before publishing their member receipt. A completed TID wake is
not repeated when a later terminal step resumes.

The original seven production ARM witnesses were red before this round and
green in its first native run. Additional production bindings cover resident
robust entries and a pending operation, real TID waiters, adopted and
native-owned threads, owner Gate waits, and refused service replies. The
structural bound is one header, one successor read per examined entry, one
successful owner-death update and wake per owned word, and one clear-TID wake.
A faulting word cannot pin the cursor. Each successful physical supply must
advance its existing bounded MM transfer.

Acceptance still requires the final focused suites and independent review.
VM-free observations do not establish signed HVF execution, live KVM backing
supply, a Docker comparison or a runtime ratio. Those gates must be recorded
separately; no signed acceptance is claimed by this note.

## Remaining P0 from independent review

The raw-exit owner now acquires ABI exit admission before cleanup and retains
it with the cursor across a memory park. The production witness
`raw_exit_keeps_admission_when_fork_closes_gate_during_cleanup` closes the
fork gate during that park for adopted and native-owned members; before the
fix it failed with NativeQuarantined on service resume. Nonfinal membership
is still acquired after cleanup, allowing a member that becomes final to
enter process exit with its original status.

Initial admission contention remains unresolved: ForkClosing, HostOnly and
AwaitingExecBinding observed before the cleanup starts reach a refusal arm.
This is not valid terminal custody. The next change must retain the admitted
terminal membership/admission across memory waits and, where admission itself
contends, enroll on the holder's existing release notification and reprobe.
An unadopted thread cannot fall back to a host adopter. Add a production
Busy-once/holder-release witness before claiming acceptance.

The two-raw-exit final-member witness is now green. Its initial leader
retirement uses neutral terminal custody, then removes the actual graph and
registry member; its two worker exits use production native entry and a real
MM producer queue. Initial lifecycle-gate contention above remains open.
