# Terminal clear custody

`kernel.thread.clear-tid-custody` covers `set_tid_address(2)` and
`CLONE_CHILD_CLEARTID`: the exiting thread clears its registered word and
wakes its joiner before exit becomes observable. Runtime registry identity
and Linux TID are separate domains; nonleader exec may promote the Linux
identity while retaining the registry runner. The Kernel thread supplies
that mapping. Capture retains the exact thread and MM; an unrelated runner
or retired MM cannot complete the clear. Work is one prepared clear and at
most one wake per retained obligation; a graph refusal cancels the permit
without either operation, and a memory wait releases executor capacity.

The VM-free `child_tid_owner_tests` include a real nonleader exec followed by
capture, clear, wake and terminal publication. `terminal_clear_loom` models
clear/wake ordering and graph refusal. The signed anonymous and fork-COW
comparison fixtures bind the terminal runtime path; broader pthread and exec
acceptance remains open.

The two-live-thread binding
`serial_host_last_sibling_clear_drain_leaves_retirement_to_terminal_owner`
forces the group-exit owner to retire before its captured
`CLONE_CHILD_CLEARTID` sibling. `LastThread` leaves that exact sibling in the
graph for the existing terminal task-exit owner; it is not a failed clear.
The drain transfers the final clear to terminal custody without a write or
wake. The terminal owner then retires the task, commits one clear and one wake,
and publishes the original group status once, including across a memory wait. Repeated drain and
terminal clear processing must perform no additional writes or wakes.
This VM-free binding does not replace signed `el1_files_exit_group_stress`.

`kernel.process.wait-owner` covers selection and consumption of a process's
children by wait4/waitid. Linux authority is wait(2)'s clone-child partition,
WNOWAIT observation, and consuming reap; wait4(2) supplies subtree CPU charging.
The shared registry must authenticate exact task serials, preserve live and
retiring children in a blocking wait, and sample the parent's wake generation
in the scan that found no event. Revision or topology admission failure must
leave the zombie, child edge and CPU ledger unchanged.

Consuming reap returns the removed non-cloneable consumer payload alongside
the semantic exit receipt, retaining exact numeric/native custody until the
caller releases the result. `consuming_wait_retains_only_selected_owned_claim_until_result_release`
proves two selected claims remain independent and release exactly once. The
same selection consumes topology and charges CPU once, with no extra scan.
The host drops its returned payload under the registry guard before observers.

The VM-free binding is `carrick-sched-core::process::wait_tests`, exercised by
`just test`. It covers two children, stale serials, observe/consume, ptrace
stops outside the child class, reservations and revision exhaustion. At 1, 8,
32 and 128 live children, with 512 unrelated processes present, unrelated
identity/event reads are exactly zero. Child identity reads are bounded by
`2*n`, and event reads by `n`, per scan; registry lookups follow only parent
edges. Consuming read prechecks accept a non-Clone UID receipt, making receipt
cloning unnecessary until the write admission. Host kernel-semantics suites
exercise the same owner through the public wait APIs. Signed ARM and live
CPL0 process bindings remain required; these inner-loop checks make no
runtime-ratio or guest-instruction claim.

`kernel.process.birth-owner` covers fork publication under retained exclusive
registry custody. Exact caller and selected-parent serial/revision, child
population collisions, group/session membership and immutable payload identity
must be authenticated before irreversible claim publication. A valid exit
participant reservation cannot license new process topology; already-admitted
thread membership remains allowed. `process::birth::tests` binds these rules,
including dropped admission, external peer roots, a genuine exit reservation
red-first refusal and zero identity reads across 512 unrelated tasks.

`kernel.process.fork-child-tid` covers `clone(SIGCHLD | CLONE_CHILD_SETTID |
CLONE_CHILD_CLEARTID, ..., ctid)` as a process fork. Linux authority is
[clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html) and
[set_tid_address(2)](https://man7.org/linux/man-pages/man2/set_tid_address.2.html):
the child sees its TID at `ctid` before returning to user mode, the parent's
private word is unchanged, and child exit zeros the word and wakes its futex.
One process birth, at most one child-MM TID store, and at most one clear and
wake are the work budget; the fork never scans or writes the parent's MM for
these effects. The VM-free bindings are
`common_linux_entry_calls_native_process_custody` for admission and
`process_clone_child_tid_lives_in_child_mm_and_clears_on_exit` for two live
processes and terminal effects. The signed bindings are the five EL1 cases
named by #491; the Docker oracle for this exact flag family remains a
separate, serialized authority check.

`kernel.process.exit-owner` covers reserved exit topology. Linux authority is
exit(2), wait(2), PR_SET_CHILD_SUBREAPER and SIGCHLD's SIG_IGN/SA_NOCLDWAIT
rules. The shared registry chooses exact-generation live ancestry, reparents
both live and zombie children, and removes the exiting child edge for autoreap.
Topology reservations retain one publication credit per live participant;
admitted thread births and nonfinal exits may advance their revisions without
closing those participants' membership gates. Dropping admission leaves their
revision unchanged; publishing topology advances the current revision.

The VM-free binding is `carrick-sched-core::process::exit_tests`, plus existing
host exit/thread-reservation tests through the same owner. Selection visits
only the exiting task, its ancestry, its children and its affected parents;
it does not scan the registry population. Private prepared-plan fields keep
adopter and child-set selection in the shared owner. Terminal zombie publication,
exit-group member selection, reservation release and parent notification ordering
use the same owner. Cancellation authority requires the exact opaque reservation
incarnation; its parent permit is available only after cancelling those members.
Notification selection authenticates the exact parent, then snapshots signal
state outside the registry guard through the existing shared signal policy.

The structural exit-effect test uses 0/1/8/32/128 own members and 512 unrelated
processes: it visits each own member once, performs at most four identity reads
for the exiting task, and performs zero unrelated identity/member reads. A full
population-scan mutant fails this budget. An unrelated reservation is refused
before exit begins, and a rebound reservation with the same numeric transaction
cannot release old effects or be erased by old rollback. Signed ARM binding and
the live CPL0 two-MM witness remain open; no runtime-ratio claim is made.
