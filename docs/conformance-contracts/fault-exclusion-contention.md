# User-fault exclusion contention

`kernel.el1.anonymous-reservations` covers the x86 user-fault crossings for
COW supply, COW settlement and Prepare table planning. Linux fork(2) requires
private writes to remain isolated; mmap(2) permits lazy backing on first touch.
An internal MM editor cannot turn either access into a fatal carrier error.

A refused exclusion retains the selected access and any MM-owned completion,
releases execution capacity and uses the existing FaultRetry continuation on
the exact MM Editor notification. Enrollment precedes one fresh probe; release
reruns the saved faulting instruction. Stale, Invalid and Quarantined remain
invariants. No polling, timeout extension, extra execution lane or host wait
pipe implements this wait. Existing work and runtime budgets are unchanged.

The three KVM exclusion witnesses reuse the owed-return fixture's real editor
word and authenticated release venue. The releasing party observes an actual
Editor queue enrollment before releasing once, so an error, missed enrollment
or a lost wake fails. Their guest fixture also creates two live threads of a
forked MM with concurrent private-page writes. A separate uninjected binding
runs that same concurrent schedule. The main thread raw-exits; its kernel
clear_child_tid precedes the last worker's exit_group, keeping the independent
x86 exit_group-with-live-sibling defect outside this witness.

These executing KVM bindings supplement the contract; they do not invent a KVM
observation layer or claim signed ARM promotion or a Docker timing ratio.
