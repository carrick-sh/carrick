# User-fault exclusion contention

`kernel.el1.anonymous-reservations` covers the x86 user-fault crossings for
COW supply, COW settlement and Prepare table planning. Linux fork(2) requires
private writes to remain isolated; mmap(2) permits lazy backing on first touch.
An internal MM editor cannot turn either access into a fatal carrier error or
an errno (#2141).

Each crossing needs a settled exclusion of the faulting MM's editor. When an
EL1 editor holds the MM, the exclusion is refused `Busy`, which is contention:

- **COW supply and Prepare planning.** The carrier answers the crossing with
  `OwnerGrantReply::EditorBusy` in the lane's reply word, before it stages any
  backing. The lane withdraws its own exact selection, so its CPU keeps no
  grant, and parks through the existing FaultRetry continuation on the MM's
  Editor notification. Enrollment precedes one fresh probe; the release
  reruns the saved faulting instruction, which selects afresh. Prepare keeps
  one exclusion through allocation and the read-only table plan, as the
  native-service lane already did.
- **COW settlement.** The access is already served and its completion belongs
  to the MM. The MM's next exclusion publishes it (every supply takes one
  before it needs pool space), and the lane waits for nothing. The deferral is
  counted (`deferred_cow_completions`).

Stale, Invalid and Quarantined remain invariants. No polling, timeout
extension, extra execution lane or host wait pipe implements this wait.
Existing work and runtime budgets are unchanged.

The three KVM exclusion witnesses reuse the owed-return fixture's real editor
word and authenticated release venue. The releasing party observes an actual
Editor queue enrollment before releasing once, so an error, missed enrollment
or a lost wake fails. Their guest fixture also creates two live threads of a
forked MM with concurrent private-page writes. A separate uninjected binding
runs that same concurrent schedule. The main thread raw-exits; its kernel
clear_child_tid precedes the last worker's exit_group, keeping the independent
x86 exit_group-with-live-sibling defect outside this witness.

Two more KVM witnesses cover the wait itself. A signal sent to a thread parked
on its contended fault runs its handler exactly once before the store reruns,
with RAX intact. #2226's shape, a second thread's first stack and TLS touch
beside its spinning main thread, parks on a held editor and reruns.

These executing KVM bindings supplement the contract; they do not invent a KVM
observation layer or claim signed ARM promotion or a Docker timing ratio.
