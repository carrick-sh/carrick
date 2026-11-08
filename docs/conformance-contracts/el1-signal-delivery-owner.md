# Host-classified synchronous faults (#1075)

`kernel.el1.signal-delivery-owner` includes native-owner MAPERR (signal 11,
si_code 1) and file-past-EOF BUS_ADRERR (signal 7, si_code 2), retaining the
exact fault address. Authority is `sigaction(2)` and `signal(7)`. One retained
payload per exact thread crosses the host VMA classification boundary; no host
signal action is selected. The existing native checkpoint and shared signal
owner select the action once. Blocked or ignored synchronous faults become
default, and that selected default returns to the existing host core/exit path
without a second ptrace stop. Busy admission retains the payload and forwards.
The compiled fault stack chain charges the larger resolver/checkpoint prefix;
no extra execution pool or second signal frame builder is introduced.
The retained Busy path currently re-enters across the host boundary without
a release subscription; park-and-probe completion remains tracked by #1083.

VM-free bindings cover both numeric payloads, native handler frames, selected
default, ignored and blocked actions, and action replacement before delivery.
The retained-home Busy witness exercises the same admission path, then releases
the holder and requires successful delivery with no retained payload. Engines
without a native fault entry (currently x86, seam #1084) return a typed absent
venue; runtime preserves signal termination and clears the published payload.
A two-live-thread witness enters the production fault wrapper with admission
already closed by a sibling's exit_group; the single inner venue owner marks
a terminal fallback rather than retrying the owner checkpoint. A host witness
consumes that default payload and runs the production terminal-loser path,
finishing only the faulting thread while preserving the sibling's exit claim.
A retained payload is admitted only on an actual fault or the explicit host-fault checkpoint, never on a syscall or interrupt return.
Closed-gate and absent-venue settlement use bounded slot reads and one
settlement. The existing
`siglongjmpaltstack` probe now recovers from real MAPERR and file-past-EOF faults
through `siglongjmp`, and checks default and blocked signal 11 in fork children
with a five-second pipe wait. Its updated source requires deliberate native
Linux oracle refresh and fresh ARM libc executables; no cached result is claimed
for that changed input. Signed probe/frame execution and the existing
`crash_parked_thread` core witness remain director-owned on HVF. No Docker or
HVF is available on ctb-w1. CPL0 already delivers MAPERR through the shared
owner; missing file-backed classification and host-to-native checkpoint wiring
are tracked by #1084 (related cancellation seam #1078).

Signal setup may park its exact owner and select a runnable peer on the same
slot. Signal dequeue, mask restoration and frame publication must authenticate
the currently selected task, member control and execution binding together.
The pre-dispatch native entry cannot accompany its successor's registers.
The final EL0 checkpoint re-enters the selected owner after dispatch and
continuation settlement, including SVC returns from retained copyout.
Unblocking a pending signal before an old-mask output wait delivers it once
before that thread returns to EL0; it never redirects its runnable peer.
The two-live-thread witnesses in `native_signal_resume_tests` cover input and
output parks, peer-frame preservation and the resumed SVC checkpoint.

Completed entries with owed work also checkpoint the selected signal owner.
Successful signal publication preserves the existing work ledger; it cannot
erase a committed result or manufacture the vector's host-work doorbell.
CarrierWork is internal completion custody, so caught signals cannot cancel
it through any service-wait enrollment or cross-thread cancellation path.
Terminal cancellation remains authoritative. An in-ring service completion
checkpoints before its first user return, including a reply acknowledged
before park enrollment. Only an interrupted Crossing uses the ARM restart
marker; a committed CarrierWork result of EINTR is never replayed.
The two-live-thread `native_signal_work_return_tests` cover both mask operations,
null and resident oldset, exact service acknowledgment before park, restart
and no-restart frames, and preservation of genuine host work. Compiled stack
envelopes include service-return and saved-resume delivery and terminal tails.

A host-owned SignalOwner borrows the ring lane only for its retained operation.
After output completes, it checkpoints the exact saved context before publishing
UserReturn to the host executor. The required callback uses the shared delivery
policy on ARM and x86 and preserves the allocated signal-frame stack pointer.
Real pending carrier work keeps this native continuation until its exact reply
is consumed. Even a reply acknowledged before park is deferred to that owned
checkpoint; it cannot return a host-owned member directly to EL0 in ring.
The two-live-thread `native_host_owned_signal_resume_tests` use the production
scheduler load and resume_production path for a rehomed host-owned root, with
no work, a parked carrier reply and an inline carrier acknowledgment. A
shared-policy refusal observed before a concurrent work drain remains owned
until its exact checkpoint; clearing the doorbell cannot erase that obligation.

For #887, a fresh-root refusal retains the classification snapshot alongside
its original contention identity. Both ISA adapters use the shared classifier.
The four pairs printed as `lookup_members_records_groups_by_process` describe
`members[execution]`, `records[record]`, `groups[group]`, and the group reached
through `by_process[process]`, in that order. Each first word contains a task
ID in its low 32 bits and flags above bit 31: 1 means index present, 2 means
its downstream lookup succeeded, and 4 means the runtime Arc agrees with the
execution member. The second word is the execution generation for members and
records, or the neutral process serial for groups. Zero identity means absent.
For records the downstream lookup is its member; for groups it is task binding;
for by_process it is the indexed group. Missing flags distinguish absence from
Arc disagreement. The snapshot and classification use the same registry guard;
receipt folding still precedes them. There are no retries or registry scans.

The original x4–x11 identity words remain intact. The snapshot uses x12–x17
and x20–x21 at the existing terminal HVC, leaving platform-reserved x18 alone.
The formatted terminal record remains 1024 bytes; the maximum-width rendering
witness includes all sixteen words. This is attribution only, not a lifecycle
fix, a cross-holder wait, or permission to wait for a self-held projection.

### #887 round 3 key attribution

On fresh-root refusal with a retained member and process index, the existing
sixteen-word terminal payload carries both group keys. Each tuple is
`[carrier, MM, root GPA, lifecycle page, namespace PID]`. The output also
records the registered and observed scheduler record IDs/incarnations and
packs the four existing lookup flag bytes in member, record, direct-group,
process-index order (least-significant byte first). The last lookup word
`0x47524f55504b4559` selects this view; other admission refusals retain the
identity view. This changes diagnostic contents, not register count or layout.

The VM-free known-answer test renews a scheduler record and deliberately
publishes a different PID before calling production classification and
fresh-root admission. It proves that the snapshot names both keys, both records
and self-held pending custody. It does not identify the signed workload's
producer or claim PID is the drifting component. The maximum-width formatter
test enforces the existing 1024-byte sink limit.

Registration still prepares custody before consuming an adopted host birth
(#1882). Existing-group recovery, source correction, x86 fatal transport and
paired signed proof remain outstanding pending the actual key snapshot.
