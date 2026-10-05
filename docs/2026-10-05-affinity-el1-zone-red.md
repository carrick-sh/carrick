# EL1 zone affinity: red witness sequenced after N1

This draft follows PR #49 and is deliberately red. It changes no production
scheduler behavior. The director sequenced the EL1 owner correction after
`work/n1`, which is rewriting zone custody and control-slot record publication.
The six documented N1 failures remain outside PR #49.

Linux sched_setaffinity names an exact thread; excluding its current CPU requires
migration. PR #49 closes host queue admission and exact host-running executor
kicks. A guest-switched thread can instead be host-Blocked with an owned zone
continuation and guest-OnCpu. Its host execution record does not identify the
currently running zone slot, and its ZoneRecord retains a cached affinity mask.

Two VM-free serial-host witnesses exercise actual kernel threads, the global
carrier zone mapping, and the existing exact RecordRef protocol:

- `affinity_change_updates_a_host_blocked_guest_running_record` parks a sibling
  through an owned zone continuation, wakes and switches it onto guest CPU 1,
  confirms host Blocked plus guest OnCpu and Linux state R, then changes the
  target mask to CPU 0. The thread mask is 1 and the caller stays unchanged,
  but the exact live record still has mask 2.
- `affinity_change_before_zone_reference_publication_is_not_lost` makes the
  publication order deterministic: capture the slot mask 2, change the exact
  thread to mask 1 while it has no record reference, then use the real
  current_or_new / bind_zone_record operations to publish the old identity.
  The queued record still has mask 2. A setter that only updates an already
  published record cannot close this window.

The second case models the explicit production operation order in
`carrick-el1::sched::Sched::current_record`; it does not boot a guest or claim
hardware interrupt delivery. Both cases allocate real aligned carrier-region
storage, authenticate exact thread serials and record incarnations, and use no
waiting loop, timer advancement, load injection, or increased timeout.

Root cause: `Thread::set_affinity` updates the thread mask and exact host-running
residency capability. `ZoneRecord.affinity` is a separate cached value, initialized
by record allocation and refreshed by unhome. `Sched::current_record` reads the
slot's cached mask before allocating/finding the record, then publishes its
RecordRef into ThreadControlSlot. That publication is not atomic with the host
mask change. ThreadControlSlot's bounded seqlock projection can also return None
for a concurrent writer. Neither missing projection permits dropping a control
operation, nor can a home-placement affinity bypass replace the Linux guarantee.

The future correction must preserve exact TaskKey/ThreadKey/generation and record
incarnation authority across record publication, exclusion, handback and retired
no-op. It must kick the actual guest owner and prevent another excluded guest
entry, including the pre-publication window. This draft proposes no second owner
path or population scan before the N1 owner protocol is settled.

Verification on cloudmac, based on af1240c4c:

```
RUST_TEST_THREADS=1 cargo test -p carrick-kernel --lib \
  kernel::scheduler::tests::serial_host::affinity_change -- --nocapture
```

Receipt: `target/storm-investigation/el1-zone-affinity-red.log`. Compilation
succeeds; both assertions fail deterministically with left 2, right 1. This is
an unresolved defect witness, not a passing implementation or acceptance receipt.
