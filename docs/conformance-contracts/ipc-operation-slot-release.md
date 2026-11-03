# IPC operation-slot release (#1509, bottom layer)

Contract: `kernel.el1.ipc-two-process`. Linux blocking IPC semantics do not
permit Carrick's internal operation-arena capacity to produce an errno or
force a retained call onto a different service path.

The retained-admission primitive subscribes to a carrier-lifetime release
source. A miss observes that source before one re-probe. The shared
`Refusal::Contended` owns the unchanged operation, a linear release ticket
and the pre-probe snapshot. The next retained
poll layer must enroll that owner and recheck once, preserving its syscall
arguments; this prerequisite does not change existing read/write admission.

Every production retirement publishes after returning a reusable operation
slot. Native and host retirement use their respective completion venues.
The source occupies a disjoint rounded spare scheduler queue and is keyed
by the shared IPC authority identity. Its base admission lasts for the zone's
lifetime; queue contention defers delivery to the existing unlock owner.
There is no periodic capacity scan, host readiness pipe or extra slot pool.
A permanently quarantined generation and a rejected stale token publish no
availability edge.

The VM-free Busy-once witness fills all 1024 real operation records, enrolls
a real scheduler record, retires through the shipping adapter, requires the
waiter to become runnable, and admits the unchanged input into the returned
slot. Its pre-fix failure was `actual operation retirement must wake the
enrolled waiter`. Scheduler witnesses also cover initial admission Busy and
publication while the queue is held: revision advances immediately, delivery
occurs once after unlock, and the original continuation token survives.
The ABI witness requires free-list visibility inside the notification and
zero notifications for stale or quarantined records.

These deterministic tests establish release custody and bounded work (at most two
allocation probes and one release publication, without polling). They
prove neither retained poll semantics nor ARM guest execution. PollWait,
its contract `kernel.poll.retained-wait`, oracle fixtures and the signed ARM
`el1_memory_first_touch_stays_in_guest` confirmation belong to the next layer
and director acceptance. No Docker timing or signed result is claimed here.

## ABI compatibility

`IpcRegion::finish_operation` now requires a release callback; every native
and host caller supplies its existing scheduler completion venue. This is a
Rust API change, with no new fields, operation kinds or IPC layout facts:
`IPC_LAYOUT_HASH` is unchanged. The scheduler reserves a previously spare
queue for this carrier source, adds that index to its layout facts, and
increments `OBJECT_WAIT_PROTOCOL` from 12 to 13. Consequently the enclosing
`EL1_ABI_LAYOUT_HASH` changes; host and guest images must be rebuilt together.
This layer adds no PollWait payload or protocol discriminant.

## Reproducing the pre-fix failure

Keep the admission API and witness, but replace the single `released()` in
`IpcRegion::finish_operation` with `let _ = released;`. This restores the
admitted main's retirement behavior: the free-list push occurs without a
scheduler notification. Run:

```sh
cargo test -p carrick-el1-linux --lib ipc_operation_slot_busy_once_then_success -- --test-threads=2
```

The mutation exits 101 at `actual operation retirement must wake the enrolled
waiter` (one test failed). Restore `released()` for the green run. This is a
production-path mutation of main's missing publication, not a claim that the
new admission API or witness already exists on main. The witness calls the
public `admit_operation_wait`, enrolls its shared contention ticket through
`park_and_rerun`, then calls the same `finish` used by shipping IPC completion.
