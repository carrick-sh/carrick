# Signed deferred handback proof: bounded implementation brief

Contract: kernel.el1.deferred-handback-identity. This is a proposed fixture,
not completed evidence or historical Python crash attribution.

The source boundary is kernel el1_zone::settle_vacated, before its live(record)
check. step_away_from_slot and leave_slot_in collect RecordRefs after the
scheduler-core operation returns. A scheduler publish_zone_handback auditor
alone is too late: stale records have already been filtered. Capturing there
would fail to exercise the original bare-index-to-new-incarnation defect.

Required ordering:
1. A real signed guest creates the target futex wait, with a real continuation
   and EL1 record. Capture its exact task/thread and RecordRef at evacuation.
2. Suspend only deferred publication after queue locks and owned producer
   mutation have finished. Do not stop the carrier or hold a kernel graph,
   execution, slot, futex, or publisher registration lock while the gate waits.
3. A different guest execution lane requests control/termination, consumes the
   original continuation and retires its record. Guest-visible reap must finish.
4. A real successor wait reuses that index with a different incarnation. Prove
   this identity; allocating synthetic records from the test is insufficient.
5. Release the old publication. Assert the replacement stays parked, receives
   no readiness or wake publication, and subsequently wakes normally through
   its own producer. Require nonzero captured/retired/reused counts.

Use the existing carrier scheduler registration to route an audit event to
its kernel; do not introduce an unscoped process-global test gate. Snapshot
any callback handle and drop its registration lock before calling the audit
hook. Audit abort propagation must follow existing KernelAuditor semantics.
Scope observations to the selected record/window, not carrier-wide deltas.

Initial feasibility bound: implement one exact ordering at scale 1, with a
bounded condition-variable gate and normal executor capacity. No retries,
timeout increases or polling. If the guest cannot force the production
boundary deterministically, retain that failed fixture evidence and revise
the trigger before adding populations or broad workload runs.

Red requirement: retain an exact controlled pre-fix implementation that drops
the captured incarnation and resolves the index at delivery; the same signed
fixture must detect replacement publication. Restored production filtering
must pass. A timeout, absent capture, absent reuse, or zero work is failure,
not a semantic red or completion. Then extend 1/8/32 and bind signed structural
observations with excess-work rejection; preserve exact bytes and cleanup.

The existing notification test is the gate/receipt pattern. It is not the
fixture itself, since its held object is a process snapshot rather than an
EL1 record. No speculative production ownership fix is proposed by this brief.
