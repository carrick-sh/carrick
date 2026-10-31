# Host bridge process-signal custody

`kernel.el1.signal-delivery-owner` also binds `carrick-signal-linux`'s
`single_mask_*` tests and the real HAL fallback-timer wake reentry test.
Linux authority is standard-signal coalescence and lowest eligible delivery
(`signal(7)`, `sigwaitinfo(2)`). The existing `PendingSet` is the only mask:
queries load it; async publication only ORs it, including zero/multi-bit input.
A normal custodian owns 64 inline complete origins (Host, interval timer, or
POSIX timer with full id/overrun/value). Timer preparation/publication, removal
and payload copy/reset, clear, wake claim and exact-tid retirement use that
custodian. Claim rechecks eligibility after acquisition; normal owner-gated
take checks ownership there. Thread-first delivery and masked-wait bypass stay
distinct; pure queries reserve nothing. No universal joint ordering with
thread/xsignal queries or universal timer-OR linearization point is asserted.

Valid timers, including coalescence, add one normal acquisition. Nonempty
process-take attempts, eligible wake-claim attempts, clear and exact-tid
retirement each add one; invalid timer inputs, async OR, pure queries and proven
empty take/claim paths add none. This introduces cross-signum blocking between
normal producers/consumers/clear/claim/retirement. A paused holder can delay all
of them. Callers holding a HAL timer transition gate acquire custody after
that gate; custody never acquires a timer lock. Origin release precedes backend,
graph and wake callbacks. There is no application callback, I/O, guest wait,
allocator/free or table traversal inside production custody. First use allocates
one process-local backing before lock acquisition; no per-event heap owner is
created. A dequeue copies/resets one inline origin and uses the existing
whole-word strong CAS. With normal removals/clear excluded, at most 63 newly
set bits can interfere with a nonempty take; mutex acquisition/fairness has no
proven bound. Clear resets 64 origins. These are work descriptions, not new
contract budgets: `structural_budgets=[]` remains unchanged.

The normal backing uses the same neutral `ForkResetBacking` authority as HVF's
waiter registry. Fork preparation allocates clean replacements before bundle
locks. Parent and failure unlock then dispose the unused allocation; child
Drop publishes its preallocated backing and abandons the copied held guard
and queue without unlocking, destroying or byte-resetting mutex state. Only
the backing changes; the authoritative pending atomic stays at the same
address. Published backings are retained until process exit, one additional
old backing per child transition, preserving every borrowed reference and any
copied waiter queue. Ordinary concurrent clear never replaces backing;
already-held reset borrows its guard. The VM-free child-branch test is not a
platform fork proof. Active carrier launch re-execs and HVPatch guest fork is
in-process; this does not claim an active inherited-lock production defect.
The existing real contended HVF fork artifact test, independent review, full
CI, signed guest delivery and the unchanged <=2x p50/20-sample runtime gate
remain required integration follow-ons.
