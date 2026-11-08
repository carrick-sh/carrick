# IPC lock release protocol (#1845, protocol layer)

The `kernel.el1.ipc-two-process` contract owns this protocol change. Linux
pipe/eventfd operations must retain their endpoint and byte cursor while they
wait. Internal lock contention cannot become errno, fatal completion, or a
worker retained until another guest task runs. Constructors must also retain
unpublished objects and cannot return EINTR for ordinary signals or group stop.

This layer repairs the scheduler queue protocol required before operation
continuations can replace `HostLockWait`. It does **not** remove that spin yet.
The data-object guard publisher, its disjoint source domain, typed refusal and
retained create/I/O/metadata continuation remain the next layer of #1845.

Every queue guard now requires a completion delivery callback. Legacy readiness
queues use the same owned bit and unlock/drain transaction as notification
queues. Timer expiration and cancellation/cleanup carry that capability too;
a short spin policy cannot manufacture a venue. Guest callbacks defer exact
host claims to the existing completion chain and mark the mapped guest task's
host-work doorbell. ARM uses its mapped task array, CPL0 its executing task
binding; host-test callbacks mark the host aperture's task doorbells.

A lock-release admission is distinct from a source notification admission.
It retains the same intrusive record and POSTED/RELEASED handshake, but it
neither pins the holder's readiness generation nor decrements its publisher
count. The two completion chains initialize before custody transfers, even
before the first binding. A pending-drain owner reads the current generation
under exclusion, so a future binding does not impersonate the older holder.
No parallel callback table, host readiness pipe, timer poll or retry loop is
introduced for lock release.

The red-first witness `legacy_object_holder_excludes_completion_admission`
uses the real readiness acquisition and completion acquisition on one queue.
On main it grants overlapping exclusive ownership; the unified protocol
refuses the second acquisition. Additional deterministic schedules cover two
retained operations, first binding, older-holder/newer-binding generations,
release before enrollment, release after transfer, release between intrusive
link and pending post followed by rebinding, and terminal cancellation with
the exact endpoint operation returned once to its adapter. These are scheduler
protocol witnesses, not executor-pool or guest-instruction acceptance.

The structural bound is inherited from the existing notification protocol:
unlock work is bounded by twice the retained record population plus one sticky
notification transition. No guard, endpoint operation, or publication custody
is discarded when acquisition refuses. Guest memory, ISA execution and default
executor-pool exhaustion still require the following layer's production
witnesses and signed/KVM acceptance; no runtime ratio is claimed here.
