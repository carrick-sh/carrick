#pragma D option quiet

/*
 * WHY DID A SYSCALL EXIT LOSE ITS MAILBOX CONTINUATION?
 *
 * (a) Joins stopped-vCPU publication, capture, handoff and reset observations
 *     by mailbox host address, generation and request sequence. A missing
 *     zone capture emits its host stack. Payload contains no guest bytes.
 * (b) Source ABI: syscall-mailbox-lifecycle(phase,address,generation,sequence,
 *     state), phases 1 validated request, 2 capture, 3 take/reset, 4 import,
 *     5 normal return, 6 register resume, 7 clock restart/reset, 8 rebind.
 *     States are MailboxState wire values. Request publication is observed
 *     after the acquire/validation at host dispatch, not at the guest store.
 *     el1-zone-capture-missing(pc,pstate) marks a required absent continuation.
 *     Live-qualified 2026-10-04 on signed el1_host_copyout, SHA-256
 *     e3e0e765ec326a518f1729a29fe015c9798d949e876e9b0b9d4b21111cad08f5:
 *     781/698/3946 lifecycle events joined generation/sequence. Full tracing
 *     perturbed the fixture into an earlier race-copyout EFAULT. Failure-only
 *     tracing caught an EL0 PC with resume_owner_zone -> service_outcome ->
 *     owner_memory_park -> zone_ctx_from_state: a second owner wait after
 *     the guest-zone loader had dropped the still-pending syscall mailbox.
 * (c) One event per observed lifecycle step; only the failure takes a stack.
 *     This changes timing; it proves ordering, never uninstrumented success.
 *     Thirty-second bound; no observed lifecycle/failure events fails closed.
 *
 * carrick trace -s scripts/dtrace/el1-syscall-mailbox-lifecycle.d -- run ...
 * For the distinct embed topology, attach during a pre-carrier diagnostic
 * hold: dtrace -C -Z -p <test-pid> -s <this file>. No hold or syscall observer
 * belongs in the uninstrumented signed acceptance fixture.
 * Use -DMAILBOX_FAILURE_ONLY with dtrace -C to enable only the rare failure
 * probe if full lifecycle tracing changes the symptom. A zero-event run
 * provides no evidence that the missing capture is absent.
 */

dtrace:::BEGIN { events = 0; failures = 0; }

#ifndef MAILBOX_FAILURE_ONLY
carrick*:::syscall-mailbox-lifecycle
/pid == $target || progenyof($target)/
{
    events++;
    printf("MAILBOX1|ns=%d|pid=%d|tid=%d|phase=%d|address=0x%x|generation=%d|sequence=%d|state=%d\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4);
}
#endif

carrick*:::el1-zone-capture-missing
/pid == $target || progenyof($target)/
{
    failures++;
    printf("MAILBOX1|ns=%d|pid=%d|tid=%d|MISSING|pc=0x%x|pstate=0x%x\n",
        timestamp, pid, tid, arg0, arg1);
    ustack(24);
}

tick-1s { seconds++; }
tick-1s /seconds >= 30/ { exit(events == 0 && failures == 0 ? 1 : 0); }

END
{
    printf("MAILBOX1|events=%d|failures=%d\n", events, failures);
}
