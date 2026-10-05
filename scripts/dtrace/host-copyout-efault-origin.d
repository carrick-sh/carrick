#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option ustackframes=40

/*
 * WHERE DOES A HOST COPYOUT INTO GUEST MEMORY TURN INTO EFAULT?
 *
 * (a) What it measures: every guest syscall that returns -EFAULT (-14),
 *     with the carrier's user stack at the return, and every
 *     `guest-internal-write-fault` USDT (the host-side write admission
 *     refusing a range: address, length, phase, reason). Written for the
 *     2026-10-01 EL1-reservation copyout gap: `read`/`pread64`/`recvfrom`
 *     into a fresh anonymous mapping, and `write` out of one, returned EFAULT
 *     once the reservation root owned the mapping. The stack names the
 *     accessor (zero-copy host pointer, write-range admission, byte copy)
 *     that refused.
 *
 * (b) Provider ABI facts: `carrick*:::syscall-return` arg0 = canonical
 *     Linux nr, arg1 = host pointer to the name string, arg2 = retval
 *     (negative Linux errno); `carrick*:::guest-internal-write-fault`
 *     arg0 = guest VA, arg1 = length, arg2 = phase, arg3 = reason string.
 *     USDT probes follow forked children under the progeny predicate.
 *
 *     Live-qualified on 2026-10-02: phases 9 (copyout commit failure),
 *     15 (post-grant leaf permission), 18 (backing preparation declined)
 *     and 21 (backend refusal reason) fired on the admitted cross-process
 *     reader reduction. All 6,717 phase-18 declines matched phase-21
 *     invalid backing requests: host copyout had no mailbox generation.
 *     Phase 22 was also live-qualified: remaining predecessor refusals
 *     named no registered MM aliases and only local rows whose physical
 *     owners remained alive. Local rows did not authenticate MM ownership.
 *     Phases 8, 10-12, 16, 19 and 20 name other source-defined refusal
 *     branches; this qualification does not claim they fired.
 *     Phase 23 names the guest-owned frame-grant descriptor transaction's
 *     preparation refusal, before any EL1 store. Its VA/length cover the
 *     full proposed publication and its reason names DescriptorRefusal.
 *     This phase is not yet live-qualified.
 *     Phase 24 names a refused or rolled-back EL1 frame-grant receipt at
 *     host settlement, before its backing is rolled back. This phase is
 *     not yet live-qualified either.
 *     Phases 25/26 identify owner SELECT/PREPARE refusals, including exact
 *     errno and transport receipt. Phase 27 preserves the owner preparation
 *     fault at dispatch lowering and the committed byte count (VA/length
 *     are zero when that error carries no range). These phases are not yet
 *     live-qualified; owner waits/supply do not emit them. They are needed
 *     for embed callers whose optional syscall-return observer is disabled.
 *     el1-mapping-leaf(phase, MM key, VA, span length, live descriptor)
 *     samples a focus page and its neighbour: phases 0 preparation,
 *     1 submitted, 2 host publication, 3 applied receipt before backend
 *     settlement, 4 after settlement, 5 before unmap, 6 after unmap.
 *     These descriptor walks execute only with this probe enabled.
 *     guest-internal-read-fault(page, length, phase, live descriptor)
 *     reports host-read refusal: phases 0 permission, 1 translation,
 *     2 backing. The combined capture binds refusal to publication and
 *     retirement in the same exact MM. New phases remain unqualified.
 *
 * (c) Perturbation: failure-only, with one ustack() per event. Thousands
 *     of repeated refusals can materially perturb a run; this profile
 *     diagnoses origin and provides no uninstrumented timing evidence.
 *     Mapping lifecycle sampling adds two live walks per publication or
 *     retirement while enabled; this is ordering evidence, not timing.
 *
 * Usage (keep the carrier alive briefly after the failure, or the stacks
 * cannot be symbolized once the process is gone):
 *   target/release/carrick trace --script scripts/dtrace/host-copyout-efault-origin.d \
 *     -- run ... /bin/sh -c '<workload>; sleep 3'
 */

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(0);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 60 && !target_exited/
{
    printf("COPYORIGIN TRUNCATED seconds=%d\n", seconds);
    exit(4);
}

dtrace:::ERROR
{
    errors++;
}

dtrace:::DROP
{
    drops++;
}

carrick*:::guest-internal-write-fault
/pid == $target || progenyof($target)/
{
    printf("WRITE-FAULT pid=%d tid=%d va=0x%x len=%d phase=%d reason=%s\n",
        pid, tid, arg0, arg1, arg2, copyinstr(arg3));
    ustack();
    @refused[arg2, copyinstr(arg3)] = count();
}

carrick*:::el1-mapping-leaf
/pid == $target || progenyof($target)/
{
    mapping_events++;
    printf("MAPLEAF ns=%d pid=%d tid=%d phase=%d mm=%d va=0x%x span=0x%x live=0x%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4);
    @mapping_phase[arg0] = count();
}

carrick*:::guest-internal-read-fault
/pid == $target || progenyof($target)/
{
    printf("READFAULT ns=%d pid=%d tid=%d page=0x%x len=%d phase=%d live=0x%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3);
    ustack();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (int64_t)arg2 == -14/
{
    printf("EFAULT pid=%d tid=%d nr=%d %s\n", pid, tid, arg0, copyinstr(arg1));
    ustack();
    @efault[copyinstr(arg1)] = count();
}

END
{
    printf("COPYORIGIN summary mapping_events=%d target_exited=%d errors=%d drops=%d\n",
        mapping_events, target_exited, errors, drops);
    printa("mapping phase=%d: %@d\n", @mapping_phase);
    printa("refused phase=%d %s: %@d\n", @refused);
    printa("EFAULT %s: %@d\n", @efault);
}
