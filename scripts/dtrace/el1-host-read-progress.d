#pragma D option quiet

/*
 * WHY DID AN ADMITTED OWNER READ STOP BEFORE THE GUEST SYSCALL?
 *
 * (a) Measures every bounded EL1-owned host read's progress class, requested
 *     guest VA/length and completed prefix. It does not expose guest bytes.
 * (b) Provider ABI: hvpatch-el1-host-read-progress(address, length, offset,
 *     class, detail), where class 0 complete, 1 advanced, 2 physical wait, 3 owner
 *     wait, 4 supply, 5 retired, 6 refused, 7 omitted suspension, 8 service
 *     failure. Detail is PortalWaitCause for class 3 (1 editor, 2
 *     reservations, 3 pending edit, 4 gate, 5 metadata, 6 reservation pool),
 *     Linux errno for class 6, zero otherwise. Qualify on the exact signed
 *     artifact before citing a run. Live-qualified on the signed
 *     guest_smoke-504ebb617cfe4759 artifact, 2026-10-04: one Gate wait,
 *     31 Reservations waits, all at offset zero, and one EFAULT refusal.
 *     hvpatch-el1-host-read-retention(ipa, reason) names physical retention
 *     refusal: 1 no indexed stage-2 record, 3 record missing, 4 unmapped,
 *     5 retiring. Live-qualified on the signed 2026-10-04 guest_smoke
 *     artifact: all 31 first-load Reservations waits followed reason 1.
 *     Source audit then found live boot structural records in the carrier's
 *     record-ID authority, absent from the old carrier-MM-only IPA index.
 *     The exact PortalWaitCause was Reservations, but no real reservation
 *     was held: this missing lookup could never wake itself.
 *     hvpatch-el1-host-write-prepare(va, len, phase, detail) observes the
 *     pre-consume host-copyout permit: phase 0 begin (detail requested bound),
 *     1 supply (1 grant, 2 COW, 3 metadata), 2 supply result (1 settled,
 *     0 declined, 2 service error), 3 prepared, 4 owner wait (detail is
 *     PortalWaitCause), 5 physical wait, 6 fault (1 bounds, 2 host map,
 *     3 retired, 4 unsupported, 5 metadata allocation, 6 other), 7 limit.
 *     Live-qualified on signed el1_host_copyout-873518cad531afb9,
 *     n1f-copyout-attach2-20261004: the original in-memory file read asked
 *     PREPARE for 20603 bytes at 0x6000004064 and got phase 7 before any
 *     copyout grant. The portal permit bound is 4096 bytes; this is the
 *     oversized caller request, not a host read failure or source EOF.
 *     syscall::recvfrom entry/return is live-listed on this Mac with entry
 *     arg0=int host fd, arg2=size_t capacity, arg3=int flags; return arg0
 *     and arg1 are int result words. This arm reports host socket progress
 *     alongside the owner prepare sequence for forwarded recvfrom.
 *     hvpatch-el1-owner-grant-supply(va,len,phase,detail) distinguishes
 *     missing transport (1), invalid ASID (2), missing foreign binding (3),
 *     overlapping retained alias (4, detail=count), publication entry (5),
 *     host deferred-return reconciliation (6, detail=number acknowledged),
 *     and exact grant result (7, detail=1 settled, 0 declined). On an
 *     overlap, phase 8 reports each alias VA/size/physical owner generation;
 *     phase 9 reports its IPA/physical size/scope (1 exact MM root, 2
 *     container root, 3 global). These diagnostics identify the retained
 *     row; they do not authorize its retirement.
 *     Phase 10 reports the fault page with live residency length and physical
 *     owner generation (both zero if lookup misses) when an alias overlaps.
 *     Phase 11 reports the residency semantic base, expected IPA for the
 *     requested page, and its physical base.
 *     Mapping-leaf probes sample the fault page, its neighbour, and the
 *     page 16 KiB above it to distinguish prepared stock from physical
 *     alias coverage without a descriptor.
 *     Live-qualified on signed el1_host_copyout-873518cad531afb9,
 *     n1g-ipa-attach-20261004: recvfrom page 0x6000008000 still had a
 *     prepared leaf for IPA 0x9b40104000 and live residency generation 8
 *     with that same expected IPA. The later grant was caused by the portal
 *     passing byte address 0x6000008005 to an aligned-page commit, which
 *     refused BadAddress in the VM-free reproduction. This traced artifact
 *     predates the aligned-page fix; its copyout failure is not a post-fix
 *     verdict.
 *     Live-qualified on signed el1_host_copyout-873518cad531afb9,
 *     n1f-grantrefusal-trace-20261004: the recvfrom destination
 *     0x6000008005 requested a 32 KiB grant rooted at 0x6000004000;
 *     phase 4 reported one overlapping alias after the prior read and pread
 *     mappings had been unmapped. The refusal preceded host recvfrom.
 *     hvpatch-el1-fault-root-mapping(far,start,end,source_handle,source_offset)
 *     observes the admitted root at final fault delivery only. A zero range
 *     means no root mapping; a zero source handle means no retained file
 *     source. It does not authorize a grant or replace EL1's own decision.
 *     hvpatch-el1-file-fault-handoff(far,mailbox_state,route) distinguishes
 *     a missing owner selection (0) from selected (1), resolved (2), refused
 *     (3) and BUS (4). State is the ABI mailbox AtomicU32 at the host exit.
 *     Live-qualified on signed guest_smoke-504ebb617cfe4759, 2026-10-04:
 *     hello's later execute fault at 0x6000042d20 retained source handle 4
 *     in the root and selected a file fault with mailbox state 2 (requested),
 *     then returned route 3 (refused) in state 3 (host working). Earlier
 *     executable pages took the same route and resolved (route 2). This
 *     excludes missing source and missing owner selection for that page.
 *     Engine subroutes: 5 preparation declined, 6 submitted, 7 descriptor
 *     receipt refused, 8 selection withdrawn without receipt, 9 source EOF,
 *     10 descriptor receipt applied. Route 7's detail is the stable
 *     DescriptorRefusal wire code; other engine subroutes use detail zero.
 *     Live-qualified on signed guest_smoke-504ebb617cfe4759,
 *     n1f-refusal-trace-20261004: route 7 carries detail 17
 *     (JournalCapacity) on 0x6000042000 after 64 prior one-page file grants
 *     in the same 2 MiB residency-index window. The owner source remains
 *     live; the index's 64-slot collision bound rejects the 65th page.
 *     Companion fault, frame-grant, mapping-leaf, syscall-service and mmap
 *     lowering probes use their carrick-observability signatures. The
 *     mapping-leaf phases are 0 prepare, 1 submit, 3 applied, 4 settled,
 *     5 before unmap, 6 after unmap. These were qualified on the same
 *     signed guest_smoke and el1_host_copyout executables, 2026-10-04.
 * (c) Perturbation: one event per transfer/fault/syscall step and a user
 *     stack on each owner wait while traced. Counts and provenance only;
 *     do not infer timing from this script. Sort ns across CPU buffers.
 *
 * Attach to a signed carrick-embed test while its startup hold is active:
 * sudo dtrace -Z -p <test-pid> -s scripts/dtrace/el1-host-read-progress.d
 */

carrick*:::hvpatch-el1-host-read-progress
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|pid=%d|tid=%d|va=0x%x|len=%d|offset=%d|class=%d|detail=%d\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4);
    @classes[arg3, arg4] = count();
    if (arg3 == 3) {
        ustack(16);
    }
}

carrick*:::hvpatch-el1-host-write-prepare
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|copyout-prepare|pid=%d|va=0x%x|len=%d|phase=%d|detail=%d\n",
        timestamp, pid, arg0, arg1, arg2, arg3);
    @copyout[arg2, arg3] = count();
}

carrick*:::hvpatch-el1-owner-grant-supply
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|grant-supply|va=0x%x|len=%d|phase=%d|detail=%d\n",
        timestamp, arg0, arg1, arg2, arg3);
    @grant_supply[arg2, arg3] = count();
}

syscall::recvfrom:entry
/pid == $target || progenyof($target)/
{
    self->recv_capacity = arg2;
    printf("EL1HOSTREAD1|ns=%d|host-recv-entry|pid=%d|fd=%d|capacity=%d|flags=%d\n",
        timestamp, pid, arg0, arg2, arg3);
}

syscall::recvfrom:return
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|host-recv-return|pid=%d|capacity=%d|r0=%d|r1=%d\n",
        timestamp, pid, self->recv_capacity, arg0, arg1);
    self->recv_capacity = 0;
}

carrick*:::hvpatch-el1-host-read-retention
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|pid=%d|ipa=0x%x|retention=%d\n", pid, arg0, arg1);
    @retention[arg1] = count();
}

carrick*:::hvpatch-el1-fault-root-mapping
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|fault-root|far=0x%x|start=0x%x|end=0x%x|handle=%d|offset=%d\n",
        arg0, arg1, arg2, arg3, arg4);
}

carrick*:::hvpatch-el1-file-fault-handoff
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|file-handoff|far=0x%x|mailbox-state=%d|route=%d\n",
        arg0, arg1, arg2);
}

carrick*:::hvpatch-guest-fault
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|guest-fault|esr=0x%x|elr=0x%x|far=0x%x|guest-pid=%d|guest-tid=%d\n",
        timestamp, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::hvpatch-first-touch-refused
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|first-touch-refused|page=0x%x|access=%d|site=%d|error=%s\n",
        arg0, arg1, arg2, copyinstr(arg3));
}

carrick*:::hvpatch-first-touch-deliver
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|first-touch-deliver|far=0x%x|reason=%d|guest-tid=%d\n",
        arg0, arg1, arg2);
}

carrick*:::hvpatch-el1-frame-grant-plan
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|frame-grant|far=0x%x|base=0x%x|len=%d|perms=%d|gen=%d\n",
        timestamp, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::el1-mapping-leaf
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|mapping-leaf|phase=%d|mm=%d|va=0x%x|span=%d|leaf=0x%x\n",
        timestamp, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::guest-internal-write-fault
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|write-fault|va=0x%x|len=%d|phase=%d|error=%s\n",
        arg0, arg1, arg2, copyinstr(arg3));
}

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|syscall-begin|guest-pid=%d|guest-tid=%d|nr=%d\n",
        timestamp, arg0, arg1, arg3);
}

carrick*:::hvpatch-syscall-args
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|syscall-args|nr=%d|a0=0x%x|a1=0x%x|a2=0x%x|a3=0x%x\n",
        timestamp, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::mmap-lowering-verdict
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|mmap-lowering|va=0x%x|len=%d|offset=%d|outcome=%d\n",
        timestamp, arg0, arg1, arg2, arg3);
}

carrick*:::mmap-lowering-error
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|ns=%d|mmap-lowering-error|va=0x%x|len=%d|offset=%d|error=%s\n",
        timestamp, arg0, arg1, arg2, copyinstr(arg3));
}

carrick*:::hvpatch-fault-terminal
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|fault-terminal|far=0x%x|signal=%d|si-code=%d|guest-tid=%d\n",
        arg0, arg1, arg2, arg3);
}

proc:::exit
/pid == $target/
{
    exit(0);
}

END
{
    printa("EL1HOSTREAD1|class=%d|detail=%d|count=%@d\n", @classes);
    printa("EL1HOSTREAD1|retention=%d|count=%@d\n", @retention);
    printa("EL1HOSTREAD1|copyout-phase=%d|detail=%d|count=%@d\n", @copyout);
    printa("EL1HOSTREAD1|grant-supply-phase=%d|detail=%d|count=%@d\n", @grant_supply);
}
