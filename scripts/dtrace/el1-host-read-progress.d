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

carrick*:::hvpatch-el1-host-read-retention
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|pid=%d|ipa=0x%x|retention=%d\n", pid, arg0, arg1);
    @retention[arg1] = count();
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
}
