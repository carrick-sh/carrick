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
 * (c) Perturbation: one event per transfer step while traced. Counts and
 *     provenance only; do not infer timing from this script.
 *
 * Attach to a signed carrick-embed test while its startup hold is active:
 * sudo dtrace -Z -p <test-pid> -s scripts/dtrace/el1-host-read-progress.d
 */

carrick*:::hvpatch-el1-host-read-progress
/pid == $target || progenyof($target)/
{
    printf("EL1HOSTREAD1|pid=%d|tid=%d|va=0x%x|len=%d|offset=%d|class=%d|detail=%d\n",
        pid, tid, arg0, arg1, arg2, arg3, arg4);
    @classes[arg3, arg4] = count();
}

proc:::exit
/pid == $target/
{
    exit(0);
}

END
{
    printa("EL1HOSTREAD1|class=%d|detail=%d|count=%@d\n", @classes);
}
