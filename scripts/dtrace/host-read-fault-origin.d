#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option ustackframes=40

/*
 * WHY DID A HOST READ OF GUEST MEMORY REFUSE?
 *
 * (a) What it measures: every `guest-internal-read-fault` (a host read of
 *     guest memory the engine refused) with the refused page, the read's
 *     length, the phase and that page's live terminal descriptor, plus the
 *     carrier stack naming the reader; and every guest syscall returning
 *     -EFAULT. Written for the 2026-10-01 delegated-MM finding: with
 *     reservation roots admitted, cpython's fork(2) returned EFAULT (its
 *     child_tid read) and node's harness saw EFAULT reading a path.
 *
 * (b) Provider ABI: `guest-internal-read-fault(u64 page, u64 length,
 *     u32 phase, u64 live_descriptor)`; phase 0 = an EL1-private leaf
 *     denies the read, 1 = no host translation and not fresh zero, 2 = the
 *     backend read failed. Descriptor bits: 0 valid, 55 SW_RETIRED,
 *     56 SW_EL1_PRIVATE, output address [47:12]. `syscall-return` arg0 =
 *     Linux nr, arg2 = retval. Not yet live-qualified (added 2026-10-01).
 *
 * (c) Perturbation: low; only refused reads and EFAULT returns fire, one
 *     ustack() each.
 *
 * Usage: target/release/carrick trace --script scripts/dtrace/host-read-fault-origin.d \
 *   -- run ... /bin/sh -c '<workload>; sleep 3'
 */

proc:::exit
/pid == $target/
{
    exit(0);
}

carrick*:::guest-internal-read-fault
/pid == $target || progenyof($target)/
{
    printf("READFAULT pid=%d tid=%d page=0x%x len=%d phase=%d live=0x%x valid=%d private=%d retired=%d\n",
        pid, tid, arg0, arg1, arg2, arg3, arg3 & 1, (arg3 >> 56) & 1, (arg3 >> 55) & 1);
    ustack();
    @phase[arg2] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (int64_t)arg2 == -14/
{
    printf("EFAULT pid=%d tid=%d nr=%d\n", pid, tid, arg0);
    @efault[arg0] = count();
}

END
{
    printa("read faults phase=%d: %@d\n", @phase);
    printa("EFAULT nr=%d: %@d\n", @efault);
}

/*
 * A host-venue step a delegated MM's reservation root refused (the error
 * fails its syscall): `hvpatch-el1-root-host-refusal(u32 refusal)`, the
 * `Refusal` ordinal (0 Busy, 1 Stale, 2 Invalid, ...). The stack names the
 * refusing step.
 */
carrick*:::hvpatch-el1-root-host-refusal
/pid == $target || progenyof($target)/
{
    printf("ROOTREFUSAL pid=%d tid=%d refusal=%d\n", pid, tid, arg0);
    ustack();
}
