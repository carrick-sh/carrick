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
 * (c) Perturbation: low; only failing copyouts take a probe body, and each
 *     takes one ustack().
 *
 * Usage (keep the carrier alive briefly after the failure, or the stacks
 * cannot be symbolized once the process is gone):
 *   target/release/carrick trace --script scripts/dtrace/host-copyout-efault-origin.d \
 *     -- run ... /bin/sh -c '<workload>; sleep 3'
 */

proc:::exit
/pid == $target/
{
    exit(0);
}

carrick*:::guest-internal-write-fault
/pid == $target || progenyof($target)/
{
    printf("WRITE-FAULT pid=%d tid=%d va=0x%x len=%d phase=%d reason=%s\n",
        pid, tid, arg0, arg1, arg2, copyinstr(arg3));
    ustack();
    @refused[arg2, copyinstr(arg3)] = count();
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
    printa("refused phase=%d %s: %@d\n", @refused);
    printa("EFAULT %s: %@d\n", @efault);
}
