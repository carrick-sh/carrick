#pragma D option quiet
#pragma D option aggsize=64m
#pragma D option dynvarsize=16m
#pragma D option strsize=4k

/*
 * Tier-D Node raw guest openat path census.
 *
 * WHAT IT MEASURES
 * ----------------
 * The raw Linux/AArch64 openat(56) dirfd and pathname presented to Carrick by
 * one launch-owned native-direct process tree. This answers whether the host
 * openat amplification attributed by native-openat-callers.d comes from
 * absolute/AT_FDCWD opens (which cannot inherit a trusted directory anchor)
 * or single-component dirfd-relative walks (which can).
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-08. carrick*:::syscall-entry arg0 is
 * the guest syscall number and arg2 is the address of six contiguous u64
 * SyscallArgs words. Tier D guest pointers are host-process pointers, so the
 * pathname in word 1 is readable with copyinstr in the firing tracee.
 * proc:::create args[0]->pr_pid is the new host child.
 *
 * PERTURBATION
 * ------------
 * MODERATE-HIGH. This enables a USDT fasttrap on every guest syscall entry and
 * copies each open pathname. Counts and path shapes are mechanism evidence;
 * elapsed time and traced-vs-clean ratios are not citable. A valid result ends
 * naturally with nonzero opens, no DTrace errors, and live=0.
 */

dtrace:::BEGIN
{
    started = timestamp;
    seconds = 0;
    live = 1;
    completed = 0;
    timed_out = 0;
    probe_errors = 0;
    tracked[$target] = 1;
}

dtrace:::ERROR
{
    probe_errors++;
    printf("TIERDRAWOPEN1|error|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
}

proc:::create
/tracked[pid] && !tracked[args[0]->pr_pid]/
{
    tracked[args[0]->pr_pid] = 1;
    live++;
}

proc:::exit
/tracked[pid]/
{
    tracked[pid] = 0;
    live--;
}

proc:::exit
/completed == 0 && live == 0/
{
    completed = 1;
    exit(0);
}

carrick*:::syscall-entry
/tracked[pid] && arg0 == 56/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    @open_path[(int)this->args[0], copyinstr(this->args[1])] = count();
    @open_by_dirfd[(int)this->args[0]] = count();
    @open_total = count();
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 20/
{
    timed_out = 1;
    exit(0);
}

dtrace:::END
{
    printa("TIERDRAWOPEN1|total=%@d\n", @open_total);
    printa("TIERDRAWOPEN1|dirfd=%d|count=%@d\n", @open_by_dirfd);
    printa("TIERDRAWOPEN1|dirfd=%d|path=%s|count=%@d\n", @open_path);
    printf("TIERDRAWOPEN1|complete|natural=%d|timed-out=%d|probe-errors=%d|live=%d|elapsed-ns=%d\n",
        completed, timed_out, probe_errors, live, timestamp - started);
}
