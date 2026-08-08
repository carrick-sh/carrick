/*
 * tier-d-exec-mprotect.d — identify the mapping that a Tier-D guest promotes
 * to executable with mprotect(2).
 *
 * Provider ABI qualified on this host/build from carrick's generated USDT
 * declaration (`syscall-entry(u64 nr, char *name, u64 *args)`): arg2 points
 * at six contiguous u64 syscall arguments. The predicate follows the tracer's
 * owned child and all fork descendants, so an exec child cannot disappear.
 *
 * This records only guest mmap/mprotect/munmap calls. It is diagnostic and
 * low-rate for the Node startup reducer, but it still arms a USDT probe on
 * every guest syscall; elapsed time from an instrumented run is not a
 * performance result.
 *
 * Use:
 *   carrick trace --script scripts/dtrace/tier-d-exec-mprotect.d \
 *     --trace-out /tmp/tier-d-exec-mprotect.out -- run ...
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    active = 1;
    printf("TIERDMAP1|event=begin|time=%Y\n", walltimestamp);
}

/* The direct identity-memory service emits the shared syscall probe pair.
 * The lifecycle clauses still bound a zero-event capture, so an absent firing
 * probe becomes an explicit empty artifact rather than a hanging session. */
proc:::create
/(pid == $target || progenyof($target))/
{
    tracked[args[0]->pr_pid] = 1;
    active++;
}

proc:::exit
/(pid == $target || progenyof($target)) && active == 1/
{
    active = 0;
    exit(0);
}

proc:::exit
/(pid == $target || progenyof($target)) && active > 1/
{
    active--;
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 30/
{
    exit(0);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 215 || arg0 == 222 || arg0 == 226)/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    printf("TIERDMAP1|event=entry|pid=%d|nr=%d|name=%s|a0=%#x|a1=%#x|a2=%#x|a3=%#x|a4=%#x|a5=%#x\n",
        pid, arg0, copyinstr(arg1),
        this->sa[0], this->sa[1], this->sa[2],
        this->sa[3], this->sa[4], this->sa[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 215 || arg0 == 222 || arg0 == 226)/
{
    printf("TIERDMAP1|event=return|pid=%d|nr=%d|name=%s|ret=%d|errno=%d\n",
        pid, arg0, copyinstr(arg1), (int64_t)arg2, (int)arg3);
}

dtrace:::END
{
    printf("TIERDMAP1|event=end|time=%Y\n", walltimestamp);
}
