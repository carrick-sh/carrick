/*
 * tier-d-v8-memory.d — attribute V8's Tier-D virtual-memory failure without
 * tracing the emitted guest instruction stream.
 *
 * Provider ABI qualified from Carrick's generated USDT declarations:
 * syscall-entry(u64 nr, char *name, u64 *args) exposes a host pointer to six
 * contiguous u64 Linux arguments; syscall-return(u64 nr, char *name,
 * i64 retval, i32 errno) exposes the Linux-shaped result. Canonical AArch64
 * numbers here are munmap=215, mmap=222, mprotect=226, madvise=233.
 *
 * The clauses arm Carrick's syscall USDT pair, so every guest syscall crosses
 * a fasttrap site even though only four memory calls are printed. This is an
 * attribution run and its elapsed time is never performance evidence. The
 * capture follows all fork descendants and is bounded at 30 seconds. A
 * zero-firing capture is an explicit error.
 *
 * Usage:
 *   carrick trace --script scripts/dtrace/tier-d-v8-memory.d \
 *     --trace-out /tmp/tier-d-v8-memory.out -- run ...
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    printf("TIERDV8MEM1|event=begin|target=%d|time=%Y\n", $target,
        walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
    (arg0 == 215 || arg0 == 222 || arg0 == 226 || arg0 == 233)/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    events++;
    printf("TIERDV8MEM1|event=entry|pid=%d|nr=%d|name=%s|a0=%#x|a1=%#x|a2=%#x|a3=%#x|a4=%#x|a5=%#x\n",
        pid, arg0, copyinstr(arg1),
        this->sa[0], this->sa[1], this->sa[2],
        this->sa[3], this->sa[4], this->sa[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
    (arg0 == 215 || arg0 == 222 || arg0 == 226 || arg0 == 233)/
{
    events++;
    printf("TIERDV8MEM1|event=return|pid=%d|nr=%d|name=%s|ret=%d|errno=%d\n",
        pid, arg0, copyinstr(arg1), (int64_t)arg2, (int)arg3);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 30 && events == 0/
{
    printf("TIERDV8MEM1|event=error|reason=zero-firing-syscall-probes|seconds=%d\n",
        seconds);
    exit(2);
}

tick-1s
/seconds >= 30 && events != 0/
{
    printf("TIERDV8MEM1|event=bound|seconds=%d|events=%d\n", seconds,
        events);
    exit(0);
}

dtrace:::END
{
    printf("TIERDV8MEM1|event=end|events=%d|time=%Y\n", events,
        walltimestamp);
}
