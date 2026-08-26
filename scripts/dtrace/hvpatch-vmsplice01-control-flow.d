/*
 * Locate the blocked edge in LTP vmsplice01's
 * poll(POLLOUT) -> vmsplice(user, pipe) -> splice(pipe, file) loop.
 *
 * Provider ABI qualified on Darwin/arm64 2026-08-26:
 * - carrick*:::syscall-entry arg0 is the canonical AArch64 syscall number,
 *   arg1 is the name, and arg2 points to the host-side six-u64 arg array.
 * - carrick*:::syscall-return args 0..3 are nr/name/signed retval/Linux errno.
 * - carrick*:::io-wait-begin args 0..2 are guest tid/fd count/timeout ms.
 * - carrick*:::host-pipe-io args 1..3 are host fd/direction/byte count.
 *
 * AArch64 numbers selected here are ppoll=73, vmsplice=75, splice=76. The
 * script prints only those syscall boundaries and wait edges, so it perturbs
 * the failing loop but is not performance evidence. It fails visibly when no
 * selected syscall fires and self-terminates after 35 seconds.
 */

#pragma D option quiet
#pragma D option destructive
#pragma D option strsize=128

dtrace:::BEGIN
{
    printf("VMS1|begin|time=%Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg0 == 73 || (uint64_t)arg0 == 75 || (uint64_t)arg0 == 76)/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    selected++;
    printf("VMS1|entry|pid=%d|htid=%d|nr=%d|name=%s|a0=%#x|a1=%#x|a2=%#x|a3=%#x|a4=%#x|a5=%#x\n",
        pid, tid, (uint64_t)arg0, copyinstr(arg1),
        this->a[0], this->a[1], this->a[2], this->a[3], this->a[4], this->a[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg0 == 73 || (uint64_t)arg0 == 75 || (uint64_t)arg0 == 76)/
{
    returns++;
    printf("VMS1|return|pid=%d|htid=%d|nr=%d|name=%s|ret=%d|errno=%d\n",
        pid, tid, (uint64_t)arg0, copyinstr(arg1), (int64_t)arg2, (int)arg3);
}

carrick*:::io-wait-begin
/pid == $target || progenyof($target)/
{
    waits++;
    printf("VMS1|wait|pid=%d|htid=%d|guest-tid=%d|fds=%d|timeout-ms=%d\n",
        pid, tid, (int)arg0, (int)arg1, (int)arg2);
}

carrick*:::host-pipe-io
/pid == $target || progenyof($target)/
{
    pipeio++;
    printf("VMS1|pipeio|pid=%d|htid=%d|host-fd=%d|dir=%d|bytes=%d\n",
        pid, tid, (int)arg1, (int)arg2, (int)arg3);
}

tick-35s
{
    printf("VMS1|timeout|selected=%d|returns=%d|waits=%d|pipeio=%d\n",
        selected, returns, waits, pipeio);
    exit(0);
}

dtrace:::END
{
    printf("VMS1|end|selected=%d|returns=%d|waits=%d|pipeio=%d\n",
        selected, returns, waits, pipeio);
}

dtrace:::END
/selected == 0/
{
    printf("VMS1|error=no-selected-syscall-entry\n");
}
