/*
 * Distinguish LTP tee01's pipe construction and splice/tee control flow from
 * a launch failure or a silent/non-firing probe. This answers whether tee(2)
 * reaches Carrick, which Linux errno it returns, and whether the operation is
 * routed through a host-backed pipe.
 *
 * Provider ABI qualified on Darwin/arm64 2026-08-26:
 * - carrick*:::syscall-entry arg0 is the canonical AArch64 syscall number,
 *   arg1 is the name, and arg2 points to the host-side six-u64 arg array.
 * - carrick*:::syscall-return args 0..3 are nr/name/signed retval/Linux errno.
 * - carrick*:::host-pipe-io args 1..3 are host fd/direction/byte count.
 *
 * AArch64 numbers selected here are pipe2=59, splice=76, and tee=77. Printing
 * every selected boundary perturbs the fixture, so this is not performance
 * evidence. The script fails visibly when no selected syscall fires and is
 * bounded at 12 seconds in case the fixture wedges.
 */

#pragma D option quiet
#pragma D option destructive
#pragma D option strsize=128

dtrace:::BEGIN
{
    printf("TEE1|begin|time=%Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg0 == 59 || (uint64_t)arg0 == 76 || (uint64_t)arg0 == 77)/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    selected++;
    printf("TEE1|entry|pid=%d|htid=%d|nr=%d|name=%s|a0=%#x|a1=%#x|a2=%#x|a3=%#x|a4=%#x|a5=%#x\n",
        pid, tid, (uint64_t)arg0, copyinstr(arg1),
        this->a[0], this->a[1], this->a[2], this->a[3], this->a[4], this->a[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg0 == 59 || (uint64_t)arg0 == 76 || (uint64_t)arg0 == 77)/
{
    returns++;
    printf("TEE1|return|pid=%d|htid=%d|nr=%d|name=%s|ret=%d|errno=%d\n",
        pid, tid, (uint64_t)arg0, copyinstr(arg1), (int64_t)arg2, (int)arg3);
}

carrick*:::host-pipe-io
/pid == $target || progenyof($target)/
{
    pipeio++;
    printf("TEE1|pipeio|pid=%d|htid=%d|host-fd=%d|dir=%d|bytes=%d\n",
        pid, tid, (int)arg1, (int)arg2, (int)arg3);
}

tick-12s
{
    printf("TEE1|timeout|selected=%d|returns=%d|pipeio=%d\n",
        selected, returns, pipeio);
    exit(0);
}

dtrace:::END
{
    printf("TEE1|end|selected=%d|returns=%d|pipeio=%d\n",
        selected, returns, pipeio);
}

dtrace:::END
/selected == 0/
{
    printf("TEE1|error=no-selected-syscall-entry\n");
}
