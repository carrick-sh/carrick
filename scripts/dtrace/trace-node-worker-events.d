/*
 * Ordered event trace for Node worker_threads stalls. Prints the syscall edge
 * events that can park a worker/main thread and the scheduler calls that Node
 * uses while starting worker isolates.
 */

#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("node-worker events started at %Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 22 || arg0 == 23 || arg0 == 63 || arg0 == 64 || arg0 == 73 ||
  arg0 == 93 || arg0 == 94 || arg0 == 96 || arg0 == 98 || arg0 == 99 ||
  arg0 == 120 || arg0 == 121 || arg0 == 124 || arg0 == 131 ||
  arg0 == 172 || arg0 == 178 || arg0 == 220 || arg0 == 275 || arg0 == 435)/
{
    self->a = (uint64_t *)copyin(arg2, 48);
    printf("[%d/%d entry] nr=%d a0=%#llx a1=%#llx a2=%#llx a3=%#llx a4=%#llx a5=%#llx\n",
        pid, tid, arg0, self->a[0], self->a[1], self->a[2], self->a[3], self->a[4], self->a[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 22 || arg0 == 23 || arg0 == 63 || arg0 == 64 || arg0 == 73 ||
  arg0 == 93 || arg0 == 94 || arg0 == 96 || arg0 == 98 || arg0 == 99 ||
  arg0 == 120 || arg0 == 121 || arg0 == 124 || arg0 == 131 ||
  arg0 == 172 || arg0 == 178 || arg0 == 220 || arg0 == 275 || arg0 == 435)/
{
    printf("[%d/%d ret  ] nr=%d ret=%d errno=%d\n", pid, tid, arg0, (int)arg2, (int)arg3);
}

carrick*:::futex-route
/pid == $target || progenyof($target)/
{
    printf("[%d/%d futex-route] addr=%#llx op=%d shared=%d host=%#llx\n",
        pid, tid, arg1, (int)arg2, (int)arg3, arg4);
}

carrick*:::io-wait-begin
/pid == $target || progenyof($target)/
{
    printf("[%d/%d io-wait-begin] guest_tid=%d count=%d timeout=%d fd0=%d events0=%#x fd1=%d\n",
        pid, tid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5);
}

carrick*:::io-wait-end
/pid == $target || progenyof($target)/
{
    printf("[%d/%d io-wait-end] guest_tid=%d result=%d count=%d fd0=%d fd1=%d fd2=%d\n",
        pid, tid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5);
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d/%d guest-exit] code=%d\n", pid, tid, (int)arg1);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 70/
{
    exit(0);
}
