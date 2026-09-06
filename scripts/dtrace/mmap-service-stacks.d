/*
 * Sample carrier host CPU stacks while running an mmap/munmap fixture.
 * macOS/arm64 ABI: service-begin/clear arg3 is the syscall number; args
 * requires begin enabled. The service marker is diagnostic only: redispatch
 * can execute mmap with marker zero, so never filter or classify by it.
 * profile-197 avoids per-page instrumentation; sampled proportions diagnose
 * work, never supply acceptance latency. Print while carrier is alive; raw
 * user PCs may still require atos plus the live LLDB image slide. ERROR or
 * zero samples is unusable. Bound 30 s. Qualified on macOS arm64 Sep 6.
 */
#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option aggsize=32m
carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    self->nr = arg3;
    begins++;
}
carrick*:::hvpatch-syscall-service-clear
/pid == $target || progenyof($target)/
{
    self->nr = 0;
}
profile-197
/(pid == $target || progenyof($target))/
{
    @stacks[pid, self->nr, ustack(16)] = count();
    samples++;
}
tick-2s
{
    printf("MMAP_STACK_SNAPSHOT samples=%d begins=%d\n",samples,begins);
    printa(@stacks);
    trunc(@stacks);
}
dtrace:::ERROR
{
    printf("UNUSABLE: DTrace error\n");
    exit(2);
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
END
{
    printf("MMAP_STACK_END samples=%d begins=%d\n",samples,begins);
}
