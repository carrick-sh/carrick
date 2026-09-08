#pragma D option quiet
#pragma D option bufsize=64m
#pragma D option aggsize=64m

carrick*:::host-image-base
/(pid == $target || progenyof($target))/
{
    printf("HOST_IMAGE_BASE|pid=%d|base=0x%llx|slide=0x%llx|path=%s\n",
        (int32_t)arg0, (uint64_t)arg1, (int64_t)arg2, copyinstr(arg3));
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target))/
{
    self->sys_ts = timestamp;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target))/
{
    @syscalls[copyinstr(arg1)] = count();
    @syscall_ns[copyinstr(arg1)] = sum(timestamp - self->sys_ts);
}

carrick*:::vcpu-fault
/(pid == $target || progenyof($target))/
{
    @counts["vcpu-fault"] = count();
}

carrick*:::hvpatch-guest-fault
/(pid == $target || progenyof($target))/
{
    @counts["hvpatch-guest-fault"] = count();
}

carrick*:::hvpatch-first-touch-deliver
/(pid == $target || progenyof($target))/
{
    @counts["hvpatch-first-touch-deliver"] = count();
}

carrick*:::stage1-arena-bind
/(pid == $target || progenyof($target))/
{
    @counts["stage1-arena-bind"] = count();
}

carrick*:::stage1-arena-install
/(pid == $target || progenyof($target))/
{
    @counts["stage1-arena-install"] = count();
}

carrick*:::hvpatch-stale-stage1-retry
/(pid == $target || progenyof($target))/
{
    @counts["hvpatch-stale-stage1-retry"] = count();
}

profile-1997
/(pid == $target || progenyof($target))/
{
    @stacks[ustack(20)] = count();
}

proc:::exit
/pid == $target/
{
    exit(0);
}

dtrace:::END
{
    printf("\n=== SYSCALL COUNTS ===\n");
    printa("%-25s %@12d\n", @syscalls);
    printf("\n=== SYSCALL TIME (ns) ===\n");
    printa("%-25s %@16d\n", @syscall_ns);
    printf("\n=== FAULT / STAGE-1 COUNTS ===\n");
    printa("%-30s %@12d\n", @counts);
    printf("\n=== TOP 10 USER STACKS ===\n");
    trunc(@stacks, 10);
    printa(@stacks);
}
