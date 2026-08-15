/*
 * Distinguish Go splice/netpoll stalls from bounded-vCPU scheduler starvation.
 *
 * Provider ABI qualified on Darwin/arm64 2026-08-15: syscall-entry arg0 is the
 * canonical AArch64 syscall number; syscall-return args 0..3 are
 * nr/name/retval/errno. io-wait-begin args 0..5 are the guest tid, fd count,
 * timeout ms, first fd, first events, and second fd. DTrace's built-in `tid`
 * is the Carrick host-thread id, so the two identifiers deliberately remain
 * separate dimensions below.
 *
 * The capture aggregates rather than printing the hot path. It therefore
 * perturbs scheduling materially less than the line-oriented epoll debugger,
 * but it still arms USDT on every selected syscall and is not performance
 * evidence. The script self-terminates after 20 seconds.
 */

#pragma D option quiet
#pragma D option destructive

dtrace:::BEGIN
{
    printf("carrick Go splice scheduler census started at %Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg0 == 22 || (uint64_t)arg0 == 76 || (uint64_t)arg0 == 98 ||
  (uint64_t)arg0 == 124)/
{
    @syscalls[pid, tid, (uint64_t)arg0] = count();
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (uint64_t)arg0 == 76/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    @splice_args[pid, tid, (int)this->a[0], (int)this->a[2],
        (uint64_t)this->a[4], (uint64_t)this->a[5]] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg0 == 22 || (uint64_t)arg0 == 76 || (uint64_t)arg0 == 98 ||
  (uint64_t)arg0 == 124)/
{
    @returns[pid, tid, (uint64_t)arg0, (int64_t)arg2, (int)arg3] = count();
}

carrick*:::io-wait-begin
/(pid == $target || progenyof($target))/
{
    @waits[pid, tid, (int)arg0, (int)arg1, (int)arg2] = count();
}

carrick*:::epoll-rebind
/(pid == $target || progenyof($target))/
{
    this->r = (uint64_t *)copyin(arg0, 48);
    @rebinds[pid, tid, (int)this->r[0], (int)this->r[1]] = count();
}

carrick*:::epoll-ctl
/(pid == $target || progenyof($target))/
{
    @epoll_ctl[pid, tid, (int)arg0, (int)arg2, (uint32_t)arg3,
        (uint64_t)arg4] = count();
}

carrick*:::epoll-result
/(pid == $target || progenyof($target))/
{
    @epoll_result[pid, tid, (int)arg0, (int)arg1, (int)arg4] = count();
}

tick-20s
{
    exit(0);
}

dtrace:::END
{
    printf("\n=== selected syscall entries: pid host-tid nr count ===\n");
    printa("  %d %d %d %@d\n", @syscalls);
    printf("\n=== selected syscall returns: pid host-tid nr retval errno count ===\n");
    printa("  %d %d %d %d %d %@d\n", @returns);
    printf("\n=== splice args: pid host-tid in-fd out-fd len flags count ===\n");
    printa("  %d %d %d %d %d %#x %@d\n", @splice_args);
    printf("\n=== waits: pid host-tid guest-tid fd-count timeout-ms count ===\n");
    printa("  %d %d %d %d %d %@d\n", @waits);
    printf("\n=== epoll rebinds: pid host-tid reason host-fd count ===\n");
    printa("  %d %d %d %d %@d\n", @rebinds);
    printf("\n=== epoll ctl: pid host-tid epfd fd events data count ===\n");
    printa("  %d %d %d %d %#x %#x %@d\n", @epoll_ctl);
    printf("\n=== epoll results: pid host-tid epfd ready kind count ===\n");
    printa("  %d %d %d %d %d %@d\n", @epoll_result);
}
