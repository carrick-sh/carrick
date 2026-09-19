#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("epoll amplification trace started at %Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 22 || arg0 == 281)/
{
    /* 22 = epoll_pwait, 281 = epoll_pwait2 on aarch64 */
    @guest_epoll_pwait = count();
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 20 || arg0 == 21)/
{
    /* 20 = epoll_create1, 21 = epoll_ctl on aarch64 */
    @guest_epoll_ctl[(int)arg0] = count();
}

carrick*:::epoll-ctl
/(pid == $target || progenyof($target))/
{
    @carrick_epoll_ctl_op[(int)arg1] = count();
}

carrick*:::epoll-result
/(pid == $target || progenyof($target))/
{
    @carrick_epoll_result[(int)arg1, (int)arg2] = count();
}

carrick*:::epoll-rebind
/(pid == $target || progenyof($target))/
{
    @carrick_epoll_rebind[(int)arg0] = count();
}

syscall::*kqueue*:entry
/(pid == $target || progenyof($target))/
{
    @host_kqueue_create = count();
}

syscall::*kevent*:entry
/(pid == $target || progenyof($target))/
{
    @host_kevent = count();
}

syscall::*poll*:entry
/(pid == $target || progenyof($target))/
{
    @host_poll = count();
}

syscall::getpeername:entry
/(pid == $target || progenyof($target))/
{
    @host_getpeername = count();
}

proc:::exit
/pid == $target/
{
    exit(0);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 25/
{
    exit(0);
}

dtrace:::END
{
    printf("\n==== GUEST SYSCALLS ====\n");
    printf("epoll_pwait/pwait2 calls:\n");
    printa("  %@d\n", @guest_epoll_pwait);
    printf("epoll_create1/ctl calls by nr:\n");
    printa("  nr=%d: %@d\n", @guest_epoll_ctl);
    printf("epoll_ctl by op (1=ADD, 2=DEL, 3=MOD):\n");
    printa("  op=%d: %@d\n", @carrick_epoll_ctl_op);
    printf("epoll results (ready, wait):\n");
    printa("  ready=%d wait=%d: %@d\n", @carrick_epoll_result);
    printf("epoll rebind by reason:\n");
    printa("  reason=%d: %@d\n", @carrick_epoll_rebind);

    printf("\n==== HOST SYSCALLS AMPLIFICATION ====\n");
    printf("host kqueue() creates (rdhup check + epoll_create):\n");
    printa("  %@d\n", @host_kqueue_create);
    printf("host kevent() calls:\n");
    printa("  %@d\n", @host_kevent);
    printf("host poll() calls:\n");
    printa("  %@d\n", @host_poll);
    printf("host getpeername() calls:\n");
    printa("  %@d\n", @host_getpeername);
}
