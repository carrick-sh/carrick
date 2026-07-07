#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("carrick epoll_ctl cost trace started at %Y\n", walltimestamp);
}

carrick*:::epoll-ctl
/(pid == $target || progenyof($target))/
{
    @epoll_ctl_op[(int)arg1] = count();
    @epoll_ctl_events[(int)arg1, (int)arg3] = count();
}

carrick*:::epoll-rebind
/(pid == $target || progenyof($target))/
{
    @epoll_rebind = count();
}

carrick*:::epoll-result
/(pid == $target || progenyof($target))/
{
    @epoll_result[(int)arg1, (int)arg2, (int)arg4] = count();
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target))/
{
    @guest_syscalls[(int)arg0] = count();
}

carrick*:::fork-post
/(pid == $target || progenyof($target))/
{
    @fork_post = count();
}

syscall::*kevent*:entry
/(pid == $target || progenyof($target))/
{
    @host_kevent[probefunc] = count();
    self->in_kevent = 1;
    self->kevent_ts = timestamp;
}

syscall::*kevent*:return
/self->in_kevent/
{
    @host_kevent_ret[probefunc, (int)arg0] = count();
    @host_kevent_ns = sum(timestamp - self->kevent_ts);
    @host_kevent_max_ns = max(timestamp - self->kevent_ts);
    self->in_kevent = 0;
    self->kevent_ts = 0;
}

syscall::*poll*:entry,
syscall::*write*:entry,
syscall::*read*:entry,
syscall::*close*:entry,
syscall::*fcntl*:entry
/(pid == $target || progenyof($target))/
{
    @host_syscalls[probefunc] = count();
}

profile-997
/(pid == $target || progenyof($target))/
{
    @samples[ustack(12)] = count();
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

dtrace:::END
{
    printf("\n==== epoll_ctl by op ====\n");
    printa("  op=%d %@d\n", @epoll_ctl_op);
    printf("\n==== epoll_ctl by events ====\n");
    printa("  op=%d events=%#x %@d\n", @epoll_ctl_events);
    printf("\n==== epoll rebind ====\n");
    printa("  %@d\n", @epoll_rebind);
    printf("\n==== epoll results ====\n");
    printa("  ready=%d wait=%d kind=%d %@d\n", @epoll_result);
    printf("\n==== guest syscall entries by nr ====\n");
    printa("  nr=%d %@d\n", @guest_syscalls);
    printf("\n==== fork post ====\n");
    printa("  %@d\n", @fork_post);
    printf("\n==== host kevent entries ====\n");
    printa("  %s %@d\n", @host_kevent);
    printf("\n==== host kevent returns ====\n");
    printa("  %s ret=%d %@d\n", @host_kevent_ret);
    printf("\n==== host kevent total/max ns ====\n");
    printa("  total %@d\n", @host_kevent_ns);
    printa("  max %@d\n", @host_kevent_max_ns);
    printf("\n==== selected host syscalls ====\n");
    printa("  %s %@d\n", @host_syscalls);
    printf("\n==== profile samples ====\n");
    printa("  %@d\n%k\n", @samples);
}
