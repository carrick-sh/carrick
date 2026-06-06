#pragma D option quiet
carrick*:::epoll-ctl
/(pid == $target || progenyof($target))/
{
    @epoll_ctl["op", arg1] = count();
}

carrick*:::epoll-wait-fd
/(pid == $target || progenyof($target))/
{
    @epoll_wait_fd["fd"] = count();
}

carrick*:::epoll-result
/(pid == $target || progenyof($target))/
{
    @epoll_result["kind", arg4] = count();
    @epoll_result["wait_count", arg2] = count();
}

syscall::kevent:entry
/(pid == $target || progenyof($target))/
{
    self->kevent_start = timestamp;
    @kevent_stats["nchanges"] = sum(arg2);
    @kevent_stats["nevents"] = sum(arg4);
}

syscall::kevent:return
/self->kevent_start/
{
    @kevent_stats["wall_ns"] = sum(timestamp - self->kevent_start);
    @kevent_returns["ret_errno", (int)arg1, errno] = count();
    self->kevent_start = 0;
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 20/
{
    exit(0);
}
