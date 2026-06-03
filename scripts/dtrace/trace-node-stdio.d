#pragma D option quiet
#pragma D option strsize=256

/*
 * Focused Node/libuv child stdio trace.
 *
 * Records the guest fd lifecycle around pipe2/socketpair/dup3/close/
 * close_range/execve plus poll/epoll/read/write/send/recv/io_uring returns, and
 * correlates successful host pipe/socket I/O/fork edges.
 */

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 20 || arg0 == 21 || arg0 == 22 || arg0 == 23 || arg0 == 24 || arg0 == 25 || arg0 == 57 || arg0 == 59 || arg0 == 63 || arg0 == 64 || arg0 == 66 || arg0 == 73 || arg0 == 198 || arg0 == 199 || arg0 == 206 || arg0 == 207 || arg0 == 209 || arg0 == 210 || arg0 == 211 || arg0 == 212 || arg0 == 221 || arg0 == 425 || arg0 == 426 || arg0 == 427 || arg0 == 436)/
{
    self->args = (uint64_t *)copyin(arg2, 48);
    printf("[%d entry] nr=%d a0=0x%llx a1=0x%llx a2=0x%llx a3=0x%llx\n",
        pid, arg0, self->args[0], self->args[1], self->args[2], self->args[3]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 20 || arg0 == 21 || arg0 == 22 || arg0 == 23 || arg0 == 24 || arg0 == 25 || arg0 == 57 || arg0 == 59 || arg0 == 63 || arg0 == 64 || arg0 == 66 || arg0 == 73 || arg0 == 198 || arg0 == 199 || arg0 == 206 || arg0 == 207 || arg0 == 209 || arg0 == 210 || arg0 == 211 || arg0 == 212 || arg0 == 221 || arg0 == 425 || arg0 == 426 || arg0 == 427 || arg0 == 436)/
{
    printf("[%d ret  ] nr=%d ret=%d errno=%d\n", pid, arg0, (int)arg2, (int)arg3);
}

carrick*:::host-pipe-io
/pid == $target || progenyof($target)/
{
    printf("[%d pipe ] host_fd=%d dir=%d n=%d\n", pid, (int)arg1, (int)arg2, (int)arg3);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d fork ] child=%d\n", pid, (int)arg0);
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d exit ] code=%d\n", pid, (int)arg1);
}

syscall::write:entry, syscall::write_nocancel:entry
/pid == $target || progenyof($target)/
{
    self->host_write_fd = (int)arg0;
    self->host_write_len = (int)arg2;
}

syscall::write:return, syscall::write_nocancel:return
/(pid == $target || progenyof($target)) && errno != 0/
{
    printf("[%d host ] write fd=%d len=%d ret=%d errno=%d\n",
        pid, self->host_write_fd, self->host_write_len, (int)arg1, errno);
}

syscall::close:entry, syscall::guarded_close_np:entry
/(pid == $target || progenyof($target)) && arg0 < 64/
{
    printf("[%d host ] %s fd=%d\n", pid, probefunc, (int)arg0);
}

tick-1s { secs++; }
tick-1s /secs >= 30/ { exit(0); }
