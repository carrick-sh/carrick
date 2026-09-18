/*
 * Measure the Darwin socket backing used by a Carrick guest stream.
 *
 * Records SO_SNDBUF/SO_RCVBUF/SO_SNDLOWAT changes and the real host write(2)
 * progress alongside Carrick's host-pipe-io USDT record.  This distinguishes
 * a guest-visible short write from a host buffer clamp or premature kqueue
 * writable edge.  It is intentionally high-volume on write-heavy workloads;
 * use only with a focused reducer.
 *
 * Qualified on macOS arm64: syscall provider setsockopt arguments are
 * (fd, level, optname, optval, optlen); write arguments are (fd, buf, len).
 * The script perturbs syscall-heavy runs and is diagnostic only.
 */

#pragma D option quiet
#pragma D option switchrate=10ms

syscall::setsockopt:entry
/pid == $target || progenyof($target)/
{
    self->set_fd = (int)arg0;
    self->set_level = (int)arg1;
    self->set_name = (int)arg2;
    self->set_value = arg4 >= 4 ? *(int *)copyin(arg3, 4) : -1;
}

syscall::setsockopt:return
/(pid == $target || progenyof($target)) && self->set_fd != 0/
{
    printf("HOSTSOCK1|setsockopt|pid=%d|fd=%d|level=%d|name=%d|value=%d|ret=%d|errno=%d\n",
        pid, self->set_fd, self->set_level, self->set_name, self->set_value,
        (int)arg1, errno);
    stream_fd[pid, self->set_fd] = errno == 0 ? 1 : 0;
    self->set_fd = 0;
}

syscall::write:entry, syscall::write_nocancel:entry
/(pid == $target || progenyof($target)) && stream_fd[pid, (int)arg0]/
{
    self->write_fd = (int)arg0;
    self->write_len = (int)arg2;
}

syscall::write:return, syscall::write_nocancel:return
/(pid == $target || progenyof($target)) && self->write_fd != 0/
{
    printf("HOSTSOCK1|write|pid=%d|fd=%d|len=%d|ret=%d|errno=%d\n",
        pid, self->write_fd, self->write_len, (int)arg1, errno);
    self->write_fd = 0;
}

carrick*:::host-pipe-io
/(pid == $target || progenyof($target)) && ((int)arg3 >= 32768 || (int)arg3 < 0)/
{
    printf("HOSTSOCK1|guest-io|pid=%d|fd=%d|dir=%d|ret=%d\n",
        pid, (int)arg1, (int)arg2, (int)arg3);
}

tick-1s { secs++; }
tick-1s /secs >= 45/ { exit(0); }
