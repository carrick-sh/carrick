/*
 * Compare guest Linux pipe I/O against the underlying macOS host syscalls,
 * to find why a pipe's host fd write fails (ENXIO/EIO) in a forked subshell.
 *
 *   carrick trace --script scripts/trace-host-fds.d -- \
 *       run ubuntu:24.04 /usr/bin/sh -c '(echo hi | cat)'
 */

#pragma D option quiet
#pragma D option switchrate=10ms

/* ---- macOS HOST syscalls (the real kernel) ---- */

/* Host pipe() creation: the returned fds land in the guest's HostPipe. */
syscall::pipe:return
/pid == $target || progenyof($target)/
{
    /* macOS arm64 pipe(2) returns the two fds in x0/x1 (arg0/arg1). */
    printf("[%d HOST] pipe() -> fd0=%d fd1=%d errno=%d\n",
        pid, (int)arg0, (int)arg1, errno);
}

/* Host fork/vfork: correlate with carrick's HVF rebuild. */
syscall::fork:return, syscall::vfork:return
/pid == $target || progenyof($target)/
{
    printf("[%d HOST] %s -> ret=%d\n", pid, probefunc, (int)arg1);
}

/* Host close: did the child close the pipe fd it needs? */
syscall::close:entry, syscall::guarded_close_np:entry
/(pid == $target || progenyof($target)) && arg0 < 16/
{
    printf("[%d HOST] %s(fd=%d)\n", pid, probefunc, (int)arg0);
}

/* Host write FAILURES: the ENXIO/EIO we're chasing. */
syscall::write:entry, syscall::write_nocancel:entry
/pid == $target || progenyof($target)/
{
    self->wfd = (int)arg0;
    self->wlen = (int)arg2;
}

syscall::write:return, syscall::write_nocancel:return
/(pid == $target || progenyof($target)) && errno != 0/
{
    printf("[%d HOST] write(fd=%d, len=%d) -> ret=%d errno=%d\n",
        pid, self->wfd, self->wlen, (int)arg1, errno);
}

/* dup2/dup on the host (if carrick mirrors guest dup3 to a host dup). */
syscall::dup2:entry, syscall::dup:entry
/(pid == $target || progenyof($target)) && arg0 < 16/
{
    printf("[%d HOST] %s(fd=%d)\n", pid, probefunc, (int)arg0);
}

/* ---- guest (carrick USDT) ---- */

carrick*:::host-pipe-io
/pid == $target || progenyof($target)/
{
    printf("[%d] guest host-pipe-io host_fd=%d dir=%d n=%d\n",
        pid, (int)arg1, (int)arg2, (int)arg3);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d] === fork-post child_pid=%d ===\n", pid, (int)arg0);
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d] guest-exit code=%d\n", pid, (int)arg1);
}
