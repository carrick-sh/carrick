/*
 * Trace interactive job-control state across the supervisor, guest shell, and
 * forked foreground jobs.
 *
 * Use with a driven pty and out-of-band trace output:
 *
 *   carrick trace --trace-out /private/tmp/carrick-jobctl.out \
 *     --script scripts/trace-job-control.d -- \
 *     run -t --fs host docker.io/library/debian:stable /bin/bash
 *
 * Always follows the whole process tree. Do not convert this to pid$target
 * probes; pid providers do not follow Carrick guest forks.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option switchrate=10ms

/* Linux/aarch64 syscall numbers:
 * ioctl=29, close=57, read=63, write=64, wait4=260,
 * kill=129, setpgid=154, getpgid=155, getsid=156, setsid=157,
 * clone=220, execve=221.
 */

dtrace:::BEGIN
{
    printf("carrick job-control trace started at %Y\n", walltimestamp);
}

carrick*:::supervisor-fork
/pid == $target || progenyof($target)/
{
    printf("[%d supervisor-fork] child=%d\n", pid, (int)arg0);
}

carrick*:::supervisor-child-ready
/pid == $target || progenyof($target)/
{
    printf("[%d supervisor-child-ready] runtime=%d\n", pid, (int)arg0);
}

carrick*:::supervisor-foreground-pgrp
/pid == $target || progenyof($target)/
{
    printf("[%d supervisor-fg-pgrp] pgid=%d errno=%d\n", pid, (int)arg0, (int)arg1);
}

carrick*:::supervisor-child-exit
/pid == $target || progenyof($target)/
{
    printf("[%d supervisor-child-exit] pid=%d status=%#x\n", pid, (int)arg0, (int)arg1);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 29 || arg0 == 129 || arg0 == 154 || arg0 == 155 ||
  arg0 == 156 || arg0 == 157 || arg0 == 220 || arg0 == 221 ||
  arg0 == 260)/
{
    self->sa = (uint64_t *)copyin(arg2, 48);
    printf("[%d entry] %-8s nr=%d args=(%#x,%#x,%#x,%#x)\n",
        pid, copyinstr(arg1), arg0,
        self->sa[0], self->sa[1], self->sa[2], self->sa[3]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 29 || arg0 == 129 || arg0 == 154 || arg0 == 155 ||
  arg0 == 156 || arg0 == 157 || arg0 == 220 || arg0 == 221 ||
  arg0 == 260)/
{
    printf("[%d ret  ] %-8s nr=%d ret=%d errno=%d\n",
        pid, copyinstr(arg1), arg0, (int)arg2, (int)arg3);
}

syscall::ioctl:entry
/(pid == $target || progenyof($target))/
{
    self->ioctl_fd = (int)arg0;
    self->ioctl_req = arg1;
}

syscall::ioctl:return
/(pid == $target || progenyof($target)) && errno != 0/
{
    printf("[%d HOST] ioctl(fd=%d, req=%#x) -> ret=%d errno=%d\n",
        pid, self->ioctl_fd, self->ioctl_req, (int)arg1, errno);
}

syscall::write:entry, syscall::write_nocancel:entry
/(pid == $target || progenyof($target))/
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

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d fork-post] child_pid=%d pc=%#x elr=%#x\n",
        pid, (int)arg0, arg1, arg2);
}

carrick*:::execve-loaded
/pid == $target || progenyof($target)/
{
    printf("[%d execve-loaded] path=%s entry=%#x\n",
        pid, copyinstr(arg0), arg1);
}

carrick*:::host-pipe-io
/pid == $target || progenyof($target)/
{
    printf("[%d host-pipe-io] dir=%d host_fd=%d n=%d\n",
        pid, (int)arg1, (int)arg2, (int)arg3);
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d guest-exit] code=%d\n", pid, (int)arg1);
}

tick-1s
{
    secs++;
}

tick-1s /secs >= 20/
{
    exit(0);
}
