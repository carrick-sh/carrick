/*
 * Targeted tracer for the subshell-pipe output-loss bug.
 *
 *   carrick trace --script scripts/trace-subshell-pipe.d -- \
 *       run ubuntu:24.04 /usr/bin/sh -c '(echo hi | cat)'
 *
 * `( a | b )` inside a subshell loses b's output; writes to the pipe / the
 * inherited fd1 fail with ENXIO/EIO. We follow the carrick process tree
 * (progenyof($target)) and print only the fd-plumbing syscalls — pipe2, dup3,
 * close, clone — plus every read/write with its fd and errno, and the
 * host-pipe-io probe (which shows the underlying host fd + byte count). That
 * makes the broken-after-fork host fd visible without drowning in the stream.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option switchrate=10ms

/* aarch64 nrs: dup3=24, pipe2=59, close=57, read=63, write=64, clone=220 */

/* pipe2 / dup3 / close / clone: show args + return. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 59 || arg0 == 24 || arg0 == 57 || arg0 == 220)/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    printf("[%d] %-8s args=(%#x, %#x, %#x)\n",
        pid, copyinstr(arg1), this->sa[0], this->sa[1], this->sa[2]);
    track[pid] = 1;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 59 || arg0 == 24 || arg0 == 57 || arg0 == 220)/
{
    printf("[%d]   %-8s -> ret=%d errno=%d\n", pid, copyinstr(arg1), (int)arg2, (int)arg3);
}

/* read/write: show the guest fd (arg0) + result/errno — this is where the
 * ENXIO/EIO shows up. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 63 || arg0 == 64)/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    rwfd[pid] = this->sa[0];
    rwlen[pid] = this->sa[2];
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 63 || arg0 == 64)/
{
    printf("[%d] %-5s fd=%d len=%d -> ret=%d errno=%d\n",
        pid, copyinstr(arg1), (int)rwfd[pid], (int)rwlen[pid], (int)arg2, (int)arg3);
}

/* host-pipe-io(pid, dir, host_fd, n): dir 0=read 1=write. Reveals the actual
 * host fd carrick read/wrote and how many bytes. */
carrick*:::host-pipe-io
/(pid == $target || progenyof($target))/
{
    printf("[%d]   host-pipe-io dir=%d host_fd=%d n=%d\n",
        pid, (int)arg1, (int)arg2, (int)arg3);
}

carrick*:::fork-post
/(pid == $target || progenyof($target))/
{
    printf("[%d] fork-post child_pid=%d\n", pid, (int)arg0);
}

carrick*:::guest-exit
/(pid == $target || progenyof($target))/
{
    printf("[%d] guest-exit code=%d\n", pid, (int)arg1);
}
