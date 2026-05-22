/*
 * Speculative "failing child" tracer for carrick.
 *
 *   carrick trace --script scripts/trace-failing-child.d -- run <image> <cmd...>
 *
 * Problem: a guest workload (e.g. `apt install`) forks hundreds of children;
 * only ONE fails, and the interesting evidence is the handful of syscalls it
 * makes right before `_exit`. Streaming every syscall of every process drowns
 * that in millions of lines.
 *
 * Technique: DTrace SPECULATIONS. We open one speculation per guest pid and
 * speculatively record its entire syscall stream (entry args + return/errno).
 * At guest exit we COMMIT the buffer only for a child that (a) exited non-zero
 * AND (b) never reached execve — i.e. a fork-then-_exit failure, the class
 * that has no execve errno to catch. Every other process is DISCARDED, so the
 * output is just the failing child's full timeline.
 *
 * Tunables: bump specsize if a failing child makes a very long pre-exec
 * sequence (apt's CLOEXEC sweep alone is ~1000 fcntls).
 */

#pragma D option quiet
#pragma D option specsize=4m
#pragma D option nspec=16
#pragma D option bufsize=8m
#pragma D option dynvarsize=16m
#pragma D option strsize=256
#pragma D option switchrate=10ms

/* Open a speculation the first time we see a syscall from a tracked pid. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && spec[pid] == 0/
{
    spec[pid] = speculation();
    did_exec[pid] = 0;
}

/* Record every NON-fcntl syscall entry (name + the six raw args). fcntl is
 * handled separately so we can drop the giant CLOEXEC fd-sweep (fcntl that
 * returns EBADF on closed fds) which would otherwise overflow the buffer. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && spec[pid] != 0 && arg0 != 25/
{
    speculate(spec[pid]);
    this->sa = (uint64_t *)copyin(arg2, 48);
    printf("[%d] %-20s nr=%-3d (%#x, %#x, %#x, %#x, %#x, %#x)\n",
        pid, copyinstr(arg1), arg0,
        this->sa[0], this->sa[1], this->sa[2], this->sa[3], this->sa[4], this->sa[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && spec[pid] != 0 && arg0 != 25/
{
    speculate(spec[pid]);
    printf("[%d]     = ret=%d errno=%d\n", pid, (int)arg2, (int)arg3);
}

/* fcntl: stash fd+cmd on entry, record on return ONLY if it is NOT the
 * benign EBADF CLOEXEC sweep — i.e. a meaningful fcntl (e.g. clearing
 * close-on-exec on a real keep-fd, or a genuine failure on an open fd). */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && spec[pid] != 0 && arg0 == 25/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    ffd[pid] = this->sa[0];
    fcmd[pid] = this->sa[1];
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && spec[pid] != 0 && arg0 == 25 && (int)arg3 != 9/
{
    speculate(spec[pid]);
    printf("[%d] fcntl fd=%d cmd=%d  = ret=%d errno=%d\n",
        pid, (int)ffd[pid], (int)fcmd[pid], (int)arg2, (int)arg3);
}

/* Mark a pid as having reached a real exec (its image was loaded). */
carrick*:::execve-loaded
/(pid == $target || progenyof($target))/
{
    did_exec[pid] = 1;
}

carrick*:::unhandled-syscall
/(pid == $target || progenyof($target)) && spec[pid] != 0/
{
    speculate(spec[pid]);
    printf("[%d] !!! UNHANDLED %s\n", pid, copyinstr(arg1));
}

/* COMMIT: non-zero exit AND never execve'd = the fork-then-_exit failure. */
carrick*:::guest-exit
/(pid == $target || progenyof($target)) && spec[pid] != 0 && (int)arg1 != 0 && did_exec[pid] == 0/
{
    speculate(spec[pid]);
    printf("[%d] >>> EXIT code=%d (fork-then-_exit, no execve) <<<\n", pid, (int)arg1);
    commit(spec[pid]);
    spec[pid] = 0;
}

/* DISCARD everyone else (clean exits, or processes that exec'd successfully). */
carrick*:::guest-exit
/(pid == $target || progenyof($target)) && spec[pid] != 0/
{
    discard(spec[pid]);
    spec[pid] = 0;
}
