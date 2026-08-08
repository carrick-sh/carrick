/*
 * tier-d-exec-commit-unmap.d — bind host unmaps around Tier-D exec commit.
 *
 * WHAT IT MEASURES
 * ----------------
 * After a descendant issues guest execve(221), print every Darwin mmap result
 * and munmap made by that host process until it exits. This distinguishes
 * fallible incoming image preparation, outgoing DirectLoadGroup/DirectStack
 * retirement, and the runner-owned ordinary-mapping catalog when an exec
 * replacement loses pages.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-08. carrick syscall-entry exposes the
 * canonical Linux number as arg0 (execve=221). syscall::mmap:entry exposes
 * addr/len/prot/flags/fd/offset as arg0..arg5; syscall::mmap:return exposes
 * result and errno as arg0/arg1. syscall::munmap:entry exposes address and
 * length as arg0/arg1. proc:::create exposes the child pid as
 * args[0]->pr_pid. The target predicate follows carrick trace's launch child
 * and every host-fork descendant.
 *
 * PERTURBATION
 * ------------
 * LOW for the reduced Node exec child: one fasttrap action at guest syscall
 * boundaries and one print per post-exec host munmap. This is mechanism
 * attribution only; elapsed time is not performance evidence. A valid capture
 * has a guest-exec marker, nonzero host munmaps, and ends naturally or at the
 * ten-second diagnostic bound without DTrace errors.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    printf("TIERDEXECUNMAP1|event=begin|target=%d|time=%Y\n", $target,
        walltimestamp);
}

dtrace:::ERROR
{
    errors++;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 221/
{
    execing[pid] = 1;
    execs++;
    printf("TIERDEXECUNMAP1|event=guest-exec|pid=%d|tid=%d\n", pid, tid);
}

syscall::munmap:entry
/execing[pid]/
{
    unmaps++;
    printf("TIERDEXECUNMAP1|event=host-munmap|pid=%d|tid=%d|address=%#x|length=%#x\n",
        pid, tid, arg0, arg1);
}

syscall::mmap:entry
/execing[pid]/
{
    self->mmap = 1;
    self->mmap_addr = arg0;
    self->mmap_len = arg1;
    self->mmap_prot = arg2;
    self->mmap_flags = arg3;
}

syscall::mmap:return
/execing[pid] && self->mmap/
{
    mmaps++;
    printf("TIERDEXECUNMAP1|event=host-mmap|pid=%d|tid=%d|hint=%#x|length=%#x|prot=%#x|flags=%#x|result=%#x|errno=%d\n",
        pid, tid, self->mmap_addr, self->mmap_len, self->mmap_prot,
        self->mmap_flags, arg0, arg1);
    self->mmap = 0;
    self->mmap_addr = 0;
    self->mmap_len = 0;
    self->mmap_prot = 0;
    self->mmap_flags = 0;
}

proc:::exit
/execing[pid]/
{
    execing[pid] = 0;
    exited++;
    exit(0);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 10/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printf("TIERDEXECUNMAP1|event=end|execs=%d|mmaps=%d|unmaps=%d|exited=%d|bounded=%d|errors=%d|time=%Y\n",
        execs, mmaps, unmaps, exited, bounded, errors, walltimestamp);
}
