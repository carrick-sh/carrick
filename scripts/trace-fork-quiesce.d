#pragma D option quiet
#pragma D option strsize=256

/*
 * Focused multithreaded fork trace.
 *
 * Correlates Go clone/exec/wait syscalls with carrick's fork-quiesce USDT
 * probe.  The important line is phase=2: a non-zero `a` is hv_vm_destroy()
 * failing, and `b` is the live-vCPU count at that instant. phase=3 reports a
 * sibling vCPU destroy/rebuild/create site result.
 */

dtrace:::BEGIN
{
    printf("fork quiesce trace started at %Y\n", walltimestamp);
}

carrick*:::fork-quiesce
/pid == $target || progenyof($target)/
{
    printf("[%d forkq] phase=%d a=%d b=%d tid=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3);
    @forkq[(int)arg0, (int)arg1, (int)arg2] = count();
}

carrick*:::fork-pre
/pid == $target || progenyof($target)/
{
    printf("[%d fork-pre] pc=%#x elr=%#x cpsr=%#x\n", pid, arg0, arg1, arg2);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d fork-post] child=%d pc=%#x elr=%#x\n",
        pid, (int)arg0, arg1, arg2);
}

carrick*:::execve-loaded
/pid == $target || progenyof($target)/
{
    printf("[%d execve] path=%s entry=%#x sp=%#x regions=%d\n",
        pid, copyinstr(arg0), arg1, arg2, (int)arg3);
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d guest-exit] code=%d\n", (int)arg0, (int)arg1);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
    (arg0 == 72 || arg0 == 73 || arg0 == 95 || arg0 == 98 || arg0 == 101 ||
     arg0 == 115 || arg0 == 220 || arg0 == 221 || arg0 == 260 ||
     arg0 == 293 || arg0 == 434 || arg0 == 435)/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    printf("[%d entry] %-12s nr=%d args=[%#x,%#x,%#x,%#x,%#x,%#x]\n",
        pid, copyinstr(arg1), arg0,
        this->sa[0], this->sa[1], this->sa[2],
        this->sa[3], this->sa[4], this->sa[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
    (arg0 == 72 || arg0 == 73 || arg0 == 95 || arg0 == 98 || arg0 == 101 ||
     arg0 == 115 || arg0 == 220 || arg0 == 221 || arg0 == 260 ||
     arg0 == 293 || arg0 == 434 || arg0 == 435)/
{
    printf("[%d ret  ] %-12s nr=%d ret=%d errno=%d\n",
        pid, copyinstr(arg1), arg0, (int)arg2, (int)arg3);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 60/
{
    exit(0);
}

dtrace:::END
{
    printf("\n--- fork-quiesce phase summary ---\n");
    printa("phase=%-2d a=%-12d b=%-12d %@d\n", @forkq);
}
