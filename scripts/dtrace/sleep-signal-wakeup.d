/*
 * Trace signal publication/delivery around interruptible sleeps.
 *
 * Result codes for io-wait-end:
 *   0 Ready, 1 TimedOut, 2 Interrupted, 3 Errno
 */

#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("sleep/signal wakeup trace started at %Y\n", walltimestamp);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
    (arg0 == 115 || arg0 == 129 || arg0 == 220 || arg0 == 260)/
{
    @syscalls[copyinstr(arg1)] = count();
    printf("%Y [%d syscall-entry] %-18s nr=%d\n",
        walltimestamp, pid, copyinstr(arg1), arg0);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
    (arg0 == 115 || arg0 == 129 || arg0 == 220 || arg0 == 260)/
{
    printf("%Y [%d syscall-ret  ] %-18s nr=%d ret=%d errno=%d\n",
        walltimestamp, pid, copyinstr(arg1), arg0, (int)arg2, (int)arg3);
}

carrick*:::signal-publish
/pid == $target || progenyof($target)/
{
    @publishes[(int)arg0, (int)arg1, (int)arg2] = count();
    printf("%Y [%d signal-pub  ] target_tid=%d signum=%d kind=%d\n",
        walltimestamp, pid, (int)arg0, (int)arg1, (int)arg2);
}

carrick*:::signal-deliver
/pid == $target || progenyof($target)/
{
    @delivers[(int)arg0, (int)arg1] = count();
    printf("%Y [%d signal-del  ] tid=%d pending=%d\n",
        walltimestamp, pid, (int)arg0, (int)arg1);
}

carrick*:::io-wait-begin
/pid == $target || progenyof($target)/
{
    @wait_begin[(int)arg0, (int)arg1, (int)arg2] = count();
    printf("%Y [%d wait-begin  ] tid=%d fd_count=%d timeout_ms=%d fd0=%d events0=%d fd1=%d\n",
        walltimestamp, pid, (int)arg0, (int)arg1, (int)arg2,
        (int)arg3, (int)arg4, (int)arg5);
}

carrick*:::io-wait-end
/pid == $target || progenyof($target)/
{
    @wait_end[(int)arg0, (int)arg1, (int)arg2] = count();
    printf("%Y [%d wait-end    ] tid=%d result=%d fd_count=%d fd0=%d fd1=%d fd2=%d\n",
        walltimestamp, pid, (int)arg0, (int)arg1, (int)arg2,
        (int)arg3, (int)arg4, (int)arg5);
}

dtrace:::END
{
    printf("\n==== syscalls ====\n");
    printa("  %-24s %@d\n", @syscalls);
    printf("\n==== signal publishes (target_tid, signum, kind) ====\n");
    printa("  tid=%-8d sig=%-3d kind=%-2d %@d\n", @publishes);
    printf("\n==== signal delivers (tid, pending) ====\n");
    printa("  tid=%-8d pending=%-3d %@d\n", @delivers);
    printf("\n==== wait begin (tid, fd_count, timeout_ms) ====\n");
    printa("  tid=%-8d fds=%-2d timeout_ms=%-6d %@d\n", @wait_begin);
    printf("\n==== wait end (tid, result, fd_count) ====\n");
    printa("  tid=%-8d result=%-2d fds=%-2d %@d\n", @wait_end);
}
