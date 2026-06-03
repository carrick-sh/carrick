#pragma D option quiet
#pragma D option strsize=256

/*
 * Focused trace for the waitrestart conformance probe. Keep this bounded and
 * process-tree-wide: the probe uses forked guest processes, and child carrick
 * processes register their own USDT providers.
 */

carrick*:::execve-argv
/pid == $target || progenyof($target)/
{
    printf("[%d] exec path=%s argv=%s\n", pid, copyinstr(arg1), copyinstr(arg2));
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d] fork-post child=%d\n", pid, (int)arg0);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
    (arg0 == 59 || arg0 == 63 || arg0 == 64 || arg0 == 93 || arg0 == 94 ||
     arg0 == 103 || arg0 == 134 || arg0 == 139 || arg0 == 220 || arg0 == 260)/
{
    printf("[%d] ret nr=%d %s ret=%d errno=%d\n",
        pid, (int)arg0, copyinstr(arg1), (int)arg2, (int)arg3);
}

carrick*:::signal-publish
/pid == $target || progenyof($target)/
{
    printf("[%d] signal-publish tid=%d sig=%d kind=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2);
}

carrick*:::itimer-fire
/pid == $target || progenyof($target)/
{
    printf("[%d] itimer-fire pidarg=%d sig=%d generation=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2);
}

carrick*:::io-wait-begin
/pid == $target || progenyof($target)/
{
    printf("[%d] io-wait-begin tid=%d fds=%d timeout=%d fd0=%d events0=%d fd1=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5);
}

carrick*:::io-wait-end
/pid == $target || progenyof($target)/
{
    printf("[%d] io-wait-end tid=%d result=%d fds=%d fd0=%d fd1=%d fd2=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4, (int)arg5);
}

carrick*:::signal-deliver
/pid == $target || progenyof($target)/
{
    printf("[%d] signal-deliver tid=%d sig=%d\n", pid, (int)arg0, (int)arg1);
}

carrick*:::signal-inject
/pid == $target || progenyof($target)/
{
    printf("[%d] signal-inject sig=%d saved_pc=%x new_sp=%x handler=%x\n",
        pid, (int)arg0, arg1, arg2, arg3);
}

carrick*:::signal-restore
/pid == $target || progenyof($target)/
{
    printf("[%d] signal-restore saved_pc=%x sp=%x magic=%x\n", pid, arg0, arg1, arg2);
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d] guest-exit pidarg=%d code=%d\n", pid, (int)arg0, (int)arg1);
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
