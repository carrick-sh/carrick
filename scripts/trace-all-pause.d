#pragma D option quiet
#pragma D option strsize=256

/* Trace all syscalls during LTP pause01 to see what diverges. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target))/
{
    printf("[%d] ENTRY  nr=%d %s\n", pid, arg0, copyinstr(arg1));
}

carrick*:::syscall-return
/(pid == $target || progenyof($target))/
{
    printf("[%d] RETURN nr=%d ret=%d errno=%d\n", pid, arg0, (int)arg2, (int)arg3);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d] fork-post child=%d\n", pid, (int)arg1);
}

tick-1s { secs++; }
tick-1s /secs >= 15/ { exit(0); }
