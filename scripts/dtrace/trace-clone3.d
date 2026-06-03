#pragma D option quiet
#pragma D option strsize=256

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 435 || arg0 == 220 || arg0 == 93 || arg0 == 94 || arg0 == 260 || arg0 == 261)/
{
    /* 435 clone3, 220 clone, 93 _exit, 94 _exit_group, 260 wait4, 261 waitid */
    printf("[%d] sys ENTRY  nr=%d\n", pid, arg0);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 435 || arg0 == 220 || arg0 == 93 || arg0 == 94 || arg0 == 260 || arg0 == 261)/
{
    printf("[%d] sys RETURN nr=%d ret=%d errno=%d\n", pid, arg0, (int)arg2, (int)arg3);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d] fork-post child=%d\n", pid, (int)arg1);
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d] guest-exit code=%d\n", pid, (int)arg1);
}

tick-1s { secs++; }
tick-1s /secs >= 12/ { exit(0); }
