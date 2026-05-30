#pragma D option quiet
#pragma D option strsize=256

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 59 || arg0 == 63 || arg0 == 64)/
{
    /* 59 pipe2, 63 read, 64 write */
    printf("[%d] sys ENTRY  nr=%d\n", pid, arg0);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 59 || arg0 == 63 || arg0 == 64)/
{
    printf("[%d] sys RETURN nr=%d ret=%d errno=%d\n", pid, arg0, (int)arg2, (int)arg3);
}

tick-1s { secs++; }
tick-1s /secs >= 8/ { exit(0); }
