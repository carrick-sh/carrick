#pragma D option quiet
#pragma D option strsize=256

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 98 || arg0 == 56 || arg0 == 222 || arg0 == 220 || arg0 == 215)/
{
    /* 98 futex, 56 openat, 220 clone, 222 mmap, 215 munmap */
    printf("[%d] sys ENTRY  nr=%d\n", pid, arg0);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 98 || arg0 == 56 || arg0 == 222 || arg0 == 220 || arg0 == 215)/
{
    printf("[%d] sys RETURN nr=%d ret=%d errno=%d\n", pid, arg0, (int)arg2, (int)arg3);
}

tick-1s { secs++; }
tick-1s /secs >= 15/ { exit(0); }
