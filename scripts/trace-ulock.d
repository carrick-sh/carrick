#pragma D option quiet
#pragma D option strsize=256

/* Pair every ulock-wait entry with its exit so we count actual __ulock
   entries created per process, and identify *who* created them. */

carrick*:::ulock-wait
/pid == $target || progenyof($target)/
{
    printf("[%d] ulock_wait phase=%d host=0x%llx val=%d to_us=%d rc=%d\n",
        pid, (int)arg4, (uint64_t)arg1, (int)arg2, (int)arg3, (int)arg5);
}

carrick*:::futex-route
/pid == $target || progenyof($target)/
{
    printf("[%d] futex-route addr=0x%llx op=%d shared=%d host=0x%llx\n",
        pid, (uint64_t)arg1, (int)arg2, (int)arg3, (uint64_t)arg4);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 98/
{
    printf("[%d] SYS_futex ret=%d errno=%d\n", pid, (int)arg2, (int)arg3);
}

tick-1s { secs++; }
tick-1s /secs >= 10/ { exit(0); }
