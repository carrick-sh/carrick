#pragma D option quiet
#pragma D option strsize=256

/* Catch EVERY ulock-wait call on the system, NOT filtered by progenyof.
   Identifies who else might be parking on the same physical page. */

carrick*:::ulock-wait
{
    printf("[%d] ulock_wait phase=%d host=0x%llx rc=%d execname=%s\n",
        pid, (int)arg4, (uint64_t)arg1, (int)arg5, execname);
}

carrick*:::ulock-wake
{
    printf("[%d] ulock_wake host=0x%llx iter=%d rc=%d execname=%s\n",
        pid, (uint64_t)arg1, (int)arg2, (int)arg3, execname);
}

tick-1s { secs++; }
tick-1s /secs >= 12/ { exit(0); }
