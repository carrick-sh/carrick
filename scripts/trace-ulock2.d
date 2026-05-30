#pragma D option quiet
#pragma D option strsize=256

/* Print each ulock-wake loop iteration so we see exactly which iteration
   succeeded (rc=0) vs failed (rc<0). Combined with ulock-wait phase 0/1
   and futex-route, this tells us:
   - which process created __ulock entries (ulock-wait phase 0)
   - which one we drained per wake call (ulock-wake rc=0)
   - how many we drained before ENOENT (count of rc=0). */

carrick*:::ulock-wake
/pid == $target || progenyof($target)/
{
    printf("[%d] ulock_wake host=0x%llx iter=%d rc=%d\n",
        pid, (uint64_t)arg1, (int)arg2, (int)arg3);
}

carrick*:::ulock-wait
/pid == $target || progenyof($target)/
{
    printf("[%d] ulock_wait phase=%d host=0x%llx rc=%d\n",
        pid, (int)arg4, (uint64_t)arg1, (int)arg5);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 98 && (int)arg2 != 0/
{
    printf("[%d] SYS_futex ret=%d errno=%d\n", pid, (int)arg2, (int)arg3);
}

tick-1s { secs++; }
tick-1s /secs >= 12/ { exit(0); }
