/*
 * Focused shared-futex requeue tracing for Carrick.
 *
 * Captures the fork-shared ulock side-table state around FUTEX_REQUEUE /
 * FUTEX_CMP_REQUEUE without dumping the full syscall stream.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    printf("carrick futex requeue trace started at %Y\n", walltimestamp);
}

carrick*:::futex-route
/(pid == $target || progenyof($target)) && ((int)arg2 == 3 || (int)arg2 == 4)/
{
    @futex_route[(int)arg2, (int)arg3] = count();
    printf("[%d futex-route] addr=%#x op=%d shared=%d host=%#x\n",
        pid, arg1, (int)arg2, (int)arg3, arg4);
}

carrick*:::ulock-requeue
/pid == $target || progenyof($target)/
{
    this->r = (uint64_t *)copyin(arg0, 144);
    @requeue[(int)this->r[1], (uint32_t)this->r[4], (uint32_t)this->r[5], (uint32_t)this->r[6], (uint32_t)this->r[7]] = count();
    @from_counts[(int)this->r[1], (uint32_t)this->r[8], (uint32_t)this->r[9], (uint32_t)this->r[10], (uint32_t)this->r[11], (uint32_t)this->r[12]] = count();
    @to_counts[(int)this->r[1], (uint32_t)this->r[13], (uint32_t)this->r[14], (uint32_t)this->r[15], (uint32_t)this->r[16], (uint32_t)this->r[17]] = count();
    printf("[%d ulock-requeue] phase=%d from=%#x to=%#x req=(%d,%d) ret=(%d,%d) from(count=%d wake=%d requeue=%d logical_requeued=%d logical_wake=%d) to(count=%d wake=%d requeue=%d logical_requeued=%d logical_wake=%d)\n",
        pid,
        (int)this->r[1],
        this->r[2],
        this->r[3],
        (uint32_t)this->r[4],
        (uint32_t)this->r[5],
        (uint32_t)this->r[6],
        (uint32_t)this->r[7],
        (uint32_t)this->r[8],
        (uint32_t)this->r[9],
        (uint32_t)this->r[10],
        (uint32_t)this->r[11],
        (uint32_t)this->r[12],
        (uint32_t)this->r[13],
        (uint32_t)this->r[14],
        (uint32_t)this->r[15],
        (uint32_t)this->r[16],
        (uint32_t)this->r[17]);
}

tick-1s { secs++; }
tick-1s /secs >= 20/ { exit(0); }

END
{
    printf("\n==== futex routes ====\n");
    printa("  op=%d shared=%d %@d\n", @futex_route);
    printf("\n==== requeue calls ====\n");
    printa("  phase=%d req=(%d,%d) ret=(%d,%d) %@d\n", @requeue);
    printf("\n==== from side-table snapshots ====\n");
    printa("  phase=%d count=%d wake=%d requeue=%d logical_requeued=%d logical_wake=%d %@d\n", @from_counts);
    printf("\n==== to side-table snapshots ====\n");
    printa("  phase=%d count=%d wake=%d requeue=%d logical_requeued=%d logical_wake=%d %@d\n", @to_counts);
}
