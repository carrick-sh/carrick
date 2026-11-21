#pragma D option quiet
/*
 * Launch through carrick trace with CARRICK_TRACE_GRANT_REFUSALS=1 and a
 * unique CARRICK_RUN_ID. Follow the traced process tree. See the probe
 * argument catalogue in docs/diagnostics-and-debugging.md.
 */
carrick*:::hvpatch-owner-grant-descriptor-refused
/pid == $target || progenyof($target)/
{
    printf("GRANT_REFUSED ns=%d pid=%d tid=%d txn=%d kind=%d va=0x%x len=%d refusal=%d residency_published=%d\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4, arg5);
}

carrick*:::frame-grant-residency-refused
/pid == $target || progenyof($target)/
{
    printf("RESIDENCY_REFUSED ns=%d pid=%d tid=%d mm=%d va=0x%x len=%d used=%d total=%d\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::frame-grant-residency-census
/pid == $target || progenyof($target)/
{
    printf("RESIDENCY_CENSUS ns=%d pid=%d tid=%d txn=%d live=%d dead_mm=%d stale_backing=%d unapplied=%d unknown=%d\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4, arg5);
}

carrick*:::descriptor-journal-reserve-failed
/pid == $target || progenyof($target)/
{
    printf("JOURNAL_RESERVE_FAILED ns=%d pid=%d tid=%d isa=%d kind=%d live_stores=%d table_grants=%d\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3);
}

carrick*:::descriptor-plan-refused
/pid == $target || progenyof($target)/
{
    printf("PLAN_REFUSED ns=%d pid=%d tid=%d isa=%d site=%d kind=%d live_stores=%d table_grants=%d refusal=%d\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4, arg5);
}

tick-1s { seconds++; }
tick-1s /seconds >= 30/ { exit(4); }
