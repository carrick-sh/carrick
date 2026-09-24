#!/usr/sbin/dtrace -qs
/*
 * el1-task-record-stale.d — does EL1 resolve fds through the wrong thread?
 *
 * WHAT IT MEASURES
 * ----------------
 * EL1 serves read/write/lseek/pread/pwrite on in-zone files by looking the
 * fd up in the fd map under the file table named by its vCPU slot's
 * current-task record. Every host syscall boundary compares that record with
 * the thread that actually trapped; `el1-task-record-stale` fires when they
 * differ. Each event is a window in which EL1 may have served the trapping
 * thread's fds out of ANOTHER thread's (another process's) file table.
 * Prints every cross-table event (slot, recorded tid/table, true tid/table)
 * and counts three classes: CROSS-TABLE (the record named another file table:
 * EL1 may have served this thread's fds with another process's files — the
 * go-build corruption of 2026-09-24), EMPTY (the record named no table: EL1
 * forwarded, costing one host boundary), and SAME-TABLE (a sibling thread of
 * the same process: same fds, harmless). A healthy run has cross_table=0.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified from carrick-observability/probes.rs on Darwin/arm64,
 * 2026-09-24: el1-task-record-stale args are u64 (slot, recorded_tid,
 * recorded_table, tid, table).
 *
 * PERTURBATION
 * ------------
 * LOW. Fires only on a wrong record; one printf per event.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    same_table = 0;
    cross_table = 0;
    empty = 0;
    secs = 0;
}

carrick*:::el1-task-record-stale
/(pid == $target || progenyof($target)) && arg2 == 0/
{
    empty++;
}

carrick*:::el1-task-record-stale
/(pid == $target || progenyof($target)) && arg2 == arg4/
{
    same_table++;
}

carrick*:::el1-task-record-stale
/(pid == $target || progenyof($target)) && arg2 != 0 && arg2 != arg4/
{
    cross_table++;
    printf("stale slot=%d recorded tid=%d table=%d trapped tid=%d table=%d\n",
        arg0, arg1, arg2, arg3, arg4);
}

tick-1s { secs++; }
tick-1s /secs >= 90/ { exit(0); }

proc:::exit
/pid == $target/
{
    exit(0);
}

dtrace:::END
{
    printf("el1-task-record-stale: cross_table=%d empty=%d same_table=%d\n",
        cross_table, empty, same_table);
}
