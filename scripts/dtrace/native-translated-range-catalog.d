/*
 * Native translated-code ownership catalog wire trace.
 *
 * This is the narrow live check for the process-wide reset/add/ready USDT
 * family. It intentionally prints DTrace's built-in pid rather than accepting
 * a redundant payload pid; Darwin exposes at most five reliable scalar
 * arguments at these probe sites.
 *
 * Run:
 *   CARRICK_RUN_ID=<exact-id> timeout 15s target/release/carrick trace \
 *     --script scripts/dtrace/native-translated-range-catalog.d \
 *     --trace-out /tmp/native-translated-range-catalog.log -- \
 *     run --exec-backend native --pull never ubuntu:24.04 /bin/true
 */
#pragma D option quiet
#pragma D option bufsize=4m
#pragma D option dynvarsize=8m

dtrace:::BEGIN
{
    ordinal = 0;
    resets = 0;
    private_ranges = 0;
    shared_ranges = 0;
    ready_records = 0;
    shared_announced = 0;
    unit_loaded = 0;
    shared_run_begin = 0;
    invalid_announcement = 0;
    missing_announcement = 0;
    duplicate_announcement = 0;
    commit_order_violations = 0;
    run_order_violations = 0;
    run_range_violations = 0;
    pending_collisions = 0;
    pending_loaded_units = 0;
    exited_pending = 0;
    reset_with_pending = 0;
    dtrace_drops = 0;
    dtrace_errors = 0;
    root_exit_seen = 0;
    root_exit_status = -1;
    tick_expired = 0;

    /*
     * Seed every dynamic-array shape before reading it. The sentinels are
     * inert: translated unit IDs are nonzero, and no real join uses TID zero.
     */
    tracked[$target] = 1;
    process_ordinal[$target] = 0;
    catalog_epoch[$target] = 0;
    catalog_live[$target] = 0;
    ann_epoch[$target, 0] = 0;
    ann_start[$target, 0] = 0;
    ann_end[$target, 0] = 0;
    ann_ordinal[$target, 0] = 0;
    pending_present[$target, 0] = 0;
    pending_epoch[$target, 0] = 0;
    pending_unit[$target, 0] = 0;
    pending_start[$target, 0] = 0;
    pending_end[$target, 0] = 0;
    pending_commit_ordinal[$target, 0] = 0;
    pending_by_pid[$target] = 0;
}

proc:::create
/tracked[pid]/
{
    tracked[args[0]->pr_pid] = 1;
    process_ordinal[args[0]->pr_pid] = 0;
    catalog_epoch[args[0]->pr_pid] = 0;
    catalog_live[args[0]->pr_pid] = 0;
    pending_by_pid[args[0]->pr_pid] = 0;
}

proc:::exit
/pid == $target/
{
    root_exit_seen = 1;
    root_exit_status = arg1;
}

proc:::exit
/tracked[pid]/
{
    exited_pending += pending_by_pid[pid];
    tracked[pid] = 0;
    process_ordinal[pid] = 0;
    catalog_epoch[pid] = 0;
    catalog_live[pid] = 0;
    pending_by_pid[pid] = 0;
}

carrick*:::host-translated-range-reset
/pid == $target || progenyof($target)/
{
    ordinal++;
    process_ordinal[pid]++;
    resets++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=reset|pid=%d|epoch=%d\n",
        ordinal, process_ordinal[pid], pid, arg0);
    reset_with_pending += pending_by_pid[pid] != 0 ? 1 : 0;
    catalog_epoch[pid] = arg0;
    catalog_live[pid] = 1;
}

carrick*:::host-translated-private-range
/pid == $target || progenyof($target)/
{
    ordinal++;
    process_ordinal[pid]++;
    private_ranges++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=private|pid=%d|epoch=%d|sequence=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, arg0, arg1, arg2, arg3);
}

carrick*:::host-translated-shared-range
/pid == $target || progenyof($target)/
{
    ordinal++;
    process_ordinal[pid]++;
    shared_ranges++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared|pid=%d|epoch=%d|sequence=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && arg2 == 0/
{
    ordinal++;
    process_ordinal[pid]++;
    invalid_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-invalid-announcement|reason=zero-unit-id|pid=%d|epoch=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, arg0, arg2, arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && arg2 != 0 && arg3 >= arg4/
{
    ordinal++;
    process_ordinal[pid]++;
    invalid_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-invalid-announcement|reason=invalid-bounds|pid=%d|epoch=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, arg0, arg2, arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && arg2 != 0 && arg3 < arg4 &&
    catalog_live[pid] != 1/
{
    ordinal++;
    process_ordinal[pid]++;
    invalid_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-invalid-announcement|reason=catalog-not-live|pid=%d|epoch=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, arg0, arg2, arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && arg2 != 0 && arg3 < arg4 &&
    catalog_live[pid] == 1 && catalog_epoch[pid] != arg0/
{
    ordinal++;
    process_ordinal[pid]++;
    invalid_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-invalid-announcement|reason=catalog-epoch-mismatch|pid=%d|epoch=%d|catalog_epoch=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, arg0, catalog_epoch[pid], arg2,
        arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && arg2 != 0 && arg3 < arg4 &&
    catalog_live[pid] == 1 && catalog_epoch[pid] == arg0 &&
    ann_ordinal[pid, arg2] != 0 && ann_epoch[pid, arg2] == arg0/
{
    ordinal++;
    process_ordinal[pid]++;
    duplicate_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-duplicate-announcement|pid=%d|epoch=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, arg0, arg2, arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && arg2 != 0 && arg3 < arg4 &&
    catalog_live[pid] == 1 && catalog_epoch[pid] == arg0 &&
    (ann_ordinal[pid, arg2] == 0 || ann_epoch[pid, arg2] != arg0)/
{
    ann_epoch[pid, arg2] = arg0;
    ann_start[pid, arg2] = arg3;
    ann_end[pid, arg2] = arg4;
    ann_ordinal[pid, arg2] = ordinal;
    shared_announced++;
}

carrick*:::host-translated-range-ready
/pid == $target || progenyof($target)/
{
    ordinal++;
    process_ordinal[pid]++;
    ready_records++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=ready|pid=%d|epoch=%d|final_sequence=%d\n",
        ordinal, process_ordinal[pid], pid, arg0, arg1);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 12 &&
    (catalog_live[pid] != 1 ||
    ann_epoch[pid, arg2] != catalog_epoch[pid] ||
    ann_start[pid, arg2] >= ann_end[pid, arg2] ||
    ann_ordinal[pid, arg2] == 0)/
{
    ordinal++;
    process_ordinal[pid]++;
    missing_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=unit-loaded-missing-announcement|pid=%d|tid=%d|unit_id=%d\n",
        ordinal, process_ordinal[pid], pid, arg0, arg2);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 12 &&
    catalog_live[pid] == 1 &&
    ann_epoch[pid, arg2] == catalog_epoch[pid] &&
    ann_start[pid, arg2] < ann_end[pid, arg2] &&
    ann_ordinal[pid, arg2] != 0 &&
    ann_ordinal[pid, arg2] >= ordinal + 1/
{
    ordinal++;
    process_ordinal[pid]++;
    commit_order_violations++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=unit-loaded-order-violation|pid=%d|tid=%d|unit_id=%d|announcement_ordinal=%d|commit_ordinal=%d\n",
        ordinal, process_ordinal[pid], pid, arg0, arg2,
        ann_ordinal[pid, arg2], ordinal);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 12 &&
    catalog_live[pid] == 1 &&
    ann_epoch[pid, arg2] == catalog_epoch[pid] &&
    ann_start[pid, arg2] < ann_end[pid, arg2] &&
    ann_ordinal[pid, arg2] != 0 &&
    ann_ordinal[pid, arg2] < ordinal + 1 &&
    pending_present[pid, arg0] != 0/
{
    ordinal++;
    process_ordinal[pid]++;
    unit_loaded++;
    pending_collisions++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=unit-loaded-pending-collision|pid=%d|tid=%d|unit_id=%d|pending_unit_id=%d\n",
        ordinal, process_ordinal[pid], pid, arg0, arg2,
        pending_unit[pid, arg0]);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 12 &&
    catalog_live[pid] == 1 &&
    ann_epoch[pid, arg2] == catalog_epoch[pid] &&
    ann_start[pid, arg2] < ann_end[pid, arg2] &&
    ann_ordinal[pid, arg2] != 0 &&
    ann_ordinal[pid, arg2] < ordinal + 1 &&
    pending_present[pid, arg0] == 0/
{
    ordinal++;
    process_ordinal[pid]++;
    unit_loaded++;
    pending_loaded_units++;
    pending_by_pid[pid]++;
    pending_present[pid, arg0] = 1;
    pending_epoch[pid, arg0] = catalog_epoch[pid];
    pending_unit[pid, arg0] = arg2;
    pending_start[pid, arg0] = ann_start[pid, arg2];
    pending_end[pid, arg0] = ann_end[pid, arg2];
    pending_commit_ordinal[pid, arg0] = ordinal;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=unit-loaded|pid=%d|tid=%d|unit_id=%d|start=%#x|end=%#x|announcement_ordinal=%d|commit_ordinal=%d|records=%d|data_bytes=%d\n",
        ordinal, process_ordinal[pid], pid, arg0, arg2,
        ann_start[pid, arg2], ann_end[pid, arg2],
        ann_ordinal[pid, arg2], ordinal, arg3, arg4);
}

carrick*:::dsr-run-begin
/(pid == $target || progenyof($target)) &&
    pending_present[pid, arg0] != 0 &&
    (pending_epoch[pid, arg0] != catalog_epoch[pid] ||
    pending_commit_ordinal[pid, arg0] >= ordinal + 1)/
{
    ordinal++;
    process_ordinal[pid]++;
    run_order_violations++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-run-order-violation|pid=%d|tid=%d|unit_id=%d|commit_ordinal=%d|run_ordinal=%d\n",
        ordinal, process_ordinal[pid], pid, arg0,
        pending_unit[pid, arg0], pending_commit_ordinal[pid, arg0], ordinal);
}

carrick*:::dsr-run-begin
/(pid == $target || progenyof($target)) &&
    pending_present[pid, arg0] != 0 &&
    pending_epoch[pid, arg0] == catalog_epoch[pid] &&
    pending_commit_ordinal[pid, arg0] < ordinal + 1 &&
    (arg2 < pending_start[pid, arg0] || arg2 >= pending_end[pid, arg0])/
{
    ordinal++;
    process_ordinal[pid]++;
    run_range_violations++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-run-range-violation|pid=%d|tid=%d|unit_id=%d|start=%#x|end=%#x|cache_pc=%#x|commit_ordinal=%d|run_ordinal=%d\n",
        ordinal, process_ordinal[pid], pid, arg0,
        pending_unit[pid, arg0], pending_start[pid, arg0],
        pending_end[pid, arg0], arg2, pending_commit_ordinal[pid, arg0],
        ordinal);
}

carrick*:::dsr-run-begin
/(pid == $target || progenyof($target)) &&
    pending_present[pid, arg0] != 0 &&
    pending_epoch[pid, arg0] == catalog_epoch[pid] &&
    pending_commit_ordinal[pid, arg0] < ordinal + 1 &&
    pending_start[pid, arg0] <= arg2 && arg2 < pending_end[pid, arg0]/
{
    ordinal++;
    process_ordinal[pid]++;
    shared_run_begin++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-run-begin|pid=%d|tid=%d|unit_id=%d|start=%#x|end=%#x|announcement_ordinal=%d|commit_ordinal=%d|run_ordinal=%d|guest_pc=%#x|cache_pc=%#x|generation=%d\n",
        ordinal, process_ordinal[pid], pid, arg0,
        pending_unit[pid, arg0], pending_start[pid, arg0],
        pending_end[pid, arg0],
        ann_ordinal[pid, pending_unit[pid, arg0]],
        pending_commit_ordinal[pid, arg0], ordinal, arg1, arg2, arg3);
    pending_present[pid, arg0] = 0;
    pending_epoch[pid, arg0] = 0;
    pending_unit[pid, arg0] = 0;
    pending_start[pid, arg0] = 0;
    pending_end[pid, arg0] = 0;
    pending_commit_ordinal[pid, arg0] = 0;
    pending_by_pid[pid]--;
    pending_loaded_units--;
}

dtrace:::DROP
{
    dtrace_drops++;
}

dtrace:::ERROR
{
    dtrace_errors++;
}

/*
 * Custom `carrick trace` scripts deliberately outlive their directly spawned
 * child so fork descendants can drain. Bound this narrow launch-time census:
 * the initial catalog must be complete long before five seconds.
 */
tick-5s
{
    tick_expired = 1;
    exit(0);
}

dtrace:::END
{
    complete = tick_expired == 1 && root_exit_seen == 1;
    commit_ok = complete == 1 &&
        root_exit_status == 0 &&
        shared_announced >= 1 && unit_loaded >= 1 &&
        invalid_announcement == 0 &&
        missing_announcement == 0 &&
        duplicate_announcement == 0 &&
        commit_order_violations == 0 &&
        dtrace_drops == 0 && dtrace_errors == 0;
    run_ok = commit_ok == 1 &&
        shared_run_begin >= 1 &&
        run_order_violations == 0 &&
        run_range_violations == 0 &&
        pending_collisions == 0 &&
        pending_loaded_units == 0 &&
        exited_pending == 0 &&
        reset_with_pending == 0;
    printf("TRANSLATED_RANGE_SUMMARY|schema=2|complete=%d|tick_expired=%d|root_exit_seen=%d|root_exit_status=%d|reset=%d|private=%d|shared=%d|ready=%d|total=%d|shared_announced=%d|unit_loaded=%d|shared_run_begin=%d|invalid_announcement=%d|missing_announcement=%d|duplicate_announcement=%d|commit_order_violations=%d|run_order_violations=%d|run_range_violations=%d|pending_collisions=%d|pending_loaded_units=%d|exited_pending=%d|reset_with_pending=%d|dtrace_drops=%d|dtrace_errors=%d|commit_ok=%d|run_ok=%d\n",
        complete, tick_expired, root_exit_seen, root_exit_status,
        resets, private_ranges, shared_ranges, ready_records, ordinal,
        shared_announced, unit_loaded, shared_run_begin,
        invalid_announcement, missing_announcement,
        duplicate_announcement, commit_order_violations, run_order_violations,
        run_range_violations, pending_collisions, pending_loaded_units,
        exited_pending, reset_with_pending, dtrace_drops, dtrace_errors,
        commit_ok, run_ok);
}
