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

dtrace:::BEGIN
{
    ordinal = 0;
    resets = 0;
    private_ranges = 0;
    shared_ranges = 0;
    ready_records = 0;
}

carrick*:::host-translated-range-reset
/pid == $target || progenyof($target)/
{
    ordinal++;
    process_ordinal[pid]++;
    resets++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=reset|pid=%d|epoch=%d\n",
        ordinal, process_ordinal[pid], pid, arg0);
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

carrick*:::host-translated-range-ready
/pid == $target || progenyof($target)/
{
    ordinal++;
    process_ordinal[pid]++;
    ready_records++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=ready|pid=%d|epoch=%d|final_sequence=%d\n",
        ordinal, process_ordinal[pid], pid, arg0, arg1);
}

/*
 * Custom `carrick trace` scripts deliberately outlive their directly spawned
 * child so fork descendants can drain. Bound this narrow launch-time census:
 * the initial catalog must be complete long before five seconds.
 */
tick-5s
{
    exit(0);
}

dtrace:::END
{
    printf("TRANSLATED_RANGE_SUMMARY|reset=%d|private=%d|shared=%d|ready=%d|total=%d\n",
        resets, private_ranges, shared_ranges, ready_records, ordinal);
}
