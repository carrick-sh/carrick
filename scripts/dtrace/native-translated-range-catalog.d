/*
 * Native translated-code ownership catalog wire trace.
 *
 * This is the narrow live check for the process-wide reset/add/ready USDT
 * family. It intentionally prints DTrace's built-in pid rather than accepting
 * a redundant payload pid; Darwin exposes at most five reliable scalar
 * arguments at these probe sites.
 *
 * Run:
 *   CARRICK_RUN_ID=<exact-id> timeout 120s target/release/carrick trace \
 *     --script scripts/dtrace/native-translated-range-catalog.d \
 *     --trace-out /tmp/native-translated-range-catalog.log -- \
 *     run --exec-backend native --pull never ubuntu:24.04 /bin/true
 */
#pragma D option quiet
#pragma D option bufsize=4m
#pragma D option dynvarsize=8m

dtrace:::BEGIN
{
    ordinal = (uint64_t)0;
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

    /* Schema-1 launch-owned fork/exec lifecycle state. */
    lifecycle_ordinal = (uint64_t)0;
    lifecycle_child_pid = 0;
    lifecycle_target_birth = 1;
    lifecycle_child_birth = 0;
    parent_catalog_ok = 0;
    child_preexec_catalog_ok = 0;
    child_postexec_catalog_ok = 0;
    parent_run = 0;
    child_preexec_run = 0;
    child_postexec_run = 0;
    fork_repair_begin = 0;
    fork_repair_end = 0;
    child_fork_post = 0;
    reexec_preflight = 0;
    reexec_begin = 0;
    exec_seen = 0;
    exec_success = 0;
    exec_failure = 0;
    reexec_end = 0;
    child_exit_seen = 0;
    child_exit_status = -1;
    wait4_success = 0;
    unexpected_events = 0;
    identity_violations = 0;
    catalog_violations = 0;
    metadata_violations = 0;
    lifecycle_run_violations = 0;
    catalog_pending = 0;
    repair_pending = 0;
    reexec_pending = 0;
    live_owners = 1;

    /*
     * DTrace infers dynamic value width from the first assignment. Seed every
     * identity, epoch, address, and ordinal as uint64_t before reading it. The
     * sentinels are inert: unit IDs are nonzero and no join uses TID zero.
     * Incarnation is retained across exit so a reused numeric PID can never
     * address tuples left by the process that previously owned that PID.
     */
    tracked[$target] = 1;
    pid_live[$target] = 1;
    incarnation[$target] = (uint64_t)1;
    image_generation[$target, incarnation[$target]] = (uint64_t)1;
    runtime_epoch[$target, incarnation[$target]] = (uint64_t)0;
    execution_armed[$target, incarnation[$target]] = 1;
    exec_inflight[$target, incarnation[$target]] = 0;
    lifecycle_stage[$target, incarnation[$target]] = 1;
    metadata_host_base[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0] = 0;
    metadata_host_catalog[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0] = 0;
    metadata_guest_base[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0] = 0;
    metadata_jit_range[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0] = 0;
    metadata_complete[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0] = 0;
    process_ordinal[$target] = (uint64_t)0;
    catalog_live[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0] = 0;
    ann_epoch[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0, (uint64_t)0] = (uint64_t)0;
    ann_start[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0, (uint64_t)0] = (uint64_t)0;
    ann_end[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0, (uint64_t)0] = (uint64_t)0;
    ann_ordinal[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0, (uint64_t)0] = (uint64_t)0;
    pending_present[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0, 0] = 0;
    pending_epoch[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0, 0] = (uint64_t)0;
    pending_unit[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0, 0] = (uint64_t)0;
    pending_start[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0, 0] = (uint64_t)0;
    pending_end[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0, 0] = (uint64_t)0;
    pending_commit_ordinal[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0, 0] = (uint64_t)0;
    pending_by_pid[$target, incarnation[$target], (uint64_t)1,
        (uint64_t)0] = 0;

    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=target-birth|pid=%d|incarnation=1|generation=1|epoch=0\n",
        lifecycle_ordinal, $target);
}

proc:::create
/tracked[pid]/
{
    /* A still-live numeric PID is never allowed to acquire another owner. */
    identity_violations += pid_live[args[0]->pr_pid] != 0 ? 1 : 0;
    birth_valid[args[0]->pr_pid,
        (uint64_t)(incarnation[args[0]->pr_pid] + 1)] =
        pid == $target &&
        lifecycle_stage[pid, incarnation[pid]] == 5 &&
        lifecycle_child_pid == 0 &&
        pid_live[args[0]->pr_pid] == 0 ? 1 : 0;
    unexpected_events += birth_valid[args[0]->pr_pid,
        (uint64_t)(incarnation[args[0]->pr_pid] + 1)] == 1 ? 0 : 1;

    /* Deliberately increment retained state before initializing this owner. */
    incarnation[args[0]->pr_pid] =
        (uint64_t)(incarnation[args[0]->pr_pid] + 1);
    tracked[args[0]->pr_pid] = 1;
    pid_live[args[0]->pr_pid] = 1;
    live_owners++;
    lifecycle_child_pid = lifecycle_child_pid == 0 ?
        args[0]->pr_pid : lifecycle_child_pid;
    image_generation[args[0]->pr_pid,
        incarnation[args[0]->pr_pid]] = (uint64_t)1;
    runtime_epoch[args[0]->pr_pid,
        incarnation[args[0]->pr_pid]] =
        (uint64_t)runtime_epoch[pid, incarnation[pid]];
    execution_armed[args[0]->pr_pid,
        incarnation[args[0]->pr_pid]] = 1;
    exec_inflight[args[0]->pr_pid,
        incarnation[args[0]->pr_pid]] = 0;
    lifecycle_stage[args[0]->pr_pid,
        incarnation[args[0]->pr_pid]] = 1;
    process_ordinal[args[0]->pr_pid] = (uint64_t)0;
    catalog_live[args[0]->pr_pid, incarnation[args[0]->pr_pid],
        (uint64_t)1,
        runtime_epoch[args[0]->pr_pid,
            incarnation[args[0]->pr_pid]]] = 0;
    pending_by_pid[args[0]->pr_pid, incarnation[args[0]->pr_pid],
        (uint64_t)1,
        runtime_epoch[args[0]->pr_pid,
            incarnation[args[0]->pr_pid]]] = 0;
}

proc:::create
/birth_valid[args[0]->pr_pid, incarnation[args[0]->pr_pid]] == 1/
{
    lifecycle_child_birth++;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-birth|pid=%d|incarnation=%d|generation=1|epoch=1|parent_pid=%d\n",
        lifecycle_ordinal, args[0]->pr_pid,
        incarnation[args[0]->pr_pid], pid);
}

/* guest-exit arg0 is the host pid and arg1 is the guest exit code. */
carrick*:::guest-exit
/pid == lifecycle_child_pid && tracked[pid] &&
    ((uint64_t)arg0 != (uint64_t)pid ||
    lifecycle_stage[pid, incarnation[pid]] != 21 ||
    (int)arg1 != 0 || child_exit_seen != 0)/
{
    child_exit_status = (int)arg1;
    unexpected_events++;
    identity_violations++;
}

carrick*:::guest-exit
/pid == lifecycle_child_pid && tracked[pid] &&
    (uint64_t)arg0 == (uint64_t)pid &&
    lifecycle_stage[pid, incarnation[pid]] == 21 &&
    (int)arg1 == 0 && child_exit_seen == 0/
{
    child_exit_seen++;
    child_exit_status = (int)arg1;
    lifecycle_stage[pid, incarnation[pid]] = 22;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-exit|pid=%d|incarnation=%d|generation=%d|epoch=%d|status=%d\n",
        lifecycle_ordinal, pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (int)arg1);
}

carrick*:::guest-exit
/pid == $target && tracked[pid] &&
    ((uint64_t)arg0 != (uint64_t)pid ||
    lifecycle_stage[pid, incarnation[pid]] != 6 ||
    (int)arg1 != 0 || root_exit_seen != 0)/
{
    root_exit_seen = 1;
    root_exit_status = (int)arg1;
    unexpected_events++;
    identity_violations++;
}

carrick*:::guest-exit
/pid == $target && tracked[pid] &&
    (uint64_t)arg0 == (uint64_t)pid &&
    lifecycle_stage[pid, incarnation[pid]] == 6 &&
    (int)arg1 == 0 && root_exit_seen == 0/
{
    root_exit_seen = 1;
    root_exit_status = (int)arg1;
    lifecycle_stage[pid, incarnation[pid]] = 7;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=root-exit|pid=%d|incarnation=%d|generation=%d|epoch=%d|status=%d\n",
        lifecycle_ordinal, pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (int)arg1);
}

/* proc exit has no portable guest exit-code argument; it only retires state. */
proc:::exit
/tracked[pid]/
{
    exited_pending += pending_by_pid[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]];
    tracked[pid] = 0;
    pid_live[pid] = 0;
    live_owners--;
    process_ordinal[pid] = (uint64_t)0;
    catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] = 0;
    pending_by_pid[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] = 0;
}

/* A self-reexec retains pid/incarnation but crosses one disarmed generation. */
proc:::exec
/pid == lifecycle_child_pid && tracked[pid] &&
    (lifecycle_stage[pid, incarnation[pid]] != 10 ||
    image_generation[pid, incarnation[pid]] != (uint64_t)1 ||
    execution_armed[pid, incarnation[pid]] != 1 ||
    exec_inflight[pid, incarnation[pid]] != 0 || exec_seen != 0)/
{
    unexpected_events++;
    identity_violations++;
}

proc:::exec
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 10 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
    execution_armed[pid, incarnation[pid]] == 1 &&
    exec_inflight[pid, incarnation[pid]] == 0 && exec_seen == 0/
{
    exec_seen++;
    lifecycle_stage[pid, incarnation[pid]] = 11;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=exec|pid=%d|incarnation=%d|generation=1|epoch=2\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

/* Ownership disarm applies to every retained owner, not only the reducer child. */
proc:::exec
/tracked[pid]/
{
    unexpected_events += execution_armed[pid, incarnation[pid]] != 1 ||
        exec_inflight[pid, incarnation[pid]] != 0 ? 1 : 0;
    identity_violations += execution_armed[pid, incarnation[pid]] != 1 ||
        exec_inflight[pid, incarnation[pid]] != 0 ? 1 : 0;
    exec_inflight[pid, incarnation[pid]] = 1;
    execution_armed[pid, incarnation[pid]] = 0;
}

/* Success advances every retained owner to a fresh disarmed-image key. */
proc:::exec-success
/tracked[pid]/
{
    unexpected_events += exec_inflight[pid, incarnation[pid]] != 1 ||
        execution_armed[pid, incarnation[pid]] != 0 ? 1 : 0;
    identity_violations += exec_inflight[pid, incarnation[pid]] != 1 ||
        execution_armed[pid, incarnation[pid]] != 0 ? 1 : 0;
    image_generation[pid, incarnation[pid]] =
        (uint64_t)(image_generation[pid, incarnation[pid]] + 1);
    runtime_epoch[pid, incarnation[pid]] = (uint64_t)0;
    execution_armed[pid, incarnation[pid]] = 1;
    exec_inflight[pid, incarnation[pid]] = 0;
    catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]], (uint64_t)0] = 0;
    pending_by_pid[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]], (uint64_t)0] = 0;
    metadata_host_base[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]], (uint64_t)0] = 0;
    metadata_host_catalog[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]], (uint64_t)0] = 0;
    metadata_guest_base[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]], (uint64_t)0] = 0;
    metadata_jit_range[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]], (uint64_t)0] = 0;
    metadata_complete[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]], (uint64_t)0] = 0;
}

proc:::exec-success
/pid == lifecycle_child_pid && tracked[pid] &&
    (lifecycle_stage[pid, incarnation[pid]] != 11 ||
    image_generation[pid, incarnation[pid]] != (uint64_t)2 ||
    execution_armed[pid, incarnation[pid]] != 1 ||
    exec_inflight[pid, incarnation[pid]] != 0 ||
    exec_seen != 1 || exec_success != 0)/
{
    unexpected_events++;
    identity_violations++;
}

proc:::exec-success
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 11 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    execution_armed[pid, incarnation[pid]] == 1 &&
    exec_inflight[pid, incarnation[pid]] == 0 &&
    exec_seen == 1 && exec_success == 0/
{
    exec_success++;
    lifecycle_stage[pid, incarnation[pid]] = 12;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=exec-success|pid=%d|incarnation=%d|generation=2|epoch=0\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

proc:::exec-failure
/tracked[pid]/
{
    exec_failure++;
    unexpected_events++;
    identity_violations++;
    exec_inflight[pid, incarnation[pid]] = 0;
    execution_armed[pid, incarnation[pid]] = 1;
}

/* Selected typed lifecycle phases; phase 36 is deliberately not a frontier. */
carrick*:::dsr-cache-lifecycle
/pid == lifecycle_child_pid && arg1 == 1 &&
    lifecycle_stage[pid, incarnation[pid]] != 1/
{
    unexpected_events++;
    catalog_violations++;
}

carrick*:::dsr-cache-lifecycle
/pid == lifecycle_child_pid && arg1 == 1 &&
    lifecycle_stage[pid, incarnation[pid]] == 1/
{
    fork_repair_begin++;
    repair_pending++;
    lifecycle_stage[pid, incarnation[pid]] = 2;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=fork-repair-begin|pid=%d|incarnation=%d|generation=1|epoch=1\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::dsr-cache-lifecycle
/pid == lifecycle_child_pid && arg1 == 2 &&
    lifecycle_stage[pid, incarnation[pid]] != 5/
{
    unexpected_events++;
    catalog_violations++;
}

carrick*:::dsr-cache-lifecycle
/pid == lifecycle_child_pid && arg1 == 2 &&
    lifecycle_stage[pid, incarnation[pid]] == 5/
{
    fork_repair_end++;
    repair_pending--;
    lifecycle_stage[pid, incarnation[pid]] = 6;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=fork-repair-end|pid=%d|incarnation=%d|generation=1|epoch=2\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::dsr-cache-lifecycle
/pid == lifecycle_child_pid && arg1 == 37 &&
    lifecycle_stage[pid, incarnation[pid]] != 8/
{
    unexpected_events++;
    identity_violations++;
}

carrick*:::dsr-cache-lifecycle
/pid == lifecycle_child_pid && arg1 == 37 &&
    lifecycle_stage[pid, incarnation[pid]] == 8/
{
    reexec_preflight++;
    lifecycle_stage[pid, incarnation[pid]] = 9;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=reexec-preflight-begin|pid=%d|incarnation=%d|generation=1|epoch=2\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::dsr-cache-lifecycle
/pid == lifecycle_child_pid && arg1 == 25 &&
    lifecycle_stage[pid, incarnation[pid]] != 9/
{
    unexpected_events++;
    identity_violations++;
}

carrick*:::dsr-cache-lifecycle
/pid == lifecycle_child_pid && arg1 == 25 &&
    lifecycle_stage[pid, incarnation[pid]] == 9/
{
    reexec_begin++;
    reexec_pending++;
    lifecycle_stage[pid, incarnation[pid]] = 10;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=reexec-begin|pid=%d|incarnation=%d|generation=1|epoch=2\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::dsr-cache-lifecycle
/pid == lifecycle_child_pid && arg1 == 26 &&
    lifecycle_stage[pid, incarnation[pid]] != 12/
{
    unexpected_events++;
    identity_violations++;
}

carrick*:::dsr-cache-lifecycle
/pid == lifecycle_child_pid && arg1 == 26 &&
    lifecycle_stage[pid, incarnation[pid]] == 12/
{
    reexec_end++;
    reexec_pending--;
    lifecycle_stage[pid, incarnation[pid]] = 13;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=reexec-end|pid=%d|incarnation=%d|generation=2|epoch=0\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

/*
 * Preserve schema-2's reset-before-rekey pending check. The lifecycle clauses
 * below may advance runtime_epoch for their four-part identity key.
 */
carrick*:::host-translated-range-reset
/pid == $target || progenyof($target)/
{
    ordinal++;
    process_ordinal[pid]++;
    resets++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=reset|pid=%d|epoch=%d\n",
        ordinal, process_ordinal[pid], pid, arg0);
    reset_with_pending += pending_by_pid[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] != 0 ? 1 : 0;
    runtime_epoch[pid, incarnation[pid]] = (uint64_t)arg0;
    catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] = 1;
}

/* Exactly three private-only catalogs: parent, fork replay, post-exec fresh. */
carrick*:::host-translated-range-reset
/(pid == $target || pid == lifecycle_child_pid) && tracked[pid] &&
    !((pid == $target &&
        lifecycle_stage[pid, incarnation[pid]] == 1 &&
        image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
        (uint64_t)arg0 == (uint64_t)1) ||
    (pid == lifecycle_child_pid &&
        lifecycle_stage[pid, incarnation[pid]] == 2 &&
        image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
        (uint64_t)arg0 == (uint64_t)2) ||
    (pid == lifecycle_child_pid &&
        lifecycle_stage[pid, incarnation[pid]] == 13 &&
        image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
        (uint64_t)arg0 == (uint64_t)1))/
{
    unexpected_events++;
    catalog_violations++;
}

carrick*:::host-translated-range-reset
/pid == $target && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 1 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
    (uint64_t)arg0 == (uint64_t)1/
{
    runtime_epoch[pid, incarnation[pid]] = (uint64_t)1;
    catalog_live[pid, incarnation[pid], (uint64_t)1, (uint64_t)1] = 1;
    private_count[pid, incarnation[pid], (uint64_t)1, (uint64_t)1] = 0;
    ready_seen[pid, incarnation[pid], (uint64_t)1, (uint64_t)1] = 0;
    catalog_pending++;
    lifecycle_stage[pid, incarnation[pid]] = 2;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=parent-reset|pid=%d|incarnation=%d|generation=1|epoch=1\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::host-translated-range-reset
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 2 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
    (uint64_t)arg0 == (uint64_t)2/
{
    runtime_epoch[pid, incarnation[pid]] = (uint64_t)2;
    catalog_live[pid, incarnation[pid], (uint64_t)1, (uint64_t)2] = 1;
    private_count[pid, incarnation[pid], (uint64_t)1, (uint64_t)2] = 0;
    ready_seen[pid, incarnation[pid], (uint64_t)1, (uint64_t)2] = 0;
    catalog_pending++;
    lifecycle_stage[pid, incarnation[pid]] = 3;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-preexec-reset|pid=%d|incarnation=%d|generation=1|epoch=2\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::host-translated-range-reset
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 13 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    (uint64_t)arg0 == (uint64_t)1/
{
    runtime_epoch[pid, incarnation[pid]] = (uint64_t)1;
    catalog_live[pid, incarnation[pid], (uint64_t)2, (uint64_t)1] = 1;
    private_count[pid, incarnation[pid], (uint64_t)2, (uint64_t)1] = 0;
    ready_seen[pid, incarnation[pid], (uint64_t)2, (uint64_t)1] = 0;
    catalog_pending++;
    lifecycle_stage[pid, incarnation[pid]] = 14;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-postexec-reset|pid=%d|incarnation=%d|generation=2|epoch=1\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

/* The sharing-disabled lifecycle has exactly one private range per catalog. */
carrick*:::host-translated-private-range
/(pid == $target || pid == lifecycle_child_pid) && tracked[pid] &&
    !((pid == $target &&
        lifecycle_stage[pid, incarnation[pid]] == 2 &&
        (uint64_t)arg0 == (uint64_t)1 &&
        (uint64_t)arg1 == (uint64_t)1 &&
        (uint64_t)arg2 < (uint64_t)arg3) ||
    (pid == lifecycle_child_pid &&
        lifecycle_stage[pid, incarnation[pid]] == 3 &&
        image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
        (uint64_t)arg0 == (uint64_t)2 &&
        (uint64_t)arg1 == (uint64_t)1 &&
        (uint64_t)arg2 == parent_private_start &&
        (uint64_t)arg3 == parent_private_end) ||
    (pid == lifecycle_child_pid &&
        lifecycle_stage[pid, incarnation[pid]] == 14 &&
        image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
        (uint64_t)arg0 == (uint64_t)1 &&
        (uint64_t)arg1 == (uint64_t)1 &&
        (uint64_t)arg2 < (uint64_t)arg3))/
{
    unexpected_events++;
    catalog_violations++;
}

carrick*:::host-translated-private-range
/pid == $target && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 2 &&
    (uint64_t)arg0 == (uint64_t)1 &&
    (uint64_t)arg1 == (uint64_t)1 &&
    (uint64_t)arg2 < (uint64_t)arg3/
{
    private_count[pid, incarnation[pid], (uint64_t)1, (uint64_t)1] = 1;
    private_start[pid, incarnation[pid], (uint64_t)1, (uint64_t)1] =
        (uint64_t)arg2;
    private_end[pid, incarnation[pid], (uint64_t)1, (uint64_t)1] =
        (uint64_t)arg3;
    parent_private_start = (uint64_t)arg2;
    parent_private_end = (uint64_t)arg3;
    lifecycle_stage[pid, incarnation[pid]] = 3;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=parent-private|pid=%d|incarnation=%d|generation=1|epoch=1|sequence=1|start=%#x|end=%#x\n",
        lifecycle_ordinal, pid, incarnation[pid], arg2, arg3);
}

carrick*:::host-translated-private-range
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 3 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
    (uint64_t)arg0 == (uint64_t)2 &&
    (uint64_t)arg1 == (uint64_t)1 &&
    (uint64_t)arg2 == parent_private_start &&
    (uint64_t)arg3 == parent_private_end/
{
    private_count[pid, incarnation[pid], (uint64_t)1, (uint64_t)2] = 1;
    private_start[pid, incarnation[pid], (uint64_t)1, (uint64_t)2] =
        (uint64_t)arg2;
    private_end[pid, incarnation[pid], (uint64_t)1, (uint64_t)2] =
        (uint64_t)arg3;
    lifecycle_stage[pid, incarnation[pid]] = 4;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-preexec-private|pid=%d|incarnation=%d|generation=1|epoch=2|sequence=1|start=%#x|end=%#x\n",
        lifecycle_ordinal, pid, incarnation[pid], arg2, arg3);
}

carrick*:::host-translated-private-range
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 14 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    (uint64_t)arg0 == (uint64_t)1 &&
    (uint64_t)arg1 == (uint64_t)1 &&
    (uint64_t)arg2 < (uint64_t)arg3/
{
    private_count[pid, incarnation[pid], (uint64_t)2, (uint64_t)1] = 1;
    private_start[pid, incarnation[pid], (uint64_t)2, (uint64_t)1] =
        (uint64_t)arg2;
    private_end[pid, incarnation[pid], (uint64_t)2, (uint64_t)1] =
        (uint64_t)arg3;
    lifecycle_stage[pid, incarnation[pid]] = 15;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-postexec-private|pid=%d|incarnation=%d|generation=2|epoch=1|sequence=1|start=%#x|end=%#x\n",
        lifecycle_ordinal, pid, incarnation[pid], arg2, arg3);
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
/(pid == $target || pid == lifecycle_child_pid) && tracked[pid]/
{
    unexpected_events++;
    catalog_violations++;
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
/(pid == $target || progenyof($target)) && (uint64_t)arg2 == 0/
{
    ordinal++;
    process_ordinal[pid]++;
    invalid_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-invalid-announcement|reason=zero-unit-id|pid=%d|incarnation=%d|epoch=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0, arg2,
        arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && (uint64_t)arg2 != 0 &&
    (uint64_t)arg3 >= (uint64_t)arg4/
{
    ordinal++;
    process_ordinal[pid]++;
    invalid_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-invalid-announcement|reason=invalid-bounds|pid=%d|incarnation=%d|epoch=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0, arg2,
        arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && (uint64_t)arg2 != 0 &&
    (uint64_t)arg3 < (uint64_t)arg4 &&
    catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] != 1/
{
    ordinal++;
    process_ordinal[pid]++;
    invalid_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-invalid-announcement|reason=catalog-not-live|pid=%d|incarnation=%d|epoch=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0, arg2,
        arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && (uint64_t)arg2 != 0 &&
    (uint64_t)arg3 < (uint64_t)arg4 &&
    catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] == 1 &&
    runtime_epoch[pid, incarnation[pid]] != (uint64_t)arg0/
{
    ordinal++;
    process_ordinal[pid]++;
    invalid_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-invalid-announcement|reason=catalog-epoch-mismatch|pid=%d|incarnation=%d|epoch=%d|catalog_epoch=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0,
        runtime_epoch[pid, incarnation[pid]], arg2, arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && (uint64_t)arg2 != 0 &&
    (uint64_t)arg3 < (uint64_t)arg4 &&
    catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] == 1 &&
    runtime_epoch[pid, incarnation[pid]] == (uint64_t)arg0 &&
    ann_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] != 0 &&
    ann_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] ==
        (uint64_t)arg0/
{
    ordinal++;
    process_ordinal[pid]++;
    duplicate_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-duplicate-announcement|pid=%d|incarnation=%d|epoch=%d|unit_id=%d|start=%#x|end=%#x\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0, arg2,
        arg3, arg4);
}

carrick*:::host-translated-shared-range
/(pid == $target || progenyof($target)) && (uint64_t)arg2 != 0 &&
    (uint64_t)arg3 < (uint64_t)arg4 &&
    catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] == 1 &&
    runtime_epoch[pid, incarnation[pid]] == (uint64_t)arg0 &&
    (ann_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] == 0 ||
    ann_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] !=
        (uint64_t)arg0)/
{
    ann_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] =
        (uint64_t)arg0;
    ann_start[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] =
        (uint64_t)arg3;
    ann_end[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] =
        (uint64_t)arg4;
    ann_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] =
        (uint64_t)ordinal;
    shared_announced++;
}

/* Ready closes each catalog; no later announcement may change its frontier. */
carrick*:::host-translated-range-ready
/(pid == $target || pid == lifecycle_child_pid) && tracked[pid] &&
    !((pid == $target &&
        lifecycle_stage[pid, incarnation[pid]] == 3 &&
        (uint64_t)arg0 == (uint64_t)1 &&
        (uint64_t)arg1 == (uint64_t)1 &&
        private_count[pid, incarnation[pid], (uint64_t)1,
            (uint64_t)1] == 1) ||
    (pid == lifecycle_child_pid &&
        lifecycle_stage[pid, incarnation[pid]] == 4 &&
        image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
        (uint64_t)arg0 == (uint64_t)2 &&
        (uint64_t)arg1 == (uint64_t)1 &&
        private_count[pid, incarnation[pid], (uint64_t)1,
            (uint64_t)2] == 1) ||
    (pid == lifecycle_child_pid &&
        lifecycle_stage[pid, incarnation[pid]] == 15 &&
        image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
        (uint64_t)arg0 == (uint64_t)1 &&
        (uint64_t)arg1 == (uint64_t)1 &&
        private_count[pid, incarnation[pid], (uint64_t)2,
            (uint64_t)1] == 1))/
{
    unexpected_events++;
    catalog_violations++;
}

carrick*:::host-translated-range-ready
/pid == $target && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 3 &&
    (uint64_t)arg0 == (uint64_t)1 &&
    (uint64_t)arg1 == (uint64_t)1 &&
    private_count[pid, incarnation[pid], (uint64_t)1, (uint64_t)1] == 1/
{
    ready_seen[pid, incarnation[pid], (uint64_t)1, (uint64_t)1] = 1;
    parent_frontier = (uint64_t)arg1;
    parent_catalog_ok++;
    catalog_pending--;
    lifecycle_stage[pid, incarnation[pid]] = 4;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=parent-ready|pid=%d|incarnation=%d|generation=1|epoch=1|frontier=1\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::host-translated-range-ready
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 4 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
    (uint64_t)arg0 == (uint64_t)2 &&
    (uint64_t)arg1 == parent_frontier &&
    private_count[pid, incarnation[pid], (uint64_t)1, (uint64_t)2] == 1/
{
    ready_seen[pid, incarnation[pid], (uint64_t)1, (uint64_t)2] = 1;
    child_preexec_catalog_ok++;
    catalog_pending--;
    lifecycle_stage[pid, incarnation[pid]] = 5;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-preexec-ready|pid=%d|incarnation=%d|generation=1|epoch=2|frontier=1\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::host-translated-range-ready
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 15 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    (uint64_t)arg0 == (uint64_t)1 &&
    (uint64_t)arg1 == (uint64_t)1 &&
    private_count[pid, incarnation[pid], (uint64_t)2, (uint64_t)1] == 1/
{
    ready_seen[pid, incarnation[pid], (uint64_t)2, (uint64_t)1] = 1;
    child_postexec_catalog_ok++;
    catalog_pending--;
    lifecycle_stage[pid, incarnation[pid]] = 16;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-postexec-ready|pid=%d|incarnation=%d|generation=2|epoch=1|frontier=1\n",
        lifecycle_ordinal, pid, incarnation[pid]);
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

carrick*:::fork-post
/pid == lifecycle_child_pid && arg0 == 0 &&
    lifecycle_stage[pid, incarnation[pid]] != 6/
{
    unexpected_events++;
    identity_violations++;
}

carrick*:::fork-post
/pid == lifecycle_child_pid && arg0 == 0 &&
    lifecycle_stage[pid, incarnation[pid]] == 6/
{
    child_fork_post++;
    lifecycle_stage[pid, incarnation[pid]] = 7;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-fork-post|pid=%d|incarnation=%d|generation=1|epoch=2\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

/*
 * Initial-image metadata is outside this lifecycle proof. After proc exec,
 * however, the new image must publish one ordered metadata set under
 * generation two and epoch one before translated execution resumes.
 */
carrick*:::host-image-base
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] >= 10 &&
    !(lifecycle_stage[pid, incarnation[pid]] == 16 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    runtime_epoch[pid, incarnation[pid]] == (uint64_t)1 &&
    (uint64_t)arg0 == (uint64_t)pid &&
    metadata_host_base[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1] == 0)/
{
    unexpected_events++;
    metadata_violations++;
}

carrick*:::host-image-base
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 16 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    runtime_epoch[pid, incarnation[pid]] == (uint64_t)1 &&
    (uint64_t)arg0 == (uint64_t)pid &&
    metadata_host_base[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1] == 0/
{
    this->path = copyinstr(arg3);
    metadata_violations += strlen(this->path) == 0 ? 1 : 0;
    unexpected_events += strlen(this->path) == 0 ? 1 : 0;
    metadata_host_base[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1]++;
    lifecycle_stage[pid, incarnation[pid]] = 17;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=host-image-base|pid=%d|incarnation=%d|generation=2|epoch=1\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::host-image-catalog
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] >= 10 &&
    !(lifecycle_stage[pid, incarnation[pid]] == 17 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    runtime_epoch[pid, incarnation[pid]] == (uint64_t)1 &&
    metadata_host_catalog[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1] == 0)/
{
    unexpected_events++;
    metadata_violations++;
}

carrick*:::host-image-catalog
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 17 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    runtime_epoch[pid, incarnation[pid]] == (uint64_t)1 &&
    metadata_host_catalog[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1] == 0/
{
    /* arg0 is the JSON pointer; process identity is DTrace's built-in pid. */
    this->catalog = copyinstr(arg0);
    metadata_violations += strlen(this->catalog) == 0 ? 1 : 0;
    unexpected_events += strlen(this->catalog) == 0 ? 1 : 0;
    metadata_host_catalog[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1]++;
    lifecycle_stage[pid, incarnation[pid]] = 18;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=host-image-catalog|pid=%d|incarnation=%d|generation=2|epoch=1\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::guest-image-base
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] >= 10 &&
    !(lifecycle_stage[pid, incarnation[pid]] == 18 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    runtime_epoch[pid, incarnation[pid]] == (uint64_t)1 &&
    (uint64_t)arg0 == (uint64_t)pid &&
    metadata_guest_base[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1] == 0)/
{
    unexpected_events++;
    metadata_violations++;
}

carrick*:::guest-image-base
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 18 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    runtime_epoch[pid, incarnation[pid]] == (uint64_t)1 &&
    (uint64_t)arg0 == (uint64_t)pid &&
    metadata_guest_base[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1] == 0/
{
    this->path = copyinstr(arg3);
    metadata_violations += strlen(this->path) == 0 ? 1 : 0;
    unexpected_events += strlen(this->path) == 0 ? 1 : 0;
    metadata_guest_base[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1]++;
    lifecycle_stage[pid, incarnation[pid]] = 19;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=guest-image-base|pid=%d|incarnation=%d|generation=2|epoch=1\n",
        lifecycle_ordinal, pid, incarnation[pid]);
}

carrick*:::host-jit-range
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] >= 10 &&
    !(lifecycle_stage[pid, incarnation[pid]] == 19 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    runtime_epoch[pid, incarnation[pid]] == (uint64_t)1 &&
    (uint64_t)arg0 == (uint64_t)pid &&
    (uint64_t)arg1 == private_start[pid, incarnation[pid],
        (uint64_t)2, (uint64_t)1] &&
    (uint64_t)arg2 == private_end[pid, incarnation[pid],
        (uint64_t)2, (uint64_t)1] &&
    metadata_jit_range[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1] == 0)/
{
    unexpected_events++;
    metadata_violations++;
}

carrick*:::host-jit-range
/pid == lifecycle_child_pid && tracked[pid] &&
    lifecycle_stage[pid, incarnation[pid]] == 19 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    runtime_epoch[pid, incarnation[pid]] == (uint64_t)1 &&
    (uint64_t)arg0 == (uint64_t)pid &&
    (uint64_t)arg1 == private_start[pid, incarnation[pid],
        (uint64_t)2, (uint64_t)1] &&
    (uint64_t)arg2 == private_end[pid, incarnation[pid],
        (uint64_t)2, (uint64_t)1] &&
    metadata_jit_range[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1] == 0/
{
    metadata_jit_range[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1]++;
    metadata_complete[pid, incarnation[pid], (uint64_t)2,
        (uint64_t)1] =
        metadata_host_base[pid, incarnation[pid], (uint64_t)2,
            (uint64_t)1] == 1 &&
        metadata_host_catalog[pid, incarnation[pid], (uint64_t)2,
            (uint64_t)1] == 1 &&
        metadata_guest_base[pid, incarnation[pid], (uint64_t)2,
            (uint64_t)1] == 1 &&
        metadata_jit_range[pid, incarnation[pid], (uint64_t)2,
            (uint64_t)1] == 1 && metadata_violations == 0 ? 1 : 0;
    lifecycle_stage[pid, incarnation[pid]] = 20;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=host-jit-range|pid=%d|incarnation=%d|generation=2|epoch=1|start=%#x|end=%#x\n",
        lifecycle_ordinal, pid, incarnation[pid], arg1, arg2);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 12 &&
    (catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] != 1 ||
    ann_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] !=
        runtime_epoch[pid, incarnation[pid]] ||
    ann_start[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] >=
        ann_end[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] ||
    ann_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] == 0)/
{
    ordinal++;
    process_ordinal[pid]++;
    missing_announcement++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=unit-loaded-missing-announcement|pid=%d|incarnation=%d|tid=%d|unit_id=%d\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0, arg2);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 12 &&
    catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] == 1 &&
    ann_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] ==
        runtime_epoch[pid, incarnation[pid]] &&
    ann_start[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] <
        ann_end[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] &&
    ann_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] != 0 &&
    ann_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] >= ordinal + 1/
{
    ordinal++;
    process_ordinal[pid]++;
    commit_order_violations++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=unit-loaded-order-violation|pid=%d|incarnation=%d|tid=%d|unit_id=%d|announcement_ordinal=%d|commit_ordinal=%d\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0, arg2,
        ann_ordinal[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2], ordinal);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 12 &&
    catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] == 1 &&
    ann_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] ==
        runtime_epoch[pid, incarnation[pid]] &&
    ann_start[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] <
        ann_end[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] &&
    ann_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] != 0 &&
    ann_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] < ordinal + 1 &&
    pending_present[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] != 0/
{
    ordinal++;
    process_ordinal[pid]++;
    unit_loaded++;
    pending_collisions++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=unit-loaded-pending-collision|pid=%d|incarnation=%d|tid=%d|unit_id=%d|pending_unit_id=%d\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0, arg2,
        pending_unit[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0]);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 12 &&
    catalog_live[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] == 1 &&
    ann_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] ==
        runtime_epoch[pid, incarnation[pid]] &&
    ann_start[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] <
        ann_end[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] &&
    ann_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] != 0 &&
    ann_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2] < ordinal + 1 &&
    pending_present[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] == 0/
{
    ordinal++;
    process_ordinal[pid]++;
    unit_loaded++;
    pending_loaded_units++;
    pending_by_pid[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]]++;
    pending_present[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] = 1;
    pending_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] =
        (uint64_t)runtime_epoch[pid, incarnation[pid]];
    pending_unit[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] = (uint64_t)arg2;
    pending_start[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] =
        (uint64_t)ann_start[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2];
    pending_end[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] =
        (uint64_t)ann_end[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2];
    pending_commit_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] =
        (uint64_t)ordinal;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=unit-loaded|pid=%d|incarnation=%d|tid=%d|unit_id=%d|start=%#x|end=%#x|announcement_ordinal=%d|commit_ordinal=%d|records=%d|data_bytes=%d\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0, arg2,
        ann_start[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2],
        ann_end[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2],
        ann_ordinal[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], (uint64_t)arg2],
        ordinal, arg3, arg4);
}

/* First in-range execution is the resume frontier; phase 36 is not used. */
carrick*:::dsr-run-begin
/(pid == $target || pid == lifecycle_child_pid) && tracked[pid] &&
    execution_armed[pid, incarnation[pid]] == 0/
{
    lifecycle_run_violations++;
    unexpected_events++;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=disarmed-run|pid=%d|incarnation=%d|generation=%d|epoch=%d|cache_pc=%#x\n",
        lifecycle_ordinal, pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg2);
}

carrick*:::dsr-run-begin
/(pid == $target || pid == lifecycle_child_pid) && tracked[pid] &&
    execution_armed[pid, incarnation[pid]] == 1 &&
    !(ready_seen[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] == 1 &&
    private_start[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] <= (uint64_t)arg2 &&
    (uint64_t)arg2 < private_end[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]] &&
    ((pid == $target &&
        lifecycle_stage[pid, incarnation[pid]] >= 4 &&
        lifecycle_stage[pid, incarnation[pid]] <= 6) ||
    (pid == lifecycle_child_pid &&
        image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
        lifecycle_stage[pid, incarnation[pid]] >= 7 &&
        lifecycle_stage[pid, incarnation[pid]] <= 10) ||
    (pid == lifecycle_child_pid &&
        image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
        lifecycle_stage[pid, incarnation[pid]] >= 20 &&
        lifecycle_stage[pid, incarnation[pid]] <= 21)))/
{
    lifecycle_run_violations++;
    unexpected_events++;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=run-violation|pid=%d|incarnation=%d|generation=%d|epoch=%d|cache_pc=%#x\n",
        lifecycle_ordinal, pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg2);
}

carrick*:::dsr-run-begin
/pid == $target && tracked[pid] &&
    execution_armed[pid, incarnation[pid]] == 1 &&
    lifecycle_stage[pid, incarnation[pid]] == 4 &&
    ready_seen[pid, incarnation[pid], (uint64_t)1, (uint64_t)1] == 1 &&
    private_start[pid, incarnation[pid], (uint64_t)1, (uint64_t)1] <=
        (uint64_t)arg2 &&
    (uint64_t)arg2 <
        private_end[pid, incarnation[pid], (uint64_t)1, (uint64_t)1]/
{
    parent_run++;
    lifecycle_stage[pid, incarnation[pid]] = 5;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=parent-first-run|pid=%d|incarnation=%d|generation=1|epoch=1|cache_pc=%#x\n",
        lifecycle_ordinal, pid, incarnation[pid], arg2);
}

carrick*:::dsr-run-begin
/pid == lifecycle_child_pid && tracked[pid] &&
    execution_armed[pid, incarnation[pid]] == 1 &&
    lifecycle_stage[pid, incarnation[pid]] == 7 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)1 &&
    ready_seen[pid, incarnation[pid], (uint64_t)1, (uint64_t)2] == 1 &&
    private_start[pid, incarnation[pid], (uint64_t)1, (uint64_t)2] <=
        (uint64_t)arg2 &&
    (uint64_t)arg2 <
        private_end[pid, incarnation[pid], (uint64_t)1, (uint64_t)2]/
{
    child_preexec_run++;
    lifecycle_stage[pid, incarnation[pid]] = 8;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-preexec-first-run|pid=%d|incarnation=%d|generation=1|epoch=2|cache_pc=%#x\n",
        lifecycle_ordinal, pid, incarnation[pid], arg2);
}

carrick*:::dsr-run-begin
/pid == lifecycle_child_pid && tracked[pid] &&
    execution_armed[pid, incarnation[pid]] == 1 &&
    lifecycle_stage[pid, incarnation[pid]] == 20 &&
    image_generation[pid, incarnation[pid]] == (uint64_t)2 &&
    ready_seen[pid, incarnation[pid], (uint64_t)2, (uint64_t)1] == 1 &&
    private_start[pid, incarnation[pid], (uint64_t)2, (uint64_t)1] <=
        (uint64_t)arg2 &&
    (uint64_t)arg2 <
        private_end[pid, incarnation[pid], (uint64_t)2, (uint64_t)1]/
{
    child_postexec_run++;
    lifecycle_stage[pid, incarnation[pid]] = 21;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=child-postexec-first-run|pid=%d|incarnation=%d|generation=2|epoch=1|cache_pc=%#x\n",
        lifecycle_ordinal, pid, incarnation[pid], arg2);
}

carrick*:::dsr-run-begin
/(pid == $target || progenyof($target)) &&
    pending_present[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] != 0 &&
    (pending_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] !=
        runtime_epoch[pid, incarnation[pid]] ||
    pending_commit_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] >= ordinal + 1)/
{
    ordinal++;
    process_ordinal[pid]++;
    run_order_violations++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-run-order-violation|pid=%d|incarnation=%d|tid=%d|unit_id=%d|commit_ordinal=%d|run_ordinal=%d\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0,
        pending_unit[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0],
        pending_commit_ordinal[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0], ordinal);
}

carrick*:::dsr-run-begin
/(pid == $target || progenyof($target)) &&
    pending_present[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] != 0 &&
    pending_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] ==
        runtime_epoch[pid, incarnation[pid]] &&
    pending_commit_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] < ordinal + 1 &&
    ((uint64_t)arg2 < pending_start[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] ||
    (uint64_t)arg2 >= pending_end[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0])/
{
    ordinal++;
    process_ordinal[pid]++;
    run_range_violations++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-run-range-violation|pid=%d|incarnation=%d|tid=%d|unit_id=%d|start=%#x|end=%#x|cache_pc=%#x|commit_ordinal=%d|run_ordinal=%d\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0,
        pending_unit[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0],
        pending_start[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0],
        pending_end[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0], arg2,
        pending_commit_ordinal[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0], ordinal);
}

carrick*:::dsr-run-begin
/(pid == $target || progenyof($target)) &&
    pending_present[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] != 0 &&
    pending_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] ==
        runtime_epoch[pid, incarnation[pid]] &&
    pending_commit_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] < ordinal + 1 &&
    pending_start[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] <= (uint64_t)arg2 &&
    (uint64_t)arg2 < pending_end[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0]/
{
    ordinal++;
    process_ordinal[pid]++;
    shared_run_begin++;
    printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|kind=shared-run-begin|pid=%d|incarnation=%d|tid=%d|unit_id=%d|start=%#x|end=%#x|announcement_ordinal=%d|commit_ordinal=%d|run_ordinal=%d|guest_pc=%#x|cache_pc=%#x|generation=%d\n",
        ordinal, process_ordinal[pid], pid, incarnation[pid], arg0,
        pending_unit[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0],
        pending_start[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0],
        pending_end[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0],
        ann_ordinal[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]],
            pending_unit[pid, incarnation[pid],
                image_generation[pid, incarnation[pid]],
                runtime_epoch[pid, incarnation[pid]], arg0]],
        pending_commit_ordinal[pid, incarnation[pid],
            image_generation[pid, incarnation[pid]],
            runtime_epoch[pid, incarnation[pid]], arg0],
        ordinal, arg1, arg2, arg3);
    pending_present[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] = 0;
    pending_epoch[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] = (uint64_t)0;
    pending_unit[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] = (uint64_t)0;
    pending_start[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] = (uint64_t)0;
    pending_end[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] = (uint64_t)0;
    pending_commit_ordinal[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]], arg0] = (uint64_t)0;
    pending_by_pid[pid, incarnation[pid],
        image_generation[pid, incarnation[pid]],
        runtime_epoch[pid, incarnation[pid]]]--;
    pending_loaded_units--;
}

/* Linux aarch64 wait4 is syscall 260; zero is a parked/retry return. */
carrick*:::syscall-return
/pid == $target && tracked[pid] && (uint64_t)arg0 == (uint64_t)260 &&
    (int)arg2 != 0 &&
    !(lifecycle_stage[pid, incarnation[pid]] == 5 &&
    lifecycle_child_pid > 0 && child_exit_seen == 1 &&
    lifecycle_stage[lifecycle_child_pid,
        incarnation[lifecycle_child_pid]] == 22 &&
    (int)arg2 == lifecycle_child_pid && (int)arg3 == 0 &&
    wait4_success == 0)/
{
    unexpected_events++;
    identity_violations++;
}

carrick*:::syscall-return
/pid == $target && tracked[pid] && (uint64_t)arg0 == (uint64_t)260 &&
    (int)arg2 != 0 &&
    lifecycle_stage[pid, incarnation[pid]] == 5 &&
    lifecycle_child_pid > 0 && child_exit_seen == 1 &&
    lifecycle_stage[lifecycle_child_pid,
        incarnation[lifecycle_child_pid]] == 22 &&
    (int)arg2 == lifecycle_child_pid && (int)arg3 == 0 &&
    wait4_success == 0/
{
    wait4_success++;
    lifecycle_stage[pid, incarnation[pid]] = 6;
    lifecycle_ordinal++;
    printf("TRANSLATED_LIFECYCLE|schema=1|ordinal=%d|kind=parent-wait4|pid=%d|incarnation=%d|generation=1|epoch=1|child_pid=%d|retval=%d|errno=0\n",
        lifecycle_ordinal, pid, incarnation[pid], lifecycle_child_pid,
        (int)arg2);
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
 * the complete fork/exec lifecycle must settle within thirty seconds.
 */
tick-30s
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
    lifecycle_pending = catalog_pending + repair_pending + reexec_pending +
        pending_loaded_units + live_owners;
    metadata_ok = metadata_complete[lifecycle_child_pid,
        incarnation[lifecycle_child_pid], (uint64_t)2, (uint64_t)1];
    lifecycle_ok = complete == 1 && root_exit_status == 0 &&
        lifecycle_target_birth == 1 && lifecycle_child_birth == 1 &&
        parent_catalog_ok == 1 && child_preexec_catalog_ok == 1 &&
        child_postexec_catalog_ok == 1 &&
        parent_run == 1 && child_preexec_run == 1 &&
        child_postexec_run == 1 &&
        fork_repair_begin == 1 && fork_repair_end == 1 &&
        child_fork_post == 1 && reexec_preflight == 1 &&
        reexec_begin == 1 && exec_seen == 1 && exec_success == 1 &&
        exec_failure == 0 && reexec_end == 1 && metadata_ok == 1 &&
        metadata_host_base[lifecycle_child_pid,
            incarnation[lifecycle_child_pid], (uint64_t)2,
            (uint64_t)1] == 1 &&
        metadata_host_catalog[lifecycle_child_pid,
            incarnation[lifecycle_child_pid], (uint64_t)2,
            (uint64_t)1] == 1 &&
        metadata_guest_base[lifecycle_child_pid,
            incarnation[lifecycle_child_pid], (uint64_t)2,
            (uint64_t)1] == 1 &&
        metadata_jit_range[lifecycle_child_pid,
            incarnation[lifecycle_child_pid], (uint64_t)2,
            (uint64_t)1] == 1 &&
        child_exit_seen == 1 && child_exit_status == 0 &&
        wait4_success == 1 && unexpected_events == 0 &&
        identity_violations == 0 && catalog_violations == 0 &&
        metadata_violations == 0 && lifecycle_run_violations == 0 &&
        lifecycle_pending == 0 && shared_ranges == 0 && resets == 3 &&
        private_ranges == 3 && ready_records == 3 &&
        invalid_announcement == 0 && missing_announcement == 0 &&
        duplicate_announcement == 0 && commit_order_violations == 0 &&
        run_order_violations == 0 && run_range_violations == 0 &&
        pending_collisions == 0 && exited_pending == 0 &&
        reset_with_pending == 0 &&
        lifecycle_ordinal == (uint64_t)29 &&
        lifecycle_stage[$target, incarnation[$target]] == 7 &&
        lifecycle_stage[lifecycle_child_pid,
            incarnation[lifecycle_child_pid]] == 22 &&
        dtrace_drops == 0 && dtrace_errors == 0;
    printf("TRANSLATED_RANGE_SUMMARY|schema=2|complete=%d|tick_expired=%d|root_exit_seen=%d|root_exit_status=%d|reset=%d|private=%d|shared=%d|ready=%d|total=%d|shared_announced=%d|unit_loaded=%d|shared_run_begin=%d|invalid_announcement=%d|missing_announcement=%d|duplicate_announcement=%d|commit_order_violations=%d|run_order_violations=%d|run_range_violations=%d|pending_collisions=%d|pending_loaded_units=%d|exited_pending=%d|reset_with_pending=%d|dtrace_drops=%d|dtrace_errors=%d|commit_ok=%d|run_ok=%d\n",
        complete, tick_expired, root_exit_seen, root_exit_status,
        resets, private_ranges, shared_ranges, ready_records, ordinal,
        shared_announced, unit_loaded, shared_run_begin,
        invalid_announcement, missing_announcement,
        duplicate_announcement, commit_order_violations, run_order_violations,
        run_range_violations, pending_collisions, pending_loaded_units,
        exited_pending, reset_with_pending, dtrace_drops, dtrace_errors,
        commit_ok, run_ok);
    printf("TRANSLATED_LIFECYCLE_SUMMARY|schema=1|complete=%d|lifecycle_ok=%d|root_exit_status=%d|target_birth=%d|child_birth=%d|parent_catalog_ok=%d|child_preexec_catalog_ok=%d|child_postexec_catalog_ok=%d|parent_run=%d|child_preexec_run=%d|child_postexec_run=%d|fork_repair_begin=%d|fork_repair_end=%d|child_fork_post=%d|preflight=%d|reexec_begin=%d|exec=%d|exec_success=%d|exec_failure=%d|reexec_end=%d|metadata_ok=%d|child_exit=%d|child_exit_status=%d|wait4_success=%d|unexpected_events=%d|identity_violations=%d|catalog_violations=%d|metadata_violations=%d|run_violations=%d|pending=%d|dtrace_drops=%d|dtrace_errors=%d\n",
        complete, lifecycle_ok, root_exit_status, lifecycle_target_birth,
        lifecycle_child_birth, parent_catalog_ok, child_preexec_catalog_ok,
        child_postexec_catalog_ok, parent_run, child_preexec_run,
        child_postexec_run, fork_repair_begin, fork_repair_end,
        child_fork_post, reexec_preflight, reexec_begin, exec_seen,
        exec_success, exec_failure, reexec_end, metadata_ok,
        child_exit_seen, child_exit_status, wait4_success,
        unexpected_events, identity_violations, catalog_violations,
        metadata_violations, lifecycle_run_violations, lifecycle_pending,
        dtrace_drops, dtrace_errors);
}
