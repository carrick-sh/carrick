#!/usr/sbin/dtrace -qs
/*
 * Close the parent-thread critical-path ledger for one-VM in-process fork.
 * This partitions the topology-lock hold outside the existing HVF snapshot
 * census without enabling every topology-lock event in the process.
 *
 * Provider ABI declared by carrick-observability for Darwin/arm64:
 * carrick*:::hvpatch-fork-runtime-stage carries five scalar CTF arguments:
 *   uint32_t phase       (0=quiesce, 1=process allocation,
 *                         2=pidfd/parent-TID publication, 3=process spec,
 *                         4=dispatcher clone, 5=runtime state,
 *                         6=thread spawn, 7=child ready, 8=publication,
 *                         9=cumulative total enclosing phases 0..8;
 *                         append-only)
 *   int32_t parent_pid
 *   int32_t child_pid    (zero during pre-allocation quiesce)
 *   int32_t forking_tid
 *   uint64_t elapsed_ns
 * The Linux identities are carried directly; DTrace's pid/tid retain the
 * Darwin host process and thread separately.
 * carrick*:::hvpatch-fork-quiesce carries parent PID, forking TID, initial
 * sibling count, 200-us poll iterations, and the same quiesce elapsed ns as
 * runtime phase 0.
 *
 * Perturbation: eleven low-frequency scalar USDT firings per successful fork.
 * Phase 9 includes probe overhead and must not be summed with phases 0..8.
 * Same-instrument ratios are citable; untraced timing remains the performance
 * gate. A valid cold-build capture has identical DTrace aggregation counts for
 * phases 0..9 and no invalid phase, empty, bounded, or DTrace errors.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    events = 0;
    phase_errors = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::hvpatch-fork-runtime-stage
/(pid == $target || progenyof($target)) && arg0 <= 9/
{
    events++;
    @stage_count[(uint32_t)arg0] = count();
    @stage_total_ns[(uint32_t)arg0] = sum((uint64_t)arg4);
    @stage_max_ns[(uint32_t)arg0] = max((uint64_t)arg4);
    printf("HVPATCH4FORKRUNTIME|stage|host_pid=%d|host_tid=%d|phase=%u|parent_pid=%d|child_pid=%d|forking_tid=%d|elapsed_ns=%llu\n",
        pid, tid, (uint32_t)arg0, (int)arg1, (int)arg2, (int)arg3,
        (uint64_t)arg4);
}

carrick*:::hvpatch-fork-runtime-stage
/(pid == $target || progenyof($target)) && arg0 > 9/
{
    phase_errors++;
}

carrick*:::hvpatch-fork-quiesce
/pid == $target || progenyof($target)/
{
    @quiesce_count_by_initial[(uint32_t)arg2] = count();
    @quiesce_polls_by_initial[(uint32_t)arg2] = sum((uint64_t)arg3);
    @quiesce_ns_by_initial[(uint32_t)arg2] = sum((uint64_t)arg4);
    @quiesce_poll_hist = quantize((uint64_t)arg3);
    printf("HVPATCH4FORKRUNTIME|quiesce|host_pid=%d|host_tid=%d|parent_pid=%d|forking_tid=%d|initial_siblings=%u|poll_iterations=%llu|elapsed_ns=%llu\n",
        pid, tid, (int)arg0, (int)arg1, (uint32_t)arg2, (uint64_t)arg3,
        (uint64_t)arg4);
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printf("HVPATCH4FORKRUNTIME|summary|phase_errors=%d|empty=%d|bounded=%d|errors=%d|coverage_source=stage-count\n",
        phase_errors, events == 0, bounded, errors);
    printa("HVPATCH4FORKRUNTIME|stage-count|phase=%u|count=%@d\n", @stage_count);
    printa("HVPATCH4FORKRUNTIME|stage-total-ns|phase=%u|ns=%@d\n", @stage_total_ns);
    printa("HVPATCH4FORKRUNTIME|stage-max-ns|phase=%u|ns=%@d\n", @stage_max_ns);
    printa("HVPATCH4FORKRUNTIME|quiesce-count|initial_siblings=%u|count=%@d\n", @quiesce_count_by_initial);
    printa("HVPATCH4FORKRUNTIME|quiesce-polls|initial_siblings=%u|polls=%@d\n", @quiesce_polls_by_initial);
    printa("HVPATCH4FORKRUNTIME|quiesce-ns|initial_siblings=%u|ns=%@d\n", @quiesce_ns_by_initial);
    printa("HVPATCH4FORKRUNTIME|quiesce-poll-hist|%@d\n", @quiesce_poll_hist);
}
