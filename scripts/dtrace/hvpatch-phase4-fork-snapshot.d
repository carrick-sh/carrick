#!/usr/sbin/dtrace -qs
/*
 * Measure the mapping shape and elapsed time of each hvpatch in-process fork
 * address-space snapshot. This answers whether the correctness union is slow
 * because it selects too many historical aliases, too many bytes, or consumes
 * most of a child's private stage-2 bank.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hvpatch-fork-snapshot-begin carries scalar CTF types
 * (int32_t child_pid, int32_t forking_tid). The end companion carries
 * (int32_t child_pid, uint64_t local_regions, uint64_t candidate_regions,
 * uint64_t added_regions, uint64_t added_bytes). The shape companion carries
 * (int32_t child_pid, uint64_t private_added_regions,
 * uint64_t shared_added_regions, uint64_t largest_added_bytes,
 * uint64_t bank_used_bytes). Every probe stays at five arguments or fewer
 * because this host has returned zero for a sixth macOS USDT argument.
 * PID and TID are Linux guest namespace identities, not Darwin host IDs.
 *
 * Perturbation: three low-frequency USDT probes per Linux guest fork. No
 * syscall, VM-exit, page, or instruction hot path is instrumented. DTrace's
 * monotonic `timestamp` brackets the complete snapshot path. A capture with
 * zero completed snapshots is not evidence that fork was cheap; it means the
 * probe did not fire or the workload never completed a snapshot.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    begins = 0;
    ends = 0;
    shapes = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::hvpatch-fork-snapshot-begin
/pid == $target || progenyof($target)/
{
    begins++;
    start_ns[(int)arg0] = timestamp;
    forking_tid[(int)arg0] = (int)arg1;
}

carrick*:::hvpatch-fork-snapshot-end
/(pid == $target || progenyof($target)) && start_ns[(int)arg0] != 0/
{
    ends++;
    this->child = (int)arg0;
    this->elapsed = timestamp - start_ns[this->child];
    printf("HVPATCH4SNAP|end|ns=%llu|host_pid=%d|child_pid=%d|forking_tid=%d|elapsed_ns=%llu|local_regions=%llu|candidate_regions=%llu|added_regions=%llu|added_bytes=%llu\n",
        timestamp, pid, this->child, forking_tid[this->child], this->elapsed,
        (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
    @elapsed_ns = quantize(this->elapsed);
    @added_regions = quantize(arg3);
    @added_bytes = quantize(arg4);
}

carrick*:::hvpatch-fork-snapshot-shape
/pid == $target || progenyof($target)/
{
    shapes++;
    printf("HVPATCH4SNAP|shape|ns=%llu|host_pid=%d|child_pid=%d|private_added=%llu|shared_added=%llu|largest_added_bytes=%llu|bank_used_bytes=%llu\n",
        timestamp, pid, (int)arg0, (uint64_t)arg1, (uint64_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
    @largest_added_bytes = quantize(arg3);
    @bank_used_bytes = quantize(arg4);
    start_ns[(int)arg0] = 0;
    forking_tid[(int)arg0] = 0;
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
    printf("HVPATCH4SNAP|summary|begins=%d|ends=%d|shapes=%d|bounded=%d|errors=%d\n",
        begins, ends, shapes, bounded, errors);
    printa("HVPATCH4SNAP|elapsed-ns%@d\n", @elapsed_ns);
    printa("HVPATCH4SNAP|added-regions%@d\n", @added_regions);
    printa("HVPATCH4SNAP|added-bytes%@d\n", @added_bytes);
    printa("HVPATCH4SNAP|largest-added-bytes%@d\n", @largest_added_bytes);
    printa("HVPATCH4SNAP|bank-used-bytes%@d\n", @bank_used_bytes);
}
