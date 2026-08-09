#!/usr/sbin/dtrace -qs
/*
 * Attribute host backing materialization and reuse during hvpatch exec.
 *
 * Provider ABI declared by carrick-observability for Darwin/arm64:
 * carrick*:::hvpatch-exec-backing carries five scalar CTF arguments:
 *   uint32_t phase       (0=materialized, 1=reused,
 *                         2=private-file-mapped; append-only)
 *   uint64_t guest_start (Linux guest VA)
 *   uint64_t ipa_start   (process-bank IPA; identifies the address space)
 *   uint64_t mapped_size
 *   uint64_t elapsed_ns  (allocation plus initialization copy when materialized)
 * Re-qualify the installed DOF with `dtrace -lvn
 * 'carrick*:::hvpatch-exec-backing'` after changing this ABI.
 *
 * Perturbation: one scalar USDT fire for each mapping materialized by an
 * in-process exec (roughly 20 per exec). It does not trace syscalls or profile
 * ticks. Zero events is invalid evidence, not proof that copying vanished.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    events = 0;
    hits = 0;
    misses = 0;
    private_file_maps = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::hvpatch-exec-backing
/pid == $target || progenyof($target)/
{
    events++;
    hits += arg0 == 1;
    misses += arg0 == 0;
    private_file_maps += arg0 == 2;
    @events_by_phase[(uint32_t)arg0] = count();
    @bytes_by_phase[(uint32_t)arg0] = sum((uint64_t)arg3);
    @elapsed_by_phase[(uint32_t)arg0] = sum((uint64_t)arg4);
    @max_elapsed_by_phase[(uint32_t)arg0] = max((uint64_t)arg4);
    printf("HVPATCH4BACKING|event|host_pid=%d|host_tid=%d|phase=%u|guest_va=0x%llx|ipa=0x%llx|bytes=%llu|elapsed_ns=%llu\n",
        pid, tid, (uint32_t)arg0, (uint64_t)arg1, (uint64_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
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
    printf("HVPATCH4BACKING|summary|events=%d|hits=%d|misses=%d|private_file_maps=%d|bounded=%d|errors=%d\n",
        events, hits, misses, private_file_maps, bounded, errors);
    printa("HVPATCH4BACKING|phase=%u|events=%@d\n", @events_by_phase);
    printa("HVPATCH4BACKING|phase=%u|bytes=%@d\n", @bytes_by_phase);
    printa("HVPATCH4BACKING|phase=%u|elapsed_total_ns=%@d\n", @elapsed_by_phase);
    printa("HVPATCH4BACKING|phase=%u|max_elapsed_ns=%@d\n", @max_elapsed_by_phase);
}
