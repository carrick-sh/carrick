#!/usr/sbin/dtrace -qs
/*
 * Attribute hvpatch exec's stage-1 process-bank layout cache.
 *
 * Provider ABI declared by carrick-observability for Darwin/arm64:
 * carrick*:::hvpatch-exec-bank-layout carries five scalar CTF arguments:
 *   uint32_t phase       (0=miss, 1=hit; append-only ordinals)
 *   uint64_t bank_base   (join to hvpatch-guest-address-space for PID/ASID)
 *   uint64_t mappings
 *   uint64_t cache_entries
 *   uint64_t elapsed_ns  (lookup plus complete construction on a miss)
 * Re-qualify the installed DOF with `dtrace -lvn
 * 'carrick*:::hvpatch-exec-bank-layout'` after changing this ABI.
 *
 * Perturbation: one low-frequency scalar USDT fire per in-process exec bank
 * preparation. No syscall or profile probes are enabled. A zero-event capture
 * is invalid evidence: the workload did not reach the instrumented path, the
 * provider was absent, or this was not the hvpatch backend.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    events = 0;
    hits = 0;
    misses = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::hvpatch-exec-bank-layout
/pid == $target || progenyof($target)/
{
    events++;
    hits += arg0 == 1;
    misses += arg0 == 0;
    @events_by_phase[(uint32_t)arg0] = count();
    @elapsed_by_phase[(uint32_t)arg0] = sum((uint64_t)arg4);
    @max_elapsed_by_phase[(uint32_t)arg0] = max((uint64_t)arg4);
    @events_by_bank[(uint64_t)arg1, (uint32_t)arg0] = count();
    printf("HVPATCH4BANK|event|host_pid=%d|host_tid=%d|phase=%u|bank=0x%llx|mappings=%llu|entries=%llu|elapsed_ns=%llu\n",
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
    printf("HVPATCH4BANK|summary|events=%d|hits=%d|misses=%d|bounded=%d|errors=%d\n",
        events, hits, misses, bounded, errors);
    printa("HVPATCH4BANK|phase=%u|events=%@d\n", @events_by_phase);
    printa("HVPATCH4BANK|phase=%u|elapsed_total_ns=%@d\n", @elapsed_by_phase);
    printa("HVPATCH4BANK|phase=%u|max_elapsed_ns=%@d\n", @max_elapsed_by_phase);
    printa("HVPATCH4BANK|bank=0x%llx|phase=%u|events=%@d\n", @events_by_bank);
}
