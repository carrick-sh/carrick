#!/usr/sbin/dtrace -qs
/*
 * Partition hvpatch in-process fork ProcessSpec construction into typed,
 * mutually exclusive stages. This answers whether time is spent copying the
 * 1.75-MiB page-table image, snapshotting private mappings, validating the
 * stage-1 plan, or duplicating wrapper/backend bookkeeping.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hvpatch-fork-process-spec-stage carries five scalar CTF values:
 * (uint32_t phase, int32_t child_pid, int32_t forking_tid,
 * uint64_t elapsed_ns, uint64_t units). PID/TID are Linux guest namespace
 * identities, not Darwin host IDs. Every probe stays at five arguments or
 * fewer because this host has returned zero for a sixth macOS USDT argument.
 * Phase ordinals are append-only: 0=parent table load, 1=vCPU snapshot,
 * 2=parent table clone, 3=rebase, 4=alias union, 5=private snapshot,
 * 6=validation, 7=table publish, 8=backend protections,
 * 9=backend finalization, 10=wrapper protections, 11=cumulative total.
 * Total encloses phases 0..10 and must not be summed with them.
 *
 * `units` is a boolean load flag for parent table load; bytes for table clone,
 * rebase, table publish, and backend finalization; packed bank span for private
 * snapshot; mapping count for alias union and validation; and zero elsewhere.
 *
 * Perturbation: twelve low-frequency USDT probes per Linux guest fork plus
 * timestamp reads around the measured stages. No syscall, VM-exit, page, or
 * instruction hot path is instrumented. A missing stage, a zero-event capture,
 * or a DTrace error exits nonzero instead of producing a plausible empty result.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    events = 0;
    errors = 0;
    bounded = 0;
    p0 = p1 = p2 = p3 = p4 = p5 = 0;
    p6 = p7 = p8 = p9 = p10 = p11 = 0;
}

carrick*:::hvpatch-fork-process-spec-stage
/pid == $target || progenyof($target)/
{
    events++;
    p0 += arg0 == 0;
    p1 += arg0 == 1;
    p2 += arg0 == 2;
    p3 += arg0 == 3;
    p4 += arg0 == 4;
    p5 += arg0 == 5;
    p6 += arg0 == 6;
    p7 += arg0 == 7;
    p8 += arg0 == 8;
    p9 += arg0 == 9;
    p10 += arg0 == 10;
    p11 += arg0 == 11;
    printf("HVPATCH4PSPEC|event|ns=%llu|host_pid=%d|phase=%u|child_pid=%d|forking_tid=%d|elapsed_ns=%llu|units=%llu\n",
        timestamp, pid, (uint32_t)arg0, (int32_t)arg1, (int32_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
    @count[arg0] = count();
    @elapsed_ns[arg0] = sum(arg3);
    @units[arg0] = sum(arg4);
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    this->bad = errors != 0 || p11 == 0 ||
        p0 != p11 || p1 != p11 || p2 != p11 || p3 != p11 ||
        p4 != p11 || p5 != p11 || p6 != p11 || p7 != p11 ||
        p8 != p11 || p9 != p11 || p10 != p11;
    exit(this->bad);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(1);
}

dtrace:::END
{
    this->bad = errors != 0 || bounded != 0 || p11 == 0 ||
        p0 != p11 || p1 != p11 || p2 != p11 || p3 != p11 ||
        p4 != p11 || p5 != p11 || p6 != p11 || p7 != p11 ||
        p8 != p11 || p9 != p11 || p10 != p11;
    printf("HVPATCH4PSPEC|summary|status=%s|events=%d|total=%d|bounded=%d|errors=%d|counts=%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
        this->bad ? "error" : "ok", events, p11, bounded, errors,
        p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11);
    printa("HVPATCH4PSPEC|count|phase=%u|value=%@d\n", @count);
    printa("HVPATCH4PSPEC|elapsed-ns|phase=%u|value=%@d\n", @elapsed_ns);
    printa("HVPATCH4PSPEC|units|phase=%u|value=%@d\n", @units);
}
