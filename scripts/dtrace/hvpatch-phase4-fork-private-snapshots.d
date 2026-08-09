#!/usr/sbin/dtrace -qs
/*
 * Attribute hvpatch in-process fork's dominant private-snapshot stage to the
 * exact guest mapping role and host snapshot mechanism. The timing and outcome
 * halves join on (Linux child PID, guest virtual start), allowing the ledger to
 * distinguish page tables, mmap arena, heap, overlay, high aliases, writable
 * data, and read-only/internal mappings without relying on host addresses.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hvpatch-fork-private-snapshot carries five scalar CTF values:
 * (int32_t child_pid, int32_t forking_tid, uint64_t guest_start,
 * uint64_t mapped_size, uint64_t elapsed_ns).
 * carrick*:::hvpatch-fork-private-snapshot-outcome carries:
 * (int32_t child_pid, int32_t forking_tid, uint64_t guest_start,
 * uint32_t role, uint32_t method).
 * PID/TID are Linux guest namespace identities. DTrace pid/tid printed below
 * remain Darwin host identities. Role is the append-only fork-footprint ABI:
 * 1=private mmap arena, 2=private heap, 3=private overlay,
 * 4=private high alias, 5=private writable other,
 * 6=private read-only/internal, 7=shared aperture, 8=shared other,
 * 9=private page tables. This private-only path must never emit roles 7 or 8.
 * Method is 0=Mach COW remap or 1=sparse-copy fallback.
 * carrick*:::hvpatch-fork-process-spec-stage phase 11 supplies the independent
 * successful-fork population.
 *
 * The split is deliberate: this host has returned zero for a sixth macOS USDT
 * argument. Keeping both probes at five scalars preserves rich guest identity
 * and mapping shape while providing typed CTF to D consumers.
 *
 * Perturbation: two low-frequency scalar USDT firings per private mapping plus
 * one already-existing process-spec total event per successful guest fork. No
 * syscall, VM-exit, page, or instruction hot path is instrumented. The script
 * fails closed on zero events/forks, invalid roles or methods, duplicate keys,
 * missing or mismatched halves, DTrace errors, or the 90-second bound.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    timing_events = 0;
    outcome_events = 0;
    joined = 0;
    outstanding = 0;
    forks = 0;
    private_stage_count = 0;
    private_stage_ns = (uint64_t)0;
    process_spec_total_ns = (uint64_t)0;
    malformed = 0;
    errors = 0;
    bounded = 0;
    /* macOS D requires global associative arrays to be assigned before read. */
    seen[(int32_t)0, (uint64_t)0] = (int32_t)0;
    saved_tid[(int32_t)0, (uint64_t)0] = (int32_t)0;
    saved_size[(int32_t)0, (uint64_t)0] = (uint64_t)0;
    saved_elapsed[(int32_t)0, (uint64_t)0] = (uint64_t)0;
    outcome_seen[(int32_t)0, (uint64_t)0] = (int32_t)0;
    valid_outcome[(int32_t)0, (uint64_t)0] = (int32_t)0;
}

carrick*:::hvpatch-fork-private-snapshot
/pid == $target || progenyof($target)/
{
    this->child_pid = (int32_t)arg0;
    this->guest_start = (uint64_t)arg2;
    malformed += seen[this->child_pid, this->guest_start] != 0;
    seen[this->child_pid, this->guest_start] = 1;
    saved_tid[this->child_pid, this->guest_start] = (int32_t)arg1;
    saved_size[this->child_pid, this->guest_start] = (uint64_t)arg3;
    saved_elapsed[this->child_pid, this->guest_start] = (uint64_t)arg4;
    timing_events++;
    outstanding++;
}

carrick*:::hvpatch-fork-private-snapshot-outcome
/pid == $target || progenyof($target)/
{
    this->child_pid = (int32_t)arg0;
    this->forking_tid = (int32_t)arg1;
    this->guest_start = (uint64_t)arg2;
    this->role = (uint32_t)arg3;
    this->method = (uint32_t)arg4;
    this->present = seen[this->child_pid, this->guest_start];
    malformed += this->present == 0;
    malformed += outcome_seen[this->child_pid, this->guest_start] != 0;
    malformed += this->present != 0 &&
        saved_tid[this->child_pid, this->guest_start] != this->forking_tid;
    malformed += this->role < 1 || this->role > 9 ||
        this->role == 7 || this->role == 8;
    malformed += this->method > 1;
    valid_outcome[this->child_pid, this->guest_start] =
        this->present != 0 &&
        outcome_seen[this->child_pid, this->guest_start] == 0;
    outcome_seen[this->child_pid, this->guest_start] = 1;
    outcome_events++;
}

carrick*:::hvpatch-fork-private-snapshot-outcome
/(pid == $target || progenyof($target)) &&
 valid_outcome[(int32_t)arg0, (uint64_t)arg2] != 0/
{
    this->child_pid = (int32_t)arg0;
    this->forking_tid = (int32_t)arg1;
    this->guest_start = (uint64_t)arg2;
    this->role = (uint32_t)arg3;
    this->method = (uint32_t)arg4;
    this->mapped_size = saved_size[this->child_pid, this->guest_start];
    this->elapsed_ns = saved_elapsed[this->child_pid, this->guest_start];
    joined++;
    outstanding--;
    @count[this->role, this->method] = count();
    @bytes[this->role, this->method] = sum(this->mapped_size);
    @elapsed_ns[this->role, this->method] = sum(this->elapsed_ns);
    @max_ns[this->role, this->method] = max(this->elapsed_ns);
    printf("HVPATCH4PSNAP|event|ns=%llu|host_pid=%d|host_tid=%d|child_pid=%d|forking_tid=%d|guest_start=0x%llx|mapped_size=%llu|elapsed_ns=%llu|role=%u|method=%u\n",
        timestamp, pid, tid, this->child_pid, this->forking_tid,
        this->guest_start, this->mapped_size, this->elapsed_ns,
        this->role, this->method);
    valid_outcome[this->child_pid, this->guest_start] = 0;
}

carrick*:::hvpatch-fork-process-spec-stage
/(pid == $target || progenyof($target)) && arg0 == 5/
{
    private_stage_count++;
    private_stage_ns += (uint64_t)arg3;
}

carrick*:::hvpatch-fork-process-spec-stage
/(pid == $target || progenyof($target)) && arg0 == 11/
{
    forks++;
    process_spec_total_ns += (uint64_t)arg3;
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    this->bad = errors != 0 || forks == 0 || timing_events == 0 ||
        timing_events != outcome_events || timing_events != joined ||
        outstanding != 0 || malformed != 0 || joined <= forks ||
        private_stage_count != forks;
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
    this->bad = errors != 0 || bounded != 0 || forks == 0 ||
        timing_events == 0 || timing_events != outcome_events ||
        timing_events != joined || outstanding != 0 || malformed != 0 ||
        joined <= forks || private_stage_count != forks;
    printf("HVPATCH4PSNAP|summary|status=%s|timing=%d|outcome=%d|joined=%d|outstanding=%d|forks=%d|private_stage_count=%d|private_stage_ns=%llu|process_spec_total_ns=%llu|malformed=%d|bounded=%d|errors=%d\n",
        this->bad ? "error" : "ok", timing_events, outcome_events, joined,
        outstanding, forks, private_stage_count, private_stage_ns,
        process_spec_total_ns, malformed, bounded, errors);
    printa("HVPATCH4PSNAP|count|role=%u|method=%u|value=%@d\n", @count);
    printa("HVPATCH4PSNAP|bytes|role=%u|method=%u|value=%@d\n", @bytes);
    printa("HVPATCH4PSNAP|elapsed-ns|role=%u|method=%u|value=%@d\n", @elapsed_ns);
    printa("HVPATCH4PSNAP|max-ns|role=%u|method=%u|value=%@d\n", @max_ns);
}
