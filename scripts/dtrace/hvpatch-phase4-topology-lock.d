#!/usr/sbin/dtrace -qs
/*
 * Attribute every shared-HVF topology-lock wait and hold to its Carrick
 * operation and Linux guest identity. This answers which holder class is
 * present when a one-VM exec begins waiting; it does not assume fork is the
 * holder merely because fork snapshots are long.
 *
 * Provider ABI declared by carrick-observability for Darwin/arm64:
 * carrick*:::hvpatch-topology-lock carries five scalar CTF arguments:
 *   uint32_t operation   (0=in-process fork, 1=exec replacement,
 *                         2=exec sibling gate, 3=sibling materialization,
 *                         4=vCPU rebind, 5=VM release, 6=legacy fork;
 *                         append-only)
 *   uint32_t phase       (0=requested, 1=acquired, 2=released, 3=try miss;
 *                         append-only)
 *   int32_t guest_pid    (0 when no process context is available)
 *   int32_t guest_tid
 *   uint64_t elapsed_ns  (wait on acquired, hold on released, attempt on miss)
 * DTrace's pid/tid fields retain the Darwin host identity separately. The
 * request event lets this script snapshot the active holder class before the
 * requester blocks; an acquired exec with >=50 us wait and no tracked holder
 * is reported as unattributed rather than assigned by guesswork.
 *
 * Perturbation: three low-frequency scalar USDT firings per successful lock
 * acquisition and two per try miss. This can perturb lock scheduling, so only
 * same-instrument holder/wait relationships are citable. Untraced timing
 * remains the performance gate. Zero events, bad ordinals, or unpaired
 * request/acquire/release records are invalid evidence.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    events = 0;
    requests = 0;
    acquires = 0;
    releases = 0;
    try_misses = 0;
    material_exec_waits = 0;
    unattributed_exec_waits = 0;
    pairing_errors = 0;
    operation_errors = 0;
    phase_errors = 0;
    errors = 0;
    bounded = 0;
    holder_live[-1] = 0;
    holder_operation[-1] = 0;
    holder_host_tid[-1] = 0;
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg0 > 6/
{
    operation_errors++;
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg1 > 3/
{
    phase_errors++;
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg0 <= 6 && arg1 == 0/
{
    events++;
    requests++;
    @phase_count[(uint32_t)arg1] = count();
    self->requested = 1;
    self->operation = (uint32_t)arg0;
    self->blocked_by = holder_live[pid] ? holder_operation[pid] + 1 : 0;
    printf("HVPATCH4TOPO|request|timestamp=%llu|host_pid=%d|host_tid=%d|operation=%u|guest_pid=%d|guest_tid=%d|holder_operation=%d\n",
        timestamp, pid, tid, (uint32_t)arg0, (int)arg2, (int)arg3,
        self->blocked_by ? self->blocked_by - 1 : -1);
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg0 <= 6 && arg1 == 1/
{
    events++;
    acquires++;
    @phase_count[(uint32_t)arg1] = count();
    this->pair_error = !self->requested || self->operation != (uint32_t)arg0;
    pairing_errors += this->pair_error;
    @pairing_error_count[(uint32_t)arg1] = sum(this->pair_error);
    @wait_count[(uint32_t)arg0] = count();
    @wait_total_ns[(uint32_t)arg0] = sum((uint64_t)arg4);
    @wait_max_ns[(uint32_t)arg0] = max((uint64_t)arg4);
    this->material_exec = arg0 == 1 && arg4 >= 50000;
    material_exec_waits += this->material_exec;
    unattributed_exec_waits += this->material_exec && self->blocked_by == 0;
    holder_live[pid] = 1;
    holder_operation[pid] = (uint32_t)arg0;
    holder_host_tid[pid] = tid;
    self->requested = 0;
    self->acquired = 1;
    printf("HVPATCH4TOPO|acquired|timestamp=%llu|host_pid=%d|host_tid=%d|operation=%u|guest_pid=%d|guest_tid=%d|wait_ns=%llu|holder_operation_at_request=%d|pair_error=%d\n",
        timestamp, pid, tid, (uint32_t)arg0, (int)arg2, (int)arg3,
        (uint64_t)arg4, self->blocked_by ? self->blocked_by - 1 : -1,
        this->pair_error);
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg0 == 1 && arg1 == 1 &&
 arg4 >= 50000 && self->blocked_by > 0/
{
    @exec_blocked_count[self->blocked_by - 1] = count();
    @exec_blocked_wait_ns[self->blocked_by - 1] = sum((uint64_t)arg4);
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg0 <= 6 && arg1 == 2/
{
    events++;
    releases++;
    @phase_count[(uint32_t)arg1] = count();
    this->pair_error = !self->acquired || !holder_live[pid] ||
        holder_operation[pid] != (uint32_t)arg0 || holder_host_tid[pid] != tid;
    pairing_errors += this->pair_error;
    @pairing_error_count[(uint32_t)arg1] = sum(this->pair_error);
    @hold_count[(uint32_t)arg0] = count();
    @hold_total_ns[(uint32_t)arg0] = sum((uint64_t)arg4);
    @hold_max_ns[(uint32_t)arg0] = max((uint64_t)arg4);
    printf("HVPATCH4TOPO|released|timestamp=%llu|host_pid=%d|host_tid=%d|operation=%u|guest_pid=%d|guest_tid=%d|hold_ns=%llu|pair_error=%d\n",
        timestamp, pid, tid, (uint32_t)arg0, (int)arg2, (int)arg3,
        (uint64_t)arg4, this->pair_error);
    holder_live[pid] = 0;
    holder_operation[pid] = 0;
    holder_host_tid[pid] = 0;
    self->acquired = 0;
    self->blocked_by = 0;
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg0 <= 6 && arg1 == 3/
{
    events++;
    try_misses++;
    @phase_count[(uint32_t)arg1] = count();
    this->pair_error = !self->requested || self->operation != (uint32_t)arg0;
    pairing_errors += this->pair_error;
    @pairing_error_count[(uint32_t)arg1] = sum(this->pair_error);
    @try_miss_count[(uint32_t)arg0] = count();
    printf("HVPATCH4TOPO|try-miss|timestamp=%llu|host_pid=%d|host_tid=%d|operation=%u|guest_pid=%d|guest_tid=%d|attempt_ns=%llu|holder_operation=%d|pair_error=%d\n",
        timestamp, pid, tid, (uint32_t)arg0, (int)arg2, (int)arg3,
        (uint64_t)arg4, self->blocked_by ? self->blocked_by - 1 : -1,
        this->pair_error);
    self->requested = 0;
    self->blocked_by = 0;
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
    printf("HVPATCH4TOPO|summary|material_exec_waits=%d|unattributed_exec_waits=%d|pairing_errors=%d|operation_errors=%d|phase_errors=%d|empty=%d|bounded=%d|errors=%d|coverage_source=phase-count\n",
        material_exec_waits, unattributed_exec_waits, pairing_errors,
        operation_errors, phase_errors, events == 0, bounded, errors);
    printa("HVPATCH4TOPO|phase-count|phase=%u|count=%@d\n", @phase_count);
    printa("HVPATCH4TOPO|pairing-error-count|phase=%u|count=%@d\n", @pairing_error_count);
    printa("HVPATCH4TOPO|wait-count|operation=%u|count=%@d\n", @wait_count);
    printa("HVPATCH4TOPO|wait-total-ns|operation=%u|ns=%@d\n", @wait_total_ns);
    printa("HVPATCH4TOPO|wait-max-ns|operation=%u|ns=%@d\n", @wait_max_ns);
    printa("HVPATCH4TOPO|hold-count|operation=%u|count=%@d\n", @hold_count);
    printa("HVPATCH4TOPO|hold-total-ns|operation=%u|ns=%@d\n", @hold_total_ns);
    printa("HVPATCH4TOPO|hold-max-ns|operation=%u|ns=%@d\n", @hold_max_ns);
    printa("HVPATCH4TOPO|try-miss-count|operation=%u|count=%@d\n", @try_miss_count);
    printa("HVPATCH4TOPO|exec-blocked-count|holder_operation=%u|count=%@d\n", @exec_blocked_count);
    printa("HVPATCH4TOPO|exec-blocked-wait-ns|holder_operation=%u|ns=%@d\n", @exec_blocked_wait_ns);
}
