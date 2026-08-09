#!/usr/sbin/dtrace -qs
/*
 * Measure complete hvpatch in-process exec latency by Linux guest PID/TID/ASID.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hvpatch-guest-lifecycle carries scalar CTF types
 * (uint32_t phase, int32_t guest_pid, int32_t guest_ppid,
 * int32_t guest_tid, uint32_t asid). Phase 6=exec-begin is emitted before ELF
 * loading; phase 2=exec-success is emitted after patching, stage-1/stage-2
 * replacement, executable-byte verification (when armed), identity restamping,
 * and guest publication. The stable phase ordinals are append-only.
 *
 * Perturbation: two low-frequency USDT probes per successful Linux guest exec.
 * The low-frequency execve-loaded probe separates ELF load/plan time from the
 * engine replacement; execve-sysregs marks the end of HVF address-space/vCPU
 * replacement and separates identity-publication tail time. These probes fire
 * on the same host thread as the lifecycle pair. No generic syscall-entry probe
 * is enabled, avoiding ~68K unrelated cold-build probe firings. The optional
 * executable verifier is NOT required by this script and should remain off for
 * authoritative latency. A begin without an end identifies a failed or
 * interrupted exec; zero completed windows is an error, not zero exec cost.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    begins = 0;
    ends = 0;
    marker_errors = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 6/
{
    begins++;
    exec_start[(int)arg1] = timestamp;
    exec_tid[(int)arg1] = (int)arg3;
    exec_asid[(int)arg1] = (uint32_t)arg4;
    self->exec_pid = (int)arg1;
    self->exec_begin = timestamp;
    self->image_loaded = 0;
    self->sysregs_ready = 0;
}

carrick*:::execve-loaded
/(pid == $target || progenyof($target)) && self->exec_begin != 0/
{
    self->image_loaded = timestamp;
    @load_plan_ns = sum(timestamp - self->exec_begin);
    @load_plan_max_ns = max(timestamp - self->exec_begin);
}

carrick*:::execve-sysregs
/(pid == $target || progenyof($target)) && self->image_loaded != 0/
{
    self->sysregs_ready = timestamp;
    @replace_ns = sum(timestamp - self->image_loaded);
    @replace_max_ns = max(timestamp - self->image_loaded);
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2 &&
 exec_start[(int)arg1] != 0 && self->sysregs_ready != 0/
{
    ends++;
    this->guest_pid = (int)arg1;
    this->elapsed = timestamp - exec_start[this->guest_pid];
    printf("HVPATCH4EXEC|end|ns=%llu|host_pid=%d|guest_pid=%d|guest_tid=%d|asid=%u|elapsed_ns=%llu\n",
        timestamp, pid, this->guest_pid, exec_tid[this->guest_pid],
        exec_asid[this->guest_pid], this->elapsed);
    @elapsed_ns = quantize(this->elapsed);
    @elapsed_total = sum(this->elapsed);
    @elapsed_max = max(this->elapsed);
    @publication_tail_ns = sum(timestamp - self->sysregs_ready);
    @publication_tail_max_ns = max(timestamp - self->sysregs_ready);
    exec_start[this->guest_pid] = 0;
    exec_tid[this->guest_pid] = 0;
    exec_asid[this->guest_pid] = 0;
    self->exec_pid = 0;
    self->exec_begin = 0;
    self->image_loaded = 0;
    self->sysregs_ready = 0;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2 &&
 exec_start[(int)arg1] != 0 && self->sysregs_ready == 0/
{
    marker_errors++;
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
    printf("HVPATCH4EXEC|summary|begins=%d|ends=%d|marker_errors=%d|bounded=%d|errors=%d\n",
        begins, ends, marker_errors, bounded, errors);
    printa("HVPATCH4EXEC|elapsed-total-ns=%@d\n", @elapsed_total);
    printa("HVPATCH4EXEC|elapsed-max-ns=%@d\n", @elapsed_max);
    printa("HVPATCH4EXEC|load-plan-total-ns=%@d\n", @load_plan_ns);
    printa("HVPATCH4EXEC|load-plan-max-ns=%@d\n", @load_plan_max_ns);
    printa("HVPATCH4EXEC|replace-total-ns=%@d\n", @replace_ns);
    printa("HVPATCH4EXEC|replace-max-ns=%@d\n", @replace_max_ns);
    printa("HVPATCH4EXEC|publication-tail-total-ns=%@d\n", @publication_tail_ns);
    printa("HVPATCH4EXEC|publication-tail-max-ns=%@d\n", @publication_tail_max_ns);
    printa("HVPATCH4EXEC|elapsed-ns%@d\n", @elapsed_ns);
}
