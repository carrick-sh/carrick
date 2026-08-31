#!/usr/sbin/dtrace -qs
/*
 * hvpatch-process-retire-critical-section.d — attribute the WORK done inside
 * the carrier-wide topology lock while it is held for ProcessRetire.
 *
 * (a) What it measures. `scripts/dtrace/hvpatch-phase4-topology-lock.d`
 * establishes how long the single carrier-wide topology mutex is held per
 * operation class; it does not say what the holder is doing. This script
 * brackets exactly the ProcessRetire hold window (acquired -> released on the
 * same host thread) and splits it three ways: on-CPU user stacks, host
 * syscalls / Mach traps issued inside it, and descheduled (off-CPU) time. It
 * also histograms per-hold duration, because the population is bimodal and a
 * mean is meaningless on it.
 *
 * (b) Provider ABI, qualified live on Darwin/arm64 (macOS 27, 2026-08-30)
 * against the carrick-observability USDT site emitted by
 * `carrick_observability::probes::real::hvpatch_topology_lock`:
 *   carrick*:::hvpatch-topology-lock carries five scalar CTF arguments —
 *     arg0 uint32_t operation (7 = process retire; append-only ordinals)
 *     arg1 uint32_t phase     (0 requested, 1 acquired, 2 released, 3 try miss)
 *     arg2 int32_t  guest_pid
 *     arg3 int32_t  guest_tid
 *     arg4 uint64_t elapsed_ns (wait on acquired, hold on released)
 * The hold window is per HOST THREAD: the guard is an RAII object released on
 * the acquiring thread, so `self->` scoping is exact and needs no pid keying.
 * `ustack()` is trustworthy here only because `.cargo/config.toml` forces
 * frame pointers; without that flag this script silently prints nonsense.
 * `sched:::off-cpu` / `sched:::on-cpu` are qualified live on this host;
 * `sched:::preempt` does NOT exist on macOS and is deliberately unused.
 *
 * Two ABI facts learned the hard way here, so nobody pays for them twice:
 *   - Do NOT stash `probefunc` in a `self->` string to read it back in the
 *     matching `:return` clause. Under this event rate the dynamic-variable
 *     space is exhausted, the string reads back as address 0, and every
 *     `:return` clause aborts with "invalid address (0x0)" — silently losing
 *     the whole census. `probefunc` is already correct in the return probe;
 *     key the aggregation on it directly.
 *   - `samples == 0` is only evidence of "not on CPU" once the CONTROL
 *     counters below prove the profile probe fired at all. They are printed
 *     unconditionally for exactly that reason.
 *
 * (c) Perturbation: YES, heavily. Two USDT firings per acquisition already
 * exist; this adds a 1997 Hz profile probe with a 20-frame unwind plus full
 * syscall/mach-trap/scheduler bracketing inside the window. Stack RANK, call
 * COUNTS and the per-hold duration DISTRIBUTION are citable; absolute
 * wall/CPU time measured under this script is not.
 *
 * Attach to the VM CARRIER, not the process that spawned it. Under the
 * in-process conformance-next lane the carrier is a grandchild carrying the
 * `carrick:<run-id>:` proctitle:
 *   sudo dtrace -qs scripts/dtrace/hvpatch-process-retire-critical-section.d \
 *     -p "$(pgrep -f 'carrick:<run-id>:' | head -1)"
 */

#pragma D option quiet
#pragma D option bufsize=64m
#pragma D option aggsize=64m
#pragma D option dynvarsize=64m

dtrace:::BEGIN
{
    started = timestamp;
    holds = 0;
    samples = 0;
    profile_ticks = 0;
    target_ticks = 0;
    syscalls = 0;
    machtraps = 0;
    offcpu_events = 0;
    errors = 0;
    bounded = 0;
    retiring[(uint64_t)0] = 0;
    acquires[(uint64_t)0] = 0;
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg0 == 7 && arg1 == 1/
{
    acquires[tid] = acquires[tid] + 1;
    retiring[tid] = 1;
    @nest[acquires[tid]] = count();
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg0 == 7 && arg1 == 2 && retiring[tid]/
{
    holds++;
    @hold_ns = quantize((uint64_t)arg4);
    @hold_total = sum((uint64_t)arg4);
    acquires[tid] = acquires[tid] - 1;
    retiring[tid] = acquires[tid] > 0 ? 1 : 0;
}

/* Control: prove the profile provider fires, and that it sees the carrier. */
profile-1997
{
    profile_ticks++;
}

profile-1997
/pid == $target || progenyof($target)/
{
    target_ticks++;
}

profile-1997
/retiring[tid]/
{
    samples++;
    @stacks[ustack(20)] = count();
}

syscall:::entry
/retiring[tid]/
{
    self->sysstart = timestamp;
}

syscall:::return
/retiring[tid] && self->sysstart/
{
    syscalls++;
    @sys_count[probefunc] = count();
    @sys_ns[probefunc] = sum(timestamp - self->sysstart);
    @sys_max[probefunc] = max(timestamp - self->sysstart);
    self->sysstart = 0;
}

mach_trap:::entry
/retiring[tid]/
{
    self->machstart = timestamp;
}

mach_trap:::return
/retiring[tid] && self->machstart/
{
    machtraps++;
    @mach_count[probefunc] = count();
    @mach_ns[probefunc] = sum(timestamp - self->machstart);
    @mach_max[probefunc] = max(timestamp - self->machstart);
    self->machstart = 0;
}

sched:::off-cpu
/retiring[tid]/
{
    self->offcpu = timestamp;
    offcpu_events++;
}

sched:::on-cpu
/retiring[tid] && self->offcpu/
{
    @offcpu_ns = sum(timestamp - self->offcpu);
    self->offcpu = 0;
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
/timestamp - started > 120 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printf("HVPRETIRECS|summary|holds=%d|on_cpu_samples=%d|profile_ticks=%d|target_ticks=%d|syscalls=%d|machtraps=%d|offcpu_events=%d|empty=%d|bounded=%d|errors=%d\n",
        holds, samples, profile_ticks, target_ticks, syscalls, machtraps,
        offcpu_events, holds == 0, bounded, errors);
    printa("HVPRETIRECS|hold-total-ns|ns=%@d\n", @hold_total);
    printa("HVPRETIRECS|off-cpu-total-ns|ns=%@d\n", @offcpu_ns);
    printa("HVPRETIRECS|host-syscall|name=%s|count=%@d\n", @sys_count);
    printa("HVPRETIRECS|host-syscall-ns|name=%s|ns=%@d\n", @sys_ns);
    printa("HVPRETIRECS|host-syscall-max-ns|name=%s|ns=%@d\n", @sys_max);
    printa("HVPRETIRECS|mach-trap|name=%s|count=%@d\n", @mach_count);
    printa("HVPRETIRECS|mach-trap-ns|name=%s|ns=%@d\n", @mach_ns);
    printa("HVPRETIRECS|mach-trap-max-ns|name=%s|ns=%@d\n", @mach_max);
    printa("HVPRETIRECS|nesting-depth|depth=%d|count=%@d\n", @nest);
    printf("HVPRETIRECS|hold-ns-distribution\n");
    printa(@hold_ns);
    printf("HVPRETIRECS|in-critical-section-on-cpu-stacks\n");
    trunc(@stacks, 15);
    printa(@stacks);
}
