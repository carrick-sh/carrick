#!/usr/sbin/dtrace -qs
/*
 * Attribute on-CPU code and Darwin kernel entry while hvpatch replaces Linux
 * guest images in one process-wide VM.
 *
 * WHAT IT MEASURES
 * ----------------
 * `hvpatch-guest-lifecycle` phase 6 (exec-begin) arms a thread-local window and
 * phase 2 (exec-success) closes it. While armed, profile-997 samples Carrick's
 * user and kernel PCs; syscall and mach_trap entry/return probes count Darwin
 * operations and their on-CPU vtimestamp. Every aggregate is restricted to the
 * complete exec window, which includes ELF loading/patching, stage-2 replacement,
 * vCPU reprogramming, and publication. The guest PID/TID/ASID carried by the
 * typed lifecycle ABI is retained in per-guest sample totals.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-09. carrick*:::hvpatch-guest-lifecycle
 * carries (uint32_t phase, int32_t guest_pid, int32_t guest_ppid,
 * int32_t guest_tid, uint32_t asid). profile-997 arg0/arg1 are kernel/user PCs.
 * syscall:::entry/return and mach_trap:::entry/return pair on the current host
 * thread; `probefunc` is the Darwin operation name. These are Linux guest
 * identities multiplexed inside one Darwin PID.
 *
 * PERTURBATION
 * ------------
 * MODERATE. Sampling is 997 Hz with bounded ustack(24), and every Darwin syscall
 * and Mach trap inside the exec window is bracketed. Shares and rankings select
 * the next mechanism; wall/CPU totals from this run are not performance gates.
 * A valid capture has 67 begins/ends on the cold-build fixture, nonzero samples,
 * zero DTrace errors, and natural completion. Zero samples is an error, never an
 * empty-cost result.
 */

#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option aggsize=32m
#pragma D option dynvarsize=16m

dtrace:::BEGIN
{
    started = timestamp;
    begins = 0;
    ends = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 6/
{
    begins++;
    exec_active[pid, tid] = 1;
    guest_pid[pid, tid] = (int)arg1;
    guest_tid[pid, tid] = (int)arg3;
    guest_asid[pid, tid] = (uint32_t)arg4;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2 && exec_active[pid, tid]/
{
    ends++;
    exec_active[pid, tid] = 0;
    guest_pid[pid, tid] = 0;
    guest_tid[pid, tid] = 0;
    guest_asid[pid, tid] = 0;
}

syscall:::entry
/exec_active[pid, tid]/
{
    self->syscall_started = vtimestamp;
    self->syscall_name = probefunc;
}

syscall:::return
/self->syscall_started != 0/
{
    @host_syscall_count[self->syscall_name] = count();
    @host_syscall_cpu_ns[self->syscall_name] =
        sum(vtimestamp - self->syscall_started);
    @host_syscall_cpu_max_ns[self->syscall_name] =
        max(vtimestamp - self->syscall_started);
    self->syscall_started = 0;
    self->syscall_name = 0;
}

mach_trap:::entry
/exec_active[pid, tid]/
{
    self->mach_started = vtimestamp;
    self->mach_name = probefunc;
}

mach_trap:::return
/self->mach_started != 0/
{
    @mach_count[self->mach_name] = count();
    @mach_cpu_ns[self->mach_name] = sum(vtimestamp - self->mach_started);
    @mach_cpu_max_ns[self->mach_name] = max(vtimestamp - self->mach_started);
    self->mach_started = 0;
    self->mach_name = 0;
}

profile-997
/exec_active[pid, tid] && arg1 != 0/
{
    @cpu_all = count();
    @cpu_user = count();
    @guest_user[guest_pid[pid, tid], guest_tid[pid, tid], guest_asid[pid, tid]] = count();
    @user_symbol[usym(uregs[R_PC])] = count();
    @user_leaf_lr[usym(uregs[R_PC]), usym(uregs[R_LR])] = count();
    @user_stack[ustack(24)] = count();
}

profile-997
/exec_active[pid, tid] && arg0 != 0/
{
    @cpu_all = count();
    @cpu_kernel = count();
    @guest_kernel[guest_pid[pid, tid], guest_tid[pid, tid], guest_asid[pid, tid]] = count();
    @kernel_function[func(arg0)] = count();
}

dtrace:::ERROR
{
    errors++;
    printf("HVPATCH4EXECPROF|error|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
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
    printf("HVPATCH4EXECPROF|summary|begins=%d|ends=%d|bounded=%d|errors=%d\n",
        begins, ends, bounded, errors);
    printa("HVPATCH4EXECPROF|cpu=all|samples=%@d\n", @cpu_all);
    printa("HVPATCH4EXECPROF|cpu=user|samples=%@d\n", @cpu_user);
    printa("HVPATCH4EXECPROF|cpu=kernel|samples=%@d\n", @cpu_kernel);

    trunc(@user_symbol, 120);
    printf("HVPATCH4EXECPROF|section=user-symbols\n");
    printa("HVPATCH4EXECPROF|user-symbol=%A|samples=%@d\n", @user_symbol);
    trunc(@user_leaf_lr, 120);
    printf("HVPATCH4EXECPROF|section=user-leaf-callers\n");
    printa("HVPATCH4EXECPROF|user-leaf=%A|caller=%A|samples=%@d\n", @user_leaf_lr);
    trunc(@user_stack, 80);
    printf("HVPATCH4EXECPROF|section=user-stacks\n");
    printa("HVPATCH4EXECPROF|user-stack=%k|samples=%@d\n", @user_stack);

    trunc(@kernel_function, 80);
    printf("HVPATCH4EXECPROF|section=kernel-functions\n");
    printa("HVPATCH4EXECPROF|kernel-function=%a|samples=%@d\n", @kernel_function);
    printf("HVPATCH4EXECPROF|section=host-syscalls\n");
    printa("HVPATCH4EXECPROF|host-syscall=%s|count=%@d\n", @host_syscall_count);
    printa("HVPATCH4EXECPROF|host-syscall=%s|cpu-ns=%@d\n", @host_syscall_cpu_ns);
    printa("HVPATCH4EXECPROF|host-syscall=%s|max-cpu-ns=%@d\n", @host_syscall_cpu_max_ns);
    printf("HVPATCH4EXECPROF|section=mach-traps\n");
    printa("HVPATCH4EXECPROF|mach-trap=%s|count=%@d\n", @mach_count);
    printa("HVPATCH4EXECPROF|mach-trap=%s|cpu-ns=%@d\n", @mach_cpu_ns);
    printa("HVPATCH4EXECPROF|mach-trap=%s|max-cpu-ns=%@d\n", @mach_cpu_max_ns);
    printf("HVPATCH4EXECPROF|section=guest-samples\n");
    printa("HVPATCH4EXECPROF|guest-pid=%d|guest-tid=%d|asid=%u|user-samples=%@d\n",
        @guest_user);
    printa("HVPATCH4EXECPROF|guest-pid=%d|guest-tid=%d|asid=%u|kernel-samples=%@d\n",
        @guest_kernel);
}
