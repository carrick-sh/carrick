#!/usr/sbin/dtrace -qs
/*
 * Count CPU placement and EL0 faults over a repeated fork/exec workload.
 * This separates a core-placement hypothesis from excessive fault/exit work.
 *
 * ABI: profile-199 arg0/arg1 are interrupted kernel/user PCs; `cpu` is the
 * logical host CPU. vcpu-fault arg0 is ESR and arg2 is FAR. COW identity arg4 is phase
 * (0=stage2, 1=stage1, 2=commit); trigger identity arg4 is trigger class
 * (0=permission fault, 1=syscall write, 2=maintenance, 3=internal). The lifecycle
 * ordinals are 6=exec begin, 2=exec success. All counts cover the spawned
 * process tree. Fault addresses are deliberately NOT treated as unique pages:
 * different Linux MMs may use the same VA. No guest identity is inferred from
 * the host PID. CPU IDs require the capture host's IODeviceTree cpus map;
 * do not hardcode P/E ranges across machines.
 *
 * Perturbation: 199 Hz placement sampling plus 997 Hz COW-window stacks,
 * fault/exec probes and scalar COW phases. A COW window joins one host
 * thread from permission fault to committed COW and must balance. The
 * profile joins use [pid, tid], not self-> state: profile fires in interrupt
 * context. This instrument requires sampled COW and successful repeated execs,
 * not arbitrary faulting code. Target syscall::exit must report zero. Use CPU placement
 * and event populations for diagnosis, never the traced wall time as a gate.
 * Kernel stacks in this capture can be dominated by the armed USDT probes;
 * use hvpatch-exec-cpu-sampling.d to rank costs without those probes.
 * Require natural target success, nonzero samples/execs, balanced execs, zero
 * errors and no consumer drops. Bounded at 45 seconds. Qualified by the
 * 2026-09-09 per-exec campaign; raw receipts live beside its performance data.
 */
#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option aggsize=16m

dtrace:::BEGIN
{
    started = timestamp;
    samples = 0;
    begins = 0;
    ends = 0;
    faults = 0;
    errors = 0;
    bounded = 0;
    target_exited = 0;
    target_exit_seen = 0;
    target_exit_code = -1;
    cow_active[0, 0] = 0;
    cow_samples = 0;
    cow_windows = 0;
    cow_window_ends = 0;
    cow_window_errors = 0;
}

profile-199
/pid == $target || progenyof($target)/
{
    samples++;
    @placement[cpu, arg0 != 0] = count();
}

carrick*:::vcpu-fault
/pid == $target || progenyof($target)/
{
    faults++;
    @fault_kind[(arg0 >> 26) & 63, arg0 & 63, (arg0 >> 6) & 1] = count();
    @fault_region[arg2 >> 32] = count();
}

carrick*:::vcpu-fault
/(pid == $target || progenyof($target)) && (arg0 & 63) == 15 && ((arg0 >> 6) & 1)/
{
    cow_window_errors += cow_active[pid, tid] != 0;
    cow_active[pid, tid] = 1;
    cow_windows++;
}

profile-997
/(pid == $target || progenyof($target)) && cow_active[pid, tid] && arg1 != 0/
{ cow_samples++; @cow_user[usym(uregs[R_PC])] = count(); @cow_stack[ustack(20)] = count(); }

profile-997
/(pid == $target || progenyof($target)) && cow_active[pid, tid] && arg0 != 0/
{ cow_samples++; @cow_kernel[func(arg0)] = count(); @cow_kernel_stack[stack(20)] = count(); }

carrick*:::hvpatch-frame-cow-identity
/pid == $target || progenyof($target)/
{
    @cow_phase[arg4] = count();
    @cow_task[(int)arg0, arg4] = count();
    self->cow_pid = (int)arg0;
    self->cow_phase = arg4;
    if (arg4 == 2 && cow_active[pid, tid]) {
        cow_active[pid, tid] = 0;
        cow_window_ends++;
    }
}

carrick*:::hvpatch-frame-cow
/(pid == $target || progenyof($target)) && self->cow_phase == 2/
{ @cow_region[self->cow_pid, arg0 >> 16] = count(); }

carrick*:::hvpatch-frame-cow-trigger-identity
/pid == $target || progenyof($target)/
{ @cow_trigger[arg4] = count(); }

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 6/
{ begins++; }

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2/
{ ends++; }

dtrace:::ERROR
{ errors++; exit(3); }

syscall::exit:entry
/pid == $target/
{
    target_exit_seen = 1;
    target_exit_code = (int)arg0;
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(samples > 0 && begins > 0 && begins == ends && errors == 0 && target_exit_seen && target_exit_code == 0 && cow_windows == cow_window_ends && cow_window_errors == 0 && cow_samples > 0 ? 0 : 2);
}

tick-1s
/timestamp - started > 45 * 1000000000/
{ bounded = 1; exit(4); }

dtrace:::END
{
    printf("EXECSTART|summary|samples=%d|begins=%d|ends=%d|faults=%d|errors=%d|bounded=%d|target_exited=%d|target_exit_seen=%d|target_exit_code=%d\n",
        samples, begins, ends, faults, errors, bounded, target_exited, target_exit_seen, target_exit_code);
    printf("EXECSTART|cow-windows=%d|cow-window-ends=%d|cow-window-errors=%d|cow-samples=%d\n", cow_windows, cow_window_ends, cow_window_errors, cow_samples);
    printa("EXECSTART|cow-user=%A|samples=%@d\n", @cow_user);
    printa("EXECSTART|cow-kernel=%a|samples=%@d\n", @cow_kernel);
    printa("EXECSTART|cow-stack=%k|samples=%@d\n", @cow_stack);
    printa("EXECSTART|cow-kernel-stack=%k|samples=%@d\n", @cow_kernel_stack);
    printa("EXECSTART|cpu=%d|kernel=%d|samples=%@d\n", @placement);
    printa("EXECSTART|ec=%u|fsc=%u|write=%u|faults=%@d\n", @fault_kind);
    printa("EXECSTART|cow-phase=%u|count=%@d\n", @cow_phase);
    printa("EXECSTART|cow-pid=%d|phase=%u|count=%@d\n", @cow_task);
    printa("EXECSTART|cow-pid=%d|va-high48=%x|count=%@d\n", @cow_region);
    printa("EXECSTART|cow-trigger=%u|count=%@d\n", @cow_trigger);
    printa("EXECSTART|va-high32=%x|faults=%@d\n", @fault_region);
}
