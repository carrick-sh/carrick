#pragma D option quiet
#pragma D option bufsize=128m
#pragma D option aggsize=128m
#pragma D option dynvarsize=128m
#pragma D option ustackframes=48

/*
 * Tier-D Node CPU / wait attribution.
 *
 * WHAT IT MEASURES
 * ----------------
 * One launch-owned Carrick process tree, admitted from `$target` through
 * proc:::create. This is intentionally independent of the DSR translated-range
 * catalog: Tier D maps Linux AArch64 text directly and therefore has no
 * ProcessTranslator range reset to select the native-wall profile's owner.
 *
 *   profile-997 user PCs/modules  -- direct guest/JIT vs Carrick/dylib CPU
 *   profile-997 kernel PCs        -- named host-syscall vs non-syscall CPU
 *   vtimestamp syscall spans      -- on-CPU Darwin lowering cost by syscall
 *   timestamp wait spans          -- elapsed blocking time and host call stack
 *   sched off/on pairs            -- voluntary vs runnable off-CPU residence
 *
 * `umod(PC)` is the authoritative cheap classifier on Darwin: an empty module
 * means the PC belongs to no Mach-O image, which is Tier-D guest text or V8
 * dynamic code. Host `ustack()` is collected only at host syscall return, after
 * Carrick has restored its host stack. Arbitrary guest/JIT samples are never
 * unwound because x29/SP are guest state there.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-08. proc:::create arg0 is the new
 * psinfo_t; sched:::off-cpu curlwpsinfo->pr_state == SSLEEP identifies a
 * voluntary sleep; profile arg0/arg1 are kernel/user PCs; syscall and
 * mach_trap vtimestamp entry/return spans measure thread on-CPU time.
 *
 * PERTURBATION
 * ------------
 * HIGH. profile-997, scheduler probes, every host syscall pair, and selected
 * 48-frame wait stacks are enabled. Absolute elapsed time and traced-vs-clean
 * ratios are not citable. Use only bucket shares and mechanism selection here;
 * retain a candidate only under an untraced clean comparison.
 *
 * The 45 s fallback is load-bearing. `carrick trace --script` deliberately
 * lets a custom program outlive its directly spawned child so descendants can
 * drain; an unbounded script otherwise leaves the root consumer alive forever.
 * A natural completion is all tracked processes exiting. A timeout, D action
 * fault, zero CPU samples, or nonzero live count makes the capture invalid.
 */

dtrace:::BEGIN
{
    started = timestamp;
    seconds = 0;
    live = 1;
    root_exited = 0;
    completed = 0;
    timed_out = 0;
    probe_errors = 0;
    tracked[$target] = 1;
}

dtrace:::ERROR
{
    probe_errors++;
    printf("TIERDNODE1|error|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
}

proc:::create
/tracked[pid] && !tracked[args[0]->pr_pid]/
{
    tracked[args[0]->pr_pid] = 1;
    live++;
    @process_creates = count();
}

proc:::exit
/tracked[pid]/
{
    tracked[pid] = 0;
    live--;
    root_exited = pid == $target ? 1 : root_exited;
    @process_exits = count();
}

proc:::exit
/root_exited && live == 0/
{
    completed = 1;
    exit(0);
}

/* Keep the typed host syscall active across kernel samples. */
syscall:::entry
/tracked[pid]/
{
    host_syscall[pid, tid] = probefunc;
    self->sys_cpu_started = vtimestamp;
}

syscall:::return
/tracked[pid] && self->sys_cpu_started != 0/
{
    this->cpu_ns = vtimestamp - self->sys_cpu_started;
    @host_syscall_count[probefunc] = count();
    @host_syscall_cpu_ns[probefunc] = sum(this->cpu_ns);
    @host_syscall_cpu_max_ns[probefunc] = max(this->cpu_ns);
    host_syscall[pid, tid] = 0;
    self->sys_cpu_started = 0;
}

mach_trap:::entry
/tracked[pid]/
{
    self->mach_cpu_started = vtimestamp;
}

mach_trap:::return
/tracked[pid] && self->mach_cpu_started != 0/
{
    @mach_trap_count[probefunc] = count();
    @mach_trap_cpu_ns[probefunc] = sum(vtimestamp - self->mach_cpu_started);
    self->mach_cpu_started = 0;
}

/* Blocking host primitives used by Node/libuv, futex lowering, and wait4. */
syscall:::entry
/tracked[pid] &&
    (probefunc == "psynch_cvwait" ||
    probefunc == "psynch_mutexwait" ||
    probefunc == "kevent" ||
    probefunc == "kevent64" ||
    probefunc == "wait4" ||
    probefunc == "waitid" ||
    probefunc == "poll" ||
    probefunc == "poll_nocancel" ||
    probefunc == "select" ||
    probefunc == "pselect")/
{
    self->wait_started = timestamp;
    self->wait_name = probefunc;
}

syscall:::return
/tracked[pid] && self->wait_started != 0/
{
    this->wait_ns = timestamp - self->wait_started;
    @wait_count[self->wait_name] = count();
    @wait_ns[self->wait_name] = sum(this->wait_ns);
    @wait_max_ns[self->wait_name] = max(this->wait_ns);
    @wait_hist_us[self->wait_name] = quantize(this->wait_ns / 1000);
    @wait_return_stack_ns[self->wait_name, ustack(48)] = sum(this->wait_ns);
    self->wait_started = 0;
    self->wait_name = 0;
}

/* Aggregate CPU from one denominator without attempting to unwind guest SP. */
profile-997
/tracked[pid] && arg1 != 0/
{
    @cpu_all = count();
    @cpu_user = count();
    @user_module[umod(uregs[R_PC])] = count();
    @user_symbol[umod(uregs[R_PC]), usym(uregs[R_PC])] = count();
    @user_pc[pid, uregs[R_PC]] = count();
}

profile-997
/tracked[pid] && arg0 != 0/
{
    @cpu_all = count();
    @cpu_kernel = count();
    @kernel_function[func(arg0)] = count();
    @kernel_by_syscall[
        host_syscall[pid, tid] != 0 ? host_syscall[pid, tid] : "non-syscall"] =
        count();
}

/* Scheduler residence, classified at the actual off-CPU transition. */
sched:::off-cpu
/tracked[pid]/
{
    self->off_started = timestamp;
    self->off_kind = curlwpsinfo->pr_state == SSLEEP ? 1 : 2;
    self->off_pc = uregs[R_PC];
}

sched:::on-cpu
/self->off_started != 0/
{
    this->off_ns = timestamp - self->off_started;
    @off_count[self->off_kind] = count();
    @off_ns[self->off_kind] = sum(this->off_ns);
    @off_max_ns[self->off_kind] = max(this->off_ns);
    @off_pc_ns[pid, self->off_kind, self->off_pc] = sum(this->off_ns);
    self->off_started = 0;
    self->off_kind = 0;
    self->off_pc = 0;
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 45/
{
    timed_out = 1;
    exit(0);
}

dtrace:::END
{
    printf("TIERDNODE1|section=cpu-totals\n");
    printa("TIERDNODE1|cpu=all|samples=%@d\n", @cpu_all);
    printa("TIERDNODE1|cpu=user|samples=%@d\n", @cpu_user);
    printa("TIERDNODE1|cpu=kernel|samples=%@d\n", @cpu_kernel);

    printf("TIERDNODE1|section=user-modules\n");
    printa("TIERDNODE1|user-module=%A|samples=%@d\n", @user_module);

    trunc(@user_symbol, 80);
    printf("TIERDNODE1|section=user-symbols\n");
    printa("TIERDNODE1|user-module=%A|user-symbol=%A|samples=%@d\n",
        @user_symbol);

    trunc(@kernel_function, 80);
    printf("TIERDNODE1|section=kernel-functions\n");
    printa("TIERDNODE1|kernel-function=%a|samples=%@d\n",
        @kernel_function);
    printf("TIERDNODE1|section=kernel-by-syscall\n");
    printa("TIERDNODE1|host=%s|kernel-samples=%@d\n",
        @kernel_by_syscall);

    trunc(@host_syscall_cpu_ns, 80);
    printf("TIERDNODE1|section=host-syscalls\n");
    printa("TIERDNODE1|host=%s|count=%@d|cpu-ns=%@d|max-cpu-ns=%@d\n",
        @host_syscall_count, @host_syscall_cpu_ns, @host_syscall_cpu_max_ns);

    trunc(@mach_trap_cpu_ns, 40);
    printf("TIERDNODE1|section=mach-traps\n");
    printa("TIERDNODE1|mach=%s|count=%@d|cpu-ns=%@d\n",
        @mach_trap_count, @mach_trap_cpu_ns);

    printf("TIERDNODE1|section=waits\n");
    printa("TIERDNODE1|wait=%s|count=%@d|elapsed-ns=%@d|max-ns=%@d\n",
        @wait_count, @wait_ns, @wait_max_ns);
    printa("TIERDNODE1|wait-hist-us=%s\n%@d\n", @wait_hist_us);
    trunc(@wait_return_stack_ns, 48);
    printa("TIERDNODESTACK1|begin|wait=%s|elapsed-ns=%@d\n%kTIERDNODESTACK1|end\n",
        @wait_return_stack_ns);

    printf("TIERDNODE1|section=offcpu|legend=1-voluntary,2-runnable\n");
    printa("TIERDNODE1|off-kind=%d|count=%@d|elapsed-ns=%@d|max-ns=%@d\n",
        @off_count, @off_ns, @off_max_ns);
    trunc(@off_pc_ns, 80);
    printa("TIERDNODE1|off-pid=%d|off-kind=%d|pc=%#x|elapsed-ns=%@d\n",
        @off_pc_ns);

    printa("TIERDNODE1|process-creates=%@d\n", @process_creates);
    printa("TIERDNODE1|process-exits=%@d\n", @process_exits);
    printf("TIERDNODE1|complete|natural=%d|timed_out=%d|probe_errors=%d|live=%d|elapsed-ns=%d\n",
        completed, timed_out, probe_errors, live, timestamp - started);
}
