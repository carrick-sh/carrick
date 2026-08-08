#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option aggsize=32m
#pragma D option dynvarsize=16m

/*
 * tier-d-node-oncpu.d -- low-perturbation on-CPU attribution for one Tier-D
 * Node process tree.
 *
 * WHAT IT MEASURES
 * ----------------
 * `profile-997` samples user and kernel PCs for Carrick executables in the
 * launch-owned `$target` process tree.  The `execname == "carrick"` predicate
 * excludes the detached `/bin/rm` reaper: canonical timing ends when Carrick
 * exits, while the tracer intentionally follows that reaper to prove complete
 * lifecycle closure.  User PCs are split by `umod()`: a raw address rather than a
 * named Mach-O module is code in no Mach-O image, which on Tier D is direct
 * Linux image text or V8-generated code.  Raw (pid, PC) samples are retained
 * for offline classification against the image announcements.  A bounded
 * `ustack(24)` is also sampled to attribute time inside symbolized host leaves,
 * and the live leaf/link-register pair retains the immediate arm64 caller even
 * after a self-reexec'd process exits and its deferred stack cannot symbolize;
 * JIT/direct guest frames have no Darwin unwind information, so only stacks
 * with a coherent symbolic host chain are evidence.  Darwin DTrace
 * exposes `umod()` as the opaque `_usymaddr` type, so the no-module subtotal is
 * derived from the printed aggregation rather than compared in a predicate.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-08.  profile-997 arg0/arg1 are the
 * kernel/user PCs.  proc:::create args[0]->pr_pid is the created pid.
 * Carrick host-image-base and guest-image-base carry host pid, base, and path
 * in the provider ABI generated from crates/carrick-observability.
 *
 * PERTURBATION
 * ------------
 * MODERATE.  This script enables a 997 Hz sampling profile with bounded user
 * stack walking, process lifecycle probes, and low-frequency image
 * announcements.  It deliberately enables no syscall, scheduler, Mach-trap,
 * or per-instruction probe.  Bucket shares select the next mechanism; elapsed
 * time from this run is not gating performance evidence.  A valid capture must
 * complete naturally with nonzero samples, no DTrace errors, and no live
 * tracked processes.
 */

dtrace:::BEGIN
{
    started = timestamp;
    seconds = 0;
    live = 1;
    completed = 0;
    timed_out = 0;
    probe_errors = 0;
    tracked[$target] = 1;
}

dtrace:::ERROR
{
    probe_errors++;
    printf("TIERDONCPU1|error|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
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
    @process_exits = count();
}

proc:::exit
/completed == 0 && live == 0/
{
    completed = 1;
    exit(0);
}

carrick*:::host-image-base
/tracked[pid]/
{
    printf("TIERDONCPU1|image=host|pid=%d|wire-pid=%d|base=%#x|slide=%d|path=%s\n",
        pid, (int)arg0, arg1, (int)arg2, copyinstr(arg3));
}

carrick*:::guest-image-base
/tracked[pid]/
{
    printf("TIERDONCPU1|image=guest|pid=%d|wire-pid=%d|base=%#x|entry=%#x|path=%s\n",
        pid, (int)arg0, arg1, arg2, copyinstr(arg3));
}

profile-997
/tracked[pid] && execname == "carrick" && arg1 != 0/
{
    @cpu_all = count();
    @cpu_user = count();
    @pid_user[pid] = count();
    @user_module[umod(uregs[R_PC])] = count();
    @user_symbol[usym(uregs[R_PC])] = count();
    @user_leaf_lr[usym(uregs[R_PC]), usym(uregs[R_LR])] = count();
    @user_stack[ustack(24)] = count();
    @user_pc[pid, uregs[R_PC]] = count();
}

profile-997
/tracked[pid] && execname == "carrick" && arg0 != 0/
{
    @cpu_all = count();
    @cpu_kernel = count();
    @pid_kernel[pid] = count();
    @kernel_function[func(arg0)] = count();
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 40/
{
    timed_out = 1;
    exit(0);
}

dtrace:::END
{
    printf("TIERDONCPU1|section=totals\n");
    printa("TIERDONCPU1|cpu=all|samples=%@d\n", @cpu_all);
    printa("TIERDONCPU1|cpu=user|samples=%@d\n", @cpu_user);
    printa("TIERDONCPU1|cpu=kernel|samples=%@d\n", @cpu_kernel);
    printf("TIERDONCPU1|section=user-modules\n");
    printa("TIERDONCPU1|user-module=%A|samples=%@d\n", @user_module);

    trunc(@user_symbol, 120);
    printf("TIERDONCPU1|section=user-symbols\n");
    printa("TIERDONCPU1|user-symbol=%A|samples=%@d\n", @user_symbol);

    trunc(@user_leaf_lr, 120);
    printf("TIERDONCPU1|section=user-leaf-callers\n");
    printa("TIERDONCPU1|user-leaf=%A|caller=%A|samples=%@d\n", @user_leaf_lr);

    trunc(@user_stack, 80);
    printf("TIERDONCPU1|section=user-stacks\n");
    printa("TIERDONCPU1|user-stack=%k|samples=%@d\n", @user_stack);

    printf("TIERDONCPU1|section=processes\n");
    printa("TIERDONCPU1|pid=%d|user-samples=%@d\n", @pid_user);
    printa("TIERDONCPU1|pid=%d|kernel-samples=%@d\n", @pid_kernel);

    trunc(@kernel_function, 80);
    printf("TIERDONCPU1|section=kernel-functions\n");
    printa("TIERDONCPU1|kernel-function=%a|samples=%@d\n", @kernel_function);

    trunc(@user_pc, 240);
    printf("TIERDONCPU1|section=user-pcs\n");
    printa("TIERDONCPU1|pid=%d|pc=%#x|samples=%@d\n", @user_pc);

    printa("TIERDONCPU1|process-creates=%@d\n", @process_creates);
    printa("TIERDONCPU1|process-exits=%@d\n", @process_exits);
    printf("TIERDONCPU1|complete|natural=%d|timed-out=%d|probe-errors=%d|live=%d|elapsed-ns=%d\n",
        completed, timed_out, probe_errors, live, timestamp - started);
}
