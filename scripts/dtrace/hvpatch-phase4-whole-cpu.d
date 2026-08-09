#!/usr/sbin/dtrace -qs
/*
 * Whole-workload CPU and Linux-service attribution for the one-VM hvpatch
 * backend. This answers whether the next >=10% opportunity is inside a named
 * Linux syscall service or elsewhere in guest execution/Carrick/HVF.
 *
 * Provider ABI qualified from carrick-observability on macOS 27.0 arm64:
 * carrick*:::hvpatch-syscall-service-begin carries four scalar CTF values:
 * (int32_t guest_pid, int32_t guest_tid, uint32_t asid,
 * uint64_t linux_syscall_number). Its enabled closure starts the runtime clock,
 * so untraced execution does not pay for timing. The matching
 * carrick*:::hvpatch-syscall-service is a completed record carrying
 * five scalar CTF values: (int32_t guest_pid, int32_t guest_tid,
 * uint32_t asid, uint64_t linux_syscall_number, uint64_t duration_ns).
 * The identities are Linux namespace identities multiplexed inside one Darwin
 * process; DTrace pid/tid remain host identities. Duration is monotonic wall
 * time measured by the runtime. A terminal `_exit` cannot run the completion
 * guard and is intentionally absent (one exit_group in the build fixture).
 *
 * Stateless completion records replace a statefully joined boundary ABI. Under this hot
 * workload, DTrace associative state silently lost thousands of joins despite
 * balanced probe populations and no dtrace:::ERROR; direct duration events are
 * therefore the fail-closed durable interface. profile-199 arg0/arg1 are
 * kernel/user PCs and provide independent whole-process CPU shape.
 *
 * Perturbation: HIGH. This fires two scalar USDT probes and takes one monotonic
 * clock measurement per host-dispatched Linux syscall, plus sampling
 * at 199 Hz. Absolute wall/CPU and traced-vs-clean ratios are not citable. Use
 * same-instrument nonblocking service shares and sample ranks only to select a
 * mechanism, then retain behavior under an untraced ABBA. Blocking syscall
 * durations are wait time, not CPU opportunity. No user/kernel stack walk is
 * attempted: guest registers and trap-context unwind are not authoritative.
 *
 * The D consumer fails on zero root/service events, timeout, or DTrace error.
 * DTrace cannot prove guest command correctness; retain a capture only when the
 * invoking `carrick trace` command also exits zero with exact expected output.
 */

#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option aggsize=64m

dtrace:::BEGIN
{
    started = timestamp;
    target_exited = 0;
    root_seen = 0;
    timed_out = 0;
    saw_service = 0;
    errors = 0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target))/
{
    @service_begin_population = count();
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target))/
{
    saw_service = 1;
    @service_completion_population = count();
    @service_calls[(uint64_t)arg3] = count();
    @service_duration_ns[(uint64_t)arg3] = sum((uint64_t)arg4);
    @service_max_ns[(uint64_t)arg3] = max((uint64_t)arg4);
    @service_task_duration_ns[
        (int32_t)arg0, (int32_t)arg1, (uint32_t)arg2,
        (uint64_t)arg3] = sum((uint64_t)arg4);
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 0/
{
    root_seen = 1;
    @root_identity[(int32_t)arg1, (int32_t)arg3, (uint32_t)arg4] = count();
}

profile-199
/(pid == $target || progenyof($target)) && arg1 != 0/
{
    @cpu_all = count();
    @cpu_user = count();
    @user_module[umod(uregs[R_PC])] = count();
    @user_symbol[usym(uregs[R_PC])] = count();
}

profile-199
/(pid == $target || progenyof($target)) && arg0 != 0/
{
    @cpu_all = count();
    @cpu_kernel = count();
    @kernel_function[func(arg0)] = count();
}

dtrace:::ERROR
{
    errors++;
    printf("HVPATCH4CPU|error=dtrace|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
    exit(3);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(saw_service && root_seen ? 0 : 1);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    timed_out = 1;
    exit(4);
}

dtrace:::END
{
    printf("HVPATCH4CPU|summary|status=%s|target_exited=%d|root_seen=%d|timed_out=%d|saw_service=%d|errors=%d\n",
        root_seen && !timed_out && saw_service && !errors ? "ok" : "error",
        target_exited, root_seen, timed_out, saw_service, errors);
    printa("HVPATCH4CPU|service-begin-population|count=%@d\n",
        @service_begin_population);
    printa("HVPATCH4CPU|service-completion-population|count=%@d\n",
        @service_completion_population);
    printa("HVPATCH4CPU|root|guest_pid=%d|guest_tid=%d|asid=%u|count=%@d\n",
        @root_identity);
    printa("HVPATCH4CPU|cpu=all|samples=%@d\n", @cpu_all);
    printa("HVPATCH4CPU|cpu=user|samples=%@d\n", @cpu_user);
    printa("HVPATCH4CPU|cpu=kernel|samples=%@d\n", @cpu_kernel);
    printa("HVPATCH4CPU|linux-call|nr=%llu|count=%@d\n", @service_calls);
    printa("HVPATCH4CPU|linux-duration-ns|nr=%llu|value=%@d\n",
        @service_duration_ns);
    printa("HVPATCH4CPU|linux-max-duration-ns|nr=%llu|value=%@d\n",
        @service_max_ns);
    printf("HVPATCH4CPU|section=linux-task-duration\n");
    trunc(@service_task_duration_ns, 160);
    printa("HVPATCH4CPU|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|duration_ns=%@d\n",
        @service_task_duration_ns);
    printf("HVPATCH4CPU|section=user-modules\n");
    trunc(@user_module, 80);
    printa("HVPATCH4CPU|user-module=%A|samples=%@d\n", @user_module);
    trunc(@user_symbol, 120);
    printa("HVPATCH4CPU|user-symbol=%A|samples=%@d\n", @user_symbol);
    printf("HVPATCH4CPU|section=kernel-functions\n");
    trunc(@kernel_function, 120);
    printa("HVPATCH4CPU|kernel-function=%a|samples=%@d\n", @kernel_function);
}
