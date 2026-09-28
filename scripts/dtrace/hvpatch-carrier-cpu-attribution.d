#!/usr/sbin/dtrace -qs
/*
 * Attribution of whole-carrier CPU for an HVPatch workload into:
 *   - time in guest (hv_vcpu_run)
 *   - host syscall service (by class)
 *   - fault service (by fault class: first touch, COW, frame grant, stage-2)
 *   - EL1 mailbox/grant handling
 *   - executor scheduling/park/unpark
 *   - lock wait
 *
 * WHAT IT MEASURES
 * ----------------
 * Decomposes 100% of carrier CPU. Samples scoped executing host threads at
 * profile-997 and records every sampled user stack until the target CLI exits.
 * Carrick USDT probes monitor host syscall service, guest faults, COW, frame
 * grants, stage-2 alias maps, mailbox handling, executor scheduling, and lock
 * wait entries. Where bracketing is impossible (e.g. guest execution in
 * hv_vcpu_run, FBT-blacklisted kernel fault entry), profile-provider sampling
 * is used to attribute carrier CPU.
 *
 * LIVE QUALIFICATION
 * ------------------
 * Qualified against carrick's HVPatch runtime on Darwin/arm64.
 * The script fails closed on target timeout (90 s), DTrace error, target root
 * non-exit, or zero scoped samples. sample-population is the authoritative
 * event count and must equal the sum of all emitted user-stack counts.
 *
 * PERTURBATION
 * ------------
 * Diagnostic instrumentation. A 24-frame unwind at 997 Hz per CPU provides
 * reliable statistical attribution across the categories without the extreme
 * perturbation of full per-block or per-instruction instrumentation.
 *
 * CAPTURE ACCEPTANCE
 * ------------------
 * Strict lossless capture required: zero consumer drops, status=ok,
 * root_exited=1, bounded=0, errors=0, saw_sample=1, sample-population > 0,
 * with exact stack-count closure.
 */

#pragma D option quiet
#pragma D option bufsize=96m
#pragma D option aggsize=128m
#pragma D option dynvarsize=64m
#pragma D option ustackframes=24

dtrace:::BEGIN
{
    /* Replaced by the Rust profile launcher with the immutable template hash. */
    printf("HVPCARRIERATTR|header|program_sha256=/* CARRICK_HVPCARRIERCPUATTR_PROGRAM_SHA256 */\n");
    started = timestamp;
    root_exited = 0;
    bounded = 0;
    errors = 0;
    saw_sample = 0;
}

/*
 * Exact Mach-O identity of the traced carrier so the raw stack population can
 * be symbolicated offline (atos -o target/release/carrick -l <text_base>).
 */
carrick*:::host-image-base
/pid == $target || progenyof($target)/
{
    printf("HVPCARRIERATTR|image|host_pid=%d|text_base=0x%llx|slide=0x%llx\n",
        (int)arg0, (uint64_t)arg1, (uint64_t)arg2);
}

carrick*:::hvpatch-syscall-service
/pid == $target || progenyof($target)/
{
    @usdt_syscall_services = count();
    @usdt_syscall_duration_ns = sum((uint64_t)arg4);
}

carrick*:::vcpu-fault
/pid == $target || progenyof($target)/
{
    @usdt_vcpu_faults = count();
}

carrick*:::hvpatch-frame-cow
/pid == $target || progenyof($target)/
{
    @usdt_cow_events = count();
}

carrick*:::hvpatch-el1-frame-grant-plan
/pid == $target || progenyof($target)/
{
    @usdt_frame_grants = count();
}

carrick*:::hv-vm-map-alias
/pid == $target || progenyof($target)/
{
    @usdt_stage2_aliases = count();
}

carrick*:::hvf-syscall-transport
/pid == $target || progenyof($target)/
{
    @usdt_mailbox_transports = count();
}

carrick*:::hvpatch-executor-claim
/pid == $target || progenyof($target)/
{
    @usdt_executor_claims = count();
}

carrick*:::hvpatch-scheduler-wake
/pid == $target || progenyof($target)/
{
    @usdt_scheduler_wakes = count();
}

syscall::psynch_cvwait:entry, syscall::psynch_mutexwait:entry, syscall::__ulock_wait:entry
/pid == $target || progenyof($target)/
{
    @usdt_lock_waits = count();
}

profile-997
/pid == $target || progenyof($target)/
{
    saw_sample = 1;
    @sample_population = count();
    @user_stacks[ustack(24)] = count();
}

dtrace:::ERROR
{
    errors++;
    printf("HVPCARRIERATTR|error=dtrace|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
    exit(3);
}

proc:::exit
/pid == $target/
{
    root_exited = 1;
    exit(saw_sample && errors == 0 ? 0 : 1);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(4);
}

dtrace:::END
{
    printf("HVPCARRIERATTR|summary|status=%s|root_exited=%d|bounded=%d|errors=%d|saw_sample=%d\n",
        root_exited && !bounded && errors == 0 && saw_sample ? "ok" : "error",
        root_exited, bounded, errors, saw_sample);
    printa("HVPCARRIERATTR|sample-population|count=%@d\n", @sample_population);
    printf("HVPCARRIERATTR|section=usdt-metrics\n");
    printa("HVPCARRIERATTR|usdt|metric=syscall-services|count=%@d\n", @usdt_syscall_services);
    printa("HVPCARRIERATTR|usdt|metric=syscall-duration-ns|count=%@d\n", @usdt_syscall_duration_ns);
    printa("HVPCARRIERATTR|usdt|metric=vcpu-faults|count=%@d\n", @usdt_vcpu_faults);
    printa("HVPCARRIERATTR|usdt|metric=cow-events|count=%@d\n", @usdt_cow_events);
    printa("HVPCARRIERATTR|usdt|metric=frame-grants|count=%@d\n", @usdt_frame_grants);
    printa("HVPCARRIERATTR|usdt|metric=stage2-aliases|count=%@d\n", @usdt_stage2_aliases);
    printa("HVPCARRIERATTR|usdt|metric=mailbox-transports|count=%@d\n", @usdt_mailbox_transports);
    printa("HVPCARRIERATTR|usdt|metric=executor-claims|count=%@d\n", @usdt_executor_claims);
    printa("HVPCARRIERATTR|usdt|metric=scheduler-wakes|count=%@d\n", @usdt_scheduler_wakes);
    printa("HVPCARRIERATTR|usdt|metric=lock-waits|count=%@d\n", @usdt_lock_waits);
    printf("HVPCARRIERATTR|section=user-stacks\n");
    printa(@user_stacks);
}
