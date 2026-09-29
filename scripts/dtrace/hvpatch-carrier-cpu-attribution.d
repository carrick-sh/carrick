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
 * To avoid severe probe-trampoline perturbation, this profile enables NO
 * per-syscall, per-fault, or per-switch USDT probes. Only rare lifecycle probes
 * (specifically carrick*:::host-image-base for carrier PID scoping and ASLR base
 * discovery, which fires once at carrier startup) are enabled. Whole-carrier CPU
 * is attributed statistically across execution categories via profile sampling.
 *
 * LIVE QUALIFICATION
 * ------------------
 * Qualified against carrick's HVPatch runtime on Darwin/arm64.
 * The script fails closed on target timeout (90 s by default; the Rust
 * launcher may override this with `carrick trace --profile-bound-seconds`
 * for long workloads such as `go build`), DTrace error, target root
 * non-exit, or zero scoped samples. sample-population is the authoritative
 * event count and must equal the sum of all emitted user-stack counts.
 *
 * PERTURBATION
 * ------------
 * Diagnostic instrumentation. A 32-frame unwind at 997 Hz per CPU provides
 * reliable statistical attribution without the perturbation of high-frequency
 * USDT probe breakpoints/trampolines. Samples landing in probe/trampoline frames
 * are explicitly categorized as "instrumentation" and must be ~0%; the profile
 * fails closed if instrumentation exceeds a few percent.
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
#pragma D option ustackframes=32
#pragma D option strsize=1024

dtrace:::BEGIN
{
    /* Replaced by the Rust profile launcher with the immutable template hash. */
    printf("HVPCARRIERATTR|header|program_sha256=/* CARRICK_HVPCARRIERCPUATTR_PROGRAM_SHA256 */\n");
    started = timestamp;
    carrier_pid = 0;
    root_exited = 0;
    bounded = 0;
    errors = 0;
    saw_sample = 0;
    bound_elapsed_s = (uint64_t)0;
    bound_limit_s = (uint64_t)90;

    /*
     * The declared capture bound. Left as the shipped default (90 s) when
     * unrendered so the bundled template stays a legal D program on its own;
     * `carrick trace --profile-bound-seconds` overrides it for long
     * workloads (e.g. `go build`), and the summary always reports whichever
     * bound was actually in force.
     */
    /* CARRICK_HVPCARRIERCPUATTR_BOUND */
}

/*
 * Exact Mach-O identity of the traced carrier so the raw stack population can
 * be symbolicated in-process by the Rust reader (goblin Mach-O/ELF symbol
 * table parsing keyed on host_pid/text_base/slide) -- no child `atos`
 * process, which the carrier-only process invariant forbids.
 * Only fires once per carrier process at startup.
 */
carrick*:::host-image-base
/pid == $target || progenyof($target)/
{
    carrier_pid = (int)arg0;
    printf("HVPCARRIERATTR|image|host_pid=%d|text_base=0x%llx|slide=0x%llx\n",
        (int)arg0, (uint64_t)arg1, (uint64_t)arg2);
}

profile-997
/carrier_pid != 0 ? pid == carrier_pid : (pid == $target || progenyof($target))/
{
    saw_sample = 1;
    @sample_population = count();
    @user_stacks[ustack(32)] = count();
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

tick-10s
{
    bound_elapsed_s += (uint64_t)10;
}

/*
 * Safety net only -- the census normally ends on the target's own exit. A
 * truncated census still emits a clean summary record but with bounded=1,
 * which the reader treats as an error (the marker, not the exit status, is
 * what closes the capture).
 */
tick-10s
/bound_elapsed_s >= bound_limit_s/
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
    printf("HVPCARRIERATTR|section=user-stacks\n");
    printa(@user_stacks);
}
