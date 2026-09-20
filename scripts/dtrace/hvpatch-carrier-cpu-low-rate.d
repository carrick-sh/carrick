#!/usr/sbin/dtrace -qs
/*
 * Low-rate whole-carrier user-stack ranking for an HVPatch workload.
 *
 * WHAT IT MEASURES
 * ----------------
 * Samples scoped executing host threads at profile-97 and preserves every
 * sampled user stack until the target CLI exits. It intentionally has no syscall
 * window, no per-syscall join, and no service timing: the result ranks the
 * carrier's broad execution shape only.
 *
 * The stack containing Applevisor `Vcpu::run` / Carrick's vCPU `run` is an
 * opaque combined guest-execution/HVF/trampoline bucket. Do not attribute that
 * bucket to a Carrick Rust function or call it a host-service cost.
 *
 * LIVE QUALIFICATION
 * ------------------
 * This allocation/counter shape was live-qualified on local Darwin/arm64 on
 * 2026-09-13 with run ID `sep13-dispatch-low-rate`, against the preserved
 * signed candidate SHA-256 `448d46fb7acaca49cdc047bb35071d481599cfbeb7e8195a6b1561d89437ffb8`.
 * `carrick trace --require-script-exit` returned 0; the script summary was
 * `status=ok`, `root_exited=1`, `bounded=0`, `errors=0`, `saw_sample=1`; and
 * authoritative `sample-population=1186` exactly equaled the sum of every
 * emitted user-stack count. The five-million invalid-fstat reducer completed
 * with `other=0` and scoped cleanup zero.
 *
 * This qualification covers the profile-97 scoped stack population and its
 * accounting only. It deliberately does not interpret profile arguments,
 * interrupted register offsets, or kernel PCs, and records no kernel stack.
 * Do not infer kernel/user mode from undocumented profile arguments. The
 * initial 1,173 scalar versus 1,174 stack-count capture remains rejected in
 * `dispatch-carrier-low-rate-initial-rejected.{json,md}`; its racy global
 * `samples++` was replaced by `@sample_population=count()`.
 *
 * PERTURBATION
 * ------------
 * This is diagnostic instrumentation. A 24-frame unwind at 97 Hz is lower rate
 * than the existing 1997 Hz profile, but elapsed time and CPU totals from this
 * capture are not performance measurements. Rank and relative stack share only
 * select a follow-up mechanism; confirm any performance result untraced.
 *
 * CAPTURE ACCEPTANCE
 * ------------------
 * Use `carrick trace --require-script-exit`; the CLI supplies consumer-drop and
 * interruption handling. Retain only CLI exit 0 and this script's `status=ok`.
 * The script itself fails closed on target timeout (90 s), DTrace error, target
 * root non-exit, or zero scoped samples. `sample-population` is the
 * authoritative event count and must equal the sum of all emitted stacks. It
 * prints one complete aggregation at END: no per-slice output and no `trunc()`
 * discard.
 */

#pragma D option quiet
#pragma D option bufsize=96m
#pragma D option aggsize=128m
#pragma D option ustackframes=24

dtrace:::BEGIN
{
    /* Replaced by the Rust profile launcher with the immutable template hash. */
    printf("HVPCARRIERLOW|header|program_sha256=/* CARRICK_HVPCARRIERLOW_PROGRAM_SHA256 */\n");
    started = timestamp;
    root_exited = 0;
    bounded = 0;
    errors = 0;
    saw_sample = 0;
}

/*
 * Exact Mach-O identity of the traced carrier so the raw stack population can
 * be symbolicated offline (`atos -o target/release/carrick -l <text_base>`).
 * Provider ABI: carrick*:::host-image-base(host_pid, runtime_TEXT_base, slide,
 * path), qualified live on Darwin/arm64 (macOS 27.0, 2026-09-19); the probe
 * fires once per carrier before any guest instruction runs.
 */
carrick*:::host-image-base
/pid == $target || progenyof($target)/
{
    printf("HVPCARRIERLOW|image|host_pid=%d|text_base=0x%llx|slide=0x%llx\n",
        (int)arg0, (uint64_t)arg1, (uint64_t)arg2);
}

profile-97
/pid == $target || progenyof($target)/
{
    saw_sample = 1;
    @sample_population = count();
    @user_stacks[ustack(24)] = count();
}

dtrace:::ERROR
{
    errors++;
    printf("HVPCARRIERLOW|error=dtrace|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
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
    printf("HVPCARRIERLOW|summary|status=%s|root_exited=%d|bounded=%d|errors=%d|saw_sample=%d\n",
        root_exited && !bounded && errors == 0 && saw_sample ? "ok" : "error",
        root_exited, bounded, errors, saw_sample);
    printa("HVPCARRIERLOW|sample-population|count=%@d\n", @sample_population);
    printf("HVPCARRIERLOW|section=user-stacks\n");
    printa(@user_stacks);
}
