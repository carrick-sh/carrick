#pragma D option quiet
#pragma D option bufsize=4m
/*
 * Which native fork owner operation refused, and with what typed cause?
 * ABI: el1-native-fork-refusal(cpu, mm, root GPA, debug reason string).
 * Root-prepublish is the positive control when a corrected fork succeeds.
 * The diagnostic is failure-only, bounded, and grants no memory authority.
 * Perturbation: scalar lifecycle records plus one bounded string on refusal;
 * no descriptor walks, stacks, logging, or workload changes.
 * The 300s bound includes the signed runner's cached build/sign/negative control.
 * External signed runners close through trace-witness-exit (raw Unix wait
 * status), since proc:::exit is unavailable on some SIP-protected Macs.
 * carrick trace also rejects libdtrace consumer drops, including hosts without
 * a dtrace:::DROP provider. The capture status is not the workload verdict.
 */
carrick*:::el1-native-fork-refusal
/pid == $target || progenyof($target)/
{
    refusals++;
    printf("NATIVEFORK cpu=%d mm=%d root=0x%x reason=%s\n", arg0, arg1, arg2, copyinstr(arg3));
}
carrick*:::hvpatch-el1-root-prepublish
/pid == $target || progenyof($target)/
{ controls++; }
carrick*:::trace-witness-exit
/pid == $target/
{ printf("NATIVEFORK witness_wait_status=%d\n", (int32_t)arg0); exited=1; exit(0); }
proc:::exit
/pid == $target/
{ exited=1; exit(0); }
tick-1s { seconds++; }
tick-1s
/seconds >= 300 && !exited/
{ bounded=1; exit(4); }
dtrace:::ERROR { errors++; }
dtrace:::DROP { drops++; }
END
{
    printf("NATIVEFORK controls=%d refusals=%d exited=%d errors=%d drops=%d bounded=%d\n",
        controls, refusals, exited, errors, drops, bounded);
    if (!controls || !exited || errors || drops || bounded) { exit(4); }
}
