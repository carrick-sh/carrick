#pragma D option quiet
#pragma D option bufsize=4m
/*
 * Which native fork owner operation refused, and with what typed cause?
 * ABI: el1-native-fork-refusal(cpu, mm, root GPA, debug reason string).
 * The stock companion carries refusal reason plus requested/cached bindings
 * and requested/cached address contexts as five bounded Debug strings.
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
    printf("NATIVEFORK cpu=%d mm=%d root=0x%llx reason=%s\n", arg0, arg1, (uint64_t)arg2, copyinstr(arg3));
}
carrick*:::hvpatch-el1-root-prepublish
/pid == $target || progenyof($target)/
{ controls++; }
carrick*:::el1-native-fork-stock-refusal
/pid == $target || progenyof($target)/
{
    stock_refusals++;
    printf("NATIVEFORK stock_reason=%s\nrequested_binding=%s\ncached_binding=%s\nrequested_context=%s\ncached_context=%s\n",
        copyinstr(arg0), copyinstr(arg1), copyinstr(arg2), copyinstr(arg3), copyinstr(arg4));
}
carrick*:::trace-witness-exit
/pid == $target/
{ printf("NATIVEFORK witness_wait_status=%d\n", (int32_t)arg0); exited=1; exit(0); }
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 220/
{ printf("NATIVEFORK clone_result=%lld\n", (int64_t)arg2); }
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
    printf("NATIVEFORK controls=%d refusals=%d stock_refusals=%d exited=%d errors=%d drops=%d bounded=%d\n",
        controls, refusals, stock_refusals, exited, errors, drops, bounded);
    if (!controls || !exited || errors || drops || bounded) { exit(4); }
}
