#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option ustackframes=40

/*
 * OWNER COPYOUT REFUSALS WITHOUT DESCRIPTOR-WALK SAMPLING.
 *
 * Measures write/read admission refusals and syscall EFAULT, following the
 * target and its descendants. The positive control is an owner BIND result.
 * Provider ABI and live-qualified phases are documented in
 * host-copyout-efault-origin.d: write(arg0 VA, arg1 length, arg2 phase,
 * arg3 reason), read(page, length, phase, descriptor), syscall(nr,name,retval).
 * hvpatch-el1-owner-bind-result arg0 is the owner errno; live-qualified by
 * el1-root-admission.d on the same 1dfba1500 artifact. This profile itself
 * still requires live qualification; zero controls, errors or drops fail.
 *
 * Perturbation: no el1-mapping-leaf probe is armed, so publication performs
 * no diagnostic descriptor walks. Stack collection occurs only at refusals.
 * This is diagnostic ordering evidence, never uninstrumented acceptance.
 */

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(0);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 60 && !target_exited/
{
    printf("COPYORIGIN TRUNCATED seconds=%d\n", seconds);
    exit(4);
}

dtrace:::ERROR
{
    errors++;
}

dtrace:::DROP
{
    drops++;
}

carrick*:::guest-internal-write-fault
/pid == $target || progenyof($target)/
{
    printf("WRITE-FAULT pid=%d tid=%d va=0x%x len=%d phase=%d reason=%s\n",
        pid, tid, arg0, arg1, arg2, copyinstr(arg3));
    ustack();
    @refused[arg2, copyinstr(arg3)] = count();
}

carrick*:::hvpatch-el1-owner-bind-result
/pid == $target || progenyof($target)/
{
    owner_bind_controls++;
}

carrick*:::guest-internal-read-fault
/pid == $target || progenyof($target)/
{
    printf("READFAULT ns=%d pid=%d tid=%d page=0x%x len=%d phase=%d live=0x%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3);
    ustack();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (int64_t)arg2 == -14/
{
    printf("EFAULT pid=%d tid=%d nr=%d %s\n", pid, tid, arg0, copyinstr(arg1));
    ustack();
    @efault[copyinstr(arg1)] = count();
}

END
{
    printf("COPYORIGIN summary owner_bind_controls=%d target_exited=%d errors=%d drops=%d\n",
        owner_bind_controls, target_exited, errors, drops);
    printa("refused phase=%d %s: %@d\n", @refused);
    printa("EFAULT %s: %@d\n", @efault);
    if (owner_bind_controls == 0 || errors != 0 || drops != 0) { exit(4); }
}
