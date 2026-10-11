#pragma D option quiet
/*
 * WHY DOES A NATIVE FORK CHILD EXHAUST ITS EL1 COW GRANTS?
 * Measures host owner-grant supply phases, host frame-COW triggers and
 * refusal text from start of the signed child-status fixture. The source ABI
 * is hvpatch-el1-owner-grant-supply(address,len,phase,detail),
 * hvpatch-frame-cow-trigger(va,syndrome,far,ttbr0), and
 * guest-internal-write-fault(address,len,phase,error). The provider wildcard
 * and phase meanings are qualified in el1-terminal-cow-supply.d; this script
 * prints only the first 80 scalar events and aggregates all phase counts.
 * Perturbation: USDT fault/supply events only, no stacks or per-copy probes.
 */
dtrace:::BEGIN { events = 0; errors = 0; controls = 0; roots = 0; }
carrick*:::hvpatch-el1-root-prepublish
/(pid == $target || progenyof($target))/ { controls++; roots++; }
carrick*:::hvpatch-el1-owner-grant-supply
/(pid == $target || progenyof($target))/
{
    controls++; @supply[arg2, arg3] = count();
    if (events++ < 80) printf("EFCOW|supply|phase=%d|va=0x%x|len=%d|detail=%d\n", arg2,arg0,arg1,arg3);
}
carrick*:::hvpatch-frame-cow-trigger
/(pid == $target || progenyof($target))/
{
    controls++; @trigger[arg1] = count();
    if (events++ < 80) printf("EFCOW|host-cow|va=0x%x|esr=0x%x|far=0x%x|ttbr=0x%x\n", arg0,arg1,arg2,arg3);
}
carrick*:::guest-internal-write-fault
/(pid == $target || progenyof($target)) && arg2 == 26/
{
    controls++;
    if (events++ < 80) printf("EFCOW|refusal|%s\n",copyinstr(arg3));
}
dtrace:::ERROR { errors++; }
proc:::exit /pid == $target/ { exit(controls == 0 || errors != 0 ? 3 : 0); }
tick-1s { seconds++; }
tick-1s /seconds >= 300/ { exit(4); }
END { printf("EFCOW|events=%d|controls=%d|roots=%d|errors=%d\n",events,controls,roots,errors); printa(@supply); printa(@trigger); }
