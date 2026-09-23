/*
 * Qualify the existing mailbox/register intervention on invalid-contract.
 * ABI from trap.rs and hvf_aarch64_engine.rs: hvf-syscall-transport arg0 is
 * transport (0 legacy, 1 mailbox), arg1 is phase (0 decode, 1 completion),
 * arg2/3/4 are actual register reads/sysreg reads/register writes. Service-begin
 * arg3 is the Linux syscall number. Both events run on the owning executor.
 * Live qualification must reconcile 169 add and 169 remove requests/returns.
 * Legacy still consumes the mailbox; this is NOT an exit-removal experiment.
 * High perturbation: counts only. Never use this capture as timing evidence.
 * Run with carrick trace --require-script-exit; error, absent probes, unmatched
 * target calls, dropped records, or missing guest completion refuse evidence.
 */
#pragma D option quiet
#pragma D option aggsize=4m
#pragma D option dynvarsize=4m

BEGIN { seconds = 0; seen = 0; errors = 0; root_exited = 0; }
carrick*:::hvf-syscall-transport
/(pid == $target || progenyof($target)) && arg1 == 0/
{
    self->decoded = 1;
    self->transport = arg0;
    self->register_reads = arg2;
    self->sysreg_reads = arg3;
}
carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) && (arg3 == 27 || arg3 == 28)/
{
    seen = 1;
    self->nr = arg3;
    @requests[self->transport, self->nr] = count();
    @reads[self->transport, self->nr] = sum(self->register_reads);
    @sysreads[self->transport, self->nr] = sum(self->sysreg_reads);
    @missing_decode[self->transport, self->nr] = sum(!self->decoded);
    self->decoded = 0;
}
carrick*:::hvf-syscall-transport
/(pid == $target || progenyof($target)) && arg1 == 1 && self->nr/
{
    @returns[arg0, self->nr] = count();
    @writes[arg0, self->nr] = sum(arg4);
    self->nr = 0;
}
proc:::exit /pid == $target/ { root_exited = 1; }
dtrace:::ERROR { errors = 1; }
tick-1s { seconds++; }
tick-1s /seconds >= 8/
{
    printf("ITC1|seen=%d|errors=%d|root_exited=%d\n", seen, errors, root_exited);
    printa("ITC1|requests|transport=%d|nr=%d|count=%@d\n", @requests);
    printa("ITC1|returns|transport=%d|nr=%d|count=%@d\n", @returns);
    printa("ITC1|reads|transport=%d|nr=%d|count=%@d\n", @reads);
    printa("ITC1|sysreads|transport=%d|nr=%d|count=%@d\n", @sysreads);
    printa("ITC1|writes|transport=%d|nr=%d|count=%@d\n", @writes);
    printa("ITC1|missing_decode|transport=%d|nr=%d|count=%@d\n", @missing_decode);
    exit(seen && !errors && root_exited ? 0 : 2);
}
