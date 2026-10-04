/*
 * Which host work grows with one shell fork/exec creation?
 * Aggregate the common pre-Phase-B and Phase-B USDT lifecycle, forwarded
 * syscall service, scheduler and topology-lock events, plus host syscall and
 * Mach-trap entries. Follow the carrier with progenyof($target); a pid-provider
 * probe on the outer CLI would miss it. No guest-memory pointers are read.
 *
 * Qualification status: source ABI declarations checked at 5e23be1a2 and
 * 1e61be8e8. NO LIVE CAPTURE IS QUALIFIED YET. The attempted base invocation
 * rejected its absent trace CLI before launch. Use a current trace consumer's
 * --external launcher to preserve the original measured artifacts; require
 * --require-script-exit. The consumer must reject drops and interruptions.
 *
 * ABI from carrick-observability/probes.rs: guest-lifecycle arg0 phases
 * 0=root, 1=fork, 2=exec, 3=thread-start, 4=thread-exit, 5=process-exit,
 * 6=exec-begin; syscall-service-begin arg3=Linux syscall number;
 * topology-lock arg0=operation, arg1=phase (1=acquired), arg4=elapsed ns;
 * exec-runtime-stage arg0=stage, arg1=elapsed ns; fork-runtime-stage
 * arg0=stage, arg4=elapsed ns; scheduler-wake arg1=kind, arg2=found state.
 * These ABI facts require live firing/closure qualification for each artifact.
 * Topology locks are counted explicitly; this is NOT a CloneAdmissionGate
 * census, whose internal operations have no USDT binding in these artifacts.
 *
 * Perturbation: one aggregation per selected event, including all host syscall
 * and Mach-trap entries. Structural counts and same-instrument stage sums are
 * diagnostic; traced wall time is never performance evidence. Require natural
 * zero-status root exit, balanced execs, forks, service entries and zero
 * consumer drops/errors. A zero thread-start count is meaningful only after
 * the other lifecycle phases fire. The watchdog fails closed after 45 seconds.
 */
#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option aggsize=16m

dtrace:::BEGIN
{ started = timestamp; forks = 0; begins = 0; execs = 0; services = 0; errors = 0; seen = 0; code = -1; bounded = 0; }

carrick*:::hvpatch-guest-lifecycle
/pid == $target || progenyof($target)/
{ @lifecycle[arg0] = count(); forks += arg0 == 1; begins += arg0 == 6; execs += arg0 == 2; }

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{ services++; @service[arg3] = count(); }

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg1 == 1/
{ @locks[arg0] = count(); }

carrick*:::hvpatch-exec-runtime-stage
/pid == $target || progenyof($target)/
{ @exec_stage_n[arg0] = count(); @exec_stage_ns[arg0] = sum(arg1); }

carrick*:::hvpatch-fork-runtime-stage
/pid == $target || progenyof($target)/
{ @fork_stage_n[arg0] = count(); @fork_stage_ns[arg0] = sum(arg4); }

carrick*:::hvpatch-scheduler-wake
/pid == $target || progenyof($target)/
{ @wake[arg1, arg2] = count(); }

carrick*:::hvpatch-executor-claim,
carrick*:::hvpatch-lease-settle,
carrick*:::vcpu-run-enter
/pid == $target || progenyof($target)/
{ @execution[probename] = count(); }

syscall:::entry
/pid == $target || progenyof($target)/
{ @host[probefunc] = count(); }

mach_trap:::entry
/pid == $target || progenyof($target)/
{ @mach[probefunc] = count(); }

syscall::exit:entry
/pid == $target/
{ seen = 1; code = (int)arg0; }

proc:::exit
/pid == $target/
{ exit(seen && code == 0 && forks > 0 && begins > 0 && begins == execs && services > 0 && errors == 0 ? 0 : 2); }

dtrace:::ERROR
{ errors++; exit(3); }

tick-1s
/timestamp - started > 45 * 1000000000/
{ bounded = 1; exit(4); }

dtrace:::END
{
    printf("SPAWNWORK1|summary|forks=%d|begins=%d|execs=%d|services=%d|errors=%d|seen=%d|code=%d|bounded=%d\n", forks, begins, execs, services, errors, seen, code, bounded);
    printa("SPAWNWORK1|lifecycle|phase=%d|count=%@d\n", @lifecycle);
    printa("SPAWNWORK1|service|nr=%d|count=%@d\n", @service);
    printa("SPAWNWORK1|topology-lock|operation=%d|count=%@d\n", @locks);
    printa("SPAWNWORK1|exec-stage|phase=%d|count=%@d\n", @exec_stage_n);
    printa("SPAWNWORK1|exec-stage|phase=%d|ns=%@d\n", @exec_stage_ns);
    printa("SPAWNWORK1|fork-stage|phase=%d|count=%@d\n", @fork_stage_n);
    printa("SPAWNWORK1|fork-stage|phase=%d|ns=%@d\n", @fork_stage_ns);
    printa("SPAWNWORK1|wake|kind=%d|state=%d|count=%@d\n", @wake);
    printa("SPAWNWORK1|execution|event=%s|count=%@d\n", @execution);
    printa("SPAWNWORK1|host|name=%s|count=%@d\n", @host);
    printa("SPAWNWORK1|mach|name=%s|count=%@d\n", @mach);
}
