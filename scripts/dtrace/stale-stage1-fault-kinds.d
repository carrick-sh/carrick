/*
 * stale-stage1-fault-kinds.d — what kind of fault reached the host's stale
 * stage-1 path, and did it cost a TLB-maintenance round trip?
 *
 * WHAT: every `hvpatch-stale-stage1-fault` decision (the live leaf already
 * permits the access) with its kind and whether it invalidated, plus the
 * Maintenance-class (5) vCPU exits and their count, so a maintenance exit
 * a contract does not budget can be attributed to stale-fault retries.
 *
 * ABI:
 * - hvpatch-stale-stage1-fault: arg0 FAR, arg1 kind (0 translation,
 *   1 access flag, 2 permission), arg2 invalidated (0/1), arg3 consecutive
 *   stale faults at this FAR (added 2026-10-01).
 * - vcpu-run-exit: arg1 exit class (5 Maintenance).
 *
 * PERTURBATION: low (one printf per stale fault). Takes the traced
 * process's executable name as $$1 (USDT is armed in every carrick on the
 * host); exits when a process of that name exits; bounded at 300 s.
 */
#pragma D option quiet

dtrace:::BEGIN { printf("ready\n"); }

carrick*:::hvpatch-stale-stage1-fault
/execname == $$1/
{
	printf("STALE far=0x%x kind=%d invalidated=%d retries=%d\n", arg0, arg1,
	    arg2, arg3);
	@stale[arg1, arg2] = count();
}

carrick*:::vcpu-run-exit
/execname == $$1 && arg1 == 5/
{
	@maint = count();
}

proc:::exit /execname == $$1/ { exit(0); }

tick-300s { exit(0); }

dtrace:::END
{
	printa("STALE_KIND %d invalidated=%d %@u\n", @stale);
	printa("MAINTENANCE %@u\n", @maint);
}
