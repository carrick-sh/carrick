#pragma D option quiet
#pragma D option bufsize=256m
#pragma D option aggsize=256m
#pragma D option dynvarsize=96m

/*
 * ONE run, one denominator: where does carrick's CPU go?
 *
 * profile-997 fires per CPU while a tracked thread is on-CPU, so
 * samples/997 IS aggregate CPU-seconds -- that is the denominator every share
 * below is quoted against. Everything else in this script divides it up:
 *
 *   arg0 != 0            -> kernel
 *   arg0 == 0            -> user, and uregs[R_PC] is the exact user PC, which
 *                           the offline classifier joins against per-process JIT
 *                           snapshots to split guest words from inserted words
 *   syscall/mach_trap    -> vtimestamp, so kernel time attributable to a NAMED
 *                           entry point, leaving the remainder as faults,
 *                           scheduling and interrupts
 *
 * No ustack(): JIT frames have no unwind info. No stack(): measured, macOS/arm64
 * kernel frames mostly do not walk out of exception context. No copyin: it killed
 * guests 2/2. Kernel providers only.
 */

/*
 * Track by carrick's own lifecycle USDT probes under `dtrace -Z`, not by
 * `execname`. execname is the binary's basename, so it silently tracks NOTHING
 * the moment the binary is not literally called "carrick" -- which is exactly
 * what happens when comparing two built arms side by side.
 *
 * `dsr-cache-capacity` fires once per process from `ProcessTranslator::new`, so
 * every guest process announces itself before it translates anything. These are
 * lifecycle probes in carrick's own host code, not pid-provider probes on a hot
 * guest path, so the fasttrap hazard does not apply.
 */
carrick*:::dsr-cache-capacity { tracked[pid] = 1; }
carrick*:::dsr-cache-event    { tracked[pid] = 1; }
proc:::create /tracked[pid]/  { tracked[args[0]->pr_pid] = 1; }
proc:::exit   /tracked[pid]/  { tracked[pid] = 0; }

profile-997 /tracked[pid]/ { @all = count(); }
profile-997 /tracked[pid] && arg0 != 0/ { @kern = count(); }
profile-997 /tracked[pid] && arg0 == 0/
{
	@user = count();
	@pc[pid, uregs[R_PC]] = count();
}

syscall:::entry /tracked[pid]/ { self->s = vtimestamp; }
syscall:::return /tracked[pid] && self->s/
{
	@sc = sum(vtimestamp - self->s);
	@sc_by[probefunc] = sum(vtimestamp - self->s);
	@sc_n[probefunc] = count();
	self->s = 0;
}

mach_trap:::entry /tracked[pid]/ { self->m = vtimestamp; }
mach_trap:::return /tracked[pid] && self->m/
{
	@mt = sum(vtimestamp - self->m);
	self->m = 0;
}

vminfo:::zfod      /tracked[pid]/ { @zfod = count(); }
vminfo:::cow_fault /tracked[pid]/ { @cow = count(); }
vminfo:::as_fault  /tracked[pid]/ { @as = count(); }

tick-1s { elapsed++; }
tick-1s /elapsed >= 60/ { exit(0); }

END
{
	printa("CPU all=%@u\n", @all);
	printa("CPU kern=%@u\n", @kern);
	printa("CPU user=%@u\n", @user);
	printa("NS syscall=%@u\n", @sc);
	printa("NS machtrap=%@u\n", @mt);
	printa("FAULT zfod=%@u\n", @zfod);
	printa("FAULT cow=%@u\n", @cow);
	printa("FAULT as=%@u\n", @as);
	printf("\n== syscall on-CPU ns ==\n");
	trunc(@sc_by, 14);
	printa("SC %-22s %@12u\n", @sc_by);
	printf("\n== user PCs ==\n");
	trunc(@pc, 40000);
	printa("PC %d 0x%x %@u\n", @pc);
}
