#pragma D option quiet
#pragma D option bufsize=128m
#pragma D option aggsize=128m
#pragma D option dynvarsize=64m

/*
 * Which MODULE owns each user-mode sample?
 *
 * `umod()` resolves an address to its containing mach-o image, so this splits the
 * user population three ways with no snapshot join and no unwinding: carrick's
 * own __TEXT, the dylibs it calls, and addresses in no image at all -- which is
 * the MAP_JIT code cache. That last bucket is the one a snapshot join can miss,
 * and mistaking it for host code is what made the previous read wrong.
 */

carrick*:::dsr-cache-capacity { tracked[pid] = 1; }
carrick*:::dsr-cache-event    { tracked[pid] = 1; }
proc:::create /tracked[pid]/  { tracked[args[0]->pr_pid] = 1; }
proc:::exit   /tracked[pid]/  { tracked[pid] = 0; }

profile-997 /tracked[pid]/ { @all = count(); }
profile-997 /tracked[pid] && arg0 == 0/
{
	@user = count();
	@mod[umod(uregs[R_PC])] = count();
	@sym[usym(uregs[R_PC])] = count();
}

tick-1s { elapsed++; }
tick-1s /elapsed >= 60/ { exit(0); }

END
{
	printa("CPU all=%@u\n", @all);
	printa("CPU user=%@u\n", @user);
	printf("\n== user samples by module ==\n");
	printa(@mod);
	printf("\n== hottest user symbols ==\n");
	trunc(@sym, 24);
	printa(@sym);
}
