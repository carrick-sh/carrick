/*
 * guest-process-census.d — what does a real workload's PROCESS shape cost us?
 *
 * A whole-run wall-clock ratio ("carrick is 15x Docker on go-build") cannot be
 * acted on: it does not say whether we are slow at ONE long-lived thing or slow
 * a THOUSAND times at a short-lived thing. Those have opposite fixes — the first
 * wants faster steady-state execution, the second wants a cheaper process
 * lifecycle — so measure the shape before choosing.
 *
 * On the native lane one guest process is one host process, so `execve-argv`
 * (fired per guest exec, carrying the host pid) and `guest-exit` bracket a guest
 * process's whole life. Bucketed by executable basename, so a toolchain workload
 * reads as "compile x N, took Y" rather than a wall of pids.
 *
 * DELIBERATELY CHEAP. Both probes fire per guest PROCESS, not per syscall or per
 * context switch, so this costs nothing measurable and the wall clock it reports
 * is comparable to an untraced run. Off-CPU/blocked attribution needs
 * `sched:::off-cpu`, which fires on every context switch on the MACHINE and cost
 * 16x wall clock when it was tried here; that belongs in its own pass against
 * its own question, not bolted onto the census.
 *
 * Partial results are printed every N seconds (arg0, default 5) rather than only
 * at END: a workload under investigation is one that may hang or need killing,
 * and an aggregation that only prints at END yields an empty file when it does.
 *
 * Run (carrick trace owns the child, so the run is covered from pid 1):
 *   target/release/carrick trace -s scripts/dtrace/guest-process-census.d \
 *     -o /tmp/census.txt -- run --exec-backend native <image> <cmd>...
 */
#pragma D option quiet
#pragma D option dynvarsize=64m
#pragma D option bufsize=16m
#pragma D option aggsize=16m
#pragma D option strsize=192
#pragma D option defaultargs

dtrace:::BEGIN
{
	t0 = timestamp;
	live = 0;
	done = 0;
	interval = $1 != 0 ? $1 : 5;
	secs = 0;
}

/* --- guest process identity: arg0 = host pid, arg1 = path, arg2 = argv --- */
carrick*:::execve-argv
{
	pstart[arg0] = timestamp;
	pname[arg0] = basename(copyinstr(arg1));
	live++;
	@execs[basename(copyinstr(arg1))] = count();
}

/*
 * Exit is the only point at which a lifetime is known, so fold this process into
 * the aggregations here.
 */
carrick*:::guest-exit
/pstart[arg0] != 0/
{
	this->life = (timestamp - pstart[arg0]) / 1000;		/* us */
	@life_us[pname[arg0]] = sum(this->life);
	@life_n[pname[arg0]] = count();
	@life_max[pname[arg0]] = max(this->life);
	@life_q[pname[arg0]] = quantize(this->life);
	@all_life = sum(this->life);
	@all_n = count();
	live--;
	done++;
	pstart[arg0] = 0;
	pname[arg0] = 0;
}

tick-1s
{
	secs++;
}

tick-1s
/secs % interval == 0/
{
	printf("\n[t=%3d s] guest processes: %d exited, %d live\n",
	    (timestamp - t0) / 1000000000, done, live);
	printf("  summed guest-process lifetime: ");
	printa("%@d us\n", @all_life);
	printf("  %-26s %8s %12s %12s\n", "image", "n", "total_us", "max_us");
	printa("  %-26s %@8d\n", @life_n);
	printa("  %-26s tot=%@d\n", @life_us);
	printa("  %-26s max=%@d\n", @life_max);
}

END
{
	printf("\n==== GUEST PROCESS CENSUS (final) ====\n");
	printf("run wall: %d ms\n", (timestamp - t0) / 1000000);
	printf("guest processes: %d exited, %d still live\n", done, live);

	printf("\n---- guest processes exec'd (count by image) ----\n");
	printa("  %-28s %@8d\n", @execs);

	printf("\n---- TOTAL over all guest processes ----\n");
	printf("  processes exited: "); printa("%@d\n", @all_n);
	printf("  summed lifetime : "); printa("%@d us\n", @all_life);

	printf("\n---- per image ----\n");
	printa("  %-26s n   =%@d\n", @life_n);
	printa("  %-26s tot =%@d us\n", @life_us);
	printa("  %-26s max =%@d us\n", @life_max);

	printf("\n---- process lifetime distribution (us) ----\n");
	printa("  %s%@d\n", @life_q);
}
