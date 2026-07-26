/*
 * native-cpu-attribution.d — what fraction of carrick's CPU is TRANSLATION?
 *
 * WHY SAMPLING, NOT BRACKETING. The obvious way to time translation is to
 * bracket it: timestamp at `dsr-translate-begin`, subtract at
 * `dsr-translate-end`. That is wrong here, and measurably so. A toolchain
 * workload translates ~1.5M blocks, so bracketing fires ~3M USDT probes and each
 * probe pair's own cost lands INSIDE the window it is timing. The result
 * reported 17.7 s of "translation" inside a 19 s window -- almost all of it
 * probe overhead, and it would have justified any conclusion at all.
 *
 * Sampling has no such feedback: `profile-997` interrupts wherever the thread
 * happens to be, and the FRACTION of samples landing in a given frame is the
 * fraction of CPU spent there. Probe cost is proportional to the sample rate,
 * not to the workload's block count, so the measurement does not scale with the
 * thing it measures. Use the cheap per-block probes for COUNTS (exact, and
 * count() needs no timestamp) and this for TIME.
 *
 * WHY THE WINDOWED AGGREGATIONS ARE PRINTED AND CLEARED. DTrace resolves a user
 * stack to symbols when it PRINTS it, using the mappings of the process the
 * sample came from -- so a stack printed after that process exited resolves to
 * bare hex. Guest processes here are short-lived forked children, i.e. exactly
 * the population doing the work, so an aggregation printed only at END loses
 * symbols for almost everything that matters. Printing each window while its
 * processes are still alive is what makes the output readable; `clear()` then
 * keeps each window an independent view of what is running now.
 *
 * Raw PCs are ALSO aggregated, uncleared, and dumped at END for offline
 * symbolication (`scripts/symbolicate.py`) — belt and braces for anything whose
 * process still managed to exit inside its own window.
 *
 * Run:
 *   target/release/carrick trace -s scripts/dtrace/native-cpu-attribution.d \
 *     -o /tmp/cpu.txt -- run --exec-backend native <image> <cmd>...
 * Or attach to a workload already in flight (arg0 = seconds, arg1 = window):
 *   sudo dtrace -q -s scripts/dtrace/native-cpu-attribution.d 60 10
 */
#pragma D option quiet
#pragma D option dynvarsize=64m
#pragma D option bufsize=32m
#pragma D option aggsize=32m
#pragma D option defaultargs
#pragma D option ustackframes=12

dtrace:::BEGIN
{
	limit = $1 != 0 ? $1 : 90;
	window = $2 != 0 ? $2 : 5;
	secs = 0;
	printf("sampling carrick on-CPU: %d s limit, %d s windows\n", limit, window);
}

/*
 * 997 Hz rather than 1000: a prime rate cannot beat against a workload timer
 * running at a round frequency, which would sample the same phase every time and
 * report a hot spot that is an artefact of the alignment.
 */
/*
 * Image announcements, printed as they happen rather than aggregated: one line
 * per guest process, and they must survive that process's exit to be useful.
 * `scripts/symbolicate.py` reads these to build a pid -> image map, which is
 * what lets a PC sampled from a long-dead process still resolve to a symbol.
 */
carrick*:::host-image-base
{
	printf("IMGBASE host pid=%d base=0x%x slide=%d path=%s\n",
	    arg0, arg1, (int)arg2, copyinstr(arg3));
}

carrick*:::guest-image-base
{
	printf("IMGBASE guest pid=%d base=0x%x entry=0x%x path=%s\n",
	    arg0, arg1, arg2, copyinstr(arg3));
}

profile-997
/execname == "carrick" && arg1 != 0/
{
	@total = count();
	@win_frame[ufunc(arg1)] = count();
	@win_stack[ustack()] = count();
	/*
	 * Keyed by pid, not by bare PC: guest processes self-reexec, so the SAME
	 * address means different code in different processes and a pid-less
	 * histogram silently merges them.
	 */
	@pc[pid, arg1] = count();
}

/* Kernel-side time, same population: a syscall storm shows up here, not above. */
profile-997
/execname == "carrick" && arg0 != 0/
{
	@ktotal = count();
	@win_kframe[func(arg0)] = count();
}

tick-1s
{
	secs++;
}

/*
 * Each window is printed while the processes that produced it are still alive,
 * so symbols resolve, then cleared so the next window stands alone.
 */
tick-1s
/secs % window == 0/
{
	printf("\n======== window ending t=%d s ========\n", secs);
	printf("cumulative user samples: "); printa("%@d\n", @total);

	printf("\n-- user frames this window --\n");
	printa("  %-56A %@8d\n", @win_frame);

	printf("\n-- kernel frames this window --\n");
	printa("  %-56a %@8d\n", @win_kframe);

	/*
	 * Truncated: printing EVERY accumulated stack each window produced a
	 * 30-million-line file whose 22M stack-frame lines swamped the actual
	 * 109k-sample histogram. The heaviest few are what a stack view is for.
	 */
	printf("\n-- heaviest user stacks this window --\n");
	trunc(@win_stack, 10);
	printa("%k  %@d\n", @win_stack);

	clear(@win_frame);
	clear(@win_kframe);
	clear(@win_stack);
}

tick-1s
/secs >= limit/
{
	exit(0);
}

END
{
	printf("\n==== CPU ATTRIBUTION (totals) ====\n");
	printf("user-mode samples  : "); printa("%@d\n", @total);
	printf("kernel-mode samples: "); printa("%@d\n", @ktotal);
	printf("(at 997 Hz, samples/997 = thread-seconds of CPU)\n");

	/*
	 * Raw per-pid PC histogram for offline symbolication, consumed together
	 * with the IMGBASE lines above by `scripts/symbolicate.py`.
	 */
	printf("\n---- RAW PC HISTOGRAM (symbolicate offline) ----\n");
	printa("PC %d 0x%-16x %@10d\n", @pc);
}
