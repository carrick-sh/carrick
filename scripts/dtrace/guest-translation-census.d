/*
 * guest-translation-census.d — how much of a workload's cost is TRANSLATION,
 * and how much of that translation is work we have already done before?
 *
 * The native (DSR) lane translates guest code into a per-process JIT cache. That
 * cache dies with the process. A toolchain workload re-executes the SAME few
 * binaries dozens of times (`go build` of one file runs `compile` 27x and `asm`
 * 34x), so if translation is a material cost, we are paying it again for
 * identical machine code on every invocation — which a file-backed, executable-
 * keyed AOT cache would pay once.
 *
 * That claim is falsifiable, so measure it rather than assert it:
 *
 *   bytes/blocks translated PER IMAGE, and the invocation count for that image.
 *     `compile` translating N bytes across 27 runs, with each run translating
 *     roughly N/27, means the same code is being re-translated per process and
 *     an AOT cache removes ~26/27 of it. If instead each run translates a
 *     disjoint slice, there is nothing to reuse and the AOT direction is wrong.
 *   translate WALL TIME per image.
 *     Bytes are only a proxy. This is the number that has to be big enough to
 *     matter against the process's own lifetime before any of it is worth doing.
 *
 * Pair with guest-process-census.d, which reports those lifetimes: translation
 * time as a FRACTION of process lifetime is the actual decision input.
 *
 * NOTE this one is not cheap -- `dsr-translate-*` fires per translated block,
 * which is millions of events on a toolchain workload. It distorts wall clock.
 * Proportions are what it measures; take lifetimes from the cheap census.
 *
 * Run:
 *   target/release/carrick trace -s scripts/dtrace/guest-translation-census.d \
 *     -o /tmp/xlat.txt -- run --exec-backend native <image> <cmd>...
 */
#pragma D option quiet
#pragma D option dynvarsize=256m
#pragma D option bufsize=32m
#pragma D option aggsize=32m
#pragma D option strsize=192
#pragma D option defaultargs

dtrace:::BEGIN
{
	t0 = timestamp;
	interval = $1 != 0 ? $1 : 10;
	secs = 0;
}

carrick*:::execve-argv
{
	pname[arg0] = basename(copyinstr(arg1));
	@runs[basename(copyinstr(arg1))] = count();
}

/* arg0 = tid, arg1 = guest_pc, arg2 = generation */
carrick*:::dsr-translate-begin
/pname[pid] != 0/
{
	self->xt = timestamp;
}

/* arg0 = tid, arg1 = guest_pc, arg2 = cache_pc, arg3 = emitted_bytes */
carrick*:::dsr-translate-end
/self->xt != 0/
{
	@xlat_ns[pname[pid]] = sum(timestamp - self->xt);
	@xlat_n[pname[pid]] = count();
	@xlat_bytes[pname[pid]] = sum(arg3);
	@all_ns = sum(timestamp - self->xt);
	@all_n = count();
	@all_bytes = sum(arg3);
	/*
	 * Distinct guest PCs translated, per image. If the same PC shows up in
	 * run after run, that is the re-translation an AOT cache elides; the
	 * per-image block count divided by the run count says how much of the
	 * work each individual process repeats.
	 */
	@pcs[pname[pid], arg1] = count();
	self->xt = 0;
}

tick-1s
{
	secs++;
}

tick-1s
/secs % interval == 0/
{
	printf("\n[t=%3d s] translation so far\n", (timestamp - t0) / 1000000000);
	printf("  blocks: "); printa("%@d", @all_n);
	printf("   bytes: "); printa("%@d", @all_bytes);
	printf("   time: "); printa("%@d us\n", @all_ns);
	printf("  %-22s %12s %14s %14s\n", "image", "runs", "blocks", "xlat_us");
	printa("  %-22s runs  =%@d\n", @runs);
	printa("  %-22s blocks=%@d\n", @xlat_n);
	printa("  %-22s bytes =%@d\n", @xlat_bytes);
	printa("  %-22s xlat  =%@d ns\n", @xlat_ns);
}

END
{
	printf("\n==== TRANSLATION CENSUS (final) ====\n");
	printf("run wall: %d ms\n", (timestamp - t0) / 1000000);
	printf("\n  total blocks translated: "); printa("%@d\n", @all_n);
	printf("  total bytes emitted    : "); printa("%@d\n", @all_bytes);
	printf("  total translate time   : "); printa("%@d ns\n", @all_ns);

	printf("\n---- per image ----\n");
	printa("  %-22s runs  =%@d\n", @runs);
	printa("  %-22s blocks=%@d\n", @xlat_n);
	printa("  %-22s bytes =%@d\n", @xlat_bytes);
	printa("  %-22s xlat  =%@d ns\n", @xlat_ns);

	/*
	 * The re-translation proof. `count()` here is how many times a single
	 * guest PC was translated across the whole run: a value of ~27 against
	 * `compile` is the same block being translated once per invocation.
	 */
	printf("\n---- most-repeatedly-translated guest PCs (image, pc, times) ----\n");
	trunc(@pcs, 25);
	printa("  %-22s 0x%-16x %@8d\n", @pcs);
}
