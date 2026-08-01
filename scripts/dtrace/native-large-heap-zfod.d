#!/usr/sbin/dtrace -s
/*
 * Campaign action 1: localize carrick's OWN large-heap first touch.
 *
 * The fault decomposition closes to ~99.5% and puts 66.7% of zero-fill faults
 * (1,254,000, ~20.5 GB per cold `go build`) in carrick's own Rust heap --
 * libmalloc's LARGE zone, which lives at 0x7x_xxxx_xxxx on this host and
 * allocates via `mach_vm_allocate`, NOT `mmap`. That is why it is invisible to
 * every syscall-level instrument: one traced build shows 2,172 `mmap` calls
 * against 1.88 M zfod.
 *
 * This script answers the one question that gates the whole workstream: WHICH
 * carrick allocations. Without it, ranks 2 and 5 risk optimizing the wrong
 * allocator for weeks.
 *
 * ABI qualified live on this host/build (macOS 27, t8132) -- see
 * `scripts/dtrace/native-fault-cost.d` for the full list. The two that matter
 * here: `vminfo:::zfod` arg2 IS the exact 16 KiB host-page base, and
 * `fbt::vm_fault:entry` is listed but never fires (FBT sees no local symbols),
 * so vminfo is the only usable fault probe.
 *
 * The large-zone window was MEASURED, not assumed: on this host
 * `malloc(8 MiB)` lands at 0x7cac400000 and `malloc(200 KiB)` at 0x7737400000,
 * while `mmap(1 GiB)` lands at 0x106ec4000 -- so [0x70_0000_0000,
 * 0x80_0000_0000) selects the large zone and excludes both the guest arena
 * (bias 0x80_0000_0000) and ordinary mmap.
 *
 * SAMPLING: 1-in-8 by page, deterministic. Exact all-page aggregation made
 * libdtrace spin in `dtrace_aggregate_snap` on this workload (see
 * native-fault-attribution.d's header), so the sample is the supported shape.
 * It ranks call sites; it is not a lossless census.
 *
 * SYMBOLIZATION IS BROKEN FOR THIS WORKLOAD -- the totals above are sound, the
 * `@sites` ranking is NOT. Measured 2026-08-01, recorded so nobody trusts it:
 * a cold `go build` runs ~70 carrick processes (self-re-exec per guest exec),
 * nearly all dead by END, each with its own ASLR slide. `ustack()` then does
 * something worse than fail -- it resolves surviving frames against the WRONG
 * process image and prints PLAUSIBLE BUT FALSE symbol names. The observed
 * output had `serde_json::serialize_field -> hashbrown::RawTable::drop ->
 * read`, which is not a call chain that exists, and all top stacks tied at
 * exactly count=154, which is per-process aliasing rather than a ranking.
 * The tell is uniform counts plus the same raw address symbolizing DIFFERENTLY
 * in different stacks. A guest `sleep` hold does not fix it: it keeps ONE
 * process alive, and that one lends its symbols to everyone else's frames.
 *
 * So: use this script for the WINDOW DECOMPOSITION (which reproduces exactly:
 * zfod_all 1,878,112 / large zone 1,252,285 / guest arena 561,454) and get
 * call-site attribution another way. The supported route is to instrument
 * carrick itself in Rust rather than to symbolize it from outside -- per
 * AGENTS.md, Rust first and extend `carrick trace`/`carrick debug`. A
 * `ustack()` capture here can only be trusted if every faulting process is
 * alive at END, which this workload structurally prevents.
 *
 * Kernel providers only, `execname`-scoped, plain `-s`; never `-c`/`-p`
 * against a live native guest, per AGENTS.md. This script PERTURBS (the zfod
 * probe fires ~1.9 M times per build); it ranks sites, it does not price them.
 *
 * Directional evidence, never a promotion artifact.
 */
#pragma D option quiet
#pragma D option aggsize=128m
#pragma D option dynvarsize=32m
#pragma D option bufsize=32m
#pragma D option ustackframes=20

dtrace:::BEGIN
{
	timed_out = 0;
	printf("NLHZ1|config|scope=execname-carrick|page_sample_modulus=8|window=0x7000000000-0x8000000000\n");
}

tick-45s
{
	timed_out = 1;
	exit(0);
}

/* Denominators first, so every share below is quoted against a real total. */
vminfo:::zfod /execname == "carrick"/ { @zfod_all = count(); }

vminfo:::zfod
/execname == "carrick" && arg2 >= 0x7000000000 && arg2 < 0x8000000000/
{
	@zfod_large = count();
}

/* The ranking itself, sampled 1-in-8 by page. */
vminfo:::zfod
/execname == "carrick" && arg2 >= 0x7000000000 && arg2 < 0x8000000000 &&
    ((arg2 >> 14) & 0x7) == 0/
{
	@sites[ustack(20)] = count();
	@sampled = count();
}

/* Where else does the mass land, so a miss is visible rather than silent? */
vminfo:::zfod
/execname == "carrick"/
{
	@by_window[arg2 >> 32] = count();
}

dtrace:::END
{
	printa("NLHZ1|total|kind=zfod_all|count=%@u\n", @zfod_all);
	printa("NLHZ1|total|kind=zfod_large_zone|count=%@u\n", @zfod_large);
	printa("NLHZ1|total|kind=sampled|count=%@u\n", @sampled);
	trunc(@by_window, 12);
	printa("NLHZ1|window|prefix=%#x|count=%@u\n", @by_window);
	trunc(@sites, 12);
	printa("NLHZ1|site|count=%@u\n%k", @sites);
	printf("NLHZ1|complete|timed_out=%d\n", timed_out);
}
