/*
 * dsr-live-arena.d — container-lifetime LIVE translation arena outcomes.
 *
 * WHAT IT MEASURES
 *   Per guest process, every named outcome of one live-arena consultation,
 *   plus the revocations that throw published code away:
 *     - kind 13 live-ready-hit          a fresh serve of another publisher's
 *                                       READY record (sharing actually paid);
 *     - kind 14 live-winner-publish     this process published the block;
 *     - kind 15 live-cas-loss           it lost the block claim;
 *     - kind 16 live-private-fallback   a named ineligibility (BUILDING,
 *                                       regenerated, cross-page, capacity …);
 *     - kind 17 live-validation-refusal a record was found and REFUSED;
 *     - kind 18 live-stale-abort-recovered  an instruction abort inside a
 *                                       revoked chunk, recovered privately;
 *   and `dsr-live-chunk-revoked`, one fire per exact 64 KiB RX chunk this
 *   task protected PROT_NONE after its guest source page was mutated.
 *   `translation-attempts` is the denominator: without it a READY-hit count
 *   says nothing about the share of translations sharing replaced.
 *
 *   Kind 16 deliberately does NOT fire for the policy-off `Unconfigured`
 *   fallback: that is every authoritative miss on the shipped default, so a
 *   probe there would sit on the default translate path. A capture with the
 *   live arena off therefore records ZERO outcomes — and this profile treats
 *   zero events as an ERROR, not an empty summary, so "I forgot
 *   CARRICK_DSR_LIVE_ARENA=compiler" fails loudly instead of reporting a
 *   clean nothing.
 *
 * PROVIDER ABI FACTS (qualified live on this host, Darwin 27.0.0 arm64)
 *   - carrick*:::dsr-cache-event  arg0=tid, arg1=kind ordinal (u32),
 *     arg2=guest PC, arg3=code generation, arg4=PRIVATE cache used bytes.
 *     The live kinds share the probe with the private-cache kinds 1..6 and
 *     the direct-binding kinds 7..12; this profile screens arg1 >= 13 so the
 *     two vocabularies never mix (`dsr-indirect.d` owns 7..12).
 *   - carrick*:::dsr-live-chunk-revoked  arg0=guest source page,
 *     arg1=chunk index (u32), arg2=local RX start, arg3=local RX end.
 *     It carries NO tid on purpose: revocation runs on the guest
 *     memory-mutation seam, which has no guest thread in scope.
 *   - The probes are carrick's own USDT, so `-Z` (arm before the process
 *     starts) is required; `carrick trace` supplies it. Screening is on
 *     `pid == $target || progenyof($target)` and NEVER on `execname`: the
 *     host self-re-exec means the two arms of one run can be built under
 *     different binary names.
 *   - `proc:::exit` arg0 is the macOS CLD_* reason (CLD_EXITED == 1).
 *
 * PERTURBATION
 *   Low but NOT zero. The screened probes fire once per live consultation
 *   and once per revoked chunk — thousands per compiler process, not the
 *   millions of `dsr-run-*`. Same-instrument ratios only: never compare a
 *   traced arm's CPU against an untraced one.
 */

#pragma D option quiet

BEGIN
{
	/*%CARRICK_LIVE_ARENA_HEADER%*/
	tracked[$target] = 1;
	active = 1;
	@outcome[$target, 13] = sum(0);
	@outcome[$target, 14] = sum(0);
	@outcome[$target, 15] = sum(0);
	@outcome[$target, 16] = sum(0);
	@outcome[$target, 17] = sum(0);
	@outcome[$target, 18] = sum(0);
	@revoked_chunks[$target] = sum(0);
	@translation_attempts[$target] = sum(0);
}

proc:::exit
/pid == $target/
{
	target_exit_reason = arg0;
}

proc:::create
/(pid == $target || progenyof($target))/
{
	tracked[args[0]->pr_pid] = 1;
	active++;
}

proc:::exit
/(pid == $target || progenyof($target)) && tracked[pid] && active == 1/
{
	tracked[pid] = 0;
	active = 0;
	exit(0);
}

proc:::exit
/(pid == $target || progenyof($target)) && tracked[pid] && active > 1/
{
	tracked[pid] = 0;
	active--;
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 >= 13/
{
	@outcome[pid, arg1] = sum(1);
	@outcome_pc[pid, arg1, arg2] = sum(1);
}

carrick*:::dsr-live-chunk-revoked
/(pid == $target || progenyof($target))/
{
	@revoked_chunks[pid] = sum(1);
	/*
	 * Both per-page aggregations key on arg0, the guest SOURCE PAGE, so the
	 * emitted `source_pc` field stays a guest address. The local RX extent
	 * (arg2..arg3) is a host address in a different domain and is summed as
	 * BYTES, never used as a key.
	 */
	@revoked_page[pid, arg0] = sum(1);
	@revoked_extent[pid, arg0] = sum(arg3 - arg2);
}

carrick*:::dsr-translate-begin
/(pid == $target || progenyof($target))/
{
	@translation_attempts[pid] = sum(1);
}

tick-1s
{
	secs++;
}

tick-1s
/secs >= 300/
{
	bounded = 1;
	exit(0);
}

END
{
	printa("DSRPROF1|count|phase=live-outcome|pid=%d|kind=%d|value=%@d\n", @outcome);
	printa("DSRPROF1|count|phase=live-outcome-pc|pid=%d|kind=%d|source_pc=%#x|value=%@d\n", @outcome_pc);
	printa("DSRPROF1|count|phase=live-revocation-chunks|pid=%d|value=%@d\n", @revoked_chunks);
	printa("DSRPROF1|count|phase=live-revocation-page|pid=%d|source_pc=%#x|value=%@d\n", @revoked_page);
	printa("DSRPROF1|count|phase=live-revocation-bytes|pid=%d|source_pc=%#x|value=%@d\n", @revoked_extent);
	printa("DSRPROF1|count|phase=translation-attempts|pid=%d|value=%@d\n", @translation_attempts);
	printf("DSRPROF1|complete|profile=dsr-live-arena|bounded=%d|target_exit_reason=%d\n",
	    bounded, target_exit_reason);
}
