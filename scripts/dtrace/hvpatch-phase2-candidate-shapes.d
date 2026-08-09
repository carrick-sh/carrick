/*
 * hvpatch-phase2-candidate-shapes.d — classify the arguments of the cold-build
 * syscall exits that hybrid.md proposes to handle without a host dispatch.
 *
 * Provider ABI qualified on Darwin/arm64 on 2026-08-08 against
 * `carrick*:::syscall-entry`: arg0 is the canonical AArch64 syscall number,
 * arg1 is a host `char *` name, and arg2 is a host pointer to six u64 syscall
 * arguments. The action copyins only arg2. The predicate follows Carrick's
 * current fork/exec descendants.
 *
 * Perturbation: one six-word copyin and aggregation updates for the five
 * selected syscall numbers. Counts/shapes are citable; time is not. The trace
 * exits when the launch child exits, with a 90 s failure bound.
 */

#pragma D option quiet
#pragma D option bufsize=16m

dtrace:::BEGIN
{
	printf("HVPATCH2SHAPE|begin\n");
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
    (arg0 == 25 || arg0 == 98 || arg0 == 101 || arg0 == 131 || arg0 == 134)/
{
	this->a = (uint64_t *)copyin(arg2, 6 * sizeof(uint64_t));
	@total[arg0] = count();
	@fcntl_cmd[arg0 == 25 ? this->a[1] : 0] =
	    sum(arg0 == 25 ? 1 : 0);
	@futex_op[arg0 == 98 ? (this->a[1] & 0x7f) : 0] =
	    sum(arg0 == 98 ? 1 : 0);
	@nanosleep_rem[arg0 == 101 ? (this->a[1] != 0) : 0] =
	    sum(arg0 == 101 ? 1 : 0);
	@tgkill_self_shape[arg0 == 131 ? (this->a[0] == this->a[1]) : 0,
	    arg0 == 131 ? this->a[2] : 0] = sum(arg0 == 131 ? 1 : 0);
	@sigaction_shape[arg0 == 134 ? this->a[0] : 0,
	    arg0 == 134 ? (this->a[1] != 0) : 0,
	    arg0 == 134 ? (this->a[2] != 0) : 0,
	    arg0 == 134 ? this->a[3] : 0] = sum(arg0 == 134 ? 1 : 0);
}

proc:::exit
/pid == $target/
{
	exit(0);
}

tick-1s
{
	seconds++;
}

tick-1s
/seconds >= 90/
{
	bounded = 1;
	exit(0);
}

dtrace:::END
{
	printf("HVPATCH2SHAPE|end|bounded=%d\n", bounded);
	printa("HVPATCH2SHAPE|total|nr=%d|count=%@d\n", @total);
	printa("HVPATCH2SHAPE|fcntl|cmd=%d|count=%@d\n", @fcntl_cmd);
	printa("HVPATCH2SHAPE|futex|op=%d|count=%@d\n", @futex_op);
	printa("HVPATCH2SHAPE|nanosleep|rem_nonnull=%d|count=%@d\n", @nanosleep_rem);
	printa("HVPATCH2SHAPE|tgkill|same_ids=%d|sig=%d|count=%@d\n",
	    @tgkill_self_shape);
	printa("HVPATCH2SHAPE|sigaction|sig=%d|new=%d|old=%d|sigset_size=%d|count=%@d\n",
	    @sigaction_shape);
}
