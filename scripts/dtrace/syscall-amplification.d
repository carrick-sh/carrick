/*
 * syscall-amplification.d — measure host/guest syscall amplification.
 *
 * For every guest Linux syscall carrick services, how many real macOS
 * syscalls does it issue? The ratio HOST_MACOS_TOTAL / GUEST_LINUX_TOTAL is
 * the amplification factor; the per-function host breakdown names which host
 * syscall is doing the amplifying (the next optimization target).
 *
 * Counts the whole process tree (progenyof) so fork/exec fan-out is included.
 *
 * Run: carrick trace --script scripts/dtrace/syscall-amplification.d -- run <args>
 */
#pragma D option quiet

/* --- guest Linux syscalls (carrick USDT; arg0 = Linux sysno) --- */
carrick*:::syscall-entry
/pid == $target || progenyof($target)/
{
	@guest_total = count();
	@guest_by_nr[arg0] = count();
}

/* --- real macOS syscalls carrick issues --- */
syscall:::entry
/pid == $target || progenyof($target)/
{
	@host_total = count();
	@host_by_fn[probefunc] = count();
}

tick-1s { secs++; }
tick-1s /secs >= 240/ { exit(0); }

END {
	printf("\n==== SYSCALL AMPLIFICATION ====\n");
	printf("GUEST_LINUX_TOTAL = "); printa("%@d\n", @guest_total);
	printf("HOST_MACOS_TOTAL  = "); printa("%@d\n", @host_total);
	printf("\n---- host macOS syscalls by function (top amplifiers) ----\n");
	printa("  %-22s %@10d\n", @host_by_fn);
	printf("\n---- guest Linux syscalls by number ----\n");
	printa("  nr=%-6d %@10d\n", @guest_by_nr);
}
