/*
 * Tripwire trace for futex-vs-signal corruption (mn-probes futex-sigurg).
 *
 * Streams futex WAIT/WAKE + signal inject/restore per host thread, and prints a
 * loud CORRUPT marker the moment an injected or restored guest PC falls outside
 * the fixture's text range [0x400000, 0x451000]. The events just before a
 * CORRUPT line show how the bad PC was produced (a clobbered rt_sigreturn
 * restore, a nested inject, or a wild guest ret).
 */
#pragma D option quiet
#pragma D option strsize=64
#pragma D option bufsize=64m
#pragma D option switchrate=200hz


carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 98/
{
	this->a = (uint64_t *)copyin(arg2, 48);
	printf("%d t%d FUTEX-ENTRY op=%d uaddr=0x%x val=%d\n",
	    timestamp / 1000, tid, (int)(this->a[1] & 0x7f), this->a[0], (int)this->a[2]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 98/
{
	printf("%d t%d FUTEX-RET ret=%d errno=%d\n",
	    timestamp / 1000, tid, (int)arg2, (int)arg3);
}

/* rt_sigreturn entry */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 139/
{
	printf("%d t%d SIGRETURN-ENTRY\n", timestamp / 1000, tid);
}

carrick*:::signal-inject
/pid == $target || progenyof($target)/
{
	printf("%d t%d INJECT sig=%d saved_pc=0x%x new_sp=0x%x handler=0x%x\n",
	    timestamp / 1000, tid, (int)arg0, arg1, arg2, arg3);
}

carrick*:::signal-inject
/(pid == $target || progenyof($target)) && (arg1 < 0x400000 || arg1 > 0x451000)/
{
	printf("%d t%d !!!CORRUPT-INJECT saved_pc=0x%x (out of text range)\n",
	    timestamp / 1000, tid, arg1);
}

carrick*:::signal-restore
/pid == $target || progenyof($target)/
{
	printf("%d t%d RESTORE saved_pc=0x%x sp=0x%x\n",
	    timestamp / 1000, tid, arg0, arg1);
}

carrick*:::kick-in-kernel
/pid == $target || progenyof($target)/
{
	@kick_in_kernel[arg0] = count();
	kik++;
}

carrick*:::signal-restore
/(pid == $target || progenyof($target)) && (arg0 < 0x400000 || arg0 > 0x451000)/
{
	printf("%d t%d !!!CORRUPT-RESTORE saved_pc=0x%x (out of text range)\n",
	    timestamp / 1000, tid, arg0);
}

tick-1s { secs++; }
tick-1s /secs >= 6/ {
	printf("=== kick_in_kernel total=%d (by EL1 pc) ===\n", kik);
	printa("  pc=0x%x %@d\n", @kick_in_kernel);
	exit(0);
}
