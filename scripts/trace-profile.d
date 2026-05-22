/*
 * Sampling profiler for a wedged carrick guest: where is the spinning process
 * burning CPU? Samples the carrick (host) user stack at 997 Hz across the
 * process tree, plus the guest syscall mix, and dumps after a bounded window
 * so it never runs away.
 *
 *   carrick trace --script scripts/trace-profile.d -- run-elf <fixture>
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=8m

profile-997
/pid == $target || progenyof($target)/
{
    @hoststack[pid, ustack(16)] = count();
}

/* Guest syscall mix: which syscall dominates the spin. */
carrick*:::syscall-entry
/pid == $target || progenyof($target)/
{
    @syscalls[copyinstr(arg1)] = count();
}

/* The guest PC at each trap — a tight set of PCs == a spin location. */
carrick*:::syscall-return
/pid == $target || progenyof($target)/
{
    @bynr[arg0, (int)arg2, (int)arg3] = count();
}

tick-1s { secs++; }
tick-1s /secs >= 6/ { exit(0); }

END
{
    printf("\n==== guest syscall counts (6s) ====\n");
    printa("  %-24s %@d\n", @syscalls);
    printf("\n==== syscall nr -> (ret,errno) counts ====\n");
    printa("  nr=%-3d ret=%-4d errno=%-3d  %@d\n", @bynr);
    printf("\n==== hottest host stacks ====\n");
    trunc(@hoststack, 8);
    printa(@hoststack);
}
