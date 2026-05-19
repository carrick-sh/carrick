/*
 * carrick syscall trace + aggregation.
 *
 * Use:  sudo dtrace -s scripts/syscalls.d -c '<carrick command line>'
 *
 * Emits a per-event line for every Linux syscall the guest issues, plus
 * an END action that prints frequency-sorted aggregations.
 *
 * Predicates use the libdtrace `$target` variable, which dtrace(1)
 * binds to the pid spawned via `-c` (or to the pid given via `-p`).
 * Every probe action that's per-event also adds `progenyof($target)`
 * so forked carrick children (the carrick-host-side that runs the
 * Linux child after clone(2)) are followed automatically.
 *
 * Pid is printed in every per-event line so operators can demultiplex
 * the parent vs child streams without dtrace -w gymnastics.
 */

#pragma D option quiet
#pragma D option strsize=512
#pragma D option destructive
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    printf("carrick trace started at %Y\n", walltimestamp);
}

carrick*:::syscall-entry
/pid == $target || progenyof($target)/
{
    @entries[copyinstr(arg1)] = count();
    /*
     * arg2 is a pointer to the JSON-serialised SyscallArgs:
     *   {"ok":[v0,v1,v2,v3,v4,v5]} — values are decimal u64s.
     */
    printf("[%d entry] %-24s nr=%-3d args=%s\n",
        pid, copyinstr(arg1), arg0, copyinstr(arg2));
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (int)arg3 != 0/
{
    @errno_returns[copyinstr(arg1), (int)arg3] = count();
}

carrick*:::syscall-return
/pid == $target || progenyof($target)/
{
    printf("[%d ret  ] %-24s nr=%-3d ret=%-12d errno=%d\n",
        pid, copyinstr(arg1), arg0, (int)arg2, (int)arg3);
}

carrick*:::unhandled-syscall
/pid == $target || progenyof($target)/
{
    @unhandled[copyinstr(arg1)] = count();
    printf("[%d unh  ] %-24s nr=%-3d args=%s\n",
        pid, copyinstr(arg1), arg0, copyinstr(arg2));
}

carrick*:::partial-syscall
{
    @partial[copyinstr(arg1), copyinstr(arg3)] = count();
    printf("[part ] %-24s nr=%d reason=%s\n",
        copyinstr(arg1), arg0, copyinstr(arg3));
}

carrick*:::unhandled-ioctl
{
    @unhandled_ioctls[(int)arg0, arg1] = count();
    printf("[ioctl] fd=%-3d request=0x%-8x arg=0x%x\n",
        (int)arg0, arg1, arg2);
}

carrick*:::proc-read-unimplemented
{
    @proc_reads[copyinstr(arg0)] = count();
    printf("[/proc] %s\n", copyinstr(arg0));
}

carrick*:::sys-read-unimplemented
{
    @sys_reads[copyinstr(arg0)] = count();
    printf("[/sys ] %s\n", copyinstr(arg0));
}

carrick*:::signal-unsupported
{
    @unsupported_signals[(int)arg0, copyinstr(arg1)] = count();
    printf("[sig  ] signum=%-2d reason=%s\n",
        (int)arg0, copyinstr(arg1));
}

carrick*:::vcpu-trap
/pid == $target || progenyof($target)/
{
    /* Aggregate by guest PC so we can spot tight loops. */
    @vcpu_pcs[arg0, arg1] = count();
}

carrick*:::fork-pre
/pid == $target || progenyof($target)/
{
    printf("[%d fork-pre ] pc=%#x elr=%#x cpsr=%#x\n",
        pid, arg0, arg1, arg2);
}

carrick*:::fork-post
/(pid == $target || progenyof($target)) && (int)arg0 == 0/
{
    printf("[%d fork-chld] pc=%#x elr=%#x\n", pid, arg1, arg2);
    @forks["child"] = count();
}

carrick*:::fork-post
/(pid == $target || progenyof($target)) && (int)arg0 != 0/
{
    printf("[%d fork-prnt] child_pid=%d pc=%#x elr=%#x\n",
        pid, (int)arg0, arg1, arg2);
    @forks["parent"] = count();
}

dtrace:::END
{
    printf("\n=================== aggregations ===================\n");

    printf("\n--- syscalls by frequency ---\n");
    printa("  %-32s %@d\n", @entries);

    printf("\n--- unhandled syscalls (frequency) ---\n");
    printa("  %-32s %@d\n", @unhandled);

    printf("\n--- partial syscalls (frequency) ---\n");
    printa("  %-24s reason=%-32s %@d\n", @partial);

    printf("\n--- errno returns (syscall, errno -> count) ---\n");
    printa("  %-24s errno=%-4d %@d\n", @errno_returns);

    printf("\n--- unhandled ioctls (fd, request -> count) ---\n");
    printa("  fd=%-3d req=0x%-8x %@d\n", @unhandled_ioctls);

    printf("\n--- /proc reads we don't synthesize ---\n");
    printa("  %-48s %@d\n", @proc_reads);

    printf("\n--- /sys reads we don't synthesize ---\n");
    printa("  %-48s %@d\n", @sys_reads);

    printf("\n--- unsupported signals ---\n");
    printa("  signum=%-2d reason=%-24s %@d\n", @unsupported_signals);

    printf("\n--- guest PC × syscall hot spots ---\n");
    printa("  pc=%#-12x x8=%-4d %@d\n", @vcpu_pcs);
}
