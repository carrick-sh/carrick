/*
 * Focused SysV message-queue trace for LTP msgstress01.
 *
 * Use with carrick trace, for example:
 *
 *   carrick trace --script scripts/dtrace/msgstress-sysv.d --trace-out /tmp/msgstress.out -- \
 *     run --name "$CARRICK_RUN_ID" --raw --fs host localhost:5050/ltp:arm64 \
 *     /opt/ltp/testcases/bin/msgstress01
 *
 * The script intentionally aggregates instead of printing every msgsnd/msgrcv:
 * msgstress can issue thousands of operations, and per-event output perturbs the
 * exact scheduling problem this script is meant to observe.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=32m
#pragma D option switchrate=10ms

dtrace:::BEGIN
{
    printf("msgstress SysV trace started at %Y\n", walltimestamp);
}

/*
 * Linux aarch64 SysV message syscalls:
 *   186 msgget, 187 msgctl, 188 msgrcv, 189 msgsnd
 */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 186 || arg0 == 187 || arg0 == 188 || arg0 == 189)/
{
    @sysv_entries[copyinstr(arg1)] = count();
    @sysv_entries_by_pid[pid, copyinstr(arg1)] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 186 || arg0 == 187 || arg0 == 188 || arg0 == 189)/
{
    @sysv_returns[copyinstr(arg1), (int)arg2, (int)arg3] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 186 || arg0 == 187 || arg0 == 188 || arg0 == 189) &&
 (int)arg3 != 0/
{
    @sysv_errno[copyinstr(arg1), (int)arg3] = count();
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 220/
{
    @clone_entries[pid] = count();
}

carrick*:::fork-post
/(pid == $target || progenyof($target)) && (int)arg0 == 0/
{
    @fork_post["child"] = count();
}

carrick*:::fork-post
/(pid == $target || progenyof($target)) && (int)arg0 != 0/
{
    @fork_post["parent"] = count();
}

profile-997
/pid == $target || progenyof($target)/
{
    @hoststacks[pid, ustack(16)] = count();
}

tick-5s
{
    printf("\n========= msgstress tick %Y =========\n", walltimestamp);

    printf("--- SysV message entries ---\n");
    printa("  %-12s %@d\n", @sysv_entries);

    printf("--- SysV message errno returns ---\n");
    printa("  %-12s errno=%-4d %@d\n", @sysv_errno);

    printf("--- clone entries by pid ---\n");
    printa("  pid=%-8d %@d\n", @clone_entries);

    printf("--- fork post roles ---\n");
    printa("  %-8s %@d\n", @fork_post);

    printf("--- hottest host stacks ---\n");
    trunc(@hoststacks, 8);
    printa(@hoststacks);
}

dtrace:::END
{
    printf("\n=================== msgstress SysV summary ===================\n");

    printf("\n--- SysV message entries ---\n");
    printa("  %-12s %@d\n", @sysv_entries);

    printf("\n--- SysV message entries by pid ---\n");
    printa("  pid=%-8d %-12s %@d\n", @sysv_entries_by_pid);

    printf("\n--- SysV message returns ---\n");
    printa("  %-12s ret=%-8d errno=%-4d %@d\n", @sysv_returns);

    printf("\n--- SysV message errno returns ---\n");
    printa("  %-12s errno=%-4d %@d\n", @sysv_errno);

    printf("\n--- clone entries by pid ---\n");
    printa("  pid=%-8d %@d\n", @clone_entries);

    printf("\n--- fork post roles ---\n");
    printa("  %-8s %@d\n", @fork_post);

    printf("\n--- hottest host stacks ---\n");
    trunc(@hoststacks, 12);
    printa(@hoststacks);
}
