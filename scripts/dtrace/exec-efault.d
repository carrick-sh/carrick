#pragma D option quiet
#pragma D option bufsize=4m

/*
 * Five scalar words from the ring. A candidate may still retry after fault
 * supply. A terminal row is the decision to return EFAULT.
 *
 * operand: 1 path, 2 argv, 3 envp, 4 fork owner, 5 exec service
 * primitive: 1 string read, 2 pointer read, 3 address arithmetic,
 *            4 fork-owner operation, 5 exec service
 * copy reason: 1 forbidden range, 2 validator, 3 guarded instruction,
 *              0x100 | PAR.FST for an ARM translation refusal
 *
 * mm and root_generation name the caller's published translation. Native
 * vfork uses a private COW child MM even when it suspends the parent.
 * Fork-owner and carrier-service errors have no guest copy address.
 */
carrick*:::hvpatch-exec-efault
/pid == $target || progenyof($target)/
{
    candidates += (arg0 & 0x10000) == 0;
    terminal += (arg0 & 0x10000) != 0;
    printf("EXECFAULT ns=%llu host=%d thread=%d operand=%u primitive=%u final=%u reason=%#x va=%#llx index=%llu mm=%llu root_generation=%llu\n",
        timestamp, pid, tid, (uint32_t)(arg0 & 0xff), (uint32_t)((arg0 >> 8) & 0xff),
        (uint32_t)((arg0 >> 16) & 1), (uint32_t)(arg0 >> 32), arg1, arg2, arg3, arg4);
}

proc:::exit
/pid == $target/
{ exited = 1; exit(0); }

tick-1s
{ seconds++; }

tick-1s
/seconds >= 90 && !exited/
{ exit(4); }

dtrace:::ERROR
{ errors++; }

dtrace:::DROP
{ drops++; }

END
{
    printf("EXECFAULT candidates=%d terminal=%d exited=%d errors=%d drops=%d\n",
        candidates, terminal, exited, errors, drops);
    if (errors != 0 || drops != 0 || !exited) { exit(4); }
}
