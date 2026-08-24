/*
 * vfork-smash-signal-injections.d — was a guest stack-canary smash preceded by
 * a carrick sigframe injection (and at what SP), or by nothing signal-shaped?
 *
 * Question: gate-load runs of vfork/clone probes die with glibc/musl
 * "*** stack smashing detected ***" (canary mismatch at function epilogue)
 * while green standalone. Discriminate the two candidate mechanisms:
 *   (a) carrick writes an rt_sigframe at a stale/wrong SP into the shared mm
 *       -> a signal-inject event with new_sp inside the victim's live stack
 *          shortly before the abort;
 *   (b) memory/COW/exec page-ownership corruption -> NO signal-inject near
 *       the abort.
 *
 * Provider ABI facts (qualified live on macOS 27.0 / this repo HEAD):
 *   carrick*:::signal-inject  arg0=signum arg1=saved_pc arg2=new_sp arg3=handler
 *   carrick*:::signal-restore arg0=saved_pc arg1=sp arg2=magic
 *   carrick*:::syscall-entry  arg0=Linux nr arg1=name arg2=&args[6]
 *     (arg2 is a HOST pointer to six u64s, so copyin(arg2,48) is valid;
 *      guest buffer pointers inside that array remain guest VAs)
 *   carrick*:::syscall-return arg0=Linux nr arg1=name arg2=ret arg3=errno
 *   carrick*:::fork-post      arg0=child host pid
 * Perturbation: per-event printf on syscall subset + signal events only;
 * moderate. A vanished repro under this script is itself a finding (timing).
 *
 * Usage (traced lane; load lanes run separately):
 *   carrick trace --script scripts/dtrace/vfork-smash-signal-injections.d \
 *     --trace-out <out> -- run --raw --fs host ubuntu:24.04 /bin/sh -c '...'
 */
#pragma D option quiet
#pragma D option strsize=128

carrick*:::signal-inject
/pid == $target || progenyof($target)/
{
    printf("[%d %d] INJECT sig=%d saved_pc=0x%x new_sp=0x%x handler=0x%x\n",
        pid, timestamp, (int)arg0, arg1, arg2, arg3);
}

carrick*:::signal-restore
/pid == $target || progenyof($target)/
{
    printf("[%d %d] RESTORE saved_pc=0x%x sp=0x%x magic=0x%x\n",
        pid, timestamp, arg0, arg1, arg2);
}

/* vfork(58), clone(220), execve(221), wait4(260), exit(93), exit_group(94), write(64) */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 58 || arg0 == 220 || arg0 == 221 || arg0 == 260 || arg0 == 93 || arg0 == 94)/
{
    printf("[%d %d] ENTRY %s\n", pid, timestamp, copyinstr(arg1));
}

/* clone: flags, child_stack, parent_tid, exit_signal/tls, child_tid. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 220/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    printf("[%d %d] CLONE flags=0x%x child_stack=0x%x parent_tid=0x%x a3=0x%x child_tid=0x%x\n",
        pid, timestamp, this->a[0], this->a[1], this->a[2], this->a[3], this->a[4]);
}

/* rt_sigprocmask(135): how, new-set guest VA, old-set guest VA, size. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 135/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    printf("[%d %d] SIGMASK how=%d nset=0x%x oset=0x%x size=%d\n",
        pid, timestamp, (int)this->a[0], this->a[1], this->a[2], (int)this->a[3]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 58 || arg0 == 220 || arg0 == 221 || arg0 == 260)/
{
    printf("[%d %d] RET %s ret=%d errno=%d\n",
        pid, timestamp, copyinstr(arg1), (int)arg2, (int)arg3);
}

/* the abort path: the guest writes the smash message then raises */
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 64/
{
    printf("[%d %d] WRITE ret=%d\n", pid, timestamp, (int)arg2);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d %d] FORK-POST child=%d\n", pid, timestamp, (int)arg0);
}

tick-1s { secs++; }
tick-1s /secs >= 90/ { exit(0); }
