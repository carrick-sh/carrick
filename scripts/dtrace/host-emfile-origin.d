#pragma D option quiet
#pragma D option bufsize=16m

/*
 * WHICH HOST SYSCALL SURFACES EMFILE/ENFILE TO THE GUEST, AND FROM WHERE?
 *
 * (a) What it measures: every host syscall in carrick's process tree
 *     (`pid == $target || progenyof($target)`) that returns with errno
 *     EMFILE (24) or ENFILE (23), with its user stack, plus the guest
 *     `syscall-return` USDT events that hand a guest -EMFILE back. Written
 *     for the 2026-09-01 creat05 investigation: the guest saw EMFILE at fd
 *     ~4096 while both its RLIMIT_NOFILE (8192..1048576) and the host soft
 *     limit (65536, raised in carrick-cli main) were far above it, so the
 *     cap had to be either a host descriptor ceiling carrick did not raise
 *     or a carrick-internal table bound. The stack answers which.
 *
 * (b) Provider ABI facts (qualified live on macOS 26 / arm64, 2026-09-01):
 *     `syscall:::return` errno is the thread-local `errno` D variable;
 *     `carrick*:::syscall-return` arg0 = canonical Linux nr, arg1 = host
 *     pointer to the name string, arg2 = retval (negative Linux errno on
 *     failure), arg3 = errno. USDT probes follow forked children under the
 *     progeny predicate; the `pid` provider does not.
 *
 * (c) Perturbation: low. Only failing host syscalls and failing guest
 *     syscalls take a probe body; the ustack() on a host EMFILE is the only
 *     expensive action and fires at most a handful of times per run.
 *
 * Usage:
 *   target/release/carrick trace --script scripts/dtrace/host-emfile-origin.d \
 *     -- run ... /bin/sh -c 'ulimit -n 8192; /opt/ltp/testcases/bin/creat05'
 */

syscall:::return
/(pid == $target || progenyof($target)) && (errno == 24 || errno == 23)/
{
    printf("HOST %s errno=%d pid=%d tid=%d\n", probefunc, errno, pid, tid);
    ustack(20);
    @host[probefunc, errno] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg2 == -24 || arg2 == -23)/
{
    printf("GUEST %s ret=%d pid=%d tid=%d\n", copyinstr(arg1), (int)arg2, pid, tid);
    @guest[copyinstr(arg1), (int)arg2] = count();
}

END
{
    printa("host  %s errno=%d count=%@d\n", @host);
    printa("guest %s ret=%d count=%@d\n", @guest);
}
