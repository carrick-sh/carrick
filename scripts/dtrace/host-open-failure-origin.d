#pragma D option quiet
#pragma D option bufsize=16m

/*
 * WHICH HOST SYSCALL FAILS (AND WITH WHAT ERRNO) RIGHT BEFORE A GUEST open
 * FAILS, AND FROM WHERE?
 *
 * (a) What it measures: every host syscall in carrick's process tree
 *     (`pid == $target || progenyof($target)`) that returns a "resource"
 *     failure — any errno except the path-resolution noise (ENOENT 2,
 *     ENOTDIR 20, EEXIST 17) and the poll/wait noise (EAGAIN 35, EINTR 4,
 *     ETIMEDOUT 60) — with its user stack, plus every guest `open*`/`creat`
 *     `syscall-return` USDT event that hands back a negative Linux errno.
 *     Sibling of `host-emfile-origin.d`, written for the 2026-09-02 fork09
 *     investigation: a guest opening files past the host's
 *     `kern.maxfilesperproc` ceiling (122880) got -EINVAL (22) instead of
 *     -EMFILE (24), at fd 122836, so the errno the guest saw was NOT the
 *     host `open` errno. The stack of the last failing host syscall before
 *     the guest -EINVAL answers which host call minted it.
 *
 * (b) Provider ABI facts (qualified live on macOS 26 / arm64, 2026-09-01,
 *     same as `host-emfile-origin.d`): `syscall:::return` errno is the
 *     thread-local `errno` D variable; `carrick*:::syscall-return` arg0 =
 *     canonical Linux nr, arg1 = host pointer to the name string, arg2 =
 *     retval (negative Linux errno on failure), arg3 = errno.
 *
 * (c) Perturbation: low in the steady state (failing host syscalls only),
 *     but the ustack() fires on EVERY qualifying host failure, so a run
 *     that fails host syscalls in a hot loop is perturbed — read the
 *     counts, not the timings.
 *
 * Usage:
 *   target/release/carrick trace --script scripts/dtrace/host-open-failure-origin.d \
 *     -- run -v openmax.py:/openmax.py python:3.12-slim python3 /openmax.py 130000
 */

syscall:::return
/(pid == $target || progenyof($target)) && errno != 0 && errno != 2 && errno != 20
 && errno != 17 && errno != 35 && errno != 4 && errno != 60/
{
    printf("HOST %s errno=%d ret=%d pid=%d tid=%d\n", probefunc, errno, (int)arg0, pid, tid);
    ustack(24);
    @host[probefunc, errno] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (int)arg2 < 0 && (int)arg2 > -4096
 && (arg0 == 56 || arg0 == 85 || arg0 == 1024 || arg0 == 437)/
{
    printf("GUEST %s ret=%d pid=%d tid=%d\n", copyinstr(arg1), (int)arg2, pid, tid);
    @guest[copyinstr(arg1), (int)arg2] = count();
}

END
{
    printa("host  %s errno=%d count=%@d\n", @host);
    printa("guest %s ret=%d count=%@d\n", @guest);
}
