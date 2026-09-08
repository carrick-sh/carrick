#pragma D option quiet
#pragma D option dynvarsize=32m

/*
 * DETAILED HOST OPENAT CALLS DURING GUEST MKDIRAT
 *
 * (a) What it measures: dirfd, path argument, flags, return value, and errno
 *     for host `openat` while servicing guest `mkdirat`.
 * (b) Provider ABI facts (qualified live on macOS 26 / arm64, 2026-09-07):
 *     `carrick*:::syscall-entry`: arg0 = canonical Linux syscall nr (34 = mkdirat).
 *     `syscall::openat:entry`: arg0 = dirfd, arg1 = path (copyinstr), arg2 = flags.
 *     `syscall::openat:return`: arg0 = return fd or -1, errno = errno.
 *     `carrick*:::guest-exit`: fires on guest exit.
 * (c) Perturbation: YES. Prints first 40 calls only.
 */

dtrace:::BEGIN
{
	n = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 34/
{
	self->in_mkdirat = 1;
}

syscall::openat:entry
/(pid == $target || progenyof($target)) && self->in_mkdirat && n < 40/
{
	printf("host openat: fd=%d path=%s flags=%#x\n", (int)arg0, copyinstr(arg1), (int)arg2);
}

syscall::openat:return
/(pid == $target || progenyof($target)) && self->in_mkdirat && n < 40/
{
	printf("host openat ret: rc=%d errno=%d\n", (int)arg0, errno);
	n++;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->in_mkdirat/
{
	self->in_mkdirat = 0;
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
	exit(0);
}

tick-1s
/n >= 40/
{
	exit(0);
}
