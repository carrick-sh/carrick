#!/usr/sbin/dtrace -Zs
/*
 * hvpatch-pt-pause-callers.d — which guest operations raise a stage-1
 * page-table pause (a drain of sibling executors), and how often.
 *
 * (a) What it measures
 *     Every `pt-pause-begin` (a coordinator that won the election and is about
 *     to kick and drain the exact MM's siblings), attributed to the Linux
 *     syscall its host thread is servicing (`hvpatch-syscall-service-begin`
 *     arg3, cleared at `syscall-return`). A pause raised with no syscall in
 *     flight is a guest fault (first-touch / COW resolution) and counts as
 *     "fault". Also the total drain wait per attribution.
 *
 * (b) Provider ABI facts qualified live (macOS 27.2, M4):
 *       * `hvpatch-syscall-service-begin` = (pid, tid, asid, nr) and
 *         `syscall-return` = (nr, name, ret, errno) fire on the same host
 *         thread (one host pthread services one logical guest thread at a
 *         time), so `self->` pairing is sound.
 *       * `pt-pause-ready` = (tid, wait_rounds, wait_us).
 *       * `nanosleep`/`exit_group` have no return record; the begin of the
 *         next syscall on that thread overwrites the attribution.
 *
 * (c) Perturbation
 *     One clause per guest syscall (sets a thread-local); low but nonzero.
 *     Counts are exact; wait times are same-instrument only.
 */
#pragma D option quiet

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
	self->nr = arg3;
	self->in = 1;
}

carrick*:::syscall-return
/pid == $target || progenyof($target)/
{
	self->in = 0;
}

carrick*:::pt-pause-begin
/(pid == $target || progenyof($target)) && self->in/
{
	self->who = self->nr;
	@raised[self->nr == 222 ? "mmap" : self->nr == 215 ? "munmap" :
	    self->nr == 226 ? "mprotect" : self->nr == 233 ? "madvise" :
	    self->nr == 220 ? "clone" : self->nr == 221 ? "execve" : "other-syscall"] = count();
}

carrick*:::pt-pause-begin
/(pid == $target || progenyof($target)) && !self->in/
{
	self->who = -1;
	@raised["fault"] = count();
}

carrick*:::pt-pause-ready
/pid == $target || progenyof($target)/
{
	@wait_us[self->who == -1 ? "fault" : self->who == 222 ? "mmap" :
	    self->who == 215 ? "munmap" : self->who == 226 ? "mprotect" :
	    self->who == 233 ? "madvise" : "other"] = sum(arg2);
}

carrick*:::pt-pause-begin
/(pid == $target || progenyof($target)) && self->in && self->nr != 222 && self->nr != 215 && self->nr != 226 && self->nr != 233/
{
	@other_nr[self->nr] = count();
}

proc:::exit
/pid == $target/
{
	exit(0);
}
