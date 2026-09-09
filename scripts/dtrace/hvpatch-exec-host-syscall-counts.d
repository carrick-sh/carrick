#!/usr/sbin/dtrace -qs
/*
 * Count host syscall entries across repeated guest execs. Tests whether host
 * filesystem setup performs enough operations to merit an optimization.
 * Uses generic syscall entry names, no syscall argument ABI or path strings.
 * HVPatch lifecycle ordinals: 6=exec begin, 2=exec success (campaign ABI).
 * Darwin syscall::exit arg0 is status, as qualified by exec-cpu-sampling.d.
 * Names observed in a live capture, not merely listed probes, are evidence.
 *
 * Perturbation: every target-tree host syscall entry plus two lifecycle
 * events per guest exec. Counts are diagnostic; never cite traced wall time
 * as performance. Require repeated balanced execs, host events, successful
 * natural target exit, zero errors/drops, and no 45-second bounded exit.
 */
#pragma D option quiet
#pragma D option bufsize=8m
#pragma D option aggsize=8m

dtrace:::BEGIN
{ started = timestamp; calls = 0; begins = 0; ends = 0; errors = 0; seen = 0; code = -1; bounded = 0; }

syscall:::entry
/pid == $target || progenyof($target)/
{ calls++; @host[probefunc] = count(); }

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 6/
{ begins++; }

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2/
{ ends++; }

syscall::exit:entry
/pid == $target/
{ seen = 1; code = (int)arg0; }

proc:::exit
/pid == $target/
{ exit(seen && code == 0 && calls > 0 && begins > 1 && begins == ends && errors == 0 ? 0 : 2); }

dtrace:::ERROR
{ errors++; exit(3); }

tick-1s
/timestamp - started > 45 * 1000000000/
{ bounded = 1; exit(4); }

dtrace:::END
{
    printf("EXECHOST|summary|calls=%d|begins=%d|ends=%d|errors=%d|seen=%d|code=%d|bounded=%d\n", calls, begins, ends, errors, seen, code, bounded);
    printa("EXECHOST|syscall=%s|count=%@d\n", @host);
}
