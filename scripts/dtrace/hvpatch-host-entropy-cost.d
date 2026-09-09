#!/usr/sbin/dtrace -qs
/*
 * Count and bracket host getentropy calls during repeated guest exec.
 * Darwin arm64 ABI qualified 2026-09-09: SDK getentropy(buffer, size),
 * syscall::getentropy entry exists; arg1 is requested size. Return arg0
 * is the syscall result, qualified by successful workload and zero failures.
 * No guest buffers or entropy bytes are read. Counts/latencies are diagnostic:
 * entry/return probes perturb every call; use untraced runs for acceptance.
 */
#pragma D option quiet
#pragma D option bufsize=16m

dtrace:::BEGIN
{ started = timestamp; entries = 0; returns = 0; errors = 0; seen = 0; code = -1; bounded = 0; }

syscall::getentropy:entry
/pid == $target || progenyof($target)/
{ self->start = timestamp; self->size = arg1; entries++; }

syscall::getentropy:return
/self->start/
{
    @calls[self->size] = count();
    @elapsed[self->size] = sum(timestamp - self->start);
    @result[(int)arg0] = count();
    returns++;
    self->start = 0;
    self->size = 0;
}

syscall::exit:entry
/pid == $target/
{ seen = 1; code = (int)arg0; }

proc:::exit
/pid == $target/
{ exit(seen && code == 0 && entries > 0 && entries == returns && errors == 0 ? 0 : 2); }

dtrace:::ERROR
{ errors++; exit(3); }

tick-1s
/timestamp - started > 45 * 1000000000/
{ bounded = 1; exit(4); }

dtrace:::END
{
    printf("ENTROPY|summary|entries=%d|returns=%d|errors=%d|seen=%d|code=%d|bounded=%d\n", entries, returns, errors, seen, code, bounded);
    printa("ENTROPY|bytes=%d|calls=%@d\n", @calls);
    printa("ENTROPY|bytes=%d|elapsed_ns=%@d\n", @elapsed);
    printa("ENTROPY|result=%d|calls=%@d\n", @result);
}
