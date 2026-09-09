#!/usr/sbin/dtrace -qs
/*
 * Boundary qualification for a serial spawn-and-wait workload.
 * Scalar provider ABI from carrick-observability, qualified on Darwin arm64
 * with this script's receipts. Phases: 1 child prepared before activation,
 * 6 exec entry, 2 exec published, 5 retirement complete. The phase-5 event is
 * prepared by record_process_exit_begin but emitted by retirement.complete;
 * it can follow parent wait return. Never treat its preparation as emission.
 * Identity probe precedes lifecycle on the same host thread. Preserve task
 * serials to reject PID reuse and join output against guest child PIDs.
 *
 * Perturbation: HIGH with syscall service-begin and return armed, even though
 * predicates print only clone/exit/wait4. Every syscall incurs probe overhead.
 * ABI: service-begin arg0 guest pid, arg3 Linux arm64 number; syscall-return
 * arg0 number, arg2 result. Wait4's positive result identifies the reaped child,
 * avoiding a host-thread identity join across suspended executor continuations.
 * These are
 * diagnostic durations, not performance acceptance. Guest measured total minus
 * child prepared-to-retirement is NOT an exclusive residual: retirement can
 * overlap the next spawn. The first 100-child capture had 23 negative residuals
 * and was rejected as a full wall budget. Require zero drops/errors, natural
 * target success, and offline complete ordered joins for every measured child.
 */
#pragma D option quiet
#pragma D option bufsize=16m

dtrace:::BEGIN
{ started = timestamp; events = 0; errors = 0; seen = 0; code = -1; bounded = 0; }

carrick*:::hvpatch-guest-lifecycle-identity
/pid == $target || progenyof($target)/
{ self->guest = (int)arg0; self->serial = arg1; }

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) &&
 (arg0 == 1 || arg0 == 6 || arg0 == 2 || arg0 == 5)/
{
    events++;
    printf("SPAWNWALL|event|ns=%llu|host=%d|guest=%d|parent=%d|phase=%d|serial=%llu|identity_guest=%d\n",
        timestamp, pid, (int)arg1, (int)arg2, (int)arg0,
        (uint64_t)self->serial, self->guest);
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 (arg3 == 220 || arg3 == 435 || arg3 == 93 || arg3 == 94 || arg3 == 260)/
{
    printf("SPAWNWALL|sysbegin|ns=%llu|host=%d|guest=%d|nr=%llu\n",
        timestamp, pid, (int)arg0, (uint64_t)arg3);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 260 && (int64_t)arg2 > 0/
{
    printf("SPAWNWALL|waitreturn|ns=%llu|host=%d|child=%lld\n",
        timestamp, pid, (int64_t)arg2);
}

syscall::exit:entry
/pid == $target/
{ seen = 1; code = (int)arg0; }

proc:::exit
/pid == $target/
{ exit(seen && code == 0 && events > 0 && errors == 0 ? 0 : 2); }

dtrace:::ERROR
{ errors++; exit(3); }

tick-1s
/timestamp - started > 45 * 1000000000/
{ bounded = 1; exit(4); }

dtrace:::END
{ printf("SPAWNWALL|summary|events=%d|errors=%d|seen=%d|code=%d|bounded=%d\n", events, errors, seen, code, bounded); }
