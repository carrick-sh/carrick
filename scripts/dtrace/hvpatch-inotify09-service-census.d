#!/usr/sbin/dtrace -qs
/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Measure host-serviced syscall counts for inotify09, including raw clocks.
 * ABI: hvpatch-syscall-service-begin arg3 is Linux syscall number, verified
 * against carrick-observability and hvpatch-raw-clock-el1.d, Darwin arm64.
 * Perturbs every host service with an aggregation; counts only, no wall claim.
 * EL1-completed calls are invisible. Zero clock events alone is not proof of
 * clock execution; compare against the known workload and positive services.
 * Darwin syscall counts cover the whole carrier tree, including startup;
 * they deliberately do not depend on the rejected service-window join.
 */
#pragma D option quiet
#pragma D option aggsize=16m

dtrace:::BEGIN { seconds = 0; services = 0; errors = 0; }

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    services++;
    @calls[(uint64_t)arg3] = count();
}

syscall:::entry
/pid == $target || progenyof($target)/
{ @host_calls[probefunc] = count(); }

dtrace:::ERROR { errors++; }
profile:::tick-1s { seconds++; }
profile:::tick-1s
/seconds >= 10/
{ exit(services > 0 && errors == 0 ? 0 : 2); }

dtrace:::END
{
    printf("INOTIFYCENSUS1|services=%d|errors=%d|bound_reached=%d\n",
        services, errors, seconds >= 10);
    printa("INOTIFYCENSUS1|nr=%llu|count=%@d\n", @calls);
    printa("INOTIFYCENSUS1|host=%s|count=%@d\n", @host_calls);
}
