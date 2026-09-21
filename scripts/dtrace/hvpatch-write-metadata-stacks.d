#!/usr/sbin/dtrace -qs
/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Attribute remaining Darwin fstat calls in the write/seek workload.
 * Darwin syscall provider uses fstat64 on this ARM64 host; match fstat too.
 * Qualify by positive events and zero errors. ustack aggregation perturbs;
 * these are attribution counts, never runtime evidence. Follow carrier tree.
 */
#pragma D option quiet
#pragma D option aggsize=16m
dtrace:::BEGIN { seconds = 0; calls = 0; errors = 0; }
syscall::fstat64:entry, syscall::fstat:entry
/pid == $target || progenyof($target)/
{ calls++; @stacks[ustack(24)] = count(); }
dtrace:::ERROR { errors++; }
profile:::tick-1s { seconds++; }
profile:::tick-1s /seconds >= 10/
{ exit(calls > 0 && errors == 0 ? 0 : 2); }
dtrace:::END
{
    printf("WRITEMETADATA1|calls=%d|errors=%d|bound_reached=%d\n",
        calls, errors, seconds >= 10);
    printa(@stacks);
}
