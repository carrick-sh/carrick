#!/usr/sbin/dtrace -qs
/*
 * N1 reservation ownership classification for a signed EL1 spawn witness.
 * Measures the committed guest TaskKey/MM lifecycle, stage-1 lease edges,
 * root publication/retirement and each prepared-root reap (id, tail).
 * Qualified against the exact signed artifact in this investigation.
 * Perturbation: low-rate lifecycle USDT events plus one event per prepared
 * completion; no syscall, scheduler, fault or sampling provider is armed.
 */
#pragma D option quiet
#pragma D option dynvarsize=16m
#pragma D option bufsize=32m
#pragma D option switchrate=1ms

dtrace:::BEGIN { events = 0; started = timestamp; }

carrick*:::hvpatch-guest-lifecycle-identity
/(pid == $target || progenyof($target))/
{
    self->task_pid = (int)arg0;
    self->task_serial = (uint64_t)arg1;
    self->parent_serial = (uint64_t)arg2;
    self->mm = (uint64_t)arg3;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target))/
{
    events++;
    printf("N1|guest|ts=%llu|pid=%d|phase=%u|task_pid=%d|serial=%llu|mm=%llu|parent_serial=%llu\n",
        (uint64_t)timestamp, pid, (uint32_t)arg0, self->task_pid,
        self->task_serial, self->mm, self->parent_serial);
}

carrick*:::hvpatch-n1-reservation-custody
/(pid == $target || progenyof($target))/
{
    events++;
    printf("N1|root|ts=%llu|pid=%d|phase=%u|mm=%llu|inc=%llu|a=%llu|b=%llu\n",
        (uint64_t)timestamp, pid, (uint32_t)arg0, (uint64_t)arg1,
        (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

carrick_core*:::reservation-custody
/(pid == $target || progenyof($target))/
{
    events++;
    printf("N1|root|ts=%llu|pid=%d|phase=%u|mm=%llu|inc=%llu|a=%llu|b=%llu\n",
        (uint64_t)timestamp, pid, (uint32_t)arg0, (uint64_t)arg1,
        (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-mm-lease-lifecycle
/(pid == $target || progenyof($target))/
{
    events++;
    printf("N1|lease|ts=%llu|pid=%d|phase=%u|task_pid=%d|serial=%llu|asid=%u|owners=%u\n",
        (uint64_t)timestamp, pid, (uint32_t)arg0, (int)arg1,
        (uint64_t)arg2, (uint32_t)arg3, (uint32_t)arg4);
}

dtrace:::DROP { printf("N1|DROP\n"); }
dtrace:::ERROR { printf("N1|ERROR\n"); }
dtrace:::END { printf("N1|end|events=%llu\n", (uint64_t)events); }

carrick*:::trace-witness-exit
/pid == $target/
{
    exit(0);
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 600 * 1000000000/
{
    exit(4);
}
