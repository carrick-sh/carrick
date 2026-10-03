/*
 * WHAT: retain the full signed-test prefix's scalar MM/frame/TLBI history;
 * print guest byte payloads only when a write reports the stale-read witness.
 * ABI: scalar argument order is declared in carrick-observability/probes.rs.
 * FrameId is an inventory identity, not a host-owner generation. This first
 * capture does not yet authenticate the hardware translation at the EL0 read.
 * PERTURBATION: scalar printf per lifecycle/COW/stage2/invalidation event;
 * write buffers <=512 bytes are inspected during their authenticated host copy.
 * Not performance evidence. No stacks, polling or retries. Bound: 180 seconds.
 * Listed providers require live qualification; zero events is a refused capture.
 */
#pragma D option quiet
#pragma D option strsize=1024
#pragma D option bufsize=32m

dtrace:::BEGIN { started = timestamp; events = 0; errors = 0; }

carrick*:::hvpatch-guest-lifecycle-identity,
carrick*:::hvpatch-guest-lifecycle,
carrick*:::hvpatch-guest-address-space,
carrick*:::hvpatch-executor-claim,
carrick*:::hvpatch-frame-cow-identity,
carrick*:::hvpatch-frame-cow,
carrick*:::hvpatch-global-frame-stage2,
carrick*:::hvpatch-mm-publication,
carrick*:::hvpatch-mm-slot,
carrick*:::hvpatch-frame-pool-hit,
carrick*:::hvpatch-frame-pool-miss,
carrick*:::hvpatch-tlb-invalidation
/pid == $target || progenyof($target)/
{
    events = 1;
    printf("MMREUSE|event|ns=%llu|host=%d|thread=%d|probe=%s|a0=%llu|a1=%llu|a2=%llu|a3=%llu|a4=%llu\n",
        timestamp, pid, tid, probename, (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{ self->guest_pid = arg0; self->guest_tid = arg1; self->asid = arg2; self->nr = arg3; }

carrick*:::mmap-lowering-verdict
/(pid == $target || progenyof($target)) && arg1 == 4096/
{
    printf("MMREUSE|file|ns=%llu|host=%d|pid=%d|tid=%d|asid=%d|va=%llx|length=%llu|offset=%llu|outcome=%d\n",
        timestamp, pid, self->guest_pid, self->guest_tid, self->asid, (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2, arg3);
}

carrick*:::guest-mem-payload
/(pid == $target || progenyof($target)) && self->nr == 64 && arg0 == 0 && arg3 >= 8 && arg3 <= 512/
{
    this->message = stringof(copyin(arg2, arg3));
    if (strstr(this->message, "stale round=") != NULL) {
        printf("MMREUSE|failure|ns=%llu|host=%d|pid=%d|tid=%d|asid=%d|buffer=%llx|message=%s\n",
            timestamp, pid, self->guest_pid, self->guest_tid, self->asid, (uint64_t)arg1, this->message);
    }
}

carrick*:::hvpatch-syscall-service-clear
/pid == $target || progenyof($target)/
{ self->nr = 0; }

dtrace:::ERROR { errors++; exit(3); }
proc:::exit /pid == $target/ { exit(events && !errors ? 0 : 2); }
tick-1s /timestamp - started > 180 * 1000000000/ { errors++; exit(4); }
dtrace:::END { printf("MMREUSE|summary|events=%d|errors=%d\n", events, errors); }
