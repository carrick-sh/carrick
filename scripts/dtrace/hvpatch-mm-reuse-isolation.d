/*
 * WHAT: retain the full signed-test prefix's scalar MM/frame/TLBI history;
 * print guest byte payloads only when a write reports the stale-read witness.
 * A failure-only 8-byte stderr write copies the same file page before its
 * next overwrite. Copy probes authenticate the software translation and
 * content; the preceding EL0 read itself remains the fixture's witness.
 * ABI: scalar argument order is declared in carrick-observability/probes.rs.
 * FrameId is an inventory identity, not a host-owner generation. This first
 * capture does not yet authenticate the hardware translation at the EL0 read.
 * PERTURBATION: scalar printf per lifecycle/COW/stage2/invalidation event;
 * write buffers <=512 bytes are inspected during their authenticated host copy.
 * Not performance evidence. No stacks, polling or retries. Bound: 180 seconds.
 * Publication/slot/TLBI and write-copy providers require live qualification.
 * Unused scalar arguments of shorter providers have no semantic meaning.
 */
#pragma D option quiet
#pragma D option strsize=1024
#pragma D option bufsize=32m

dtrace:::BEGIN { started = timestamp; events = 0; errors = 0; publication = 0; slots = 0; tlbi = 0; copies = 0; }

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

carrick*:::hvpatch-mm-publication /pid == $target || progenyof($target)/ { publication = 1; }
carrick*:::hvpatch-mm-slot /pid == $target || progenyof($target)/ { slots = 1; }
carrick*:::hvpatch-tlb-invalidation /pid == $target || progenyof($target)/ { tlbi = 1; }

carrick*:::guest-mem-copy,
carrick*:::guest-mem-bytes
/(pid == $target || progenyof($target)) && self->nr == 64 && arg0 == 0 && arg2 == 8/
{
    printf("MMREUSE|read|ns=%llu|host=%d|pid=%d|tid=%d|asid=%d|probe=%s|va=%llx|len=%llu|a3=%llu|a4=%llu\n",
        timestamp, pid, self->guest_pid, self->guest_tid, self->asid, probename,
        (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::guest-mem-copy
/(pid == $target || progenyof($target)) && self->nr == 64 && arg0 == 0/
{ self->read8 = arg2 == 8; }

carrick*:::guest-mem-region
/(pid == $target || progenyof($target)) && self->nr == 64 && arg0 == 0 && self->read8/
{
    printf("MMREUSE|region|ns=%llu|host=%d|pid=%d|tid=%d|asid=%d|a1=%llu|a2=%llu|a3=%llu|a4=%llu\n",
        timestamp, pid, self->guest_pid, self->guest_tid, self->asid,
        (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::guest-mem-payload
/(pid == $target || progenyof($target)) && self->nr == 64 && arg0 == 0 && arg3 >= 8 && arg3 <= 512/
{
    copies = 1;
    this->message = stringof(copyin(arg2, arg3));
    if (strstr(this->message, "stale round=") != NULL || strstr(this->message, "tlb-stale-witness") != NULL) {
        printf("MMREUSE|failure|ns=%llu|host=%d|pid=%d|tid=%d|asid=%d|buffer=%llx|message=%s\n",
            timestamp, pid, self->guest_pid, self->guest_tid, self->asid, (uint64_t)arg1, this->message);
    }
}

carrick*:::hvpatch-syscall-service-clear
/pid == $target || progenyof($target)/
{ self->nr = 0; self->read8 = 0; }

dtrace:::ERROR { errors++; exit(3); }
proc:::exit /pid == $target/ { exit(events && publication && slots && tlbi && copies && !errors ? 0 : 2); }
tick-1s /timestamp - started > 180 * 1000000000/ { errors++; exit(4); }
dtrace:::END { printf("MMREUSE|summary|events=%d|publication=%d|slots=%d|tlbi=%d|copies=%d|errors=%d\n", events, publication, slots, tlbi, copies, errors); }
