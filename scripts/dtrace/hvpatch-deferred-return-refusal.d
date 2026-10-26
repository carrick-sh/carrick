/*
 * hvpatch-deferred-return-refusal.d — where does an owed EL1 return fail?
 *
 * WHAT: correlates a mapping syscall with the stable stage-1 leaf and stage-2
 * lifecycle probes around it.  A before-unmap leaf without a matching
 * after-unmap leaf or stage-2 removal names a backend refusal before the
 * retirement transaction published progress.
 *
 * ABI: syscall service/args/return, el1-mapping-leaf and
 * hvpatch-global-frame-stage2 follow their documented carrick-observability
 * USDT signatures. Mapping-leaf phases are 5 before unmap and 6 after unmap;
 * global-frame-stage2 phase 1 is removal.
 *
 * PERTURBATION: low for this reducer (one line per mapping syscall, mapping
 * leaf and stage-2 transition). Bounded at 60 seconds so the signed-test
 * wrapper can perform its own fixture verification. Zero stable USDT events
 * is a failed capture, not evidence that no reconciliation occurred.
 */
#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=8m

inline int BOUND_SECONDS = 60;

dtrace:::BEGIN
{
    printf("DRR1|header|version=1|bound_s=%d\n", BOUND_SECONDS);
    secs = 0;
    events = 0;
    errors = 0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target))/
{
    self->nr = (uint64_t)arg3;
    printf("DRR1|syscall-begin|ts=%llu|lpid=%d|ltid=%d|nr=%llu\n",
        timestamp, (int32_t)arg0, (int32_t)arg1, self->nr);
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && (uint64_t)arg0 == self->nr/
{
    printf("DRR1|syscall-args|ts=%llu|nr=%llu|a0=0x%llx|a1=0x%llx|a2=0x%llx|a3=0x%llx\n",
        timestamp, (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target))/
{
    printf("DRR1|syscall-return|ts=%llu|nr=%llu|name=%s|ret=%lld|errno=%d\n",
        timestamp, (uint64_t)arg0, copyinstr(arg1), (int64_t)arg2,
        (int32_t)arg3);
}

carrick*:::el1-mapping-leaf
/(pid == $target || progenyof($target))/
{
    events++;
    printf("DRR1|mapping-leaf|ts=%llu|phase=%u|mm=%llu|va=0x%llx|span=0x%llx|leaf=0x%llx\n",
        timestamp, (uint32_t)arg0, (uint64_t)arg1, (uint64_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-global-frame-stage2
/(pid == $target || progenyof($target))/
{
    events++;
    printf("DRR1|stage2|ts=%llu|phase=%u|ipa=0x%llx|len=0x%llx|host=0x%llx|perms=0x%llx\n",
        timestamp, (uint32_t)arg0, (uint64_t)arg1, (uint64_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

dtrace:::ERROR
{
    errors++;
}

profile:::tick-1s
{
    secs++;
}

profile:::tick-1s
/secs >= BOUND_SECONDS/
{
    printf("DRR1|end|reason=bound|events=%d|errors=%d\n", events, errors);
    exit(events == 0 ? 2 : 0);
}

dtrace:::END
{
    printf("DRR1|end|reason=end|events=%d|errors=%d\n", events, errors);
}
