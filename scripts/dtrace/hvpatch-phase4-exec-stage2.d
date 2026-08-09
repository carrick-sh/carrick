#!/usr/sbin/dtrace -qs
/*
 * Measure raw Hypervisor.framework stage-2 map/unmap time during hvpatch exec.
 *
 * Provider ABI declared by carrick-observability for Darwin/arm64:
 * carrick*:::hvpatch-exec-stage2 carries five scalar CTF arguments:
 *   uint32_t phase       (0=unmap-begin, 1=unmap-end,
 *                         2=map-begin,   3=map-end; append-only)
 *   uint64_t ipa
 *   uint64_t size
 *   uint64_t guest_start (UINT64_MAX for the IPA-only unmap ledger)
 *   int32_t  rc          (raw HVF status on end; zero on begin)
 * Re-qualify the installed DOF with `dtrace -lvn
 * 'carrick*:::hvpatch-exec-stage2'` after changing this ABI.
 *
 * Perturbation: two scalar USDT probes per raw stage-2 call. The workload has
 * roughly 20 map plus 20 unmap calls per exec, so this is attribution evidence,
 * not an authoritative untraced performance run. Only same-instrument map vs
 * unmap ratios are citable. Zero completed calls is invalid evidence.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    begins = 0;
    ends = 0;
    hvf_errors = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::hvpatch-exec-stage2
/(pid == $target || progenyof($target)) && (arg0 == 0 || arg0 == 2)/
{
    begins++;
    self->stage2_start = timestamp;
    self->stage2_kind = arg0 == 0 ? 0 : 1;
    self->stage2_ipa = (uint64_t)arg1;
    self->stage2_size = (uint64_t)arg2;
}

carrick*:::hvpatch-exec-stage2
/(pid == $target || progenyof($target)) && (arg0 == 1 || arg0 == 3) &&
 self->stage2_start != 0 && self->stage2_kind == (arg0 == 1 ? 0 : 1) &&
 self->stage2_ipa == (uint64_t)arg1 && self->stage2_size == (uint64_t)arg2/
{
    ends++;
    this->elapsed = timestamp - self->stage2_start;
    this->kind = self->stage2_kind;
    hvf_errors += (int)arg4 != 0;
    @calls[this->kind] = count();
    @bytes[this->kind] = sum((uint64_t)arg2);
    @elapsed_ns[this->kind] = sum(this->elapsed);
    @max_elapsed_ns[this->kind] = max(this->elapsed);
    @latency_ns[this->kind] = quantize(this->elapsed);
    self->stage2_start = 0;
    self->stage2_kind = 0;
    self->stage2_ipa = 0;
    self->stage2_size = 0;
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printf("HVPATCH4STAGE2|summary|begins=%d|ends=%d|pair_errors=%d|hvf_errors=%d|bounded=%d|errors=%d\n",
        begins, ends, begins - ends, hvf_errors, bounded, errors);
    printa("HVPATCH4STAGE2|kind=%d|calls=%@d\n", @calls);
    printa("HVPATCH4STAGE2|kind=%d|bytes=%@d\n", @bytes);
    printa("HVPATCH4STAGE2|kind=%d|elapsed_total_ns=%@d\n", @elapsed_ns);
    printa("HVPATCH4STAGE2|kind=%d|max_elapsed_ns=%@d\n", @max_elapsed_ns);
    printa("HVPATCH4STAGE2|kind=%d|latency_ns%@d\n", @latency_ns);
}
