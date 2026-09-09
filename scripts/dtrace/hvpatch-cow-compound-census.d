#!/usr/sbin/dtrace -qs
/*
 * Count separate COW owners for neighboring semantic pages/source compounds.
 * Scalar ABI qualified from carrick-observability on Darwin arm64 2026-09-09:
 * identity=(pid,tid,mm,asid,phase); immediately following data=(va,old_frame,
 * new_frame,old_ipa,new_ipa). Pair only these adjacent probes on the same host
 * thread; do not assume thread affinity across a whole transaction.
 * Phase 0=mapped, 1=published, 2=committed. Retain all phases for offline
 * balance validation. VA is the receipt page; IPA is the physical compound.
 *
 * Perturbation: high-rate USDT and output. Counts only, never cite these
 * timings. Deliberately do not arm the copy-hash probe (it scans every byte).
 */
#pragma D option quiet
#pragma D option bufsize=32m

dtrace:::BEGIN
{ started = timestamp; events = 0; errors = 0; seen = 0; code = -1; bounded = 0; self->ready = 0; }

carrick*:::hvpatch-frame-cow-identity
/pid == $target || progenyof($target)/
{
    errors += self->ready != 0;
    self->guest = arg0; self->mm = arg2; self->phase = arg4;
    self->ready = 1;
}

carrick*:::hvpatch-frame-cow
/pid == $target || progenyof($target)/
{
    errors += self->ready == 0;
    events++;
    printf("COWPACK|event|guest=%d|mm=%llu|phase=%d|va=%llu|old_frame=%llu|new_frame=%llu|old_ipa=%llu|new_ipa=%llu\n",
        (int)self->guest, (uint64_t)self->mm, (int)self->phase,
        (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
    self->ready = 0;
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
{ printf("COWPACK|summary|events=%d|errors=%d|seen=%d|code=%d|bounded=%d\n", events, errors, seen, code, bounded); }
