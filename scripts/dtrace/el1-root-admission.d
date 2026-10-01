#!/usr/sbin/dtrace -qs
/*
 * WHICH ADDRESS SPACES DID GUEST EL1 GET TO SERVE?
 *
 * (a) What it measures: every reservation root admission decided at an
 *     address space's publication, one line each, and a per-(origin,
 *     outcome) count at exit. An MM whose root is admitted (`delegated`)
 *     has its anonymous brk/mmap/munmap/mprotect served by EL1; every other
 *     outcome keeps the host serving them (correct, slower). A zero-event
 *     run means no address space was published (no EL1 zone, switching
 *     off, or a non-switchable memory model), never "all delegated".
 *
 * (b) Provider ABI: `hvpatch-el1-root-admission(u64 mm, u32 origin,
 *     u32 outcome)`. origin: 0 = the MM's first load (initial runner or
 *     exec), 1 = fork commit. outcome (`HvpatchEl1RootAdmission`):
 *     0 delegated, 1 host_setup (CARRICK_EL1_RESERVATIONS=0 or no
 *     provider), 2 no_authority, 3 refused_busy, 4 refused_stale,
 *     5 refused_invalid, 6 refused_metadata_required, 7 refused_other.
 *     Not yet live-qualified on a signed binary (added 2026-10-01).
 *
 * (c) Perturbation: none measurable; one event per published address
 *     space.
 *
 * Usage: target/release/carrick trace --script scripts/dtrace/el1-root-admission.d -- run ...
 */

#pragma D option quiet

carrick*:::hvpatch-el1-root-admission
/pid == $target || progenyof($target)/
{
    printf("EL1ROOTADMISSION1|mm=%llu|origin=%u|outcome=%u|pid=%d\n",
        (uint64_t)arg0, (uint32_t)arg1, (uint32_t)arg2, pid);
    @admissions[(uint32_t)arg1, (uint32_t)arg2] = count();
}

proc:::exit
/pid == $target/
{
    exit(0);
}

dtrace:::END
{
    printa("EL1ROOTADMISSION1|summary|origin=%u|outcome=%u|count=%@d\n", @admissions);
}
